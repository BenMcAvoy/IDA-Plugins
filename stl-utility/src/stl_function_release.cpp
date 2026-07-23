#include "stl_function_release.h"

#include <typeinf.hpp>

#include <set>

namespace stl_utility
{

namespace
{

const cexpr_t *strip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

bool is_num32(const cexpr_t *e, uint32 value)
{
  return e != nullptr && e->op == cot_num && uint32(e->numval()) == value;
}

bool same_expr(const cexpr_t *a, const cexpr_t *b)
{
  a = strip_casts(a);
  b = strip_casts(b);
  if ( a == nullptr || b == nullptr )
    return false;
  return a->equal_effect(*b);
}

// True if `stmt` is a `cit_expr` statement whose (cast-stripped) expression
// is a `cot_call` through something other than a plain named function
// reference -- i.e. some indirect/computed call, such as the vtable-slot-4
// virtual dispatch (`v13->VTABLE[0x4](v7)`) this matcher is looking for.
// Deliberately does NOT validate the callee's exact vtable-index-4 shape
// (it can print several different ways depending on Hex-Rays version); the
// surrounding bare-pointer condition + trailing null-out give this enough
// specificity, mirroring how stl_shared_ptr_release.cpp's destroy_call and
// stl_string_release.cpp's free call also aren't deeply inspected.
bool is_indirect_call_stmt(const cinsn_t &stmt)
{
  if ( stmt.op != cit_expr || stmt.cexpr == nullptr )
    return false;

  const cexpr_t *call = strip_casts(stmt.cexpr);
  if ( call == nullptr || call->op != cot_call )
    return false;

  const cexpr_t *callee = strip_casts(call->x);
  return callee != nullptr && callee->op != cot_obj;
}

// True if `stmt` is `P = 0;` (tolerating cast wrapping on either side), i.e.
// the tracking pointer being nulled out after teardown.
bool is_null_out_stmt(const cinsn_t &stmt, const cexpr_t *ptr_expr)
{
  if ( stmt.op != cit_expr || stmt.cexpr == nullptr )
    return false;

  const cexpr_t *asg = strip_casts(stmt.cexpr);
  if ( asg == nullptr || asg->op != cot_asg )
    return false;

  if ( !same_expr(asg->x, ptr_expr) )
    return false;

  return is_num32(strip_casts(asg->y), 0);
}

struct release_match_t
{
  cinsn_t *matched_stmt = nullptr;
  const cexpr_t *sp_expr = nullptr;
};

bool try_match_function_release(cinsn_t *outer_if, release_match_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;
  if ( outer_if->cif->ielse != nullptr )
    return false;

  const cexpr_t *ptr_expr = strip_casts(&outer_if->cif->expr);
  if ( ptr_expr == nullptr )
    return false;

  cinsn_t *body = outer_if->cif->ithen;
  if ( body == nullptr || body->op != cit_block || body->cblock == nullptr )
    return false;

  bool found_call = false;
  bool found_null_out = false;
  for ( cinsn_t &stmt : *body->cblock )
  {
    if ( !found_call )
    {
      if ( is_indirect_call_stmt(stmt) )
        found_call = true;
      continue;
    }

    // Already saw the indirect call; now look for the trailing null-out.
    if ( is_null_out_stmt(stmt, ptr_expr) )
    {
      found_null_out = true;
      break;
    }
  }

  if ( !found_call || !found_null_out )
    return false;

  out->matched_stmt = outer_if;
  out->sp_expr = ptr_expr;
  return true;
}

bool synthesize_and_replace(const release_match_t &match)
{
  if ( match.matched_stmt == nullptr || match.sp_expr == nullptr )
    return false;

  tinfo_t void_type;
  if ( !void_type.create_simple_type(BTF_VOID) )
    return false;

  carglist_t *args = new carglist_t();
  args->resize(1);
  args->at(0).consume_cexpr(new cexpr_t(*match.sp_expr));

  // Render as a destructor-call-shaped helper, e.g. "~function(v13)", rather
  // than a generic "release(v13)". Hex-Rays' call_helper()/vcall_helper()
  // (see hexrays.hpp) only ever print a helper expression as "name(args...)"
  // -- the name is an arbitrary string the decompiler prints verbatim, not a
  // real function, and there is no ctree construct available to us that
  // prints true member-destructor syntax ("obj.~Type()"); that form only
  // appears when Hex-Rays itself recognizes an actual destructor call, which
  // is not what we're synthesizing here. So "~function(...)" is the closest
  // achievable approximation, and importantly the object argument below is
  // still a real cloned cexpr_t (not text baked into the helper name), so it
  // stays clickable/renameable in the pseudocode.
  cexpr_t *call = call_helper(void_type, args, "~function");
  if ( call == nullptr )
    return false;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = call;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

struct function_release_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  function_release_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_if )
      return 0;

    release_match_t match;
    if ( !try_match_function_release(insn, &match) )
      return 0;
    if ( synthesize_and_replace(match) )
      ++collapsed_count;
    return 0;
  }
};

struct used_var_collector_t : public ctree_visitor_t
{
  std::set<int> used_indices;

  used_var_collector_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op == cot_var )
      used_indices.insert(e->v.idx);
    return 0;
  }
};

// See stl_shared_ptr_release.cpp for the rationale: replace_by deletes
// statements but leaves now-orphaned locals (the cached storage/tracking
// pointer, e.g. "v13") declared-but-unused, since their CVAR_USED flag isn't
// recalculated after our mutation. Hide anything no longer referenced,
// skipping arguments (never hide those -- it would alter the printed
// function signature, not just a declaration line).
void hide_orphaned_locals(cfunc_t *cfunc)
{
  used_var_collector_t collector;
  collector.apply_to(&cfunc->body, nullptr);

  lvars_t *lvars = cfunc->get_lvars();
  if ( lvars == nullptr )
    return;

  for ( size_t i = 0; i < lvars->size(); ++i )
  {
    lvar_t &lvar = lvars->at(i);
    if ( lvar.is_arg_var() || !lvar.used() )
      continue;
    if ( collector.used_indices.find(int(i)) == collector.used_indices.end() )
      lvar.clear_used();
  }
}

} // namespace

int collapse_function_releases(cfunc_t *cfunc)
{
  function_release_collapser_t collapser;
  collapser.apply_to(&cfunc->body, nullptr);
  if ( collapser.collapsed_count > 0 )
    hide_orphaned_locals(cfunc);
  return collapser.collapsed_count;
}

} // namespace stl_utility

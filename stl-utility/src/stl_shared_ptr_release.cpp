#include "stl_shared_ptr_release.h"

#include <typeinf.hpp>

#include <cstring>
#include <set>

namespace stl_utility
{

namespace
{

constexpr uint32 REP_OFFSET = 0x08; // shared_ptr/weak_ptr's _Rep member offset

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

// True if `e` is `obj._Rep` / `obj->_Rep` (a memref/memptr at REP_OFFSET).
// On success, *base is the shared_ptr/weak_ptr object expression to embed
// in the synthetic call.
bool match_rep_member(const cexpr_t *e, const cexpr_t **base)
{
  e = strip_casts(e);
  if ( e == nullptr || (e->op != cot_memref && e->op != cot_memptr) || e->m != REP_OFFSET )
    return false;
  *base = e->x;
  return true;
}

// Shared shape-check for both match_decrement_check() and
// match_decrement_check_at() below. Returns the inner
// `_InterlockedExchangeAdd(...)` call node if `e` is
// `_InterlockedExchangeAdd(ANY_PTR_EXPR, 0xFFFFFFFF) == 1`, else nullptr.
const cexpr_t *extract_decrement_call(const cexpr_t *e)
{
  e = strip_casts(e);
  if ( e == nullptr || e->op != cot_eq )
    return nullptr;

  const cexpr_t *a = strip_casts(e->x);
  const cexpr_t *b = strip_casts(e->y);
  const cexpr_t *call = nullptr;
  if ( is_num32(a, 1) )
    call = b;
  else if ( is_num32(b, 1) )
    call = a;
  if ( call == nullptr )
    return nullptr;

  call = strip_casts(call);
  if ( call == nullptr || call->op != cot_call || call->a == nullptr || call->a->size() != 2 )
    return nullptr;

  const cexpr_t *callee = strip_casts(call->x);
  if ( callee == nullptr || callee->op != cot_helper || callee->helper == nullptr )
    return nullptr;
  if ( std::strcmp(callee->helper, "_InterlockedExchangeAdd") != 0 )
    return nullptr;

  if ( !is_num32(strip_casts(&call->a->at(1)), 0xFFFFFFFFu) )
    return nullptr;

  return call;
}

// True if `e` is `_InterlockedExchangeAdd(ANY_PTR_EXPR, 0xFFFFFFFF) == 1`.
bool match_decrement_check(const cexpr_t *e)
{
  return extract_decrement_call(e) != nullptr;
}

bool same_expr(const cexpr_t *a, const cexpr_t *b)
{
  a = strip_casts(a);
  b = strip_casts(b);
  if ( a == nullptr || b == nullptr )
    return false;
  return a->equal_effect(*b);
}

// True if `e` is structurally `base + units` (or `units + base`), tolerating
// cast wrapping on either operand -- e.g. `base` being a `volatile signed
// __int32 *` and `units` being 2, matching `base + 2` in that pointer's own
// element units (== +8 bytes, i.e. `_Uses`'s offset).
bool match_ptr_plus_units(const cexpr_t *e, const cexpr_t *base, uint32 units)
{
  e = strip_casts(e);
  if ( e == nullptr || e->op != cot_add )
    return false;

  const cexpr_t *x = strip_casts(e->x);
  const cexpr_t *y = strip_casts(e->y);
  if ( is_num32(y, units) )
    return same_expr(x, base);
  if ( is_num32(x, units) )
    return same_expr(y, base);
  return false;
}

// Like match_decrement_check(), but additionally requires the call's first
// argument to be structurally `base + units` (tolerating casts). Used for
// the bare-pointer cot_land shape below, where there's no `._Rep` member
// access to anchor the match on, so we must verify the pointer arithmetic
// explicitly instead.
bool match_decrement_check_at(const cexpr_t *e, const cexpr_t *base, uint32 units)
{
  const cexpr_t *call = extract_decrement_call(e);
  if ( call == nullptr )
    return false;
  return match_ptr_plus_units(&call->a->at(0), base, units);
}

// If `branch` is a single cit_expr/cit_if directly, returns it; if it's a
// cit_block containing exactly one such top-level statement, returns that;
// otherwise nullptr.
cinsn_t *single_statement(cinsn_t *branch, ctype_t expected_op)
{
  if ( branch == nullptr )
    return nullptr;
  if ( branch->op == expected_op )
    return branch;
  if ( branch->op != cit_block || branch->cblock == nullptr )
    return nullptr;

  cinsn_t *found = nullptr;
  size_t count = 0;
  for ( cinsn_t &stmt : *branch->cblock )
  {
    ++count;
    if ( stmt.op == expected_op )
      found = &stmt;
  }
  return count == 1 ? found : nullptr;
}

struct release_match_t
{
  cinsn_t *matched_stmt = nullptr;
  const cexpr_t *sp_expr = nullptr;
};

bool try_match_release(cinsn_t *outer_if, release_match_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;
  if ( outer_if->cif->ielse != nullptr )
    return false;

  const cexpr_t *sp_expr = nullptr;
  if ( !match_rep_member(&outer_if->cif->expr, &sp_expr) )
  {
    // Second valid shape: the owning object was never retyped to a
    // shared_ptr-bearing struct, so there's no "obj._Rep" member access --
    // the control-block pointer is already a bare raw pointer local (e.g.
    // "v30"), and the null-check + _Uses-decrement check are combined into
    // a single `cot_land` (`P && decrement_check(P + 2)`) instead of two
    // nested `if`s:
    //
    //   if ( v30 && _InterlockedExchangeAdd(v30 + 2, 0xFFFFFFFF) == 1 )
    //
    // Here `sp_expr` becomes `P` itself (the bare pointer), since there's no
    // `_Rep` member to embed -- the synthesized helper is `~shared_ptr(P)`.
    const cexpr_t *land = strip_casts(&outer_if->cif->expr);
    if ( land != nullptr && land->op == cot_land )
    {
      const cexpr_t *ptr_expr = strip_casts(land->x);
      if ( ptr_expr == nullptr )
        return false;
      if ( !match_decrement_check_at(land->y, ptr_expr, 2) )
        return false;

      sp_expr = ptr_expr;
    }
    else
    {
      // Third valid shape (confirmed via sub_140452240 in ScrapMechanic.exe):
      // same bare-pointer situation as the cot_land shape above (no "._Rep"
      // member to anchor on), but here the null-check and the _Uses-
      // decrement check are NOT combined into one `cot_land` condition --
      // they're two separate nested `if`s, same structure as the first
      // (typed) shape, just with a bare pointer instead of "obj._Rep":
      //
      //   if ( v8 )
      //   {
      //     if ( _InterlockedExchangeAdd(v8 + 2, 0xFFFFFFFF) == 1 )
      //     {
      //       (**(void (__fastcall ***)(volatile signed __int32 *))v8)(v8);
      //       if ( _InterlockedExchangeAdd(v8 + 3, 0xFFFFFFFF) == 1 )
      //         v8->VTABLE[0x1]();
      //     }
      //   }
      //
      // The outer condition here is just the bare pointer expression itself
      // (`v8`), stripped of casts -- there's nothing further to validate
      // about its shape; the existing strict uses_if/uses_body checks below
      // (identical to the first shape's) provide the safety margin, since
      // uses_if must independently pass match_decrement_check() and
      // uses_body must have exactly a destroy-call statement plus a
      // weaks_if that itself passes match_decrement_check().
      const cexpr_t *ptr_expr = strip_casts(&outer_if->cif->expr);
      if ( ptr_expr == nullptr )
        return false;

      sp_expr = ptr_expr;
    }
  }

  cinsn_t *uses_if = single_statement(outer_if->cif->ithen, cit_if);
  if ( uses_if == nullptr || uses_if->cif == nullptr || uses_if->cif->ielse != nullptr )
    return false;
  if ( !match_decrement_check(&uses_if->cif->expr) )
    return false;

  cinsn_t *uses_body = uses_if->cif->ithen;
  if ( uses_body == nullptr || uses_body->op != cit_block || uses_body->cblock == nullptr )
    return false;

  cinsn_t *destroy_call = nullptr;
  cinsn_t *weaks_if = nullptr;
  size_t stmt_count = 0;
  for ( cinsn_t &stmt : *uses_body->cblock )
  {
    ++stmt_count;
    if ( stmt.op == cit_expr )
      destroy_call = &stmt;
    else if ( stmt.op == cit_if )
      weaks_if = &stmt;
  }
  if ( stmt_count != 2 || destroy_call == nullptr || weaks_if == nullptr || weaks_if->cif == nullptr )
    return false;
  if ( weaks_if->cif->ielse != nullptr )
    return false;
  if ( !match_decrement_check(&weaks_if->cif->expr) )
    return false;

  cinsn_t *delete_call = single_statement(weaks_if->cif->ithen, cit_expr);
  if ( delete_call == nullptr )
    return false;

  out->matched_stmt = outer_if;
  out->sp_expr = sp_expr;
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

  // Render as a destructor-call-shaped helper, e.g. "~shared_ptr(sp_x)",
  // rather than a generic "release(sp_x)". Hex-Rays' call_helper()/
  // vcall_helper() (see hexrays.hpp) only ever print a helper expression as
  // "name(args...)" -- the name is an arbitrary string the decompiler prints
  // verbatim, not a real function, and there is no ctree construct available
  // to us that prints true member-destructor syntax ("obj.~Type()"); that
  // form only appears when Hex-Rays itself recognizes an actual destructor
  // call, which is not what we're synthesizing here. So "~shared_ptr(...)"
  // is the closest achievable approximation, and importantly the object
  // argument below is still a real cloned cexpr_t (not text baked into the
  // helper name), so it stays clickable/renameable in the pseudocode.
  //
  // Note: match_rep_member()/try_match_release() above only recognize the
  // "obj._Rep" member-offset pattern and never inspect the object's type,
  // so this matcher cannot distinguish shared_ptr from weak_ptr releases --
  // both render as "~shared_ptr(...)" here.
  cexpr_t *call = call_helper(void_type, args, "~shared_ptr");
  if ( call == nullptr )
    return false;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = call;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

struct release_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  release_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_if )
      return 0;

    release_match_t match;
    if ( !try_match_release(insn, &match) )
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

// See IDA-XXHash-Utility's xxhash_plugin.cpp for the rationale: replace_by
// deletes statements but leaves now-orphaned locals (the cached control
// block pointer, e.g. "v22") declared-but-unused, since their CVAR_USED
// flag isn't recalculated after our mutation. Hide anything no longer
// referenced, skipping arguments (never hide those -- it would alter the
// printed function signature, not just a declaration line).
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

int collapse_shared_ptr_releases(cfunc_t *cfunc)
{
  release_collapser_t collapser;
  collapser.apply_to(&cfunc->body, nullptr);
  if ( collapser.collapsed_count > 0 )
    hide_orphaned_locals(cfunc);
  return collapser.collapsed_count;
}

} // namespace stl_utility

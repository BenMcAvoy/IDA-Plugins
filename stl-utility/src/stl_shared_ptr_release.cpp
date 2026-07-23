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

// True if `e` is `_InterlockedExchangeAdd(ANY_PTR_EXPR, 0xFFFFFFFF) == 1`.
bool match_decrement_check(const cexpr_t *e)
{
  e = strip_casts(e);
  if ( e == nullptr || e->op != cot_eq )
    return false;

  const cexpr_t *a = strip_casts(e->x);
  const cexpr_t *b = strip_casts(e->y);
  const cexpr_t *call = nullptr;
  if ( is_num32(a, 1) )
    call = b;
  else if ( is_num32(b, 1) )
    call = a;
  if ( call == nullptr )
    return false;

  call = strip_casts(call);
  if ( call == nullptr || call->op != cot_call || call->a == nullptr || call->a->size() != 2 )
    return false;

  const cexpr_t *callee = strip_casts(call->x);
  if ( callee == nullptr || callee->op != cot_helper || callee->helper == nullptr )
    return false;
  if ( std::strcmp(callee->helper, "_InterlockedExchangeAdd") != 0 )
    return false;

  return is_num32(strip_casts(&call->a->at(1)), 0xFFFFFFFFu);
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
    return false;

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

  cexpr_t *call = call_helper(void_type, args, "release");
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

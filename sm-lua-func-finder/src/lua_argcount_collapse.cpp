#include "lua_argcount_collapse.h"

#include <name.hpp>
#include <bytes.hpp>
#include <typeinf.hpp>

#include <cstring>
#include <map>
#include <set>

namespace
{

constexpr char EXPECTED_ARGS_FORMAT[] = "Expected %d arguments (got %d)";

const cexpr_t *strip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

// Same string-content resolution convention as reg_scan.cpp's
// resolve_str_arg(): either a literal folded directly into the call, or a
// global pointer-to-string read by value.
bool resolve_str_arg(const cexpr_t *e, qstring *out)
{
  e = strip_casts(e);
  if ( e == nullptr )
    return false;

  if ( e->op == cot_str )
  {
    if ( e->string == nullptr )
      return false;
    *out = e->string;
    return true;
  }

  if ( e->op == cot_obj )
  {
    ea_t g = e->obj_ea;
    if ( !is_loaded(g) )
      return false;
    ea_t p = ea_t(get_qword(g));
    if ( p == 0 || !is_loaded(p) )
      return false;
    return get_strlit_contents(out, p, -1, STRTYPE_C) > 0;
  }

  return false;
}

bool is_expected_args_format_string(const cexpr_t *e)
{
  qstring contents;
  return resolve_str_arg(e, &contents) && contents == EXPECTED_ARGS_FORMAT;
}

// Lazily resolves a named import's ea once per process, caching the result
// (the database doesn't change which imports exist mid-session).
ea_t named_ea(const char *name)
{
  static std::map<qstring, ea_t> cache;
  qstring key = name;
  auto it = cache.find(key);
  if ( it != cache.end() )
    return it->second;
  ea_t ea = get_name_ea(BADADDR, name);
  cache[key] = ea;
  return ea;
}

// True if `e` (after stripping casts) is a `cot_call` whose callee resolves
// (via cot_obj/obj_ea) to the named imported function. On success, *args is
// the call's argument list.
bool is_call_to_named(const cexpr_t *e, const char *name, const carglist_t **args)
{
  e = strip_casts(e);
  if ( e == nullptr || e->op != cot_call || e->a == nullptr )
    return false;

  const cexpr_t *callee = strip_casts(e->x);
  if ( callee == nullptr || callee->op != cot_obj )
    return false;

  ea_t target_ea = named_ea(name);
  if ( target_ea == BADADDR || callee->obj_ea != target_ea )
    return false;

  *args = e->a;
  return true;
}

bool same_expr(const cexpr_t *a, const cexpr_t *b)
{
  a = strip_casts(a);
  b = strip_casts(b);
  if ( a == nullptr || b == nullptr )
    return false;
  return a->equal_effect(*b);
}

// True if `cond` (after stripping casts) is `(cast) lua_gettop(L) <op> N`
// or `N <op> (cast) lua_gettop(L)`, for the requested comparison opcode.
// On success, *l_expr is the `L` argument expression (still inside the
// live ctree -- not cloned) and *n_expr is the literal `N` expression.
bool match_gettop_compare(const cexpr_t *cond, ctype_t want_op, const cexpr_t **l_expr, const cexpr_t **n_expr)
{
  cond = strip_casts(cond);
  if ( cond == nullptr || cond->op != want_op )
    return false;

  const cexpr_t *x = strip_casts(cond->x);
  const cexpr_t *y = strip_casts(cond->y);

  const cexpr_t *call_side = nullptr;
  const cexpr_t *num_side = nullptr;
  if ( y != nullptr && y->op == cot_num )
  {
    call_side = x;
    num_side = y;
  }
  else if ( x != nullptr && x->op == cot_num )
  {
    call_side = y;
    num_side = x;
  }
  else
  {
    return false;
  }

  const carglist_t *args = nullptr;
  if ( !is_call_to_named(call_side, "lua_gettop", &args) || args->size() < 1 )
    return false;

  *l_expr = &args->at(0);
  *n_expr = num_side;
  return true;
}

// True if `stmt` is `<var> = lua_gettop(l_expr);` (the throwaway "got count"
// recompute) -- matched structurally against `l_expr` via same_expr(), not
// by variable name.
bool match_gettop_recompute(const cinsn_t *stmt, const cexpr_t *l_expr)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr )
    return false;

  const cexpr_t *asg = strip_casts(stmt->cexpr);
  if ( asg == nullptr || asg->op != cot_asg )
    return false;

  const cexpr_t *lhs = strip_casts(asg->x);
  if ( lhs == nullptr || lhs->op != cot_var )
    return false;

  const carglist_t *args = nullptr;
  if ( !is_call_to_named(asg->y, "lua_gettop", &args) || args->size() < 1 )
    return false;

  return same_expr(&args->at(0), l_expr);
}

// True if `stmt` is the `luaL_error(L, "Expected %d arguments (got %d)", N,
// <got-count expr>);` call, for the SAME `l_expr` (structural equality).
// On success, *n_expr is the expected-count literal (2nd arg to
// luaL_error -- the 3rd call argument overall).
bool match_luaL_error_call(const cinsn_t *stmt, const cexpr_t *l_expr, const cexpr_t **n_expr)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr )
    return false;

  const carglist_t *args = nullptr;
  if ( !is_call_to_named(stmt->cexpr, "luaL_error", &args) || args->size() < 4 )
    return false;

  if ( !same_expr(&args->at(0), l_expr) )
    return false;

  if ( !is_expected_args_format_string(&args->at(1)) )
    return false;

  const cexpr_t *n_lit = strip_casts(&args->at(2));
  if ( n_lit == nullptr || n_lit->op != cot_num )
    return false;

  *n_expr = n_lit;
  return true;
}

struct argcount_match_t
{
  cinsn_t *matched_stmt = nullptr;  // the whole outer cit_if
  const cexpr_t *l_expr = nullptr;  // lua_State* expression (live, uncloned)
  const cexpr_t *n_expr = nullptr;  // expected-argcount literal (live, uncloned)
  bool has_else = false;            // Shape B: real body must be reparented
  cinsn_t *real_body = nullptr;     // Shape B only: the ithen block to keep
};

// Shape A: early-return-on-mismatch.
//   if ( (unsigned int)lua_gettop(L) != N )
//   {
//     v2 = lua_gettop(L);
//     luaL_error(L, "Expected %d arguments (got %d)", N, v2);
//     return ...;
//   }
//   ... real body follows as later siblings, untouched ...
bool try_match_shape_a(cinsn_t *outer_if, argcount_match_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;
  if ( outer_if->cif->ielse != nullptr )
    return false; // shape A has no else -- that's shape B

  const cexpr_t *l_expr = nullptr;
  const cexpr_t *n_expr = nullptr;
  if ( !match_gettop_compare(&outer_if->cif->expr, cot_ne, &l_expr, &n_expr) )
    return false;

  cinsn_t *body = outer_if->cif->ithen;
  if ( body == nullptr || body->op != cit_block || body->cblock == nullptr )
    return false;

  cinsn_t *recompute_stmt = nullptr;
  cinsn_t *error_stmt = nullptr;
  cinsn_t *return_stmt = nullptr;
  size_t stmt_count = 0;
  for ( cinsn_t &stmt : *body->cblock )
  {
    ++stmt_count;
    if ( stmt.op == cit_return )
      return_stmt = &stmt;
    else if ( stmt.op == cit_expr )
    {
      // Disambiguate the two cit_expr statements by trying the more
      // specific match (luaL_error) first.
      const cexpr_t *n_from_error = nullptr;
      if ( error_stmt == nullptr && match_luaL_error_call(&stmt, l_expr, &n_from_error) )
        error_stmt = &stmt;
      else if ( recompute_stmt == nullptr && match_gettop_recompute(&stmt, l_expr) )
        recompute_stmt = &stmt;
    }
  }

  if ( stmt_count != 3 || recompute_stmt == nullptr || error_stmt == nullptr || return_stmt == nullptr )
    return false;

  out->matched_stmt = outer_if;
  out->l_expr = l_expr;
  out->n_expr = n_expr;
  out->has_else = false;
  out->real_body = nullptr;
  return true;
}

// Shape B: match-wraps-the-body, mismatch in the else.
//   if ( (unsigned int)lua_gettop(L) == N )
//   {
//     ... real body ...
//   }
//   else
//   {
//     v2 = lua_gettop(L);
//     luaL_error(L, "Expected %d arguments (got %d)", N, v2);
//   }
bool try_match_shape_b(cinsn_t *outer_if, argcount_match_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;
  if ( outer_if->cif->ielse == nullptr )
    return false; // shape B requires an else -- that's shape A

  const cexpr_t *l_expr = nullptr;
  const cexpr_t *n_expr = nullptr;
  if ( !match_gettop_compare(&outer_if->cif->expr, cot_eq, &l_expr, &n_expr) )
    return false;

  cinsn_t *else_body = outer_if->cif->ielse;
  if ( else_body == nullptr || else_body->op != cit_block || else_body->cblock == nullptr )
    return false;

  cinsn_t *recompute_stmt = nullptr;
  cinsn_t *error_stmt = nullptr;
  size_t stmt_count = 0;
  for ( cinsn_t &stmt : *else_body->cblock )
  {
    ++stmt_count;
    if ( stmt.op != cit_expr )
      continue;
    const cexpr_t *n_from_error = nullptr;
    if ( error_stmt == nullptr && match_luaL_error_call(&stmt, l_expr, &n_from_error) )
      error_stmt = &stmt;
    else if ( recompute_stmt == nullptr && match_gettop_recompute(&stmt, l_expr) )
      recompute_stmt = &stmt;
  }

  if ( stmt_count != 2 || recompute_stmt == nullptr || error_stmt == nullptr )
    return false;

  cinsn_t *body = outer_if->cif->ithen;
  if ( body == nullptr )
    return false;

  out->matched_stmt = outer_if;
  out->l_expr = l_expr;
  out->n_expr = n_expr;
  out->has_else = true;
  out->real_body = body;
  return true;
}

// Builds `L_checkArgCount(L, N)` as a synthetic call_helper expression.
// luaL_error() never returns (it longjmps out of the Lua VM via
// lua_error()/lj_err_throw()-style unwinding), so the recompute-for-the-
// message local, the luaL_error() call itself, and (in Shape A) the early
// return are all pure noise that only exist because Hex-Rays can't know
// the callee is noreturn. Collapsing them to a single named helper call
// (the same "call_helper()/vcall_helper() only ever print name(args...)"
// technique used by stl_shared_ptr_release.cpp/stl_string_release.cpp)
// keeps the check visible -- and its operands (L, N) still real, cloned
// cexpr_t nodes, so they stay clickable/renameable in the pseudocode --
// while dropping everything that exists solely to satisfy a control-flow
// edge Hex-Rays believes it needs but which can never actually be taken.
cexpr_t *make_check_call(const cexpr_t *l_expr, const cexpr_t *n_expr)
{
  tinfo_t void_type;
  if ( !void_type.create_simple_type(BTF_VOID) )
    return nullptr;

  carglist_t *args = new carglist_t();
  args->resize(2);
  args->at(0).consume_cexpr(new cexpr_t(*l_expr));
  args->at(1).consume_cexpr(new cexpr_t(*n_expr));

  return call_helper(void_type, args, "L_checkArgCount");
}

bool synthesize_and_replace_shape_a(const argcount_match_t &match)
{
  cexpr_t *call = make_check_call(match.l_expr, match.n_expr);
  if ( call == nullptr )
    return false;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = call;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

bool synthesize_and_replace_shape_b(argcount_match_t &match)
{
  cexpr_t *call = make_check_call(match.l_expr, match.n_expr);
  if ( call == nullptr )
    return false;

  // outer_if->cif owns `real_body` (the ithen subtree). replace_by() below
  // deletes the whole matched cit_if node (including its cif_t, which
  // deletes ithen/ielse in its destructor), so we must detach `real_body`
  // from the cif_t BEFORE replacing, or the reparented subtree would be
  // double-freed once as part of the old node's cleanup and again when the
  // new block housing it is eventually torn down.
  cinsn_t *real_body = match.real_body;
  match.matched_stmt->cif->ithen = nullptr;

  cblock_t *new_cblock = new cblock_t();

  // First statement: the synthesized check.
  cinsn_t check_stmt;
  check_stmt.op = cit_expr;
  check_stmt.cexpr = call;
  check_stmt.ea = match.matched_stmt->ea;
  new_cblock->push_back().swap(check_stmt);

  // Second statement: the real body, MOVED (not cloned) via cinsn_t::swap
  // -- cinsn_t's copy-assignment (used by qlist::push_back(const T&)) does
  // a deep structural copy, which would be wasteful (and needless copy
  // risk) for a whole function body; swap() just exchanges the union
  // pointers/op tags, so ownership transfers cheaply and exactly.
  new_cblock->push_back().swap(*real_body);
  delete real_body; // now cit_empty (its contents were swapped out) -- safe

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_block;
  new_stmt->cblock = new_cblock;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

struct argcount_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  argcount_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_if )
      return 0;

    argcount_match_t match;
    if ( try_match_shape_a(insn, &match) )
    {
      if ( synthesize_and_replace_shape_a(match) )
        ++collapsed_count;
      return 0;
    }

    if ( try_match_shape_b(insn, &match) )
    {
      if ( synthesize_and_replace_shape_b(match) )
        ++collapsed_count;
      return 0;
    }

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

// See stl_shared_ptr_release.cpp's hide_orphaned_locals() for the
// rationale: replace_by deletes statements but leaves now-orphaned locals
// (here, the "got count" recompute local, e.g. "v2") declared-but-unused,
// since their CVAR_USED flag isn't recalculated after our mutation. Hide
// anything no longer referenced, skipping arguments (never hide those --
// it would alter the printed function signature, not just a declaration
// line).
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

int collapse_lua_argcount_checks(cfunc_t *cfunc)
{
  argcount_collapser_t collapser;
  collapser.apply_to(&cfunc->body, nullptr);
  if ( collapser.collapsed_count > 0 )
    hide_orphaned_locals(cfunc);
  return collapser.collapsed_count;
}

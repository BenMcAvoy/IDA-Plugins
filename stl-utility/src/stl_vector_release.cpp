#include "stl_vector_release.h"

#include <typeinf.hpp>

#include <set>

namespace stl_utility
{

namespace
{

// Same struct-shape knowledge as src/stl_vector.cpp's MYFIRST_OFFSET: the
// first of the three pointers ({_Myfirst,_Mylast,_Myend}) in a vector-shaped
// object, at offset 0x00.
constexpr uint32 MYFIRST_OFFSET = 0x00;

const cexpr_t *strip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

bool same_expr(const cexpr_t *a, const cexpr_t *b)
{
  a = strip_casts(a);
  b = strip_casts(b);
  if ( a == nullptr || b == nullptr )
    return false;
  return a->equal_effect(*b);
}

// True if `e` is `obj._Myfirst` / `obj->_Myfirst` (a memref/memptr at
// MYFIRST_OFFSET). On success, *base is the vector object expression to
// embed in the synthetic call.
bool match_myfirst_member(const cexpr_t *e, const cexpr_t **base)
{
  e = strip_casts(e);
  if ( e == nullptr || (e->op != cot_memref && e->op != cot_memptr) || e->m != MYFIRST_OFFSET )
    return false;
  *base = e->x;
  return true;
}

// If `branch` is a single cit_expr directly, returns it; if it's a
// cit_block containing exactly one such top-level statement, returns that;
// otherwise nullptr. Same helper pattern as
// stl_shared_ptr_release.cpp's single_statement().
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

// True if `stmt` is a `cit_expr` wrapping a `cot_call` (operator
// delete/free-shaped) whose first argument is the SAME base expression as
// `base_expr` (per same_expr()). Tolerates an optional 2nd size argument
// (the sized-delete form, `operator delete(ptr, size)`) without validating
// its exact shape -- same laxity precedent as
// stl_function_release.cpp's deliberately-loose call matching.
bool match_free_call(const cinsn_t *stmt, const cexpr_t *base_expr)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr )
    return false;

  const cexpr_t *call = strip_casts(stmt->cexpr);
  if ( call == nullptr || call->op != cot_call || call->a == nullptr || call->a->empty() )
    return false;

  // Tolerate 1 (plain delete) or 2 (sized delete) arguments; anything else
  // isn't the shape we're looking for.
  if ( call->a->size() != 1 && call->a->size() != 2 )
    return false;

  return same_expr(&call->a->at(0), base_expr);
}

struct release_match_t
{
  cinsn_t *matched_stmt = nullptr;
  const cexpr_t *vec_expr = nullptr;
};

bool try_match_vector_release(cinsn_t *outer_if, release_match_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;
  if ( outer_if->cif->ielse != nullptr )
    return false;

  const cexpr_t *vec_expr = nullptr;
  if ( !match_myfirst_member(&outer_if->cif->expr, &vec_expr) )
  {
    // Second valid shape: the vector was never retyped to a struct with a
    // "._Myfirst" member, so the backing-buffer pointer is already a bare
    // raw pointer local -- the condition is just that pointer itself,
    // tolerating cast wrapping (e.g. `if ( v8 )`).
    const cexpr_t *ptr_expr = strip_casts(&outer_if->cif->expr);
    if ( ptr_expr == nullptr )
      return false;
    vec_expr = ptr_expr;
  }

  cinsn_t *free_stmt = single_statement(outer_if->cif->ithen, cit_expr);
  if ( free_stmt == nullptr )
    return false;
  if ( !match_free_call(free_stmt, vec_expr) )
    return false;

  out->matched_stmt = outer_if;
  out->vec_expr = vec_expr;
  return true;
}

bool synthesize_and_replace(const release_match_t &match)
{
  if ( match.matched_stmt == nullptr || match.vec_expr == nullptr )
    return false;

  tinfo_t void_type;
  if ( !void_type.create_simple_type(BTF_VOID) )
    return false;

  carglist_t *args = new carglist_t();
  args->resize(1);
  args->at(0).consume_cexpr(new cexpr_t(*match.vec_expr));

  // Same rendering approach as this codebase's other release collapsers
  // (stl_shared_ptr_release.cpp, stl_string_release.cpp,
  // stl_function_release.cpp): a helper expression printed as
  // "name(args...)" via call_helper()/vcall_helper() (see hexrays.hpp) is
  // the closest achievable approximation of true "obj.~Type()" syntax --
  // there is no ctree construct available to us that prints real
  // member-destructor syntax, since that form only appears when Hex-Rays
  // itself recognizes an actual destructor call, not something we
  // synthesize. So "~vector(...)" is the closest approximation, and the
  // object argument below is still a real cloned cexpr_t (not text baked
  // into the helper name), so it stays clickable/renameable in the
  // pseudocode.
  cexpr_t *call = call_helper(void_type, args, "~vector");
  if ( call == nullptr )
    return false;

  cinsn_t *new_stmt = new cinsn_t();
  new_stmt->op = cit_expr;
  new_stmt->cexpr = call;
  new_stmt->ea = match.matched_stmt->ea;

  match.matched_stmt->replace_by(new_stmt);
  return true;
}

struct vector_release_collapser_t : public ctree_visitor_t
{
  int collapsed_count = 0;

  vector_release_collapser_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_insn(cinsn_t *insn) override
  {
    if ( insn->op != cit_if )
      return 0;

    release_match_t match;
    if ( !try_match_vector_release(insn, &match) )
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

// See stl_shared_ptr_release.cpp's hide_orphaned_locals() for the
// rationale: replace_by deletes statements but leaves now-orphaned locals
// (the cached backing-buffer pointer) declared-but-unused, since their
// CVAR_USED flag isn't recalculated after our mutation. Hide anything no
// longer referenced, skipping arguments (never hide those -- it would alter
// the printed function signature, not just a declaration line). Kept as its
// own copy per this codebase's established one-copy-per-file convention.
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

int collapse_vector_releases(cfunc_t *cfunc)
{
  vector_release_collapser_t collapser;
  collapser.apply_to(&cfunc->body, nullptr);
  if ( collapser.collapsed_count > 0 )
    hide_orphaned_locals(cfunc);
  return collapser.collapsed_count;
}

} // namespace stl_utility

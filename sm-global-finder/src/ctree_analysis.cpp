#include "ctree_analysis.h"

#include <funcs.hpp>
#include <hexrays.hpp>

namespace
{

const cexpr_t *skip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

bool is_call_to(const cexpr_t *e, ea_t target_ea)
{
  e = skip_casts(e);
  if ( e == nullptr || e->op != cot_call )
    return false;
  const cexpr_t *callee = skip_casts(e->x);
  return callee != nullptr && callee->op == cot_obj && callee->obj_ea == target_ea;
}

// Finds the first "global = ctor_ea(...)" assignment in program order, either
// directly ("global = ctor(...)") or through one level of indirection
// ("local = ctor(...); ... ; global = local;" -- the common try/catch-wrapped
// or null-checked allocator shape).
struct find_global_store_visitor_t final : public ctree_visitor_t
{
  ea_t ctor_ea;
  ea_t found_global_ea = BADADDR;
  qvector<int> ctor_result_locals; // lvar indices holding ctor_ea's return value

  explicit find_global_store_visitor_t(ea_t ctor_ea_)
    : ctree_visitor_t(CV_FAST), ctor_ea(ctor_ea_) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op != cot_asg )
      return 0;

    if ( is_call_to(e->y, ctor_ea) )
    {
      if ( e->x->op == cot_obj )
      {
        found_global_ea = e->x->obj_ea;
        return 1; // stop: first direct match in program order
      }
      if ( e->x->op == cot_var )
        ctor_result_locals.push_back(e->x->v.idx);
      return 0;
    }

    if ( e->x->op == cot_obj )
    {
      const cexpr_t *rhs = skip_casts(e->y);
      if ( rhs != nullptr && rhs->op == cot_var )
      {
        for ( int idx : ctor_result_locals )
        {
          if ( idx == rhs->v.idx )
          {
            found_global_ea = e->x->obj_ea;
            return 1; // stop: first indirect match in program order
          }
        }
      }
    }

    return 0;
  }
};

// Finds the first "global = this;" self-registration assignment in program
// order, inside the constructor's own body (this_lvar_idx is the ctor's
// "this" argument's index into cfunc->lvars). Mirrors the shape/style of
// find_global_store_visitor_t above, but looks at a var (the ctor's own
// argument), never a call result.
struct find_self_registered_global_visitor_t final : public ctree_visitor_t
{
  int this_lvar_idx;
  ea_t found_global_ea = BADADDR;

  explicit find_self_registered_global_visitor_t(int this_lvar_idx_)
    : ctree_visitor_t(CV_FAST), this_lvar_idx(this_lvar_idx_) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op != cot_asg || e->x->op != cot_obj )
      return 0;

    const cexpr_t *rhs = skip_casts(e->y);
    if ( rhs != nullptr && rhs->op == cot_var && rhs->v.idx == this_lvar_idx )
    {
      found_global_ea = e->x->obj_ea;
      return 1; // stop: first match in program order
    }

    return 0;
  }
};

} // namespace

ea_t find_self_registered_global(ea_t ctor_ea, qstring *reason)
{
  func_t *pfn = get_func(ctor_ea);
  if ( pfn == nullptr )
  {
    if ( reason != nullptr )
      *reason = "constructor candidate has no containing function";
    return BADADDR;
  }

  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_func(pfn, &hf);
  if ( cf == nullptr )
  {
    if ( reason != nullptr )
      *reason = "decompilation of constructor candidate failed";
    return BADADDR;
  }

  // Locate the ctor's "this" argument: by MSVC __fastcall/__thiscall
  // convention, this is the first (lowest-index) argument lvar.
  lvars_t *lvars = cf->get_lvars();
  int this_lvar_idx = -1;
  if ( lvars != nullptr )
  {
    for ( size_t i = 0; i < lvars->size(); ++i )
    {
      if ( (*lvars)[i].is_arg_var() )
      {
        this_lvar_idx = int(i);
        break;
      }
    }
  }

  if ( this_lvar_idx < 0 )
  {
    if ( reason != nullptr )
      *reason = "constructor has no argument lvars (no 'this' parameter found)";
    return BADADDR;
  }

  find_self_registered_global_visitor_t visitor(this_lvar_idx);
  visitor.apply_to(&cf->body, nullptr);

  if ( visitor.found_global_ea == BADADDR && reason != nullptr )
    *reason = "constructor's own body has no self-registration store of its 'this' argument to a global";

  return visitor.found_global_ea;
}

ea_t find_global_store(ea_t allocator_ea, ea_t ctor_ea, qstring *reason)
{
  func_t *pfn = get_func(allocator_ea);
  if ( pfn == nullptr )
  {
    if ( reason != nullptr )
      *reason = "allocator candidate has no containing function";
    return BADADDR;
  }

  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_func(pfn, &hf);
  if ( cf == nullptr )
  {
    if ( reason != nullptr )
      *reason = "decompilation of allocator candidate failed";
    return BADADDR;
  }

  find_global_store_visitor_t visitor(ctor_ea);
  visitor.apply_to(&cf->body, nullptr);

  if ( visitor.found_global_ea == BADADDR && reason != nullptr )
    *reason = "no direct or 1-level-indirect global store of ctor's return value found";

  return visitor.found_global_ea;
}

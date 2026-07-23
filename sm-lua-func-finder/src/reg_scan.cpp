#include "reg_scan.h"
#include "lua_reg_array.h"

#include <hexrays.hpp>

#include <name.hpp>
#include <xref.hpp>
#include <funcs.hpp>
#include <bytes.hpp>

#include <qset.hpp>

#include <algorithm>

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

// Resolves a "const char *" argument to its string contents. Handles two
// shapes seen in practice:
//   - a literal string constant folded directly into the call
//   - a global pointer variable read by value (e.g. a cached "Tool" name
//     stashed in a static local next to a typeid-hash cache) -- the global
//     itself holds a pointer to the string, so it needs one dereference.
bool resolve_str_arg(const cexpr_t *e, qstring *out)
{
  e = skip_casts(e);
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

// Resolves the "const luaL_Reg *" argument to the ea of the array it points
// at. The compiler always takes this array's address explicitly (&global),
// which shows up in the ctree as cot_ref(cot_obj(obj_ea=array)).
bool resolve_array_ea(const cexpr_t *e, ea_t *arr_ea)
{
  e = skip_casts(e);
  if ( e == nullptr )
    return false;

  if ( e->op == cot_ref )
  {
    const cexpr_t *inner = skip_casts(e->x);
    if ( inner != nullptr && inner->op == cot_obj )
    {
      *arr_ea = inner->obj_ea;
      return true;
    }
    return false;
  }

  // Defensive fallback: some shapes may present the array address as a
  // plain object reference without an explicit cot_ref wrapper.
  if ( e->op == cot_obj )
  {
    *arr_ea = e->obj_ea;
    return true;
  }

  return false;
}

struct newmt_hit_t
{
  ea_t call_ea;
  qstring name;
};

struct register_hit_t
{
  ea_t call_ea;
  bool libname_is_null;
  qstring libname_str;
  bool arr_resolved;
  ea_t arr_ea;
};

struct reg_call_visitor_t final : public ctree_visitor_t
{
  ea_t register_ea;
  ea_t newmetatable_ea;
  qvector<newmt_hit_t> newmt_hits;
  qvector<register_hit_t> register_hits;

  reg_call_visitor_t(ea_t register_ea_, ea_t newmetatable_ea_)
    : ctree_visitor_t(CV_FAST), register_ea(register_ea_), newmetatable_ea(newmetatable_ea_)
  {
  }

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op != cot_call || e->a == nullptr )
      return 0;

    const cexpr_t *callee = skip_casts(e->x);
    if ( callee == nullptr || callee->op != cot_obj )
      return 0;

    if ( callee->obj_ea == newmetatable_ea && e->a->size() >= 2 )
    {
      newmt_hit_t hit;
      hit.call_ea = e->ea;
      if ( resolve_str_arg(&(*e->a)[1], &hit.name) )
        newmt_hits.push_back(hit);
      return 0;
    }

    if ( callee->obj_ea == register_ea && e->a->size() >= 3 )
    {
      register_hit_t hit;
      hit.call_ea = e->ea;
      const cexpr_t &libname_arg = (*e->a)[1];
      const cexpr_t *libname = skip_casts(&libname_arg);
      hit.libname_is_null = libname != nullptr && libname->op == cot_num && libname->is_zero_const();
      if ( !hit.libname_is_null )
      {
        if ( !resolve_str_arg(&libname_arg, &hit.libname_str) )
          return 0; // unresolvable libname shape -- skip this call site entirely
      }
      hit.arr_resolved = resolve_array_ea(&(*e->a)[2], &hit.arr_ea);
      register_hits.push_back(hit);
      return 0;
    }

    return 0;
  }
};

bool less_by_call_ea_newmt(const newmt_hit_t &a, const newmt_hit_t &b)
{
  return a.call_ea < b.call_ea;
}

bool less_by_call_ea_reg(const register_hit_t &a, const register_hit_t &b)
{
  return a.call_ea < b.call_ea;
}

qvector<ea_t> find_caller_func_starts(ea_t target_ea)
{
  qvector<ea_t> out;
  qset<ea_t> seen;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target_ea, XREF_ALL); ok; ok = xb.next_to() )
  {
    if ( xb.type != fl_CN && xb.type != fl_CF )
      continue;
    func_t *pfn = get_func(xb.from);
    if ( pfn == nullptr )
      continue;
    if ( seen.find(pfn->start_ea) == seen.end() )
    {
      seen.insert(pfn->start_ea);
      out.push_back(pfn->start_ea);
    }
  }
  return out;
}

void process_function(
    ea_t func_start,
    ea_t register_ea,
    ea_t newmetatable_ea,
    qvector<lua_func_reg_t> *out,
    qstring *log)
{
  func_t *pfn = get_func(func_start);
  if ( pfn == nullptr )
    return;

  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_func(pfn, &hf);
  if ( cf == nullptr )
  {
    log->cat_sprnt("SKIP function %a: decompilation failed (%s)\n", func_start, hf.desc().c_str());
    return;
  }

  reg_call_visitor_t visitor(register_ea, newmetatable_ea);
  visitor.apply_to(&cf->body, nullptr);

  std::sort(visitor.newmt_hits.begin(), visitor.newmt_hits.end(), less_by_call_ea_newmt);
  std::sort(visitor.register_hits.begin(), visitor.register_hits.end(), less_by_call_ea_reg);

  for ( const register_hit_t &reg : visitor.register_hits )
  {
    if ( !reg.arr_resolved )
    {
      log->cat_sprnt(
          "SKIP call %a in %a: couldn't resolve the luaL_Reg array argument\n",
          reg.call_ea, func_start);
      continue;
    }

    qstring owner;
    bool is_userdata;
    if ( reg.libname_is_null )
    {
      is_userdata = true;
      const newmt_hit_t *preceding = nullptr;
      for ( const newmt_hit_t &nh : visitor.newmt_hits )
      {
        if ( nh.call_ea <= reg.call_ea )
          preceding = &nh;
        else
          break;
      }
      if ( preceding == nullptr )
      {
        log->cat_sprnt(
            "SKIP call %a in %a: NULL-libname luaL_register with no preceding "
            "luaL_newmetatable in this function\n",
            reg.call_ea, func_start);
        continue;
      }
      owner = preceding->name;
    }
    else
    {
      is_userdata = false;
      owner = reg.libname_str.empty() ? qstring("GLOBAL") : reg.libname_str;
    }

    qstring reason;
    qvector<lua_reg_entry_t> entries = parse_luaL_reg_array(reg.arr_ea, &reason);
    if ( entries.empty() )
    {
      log->cat_sprnt(
          "SKIP call %a in %a: luaL_Reg array at %a yielded no entries (%s)\n",
          reg.call_ea, func_start, reg.arr_ea,
          reason.empty() ? "empty array" : reason.c_str());
      continue;
    }

    for ( const lua_reg_entry_t &entry : entries )
    {
      if ( entry.func_ea == 0 || !is_loaded(entry.func_ea) )
        continue;

      lua_func_reg_t rec;
      rec.owner = owner;
      rec.is_userdata = is_userdata;
      rec.funcname = entry.name;
      rec.func_ea = entry.func_ea;
      rec.call_ea = reg.call_ea;
      out->push_back(rec);
    }
  }
}

} // namespace

qvector<lua_func_reg_t> scan_lua_registrations(qstring *log)
{
  qvector<lua_func_reg_t> out;

  ea_t register_ea = get_name_ea(BADADDR, "luaL_register");
  ea_t newmetatable_ea = get_name_ea(BADADDR, "luaL_newmetatable");
  if ( register_ea == BADADDR || newmetatable_ea == BADADDR )
  {
    log->cat_sprnt(
        "luaL_register/luaL_newmetatable not found by name -- is lua51.dll "
        "imported and named normally in this database?\n");
    return out;
  }

  qset<ea_t> func_set;
  for ( ea_t ea : find_caller_func_starts(register_ea) )
    func_set.insert(ea);
  for ( ea_t ea : find_caller_func_starts(newmetatable_ea) )
    func_set.insert(ea);

  for ( ea_t func_start : func_set )
    process_function(func_start, register_ea, newmetatable_ea, &out, log);

  return out;
}

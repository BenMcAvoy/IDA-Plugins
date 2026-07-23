// Constructor-driven struct layout synthesis (conservative,
// read-only-application v1).
//
// For each class this plugin already resolved a ctor candidate for, we
// decompile that ctor and walk its body for direct field-initialization
// writes on the ctor's own "this" parameter -- either the raw-pointer-cast
// shape Hex-Rays sometimes leaves un-simplified ("*(_DWORD *)(a1 + 140) =
// 200;") or the already-member-accessed shape it produces once it infers a
// partial struct ("a1->field_8C = 200;"). From those writes we synthesize a
// best-effort `struct` type and register it into Local Types -- but we
// deliberately never retype any lvar/parameter/global with it. A wrong
// guess (a misclassified field width, or two constructors of the same class
// writing genuinely different shapes) would silently corrupt decompilation
// everywhere that type got applied; leaving it as a reviewable Local Type
// the user can inspect and apply by hand (right-click "Set lvar type") is
// the safe default for a v1 heuristic like this.

#include "struct_synth.h"
#include "rtti_scan.h" // find_callers_of()

#include <funcs.hpp>
#include <hexrays.hpp>
#include <typeinf.hpp>
#include <name.hpp>

#include <algorithm>

namespace
{

constexpr const char *SYNTHETIC_PREFIX = "__sm_layout_";

const cexpr_t *skip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

// One recorded direct field write on the ctor's "this" parameter.
struct field_write_t
{
  uint64 offset = 0;
  int width = 0;
  bool is_pointer = false;
};

// Finds every "*(TYPE*)(this + N) = expr;" / "this->field = expr;" style
// write in ctor_ea's body, recording (offset, width, is_pointer) for each.
// Anything not cleanly shaped as "this + literal" (another variable, a
// multiply/array index, or a negative offset) is silently skipped -- out of
// v1's scope, not an error.
struct field_write_visitor_t final : public ctree_visitor_t
{
  int this_lvar_idx;
  qvector<field_write_t> writes;

  explicit field_write_visitor_t(int this_lvar_idx_)
    : ctree_visitor_t(CV_FAST), this_lvar_idx(this_lvar_idx_) {}

  // Matches "this + N" or "N + this" (after stripping casts), rejecting
  // anything else (another variable, multiply/array-index shapes, negative
  // literals).
  bool match_this_plus_offset(const cexpr_t *e, uint64 *out_offset) const
  {
    e = skip_casts(e);
    if ( e == nullptr || e->op != cot_add )
      return false;

    const cexpr_t *a = skip_casts(e->x);
    const cexpr_t *b = skip_casts(e->y);
    const cexpr_t *num = nullptr;
    const cexpr_t *var = nullptr;
    if ( a != nullptr && a->op == cot_var && a->v.idx == this_lvar_idx
      && b != nullptr && b->op == cot_num )
    {
      var = a;
      num = b;
    }
    else if ( b != nullptr && b->op == cot_var && b->v.idx == this_lvar_idx
      && a != nullptr && a->op == cot_num )
    {
      var = b;
      num = a;
    }
    else
    {
      return false;
    }
    (void)var;

    if ( num->is_negative_const() )
      return false; // negative offset -- out of v1 scope, just skip

    *out_offset = num->numval();
    return true;
  }

  void record_write(uint64 offset, const tinfo_t &deref_type)
  {
    int width = int(deref_type.get_size());
    if ( width <= 0 )
      return; // couldn't size the deref'd type -- nothing usable to record

    field_write_t fw;
    fw.offset = offset;
    fw.width = width;
    fw.is_pointer = deref_type.is_ptr();
    writes.push_back(fw);
  }

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op != cot_asg )
      return 0;

    cexpr_t *lhs = e->x;

    // Form 1: *(TYPE*)(this + N) = expr; -- also covers the offset-0 case,
    // where Hex-Rays renders the address as bare "this" with no "+ 0" cot_add
    // node at all (verified against a real ctor: "*(_QWORD *)a1 = &vtable;"
    // has no add node, unlike every other offset in the same function).
    if ( lhs->op == cot_ptr )
    {
      const cexpr_t *inner = skip_casts(lhs->x);
      if ( inner != nullptr && inner->op == cot_var && inner->v.idx == this_lvar_idx )
      {
        record_write(0, lhs->type);
      }
      else
      {
        uint64 offset;
        if ( match_this_plus_offset(lhs->x, &offset) )
          record_write(offset, lhs->type);
      }
      return 0;
    }

    // Form 2: already-member-accessed this->field = expr; (Hex-Rays
    // sometimes synthesizes a partial struct access instead of leaving raw
    // pointer arithmetic -- accept either shape).
    if ( lhs->op == cot_memptr || lhs->op == cot_memref )
    {
      const cexpr_t *obj = skip_casts(lhs->x);
      if ( obj != nullptr && obj->op == cot_var && obj->v.idx == this_lvar_idx )
        record_write(lhs->m, lhs->type);
      return 0;
    }

    return 0;
  }
};

// Looks for the first "operator new"/"operator new[]" call site, with a
// constant size argument, among ctor_ea's direct callers' decompiled
// bodies. This is a small, focused re-derivation of the "find the
// allocation size" idea -- NOT a reuse of the existing singleton-chain
// feature's resolve_allocator_chain(), which is scoped to finding a global
// store, not a `new` call's size argument. Tolerates not finding one.
struct operator_new_size_visitor_t final : public ctree_visitor_t
{
  bool found = false;
  uint64 found_size = 0;

  operator_new_size_visitor_t() : ctree_visitor_t(CV_FAST) {}

  static bool is_operator_new_callee(ea_t callee_ea)
  {
    qstring name;
    if ( get_short_name(&name, callee_ea) <= 0 )
      return false;
    return name.find("operator new") != qstring::npos;
  }

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( found )
      return 1; // already have an answer, stop walking

    if ( e->op != cot_call )
      return 0;

    const cexpr_t *callee = skip_casts(e->x);
    if ( callee == nullptr || callee->op != cot_obj )
      return 0;
    if ( !is_operator_new_callee(callee->obj_ea) )
      return 0;

    if ( e->a == nullptr || e->a->empty() )
      return 0;

    const cexpr_t *arg0 = skip_casts(&(*e->a)[0]);
    if ( arg0 == nullptr || arg0->op != cot_num )
      return 0;

    found_size = arg0->numval();
    found = true;
    return 1;
  }
};

// Tries to find a constant `operator new(SIZE)` call among ctor_ea's direct
// callers. Returns false (no *out_size written) if none is found -- this is
// tolerated, not an error.
bool find_allocation_size(ea_t ctor_ea, uint64 *out_size)
{
  qvector<ea_t> callers = find_callers_of(ctor_ea);
  for ( ea_t caller_ea : callers )
  {
    func_t *pfn = get_func(caller_ea);
    if ( pfn == nullptr )
      continue;

    hexrays_failure_t hf;
    cfuncptr_t cf = decompile_func(pfn, &hf);
    if ( cf == nullptr )
      continue;

    operator_new_size_visitor_t visitor;
    visitor.apply_to(&cf->body, nullptr);
    if ( visitor.found )
    {
      *out_size = visitor.found_size;
      return true;
    }
  }
  return false;
}

// One member slated for the synthesized struct, in final offset order.
struct planned_member_t
{
  uint64 offset = 0;
  int width = 0;
  bool is_pointer = false;
  bool is_vfptr = false;
  bool is_gap = false;
};

qstring sanitize_type_name(const qstring &class_name)
{
  qstring name = SYNTHETIC_PREFIX;
  for ( size_t i = 0; i < class_name.length(); ++i )
  {
    char c = class_name[i];
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
           || (c >= '0' && c <= '9') || c == '_';
    name.append(ok ? c : '_');
  }
  return name;
}

// Builds a tinfo_t for a real (non-gap, non-vfptr) field from its recorded
// width/is_pointer, or returns false (unsupported width -- out of v1 scope)
// if width isn't one of {1, 2, 4, 8}.
bool build_field_type(int width, bool is_pointer, tinfo_t *out)
{
  if ( width == 8 && is_pointer )
  {
    tinfo_t voidt;
    if ( !voidt.create_simple_type(BTF_VOID) )
      return false;
    return out->create_ptr(voidt);
  }

  type_t base;
  switch ( width )
  {
    case 1: base = BTF_UINT8;  break;
    case 2: base = BTF_UINT16; break;
    case 4: base = BTF_UINT32; break;
    case 8: base = BTF_UINT64; break;
    default: return false;
  }
  return out->create_simple_type(base);
}

bool build_gap_type(uint64 gap_size, tinfo_t *out)
{
  tinfo_t bytet;
  if ( !bytet.create_simple_type(BTF_UINT8) )
    return false;
  return out->create_array(bytet, uint32(gap_size));
}

} // namespace

layout_synth_result_t synthesize_struct_layout(
    ea_t ctor_ea,
    const qstring &class_name,
    ea_t vft_ea,
    bool is_polymorphic)
{
  layout_synth_result_t result;
  result.class_name = class_name;
  result.ctor_ea = ctor_ea;

  func_t *pfn = get_func(ctor_ea);
  if ( pfn == nullptr )
  {
    result.reason = "constructor candidate has no containing function";
    return result;
  }

  hexrays_failure_t hf;
  cfuncptr_t cf = decompile_func(pfn, &hf);
  if ( cf == nullptr )
  {
    result.reason = "decompilation of constructor candidate failed";
    return result;
  }

  // Same technique used elsewhere in this plugin (e.g.
  // find_self_registered_global in ctree_analysis.cpp): the ctor's "this"
  // is its first is_arg_var() lvar.
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
    result.reason = "constructor has no argument lvars (no 'this' parameter found)";
    return result;
  }

  field_write_visitor_t visitor(this_lvar_idx);
  visitor.apply_to(&cf->body, nullptr);

  if ( visitor.writes.empty() )
  {
    result.reason = "no direct field-initialization writes found on constructor's 'this' parameter";
    return result;
  }

  // Dedupe exact duplicates (same offset+width+is_pointer -- e.g. written
  // twice), then sort by offset for the overlap/gap pass.
  qvector<field_write_t> &writes = visitor.writes;
  std::sort(
      writes.begin(), writes.end(),
      [](const field_write_t &a, const field_write_t &b)
      {
        if ( a.offset != b.offset )
          return a.offset < b.offset;
        return a.width < b.width;
      });

  qvector<field_write_t> deduped;
  for ( const field_write_t &fw : writes )
  {
    if ( !deduped.empty()
      && deduped.back().offset == fw.offset
      && deduped.back().width == fw.width
      && deduped.back().is_pointer == fw.is_pointer )
    {
      continue; // exact duplicate write, drop it
    }
    deduped.push_back(fw);
  }

  // Overlap detection: any two recorded (differently-shaped or not) writes
  // whose [offset, offset+width) ranges intersect means we can't trust the
  // layout -- drop the whole class rather than guess.
  uint64 running_end = 0;
  bool first = true;
  for ( const field_write_t &fw : deduped )
  {
    if ( !first && fw.offset < running_end )
    {
      result.reason.sprnt(
          "overlapping/conflicting field writes at offset 0x%llx",
          (unsigned long long)fw.offset);
      return result;
    }
    running_end = std::max<uint64>(running_end, fw.offset + fw.width);
    first = false;
  }

  // Validate widths up front -- unsupported widths take the whole class out
  // of v1's scope (rather than silently dropping just that one field).
  for ( const field_write_t &fw : deduped )
  {
    if ( fw.width != 1 && fw.width != 2 && fw.width != 4 && fw.width != 8 )
    {
      result.reason.sprnt(
          "unsupported field width %d at offset 0x%llx",
          fw.width,
          (unsigned long long)fw.offset);
      return result;
    }
  }

  qvector<planned_member_t> planned;
  bool offset0_covered = !deduped.empty() && deduped[0].offset == 0;

  if ( is_polymorphic && !offset0_covered )
  {
    planned_member_t vfptr;
    vfptr.offset = 0;
    vfptr.width = 8;
    vfptr.is_pointer = true;
    vfptr.is_vfptr = true;
    planned.push_back(vfptr);
  }

  for ( const field_write_t &fw : deduped )
  {
    planned_member_t m;
    m.offset = fw.offset;
    m.width = fw.width;
    m.is_pointer = fw.is_pointer;
    planned.push_back(m);
  }

  std::sort(
      planned.begin(), planned.end(),
      [](const planned_member_t &a, const planned_member_t &b)
      {
        return a.offset < b.offset;
      });

  // Total object size: an operator new(SIZE) call among the ctor's direct
  // callers, if one is found, tells us the true end of the object so we can
  // add one final trailing padding member. Not finding one is tolerated --
  // we just size the struct to the last recorded field's end offset.
  uint64 alloc_size = 0;
  bool have_alloc_size = find_allocation_size(ctor_ea, &alloc_size);

  udt_type_data_t udt;
  udt.is_union = false;

  uint64 next_offset = 0;
  int gap_index = 0;
  for ( const planned_member_t &m : planned )
  {
    if ( m.offset > next_offset )
    {
      uint64 gap_size = m.offset - next_offset;
      tinfo_t gap_type;
      if ( !build_gap_type(gap_size, &gap_type) )
      {
        result.reason.sprnt("failed to build padding type for gap at offset 0x%llx", (unsigned long long)next_offset);
        return result;
      }
      qstring gap_name;
      gap_name.sprnt("gap_0x%llx", (unsigned long long)next_offset);
      udt.add_member(gap_name.c_str(), gap_type, next_offset * 8);
      ++gap_index;
    }

    tinfo_t field_type;
    if ( m.is_vfptr )
    {
      if ( !field_type.create_ptr(tinfo_t(BTF_VOID)) )
      {
        result.reason = "failed to build vfptr member type";
        return result;
      }
      udt.add_member("vfptr", field_type, m.offset * 8);
    }
    else
    {
      if ( !build_field_type(m.width, m.is_pointer, &field_type) )
      {
        result.reason.sprnt("failed to build field type for offset 0x%llx", (unsigned long long)m.offset);
        return result;
      }
      qstring field_name;
      field_name.sprnt("field_0x%llx", (unsigned long long)m.offset);
      udt.add_member(field_name.c_str(), field_type, m.offset * 8);
    }

    next_offset = m.offset + m.width;
  }

  if ( have_alloc_size && alloc_size > next_offset )
  {
    uint64 gap_size = alloc_size - next_offset;
    tinfo_t gap_type;
    if ( build_gap_type(gap_size, &gap_type) )
    {
      qstring gap_name;
      gap_name.sprnt("gap_0x%llx", (unsigned long long)next_offset);
      udt.add_member(gap_name.c_str(), gap_type, next_offset * 8);
      next_offset = alloc_size;
    }
    // If building the trailing pad type somehow fails, just leave the
    // struct sized to the last recorded field -- no guessing further.
  }

  tinfo_t struct_type;
  if ( !struct_type.create_udt(udt) )
  {
    result.reason = "tinfo_t::create_udt failed";
    return result;
  }

  qstring type_name = sanitize_type_name(class_name);
  if ( struct_type.set_named_type(nullptr, type_name.c_str(), NTF_TYPE | NTF_REPLACE) != TERR_OK )
  {
    result.reason = "tinfo_t::set_named_type failed";
    return result;
  }

  result.type_name = type_name;
  result.resolved = true;
  return result;
}

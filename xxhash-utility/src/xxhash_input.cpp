// MSVC std::string layout constants (x64), duplicated locally from
// IDA-STL-Utility/src/stl_string.cpp rather than depending on that plugin
// being installed -- this plugin must work standalone in a fresh idb.
//   struct basic_string {          // sizeof == 0x20
//     union _Bxty { char _Buf[16]; char *_Ptr; } _Bx;  // offset 0x00
//     size_t _Mysize;                                  // offset 0x10
//     size_t _Myres;                                   // offset 0x18
//   };

#include "xxhash_input.h"
#include "xxhash_common.h"

#include <vector>

namespace xxhash_utility
{

namespace
{

constexpr uint64 BX_PTR_OFFSET = 0x00;
constexpr uint64 MYSIZE_OFFSET = 0x10;
constexpr uint64 MYRES_OFFSET = 0x18;

struct member_hit_t
{
  const cexpr_t *expr;
  member_access_t access;
};

struct member_collector_t : public ctree_visitor_t
{
  std::vector<member_hit_t> hits;
  std::vector<const cexpr_t *> asg_targets;
  std::vector<const cexpr_t *> asg_sources;

  member_collector_t() : ctree_visitor_t(CV_FAST) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op == cot_memref || e->op == cot_memptr )
    {
      member_access_t access = resolve_member_access(e);
      if ( access.ok )
        hits.push_back({ e, access });
    }
    else if ( e->op == cot_asg )
    {
      asg_targets.push_back(e->x);
      asg_sources.push_back(e->y);
    }
    return 0;
  }
};

} // namespace

bool try_resolve_string_input(cinsn_t *scope, xxhash_input_t *out)
{
  member_collector_t collector;
  collector.apply_to(scope, nullptr);

  const cexpr_t *mysize_expr = nullptr;
  match_identity_t base;
  bool have_myres = false;

  for ( const member_hit_t &hit : collector.hits )
  {
    if ( hit.access.offset == MYSIZE_OFFSET )
    {
      mysize_expr = hit.expr;
      base = hit.access.base;
    }
  }
  if ( mysize_expr == nullptr )
    return false;

  for ( const member_hit_t &hit : collector.hits )
  {
    if ( hit.access.offset == MYRES_OFFSET && hit.access.base == base )
      have_myres = true;
  }
  if ( !have_myres )
    return false;

  // Find a variable that's assigned the base's own address (the small/SSO
  // arm) somewhere in scope -- the pointer-selection variable.
  match_identity_t ptr_var;
  bool have_ptr_var = false;
  for ( size_t i = 0; i < collector.asg_targets.size(); ++i )
  {
    const cexpr_t *source = strip_casts(collector.asg_sources[i]);
    if ( source == nullptr )
      continue;

    bool is_base_address = false;
    if ( source->op == cot_ref )
    {
      const match_identity_t addressed = identify(source->x);
      is_base_address = addressed.valid() && addressed == base;
    }
    else
    {
      const member_access_t access = resolve_member_access(source);
      is_base_address = access.ok && access.offset == BX_PTR_OFFSET && access.base == base;
    }

    if ( is_base_address )
    {
      const match_identity_t target = identify(collector.asg_targets[i]);
      if ( target.valid() )
      {
        ptr_var = target;
        have_ptr_var = true;
        break;
      }
    }
  }
  if ( !have_ptr_var )
    return false;

  // Recover the actual pointer expression to hand back: the assignment
  // target's own expression is fine as a representative reference (it will
  // be cloned before use, per xxhash_synth's contract).
  const cexpr_t *ptr_expr = nullptr;
  for ( size_t i = 0; i < collector.asg_targets.size(); ++i )
  {
    const match_identity_t target = identify(collector.asg_targets[i]);
    if ( target.valid() && target == ptr_var )
    {
      ptr_expr = collector.asg_targets[i];
      break;
    }
  }
  if ( ptr_expr == nullptr )
    return false;

  out->data_ptr = ptr_expr;
  out->length = mysize_expr;
  return true;
}

bool try_resolve_raw_buffer_input(
      const cexpr_t *candidate_ptr,
      const cexpr_t *candidate_length,
      xxhash_input_t *out)
{
  if ( candidate_ptr == nullptr || candidate_length == nullptr )
    return false;

  // Reject if the length expression is actually a std::string's _Mysize
  // member -- that case belongs to try_resolve_string_input instead.
  const member_access_t access = resolve_member_access(candidate_length);
  if ( access.ok && access.offset == MYSIZE_OFFSET )
    return false;

  out->data_ptr = candidate_ptr;
  out->length = candidate_length;
  return true;
}

} // namespace xxhash_utility

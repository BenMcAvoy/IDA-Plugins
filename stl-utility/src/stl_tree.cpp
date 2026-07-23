// MSVC std::map/std::set/std::multimap/std::multiset descriptor -- v1
// STUB. These are red-black trees (_Tree<_Traits>) with per-node
// {_Left,_Parent,_Right,_Color,_Isnil,_Myval} layout that varies with the
// templated value type at a variable offset; full node/iterator traversal
// is deferred to v2. For now this only exposes the tree's header:
//
//   struct _Tree_val_header {   // sizeof == 0x10 (approximate/generic)
//     _Tree_node *_Myhead;      // offset 0x00 -- sentinel/root anchor
//     size_t _Mysize;           // offset 0x08 -- element count
//   };
//
// giving a one-click retype that at least reports element count and the
// root/sentinel address, without attempting to walk the tree.

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_util.h"

#include <typeinf.hpp>

#include <cstring>

namespace stl_utility
{

namespace
{

constexpr size_t STRUCT_SIZE = 0x10;
constexpr size_t MYHEAD_OFFSET = 0x00;
constexpr size_t MYSIZE_OFFSET = 0x08;
constexpr const char *SYNTHETIC_NAME = "__stl_tree_header_generic";

bool build_or_get_type_impl(til_t *, const tinfo_t *, const qstring *, tinfo_t *out_type, qstring *out_name)
{
  tinfo_t existing;
  if ( existing.get_named_type(nullptr, SYNTHETIC_NAME, BTF_STRUCT) && existing.get_size() == STRUCT_SIZE )
  {
    *out_type = existing;
    *out_name = SYNTHETIC_NAME;
    return true;
  }

  tinfo_t void_type, void_ptr, size_type;
  if ( !void_type.create_simple_type(BTF_VOID) || !void_ptr.create_ptr(void_type)
    || !size_type.create_simple_type(BTF_UINT64) )
  {
    return false;
  }

  udt_type_data_t p;
  p.is_union = false;
  p.add_member("_Myhead", void_ptr, MYHEAD_OFFSET * 8);
  p.add_member("_Mysize", size_type, MYSIZE_OFFSET * 8);

  tinfo_t built;
  if ( !built.create_udt(p) )
    return false;

  debug_log("stl_tree: building synthetic header type '%s'", SYNTHETIC_NAME);
  if ( built.set_named_type(nullptr, SYNTHETIC_NAME, NTF_REPLACE) != TERR_OK )
    return false;

  tinfo_t saved;
  if ( saved.get_named_type(nullptr, SYNTHETIC_NAME, BTF_STRUCT) && saved.get_size() == STRUCT_SIZE )
    *out_type = saved;
  else
    *out_type = built;
  *out_name = SYNTHETIC_NAME;
  return true;
}

match_confidence_t matches_impl(const tinfo_t *existing_type, const qstring *demangled_name_hint)
{
  if ( demangled_name_hint != nullptr )
  {
    static const char *const markers[] = { "map<", "set<", "multimap<", "multiset<" };
    for ( const char *marker : markers )
    {
      if ( demangled_name_hint->find(marker) != qstring::npos )
        return MATCH_HIGH;
    }

    if ( *demangled_name_hint == SYNTHETIC_NAME )
      return MATCH_HIGH;
  }

  if ( existing_type != nullptr && !existing_type->empty() && existing_type->get_size() == STRUCT_SIZE )
    return MATCH_AMBIGUOUS;

  return MATCH_NONE;
}

stl_decode_result_t decode_preview_impl(ea_t instance_ea, const tinfo_t &)
{
  stl_decode_result_t result;

  if ( instance_ea == BADADDR )
  {
    result.ok = true;
    result.preview = "(no fixed address)";
    return result;
  }

  const stl_read_result_t header = stl_read_memory(instance_ea, STRUCT_SIZE);
  if ( !header.ok )
  {
    result.ok = true;
    result.preview = looks_like_stack_address(instance_ea)
      ? qstring("(stack-local, attach debugger to preview)")
      : qstring("(unable to read memory)");
    return result;
  }

  ea_t head = BADADDR;
  uint64 size = 0;
  std::memcpy(&head, header.data.begin() + MYHEAD_OFFSET, sizeof(ea_t));
  std::memcpy(&size, header.data.begin() + MYSIZE_OFFSET, sizeof(size));

  result.from_live_memory = header.from_debugger;
  result.ok = true;
  result.preview.sprnt(
    "count=%" FMT_64 "u root=%a (header only, node traversal not supported in v1)",
    uint64(size),
    head);
  return result;
}

const stl_type_descriptor_t TREE_DESCRIPTOR =
{
  "std_tree_header", "std::map/set (header only, v1 stub)",
  &matches_impl, &build_or_get_type_impl, &decode_preview_impl
};

} // namespace

void register_stl_tree_descriptors(std::vector<const stl_type_descriptor_t *> *out)
{
  out->push_back(&TREE_DESCRIPTOR);
}

} // namespace stl_utility

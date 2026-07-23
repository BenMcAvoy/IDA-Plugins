// MSVC std::unordered_map/std::unordered_set descriptor -- v1 STUB, header
// stats only. Both containers share the same underlying `_Hash<_Traits>`
// layout (only the value_type differs), so this is ONE descriptor covering
// both, mirroring src/stl_tree.cpp's precedent of covering
// map/set/multimap/multiset with a single descriptor.
//
// Layout derived from the REAL MSVC STL header source (confirmed by reading
// it directly, not just trusting a summary):
//   C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\
//   14.44.35207\include\xhash, class `_Hash`, around line 2009-2019:
//
//   class _Hash {
//     _Traits _Traitsobj;    // _Umap_traits -> _Uhash_compare ->
//                            // _Compressed_pair<Hasher, _Compressed_pair<
//                            // Keyeq, float>>. For the common case
//                            // (stateless std::hash<K>/std::equal_to<K>),
//                            // EBO collapses this down to JUST the trailing
//                            // `float` (max_load_factor, default 1.0f) --
//                            // everything else is zero-sized.
//     _Mylist _List;          // = std::list<pair<const Kty,Ty>, Alloc> --
//                            // a REAL embedded std::list object:
//                            // {_Myhead (node ptr), _Mysize (size_t)} for a
//                            // stateless allocator (standard list layout).
//     _Hash_vec<_Aliter> _Vec; // vector-shaped bucket array:
//                            // {_Myfirst,_Mylast,_Myend} pointers (standard
//                            // vector layout, Release/_ITERATOR_DEBUG_LEVEL
//                            // =0 build, no _Myproxy field); each element a
//                            // pair<node*,node*> (16 bytes) denoting one
//                            // bucket's [begin,end) range.
//     size_type _Mask;        // bucket_count - 1
//     size_type _Maxidx;      // current max bucket count, power of 2
//   };
//
// The ONE uncertain detail was the exact padding after the leading `float`
// in `_Traitsobj` before `_List` starts (which needs 8-byte alignment for
// its pointer member). Standard-layout C++ rules mean the compiler lays out
// `_Traitsobj` (just a 4-byte float after EBO) at offset 0, then pads to the
// next 8-byte boundary before `_List` begins at offset 8:
//
//   offset 0x00: float    _MaxLoadFactor   (4 bytes; 4 bytes trailing pad)
//   offset 0x08: void*    _List_Myhead
//   offset 0x10: size_t   _List_Mysize
//   offset 0x18: void*    _Vec_Myfirst     (bucket-pair array begin)
//   offset 0x20: void*    _Vec_Mylast
//   offset 0x28: void*    _Vec_Myend
//   offset 0x30: size_t   _Mask
//   offset 0x38: size_t   _Maxidx
//   sizeof == 0x40
//
// IMPORTANT, unlike this plugin's other descriptors: this layout is
// header-derived and UNVERIFIED against a live binary. ScrapMechanic.exe
// (this plugin's usual real-world test target) was confirmed via MCP search
// to have NO real std::unordered_map/std::unordered_set usage anywhere --
// it uses Bullet Physics' own unrelated btHashMap instead -- so there is no
// decompiled ground-truth instance to verify this against. Compensate by
// being extra defensive: build_or_get_type_impl() below explicitly checks
// the built type's final get_size() against the expected 0x40 and logs a
// warning (rather than silently proceeding) if it doesn't match.
//
// Scope, matching src/stl_tree.cpp's precedent: header stats only (element
// count, bucket count, max load factor). Full linked-list node traversal
// (walking `_List`'s node chain, each node `{Next,Prev,pair<K,V>}`, to dump
// keys/values) requires live memory reads and is deferred to a v2 pass, NOT
// attempted here. A release/destructor collapse for unordered_map is also
// out of scope for this pass -- unlike vector's trivial-element shortcut,
// unordered_map's teardown is a substantially more complex per-node
// destruction loop that isn't safe to pattern-match yet.

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_util.h"

#include <typeinf.hpp>

#include <cstring>

namespace stl_utility
{

namespace
{

constexpr size_t STRUCT_SIZE = 0x40;
constexpr size_t MAXLOADFACTOR_OFFSET = 0x00;
constexpr size_t LIST_MYHEAD_OFFSET = 0x08;
constexpr size_t LIST_MYSIZE_OFFSET = 0x10;
constexpr size_t VEC_MYFIRST_OFFSET = 0x18;
constexpr size_t VEC_MYLAST_OFFSET = 0x20;
constexpr size_t VEC_MYEND_OFFSET = 0x28;
constexpr size_t MASK_OFFSET = 0x30;
constexpr size_t MAXIDX_OFFSET = 0x38;
constexpr const char *SYNTHETIC_NAME = "__stl_unordered_map_header";

bool build_or_get_type_impl(til_t *, const tinfo_t *, const qstring *, tinfo_t *out_type, qstring *out_name)
{
  tinfo_t existing;
  if ( existing.get_named_type(nullptr, SYNTHETIC_NAME, BTF_STRUCT) && existing.get_size() == STRUCT_SIZE )
  {
    *out_type = existing;
    *out_name = SYNTHETIC_NAME;
    return true;
  }

  tinfo_t float_type, void_type, void_ptr, size_type, pad_type;
  if ( !float_type.create_simple_type(BTF_FLOAT)
    || !void_type.create_simple_type(BTF_VOID)
    || !void_ptr.create_ptr(void_type)
    || !size_type.create_simple_type(BTF_UINT64)
    || !pad_type.create_simple_type(BTF_UINT32) )
  {
    return false;
  }

  udt_type_data_t p;
  p.is_union = false;
  p.add_member("_MaxLoadFactor", float_type, MAXLOADFACTOR_OFFSET * 8);
  // Explicit anonymous padding member rather than relying on inferred
  // alignment -- an explicit field is safer than trusting create_udt()'s
  // padding inference given the "one uncertain detail" this whole layout
  // hinges on (see the file-level comment above).
  p.add_member("_Pad0", pad_type, 0x04 * 8);
  p.add_member("_List_Myhead", void_ptr, LIST_MYHEAD_OFFSET * 8);
  p.add_member("_List_Mysize", size_type, LIST_MYSIZE_OFFSET * 8);
  // Bucket-array elements (pair<node*,node*>) are an opaque internal type
  // not useful to expose as a real pointer-to-something -- void* instead.
  p.add_member("_Vec_Myfirst", void_ptr, VEC_MYFIRST_OFFSET * 8);
  p.add_member("_Vec_Mylast", void_ptr, VEC_MYLAST_OFFSET * 8);
  p.add_member("_Vec_Myend", void_ptr, VEC_MYEND_OFFSET * 8);
  p.add_member("_Mask", size_type, MASK_OFFSET * 8);
  p.add_member("_Maxidx", size_type, MAXIDX_OFFSET * 8);

  tinfo_t built;
  if ( !built.create_udt(p) )
    return false;

  debug_log("stl_unordered_map: building synthetic header type '%s'", SYNTHETIC_NAME);
  if ( built.set_named_type(nullptr, SYNTHETIC_NAME, NTF_REPLACE) != TERR_OK )
    return false;

  tinfo_t saved;
  const bool have_saved = saved.get_named_type(nullptr, SYNTHETIC_NAME, BTF_STRUCT);
  const tinfo_t &final_type = have_saved ? saved : built;

  // This layout is header-derived and unverified against a live binary (see
  // file-level comment): make any padding/alignment mistake immediately
  // visible in the log rather than silently corrupting previews.
  if ( final_type.get_size() != STRUCT_SIZE )
  {
    debug_log(
      "stl_unordered_map: WARNING built type '%s' has size 0x%llX, expected 0x%llX -- "
      "layout assumption may be wrong",
      SYNTHETIC_NAME,
      uint64(final_type.get_size()),
      uint64(STRUCT_SIZE));
  }

  *out_type = final_type;
  *out_name = SYNTHETIC_NAME;
  return true;
}

match_confidence_t matches_impl(const tinfo_t *existing_type, const qstring *demangled_name_hint)
{
  if ( demangled_name_hint != nullptr )
  {
    static const char *const markers[] = { "unordered_map<", "unordered_set<" };
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

  float max_load_factor = 0.0f;
  uint64 list_size = 0;
  uint64 mask = 0;
  std::memcpy(&max_load_factor, header.data.begin() + MAXLOADFACTOR_OFFSET, sizeof(max_load_factor));
  std::memcpy(&list_size, header.data.begin() + LIST_MYSIZE_OFFSET, sizeof(list_size));
  std::memcpy(&mask, header.data.begin() + MASK_OFFSET, sizeof(mask));

  result.from_live_memory = header.from_debugger;
  result.ok = true;
  result.preview.sprnt(
    "size=%" FMT_64 "u buckets=%" FMT_64 "u max_load_factor=%.2f "
    "(header only, node traversal not supported)",
    list_size,
    mask + 1,
    double(max_load_factor));
  return result;
}

const stl_type_descriptor_t UNORDERED_MAP_DESCRIPTOR =
{
  "std_unordered_map_header", "std::unordered_map/unordered_set (header only, v1 stub)",
  &matches_impl, &build_or_get_type_impl, &decode_preview_impl
};

} // namespace

void register_stl_unordered_map_descriptors(std::vector<const stl_type_descriptor_t *> *out)
{
  out->push_back(&UNORDERED_MAP_DESCRIPTOR);
}

} // namespace stl_utility

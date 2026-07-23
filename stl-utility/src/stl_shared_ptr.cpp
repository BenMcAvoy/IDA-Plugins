// MSVC std::shared_ptr<T>/std::weak_ptr<T> descriptor. Layout (x64,
// VS2019/2022 ABI), per microsoft/STL's memory header:
//
//   struct shared_ptr<T> {           // sizeof == 0x10
//     T *_Ptr;                       // offset 0x00 -- raw pointer to managed object
//     _Ref_count_base *_Rep;         // offset 0x08 -- control block pointer
//   };
//   // weak_ptr<T> has the identical {_Ptr, _Rep} layout.
//
//   struct _Ref_count_base {         // control block header, stable across
//     void **vfptr;                  // offset 0x00    make_shared/new-T flavors
//     long _Uses;                    // offset 0x08 -- strong refcount
//     long _Weaks;                   // offset 0x0C -- weak refcount
//   };
//
// The element type T isn't needed to read refcounts (decode_preview only
// reads the control block's raw bytes at fixed offsets), but it IS needed
// for the applied _Ptr field to be useful for navigation/further typing in
// Hex-Rays, so it's recovered the same way stl_vector.cpp/stl_unique_ptr.cpp
// do: existing type info first, then the demangled name hint, then prompt.

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_util.h"

#include <kernwin.hpp>
#include <typeinf.hpp>

#include <cctype>
#include <cstdint>
#include <cstring>
#include <string>

namespace stl_utility
{

namespace
{

constexpr size_t STRUCT_SIZE = 0x10;
constexpr size_t PTR_OFFSET = 0x00;
constexpr size_t REP_OFFSET = 0x08;
constexpr size_t USES_OFFSET = 0x08;
constexpr size_t WEAKS_OFFSET = 0x0C;
constexpr size_t CONTROL_BLOCK_READ_SIZE = 0x10;

struct ptr_kind_t
{
  bool is_weak;
  const char *key;
  const char *display_name;
  const char *marker;            // "shared_ptr<" / "weak_ptr<"
  const char *synthetic_prefix;  // "__stl_shared_ptr_of_" / "__stl_weak_ptr_of_"
};

const ptr_kind_t SHARED_KIND =
  { false, "std_shared_ptr", "std::shared_ptr<T>", "shared_ptr<", "__stl_shared_ptr_of_" };
const ptr_kind_t WEAK_KIND =
  { true, "std_weak_ptr", "std::weak_ptr<T>", "weak_ptr<", "__stl_weak_ptr_of_" };

std::string extract_element_type_name(const ptr_kind_t &kind, const qstring *hint)
{
  if ( hint == nullptr )
    return {};

  const std::string text(hint->c_str());
  const size_t marker = text.find(kind.marker);
  if ( marker == std::string::npos )
    return {};

  const size_t args_start = marker + std::strlen(kind.marker);
  int depth = 1;
  size_t cursor = args_start;
  size_t first_comma = std::string::npos;
  for ( ; cursor < text.size() && depth > 0; ++cursor )
  {
    if ( text[cursor] == '<' )
      ++depth;
    else if ( text[cursor] == '>' )
      --depth;
    else if ( text[cursor] == ',' && depth == 1 && first_comma == std::string::npos )
      first_comma = cursor;
  }
  if ( depth != 0 )
    return {};

  const size_t args_end = first_comma != std::string::npos ? first_comma : cursor - 1;
  if ( args_end <= args_start )
    return {};

  std::string element = text.substr(args_start, args_end - args_start);
  size_t begin = 0;
  size_t end = element.size();
  while ( begin < end && std::isspace(static_cast<unsigned char>(element[begin])) != 0 )
    ++begin;
  while ( end > begin && std::isspace(static_cast<unsigned char>(element[end - 1])) != 0 )
    --end;
  return element.substr(begin, end - begin);
}

bool resolve_element_type(
      const ptr_kind_t &kind,
      const tinfo_t *existing_type,
      const qstring *demangled_name_hint,
      tinfo_t *out_element,
      qstring *out_element_name)
{
  // 1. If IDA already knows a UDT shaped like {T *_Ptr; ...}, recover T
  //    from that member's pointee.
  if ( existing_type != nullptr && !existing_type->empty() && existing_type->is_udt() )
  {
    udt_type_data_t udt;
    if ( existing_type->get_udt_details(&udt) && !udt.empty() && udt[0].type.is_ptr() )
    {
      tinfo_t pointee = udt[0].type.get_pointed_object();
      if ( !pointee.empty() )
      {
        *out_element = pointee;
        *out_element_name = printable_type_name(pointee);
        return true;
      }
    }
  }

  // 2. Parse "shared_ptr<T,...>"/"weak_ptr<T,...>" from the demangled hint.
  const std::string extracted = extract_element_type_name(kind, demangled_name_hint);
  if ( !extracted.empty() && parse_type_string(extracted.c_str(), out_element) )
  {
    *out_element_name = extracted.c_str();
    return true;
  }

  // 3. Prompt the user for the element type.
  qstring typed;
  if ( ask_str(&typed, HIST_TYPE, "%s element type (e.g. \"int\", \"MyStruct\"):", kind.display_name)
    && parse_type_string(typed.c_str(), out_element) )
  {
    *out_element_name = typed;
    return true;
  }

  return false;
}

// Registers a small documentation-only Local Type for the shared control
// block (not applied to any variable -- decode_preview reads its bytes
// directly), so users can inspect the layout in Local Types if curious.
void ensure_control_block_type_registered()
{
  tinfo_t existing;
  if ( existing.get_named_type(nullptr, "__stl_ref_count_base", BTF_STRUCT) )
    return;

  tinfo_t void_type, void_ptr, void_ptr_ptr, long_type;
  if ( !void_type.create_simple_type(BTF_VOID) || !void_ptr.create_ptr(void_type)
    || !void_ptr_ptr.create_ptr(void_ptr) || !long_type.create_simple_type(BTF_INT32) )
  {
    return;
  }

  udt_type_data_t p;
  p.is_union = false;
  p.add_member("vfptr", void_ptr_ptr, 0);
  p.add_member("_Uses", long_type, USES_OFFSET * 8);
  p.add_member("_Weaks", long_type, WEAKS_OFFSET * 8);

  tinfo_t built;
  if ( built.create_udt(p) )
    built.set_named_type(nullptr, "__stl_ref_count_base", NTF_REPLACE);
}

bool build_or_get_type_impl(
      const ptr_kind_t &kind,
      const tinfo_t *existing_type,
      const qstring *demangled_name_hint,
      tinfo_t *out_type,
      qstring *out_name)
{
  tinfo_t element;
  qstring element_name;
  if ( !resolve_element_type(kind, existing_type, demangled_name_hint, &element, &element_name) )
  {
    debug_log("stl_shared_ptr: could not resolve element type, aborting retype");
    return false;
  }

  ensure_control_block_type_registered();

  tinfo_t rep_ptr, elem_ptr;
  {
    tinfo_t void_type;
    if ( !void_type.create_simple_type(BTF_VOID) || !rep_ptr.create_ptr(void_type) )
      return false;
  }
  if ( !elem_ptr.create_ptr(element) )
    return false;

  udt_type_data_t p;
  p.is_union = false;
  p.add_member("_Ptr", elem_ptr, PTR_OFFSET * 8);
  p.add_member("_Rep", rep_ptr, REP_OFFSET * 8);

  tinfo_t built;
  if ( !built.create_udt(p) )
    return false;

  qstring synthetic_name = kind.synthetic_prefix;
  for ( size_t i = 0; i < element_name.length(); ++i )
  {
    const char c = element_name[i];
    synthetic_name.append(std::isalnum(static_cast<unsigned char>(c)) != 0 ? c : '_');
  }

  debug_log("stl_shared_ptr: building synthetic type '%s'", synthetic_name.c_str());
  if ( built.set_named_type(nullptr, synthetic_name.c_str(), NTF_REPLACE) != TERR_OK )
    return false;

  tinfo_t saved;
  if ( saved.get_named_type(nullptr, synthetic_name.c_str(), BTF_STRUCT) && saved.get_size() == STRUCT_SIZE )
    *out_type = saved;
  else
    *out_type = built;
  *out_name = synthetic_name;
  return true;
}

match_confidence_t matches_impl(
      const ptr_kind_t &kind,
      const tinfo_t *existing_type,
      const qstring *demangled_name_hint)
{
  if ( demangled_name_hint != nullptr )
  {
    const bool has_shared = demangled_name_hint->find("shared_ptr<") != qstring::npos;
    const bool has_weak = demangled_name_hint->find("weak_ptr<") != qstring::npos;
    if ( has_shared || has_weak )
      return has_weak == kind.is_weak ? MATCH_HIGH : MATCH_NONE;

    // Recognize our own previously-applied synthetic "__stl_shared_ptr_of_*"
    // / "__stl_weak_ptr_of_*" type by name, so the preview keeps rendering
    // on later decompiles without re-running the retype action.
    if ( demangled_name_hint->find(kind.synthetic_prefix) == 0 )
      return MATCH_HIGH;
  }

  if ( existing_type != nullptr && !existing_type->empty() && existing_type->get_size() == STRUCT_SIZE )
    return MATCH_AMBIGUOUS;

  return MATCH_NONE;
}

stl_decode_result_t decode_preview_impl(const ptr_kind_t &kind, ea_t instance_ea, const tinfo_t &)
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

  ea_t rep = BADADDR;
  std::memcpy(&rep, header.data.begin() + REP_OFFSET, sizeof(ea_t));
  result.from_live_memory = header.from_debugger;

  if ( rep == BADADDR || rep == 0 )
  {
    result.ok = true;
    result.preview = kind.is_weak ? "expired/empty" : "empty";
    return result;
  }

  const stl_read_result_t control = stl_read_memory(rep, CONTROL_BLOCK_READ_SIZE);
  if ( !control.ok )
  {
    result.ok = true;
    result.preview.sprnt("rep=%a (heap, attach debugger to preview)", rep);
    return result;
  }

  int32_t uses = 0;
  int32_t weaks = 0;
  std::memcpy(&uses, control.data.begin() + USES_OFFSET, sizeof(uses));
  std::memcpy(&weaks, control.data.begin() + WEAKS_OFFSET, sizeof(weaks));
  result.from_live_memory = result.from_live_memory || control.from_debugger;
  result.ok = true;
  result.preview.sprnt(
    "%sstrong=%d weak=%d%s",
    kind.is_weak ? "weak_ptr: " : "",
    int(uses),
    int(weaks),
    kind.is_weak && uses <= 0 ? " (expired)" : "");
  return result;
}

match_confidence_t matches_shared(const tinfo_t *t, const qstring *hint) { return matches_impl(SHARED_KIND, t, hint); }
match_confidence_t matches_weak(const tinfo_t *t, const qstring *hint) { return matches_impl(WEAK_KIND, t, hint); }
bool build_shared(til_t *, const tinfo_t *t, const qstring *hint, tinfo_t *out_type, qstring *out_name) { return build_or_get_type_impl(SHARED_KIND, t, hint, out_type, out_name); }
bool build_weak(til_t *, const tinfo_t *t, const qstring *hint, tinfo_t *out_type, qstring *out_name) { return build_or_get_type_impl(WEAK_KIND, t, hint, out_type, out_name); }
stl_decode_result_t decode_shared(ea_t ea, const tinfo_t &t) { return decode_preview_impl(SHARED_KIND, ea, t); }
stl_decode_result_t decode_weak(ea_t ea, const tinfo_t &t) { return decode_preview_impl(WEAK_KIND, ea, t); }

const stl_type_descriptor_t SHARED_DESCRIPTOR =
{
  SHARED_KIND.key, SHARED_KIND.display_name,
  &matches_shared, &build_shared, &decode_shared
};

const stl_type_descriptor_t WEAK_DESCRIPTOR =
{
  WEAK_KIND.key, WEAK_KIND.display_name,
  &matches_weak, &build_weak, &decode_weak
};

} // namespace

void register_stl_shared_ptr_descriptors(std::vector<const stl_type_descriptor_t *> *out)
{
  out->push_back(&SHARED_DESCRIPTOR);
  out->push_back(&WEAK_DESCRIPTOR);
}

} // namespace stl_utility

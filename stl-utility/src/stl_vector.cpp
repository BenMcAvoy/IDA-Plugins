// MSVC std::vector<T> descriptor. Layout (x64, VS2019/2022 ABI), per
// microsoft/STL's vector header (_Vector_val):
//
//   struct vector<T> {      // sizeof == 0x18
//     T *_Myfirst;          // offset 0x00 -- begin
//     T *_Mylast;           // offset 0x08 -- end (size = _Mylast - _Myfirst)
//     T *_Myend;            // offset 0x10 -- end of allocation (capacity)
//   };
//
// Recovering the element type T is needed to report size/capacity in
// elements rather than bytes. We try, in order: (1) the existing tinfo_t's
// template argument if IDA already knows it, (2) the demangled name hint's
// "vector<...>" first template argument, (3) prompting the user.

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_util.h"

#include <kernwin.hpp>
#include <typeinf.hpp>

#include <cctype>
#include <cstring>
#include <string>

namespace stl_utility
{

namespace
{

constexpr size_t STRUCT_SIZE = 0x18;
constexpr size_t MYFIRST_OFFSET = 0x00;
constexpr size_t MYLAST_OFFSET = 0x08;
constexpr size_t MYEND_OFFSET = 0x10;
constexpr const char *SYNTHETIC_PREFIX = "__stl_vector_of_";

// Extracts the first top-level template argument from "vector<...>" inside
// `hint`, honoring nested angle brackets (e.g. "vector<std::pair<int,int>>"
// yields "std::pair<int,int>"). Returns empty on failure.
std::string extract_element_type_name(const qstring *hint)
{
  if ( hint == nullptr )
    return {};

  const std::string text(hint->c_str());
  const size_t marker = text.find("vector<");
  if ( marker == std::string::npos )
    return {};

  const size_t args_start = marker + std::strlen("vector<");
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
      const tinfo_t *existing_type,
      const qstring *demangled_name_hint,
      tinfo_t *out_element,
      qstring *out_element_name)
{
  // 1. If IDA already knows a UDT shaped like vector<T> with a typed first
  //    pointer member, recover T from that member's pointee.
  if ( existing_type != nullptr && !existing_type->empty() && existing_type->is_udt() )
  {
    udt_type_data_t udt;
    if ( existing_type->get_udt_details(&udt) && !udt.empty() )
    {
      const tinfo_t &first_member_type = udt[0].type;
      if ( first_member_type.is_ptr() )
      {
        tinfo_t pointee = first_member_type.get_pointed_object();
        if ( !pointee.empty() )
        {
          *out_element = pointee;
          *out_element_name = printable_type_name(pointee);
          return true;
        }
      }
    }
  }

  // 2. Parse "vector<T,...>" from the demangled name hint.
  const std::string extracted = extract_element_type_name(demangled_name_hint);
  if ( !extracted.empty() && parse_type_string(extracted.c_str(), out_element) )
  {
    *out_element_name = extracted.c_str();
    return true;
  }

  // 3. Prompt the user for the element type.
  qstring typed;
  if ( ask_str(&typed, HIST_TYPE, "std::vector element type (e.g. \"int\", \"MyStruct *\"):")
    && parse_type_string(typed.c_str(), out_element) )
  {
    *out_element_name = typed;
    return true;
  }

  return false;
}

bool build_or_get_type_impl(
      til_t *,
      const tinfo_t *existing_type,
      const qstring *demangled_name_hint,
      tinfo_t *out_type,
      qstring *out_name)
{
  tinfo_t element;
  qstring element_name;
  if ( !resolve_element_type(existing_type, demangled_name_hint, &element, &element_name) )
  {
    debug_log("stl_vector: could not resolve element type, aborting retype");
    return false;
  }

  tinfo_t elem_ptr;
  if ( !elem_ptr.create_ptr(element) )
    return false;

  udt_type_data_t p;
  p.is_union = false;
  p.add_member("_Myfirst", elem_ptr, MYFIRST_OFFSET * 8);
  p.add_member("_Mylast", elem_ptr, MYLAST_OFFSET * 8);
  p.add_member("_Myend", elem_ptr, MYEND_OFFSET * 8);

  tinfo_t built;
  if ( !built.create_udt(p) )
    return false;

  qstring synthetic_name = SYNTHETIC_PREFIX;
  for ( size_t i = 0; i < element_name.length(); ++i )
  {
    const char c = element_name[i];
    synthetic_name.append(std::isalnum(static_cast<unsigned char>(c)) != 0 ? c : '_');
  }

  debug_log("stl_vector: building synthetic type '%s'", synthetic_name.c_str());
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

match_confidence_t matches_impl(const tinfo_t *existing_type, const qstring *demangled_name_hint)
{
  if ( demangled_name_hint != nullptr )
  {
    if ( demangled_name_hint->find("vector<") != qstring::npos )
      return MATCH_HIGH;
    // Recognize our own previously-applied synthetic "__stl_vector_of_*"
    // type by name, so the preview keeps rendering on later decompiles.
    if ( demangled_name_hint->find(SYNTHETIC_PREFIX) == 0 )
      return MATCH_HIGH;
  }

  if ( existing_type != nullptr && !existing_type->empty() && existing_type->get_size() == STRUCT_SIZE )
    return MATCH_AMBIGUOUS;

  return MATCH_NONE;
}

stl_decode_result_t decode_preview_impl(ea_t instance_ea, const tinfo_t &resolved_type)
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

  ea_t first = BADADDR, last = BADADDR, end = BADADDR;
  std::memcpy(&first, header.data.begin() + MYFIRST_OFFSET, sizeof(ea_t));
  std::memcpy(&last, header.data.begin() + MYLAST_OFFSET, sizeof(ea_t));
  std::memcpy(&end, header.data.begin() + MYEND_OFFSET, sizeof(ea_t));
  result.from_live_memory = header.from_debugger;
  result.ok = true;

  if ( first == BADADDR || last == BADADDR || end == BADADDR || last < first || end < last )
  {
    result.preview.sprnt("first=%a last=%a end=%a (unexpected layout)", first, last, end);
    return result;
  }

  size_t element_size = 1;
  udt_type_data_t udt;
  if ( resolved_type.get_udt_details(&udt) && !udt.empty() && udt[0].type.is_ptr() )
  {
    const asize_t pointee_size = udt[0].type.get_pointed_object().get_size();
    if ( pointee_size > 0 )
      element_size = size_t(pointee_size);
  }

  const uint64 byte_size = uint64(last - first);
  const uint64 byte_cap = uint64(end - first);
  result.preview.sprnt(
    "size=%" FMT_64 "u cap=%" FMT_64 "u (elements, %" FMT_64 "u bytes/element)",
    uint64(byte_size / element_size),
    uint64(byte_cap / element_size),
    uint64(element_size));
  return result;
}

const stl_type_descriptor_t VECTOR_DESCRIPTOR =
{
  "std_vector", "std::vector<T>",
  &matches_impl, &build_or_get_type_impl, &decode_preview_impl
};

} // namespace

void register_stl_vector_descriptors(std::vector<const stl_type_descriptor_t *> *out)
{
  out->push_back(&VECTOR_DESCRIPTOR);
}

} // namespace stl_utility

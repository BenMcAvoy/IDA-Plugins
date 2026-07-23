// MSVC std::unique_ptr<T> descriptor (default_delete<T> case). With a
// stateless deleter, empty-base-class-optimization collapses the
// _Compressed_pair<Deleter,T*> down to a single 8-byte T* at offset 0 --
// so the applied type is simply "T *", no synthetic struct needed.
// (A stateful deleter changes this layout; out of scope for v1.)

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_util.h"

#include <kernwin.hpp>
#include <name.hpp>
#include <typeinf.hpp>

#include <cctype>
#include <cstring>
#include <string>

namespace stl_utility
{

namespace
{

std::string extract_element_type_name(const qstring *hint)
{
  if ( hint == nullptr )
    return {};

  const std::string text(hint->c_str());
  const size_t marker = text.find("unique_ptr<");
  if ( marker == std::string::npos )
    return {};

  const size_t args_start = marker + std::strlen("unique_ptr<");
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
      tinfo_t *out_element)
{
  if ( existing_type != nullptr && !existing_type->empty() && existing_type->is_ptr() )
  {
    tinfo_t pointee = existing_type->get_pointed_object();
    if ( !pointee.empty() )
    {
      *out_element = pointee;
      return true;
    }
  }

  const std::string extracted = extract_element_type_name(demangled_name_hint);
  if ( !extracted.empty() && parse_type_string(extracted.c_str(), out_element) )
    return true;

  qstring typed;
  if ( ask_str(&typed, HIST_TYPE, "std::unique_ptr element type (e.g. \"int\", \"MyStruct *\"):")
    && parse_type_string(typed.c_str(), out_element) )
  {
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
  if ( !resolve_element_type(existing_type, demangled_name_hint, &element) )
  {
    debug_log("stl_unique_ptr: could not resolve element type, aborting retype");
    return false;
  }

  if ( !out_type->create_ptr(element) )
    return false;

  *out_name = printable_type_name(*out_type);
  return true;
}

match_confidence_t matches_impl(const tinfo_t *existing_type, const qstring *demangled_name_hint)
{
  if ( demangled_name_hint != nullptr && demangled_name_hint->find("unique_ptr<") != qstring::npos )
    return MATCH_HIGH;

  // A bare pointer is too common/ambiguous to guess as unique_ptr on its
  // own -- only match when the name explicitly says so.
  (void)existing_type;
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

  const stl_read_result_t header = stl_read_memory(instance_ea, sizeof(ea_t));
  if ( !header.ok )
  {
    result.ok = true;
    result.preview = looks_like_stack_address(instance_ea)
      ? qstring("(stack-local, attach debugger to preview)")
      : qstring("(unable to read memory)");
    return result;
  }

  ea_t target = BADADDR;
  std::memcpy(&target, header.data.begin(), sizeof(ea_t));
  result.from_live_memory = header.from_debugger;
  result.ok = true;

  if ( target == BADADDR || target == 0 )
  {
    result.preview = "empty";
    return result;
  }

  qstring name = get_name(target);
  if ( !name.empty() )
    result.preview.sprnt("-> %a (%s)", target, name.c_str());
  else
    result.preview.sprnt("-> %a", target);
  return result;
}

const stl_type_descriptor_t UNIQUE_PTR_DESCRIPTOR =
{
  "std_unique_ptr", "std::unique_ptr<T>",
  &matches_impl, &build_or_get_type_impl, &decode_preview_impl
};

} // namespace

void register_stl_unique_ptr_descriptors(std::vector<const stl_type_descriptor_t *> *out)
{
  out->push_back(&UNIQUE_PTR_DESCRIPTOR);
}

} // namespace stl_utility

// MSVC std::basic_string<char>/<wchar_t> descriptor: the SSO-union pain
// point this plugin exists to solve. Layout (x64, VS2019/2022 ABI), per
// microsoft/STL's xstring:
//
//   struct basic_string {                 // sizeof == 0x20
//     union _Bxty {                       // offset 0x00, size 16
//       value_type _Buf[_BUF_SIZE];        // inline SSO storage
//       value_type *_Ptr;                  // heap pointer
//     } _Bx;
//     size_t _Mysize;                      // offset 0x10 -- length in chars
//     size_t _Myres;                       // offset 0x18 -- capacity in chars
//   };
//
// _BUF_SIZE is 16 for char, 8 for wchar_t. The union's active arm is chosen
// by capacity, not length: _Myres < _BUF_SIZE means the inline buffer is
// live; otherwise _Bx._Ptr is the heap pointer.

#include "stl_registry.h"
#include "stl_memory.h"
#include "stl_util.h"

#include <typeinf.hpp>

#include <cstdint>
#include <cstring>
#include <string>

namespace stl_utility
{

namespace
{

constexpr size_t STRUCT_SIZE = 0x20;
constexpr size_t MYSIZE_OFFSET = 0x10;
constexpr size_t MYRES_OFFSET = 0x18;
constexpr size_t MAX_PREVIEW_CHARS = 200;

struct string_kind_t
{
  bool is_wide;
  size_t element_size;   // 1 for char, 2 for wchar_t
  size_t buf_size;       // SSO threshold in elements: 16 for char, 8 for wchar_t
  const char *key;
  const char *display_name;
  const char *synthetic_name;
  const char *real_names[3]; // candidate exact STL names to look up first, nullptr-terminated
};

const string_kind_t CHAR_KIND =
{
  false, 1, 16,
  "std_string_char",
  "std::string (char)",
  "__stl_string_char_sso",
  { "std::basic_string<char,std::char_traits<char>,std::allocator<char>>", "std::string", nullptr }
};

const string_kind_t WCHAR_KIND =
{
  true, 2, 8,
  "std_string_wchar",
  "std::wstring (wchar_t)",
  "__stl_string_wchar_sso",
  { "std::basic_string<wchar_t,std::char_traits<wchar_t>,std::allocator<wchar_t>>", "std::wstring", nullptr }
};

bool build_element_type(const string_kind_t &kind, tinfo_t *out)
{
  return out->create_simple_type(kind.is_wide ? BTF_UINT16 : BTF_CHAR);
}

// Builds the plugin-owned synthetic struct/union layout described above and
// registers it into Local Types under `kind.synthetic_name`.
bool build_synthetic_type(const string_kind_t &kind, tinfo_t *out_type, qstring *out_name)
{
  tinfo_t element;
  if ( !build_element_type(kind, &element) )
    return false;

  tinfo_t buf_array;
  if ( !buf_array.create_array(element, uint32(kind.buf_size)) )
    return false;

  tinfo_t ptr_type;
  if ( !ptr_type.create_ptr(element) )
    return false;

  udt_type_data_t union_data;
  union_data.is_union = true;
  union_data.add_member("_Buf", buf_array, 0);
  union_data.add_member("_Ptr", ptr_type, 0);
  tinfo_t union_type;
  if ( !union_type.create_udt(union_data) )
    return false;

  tinfo_t size_type;
  if ( !size_type.create_simple_type(BTF_UINT64) )
    return false;

  udt_type_data_t struct_data;
  struct_data.is_union = false;
  struct_data.add_member("_Bx", union_type, 0);
  struct_data.add_member("_Mysize", size_type, MYSIZE_OFFSET * 8);
  struct_data.add_member("_Myres", size_type, MYRES_OFFSET * 8);

  tinfo_t struct_type;
  if ( !struct_type.create_udt(struct_data) )
    return false;

  if ( struct_type.set_named_type(nullptr, kind.synthetic_name, NTF_REPLACE) != TERR_OK )
    return false;

  tinfo_t saved;
  if ( saved.get_named_type(nullptr, kind.synthetic_name, BTF_STRUCT) && saved.get_size() == STRUCT_SIZE )
  {
    *out_type = saved;
    *out_name = kind.synthetic_name;
    return true;
  }

  *out_type = struct_type;
  *out_name = kind.synthetic_name;
  return true;
}

bool build_or_get_type_impl(const string_kind_t &kind, tinfo_t *out_type, qstring *out_name)
{
  for ( int i = 0; kind.real_names[i] != nullptr; ++i )
  {
    tinfo_t candidate;
    if ( candidate.get_named_type(nullptr, kind.real_names[i], BTF_STRUCT)
      && candidate.get_size() == STRUCT_SIZE )
    {
      *out_type = candidate;
      *out_name = kind.real_names[i];
      debug_log("stl_string: reusing existing Local Type '%s'", kind.real_names[i]);
      return true;
    }
  }

  debug_log("stl_string: building synthetic type '%s'", kind.synthetic_name);
  return build_synthetic_type(kind, out_type, out_name);
}

match_confidence_t matches_impl(
      const string_kind_t &kind,
      const tinfo_t *existing_type,
      const qstring *demangled_name_hint)
{
  if ( demangled_name_hint != nullptr && demangled_name_hint->find("basic_string") != qstring::npos )
  {
    const bool hint_is_wide =
      demangled_name_hint->find("wchar_t") != qstring::npos
      || demangled_name_hint->find("wstring") != qstring::npos;
    return hint_is_wide == kind.is_wide ? MATCH_HIGH : MATCH_NONE;
  }

  // Recognize our own previously-applied synthetic type by name, so the
  // content preview keeps rendering on every subsequent decompile without
  // requiring the user to re-run the retype action.
  if ( demangled_name_hint != nullptr && *demangled_name_hint == kind.synthetic_name )
    return MATCH_HIGH;

  // Structural fallback: an opaque/undecoded 0x20-byte buffer is exactly
  // the case this plugin targets (Hex-Rays showing raw bytes because it
  // can't resolve the SSO union). We can't tell char from wchar_t purely
  // from size, so both kinds report ambiguous here and the retype action's
  // chooser lets the user pick.
  if ( existing_type != nullptr && !existing_type->empty() && existing_type->get_size() == STRUCT_SIZE )
    return MATCH_AMBIGUOUS;

  return MATCH_NONE;
}

std::string format_preview(const uint8_t *bytes, size_t byte_count, bool is_wide, bool truncated)
{
  std::string out = "\"";
  const size_t char_count = is_wide ? byte_count / 2 : byte_count;
  for ( size_t i = 0; i < char_count; ++i )
  {
    uint32_t code;
    if ( is_wide )
      code = uint32_t(bytes[i * 2]) | (uint32_t(bytes[i * 2 + 1]) << 8);
    else
      code = bytes[i];

    if ( code == '"' || code == '\\' )
    {
      out.push_back('\\');
      out.push_back(char(code));
    }
    else if ( code == '\n' )
    {
      out += "\\n";
    }
    else if ( code == '\r' )
    {
      out += "\\r";
    }
    else if ( code == '\t' )
    {
      out += "\\t";
    }
    else if ( code >= 0x20 && code < 0x7F )
    {
      out.push_back(char(code));
    }
    else
    {
      char buf[8];
      qsnprintf(buf, sizeof(buf), "\\x%02X", code & 0xFF);
      out += buf;
    }
  }
  out.push_back('"');
  if ( truncated )
    out += "...";
  return out;
}

stl_decode_result_t decode_preview_impl(const string_kind_t &kind, ea_t instance_ea, const tinfo_t &)
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

  uint64_t mysize = 0;
  uint64_t myres = 0;
  std::memcpy(&mysize, header.data.begin() + MYSIZE_OFFSET, sizeof(mysize));
  std::memcpy(&myres, header.data.begin() + MYRES_OFFSET, sizeof(myres));

  result.from_live_memory = header.from_debugger;

  const size_t element_size = kind.element_size;
  const size_t char_count = size_t(mysize < MAX_PREVIEW_CHARS ? mysize : MAX_PREVIEW_CHARS);
  const bool truncated = mysize > MAX_PREVIEW_CHARS;

  if ( myres < kind.buf_size )
  {
    // SSO arm: the string bytes live inline in _Bx._Buf.
    const size_t byte_count = char_count * element_size;
    result.ok = true;
    result.preview.sprnt(
      "%s (size=%" FMT_64 "u cap=%" FMT_64 "u, inline)",
      format_preview(header.data.begin(), byte_count, kind.is_wide, truncated).c_str(),
      uint64(mysize),
      uint64(myres));
    return result;
  }

  // Heap arm: _Bx._Ptr holds the pointer to the allocation.
  ea_t heap_ptr = BADADDR;
  std::memcpy(&heap_ptr, header.data.begin(), sizeof(ea_t));

  if ( char_count == 0 )
  {
    result.ok = true;
    result.preview.sprnt(
      "\"\" (size=%" FMT_64 "u cap=%" FMT_64 "u, heap)",
      uint64(mysize),
      uint64(myres));
    return result;
  }

  const stl_read_result_t content =
    heap_ptr == BADADDR ? stl_read_result_t{} : stl_read_memory(heap_ptr, char_count * element_size);
  if ( !content.ok )
  {
    result.ok = true;
    result.preview.sprnt(
      "ptr=%a size=%" FMT_64 "u cap=%" FMT_64 "u (heap, attach debugger to preview)",
      heap_ptr,
      uint64(mysize),
      uint64(myres));
    return result;
  }

  result.from_live_memory = result.from_live_memory || content.from_debugger;
  result.ok = true;
  result.preview.sprnt(
    "%s (size=%" FMT_64 "u cap=%" FMT_64 "u, heap)",
    format_preview(content.data.begin(), content.data.size(), kind.is_wide, truncated).c_str(),
    uint64(mysize),
    uint64(myres));
  return result;
}

match_confidence_t matches_char(const tinfo_t *t, const qstring *hint) { return matches_impl(CHAR_KIND, t, hint); }
match_confidence_t matches_wchar(const tinfo_t *t, const qstring *hint) { return matches_impl(WCHAR_KIND, t, hint); }
bool build_char(til_t *, const tinfo_t *, const qstring *, tinfo_t *out_type, qstring *out_name) { return build_or_get_type_impl(CHAR_KIND, out_type, out_name); }
bool build_wchar(til_t *, const tinfo_t *, const qstring *, tinfo_t *out_type, qstring *out_name) { return build_or_get_type_impl(WCHAR_KIND, out_type, out_name); }
stl_decode_result_t decode_char(ea_t ea, const tinfo_t &t) { return decode_preview_impl(CHAR_KIND, ea, t); }
stl_decode_result_t decode_wchar(ea_t ea, const tinfo_t &t) { return decode_preview_impl(WCHAR_KIND, ea, t); }

const stl_type_descriptor_t CHAR_DESCRIPTOR =
{
  CHAR_KIND.key, CHAR_KIND.display_name,
  &matches_char, &build_char, &decode_char
};

const stl_type_descriptor_t WCHAR_DESCRIPTOR =
{
  WCHAR_KIND.key, WCHAR_KIND.display_name,
  &matches_wchar, &build_wchar, &decode_wchar
};

} // namespace

void register_stl_string_descriptors(std::vector<const stl_type_descriptor_t *> *out)
{
  out->push_back(&CHAR_DESCRIPTOR);
  out->push_back(&WCHAR_DESCRIPTOR);
}

} // namespace stl_utility

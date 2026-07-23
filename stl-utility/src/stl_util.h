#pragma once

#include <hexrays.hpp>

#include <string>

namespace stl_utility
{

// Writes to %APPDATA%\Hex-Rays\IDA Pro\IDA-STL-Utility.log, mirroring the
// sister IDA-VTable-Utility plugin's debug_log convention.
void debug_log(const char *format, ...);

// Strips color tags and surrounding whitespace from a Hex-Rays-rendered
// string (as produced by cexpr_t::print1/cfunc_t line text).
std::string trimmed_plain_text(const qstring &tagged);

// Returns the demangled/printable type name for a tinfo_t (e.g.
// "std::basic_string<char,std::char_traits<char>,std::allocator<char>>"),
// or an empty string if the type is empty/unprintable.
qstring printable_type_name(const tinfo_t &type);

// Parses a single C type declaration typed by the user (e.g. "int",
// "MyStruct *") into a tinfo_t. Appends the trailing ';' parse_decl expects
// if the caller didn't include one.
bool parse_type_string(const char *decl, tinfo_t *out_type);

} // namespace stl_utility

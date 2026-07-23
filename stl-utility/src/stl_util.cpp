#include "stl_util.h"

#include <diskio.hpp>
#include <fpro.h>

#include <cctype>
#include <cstdarg>

namespace stl_utility
{

void debug_log(const char *format, ...)
{
  qstring path;
  path.sprnt("%s/IDA-STL-Utility.log", get_user_idadir());
  FILE *file = qfopen(path.c_str(), "a");
  if ( file == nullptr )
    return;

  qstring message;
  va_list args;
  va_start(args, format);
  message.vsprnt(format, args);
  va_end(args);
  qfprintf(
    file,
    "[%u.%06u] %s\n",
    get_secs(qtime64()),
    get_usecs(qtime64()),
    message.c_str());
  qfclose(file);
}

std::string trimmed_plain_text(const qstring &tagged)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, tagged);
  std::string plain(plain_qstr.c_str());
  size_t begin = 0;
  size_t end = plain.size();
  while ( begin < end && std::isspace(static_cast<unsigned char>(plain[begin])) != 0 )
    ++begin;
  while ( end > begin && std::isspace(static_cast<unsigned char>(plain[end - 1])) != 0 )
    --end;
  return plain.substr(begin, end - begin);
}

qstring printable_type_name(const tinfo_t &type)
{
  qstring out;
  if ( type.empty() )
    return out;
  type.print(&out);
  return out;
}

bool parse_type_string(const char *decl, tinfo_t *out_type)
{
  if ( decl == nullptr || *decl == '\0' )
    return false;

  std::string with_semicolon(decl);
  size_t end = with_semicolon.size();
  while ( end > 0 && std::isspace(static_cast<unsigned char>(with_semicolon[end - 1])) != 0 )
    --end;
  with_semicolon.erase(end);
  if ( with_semicolon.empty() )
    return false;
  if ( with_semicolon.back() != ';' )
    with_semicolon.push_back(';');

  qstring name;
  return parse_decl(out_type, &name, nullptr, with_semicolon.c_str(), PT_TYP | PT_SIL)
      && !out_type->empty();
}

} // namespace stl_utility

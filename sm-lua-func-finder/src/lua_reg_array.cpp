#include "lua_reg_array.h"

#include <bytes.hpp>
#include <segment.hpp>

namespace
{

constexpr int MAX_REG_ENTRIES = 1024;
constexpr int ENTRY_SIZE = 16; // {const char *name; lua_CFunction func;} on x64

} // namespace

qvector<lua_reg_entry_t> parse_luaL_reg_array(ea_t arr_ea, qstring *reason)
{
  qvector<lua_reg_entry_t> out;

  if ( arr_ea == BADADDR || !is_loaded(arr_ea) )
  {
    if ( reason != nullptr )
      *reason = "array address is unmapped";
    return out;
  }

  ea_t entry_ea = arr_ea;
  for ( int i = 0; i < MAX_REG_ENTRIES; ++i, entry_ea += ENTRY_SIZE )
  {
    if ( !is_loaded(entry_ea) || !is_loaded(entry_ea + 8) )
    {
      if ( reason != nullptr && out.empty() )
        *reason = "array runs off the end of a mapped segment before a NULL terminator";
      break;
    }

    ea_t name_ptr = ea_t(get_qword(entry_ea));
    ea_t func_ptr = ea_t(get_qword(entry_ea + 8));
    if ( name_ptr == 0 && func_ptr == 0 )
      return out; // clean terminator

    if ( name_ptr == 0 || !is_loaded(name_ptr) )
    {
      if ( reason != nullptr && out.empty() )
        *reason = "first array slot's name pointer is invalid";
      break;
    }

    qstring name;
    if ( get_strlit_contents(&name, name_ptr, -1, STRTYPE_C) <= 0 || name.empty() )
    {
      if ( reason != nullptr && out.empty() )
        *reason = "first array slot's name isn't a readable C string";
      break;
    }

    lua_reg_entry_t entry;
    entry.name = name;
    entry.func_ea = func_ptr;
    out.push_back(entry);
  }

  return out;
}

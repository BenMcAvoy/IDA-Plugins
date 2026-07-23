#pragma once

#include <pro.h>
#include <ida.hpp>

// One {const char *name; lua_CFunction func;} slot out of a luaL_Reg array.
struct lua_reg_entry_t
{
  qstring name;
  ea_t func_ea;
};

// Parses the null-terminated luaL_Reg array (16-byte {name_ptr, func_ptr}
// slots on x64) starting at arr_ea, stopping at the first {0,0} terminator.
// Returns the entries found (possibly empty); *reason is filled when the
// array couldn't be read at all (arr_ea unmapped, first slot unreadable).
qvector<lua_reg_entry_t> parse_luaL_reg_array(ea_t arr_ea, qstring *reason);

#pragma once

#include <pro.h>
#include <ida.hpp>

// One Lua-callable C function discovered through a luaL_register() call --
// either a static namespace function (owner = dotted path, e.g. "sm.audio")
// or a userdata method (owner = the luaL_newmetatable() type name that the
// enclosing luaL_register(L, NULL, ...) call registers into, e.g. "Character").
struct lua_func_reg_t
{
  qstring owner;
  bool is_userdata;
  qstring funcname;
  ea_t func_ea;
  ea_t call_ea; // address of the luaL_register() call site, for diagnostics
};

// Scans every function in the database that calls luaL_register or
// luaL_newmetatable, decompiles it, and walks its ctree to recover the
// (owner, funcname, func_ea) triples described above. Diagnostic lines
// (missing imports, undecodable call sites, etc.) are appended to *log.
qvector<lua_func_reg_t> scan_lua_registrations(qstring *log);

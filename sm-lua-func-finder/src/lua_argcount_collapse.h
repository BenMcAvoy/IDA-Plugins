#pragma once

#include <hexrays.hpp>

// Recognizes the Lua argument-count-check boilerplate that opens nearly
// every Lua-bound C function in this binary (confirmed via the
// "Expected %d arguments (got %d)" luaL_error() format string, which has
// hundreds of xrefs -- essentially the same population this plugin's
// luaL_register() scan already discovers). Two equivalent shapes are
// recognized:
//
//   Shape A (early-return-on-mismatch):
//     if ( (unsigned int)lua_gettop(a1) != 1 )
//     {
//       v2 = lua_gettop(a1);
//       luaL_error(a1, "Expected %d arguments (got %d)", 1, v2);
//       return 0;
//     }
//     ... real function body ...
//
//   Shape B (match-wraps-the-body):
//     if ( (unsigned int)lua_gettop(a1) == 1 )
//     {
//       ... real function body ...
//     }
//     else
//     {
//       v2 = lua_gettop(a1);
//       luaL_error(a1, "Expected %d arguments (got %d)", 1, v2);
//     }
//
// luaL_error() never returns (it longjmps out of the Lua VM), so everything
// besides the check itself is pure noise that only exists because Hex-Rays
// can't know that. Both shapes are collapsed into a single synthetic
// `L_checkArgCount(L, N);` statement (named to match this exact binary's
// existing L_checkType/L_getVM/L_getCharacter helper-naming convention),
// dropping the recompute-for-the-error-message local, the luaL_error() call,
// and (for Shape A) the early return -- while preserving the real function
// body verbatim.
//
// Runs at hxe_maturity/CMAT_FINAL, mutating the ctree via cinsn_t::replace_by
// before pseudocode text is generated. Returns the number of collapsed
// occurrences within `cfunc`'s body.
int collapse_lua_argcount_checks(cfunc_t *cfunc);

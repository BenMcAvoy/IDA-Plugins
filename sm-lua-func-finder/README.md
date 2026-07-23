# SM-Lua-Func-Finder

Discovers Lua-callable C functions in Scrap Mechanic's `ScrapMechanic.exe`
(and similar Lua-51-embedding binaries) by scanning for `luaL_register()`
call sites, renames the discovered functions `Lua_<Owner>_<func>`, and
collapses the argument-count-check boilerplate that opens nearly every one
of them so the real function body reads cleanly.

### NOTE: This project is fully AI generated, I don't take any credit for anything in here.

## What it does

### 1. Scan and rename (`Edit -> Plugins -> SM Lua Function Finder`)

- Finds every function that calls `luaL_register()` (`sm.*` static
  namespaces) or precedes it with a matching `luaL_newmetatable()`
  (userdata methods), walking the referenced `luaL_Reg` array to recover
  each registered Lua name.
- Renames the underlying C function `Lua_<Owner>_<func>` (e.g.
  `Lua_sm_audio_play`, `Lua_Tool_Character_getTpBonePos`), merging labels
  when the same implementation is shared across multiple owners.
- Adds a doc comment pulled from the `sm_api_differ` JSON dump where an
  entry matches, and shows every result in a modal chooser plus a written
  log next to the current database
  (`<idb dir>\sm_lua_func_finder_scan.log`).

### 2. Argument-count-check collapse (automatic, every decompile)

Nearly every Lua-bound C function in this binary opens with boilerplate
that checks `lua_gettop(L)` against the expected argument count and calls
`luaL_error(L, "Expected %d arguments (got %d)", ...)` on mismatch. Since
`luaL_error()` never returns (it longjmps out of the Lua VM), Hex-Rays still
has to show the "got count" recompute, the error call, and (in one of the
two equivalent shapes) an unreachable early return -- pure noise around the
one thing that actually matters, the expected count. Both shapes:

```c
if ( (unsigned int)lua_gettop(a1) != 1 )
{
  v2 = lua_gettop(a1);
  luaL_error(a1, "Expected %d arguments (got %d)", 1, v2);
  return 0;
}
... real function body ...
```

```c
if ( (unsigned int)lua_gettop(a1) == 1 )
{
  ... real function body ...
}
else
{
  v2 = lua_gettop(a1);
  luaL_error(a1, "Expected %d arguments (got %d)", 1, v2);
}
```

are collapsed into a single synthesized call (real function body
untouched, in place):

```c
L_checkArgCount(a1, 1);
... real function body ...
```

This runs automatically on every decompile, right before pseudocode text
is generated (at `hxe_maturity`/`CMAT_FINAL`) -- no user interaction
required.

## Requirements

- IDA Professional 9.2 or newer
- Hex-Rays decompiler
- IDA SDK configured through the `IDASDK` environment variable (a checkout of
  [HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) at a tag with
  CMake support, e.g. `v9.3.1-release` -- not the classic hex-rays SDK zip)
- CMake 3.27 or newer
- Visual Studio with C++ build tools on Windows

## Build

```powershell
$env:IDASDK = "C:\path\to\ida-sdk"
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

On Windows, the build installs the DLL and metadata into IDA's plugin
directory automatically if it has write access; otherwise copy
`sm_lua_func_finder.dll` and `ida-plugin.json` into
`<IDA install>\plugins\sm_lua_func_finder\` yourself (this typically needs
an elevated copy, since `Program Files` is admin-writable only).

## Known limitations (v1)

- The rename pass only recognizes registrations reachable through
  `luaL_register()`/`luaL_newmetatable()` call sites that Hex-Rays can
  decompile; unusual registration shapes are skipped and logged.
- The argcount-check collapse only recognizes the two boilerplate shapes
  shown above, anchored on the exact `"Expected %d arguments (got %d)"`
  format string; other error-message wording or argument-count-check
  styles are left untouched.

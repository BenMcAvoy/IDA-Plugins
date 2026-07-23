# IDA-Plugins

A collection of IDA Pro / Hex-Rays plugins, built and installed together.

## Plugins

| Directory | Target | Description |
| --- | --- | --- |
| `vtable-utility/` | `pseudocode_xrefs` | Virtual-call recognition, inheritance-aware VTable navigation, renaming, prototypes, and cross-references. |
| `stl-utility/` | `stl_retype` | One-click retyping and SSO-aware content preview for MSVC STL containers (`std::string`, `shared_ptr`, `vector`, `unique_ptr`, header-only `map`/`set`/`unordered_map`/`unordered_set` stats), plus collapsing inlined `shared_ptr`/`string`/`std::function`/`vector` (trivial-element only) release and closure-teardown boilerplate. |
| `xxhash-utility/` | `xxhash_collapse` | Recognizes compiler-inlined `XXH32`/`XXH64` and collapses them into a readable call. |
| `sm-global-finder/` | `sm_global_finder` | Discovers MSVC RTTI singleton construction/allocation chains and renames the constructor, allocator, and backing global; also walks the real MSVC RTTI structures (Complete Object Locator / Class Hierarchy Descriptor) to recover each class's base classes and annotates its vtable with an inheritance comment; also synthesizes a best-effort struct layout for each class from its constructor's field-initialization writes, registered into Local Types for manual review (not auto-applied, to avoid silently corrupting decompilation with a wrong guess). |
| `crt-idioms-utility/` | `crt_idioms_collapse` | Recognizes compiler-inlined CRT idioms (currently: inlined `strlen` loops) and collapses them into a readable call. |
| `sm-lua-func-finder/` | `sm_lua_func_finder` | Discovers Lua-callable C functions registered via `luaL_register()` (Scrap Mechanic's `sm.*` static namespaces and userdata methods) and renames them `Lua_<Owner>_<func>`, adding doc comments from the `sm_api_differ` json dump where available; also collapses the `lua_gettop`/`luaL_error` argument-count-check boilerplate that opens nearly every one of them into a single `L_checkArgCount(L, N)` call. |

Each plugin is a self-contained CMake project (its own `CMakeLists.txt` /
`ida-plugin.json`), sharing the same build conventions.

## Requirements

- IDA Professional 9.2 or newer, Hex-Rays decompiler
- IDA SDK configured through the `IDASDK` environment variable (a checkout of
  [HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) at a tag with
  CMake support, e.g. `v9.3.1-release` -- not the classic hex-rays SDK zip)
- CMake 3.27+, Visual Studio with C++ build tools

## Install everything

```powershell
$env:IDASDK = "C:\path\to\ida-sdk"
.\install.ps1
```

This builds every plugin (Release, x64) and copies each one into
`<IDA install dir>\plugins\<target>\`. Since that's usually under
`Program Files`, the script re-launches itself elevated (a UAC prompt) if
it isn't already running as Administrator.

To build/install a single plugin manually instead, see that plugin's own
README.

## Diagnostic logs

Each plugin writes its own log to `%APPDATA%\Hex-Rays\IDA Pro\<name>.log`.

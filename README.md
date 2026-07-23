# IDA-Plugins

A collection of IDA Pro / Hex-Rays plugins, built and installed together.

## Plugins

| Directory | Target | Description |
| --- | --- | --- |
| `vtable-utility/` | `pseudocode_xrefs` | Virtual-call recognition, inheritance-aware VTable navigation, renaming, prototypes, and cross-references. |
| `stl-utility/` | `stl_retype` | One-click retyping and SSO-aware content preview for MSVC STL containers (`std::string`, `shared_ptr`, `vector`, `unique_ptr`), plus collapsing inlined `shared_ptr` release boilerplate. |
| `xxhash-utility/` | `xxhash_collapse` | Recognizes compiler-inlined `XXH32`/`XXH64` and collapses them into a readable call. |
| `sm-global-finder/` | `sm_global_finder` | Discovers MSVC RTTI singleton construction/allocation chains and renames the constructor, allocator, and backing global. |

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

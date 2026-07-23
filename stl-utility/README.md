# IDA-STL-Utility

One-click retyping and content preview for MSVC STL containers in Hex-Rays
pseudocode. Built to solve the biggest recurring pain point when reversing
MSVC binaries: `std::string`'s small-string-optimization (SSO) union, which
Hex-Rays can't resolve on its own, so it never shows the real string content.

### NOTE: This project is fully AI generated, I don't take any credit for anything in here.

## Supported types (v1)

- `std::basic_string<char>` / `std::basic_string<wchar_t>` (`std::string` /
  `std::wstring`), including SSO-aware content decoding.
- `std::shared_ptr<T>` / `std::weak_ptr<T>`, with strong/weak refcount preview.
- `std::vector<T>`, with element-count/capacity preview.
- `std::unique_ptr<T>` (stateless-deleter/EBO case).
- `std::map` / `std::set` / `std::multimap` / `std::multiset`: **header-only
  stub** -- shows element count and the root/sentinel pointer; full node
  traversal is not implemented in v1.
- `std::unordered_map` / `std::unordered_set`: **header-only stub** -- shows
  element count, bucket count, and max load factor; full node traversal is
  not implemented in v1. Unlike this plugin's other descriptors, this
  layout is derived purely from the MSVC STL header source and has **not**
  been verified against a live/decompiled binary (this plugin's usual real-
  world test target has no `unordered_map`/`unordered_set` usage anywhere
  in it) -- treat the applied type with a bit more skepticism than the
  others.

Additionally, this plugin collapses several kinds of inlined MSVC STL
scope-exit teardown boilerplate directly in Hex-Rays pseudocode (not tied to
the retype action above -- these run automatically on every decompile):

- Inlined `std::shared_ptr`/`std::weak_ptr` release sequences, collapsed to
  `~shared_ptr(obj);`.
- Inlined `std::basic_string` (SSO-aware) release sequences, collapsed to
  `~string(obj);`.
- Inlined `std::function`/delegate-closure teardown sequences (the
  `std::_Func_impl_no_alloc<...>` internal storage behind `std::function`),
  collapsed to `~function(obj);`.
- Inlined `std::vector<T>::~vector()` for TRIVIALLY DESTRUCTIBLE element
  types `T` only (pointers, ints, PODs, structs without destructors -- the
  overwhelmingly common case), collapsed to `~vector(obj);`. For a trivial
  `T`, MSVC elides the per-element destroy loop entirely, so the whole
  destructor is just `if ( v->_Myfirst ) operator delete(v->_Myfirst);` (or
  the sized-delete form). The non-trivial-element case (a loop destroying
  each element before the free) is a different, harder shape and is **not**
  handled -- it's simply left uncollapsed, not mis-collapsed.

## Usage

Put the cursor on a variable, parameter, or global in Hex-Rays pseudocode
and press **Ctrl-Shift-T** (or right-click and choose **IDA-STL-Utility ->
Retype as STL container**).

- If exactly one supported type matches with high confidence (e.g. the
  variable's type name already contains `basic_string`, `shared_ptr<`,
  `vector<`, etc.), it's applied immediately.
- If the match is ambiguous (e.g. an opaque same-size buffer that could be
  more than one type), a numbered prompt lets you pick.
- Once retyped, a trailing comment renders automatically on every
  subsequent decompile of that function, e.g.:

  ```c
  std::string name;          // "hello world" (size=11 cap=15, inline)
  std::shared_ptr<Foo> ptr;  // strong=2 weak=1
  std::vector<int> values;   // size=3 cap=8 (elements, 4 bytes/element)
  ```

  (`std::unique_ptr<T>` only shows its preview comment immediately after the
  retype action runs, since a plain pointer can't be distinguished from any
  other pointer of the same type on later decompiles.)

## Content preview: static vs. live

- With a debugger attached, previews are read from live process memory,
  including heap-allocated content (SSO's "big string" arm, `shared_ptr`
  control blocks, `vector` backing storage).
- Without a debugger, previews are read from the static database image
  (`.rdata`/`.data`), which works well for fixed globals/statics with a real
  initializer, but **cannot** recover:
  - Stack-local temporaries (no fixed address without a live debugger at the
    right frame) -- shown as `(stack-local, attach debugger to preview)`.
  - Heap-allocated content with no debugger attached -- shown as `(heap,
    attach debugger to preview)`.

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
`stl_retype.dll` and `ida-plugin.json` into
`<IDA install>\plugins\stl_retype\` yourself (this typically needs an
elevated copy, since `Program Files` is admin-writable only).

## Diagnostic output

Diagnostic output is written to:

```text
%APPDATA%\Hex-Rays\IDA Pro\IDA-STL-Utility.log
```

## Known limitations (v1)

- x64 only (MSVC VS2019/2022 ABI). 32-bit targets are not supported.
- `std::map`/`std::set` only expose the tree header (count + root pointer),
  not full node/iterator traversal.
- `std::unordered_map`/`std::unordered_set` only expose the hash-table
  header (count, bucket count, max load factor), not full node/iterator
  traversal; and this layout is header-derived, not verified against a
  live/decompiled binary.
- `std::vector<T>`'s destructor/release collapse only handles trivially
  destructible element types `T`; a non-trivial per-element destructor loop
  is not recognized.
- `std::vector<T>`/`std::unique_ptr<T>` prompt for the element type `T` when
  it can't be recovered from existing type info.
- `std::unique_ptr<T>` with a stateful deleter (not the default
  `std::default_delete<T>`) uses a different layout than what this plugin
  assumes; not supported.
- Synthetic Local Types this plugin creates are named `__stl_*` to avoid
  colliding with any real PDB-derived STL type of the same name; if a valid
  real STL type already exists in Local Types (matching size/shape), it's
  reused instead and the real name shows up in pseudocode.

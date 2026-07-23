# IDA-CRT-Idioms-Utility

Recognizes compiler-inlined CRT idioms in Hex-Rays pseudocode and collapses
them into a single readable call, so you see what the code is doing instead
of the compiler's inlined implementation.

### NOTE: This project is fully AI generated, I don't take any credit for anything in here.

## Supported idioms (v1)

- Inlined `strlen`: MSVC frequently inlines `strlen` as

  ```c
  counter = -1;
  do
    ++counter;
  while ( *(_BYTE *)(ptr + counter) );
  ```

  This is collapsed into:

  ```c
  counter = strlen(ptr);
  ```

## Usage

No user interaction required -- the collapse pass runs automatically on
every decompile, right before pseudocode text is generated (at
`hxe_maturity`/`CMAT_FINAL`).

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
`crt_idioms_collapse.dll` and `ida-plugin.json` into
`<IDA install>\plugins\crt_idioms_collapse\` yourself (this typically needs
an elevated copy, since `Program Files` is admin-writable only).

## Diagnostic output

Diagnostic output is written to:

```text
%APPDATA%\Hex-Rays\IDA Pro\IDA-CRT-Idioms-Utility.log
```

## Known limitations (v1)

- Only recognizes the do-while-with-counter-initialized-to--1 shape of
  inlined `strlen` shown above; other inlining shapes (e.g. loop-unrolled or
  SIMD-vectorized variants) are not recognized.
- Does not verify that `ptr` is actually a `char*`/byte pointer beyond the
  byte-sized dereference in the loop condition -- unrelated do-while loops
  that happen to match this exact shape (rare) would also be collapsed.

# IDA-XXHash-Utility

Recognizes compiler-inlined `XXH32`/`XXH64` hashing routines in Hex-Rays
pseudocode and collapses them into a single readable call. MSVC-optimized
builds routinely inline these hash functions directly into the caller as
raw arithmetic (a do-while loop over 4 accumulators, magic-constant
multiplies, and rotate intrinsics), leaving no trace of the original call.
This plugin recognizes that shape and rewrites it as e.g.:

```c
hash = XXH32(boneName.c_str(), boneName._Mysize, 1);
```

instead of ~20 lines of unreadable inlined arithmetic.

### NOTE: This project is fully AI generated, I don't take any credit for anything in here.

## How it works

Unlike the sister plugins (which annotate/rewrite already-*printed*
pseudocode text), this plugin mutates the actual Hex-Rays ctree at
`hxe_maturity`/`CMAT_FINAL` (before pseudocode text is generated), since the
recognized pattern spans a whole `if`/`if-else`/`do-while` statement
sequence, not a single expression. It structurally matches:

- the 4-lane accumulator update loop (prime-constant multiplies + rotate
  intrinsics `__ROL4__`/`__ROL8__`, matched by exact rotate amount: 13 for
  XXH32, 31 for XXH64),
- the convergence step (`rotl(acc1,1)+rotl(acc2,7)+rotl(acc3,12)+rotl(acc4,18)`),
- the small/large-input `if`/`else` split,
- and the finalization tail call,

matching by **variable identity** (same lvar/global, tracked through the
ctree) rather than by variable name (compiler-generated names like `v9`,
`v10` differ per call site and can't be relied on), then splices in a
synthetic `hash = XXH32(data, length, seed);` statement via
`cinsn_t::replace_by`.

Matching is deliberately **strict**: every structural piece (loop shape,
convergence, small/large split, tail call) must be found, or nothing is
rewritten. This trades some false negatives (real call sites that won't
collapse yet) for confidence that no unrelated code gets corrupted by a bad
match, since this plugin — unlike the sister plugins — actually deletes and
replaces real ctree nodes rather than just annotating or hiding a single
argument.

The hashed input is recognized either as a `std::string` (MSVC SSO layout,
detected structurally — not by reading memory, since this plugin only
needs to recognize the *shape*) or a raw pointer+length buffer.

## Requirements

- IDA Professional 9.2 or newer
- Hex-Rays decompiler
- IDA SDK configured through the `IDASDK` environment variable (a checkout of
  [HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) at a tag with
  CMake support, e.g. `v9.3.1-release` — not the classic hex-rays SDK zip)
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
`xxhash_collapse.dll` and `ida-plugin.json` into
`<IDA install>\plugins\xxhash_collapse\` yourself (typically needs an
elevated copy, since `Program Files` is admin-writable only).

## Diagnostic output

```text
%APPDATA%\Hex-Rays\IDA Pro\IDA-XXHash-Utility.log
```

## Known limitations (v1)

- x64 only.
- The finalization tail is only recognized as a **named/callable helper**
  (e.g. `XXH32_FinalizeTail(...)`) — a fully inlined tail/avalanche (no
  helper call at all, just more raw arithmetic) is not recognized in v1.
- **XXH64 support is preliminary.** It reuses the exact same structural
  matcher as XXH32 (parameterized for 64-bit primes, rotate 31, advance 32)
  but does **not** yet recognize the extra per-accumulator merge-round pass
  real XXH64 performs before convergence. It was implemented without a
  verified real-world XXH64 sample to test against — treat it as
  best-effort until validated against an actual binary.
- The accumulator-seeding statements (before the loop) are only checked
  for *presence* (each of the 4 lane variables must be assigned something
  before the loop), not validated against the exact textbook seeding
  formula — real-world seed folding turned out to be more variable than
  expected (see the design doc), so the loop/convergence/tail-call matches
  are the actual strictness backstop, not the seeding formula.
- `std::map`/`std::set`-style inputs aren't applicable here; only
  `std::string` and raw buffers are recognized as hash inputs.
- Because this plugin mutates the ctree (not just pseudocode text), a
  false match would actually corrupt the decompilation output for that
  function. The strict matching is the safety net — if you ever see an
  incorrect collapse, please note the exact pseudocode that triggered it.

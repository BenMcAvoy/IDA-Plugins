# sm-global-finder

An IDA Pro / Hex-Rays plugin (`sm_global_finder`) that mines MSVC RTTI data
already present in the binary to recover information about singletons and
class hierarchies, purely from static data structures -- no decompilation
required for either feature.

## Features

### Singleton chain discovery

For every MSVC RTTI vtable found (`??_7<ClassName>@@6B@` symbols), the plugin
walks the vft -> constructor -> allocator -> global chain: it finds the
function(s) that stamp the vtable pointer into an object, follows their
callers looking for an `operator new` + construct wrapper (or a
self-registering constructor that stores its own `this` into a global), and
renames the discovered constructor, allocator (as `ClassName::create`, since
it unconditionally allocates and constructs a fresh instance on every call --
it is a factory, not a lazy singleton accessor with a cached-instance check),
and backing global (as `g_ClassName`). A comment summarizing the chain is
added to the constructor and allocator functions.

### RTTI class hierarchy recovery

Independently of the singleton scan, the plugin also walks the actual MSVC
RTTI data structures for every discovered vtable -- the
`_RTTICompleteObjectLocator` pointer stored at `vft_ea - 8`, its
`_RTTIClassHierarchyDescriptor`, and its base-class array of
`_RTTIBaseClassDescriptor` entries -- to recover the real base classes of
each class (single and multiple inheritance, with each base's byte offset
within the derived object). This is read-only enrichment: it does not create
or modify any IDA struct types, it only adds a comment at the vtable's
address, e.g.:

```
RTTI hierarchy: ClassName : BaseA (+0x8), BaseB (+0x18)   [multiple inheritance]
```

or for single inheritance:

```
RTTI hierarchy: ClassName : BaseClass
```

### Constructor-driven struct layout synthesis (opt-in review, not auto-applied)

Also independent of the two features above: for each class, the plugin
decompiles the same constructor candidate the singleton-chain scan already
settled on and walks its body for direct field-initialization writes on the
constructor's own `this` parameter -- either raw pointer-cast writes
(`*(_DWORD *)(a1 + 140) = 200;`) or writes Hex-Rays already rendered as
member accesses (`a1->field_8C = 200;`). From the recorded
`(offset, width, is_pointer)` triples it synthesizes a best-effort `struct`
type describing the class's memory layout: real fields named
`field_0x<offset>`, gaps between them filled with anonymous
`gap_0x<offset>` byte-array padding so the layout and total size stay
accurate even where the real field contents aren't known, and -- since the
class is already known to be polymorphic from the RTTI scan above -- an
explicit `vfptr` member at offset 0 when no write already covers it. If an
`operator new(SIZE)` call with a constant size can be found among the
constructor's direct callers, that size is used to add one final trailing
padding member so the struct's total size matches the real allocation.

If any two recorded field writes conflict (overlapping byte ranges with
different shapes), or a field's width isn't 1/2/4/8 bytes, the whole class
is dropped from struct synthesis for this class rather than guessing --
better no struct than a wrong one.

**This synthesized struct is registered into Local Types (as
`__sm_layout_<ClassName>`, with `::` replaced by `_`) and a comment is added
to the constructor pointing at it -- but it is never automatically applied to
any lvar, parameter, or global.** This is a deliberate safety choice: a
misclassified field width, an unrecognized write shape, or a genuinely
different memory layout in another constructor of the same class could
silently retype the object wrong everywhere it's used, corrupting
decompilation output well beyond the one function being analyzed. Reviewing
the generated type in Local Types and applying it by hand (right-click a
variable -> "Set lvar type") keeps a human in the loop for that judgment
call.

Both features run together in the same pass, and a scan log (written next to
the current database) records the resolved/unresolved outcome for each class
in both categories (including the struct layout synthesis).

## Requirements

- IDA Professional 9.2 or newer, Hex-Rays decompiler
- IDA SDK configured through the `IDASDK` environment variable (a checkout of
  [HexRaysSA/ida-sdk](https://github.com/HexRaysSA/ida-sdk) at a tag with
  CMake support)
- CMake 3.27+, Visual Studio with C++ build tools

## Build

```powershell
$env:IDASDK = "C:\path\to\ida-sdk"
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

See the top-level `IDA-Plugins/README.md` for the shared install script that
builds and deploys every plugin in this repo at once.

## Diagnostic log

Running the plugin writes `sm_global_finder_scan.log` next to the current
database, listing every scanned class's singleton-chain result, RTTI
hierarchy result, and struct-layout-synthesis result (resolved or, with a
reason, unresolved).

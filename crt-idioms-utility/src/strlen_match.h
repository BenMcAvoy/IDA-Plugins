#pragma once

#include <hexrays.hpp>

namespace crt_idioms
{

// Recognizes the inlined MSVC strlen idiom:
//   counter = -1;
//   do
//     ++counter;
//   while ( *(_BYTE *)(ptr + counter) );
// This is `strlen` fully inlined by the compiler: a counter initialized to
// -1, incremented in a do-while whose trailing condition tests the byte at
// (ptr + counter) for non-zero. Once the loop exits, `counter` holds the
// string length (not counting the terminator). This is pure CRT boilerplate
// -- not useful to a reverse engineer -- so it's collapsed into a single
// `counter = strlen((char*)ptr);`-shaped synthetic call, mirroring the
// sister IDA-STL-Utility / IDA-XXHash-Utility plugins' approach to
// collapsing inlined boilerplate. Runs at hxe_maturity/CMAT_FINAL, mutating
// the ctree via cinsn_t::replace_by before pseudocode text is generated.
//
// Returns the number of collapsed occurrences within `cfunc`'s body.
int collapse_strlen_idioms(cfunc_t *cfunc);

} // namespace crt_idioms

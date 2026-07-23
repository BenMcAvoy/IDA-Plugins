#pragma once

#include <hexrays.hpp>

namespace stl_utility
{

// Recognizes MSVC's inlined std::vector<T>::~vector() for a TRIVIALLY
// DESTRUCTIBLE element type T (pointers, ints, PODs, structs without
// destructors -- the overwhelmingly common case for vectors in this
// codebase). For a trivial T, the compiler elides the per-element
// _Destroy_range() loop entirely, so the whole destructor collapses to just
// freeing the backing buffer if one was ever allocated:
//
//   if ( v->_Myfirst )
//     operator delete(v->_Myfirst);
//
// (or the sized-delete form, operator delete(v->_Myfirst, (size_t)((char*)
// v->_Myend - (char*)v->_Myfirst)) -- both are tolerated).
//
// This is pure ABI boilerplate -- not useful to a reverse engineer -- so
// it's collapsed into a single `~vector(obj);`-shaped synthetic call,
// mirroring this codebase's other release collapsers (shared_ptr, string,
// function). v1 scope is deliberately limited to the trivial-element shape
// above; the non-trivial-element case (a loop destroying each element
// before the free) is a fundamentally different, harder-to-verify shape and
// is NOT matched here -- if it isn't seen, the matcher simply fails to
// match rather than mis-collapsing it.
//
// Runs at hxe_maturity/CMAT_FINAL, mutating the ctree via
// cinsn_t::replace_by before pseudocode text is generated.
//
// Returns the number of collapsed occurrences within `cfunc`'s body.
int collapse_vector_releases(cfunc_t *cfunc);

} // namespace stl_utility

#pragma once

#include <hexrays.hpp>

namespace stl_utility
{

// Recognizes the inlined MSVC std::basic_string (std::string/std::wstring)
// scope-exit release sequence -- the conditional heap-free that only runs
// when the string wasn't using small-string-optimization (SSO). See
// src/stl_string.cpp for the established basic_string layout (_Bx at 0x00,
// _Mysize at 0x10, _Myres at 0x18, struct size 0x20):
//
//   if ( obj._Myres > 0xF )                          // NOT using inline SSO buffer
//   {
//     ptr = obj._Bx._Ptr;
//     if ( obj._Myres + 1 >= 0x1000 )                 // OPTIONAL: big-allocation
//     {                                                // header validation, only
//       ptr = *((char **)obj._Bx._Ptr - 1);            // emitted for very large
//       if ( (unsigned __int64)(obj._Bx._Ptr - ptr - 8) > 0x1F )
//         invalid_parameter_noinfo_noreturn();          // allocations / checked builds
//     }
//     free_or_delete_call(ptr);
//   }
//
// This is pure ABI boilerplate emitted at every std::string/std::wstring
// scope exit -- not useful to a reverse engineer -- so it's collapsed into
// a single `~string(obj);`-shaped synthetic call, mirroring
// stl_shared_ptr_release.cpp's approach for shared_ptr/weak_ptr release.
// Runs at hxe_maturity/CMAT_FINAL, mutating the ctree via
// cinsn_t::replace_by before pseudocode text is generated.
//
// The inner big-allocation-header-validation `if` and the exact free/abort
// callee names are NOT required by the matcher (they vary across build
// configurations and may be absent entirely); the strict, distinctive
// backstop is the `_Myres > 0xF` / `_Bx._Ptr` member-access shape, mirroring
// how the shared_ptr matcher leans on its own `_Rep`/`_InterlockedExchangeAdd`
// backstop rather than validating callee names.
//
// Returns the number of collapsed occurrences within `cfunc`'s body.
int collapse_string_releases(cfunc_t *cfunc);

} // namespace stl_utility

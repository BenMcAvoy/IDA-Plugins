#pragma once

#include <hexrays.hpp>

namespace stl_utility
{

// Recognizes the inlined MSVC std::shared_ptr/weak_ptr release sequence:
//   if ( sp._Rep )
//   {
//     if ( _InterlockedExchangeAdd(&sp._Rep->_Uses, -1) == 1 )
//     {
//       sp._Rep->vtbl[0](sp._Rep);  // virtual destroy
//       if ( _InterlockedExchangeAdd(&sp._Rep->_Weaks, -1) == 1 )
//         sp._Rep->vtbl[1]();      // virtual delete-this
//     }
//   }
// This is pure ABI boilerplate emitted at every shared_ptr scope exit --
// not useful to a reverse engineer -- so it's collapsed into a single
// `release(sp);`-shaped synthetic call, mirroring IDA-XXHash-Utility's
// approach to collapsing inlined algorithm boilerplate. Runs at
// hxe_maturity/CMAT_FINAL, mutating the ctree via cinsn_t::replace_by
// before pseudocode text is generated.
//
// Returns the number of collapsed occurrences within `cfunc`'s body.
int collapse_shared_ptr_releases(cfunc_t *cfunc);

} // namespace stl_utility

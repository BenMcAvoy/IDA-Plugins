#pragma once

#include "xxhash_match.h"

namespace xxhash_utility
{

// Builds a synthetic `hash_target = XXH32(data_ptr, length, seed);` (or
// XXH64) call statement and splices it in place of `match.matched_stmt`
// via cinsn_t::replace_by. Returns false (without mutating the ctree) if
// any required piece of `match` is missing.
bool synthesize_and_replace(const xxhash_match_t &match);

} // namespace xxhash_utility

#pragma once

#include "xxhash_common.h"
#include "xxhash_input.h"

namespace xxhash_utility
{

struct xxhash_match_t
{
  cinsn_t *matched_stmt = nullptr; // the outer cit_if to replace
  xxhash_variant_t variant = XXHASH_32;
  xxhash_input_t input;
  const cexpr_t *seed_expr = nullptr;   // 4th arg of the finalize-tail call
  const cexpr_t *hash_target = nullptr; // lvalue the tail call result is assigned to
};

// `outer_if` must have op == cit_if. Returns true and fills `out` if it
// matches the recognized inlined XXH32/XXH64 shape (see
// C:\Users\Ben\.claude\plans\spicy-imagining-church.md for the full
// structural description).
bool try_match_xxh32(cinsn_t *outer_if, xxhash_match_t *out);
bool try_match_xxh64(cinsn_t *outer_if, xxhash_match_t *out);

} // namespace xxhash_utility

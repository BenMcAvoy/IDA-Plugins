// XXH64 support is preliminary: it reuses the exact same orchestration as
// XXH32 (loop shape, convergence, small/large split, finalize-tail call),
// parameterized for 64-bit primes/rotate-31/advance-32, but does NOT yet
// recognize the extra per-accumulator merge-round pass XXH64 performs
// before convergence (see the plan doc's algorithm notes). Real-world
// XXH64 call sites that include that merge-round pass will not match
// until that's implemented; flagged here and in the README as a known
// v1 limitation, since no real XXH64 sample was available to validate
// against during initial implementation.

#include "xxhash_match.h"

namespace xxhash_utility
{

bool try_match_xxh64(cinsn_t *outer_if, xxhash_match_t *out)
{
  match_orchestration_result_t result;
  if ( !match_xxhash_pattern(outer_if, true, &result) )
    return false;

  out->matched_stmt = result.matched_stmt;
  out->variant = XXHASH_64;
  out->input = result.input;
  out->seed_expr = result.seed_expr;
  out->hash_target = result.hash_target;
  return true;
}

} // namespace xxhash_utility

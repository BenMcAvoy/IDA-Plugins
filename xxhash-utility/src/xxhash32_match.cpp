#include "xxhash_match.h"

namespace xxhash_utility
{

bool try_match_xxh32(cinsn_t *outer_if, xxhash_match_t *out)
{
  match_orchestration_result_t result;
  if ( !match_xxhash_pattern(outer_if, false, &result) )
    return false;

  out->matched_stmt = result.matched_stmt;
  out->variant = XXHASH_32;
  out->input = result.input;
  out->seed_expr = result.seed_expr;
  out->hash_target = result.hash_target;
  return true;
}

} // namespace xxhash_utility

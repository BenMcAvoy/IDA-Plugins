#pragma once

#include <hexrays.hpp>

#include "xxhash_input.h"

namespace xxhash_utility
{

enum xxhash_variant_t
{
  XXHASH_32,
  XXHASH_64,
};

// XXH32 primes, indexed 1..5 (index 0 unused).
extern const uint32 XXH32_PRIME[6];
// XXH64 primes, indexed 1..5 (index 0 unused).
extern const uint64 XXH64_PRIME[6];

// True if `e` is a cot_num literal equal to `value` (compared in the given
// bit width, tolerant of the signed/unsigned representation a decompiler
// may choose to print).
bool is_num32(const cexpr_t *e, uint32 value);
bool is_num64(const cexpr_t *e, uint64 value);

// Strips cot_cast wrapper(s) to reach the underlying expression.
const cexpr_t *strip_casts(const cexpr_t *e);
cexpr_t *strip_casts(cexpr_t *e);

// Recognizes a __ROL4__/__ROL8__ compiler-intrinsic helper call
// (cot_call to a cot_helper named accordingly). On success, *value is set
// to the rotated operand (arg 0) and *amount to the rotate amount, which
// must itself be a cot_num literal (arg 1).
bool match_rol(const cexpr_t *e, bool is_64, const cexpr_t **value, int *amount);

// Identifies a variable/global referenced by `e` (after stripping casts).
// Two match_identity_t values compare equal only when they refer to the
// exact same lvar (by index) or the exact same global (by address) --
// never by textual name, since compiler-generated names differ per call
// site and are not a reliable identity signal.
struct match_identity_t
{
  bool is_var = false;
  bool is_obj = false;
  int var_idx = -1;
  ea_t obj_ea = BADADDR;

  bool valid() const { return is_var || is_obj; }
  bool operator==(const match_identity_t &r) const
  {
    if ( is_var && r.is_var )
      return var_idx == r.var_idx;
    if ( is_obj && r.is_obj )
      return obj_ea == r.obj_ea;
    return false;
  }
};

match_identity_t identify(const cexpr_t *e);

// Resolves a (possibly nested) x.m/x->m member-access chain down to its
// ultimate base variable/global and the cumulative byte offset from that
// base. Used to recognize std::string's `_Mysize`/`_Myres`/`_Bx._Ptr`
// fields regardless of whether Hex-Rays represents the union access as one
// flattened memref or several nested ones.
struct member_access_t
{
  bool ok = false;
  match_identity_t base;
  uint64 offset = 0;
};

member_access_t resolve_member_access(const cexpr_t *e);

// Result of matching the do-while lane-update loop shared by XXH32/XXH64:
//   do {
//     lane[i] = PRIME1 * rol(lane[i] (+/-) PRIME2 * *(ptr + i*element), rotate_amount);
//     ...
//     ptr += 16 (XXH32) / 32 (XXH64);
//   } while (...)
struct lane_loop_match_t
{
  match_identity_t lanes[4];
  match_identity_t ptr_var;
};

// Matches the lane-update loop body against `do_stmt` (must have
// op == cit_do). `is_64` selects PRIME32_1/2 + rotate 13 + advance 16 vs
// PRIME64_1/2 + rotate 31 + advance 32. Requires exactly 4 distinct lane
// updates (offsets {0,1,2,3} element-units from the same pointer variable)
// plus exactly one pointer-advance statement, with nothing left
// unclassified in the loop body (strict: no partial matches).
bool match_lane_loop(const cinsn_t *do_stmt, bool is_64, lane_loop_match_t *out);

// Matches a convergence assignment `target = rol(lane0,1)+rol(lane1,7)+rol(lane2,12)+rol(lane3,18)`
// (order-independent sum) against `stmt` (must be cit_expr wrapping a
// cot_asg). `lanes` must be the 4 identities from match_lane_loop, matched
// as a set (each used exactly once). On success, *target_out is the
// assignment's target identity.
bool match_convergence(
      const cinsn_t *stmt,
      bool is_64,
      const match_identity_t lanes[4],
      match_identity_t *target_out);

// Iterates the top-level statements of a cit_block statement, calling
// `visit(stmt)` for each. Returns false if `block_stmt` isn't a block.
template <typename Visitor>
bool for_each_top_level_stmt(cinsn_t *block_stmt, Visitor visit)
{
  if ( block_stmt == nullptr || block_stmt->op != cit_block || block_stmt->cblock == nullptr )
    return false;
  for ( cinsn_t &stmt : *block_stmt->cblock )
    visit(&stmt);
  return true;
}

struct match_orchestration_result_t
{
  cinsn_t *matched_stmt = nullptr;
  xxhash_input_t input;
  const cexpr_t *seed_expr = nullptr;
  const cexpr_t *hash_target = nullptr;
};

// Shared XXH32/XXH64 orchestration: matches the full if/if-else/do-while
// shape rooted at `outer_if` (must have op == cit_if). See
// C:\Users\Ben\.claude\plans\spicy-imagining-church.md for the structural
// description this implements.
bool match_xxhash_pattern(cinsn_t *outer_if, bool is_64, match_orchestration_result_t *out);

} // namespace xxhash_utility

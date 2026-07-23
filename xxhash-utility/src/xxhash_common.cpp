#include "xxhash_common.h"
#include "xxhash_input.h"

#include <name.hpp>

#include <cctype>
#include <cstring>
#include <string>

namespace xxhash_utility
{

const uint32 XXH32_PRIME[6] =
{
  0,
  0x9E3779B1u, // PRIME32_1
  0x85EBCA77u, // PRIME32_2
  0xC2B2AE3Du, // PRIME32_3
  0x27D4EB2Fu, // PRIME32_4
  0x165667B1u, // PRIME32_5
};

const uint64 XXH64_PRIME[6] =
{
  0,
  0x9E3779B185EBCA87ull, // PRIME64_1
  0xC2B2AE3D27D4EB4Full, // PRIME64_2
  0x165667B19E3779F9ull, // PRIME64_3
  0x85EBCA77C2B2AE63ull, // PRIME64_4
  0x27D4EB2F165667C5ull, // PRIME64_5
};

bool is_num32(const cexpr_t *e, uint32 value)
{
  return e != nullptr && e->op == cot_num && uint32(e->numval()) == value;
}

bool is_num64(const cexpr_t *e, uint64 value)
{
  return e != nullptr && e->op == cot_num && uint64(e->numval()) == value;
}

const cexpr_t *strip_casts(const cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

cexpr_t *strip_casts(cexpr_t *e)
{
  while ( e != nullptr && e->op == cot_cast )
    e = e->x;
  return e;
}

bool match_rol(const cexpr_t *e, bool is_64, const cexpr_t **value, int *amount)
{
  e = strip_casts(e);
  if ( e == nullptr || e->op != cot_call || e->a == nullptr || e->a->size() != 2 )
    return false;

  const cexpr_t *callee = strip_casts(e->x);
  if ( callee == nullptr || callee->op != cot_helper || callee->helper == nullptr )
    return false;

  const char *expect = is_64 ? "__ROL8__" : "__ROL4__";
  if ( std::strcmp(callee->helper, expect) != 0 )
    return false;

  const cexpr_t *amount_expr = strip_casts(&e->a->at(1));
  if ( amount_expr == nullptr || amount_expr->op != cot_num )
    return false;

  *value = &e->a->at(0);
  *amount = int(amount_expr->numval());
  return true;
}

match_identity_t identify(const cexpr_t *e)
{
  match_identity_t result;
  e = strip_casts(e);
  if ( e == nullptr )
    return result;

  if ( e->op == cot_var )
  {
    result.is_var = true;
    result.var_idx = e->v.idx;
  }
  else if ( e->op == cot_obj )
  {
    result.is_obj = true;
    result.obj_ea = e->obj_ea;
  }
  return result;
}

member_access_t resolve_member_access(const cexpr_t *e)
{
  member_access_t result;
  uint64 offset = 0;
  const cexpr_t *cur = strip_casts(e);
  while ( cur != nullptr && (cur->op == cot_memref || cur->op == cot_memptr) )
  {
    offset += cur->m;
    cur = strip_casts(cur->x);
  }
  if ( cur == nullptr )
    return result;

  const match_identity_t base = identify(cur);
  if ( !base.valid() )
    return result;

  result.ok = true;
  result.base = base;
  result.offset = offset;
  return result;
}

namespace
{

// target += advance
bool try_match_advance(const cexpr_t *asg, uint64 advance, match_identity_t *target)
{
  const match_identity_t candidate = identify(asg->x);
  if ( !candidate.valid() )
    return false;

  const cexpr_t *src = strip_casts(asg->y);
  if ( src == nullptr || src->op != cot_add )
    return false;

  const cexpr_t *a = strip_casts(src->x);
  const cexpr_t *b = strip_casts(src->y);
  const match_identity_t ia = identify(a);
  const match_identity_t ib = identify(b);

  if ( ia.valid() && ia == candidate && is_num64(b, advance) )
  {
    *target = candidate;
    return true;
  }
  if ( ib.valid() && ib == candidate && is_num64(a, advance) )
  {
    *target = candidate;
    return true;
  }
  return false;
}

// target = PRIME1 * rol(target (+/-) PRIME2 * *(ptr + k), rotate_amount)
bool try_match_lane(
      const cexpr_t *asg,
      bool is_64,
      int rotate_amount,
      match_identity_t *lane_target,
      match_identity_t *deref_base,
      uint64 *elem_offset)
{
  const match_identity_t target = identify(asg->x);
  if ( !target.valid() )
    return false;

  const uint64 prime1 = is_64 ? XXH64_PRIME[1] : XXH32_PRIME[1];
  const uint64 prime2 = is_64 ? XXH64_PRIME[2] : XXH32_PRIME[2];
  auto is_prime1 = [&](const cexpr_t *e) { return is_64 ? is_num64(e, prime1) : is_num32(e, uint32(prime1)); };
  auto is_prime2 = [&](const cexpr_t *e) { return is_64 ? is_num64(e, prime2) : is_num32(e, uint32(prime2)); };

  const cexpr_t *src = strip_casts(asg->y);
  if ( src == nullptr || src->op != cot_mul )
    return false;

  const cexpr_t *a = strip_casts(src->x);
  const cexpr_t *b = strip_casts(src->y);
  const cexpr_t *rol_candidate = nullptr;
  if ( is_prime1(a) )
    rol_candidate = b;
  else if ( is_prime1(b) )
    rol_candidate = a;
  if ( rol_candidate == nullptr )
    return false;

  const cexpr_t *rotated_value = nullptr;
  int amount = 0;
  if ( !match_rol(rol_candidate, is_64, &rotated_value, &amount) || amount != rotate_amount )
    return false;

  const cexpr_t *inner = strip_casts(rotated_value);
  if ( inner == nullptr || (inner->op != cot_add && inner->op != cot_sub) )
    return false;

  const cexpr_t *ia_expr = strip_casts(inner->x);
  const cexpr_t *ib_expr = strip_casts(inner->y);
  match_identity_t self_id = identify(ia_expr);
  const cexpr_t *mul_expr = ib_expr;
  if ( !(self_id.valid() && self_id == target) )
  {
    self_id = identify(ib_expr);
    mul_expr = ia_expr;
  }
  if ( !(self_id.valid() && self_id == target) || mul_expr == nullptr || mul_expr->op != cot_mul )
    return false;

  const cexpr_t *ma = strip_casts(mul_expr->x);
  const cexpr_t *mb = strip_casts(mul_expr->y);
  const cexpr_t *deref_expr = nullptr;
  if ( is_prime2(ma) )
    deref_expr = mb;
  else if ( is_prime2(mb) )
    deref_expr = ma;
  if ( deref_expr == nullptr )
    return false;

  deref_expr = strip_casts(deref_expr);
  if ( deref_expr == nullptr || deref_expr->op != cot_ptr )
    return false;

  const cexpr_t *base = strip_casts(deref_expr->x);
  if ( base == nullptr )
    return false;

  match_identity_t base_id;
  uint64 offset = 0;
  if ( base->op == cot_add )
  {
    const cexpr_t *ba = strip_casts(base->x);
    const cexpr_t *bb = strip_casts(base->y);
    const match_identity_t bia = identify(ba);
    const match_identity_t bib = identify(bb);
    if ( bia.valid() && bb != nullptr && bb->op == cot_num )
    {
      base_id = bia;
      offset = bb->numval();
    }
    else if ( bib.valid() && ba != nullptr && ba->op == cot_num )
    {
      base_id = bib;
      offset = ba->numval();
    }
    else
    {
      return false;
    }
  }
  else
  {
    base_id = identify(base);
    offset = 0;
  }
  if ( !base_id.valid() )
    return false;

  *lane_target = target;
  *deref_base = base_id;
  *elem_offset = offset;
  return true;
}

} // namespace

bool match_lane_loop(const cinsn_t *do_stmt, bool is_64, lane_loop_match_t *out)
{
  if ( do_stmt == nullptr || do_stmt->op != cit_do || do_stmt->cdo == nullptr )
    return false;

  cinsn_t *body = do_stmt->cdo->body;
  if ( body == nullptr || body->op != cit_block || body->cblock == nullptr )
    return false;

  const uint64 advance = is_64 ? 32 : 16;
  const int rotate_amount = is_64 ? 31 : 13;

  match_identity_t lanes[4];
  bool lane_found[4] = { false, false, false, false };
  match_identity_t ptr_var;
  bool ptr_var_found = false;
  bool advance_found = false;

  for ( cinsn_t &stmt : *body->cblock )
  {
    if ( stmt.op != cit_expr || stmt.cexpr == nullptr || stmt.cexpr->op != cot_asg )
      return false;

    match_identity_t advance_target;
    if ( try_match_advance(stmt.cexpr, advance, &advance_target) )
    {
      if ( advance_found )
        return false; // strict: exactly one pointer-advance statement
      ptr_var = advance_target;
      ptr_var_found = true;
      advance_found = true;
      continue;
    }

    match_identity_t lane_target;
    match_identity_t deref_base;
    uint64 elem_offset = 0;
    if ( !try_match_lane(stmt.cexpr, is_64, rotate_amount, &lane_target, &deref_base, &elem_offset) )
      return false; // strict: every statement must be classified

    if ( elem_offset > 3 || lane_found[elem_offset] )
      return false;
    if ( ptr_var_found && !(ptr_var == deref_base) )
      return false;

    if ( !ptr_var_found )
    {
      ptr_var = deref_base;
      ptr_var_found = true;
    }
    lanes[elem_offset] = lane_target;
    lane_found[elem_offset] = true;
  }

  if ( !advance_found || !ptr_var_found )
    return false;
  for ( int i = 0; i < 4; ++i )
  {
    if ( !lane_found[i] )
      return false;
  }

  out->ptr_var = ptr_var;
  for ( int i = 0; i < 4; ++i )
    out->lanes[i] = lanes[i];
  return true;
}

namespace
{

void collect_add_chain(const cexpr_t *e, qvector<const cexpr_t *> *out)
{
  e = strip_casts(e);
  if ( e == nullptr )
    return;
  if ( e->op == cot_add )
  {
    collect_add_chain(e->x, out);
    collect_add_chain(e->y, out);
  }
  else
  {
    out->push_back(e);
  }
}

} // namespace

bool match_convergence(
      const cinsn_t *stmt,
      bool is_64,
      const match_identity_t lanes[4],
      match_identity_t *target_out)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr || stmt->cexpr->op != cot_asg )
    return false;

  const match_identity_t target = identify(stmt->cexpr->x);
  if ( !target.valid() )
    return false;

  qvector<const cexpr_t *> addends;
  collect_add_chain(stmt->cexpr->y, &addends);
  if ( addends.size() != 4 )
    return false;

  static const int expected_amounts[4] = { 1, 7, 12, 18 };
  bool amount_used[4] = { false, false, false, false };
  bool lane_used[4] = { false, false, false, false };

  for ( const cexpr_t *addend : addends )
  {
    const cexpr_t *value = nullptr;
    int amount = 0;
    if ( !match_rol(addend, is_64, &value, &amount) )
      return false;

    int amount_slot = -1;
    for ( int i = 0; i < 4; ++i )
    {
      if ( !amount_used[i] && expected_amounts[i] == amount )
      {
        amount_slot = i;
        break;
      }
    }
    if ( amount_slot < 0 )
      return false;

    const match_identity_t value_id = identify(value);
    int lane_slot = -1;
    for ( int i = 0; i < 4; ++i )
    {
      if ( !lane_used[i] && value_id.valid() && value_id == lanes[i] )
      {
        lane_slot = i;
        break;
      }
    }
    if ( lane_slot < 0 )
      return false;

    amount_used[amount_slot] = true;
    lane_used[lane_slot] = true;
  }

  *target_out = target;
  return true;
}

namespace
{

bool assigns_target(const cinsn_t *stmt, match_identity_t target)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr || stmt->cexpr->op != cot_asg )
    return false;
  const match_identity_t candidate = identify(stmt->cexpr->x);
  return candidate.valid() && candidate == target;
}

// Handles both a curly-braced branch (cit_block) and a single-statement
// branch (Hex-Rays sometimes omits the block for a one-line branch).
bool block_or_single_assigns(cinsn_t *branch, match_identity_t target)
{
  if ( branch == nullptr )
    return false;
  if ( branch->op != cit_block )
    return assigns_target(branch, target);

  bool found = false;
  for_each_top_level_stmt(branch, [&](cinsn_t *stmt)
  {
    if ( assigns_target(stmt, target) )
      found = true;
  });
  return found;
}

cinsn_t *find_top_level_do(cinsn_t *branch)
{
  if ( branch == nullptr )
    return nullptr;
  if ( branch->op == cit_do )
    return branch;
  if ( branch->op != cit_block )
    return nullptr;

  cinsn_t *found = nullptr;
  for_each_top_level_stmt(branch, [&](cinsn_t *stmt)
  {
    if ( stmt->op == cit_do )
      found = stmt;
  });
  return found;
}

bool looks_like_finalize_name(ea_t ea)
{
  if ( ea == BADADDR )
    return false;
  qstring name = get_name(ea);
  std::string lowered(name.c_str());
  for ( char &c : lowered )
    c = char(std::tolower(static_cast<unsigned char>(c)));
  return lowered.find("finaliz") != std::string::npos;
}

// Recognizes the finalization-tail call: `target = Callee(arg0, ptr, remaining_len, seed);`
// Accepts any callee name if it structurally receives `ptr_var` as one of
// its arguments (since the callee may just be an unnamed sub_XXXXXX);
// otherwise requires the name to look like a "finalize"-shaped helper.
bool match_tail_call(
      const cinsn_t *stmt,
      match_identity_t ptr_var,
      match_identity_t *hash_target_out,
      const cexpr_t **seed_expr_out,
      const cexpr_t **ptr_arg_out,
      const cexpr_t **length_arg_out)
{
  if ( stmt == nullptr || stmt->op != cit_expr || stmt->cexpr == nullptr || stmt->cexpr->op != cot_asg )
    return false;

  const cexpr_t *call = strip_casts(stmt->cexpr->y);
  if ( call == nullptr || call->op != cot_call || call->a == nullptr || call->a->size() != 4 )
    return false;

  bool name_ok = false;
  const cexpr_t *callee = strip_casts(call->x);
  if ( callee != nullptr && callee->op == cot_obj )
    name_ok = looks_like_finalize_name(callee->obj_ea);

  bool structurally_ok = false;
  for ( size_t i = 0; i < call->a->size(); ++i )
  {
    const match_identity_t arg_id = identify(&call->a->at(i));
    if ( arg_id.valid() && arg_id == ptr_var )
    {
      structurally_ok = true;
      break;
    }
  }

  if ( !name_ok && !structurally_ok )
    return false;

  const match_identity_t target = identify(stmt->cexpr->x);
  if ( !target.valid() )
    return false;

  *hash_target_out = target;
  *seed_expr_out = &call->a->at(3);
  *ptr_arg_out = &call->a->at(1);
  *length_arg_out = &call->a->at(2);
  return true;
}

} // namespace

bool match_xxhash_pattern(cinsn_t *outer_if, bool is_64, match_orchestration_result_t *out)
{
  if ( outer_if == nullptr || outer_if->op != cit_if || outer_if->cif == nullptr )
    return false;

  cif_t *cif = outer_if->cif;
  if ( cif->ielse == nullptr )
    return false; // strict: the "no data -> hash=0" else branch is required

  cinsn_t *then_block = cif->ithen;
  if ( then_block == nullptr || then_block->op != cit_block )
    return false;

  // Find the small/large split: a cit_if among then_block's top-level
  // statements with a cit_do on exactly one of its branches.
  cinsn_t *inner_if = nullptr;
  cinsn_t *large_branch = nullptr;
  cinsn_t *small_branch = nullptr;
  for_each_top_level_stmt(then_block, [&](cinsn_t *stmt)
  {
    if ( inner_if != nullptr || stmt->op != cit_if || stmt->cif == nullptr )
      return;
    if ( stmt->cif->ielse == nullptr )
      return;

    cinsn_t *then_loop = find_top_level_do(stmt->cif->ithen);
    cinsn_t *else_loop = find_top_level_do(stmt->cif->ielse);
    if ( (then_loop != nullptr) == (else_loop != nullptr) )
      return; // require exactly one side to hold the loop

    inner_if = stmt;
    if ( then_loop != nullptr )
    {
      large_branch = stmt->cif->ithen;
      small_branch = stmt->cif->ielse;
    }
    else
    {
      large_branch = stmt->cif->ielse;
      small_branch = stmt->cif->ithen;
    }
  });
  if ( inner_if == nullptr )
    return false;

  cinsn_t *do_stmt = find_top_level_do(large_branch);
  if ( do_stmt == nullptr )
    return false;

  lane_loop_match_t loop_match;
  if ( !match_lane_loop(do_stmt, is_64, &loop_match) )
    return false;

  // Light presence check: the 4 lane variables must each appear as an
  // assignment target somewhere in the large branch (the accumulator
  // seeding), without further validating the exact seeding formula --
  // real-world seed folding turned out to be more variable than the
  // textbook formula, so the loop/prime/rotate/convergence/tail matches
  // below are the actual strictness backstop.
  bool lane_seeded[4] = { false, false, false, false };
  for_each_top_level_stmt(large_branch, [&](cinsn_t *stmt)
  {
    if ( stmt->op != cit_expr || stmt->cexpr == nullptr || stmt->cexpr->op != cot_asg )
      return;
    const match_identity_t target = identify(stmt->cexpr->x);
    if ( !target.valid() )
      return;
    for ( int i = 0; i < 4; ++i )
    {
      if ( target == loop_match.lanes[i] )
        lane_seeded[i] = true;
    }
  });
  for ( int i = 0; i < 4; ++i )
  {
    if ( !lane_seeded[i] )
      return false;
  }

  // Find the convergence assignment among large_branch's top-level
  // statements (after the loop).
  match_identity_t intermediate_var;
  bool have_convergence = false;
  for_each_top_level_stmt(large_branch, [&](cinsn_t *stmt)
  {
    if ( have_convergence )
      return;
    match_identity_t target;
    if ( match_convergence(stmt, is_64, loop_match.lanes, &target) )
    {
      intermediate_var = target;
      have_convergence = true;
    }
  });
  if ( !have_convergence )
    return false;

  // The small-input branch must assign the same intermediate variable.
  if ( !block_or_single_assigns(small_branch, intermediate_var) )
    return false;

  // Find the finalization tail call: a top-level statement of then_block
  // (a sibling after inner_if) shaped like `hash = Callee(a, ptr, len, seed);`.
  match_identity_t hash_target_id;
  const cexpr_t *seed_expr = nullptr;
  const cexpr_t *ptr_arg = nullptr;
  const cexpr_t *length_arg = nullptr;
  const cexpr_t *hash_target_expr = nullptr;
  bool have_tail = false;
  for_each_top_level_stmt(then_block, [&](cinsn_t *stmt)
  {
    if ( have_tail )
      return;
    if ( match_tail_call(stmt, loop_match.ptr_var, &hash_target_id, &seed_expr, &ptr_arg, &length_arg) )
    {
      hash_target_expr = stmt->cexpr->x;
      have_tail = true;
    }
  });
  if ( !have_tail )
    return false;

  // Resolve the hashed input: prefer std::string SSO recognition (gives a
  // semantically clear _Mysize length expression), falling back to the
  // tail call's own pointer/length arguments for the raw-buffer case.
  xxhash_input_t input;
  if ( !try_resolve_string_input(then_block, &input) )
  {
    const cexpr_t *raw_length = length_arg;
    const cexpr_t *stripped_length = strip_casts(length_arg);
    if ( stripped_length != nullptr && stripped_length->op == cot_band && stripped_length->y != nullptr
      && stripped_length->y->op == cot_num )
    {
      raw_length = stripped_length->x;
    }
    if ( !try_resolve_raw_buffer_input(ptr_arg, raw_length, &input) )
      return false;
  }

  out->matched_stmt = outer_if;
  out->input = input;
  out->seed_expr = seed_expr;
  out->hash_target = hash_target_expr;
  return true;
}

} // namespace xxhash_utility

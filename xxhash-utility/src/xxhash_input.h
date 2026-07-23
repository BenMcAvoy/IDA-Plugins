#pragma once

#include <hexrays.hpp>

namespace xxhash_utility
{

struct xxhash_input_t
{
  const cexpr_t *data_ptr = nullptr;
  const cexpr_t *length = nullptr;
};

// Recognizes a std::string (MSVC SSO layout) being hashed: looks for
// member accesses to `_Mysize` (offset 0x10) and `_Myres` (offset 0x18)
// sharing the same base object/variable somewhere within `scope`, plus a
// variable that gets assigned either the base's address or its `_Bx._Ptr`
// union member (offset 0x00) -- the SSO-arm pointer selection. On success,
// `out->length` is a `_Mysize` member-access expression and `out->data_ptr`
// is the resolved pointer variable's expression.
bool try_resolve_string_input(cinsn_t *scope, xxhash_input_t *out);

// Fallback for a raw pointer+length buffer: `candidate_ptr`/`candidate_length`
// are expressions already identified by the caller (e.g. the loop's pointer
// operand and the finalization tail's remaining-length operand) -- this
// only rejects the pair if it looks like it's actually the string case
// (so callers should try `try_resolve_string_input` first).
bool try_resolve_raw_buffer_input(
      const cexpr_t *candidate_ptr,
      const cexpr_t *candidate_length,
      xxhash_input_t *out);

} // namespace xxhash_utility

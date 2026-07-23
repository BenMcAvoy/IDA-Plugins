#pragma once

#include <hexrays.hpp>

#include <vector>

namespace stl_utility
{

enum match_confidence_t
{
  MATCH_NONE = 0,
  MATCH_AMBIGUOUS,
  MATCH_HIGH,
};

struct stl_decode_result_t
{
  bool ok = false;
  qstring preview;
  bool from_live_memory = false;
};

// One implementation per supported MSVC STL container. See
// C:\Users\Ben\.claude\plans\spicy-imagining-church.md for the design.
struct stl_type_descriptor_t
{
  const char *key;           // stable internal id, e.g. "std_string_char"
  const char *display_name;  // shown in the "pick a type" chooser

  // Decide if this descriptor plausibly matches a variable/global's current
  // (possibly empty/void) type and/or a hint string (its current type's
  // printable name, or an empty string if unknown).
  match_confidence_t (*matches)(
        const tinfo_t *existing_type,
        const qstring *demangled_name_hint);

  // Resolve the tinfo_t to apply. `existing_type` (possibly empty) and
  // `demangled_name_hint` (possibly empty) are the same context passed to
  // `matches()`, so descriptors that need a template argument (e.g.
  // std::vector<T>'s element type) can try to recover it from the existing
  // type/name before falling back to an interactive prompt.
  //
  // Implementations should first try tinfo_t::get_named_type() for the
  // exact real STL name and validate its size/shape before reusing it; only
  // build+register a plugin-owned synthetic type as a fallback. Returns
  // false if a type couldn't be resolved (e.g. the user cancelled a
  // required prompt, such as vector's element-type prompt).
  bool (*build_or_get_type)(
        til_t *til,
        const tinfo_t *existing_type,
        const qstring *demangled_name_hint,
        tinfo_t *out_type,
        qstring *out_name);

  // Decode a human-readable content preview for an instance at
  // `instance_ea` (BADADDR if the instance has no fixed address, e.g. an
  // unresolved stack local).
  stl_decode_result_t (*decode_preview)(
        ea_t instance_ea,
        const tinfo_t &resolved_type);
};

const std::vector<const stl_type_descriptor_t *> &get_stl_descriptor_registry();

} // namespace stl_utility

#include <hexrays.hpp>
#include <xref.hpp>
#include <graph.hpp>
#include <moves.hpp>
#include <diskio.hpp>
#include <fpro.h>
#include <netnode.hpp>
#include <nalt.hpp>

#include <cctype>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>

#ifdef __NT__
#include <windows.h>
#endif

namespace
{
struct pseudocode_xrefs_plugmod_t;
static pseudocode_xrefs_plugmod_t *g_active_plugin = nullptr;

constexpr char ACTION_NAME[] = "pseudocode_xrefs:show";
constexpr char ACTION_LABEL[] = "Show xrefs to item";
constexpr char ACTION_HOTKEY[] = "K";
constexpr char VTABLE_ACTION_NAME[] = "pseudocode_xrefs:jump_vtable_target";
constexpr char VTABLE_ACTION_LABEL[] = "Jump to VTABLE target";
constexpr char VTABLE_ACTION_HOTKEY[] = "J";
constexpr char VTABLE_INDEX_ACTION_NAME[] = "pseudocode_xrefs:show_vtable_index";
constexpr char VTABLE_INDEX_ACTION_LABEL[] = "Show VTABLE index";
constexpr char VTABLE_INDEX_ACTION_HOTKEY[] = "I";
constexpr char VTABLE_RENAME_ACTION_NAME[] = "pseudocode_xrefs:rename_vtable_target";
constexpr char VTABLE_RENAME_ACTION_LABEL[] = "Rename VTABLE target";
constexpr char VTABLE_XREF_ACTION_NAME[] = "pseudocode_xrefs:show_hierarchy_versions";
constexpr char VTABLE_XREF_ACTION_LABEL[] = "Show hierarchy implementations";
constexpr char VTABLE_GRAPH_ACTION_NAME[] = "pseudocode_xrefs:show_hierarchy_graph";
constexpr char VTABLE_GRAPH_ACTION_LABEL[] = "Show hierarchy graph";
constexpr char VTABLE_GRAPH_ACTION_HOTKEY[] = "H";
constexpr char VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME[] =
  "pseudocode_xrefs:hide_inherited_graph_nodes";
constexpr char VTABLE_GRAPH_HIDE_INHERITED_ACTION_LABEL[] =
  "Hide inherited implementations";
constexpr char VTABLE_DECLARING_ACTION_NAME[] = "pseudocode_xrefs:set_declaring_class";
constexpr char VTABLE_DECLARING_ACTION_LABEL[] = "Set virtual method declaring class...";
constexpr char VTABLE_TYPE_ACTION_NAME[] = "pseudocode_xrefs:edit_vtable_function_type";
constexpr char VTABLE_TYPE_ACTION_LABEL[] = "Edit VTABLE function signature";
constexpr char DECLARATIONS_NODE_NAME[] = "$ pseudocode_xrefs declarations";

struct vtable_marker_t
{
  int line = -1;
  int start_column = 0;
  int end_column = 0;
  uval_t byte_offset = 0;
  uval_t slot = 0;
  qstring object_name;
  qstring class_name_override;
  ea_t target = BADADDR;
  qstring display_name;
  bool assignment_reference = false;
};

using vtable_markers_t = qvector<vtable_marker_t>;

// A single synthesized native code cross-reference: the address of the
// (indirect) call instruction that Hex-Rays rendered as "object->Method(...)"
// via a recognized VTABLE[...] marker, and the vtable slot's resolved
// implementation address. Used to register/diff real add_cref()/del_cref()
// xrefs so IDA's own xref system (Ctrl-X, the Xrefs subview) knows about
// these calls, not just this plugin's own side-channel actions.
struct vtable_call_xref_t
{
  ea_t call_ea = BADADDR;
  ea_t target = BADADDR;

  bool operator==(const vtable_call_xref_t &rhs) const
  {
    return call_ea == rhs.call_ea && target == rhs.target;
  }
  bool operator<(const vtable_call_xref_t &rhs) const
  {
    return call_ea != rhs.call_ea ? call_ea < rhs.call_ea : target < rhs.target;
  }
};

using vtable_call_xrefs_t = qvector<vtable_call_xref_t>;

bool is_identifier_start(char c);
bool is_identifier_char(char c);
bool is_vtable_override(
      const qstring &selected_class,
      uval_t slot,
      ea_t target);
bool get_declaring_class(
      const qstring &selected_class,
      uval_t slot,
      qstring *declaring_class);

struct itanium_method_t
{
  qstring class_name;
  qstring method_name;
};

bool parse_itanium_method(const qstring &symbol, itanium_method_t *method)
{
  const std::string name(symbol.c_str());
  if ( name.rfind("_ZN", 0) != 0 )
    return false;
  size_t cursor = 3;
  qvector<qstring> components;
  while ( cursor < name.size() && name[cursor] != 'E' )
  {
    if ( std::isdigit(uchar(name[cursor])) == 0 )
      return false;
    size_t length = 0;
    while ( cursor < name.size() && std::isdigit(uchar(name[cursor])) != 0 )
      length = length * 10 + size_t(name[cursor++] - '0');
    if ( length == 0 || cursor + length > name.size() )
      return false;
    components.push_back(name.substr(cursor, length).c_str());
    cursor += length;
  }
  if ( cursor >= name.size() || name[cursor] != 'E' || components.size() < 2 )
    return false;

  method->method_name = components.back();
  method->class_name.clear();
  for ( size_t index = 0; index + 1 < components.size(); ++index )
  {
    if ( !method->class_name.empty() )
      method->class_name.append("::");
    method->class_name.append(components[index]);
  }
  return true;
}

bool mangle_itanium_method(const qstring &scoped_name, qstring *mangled)
{
  const std::string input(scoped_name.c_str());
  qvector<std::string> components;
  size_t start = 0;
  while ( start < input.size() )
  {
    const size_t separator = input.find("::", start);
    const size_t end = separator == std::string::npos ? input.size() : separator;
    if ( end == start )
      return false;
    const std::string component = input.substr(start, end - start);
    if ( !is_identifier_start(component[0]) )
      return false;
    for ( char c : component )
      if ( !is_identifier_char(c) )
        return false;
    components.push_back(component);
    if ( separator == std::string::npos )
      break;
    start = separator + 2;
  }
  if ( components.size() < 2 )
    return false;

  *mangled = "_ZN";
  for ( const std::string &component : components )
    mangled->cat_sprnt("%" FMT_Z "%s", component.length(), component.c_str());
  mangled->append("Ev");
  return true;
}

bool find_class_vtable(
      const qstring &class_name,
      qstring *vtable_name,
      ea_t *vtable_ea)
{
  qvector<qstring> class_candidates;
  class_candidates.push_back(class_name);
  const char *separator = strrchr(class_name.c_str(), ':');
  if ( separator != nullptr )
    class_candidates.push_back(separator + 1);

  constexpr const char *suffixes[] = { "_vft", "_Vft", "_VFT" };
  for ( const qstring &candidate : class_candidates )
  {
    for ( const char *suffix : suffixes )
    {
      *vtable_name = candidate;
      vtable_name->append(suffix);
      *vtable_ea = get_name_ea(BADADDR, vtable_name->c_str());
      if ( *vtable_ea != BADADDR )
        return true;
    }
  }

  // MSVC RTTI encodes the primary vtable for a single/first-inheritance
  // class as "??_7ClassName@@6B@" (rendered by IDA as
  // "const ClassName::`vftable'"). Try that convention too, since many
  // real-world Windows binaries never carry the "_vft" style symbol name.
  for ( const qstring &candidate : class_candidates )
  {
    *vtable_name = "??_7";
    vtable_name->append(candidate);
    vtable_name->append("@@6B@");
    *vtable_ea = get_name_ea(BADADDR, vtable_name->c_str());
    if ( *vtable_ea != BADADDR )
      return true;
  }
  return false;
}

bool resolve_class_name_from_type(tinfo_t object_type, qstring *class_name)
{
  if ( !object_type.is_ptr() || !object_type.remove_ptr_or_array() )
    return false;
  return object_type.get_type_name(class_name)
      || object_type.get_final_type_name(class_name);
}

bool find_object_vtable(
      cfunc_t *cfunc,
      const qstring &object_name,
      qstring *class_name,
      qstring *vtable_name,
      ea_t *vtable_ea)
{
  const lvars_t *lvars = cfunc->get_lvars();
  const lvar_t *object_lvar = nullptr;
  for ( const lvar_t &lvar : *lvars )
  {
    if ( lvar.name == object_name )
    {
      object_lvar = &lvar;
      break;
    }
  }

  if ( object_lvar != nullptr )
  {
    if ( !resolve_class_name_from_type(object_lvar->type(), class_name) )
      return false;
    return find_class_vtable(*class_name, vtable_name, vtable_ea);
  }

  // Not a local variable/parameter; the object may be a global (e.g.
  // g_characterManagerClient) whose type lives in the address's tinfo
  // rather than in this function's lvar list.
  const ea_t global_ea = get_name_ea(BADADDR, object_name.c_str());
  if ( global_ea == BADADDR )
    return false;

  tinfo_t object_type;
  if ( get_tinfo(&object_type, global_ea)
    && resolve_class_name_from_type(object_type, class_name) )
  {
    return find_class_vtable(*class_name, vtable_name, vtable_ea);
  }

  // The global has no (or no usable) pointer-to-struct type. Many
  // singleton-style globals are simply named after their class, optionally
  // with a "g_"/"s_"/"m_" prefix (e.g. "CharacterManagerClient" or
  // "g_characterManagerClient" for class CharacterManagerClient). Fall back
  // to treating the identifier itself as the class name candidate.
  const std::string raw_name(object_name.c_str());
  static const char *const global_prefixes[] = { "g_", "s_", "m_" };
  qvector<qstring> name_candidates;
  name_candidates.push_back(object_name);
  for ( const char *prefix : global_prefixes )
  {
    const size_t prefix_len = std::strlen(prefix);
    if ( raw_name.compare(0, prefix_len, prefix) == 0 && raw_name.size() > prefix_len )
    {
      std::string stripped = raw_name.substr(prefix_len);
      name_candidates.push_back(qstring(stripped.c_str()));

      // Hungarian-style globals typically camelCase the class name after
      // the prefix (g_characterManagerClient -> class CharacterManagerClient).
      // Symbol lookups are case-sensitive, so try the capitalized form too.
      if ( std::islower(uchar(stripped[0])) != 0 )
      {
        stripped[0] = char(std::toupper(uchar(stripped[0])));
        name_candidates.push_back(qstring(stripped.c_str()));
      }
    }
  }

  for ( const qstring &candidate : name_candidates )
  {
    if ( find_class_vtable(candidate, vtable_name, vtable_ea) )
    {
      *class_name = candidate;
      return true;
    }
  }
  return false;
}

bool find_marker_vtable(
      cfunc_t *cfunc,
      const vtable_marker_t &marker,
      qstring *class_name,
      qstring *vtable_name,
      ea_t *vtable_ea)
{
  if ( !marker.class_name_override.empty() )
  {
    *class_name = marker.class_name_override;
    return find_class_vtable(*class_name, vtable_name, vtable_ea);
  }
  return find_object_vtable(
    cfunc, marker.object_name, class_name, vtable_name, vtable_ea);
}

bool get_vtable_entry_target(
      cfunc_t *cfunc,
      const vtable_marker_t &marker,
      ea_t *target)
{
  qstring class_name;
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  if ( !find_marker_vtable(
        cfunc,
        marker,
        &class_name,
        &vtable_name,
        &vtable_ea) )
  {
    return false;
  }

  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const ea_t entry_ea = vtable_ea + marker.slot * pointer_size;
  if ( !is_loaded(entry_ea) )
    return false;
  *target =
    pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
  return *target != BADADDR && is_mapped(*target);
}

// Resolve the native instruction address underlying a recognized VTABLE[...]
// marker (i.e. the address of the actual indirect "call" opcode Hex-Rays
// rendered as "object->Method(...)"), so a real IDA code cross-reference can
// be registered from it. Pseudocode text carries invisible COLOR_ADDR tags
// that map a rendered position back to its ctree item/instruction address;
// cfunc_t::get_line_item() decodes those tags the same way the decompiler
// itself resolves cursor positions for vdui_t::get_current_item(). The x
// coordinate is in the same "visible, tag-stripped" coordinate space as
// vtable_marker_t::start_column and vdui_t::cpos.x elsewhere in this file.
bool resolve_marker_call_ea(
      cfunc_t *cfunc,
      const vtable_marker_t &marker,
      ea_t *call_ea)
{
  if ( marker.line < 0 || marker.line >= cfunc->sv.size() )
    return false;

  const simpleline_t &line = cfunc->sv[marker.line];
  ctree_item_t head, item, tail;
  if ( !cfunc->get_line_item(
        line.line.c_str(),
        marker.start_column,
        true,
        &head,
        &item,
        &tail) )
  {
    return false;
  }

  const ea_t ea = item.get_ea();
  if ( ea == BADADDR || !is_mapped(ea) )
    return false;

  *call_ea = ea;
  return true;
}

bool extract_function_type(tinfo_t type, tinfo_t *function_type)
{
  for ( int depth = 0; depth < 4; ++depth )
  {
    if ( type.is_func() )
    {
      *function_type = type;
      return true;
    }
    if ( !type.is_ptr_or_array() )
      break;
    type = type.get_ptrarr_object();
  }
  return false;
}

bool is_placeholder_function_type(const tinfo_t &type)
{
  func_type_data_t details;
  return type.get_func_details(&details, GTD_NO_ARGLOCS)
      && details.empty()
      && details.rettype.is_char();
}

bool get_vtable_slot_function_type(
      ea_t vtable_ea,
      uval_t slot,
      tinfo_t *function_type)
{
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const ea_t entry_ea = vtable_ea + slot * pointer_size;
  tinfo_t entry_type;
  if ( get_tinfo(&entry_type, entry_ea)
    && extract_function_type(entry_type, function_type) )
  {
    return true;
  }

  tinfo_t vtable_type;
  if ( !get_tinfo(&vtable_type, vtable_ea) )
    return false;
  if ( vtable_type.is_array() )
    return extract_function_type(vtable_type.get_ptrarr_object(), function_type);
  if ( vtable_type.is_udt() )
  {
    udt_type_data_t members;
    if ( !vtable_type.get_udt_details(&members) )
      return false;
    const uint64 bit_offset = uint64(slot * pointer_size * 8);
    for ( const udm_t &member : members )
    {
      if ( member.offset == bit_offset
        && extract_function_type(member.type, function_type) )
      {
        return true;
      }
    }
  }
  return false;
}

bool make_class_pointer_type(
      const qstring &class_name,
      const tinfo_t &original_pointer_type,
      tinfo_t *pointer_type)
{
  ptr_type_data_t pointer_details;
  if ( !original_pointer_type.get_ptr_details(&pointer_details) )
    return false;

  const type_t pointer_modifiers = original_pointer_type.get_modifiers();
  const type_t pointee_modifiers = pointer_details.obj_type.get_modifiers();

  tinfo_t class_type;
  if ( !class_type.get_named_type(nullptr, class_name.c_str(), BTF_STRUCT)
    && !class_type.get_named_type(nullptr, class_name.c_str()) )
  {
    return false;
  }
  class_type.set_modifiers(pointee_modifiers);
  pointer_details.obj_type = class_type;
  return pointer_type->create_ptr(pointer_details, BT_PTR | pointer_modifiers);
}

bool is_receiver_argument_name(const qstring &argument_name)
{
  if ( argument_name.empty() )
    return true;

  std::string normalized(argument_name.c_str());
  std::transform(
    normalized.begin(),
    normalized.end(),
    normalized.begin(),
    [](unsigned char c) { return char(std::tolower(c)); });
  return normalized == "this"
      || normalized == "self"
      || normalized == "object";
}

bool retarget_this_pointer_type(
      const tinfo_t &function_type,
      const qstring &class_name,
      tinfo_t *retargeted_type)
{
  func_type_data_t details;
  if ( !function_type.get_func_details(&details, GTD_NO_ARGLOCS)
    || details.empty()
    || !details[0].type.is_ptr_or_array()
    || !is_receiver_argument_name(details[0].name) )
  {
    *retargeted_type = function_type;
    return true;
  }

  tinfo_t class_pointer_type;
  if ( !make_class_pointer_type(
          class_name, details[0].type, &class_pointer_type) )
  {
    *retargeted_type = function_type;
    return true;
  }

  details[0].type = class_pointer_type;
  return retargeted_type->create_func(details);
}

bool get_named_vtable_entry(
      cfunc_t *cfunc,
      vtable_marker_t *marker)
{
  ea_t target = BADADDR;
  if ( !get_vtable_entry_target(cfunc, *marker, &target) )
    return false;

  qstring selected_class, vtable_name;
  ea_t vtable_ea = BADADDR;
  find_marker_vtable(
    cfunc, *marker, &selected_class, &vtable_name, &vtable_ea);

  std::string display;
  itanium_method_t itanium;
  const qstring raw_name = get_name(target);
  if ( parse_itanium_method(raw_name, &itanium) )
  {
    display = itanium.method_name.c_str();
    if ( display.rfind("exec", 0) == 0
      && display.length() > 4
      && std::isupper(uchar(display[4])) != 0 )
    {
      display.erase(0, 4);
    }
    if ( is_vtable_override(selected_class, marker->slot, target) )
      display = std::string(itanium.class_name.c_str()) + "::" + display;
  }
  else
  {
    qstring short_name = get_short_name(target);
    display = short_name.c_str();
    const size_t namespace_separator = display.rfind("::");
    if ( namespace_separator != std::string::npos )
      display.erase(0, namespace_separator + 2);
  }
  if ( display.empty() )
    return false;

  marker->target = target;
  marker->display_name = display.c_str();
  return true;
}

struct inheritance_edge_t
{
  qstring derived;
  qstring base;
};

using inheritance_edges_t = qvector<inheritance_edge_t>;

bool contains_type_name(const qvector<qstring> &names, const qstring &name)
{
  for ( const qstring &candidate : names )
  {
    if ( candidate == name )
      return true;
  }
  return false;
}

void collect_inheritance_edges(inheritance_edges_t *edges)
{
  const uint32 ordinal_limit = get_ordinal_limit(nullptr);
  for ( uint32 ordinal = 1; ordinal < ordinal_limit; ++ordinal )
  {
    const char *derived_name = get_numbered_type_name(nullptr, ordinal);
    if ( derived_name == nullptr || *derived_name == '\0' )
      continue;

    tinfo_t derived_type;
    if ( !derived_type.get_numbered_type(ordinal) )
      continue;
    udt_type_data_t udt;
    if ( !derived_type.get_udt_details(&udt) )
      continue;

    for ( const udm_t &member : udt )
    {
      if ( !member.is_baseclass() )
        continue;
      qstring base_name;
      if ( !member.type.get_type_name(&base_name)
        && !member.type.get_final_type_name(&base_name) )
      {
        continue;
      }
      inheritance_edge_t &edge = edges->push_back();
      edge.derived = derived_name;
      edge.base = base_name;
    }
  }
}

void collect_connected_hierarchy(
      const qstring &selected_class,
      qvector<qstring> *class_names)
{
  class_names->push_back(selected_class);
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);

  bool changed = true;
  while ( changed )
  {
    changed = false;
    for ( const inheritance_edge_t &edge : edges )
    {
      const bool has_derived = contains_type_name(*class_names, edge.derived);
      const bool has_base = contains_type_name(*class_names, edge.base);
      if ( has_derived && !has_base )
      {
        class_names->push_back(edge.base);
        changed = true;
      }
      else if ( has_base && !has_derived )
      {
        class_names->push_back(edge.derived);
        changed = true;
      }
    }
  }
}

void collect_class_lineage(
      const qstring &selected_class,
      qvector<qstring> *class_names)
{
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);
  class_names->push_back(selected_class);

  qvector<qstring> ancestors;
  ancestors.push_back(selected_class);
  for ( size_t cursor = 0; cursor < ancestors.size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.derived == ancestors[cursor]
        && !contains_type_name(ancestors, edge.base) )
      {
        ancestors.push_back(edge.base);
        if ( !contains_type_name(*class_names, edge.base) )
          class_names->push_back(edge.base);
      }
    }
  }

  qvector<qstring> descendants;
  descendants.push_back(selected_class);
  for ( size_t cursor = 0; cursor < descendants.size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.base == descendants[cursor]
        && !contains_type_name(descendants, edge.derived) )
      {
        descendants.push_back(edge.derived);
        if ( !contains_type_name(*class_names, edge.derived) )
          class_names->push_back(edge.derived);
      }
    }
  }
}

void collect_descendant_hierarchy(
      const qstring &declaring_class,
      qvector<qstring> *class_names)
{
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);
  class_names->push_back(declaring_class);
  for ( size_t cursor = 0; cursor < class_names->size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.base == (*class_names)[cursor]
        && !contains_type_name(*class_names, edge.derived) )
      {
        class_names->push_back(edge.derived);
      }
    }
  }
}

void collect_ancestor_hierarchy(
      const qstring &selected_class,
      qvector<qstring> *class_names)
{
  inheritance_edges_t edges;
  collect_inheritance_edges(&edges);
  class_names->push_back(selected_class);
  for ( size_t cursor = 0; cursor < class_names->size(); ++cursor )
  {
    for ( const inheritance_edge_t &edge : edges )
    {
      if ( edge.derived == (*class_names)[cursor]
        && !contains_type_name(*class_names, edge.base) )
      {
        class_names->push_back(edge.base);
      }
    }
  }
}

ea_t get_class_vtable_entry(const qstring &class_name, uval_t slot)
{
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
    return BADADDR;
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const ea_t entry_ea = vtable_ea + slot * pointer_size;
  return is_loaded(entry_ea) ? entry_ea : BADADDR;
}

bool is_vtable_override(
      const qstring &selected_class,
      uval_t slot,
      ea_t target)
{
  qstring declaring_class;
  if ( get_declaring_class(selected_class, slot, &declaring_class) )
  {
    if ( declaring_class == selected_class )
      return false;
    const ea_t declaring_entry = get_class_vtable_entry(declaring_class, slot);
    if ( declaring_entry == BADADDR )
      return false;
    const size_t pointer_size = inf_is_64bit() ? 8 : 4;
    const ea_t declaring_target = pointer_size == 8
      ? ea_t(get_qword(declaring_entry))
      : ea_t(get_dword(declaring_entry));
    return declaring_target != BADADDR
        && is_mapped(declaring_target)
        && declaring_target != target;
  }

  qvector<qstring> ancestors;
  collect_ancestor_hierarchy(selected_class, &ancestors);
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  for ( const qstring &ancestor : ancestors )
  {
    if ( ancestor == selected_class )
      continue;
    const ea_t entry_ea = get_class_vtable_entry(ancestor, slot);
    if ( entry_ea == BADADDR )
      continue;
    const ea_t ancestor_target = pointer_size == 8
      ? ea_t(get_qword(entry_ea))
      : ea_t(get_dword(entry_ea));
    if ( ancestor_target != BADADDR
      && is_mapped(ancestor_target)
      && ancestor_target != target )
    {
      return true;
    }
  }
  return false;
}

bool get_declaring_class(
      const qstring &selected_class,
      uval_t slot,
      qstring *declaring_class)
{
  netnode declarations(DECLARATIONS_NODE_NAME);
  qvector<qstring> ancestors;
  collect_ancestor_hierarchy(selected_class, &ancestors);
  for ( const qstring &candidate : ancestors )
  {
    const ea_t entry_ea = get_class_vtable_entry(candidate, slot);
    if ( entry_ea != BADADDR
      && declarations.supstr_ea(declaring_class, entry_ea) > 0 )
    {
      return true;
    }
  }
  return false;
}

bool set_declaring_class_metadata(
      const qstring &selected_class,
      const qstring &declaring_class,
      uval_t slot)
{
  netnode declarations;
  declarations.create(DECLARATIONS_NODE_NAME);

  qvector<qstring> connected;
  collect_connected_hierarchy(selected_class, &connected);
  for ( const qstring &class_name : connected )
  {
    const ea_t entry_ea = get_class_vtable_entry(class_name, slot);
    if ( entry_ea != BADADDR )
      declarations.supdel_ea(entry_ea);
  }

  const ea_t declaring_entry = get_class_vtable_entry(declaring_class, slot);
  return declaring_entry != BADADDR
      && declarations.supset_ea(declaring_entry, declaring_class.c_str());
}

qstring identifier_from_type_name(const qstring &type_name)
{
  qstring result;
  for ( const char *cursor = type_name.c_str(); *cursor != '\0'; ++cursor )
  {
    const char c = *cursor;
    result.append(is_identifier_char(c) ? c : '_');
  }
  return result;
}

struct hierarchy_target_t
{
  qstring class_name;
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  ea_t target = BADADDR;
};

using hierarchy_targets_t = qvector<hierarchy_target_t>;

void append_colored(qstring *output, const char *text, const char *color);

void collect_hierarchy_targets(
      const qstring &selected_class,
      uval_t slot,
      hierarchy_targets_t *targets,
      size_t *vtable_count)
{
  qvector<qstring> class_names;
  qstring declaring_class;
  if ( get_declaring_class(selected_class, slot, &declaring_class) )
    collect_descendant_hierarchy(declaring_class, &class_names);
  else
    collect_descendant_hierarchy(selected_class, &class_names);
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  *vtable_count = 0;
  for ( const qstring &class_name : class_names )
  {
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
      continue;
    ++*vtable_count;

    const ea_t entry_ea = vtable_ea + slot * pointer_size;
    if ( !is_loaded(entry_ea) )
      continue;
    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    if ( target == BADADDR || !is_mapped(target) )
      continue;

    bool duplicate = false;
    for ( const hierarchy_target_t &existing : *targets )
    {
      if ( existing.target == target )
      {
        duplicate = true;
        break;
      }
    }
    if ( duplicate )
      continue;

    hierarchy_target_t &entry = targets->push_back();
    entry.class_name = class_name;
    entry.vtable_name = vtable_name;
    entry.vtable_ea = vtable_ea;
    entry.target = target;
  }
}

void collect_all_hierarchy_targets(
      const qstring &selected_class,
      uval_t slot,
      hierarchy_targets_t *targets)
{
  qvector<qstring> class_names;
  qstring declaring_class;
  if ( get_declaring_class(selected_class, slot, &declaring_class) )
    collect_descendant_hierarchy(declaring_class, &class_names);
  else
    collect_descendant_hierarchy(selected_class, &class_names);
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  for ( const qstring &class_name : class_names )
  {
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
      continue;
    const ea_t entry_ea = vtable_ea + slot * pointer_size;
    if ( !is_loaded(entry_ea) )
      continue;
    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    if ( target == BADADDR || !is_mapped(target) )
      continue;
    hierarchy_target_t &entry = targets->push_back();
    entry.class_name = class_name;
    entry.vtable_name = vtable_name;
    entry.vtable_ea = vtable_ea;
    entry.target = target;
  }
}

struct hierarchy_graph_edge_t
{
  int parent = -1;
  int child = -1;
};

enum class hierarchy_graph_node_kind_t
{
  root,
  inherited,
  overridden,
  unresolved,
};

// bgcolor_t uses Windows COLORREF byte order (0x00BBGGRR). Keep graph nodes
// dark so IDA's syntax colors retain strong contrast in both UI themes.
constexpr bgcolor_t HIERARCHY_GRAPH_ROOT_COLOR = 0x00382B20;
constexpr bgcolor_t HIERARCHY_GRAPH_INHERITED_COLOR = 0x00243A28;
constexpr bgcolor_t HIERARCHY_GRAPH_OVERRIDE_COLOR = 0x003A2638;
constexpr bgcolor_t HIERARCHY_GRAPH_UNRESOLVED_COLOR = 0x00332F28;
constexpr double HIERARCHY_GRAPH_MINIMUM_ZOOM = 0.75;
constexpr int HIERARCHY_GRAPH_POSITION_ATTEMPTS = 10;

struct hierarchy_graph_data_t
{
  qstring title;
  qstring root_class;
  uval_t slot = 0;
  qvector<hierarchy_target_t> nodes;
  qvector<hierarchy_graph_edge_t> edges;
  qvector<hierarchy_graph_node_kind_t> node_kinds;
  qstrvec_t comparison_classes;
  qstrvec_t labels;
  bool hide_inherited = false;

  void refresh(interactive_graph_t *graph);
};

DECLARE_TYPE_AS_MOVABLE(hierarchy_graph_edge_t);

const char *hierarchy_graph_node_kind_badge(hierarchy_graph_node_kind_t kind)
{
  switch ( kind )
  {
    case hierarchy_graph_node_kind_t::root:
      return "[root]";
    case hierarchy_graph_node_kind_t::inherited:
      return "[inherited]";
    case hierarchy_graph_node_kind_t::overridden:
      return "[override]";
    case hierarchy_graph_node_kind_t::unresolved:
      return "[unresolved]";
  }
  return "[unresolved]";
}

bgcolor_t hierarchy_graph_node_color(hierarchy_graph_node_kind_t kind)
{
  switch ( kind )
  {
    case hierarchy_graph_node_kind_t::root:
      return HIERARCHY_GRAPH_ROOT_COLOR;
    case hierarchy_graph_node_kind_t::inherited:
      return HIERARCHY_GRAPH_INHERITED_COLOR;
    case hierarchy_graph_node_kind_t::overridden:
      return HIERARCHY_GRAPH_OVERRIDE_COLOR;
    case hierarchy_graph_node_kind_t::unresolved:
      return HIERARCHY_GRAPH_UNRESOLVED_COLOR;
  }
  return HIERARCHY_GRAPH_UNRESOLVED_COLOR;
}

int find_hierarchy_graph_node(
      const hierarchy_graph_data_t &graph,
      const qstring &class_name)
{
  for ( size_t index = 0; index < graph.nodes.size(); ++index )
  {
    if ( graph.nodes[index].class_name == class_name )
      return int(index);
  }
  return -1;
}

bool position_hierarchy_graph_view(graph_viewer_t *viewer, int root_node)
{
  interactive_graph_t *graph = get_viewer_graph(viewer);
  if ( graph == nullptr || root_node < 0 || root_node >= graph->size() )
    return false;

  const rect_t &root_rect = graph->nrect(root_node);
  if ( root_rect.width() <= 0 || root_rect.height() <= 0 )
    return false;

  viewer_fit_window(viewer);
  graph_location_info_t location;
  if ( !viewer_get_gli(&location, viewer, GLICTL_CENTER) )
    return false;
  if ( location.zoom < HIERARCHY_GRAPH_MINIMUM_ZOOM )
    location.zoom = HIERARCHY_GRAPH_MINIMUM_ZOOM;

  const point_t root_center = root_rect.center();
  location.orgx = root_center.x;
  location.orgy = root_center.y;
  viewer_set_gli(viewer, &location, GLICTL_CENTER);
  return true;
}

struct hierarchy_graph_position_request_t final : ui_request_t
{
  qstring title;
  int root_node;
  int attempts = 0;

  hierarchy_graph_position_request_t(const qstring &title_, int root_node_)
    : title(title_), root_node(root_node_)
  {
  }

  bool idaapi run() override
  {
    TWidget *widget = find_widget(title.c_str());
    graph_viewer_t *viewer = widget != nullptr ? get_graph_viewer(widget) : nullptr;
    if ( viewer != nullptr && position_hierarchy_graph_view(viewer, root_node) )
      return false;
    return ++attempts < HIERARCHY_GRAPH_POSITION_ATTEMPTS;
  }
};

void classify_hierarchy_graph_nodes(hierarchy_graph_data_t *graph)
{
  graph->node_kinds.resize(graph->nodes.size());
  graph->comparison_classes.resize(graph->nodes.size());
  for ( size_t index = 0; index < graph->nodes.size(); ++index )
  {
    graph->comparison_classes[index].clear();
    const hierarchy_target_t &entry = graph->nodes[index];
    if ( entry.class_name == graph->root_class )
    {
      graph->node_kinds[index] = hierarchy_graph_node_kind_t::root;
      continue;
    }

    bool has_parent = false;
    graph->node_kinds[index] = hierarchy_graph_node_kind_t::unresolved;
    for ( const hierarchy_graph_edge_t &edge : graph->edges )
    {
      if ( edge.child != int(index)
        || edge.parent < 0
        || edge.parent >= int(graph->nodes.size()) )
      {
        continue;
      }

      has_parent = true;
      const hierarchy_target_t &parent = graph->nodes[edge.parent];
      if ( graph->comparison_classes[index].empty() )
        graph->comparison_classes[index] = parent.class_name;
      if ( parent.target == entry.target )
      {
        graph->node_kinds[index] = hierarchy_graph_node_kind_t::inherited;
        graph->comparison_classes[index] = parent.class_name;
        break;
      }
    }
    if ( has_parent
      && graph->node_kinds[index] != hierarchy_graph_node_kind_t::inherited )
    {
      graph->node_kinds[index] = hierarchy_graph_node_kind_t::overridden;
    }
  }
}

bool contains_hierarchy_graph_edge(
      const qvector<hierarchy_graph_edge_t> &edges,
      int parent,
      int child)
{
  for ( const hierarchy_graph_edge_t &edge : edges )
  {
    if ( edge.parent == parent && edge.child == child )
      return true;
  }
  return false;
}

void collect_nearest_visible_graph_parents(
      const qvector<hierarchy_graph_edge_t> &edges,
      const qvector<hierarchy_graph_node_kind_t> &node_kinds,
      int child,
      qvector<char> *visited,
      qvector<int> *parents)
{
  for ( const hierarchy_graph_edge_t &edge : edges )
  {
    if ( edge.child != child
      || edge.parent < 0
      || edge.parent >= int(node_kinds.size())
      || (*visited)[edge.parent] != 0 )
    {
      continue;
    }

    (*visited)[edge.parent] = 1;
    if ( node_kinds[edge.parent] != hierarchy_graph_node_kind_t::inherited )
    {
      if ( std::find(parents->begin(), parents->end(), edge.parent) == parents->end() )
        parents->push_back(edge.parent);
      continue;
    }
    collect_nearest_visible_graph_parents(
      edges,
      node_kinds,
      edge.parent,
      visited,
      parents);
  }
}

void hide_inherited_hierarchy_graph_nodes(hierarchy_graph_data_t *graph)
{
  const qvector<hierarchy_target_t> all_nodes = graph->nodes;
  const qvector<hierarchy_graph_edge_t> all_edges = graph->edges;
  const qvector<hierarchy_graph_node_kind_t> all_kinds = graph->node_kinds;
  const qstrvec_t all_comparison_classes = graph->comparison_classes;

  qvector<int> visible_indices;
  qvector<int> old_to_new;
  old_to_new.resize(all_nodes.size());
  for ( size_t index = 0; index < all_nodes.size(); ++index )
  {
    old_to_new[index] = -1;
    if ( all_kinds[index] != hierarchy_graph_node_kind_t::inherited )
    {
      old_to_new[index] = int(visible_indices.size());
      visible_indices.push_back(int(index));
    }
  }

  graph->nodes.clear();
  graph->edges.clear();
  graph->node_kinds.clear();
  graph->comparison_classes.clear();
  for ( int old_index : visible_indices )
  {
    graph->nodes.push_back(all_nodes[old_index]);
    graph->node_kinds.push_back(all_kinds[old_index]);
    graph->comparison_classes.push_back(all_comparison_classes[old_index]);
  }

  for ( int old_child : visible_indices )
  {
    qvector<char> visited;
    visited.resize(all_nodes.size());
    std::fill(visited.begin(), visited.end(), 0);
    qvector<int> old_parents;
    collect_nearest_visible_graph_parents(
      all_edges,
      all_kinds,
      old_child,
      &visited,
      &old_parents);
    const int child = old_to_new[old_child];
    for ( int old_parent : old_parents )
    {
      const int parent = old_to_new[old_parent];
      if ( parent < 0
        || parent == child
        || contains_hierarchy_graph_edge(graph->edges, parent, child) )
      {
        continue;
      }
      hierarchy_graph_edge_t &edge = graph->edges.push_back();
      edge.parent = parent;
      edge.child = child;
    }
  }
}

bool hierarchy_graph_classification_self_test()
{
  hierarchy_graph_data_t graph;
  graph.root_class = "Root";

  hierarchy_target_t &root = graph.nodes.push_back();
  root.class_name = "Root";
  root.target = 0x1000;
  hierarchy_target_t &inherited = graph.nodes.push_back();
  inherited.class_name = "Inherited";
  inherited.target = 0x1000;
  hierarchy_target_t &overridden = graph.nodes.push_back();
  overridden.class_name = "Overridden";
  overridden.target = 0x2000;
  hierarchy_target_t &unresolved = graph.nodes.push_back();
  unresolved.class_name = "Unresolved";
  unresolved.target = 0x3000;
  hierarchy_target_t &grandchild = graph.nodes.push_back();
  grandchild.class_name = "Grandchild";
  grandchild.target = 0x2000;
  hierarchy_target_t &multiple_inherited = graph.nodes.push_back();
  multiple_inherited.class_name = "MultipleInherited";
  multiple_inherited.target = 0x1000;
  hierarchy_target_t &multiple_overridden = graph.nodes.push_back();
  multiple_overridden.class_name = "MultipleOverridden";
  multiple_overridden.target = 0x4000;
  hierarchy_target_t &descendant_override = graph.nodes.push_back();
  descendant_override.class_name = "DescendantOverride";
  descendant_override.target = 0x5000;

  hierarchy_graph_edge_t &inherited_edge = graph.edges.push_back();
  inherited_edge.parent = 0;
  inherited_edge.child = 1;
  hierarchy_graph_edge_t &override_edge = graph.edges.push_back();
  override_edge.parent = 0;
  override_edge.child = 2;
  hierarchy_graph_edge_t &grandchild_edge = graph.edges.push_back();
  grandchild_edge.parent = 2;
  grandchild_edge.child = 4;
  hierarchy_graph_edge_t &multiple_inherited_root_edge = graph.edges.push_back();
  multiple_inherited_root_edge.parent = 0;
  multiple_inherited_root_edge.child = 5;
  hierarchy_graph_edge_t &multiple_inherited_override_edge = graph.edges.push_back();
  multiple_inherited_override_edge.parent = 2;
  multiple_inherited_override_edge.child = 5;
  hierarchy_graph_edge_t &multiple_overridden_root_edge = graph.edges.push_back();
  multiple_overridden_root_edge.parent = 0;
  multiple_overridden_root_edge.child = 6;
  hierarchy_graph_edge_t &multiple_overridden_override_edge = graph.edges.push_back();
  multiple_overridden_override_edge.parent = 2;
  multiple_overridden_override_edge.child = 6;
  hierarchy_graph_edge_t &descendant_override_edge = graph.edges.push_back();
  descendant_override_edge.parent = 1;
  descendant_override_edge.child = 7;

  classify_hierarchy_graph_nodes(&graph);
  const bool classification_ok = graph.node_kinds.size() == 8
      && graph.comparison_classes.size() == 8
      && graph.node_kinds[0] == hierarchy_graph_node_kind_t::root
      && graph.node_kinds[1] == hierarchy_graph_node_kind_t::inherited
      && graph.node_kinds[2] == hierarchy_graph_node_kind_t::overridden
      && graph.node_kinds[3] == hierarchy_graph_node_kind_t::unresolved
      && graph.node_kinds[4] == hierarchy_graph_node_kind_t::inherited
      && graph.node_kinds[5] == hierarchy_graph_node_kind_t::inherited
      && graph.node_kinds[6] == hierarchy_graph_node_kind_t::overridden
      && graph.node_kinds[7] == hierarchy_graph_node_kind_t::overridden
      && graph.comparison_classes[1] == "Root"
      && graph.comparison_classes[2] == "Root"
      && graph.comparison_classes[4] == "Overridden"
      && graph.comparison_classes[5] == "Root"
      && graph.comparison_classes[7] == "Inherited";
  hide_inherited_hierarchy_graph_nodes(&graph);
  const int filtered_root = find_hierarchy_graph_node(graph, "Root");
  const int filtered_descendant =
    find_hierarchy_graph_node(graph, "DescendantOverride");
  return classification_ok
      && graph.nodes.size() == 5
      && find_hierarchy_graph_node(graph, "Inherited") < 0
      && filtered_root >= 0
      && filtered_descendant >= 0
      && contains_hierarchy_graph_edge(
        graph.edges,
        filtered_root,
        filtered_descendant);
}

void build_hierarchy_graph_data(
      const qstring &selected_class,
      uval_t slot,
      hierarchy_graph_data_t *graph)
{
  graph->root_class = selected_class;
  graph->slot = slot;
  graph->nodes.clear();
  graph->edges.clear();
  graph->node_kinds.clear();
  graph->comparison_classes.clear();
  graph->labels.clear();

  qvector<qstring> class_names;
  collect_descendant_hierarchy(selected_class, &class_names);

  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  for ( const qstring &class_name : class_names )
  {
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_class_vtable(class_name, &vtable_name, &vtable_ea) )
      continue;

    const ea_t entry_ea = vtable_ea + slot * pointer_size;
    if ( !is_loaded(entry_ea) )
      continue;
    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    if ( target == BADADDR || !is_mapped(target) )
      continue;

    hierarchy_target_t &entry = graph->nodes.push_back();
    entry.class_name = class_name;
    entry.vtable_name = vtable_name;
    entry.vtable_ea = vtable_ea;
    entry.target = target;
  }

  inheritance_edges_t inheritance_edges;
  collect_inheritance_edges(&inheritance_edges);
  for ( const inheritance_edge_t &inheritance_edge : inheritance_edges )
  {
    const int parent = find_hierarchy_graph_node(*graph, inheritance_edge.base);
    const int child = find_hierarchy_graph_node(*graph, inheritance_edge.derived);
    if ( parent < 0 || child < 0 )
      continue;

    hierarchy_graph_edge_t &graph_edge = graph->edges.push_back();
    graph_edge.parent = parent;
    graph_edge.child = child;
  }

  classify_hierarchy_graph_nodes(graph);
  if ( graph->hide_inherited )
    hide_inherited_hierarchy_graph_nodes(graph);
  graph->labels.resize(graph->nodes.size());
  for ( size_t index = 0; index < graph->nodes.size(); ++index )
  {
    const hierarchy_target_t &entry = graph->nodes[index];
    qstring method_name = get_short_name(entry.target);
    const char *scope = strrchr(method_name.c_str(), ':');
    if ( scope != nullptr )
      method_name = scope + 1;

    qstring slot_text;
    slot_text.sprnt("vft[0x%" FMT_64 "X]", uint64(graph->slot));

    qstring target_text;
    target_text.sprnt("%a", entry.target);

    qstring &label = graph->labels[index];
    label.append(" \n  ");
    append_colored(&label, entry.class_name.c_str(), SCOLOR_CNAME);
    append_colored(&label, "::", SCOLOR_SYMBOL);
    append_colored(&label, method_name.c_str(), SCOLOR_CODNAME);
    label.append("  ");
    append_colored(
      &label,
      hierarchy_graph_node_kind_badge(graph->node_kinds[index]),
      SCOLOR_DEFAULT);
    label.append("  \n  ");
    append_colored(&label, slot_text.c_str(), SCOLOR_INSN);
    label.append("  ");
    append_colored(&label, entry.vtable_name.c_str(), SCOLOR_DNAME);
    label.append("  \n  ");
    append_colored(&label, "call", SCOLOR_INSN);
    label.append("   ");
    append_colored(&label, target_text.c_str(), SCOLOR_CODNAME);
    label.append("  \n ");
  }
}

void hierarchy_graph_data_t::refresh(interactive_graph_t *graph)
{
  const qstring selected_class = root_class;
  const uval_t selected_slot = slot;
  build_hierarchy_graph_data(selected_class, selected_slot, this);
  graph->clear();
  graph->current_layout = layout_digraph;
  graph->resize(nodes.size());
  for ( const hierarchy_graph_edge_t &edge : edges )
  {
    if ( edge.parent >= 0
      && edge.child >= 0
      && edge.parent < graph->size()
      && edge.child < graph->size() )
    {
      graph->add_edge(edge.parent, edge.child, nullptr);
    }
  }
}

ssize_t idaapi hierarchy_graph_callback(void *user_data, int code, va_list va)
{
  auto *graph_data = static_cast<hierarchy_graph_data_t *>(user_data);
  switch ( code )
  {
    case grcode_user_refresh:
    {
      interactive_graph_t *graph = va_arg(va, interactive_graph_t *);
      graph_data->refresh(graph);
      return true;
    }

    case grcode_user_text:
    {
      interactive_graph_t *graph = va_arg(va, interactive_graph_t *);
      qnotused(graph);
      const int node = va_arg(va, int);
      const char **text = va_arg(va, const char **);
      bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);
      if ( node < 0
        || node >= graph_data->labels.size()
        || node >= graph_data->node_kinds.size() )
        return false;
      *text = graph_data->labels[node].c_str();
      if ( bgcolor != nullptr )
        *bgcolor = hierarchy_graph_node_color(graph_data->node_kinds[node]);
      return true;
    }

    case grcode_dblclicked:
    {
      graph_viewer_t *viewer = va_arg(va, graph_viewer_t *);
      qnotused(viewer);
      selection_item_t *selection = va_arg(va, selection_item_t *);
      if ( selection == nullptr
        || !selection->is_node
        || selection->node < 0
        || selection->node >= graph_data->nodes.size() )
      {
        return false;
      }
      open_pseudocode(graph_data->nodes[selection->node].target, 0);
      return true;
    }

    case grcode_user_hint:
    {
      interactive_graph_t *graph = va_arg(va, interactive_graph_t *);
      qnotused(graph);
      const int mouse_node = va_argi(va, int);
      const int mouse_edge_src = va_argi(va, int);
      const int mouse_edge_dst = va_argi(va, int);
      char **hint = va_arg(va, char **);
      qnotused(mouse_edge_src);
      qnotused(mouse_edge_dst);
      if ( mouse_node < 0
        || mouse_node >= graph_data->nodes.size()
        || mouse_node >= graph_data->node_kinds.size()
        || mouse_node >= graph_data->comparison_classes.size() )
        return false;

      const hierarchy_target_t &entry = graph_data->nodes[mouse_node];
      const hierarchy_graph_node_kind_t kind = graph_data->node_kinds[mouse_node];
      qstring dispatch_text;
      switch ( kind )
      {
        case hierarchy_graph_node_kind_t::root:
          dispatch_text = "Target: selected graph root";
          break;
        case hierarchy_graph_node_kind_t::inherited:
          dispatch_text.sprnt(
            "Target: same as %s (inherited)",
            graph_data->comparison_classes[mouse_node].c_str());
          break;
        case hierarchy_graph_node_kind_t::overridden:
          dispatch_text.sprnt(
            "Target: differs from %s (override)",
            graph_data->comparison_classes[mouse_node].c_str());
          break;
        case hierarchy_graph_node_kind_t::unresolved:
          dispatch_text = "Target comparison: mapped direct parent unavailable";
          break;
      }
      qstring text;
      text.sprnt(
        "%s\n%s[0x%" FMT_64 "X]\nImplementation: %a\n%s",
        entry.class_name.c_str(),
        entry.vtable_name.c_str(),
        uint64(graph_data->slot),
        entry.target,
        dispatch_text.c_str());
      *hint = qstrdup(text.c_str());
      return true;
    }

    case grcode_destroyed:
      // IDA can destroy/rebuild the interactive graph while the viewer and
      // callback userdata remain alive. Keep graph_data valid for the viewer.
      return 0;

    default:
      return 0;
  }
}

void debug_log(const char *format, ...)
{
  qstring path;
  path.sprnt("%s/pseudocode_xrefs.log", get_user_idadir());
  FILE *file = qfopen(path.c_str(), "a");
  if ( file == nullptr )
    return;

  qstring message;
  va_list args;
  va_start(args, format);
  message.vsprnt(format, args);
  va_end(args);
  qfprintf(
    file,
    "[%u.%06u] %s\n",
    get_secs(qtime64()),
    get_usecs(qtime64()),
    message.c_str());
  qfclose(file);
}

void append_colored(qstring *output, const char *text, const char *color)
{
  output->append(SCOLOR_ON);
  output->append(color);
  output->append(text);
  output->append(SCOLOR_OFF);
  output->append(color);
}

const char *find_identifier_after(
        const qstring &tagged_line,
        const std::string &identifier,
        size_t plain_column)
{
  const char *search = tag_advance(tagged_line.c_str(), int(plain_column));
  while ( true )
  {
    const char *found = strstr(search, identifier.c_str());
    if ( found == nullptr )
      return nullptr;

    const char before = found == tagged_line.c_str() ? '\0' : found[-1];
    const char after = found[identifier.length()];
    if ( !is_identifier_char(before) && !is_identifier_char(after) )
      return found;
    search = found + identifier.length();
  }
}

char find_identifier_color(
        const qstring &tagged_line,
        const std::string &identifier,
        size_t plain_column)
{
  const char *found = find_identifier_after(tagged_line, identifier, plain_column);
  if ( found != nullptr
    && found - tagged_line.c_str() >= 2
    && found[-2] == COLOR_ON )
  {
    return found[-1];
  }

  // Hex-Rays uses this color for local variables and parameters in pseudocode.
  return *SCOLOR_LIBNAME;
}

bool is_identifier_start(char c)
{
  const uchar value = uchar(c);
  return std::isalpha(value) != 0 || c == '_';
}

bool is_identifier_char(char c)
{
  const uchar value = uchar(c);
  return std::isalnum(value) != 0 || c == '_';
}

size_t skip_balanced_parens(const std::string &plain, size_t pos)
{
  if ( pos >= plain.size() || plain[pos] != '(' )
    return std::string::npos;

  int depth = 0;
  for ( size_t i = pos; i < plain.size(); ++i )
  {
    if ( plain[i] == '(' )
      ++depth;
    else if ( plain[i] == ')' )
    {
      --depth;
      if ( depth == 0 )
        return i + 1;
    }
  }
  return std::string::npos;
}

// Matches the common cast-and-call rendering Hex-Rays uses when the call
// target is not already statically typed as a function pointer:
//   (*(FUNC_TYPE)(*(OBJ_CAST)object + 0xNN))(args)
// FUNC_TYPE and OBJ_CAST are arbitrary balanced-paren cast expressions and
// OBJ_CAST is optional (a bare "*object" is accepted too).
bool find_vtable_cast_call_pattern(
        const std::string &plain,
        size_t marker,
        size_t *match_start,
        size_t *match_end,
        size_t *object_start,
        size_t *object_end,
        uval_t *byte_offset)
{
  const size_t cast_group_start = marker + 2;
  if ( cast_group_start >= plain.size() || plain[cast_group_start] != '(' )
    return false;

  const size_t cast_group_end = skip_balanced_parens(plain, cast_group_start);
  if ( cast_group_end == std::string::npos
    || cast_group_end >= plain.size()
    || plain[cast_group_end] != '(' )
  {
    return false;
  }

  const size_t inner_group_start = cast_group_end;
  const size_t inner_group_end = skip_balanced_parens(plain, inner_group_start);
  if ( inner_group_end == std::string::npos
    || inner_group_end >= plain.size()
    || plain[inner_group_end] != ')'
    || inner_group_end + 1 >= plain.size()
    || plain[inner_group_end + 1] != '(' )
  {
    return false;
  }

  size_t cursor = inner_group_start + 1;
  if ( cursor >= plain.size() || plain[cursor] != '*' )
    return false;
  ++cursor;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;

  if ( cursor < plain.size() && plain[cursor] == '(' )
  {
    const size_t obj_cast_end = skip_balanced_parens(plain, cursor);
    if ( obj_cast_end == std::string::npos )
      return false;
    cursor = obj_cast_end;
    while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
      ++cursor;
  }

  if ( cursor >= plain.size() || !is_identifier_start(plain[cursor]) )
    return false;

  const size_t object_begin = cursor++;
  while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
    ++cursor;
  const size_t object_finish = cursor;

  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor >= plain.size() || plain[cursor] != '+' )
    return false;
  ++cursor;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;

  const size_t number_begin = cursor;
  if ( cursor + 2 <= plain.size()
    && plain[cursor] == '0'
    && (plain[cursor + 1] == 'x' || plain[cursor + 1] == 'X') )
  {
    cursor += 2;
    const size_t digits_begin = cursor;
    while ( cursor < plain.size() && std::isxdigit(uchar(plain[cursor])) != 0 )
      ++cursor;
    if ( cursor == digits_begin )
      return false;
  }
  else
  {
    while ( cursor < plain.size() && std::isdigit(uchar(plain[cursor])) != 0 )
      ++cursor;
    if ( cursor == number_begin )
      return false;
  }

  const std::string number = plain.substr(number_begin, cursor - number_begin);
  while ( cursor < plain.size()
       && (plain[cursor] == 'u' || plain[cursor] == 'U'
        || plain[cursor] == 'l' || plain[cursor] == 'L') )
  {
    ++cursor;
  }
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;

  if ( cursor != inner_group_end - 1 )
    return false;

  *match_start = marker;
  *match_end = inner_group_end + 1;
  *object_start = object_begin;
  *object_end = object_finish;
  *byte_offset = uval_t(::strtoull(number.c_str(), nullptr, 0));
  return true;
}

bool find_vtable_pattern(
        const std::string &plain,
        size_t search_from,
        size_t *match_start,
        size_t *match_end,
        size_t *object_start,
        size_t *object_end,
        uval_t *byte_offset)
{
  size_t marker = plain.find("*(*", search_from);
  while ( marker != std::string::npos )
  {
    size_t cursor = marker + 3;
    if ( cursor < plain.size() && is_identifier_start(plain[cursor]) )
    {
      const size_t object_begin = cursor++;
      while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
        ++cursor;
      const size_t object_finish = cursor;

      while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
        ++cursor;
      if ( cursor < plain.size() && plain[cursor++] == '+' )
      {
        while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
          ++cursor;
        const size_t number_begin = cursor;
        if ( cursor + 2 <= plain.size()
          && plain[cursor] == '0'
          && (plain[cursor + 1] == 'x' || plain[cursor + 1] == 'X') )
        {
          cursor += 2;
          const size_t digits_begin = cursor;
          while ( cursor < plain.size()
               && std::isxdigit(uchar(plain[cursor])) != 0 )
          {
            ++cursor;
          }
          if ( cursor > digits_begin )
          {
            const std::string number = plain.substr(number_begin, cursor - number_begin);
            while ( cursor < plain.size()
                 && (plain[cursor] == 'u'
                  || plain[cursor] == 'U'
                  || plain[cursor] == 'l'
                  || plain[cursor] == 'L') )
            {
              ++cursor;
            }
            while ( cursor < plain.size()
                 && std::isspace(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
            if ( cursor < plain.size() && plain[cursor] == ')' )
            {
              size_t finish = cursor + 1;
              while ( finish < plain.size() && plain[finish] == ')' )
                ++finish;
              if ( finish < plain.size() && plain[finish] == '(' )
              {
                size_t begin = marker;
                if ( begin > 0 && plain[begin - 1] == '(' )
                  --begin;

                *match_start = begin;
                *match_end = finish;
                *object_start = object_begin;
                *object_end = object_finish;
                *byte_offset = uval_t(::strtoull(number.c_str(), nullptr, 0));
                return true;
              }
            }
          }
        }
      }
    }
    marker = plain.find("*(*", marker + 3);
  }

  // Typed objects are commonly rendered as
  //   (*(object->VTable + slot))(arguments)
  // where pointer arithmetic already uses a slot index rather than a byte offset.
  marker = plain.find("(*(", search_from);
  while ( marker != std::string::npos )
  {
    size_t cursor = marker + 3;
    if ( cursor < plain.size() && is_identifier_start(plain[cursor]) )
    {
      const size_t object_begin = cursor++;
      while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
        ++cursor;
      const size_t object_finish = cursor;
      if ( cursor + 2 <= plain.size() && plain.compare(cursor, 2, "->") == 0 )
      {
        cursor += 2;
        const size_t member_begin = cursor;
        while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
          ++cursor;
        std::string member = plain.substr(member_begin, cursor - member_begin);
        for ( char &c : member )
          c = char(std::tolower(uchar(c)));
        while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
          ++cursor;
        if ( (member == "vtable" || member == "vftable")
          && cursor < plain.size()
          && plain[cursor++] == '+' )
        {
          while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
            ++cursor;
          const size_t number_begin = cursor;
          if ( cursor + 2 <= plain.size()
            && plain[cursor] == '0'
            && (plain[cursor + 1] == 'x' || plain[cursor + 1] == 'X') )
          {
            cursor += 2;
            while ( cursor < plain.size()
                 && std::isxdigit(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
          }
          else
          {
            while ( cursor < plain.size()
                 && std::isdigit(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
          }
          if ( cursor > number_begin )
          {
            const std::string number =
              plain.substr(number_begin, cursor - number_begin);
            while ( cursor < plain.size()
                 && (plain[cursor] == 'u'
                  || plain[cursor] == 'U'
                  || plain[cursor] == 'l'
                  || plain[cursor] == 'L') )
            {
              ++cursor;
            }
            while ( cursor < plain.size()
                 && std::isspace(uchar(plain[cursor])) != 0 )
            {
              ++cursor;
            }
            if ( cursor + 2 < plain.size()
              && plain[cursor] == ')'
              && plain[cursor + 1] == ')'
              && plain[cursor + 2] == '(' )
            {
              const uval_t slot =
                uval_t(::strtoull(number.c_str(), nullptr, 0));
              *match_start = marker;
              *match_end = cursor + 2;
              *object_start = object_begin;
              *object_end = object_finish;
              *byte_offset = slot * (inf_is_64bit() ? 8 : 4);
              return true;
            }
          }
        }
      }
    }

    if ( find_vtable_cast_call_pattern(
          plain,
          marker,
          match_start,
          match_end,
          object_start,
          object_end,
          byte_offset) )
    {
      return true;
    }

    marker = plain.find("(*(", marker + 3);
  }
  return false;
}

bool rewrite_vtable_line(
        simpleline_t *line,
        int line_number,
        vtable_markers_t *markers)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, line->line);
  const std::string plain(plain_qstr.c_str());
  const qstring original = line->line;

  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  size_t search_from = 0;
  ptrdiff_t column_delta = 0;
  bool changed = false;
  qstring rewritten;

  while ( search_from < plain.size() )
  {
    size_t match_start = 0;
    size_t match_end = 0;
    size_t object_start = 0;
    size_t object_end = 0;
    uval_t byte_offset = 0;
    if ( !find_vtable_pattern(
          plain,
          search_from,
          &match_start,
          &match_end,
          &object_start,
          &object_end,
          &byte_offset) )
    {
      break;
    }
    if ( byte_offset % pointer_size != 0 )
    {
      search_from = match_end;
      continue;
    }

    const char *raw_begin = original.c_str();
    const char *raw_search_from = tag_advance(raw_begin, int(search_from));
    const char *raw_prefix_end = tag_advance(raw_begin, int(match_start));
    const char *raw_object_begin = tag_advance(raw_begin, int(object_start));
    const char *raw_object_end = tag_advance(raw_begin, int(object_end));
    rewritten.append(raw_search_from, raw_prefix_end - raw_search_from);
    rewritten.append(raw_object_begin, raw_object_end - raw_object_begin);

    append_colored(&rewritten, "->", SCOLOR_SYMBOL);
    const int token_start =
      int(ptrdiff_t(match_start) + column_delta + ptrdiff_t(object_end - object_start) + 2);
    append_colored(&rewritten, "VTABLE", SCOLOR_DEFAULT);
    append_colored(&rewritten, "[", SCOLOR_SYMBOL);

    const uval_t slot = byte_offset / pointer_size;
    qstring slot_text;
    slot_text.sprnt("0x%" FMT_64 "X", uint64(slot));
    append_colored(&rewritten, slot_text.c_str(), SCOLOR_NUMBER);
    append_colored(&rewritten, "]", SCOLOR_SYMBOL);
    const int token_end = token_start + 8 + int(slot_text.length());

    vtable_marker_t &marker = markers->push_back();
    marker.line = line_number;
    marker.start_column = token_start;
    marker.end_column = token_end;
    marker.byte_offset = byte_offset;
    marker.slot = slot;
    marker.object_name = plain.substr(object_start, object_end - object_start).c_str();

    const size_t replacement_length =
      object_end - object_start + 10 + slot_text.length();
    column_delta += ptrdiff_t(replacement_length) - ptrdiff_t(match_end - match_start);
    search_from = match_end;
    changed = true;
  }

  if ( changed )
  {
    const char *raw_tail = tag_advance(original.c_str(), int(search_from));
    rewritten.append(raw_tail);
    line->line.swap(rewritten);
  }
  return changed;
}

struct indirect_vtable_binding_t
{
  std::string variable;
  qstring object_name;
  qstring class_name_override;
  uval_t byte_offset = 0;
  int assignment_line = -1;
  int variable_column = 0;
  int expression_start = 0;
  int expression_end = 0;
};

struct vtable_pointer_alias_t
{
  std::string variable;
  qstring object_name;
  qstring class_name_override;
};

bool find_assigned_variable(
      const std::string &plain,
      size_t *equals,
      size_t *lhs_start,
      size_t *lhs_end)
{
  *equals = plain.find('=');
  if ( *equals == std::string::npos )
    return false;
  if ( *equals + 1 < plain.size() && plain[*equals + 1] == '=' )
    return false;
  size_t operator_column = *equals;
  while ( operator_column > 0
       && std::isspace(uchar(plain[operator_column - 1])) != 0 )
  {
    --operator_column;
  }
  if ( operator_column > 0
    && strchr("!<>=+-*/%&|^", plain[operator_column - 1]) != nullptr )
  {
    return false;
  }
  *lhs_end = *equals;
  while ( *lhs_end > 0 && std::isspace(uchar(plain[*lhs_end - 1])) != 0 )
    --*lhs_end;
  *lhs_start = *lhs_end;
  while ( *lhs_start > 0 && is_identifier_char(plain[*lhs_start - 1]) )
    --*lhs_start;
  return *lhs_start < *lhs_end && is_identifier_start(plain[*lhs_start]);
}

bool parse_integer_literal(
      const std::string &plain,
      size_t *cursor,
      uval_t *value)
{
  while ( *cursor < plain.size() && std::isspace(uchar(plain[*cursor])) != 0 )
    ++*cursor;
  const size_t begin = *cursor;
  if ( *cursor + 2 <= plain.size()
    && plain[*cursor] == '0'
    && (plain[*cursor + 1] == 'x' || plain[*cursor + 1] == 'X') )
  {
    *cursor += 2;
    while ( *cursor < plain.size()
         && std::isxdigit(uchar(plain[*cursor])) != 0 )
      ++*cursor;
  }
  else
  {
    while ( *cursor < plain.size() && std::isdigit(uchar(plain[*cursor])) != 0 )
      ++*cursor;
  }
  if ( *cursor == begin || (*cursor == begin + 2 && plain[begin] == '0') )
    return false;
  const std::string number = plain.substr(begin, *cursor - begin);
  *value = uval_t(::strtoull(number.c_str(), nullptr, 0));
  while ( *cursor < plain.size()
       && (plain[*cursor] == 'u' || plain[*cursor] == 'U'
        || plain[*cursor] == 'l' || plain[*cursor] == 'L') )
    ++*cursor;
  return true;
}

bool find_vtable_assignment(
      const std::string &plain,
      indirect_vtable_binding_t *binding)
{
  size_t equals = 0;
  size_t lhs_start = 0;
  size_t lhs_end = 0;
  if ( !find_assigned_variable(plain, &equals, &lhs_start, &lhs_end) )
    return false;

  size_t marker = plain.find("*(", equals + 1);
  if ( marker == std::string::npos )
    return false;
  size_t cursor = marker + 2;
  bool raw_void_form = false;
  if ( cursor < plain.size() && plain[cursor] == '*' )
  {
    raw_void_form = true;
    ++cursor;
  }
  if ( cursor >= plain.size() || !is_identifier_start(plain[cursor]) )
    return false;
  const size_t object_start = cursor++;
  while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
    ++cursor;
  const size_t object_end = cursor;

  if ( !raw_void_form )
  {
    if ( cursor + 2 > plain.size() || plain.compare(cursor, 2, "->") != 0 )
      return false;
    cursor += 2;
    const size_t member_start = cursor;
    while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
      ++cursor;
    std::string member = plain.substr(member_start, cursor - member_start);
    for ( char &c : member )
      c = char(std::tolower(uchar(c)));
    if ( member != "vtable" && member != "vftable" )
      return false;
  }

  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor >= plain.size() || plain[cursor++] != '+' )
    return false;
  uval_t offset = 0;
  if ( !parse_integer_literal(plain, &cursor, &offset) )
    return false;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor >= plain.size() || plain[cursor] != ')' )
    return false;
  ++cursor;

  binding->variable = plain.substr(lhs_start, lhs_end - lhs_start);
  binding->object_name = plain.substr(object_start, object_end - object_start).c_str();
  binding->byte_offset = raw_void_form
    ? offset
    : offset * (inf_is_64bit() ? 8 : 4);
  binding->variable_column = int(lhs_start);
  binding->expression_start = int(marker);
  binding->expression_end = int(cursor);
  return binding->byte_offset % (inf_is_64bit() ? 8 : 4) == 0;
}

bool find_vtable_pointer_alias_assignment(
      const std::string &plain,
      vtable_pointer_alias_t *alias)
{
  size_t equals = 0;
  size_t lhs_start = 0;
  size_t lhs_end = 0;
  if ( !find_assigned_variable(plain, &equals, &lhs_start, &lhs_end) )
    return false;

  size_t cursor = equals + 1;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor >= plain.size() || !is_identifier_start(plain[cursor]) )
    return false;
  const size_t object_start = cursor++;
  while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
    ++cursor;
  const size_t object_end = cursor;
  if ( cursor + 2 > plain.size() || plain.compare(cursor, 2, "->") != 0 )
    return false;
  cursor += 2;
  const size_t member_start = cursor;
  while ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
    ++cursor;
  std::string member = plain.substr(member_start, cursor - member_start);
  for ( char &c : member )
    c = char(std::tolower(uchar(c)));
  if ( member != "vtable" && member != "vftable" )
    return false;

  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor < plain.size() && plain[cursor] == ';' )
    ++cursor;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor != plain.size() )
    return false;

  alias->variable = plain.substr(lhs_start, lhs_end - lhs_start);
  alias->object_name = plain.substr(object_start, object_end - object_start).c_str();
  return true;
}

bool find_vtable_alias_slot_assignment(
      const std::string &plain,
      const vtable_pointer_alias_t &alias,
      indirect_vtable_binding_t *binding)
{
  size_t equals = 0;
  size_t lhs_start = 0;
  size_t lhs_end = 0;
  if ( !find_assigned_variable(plain, &equals, &lhs_start, &lhs_end) )
    return false;

  size_t cursor = equals + 1;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  const size_t expression_start = cursor;
  if ( cursor + alias.variable.length() > plain.size()
    || plain.compare(cursor, alias.variable.length(), alias.variable) != 0 )
  {
    return false;
  }
  cursor += alias.variable.length();
  if ( cursor < plain.size() && is_identifier_char(plain[cursor]) )
    return false;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor >= plain.size() || plain[cursor++] != '[' )
    return false;
  uval_t slot = 0;
  if ( !parse_integer_literal(plain, &cursor, &slot) )
    return false;
  while ( cursor < plain.size() && std::isspace(uchar(plain[cursor])) != 0 )
    ++cursor;
  if ( cursor >= plain.size() || plain[cursor++] != ']' )
    return false;

  binding->variable = plain.substr(lhs_start, lhs_end - lhs_start);
  binding->object_name = alias.object_name;
  binding->class_name_override = alias.class_name_override;
  binding->byte_offset = slot * (inf_is_64bit() ? 8 : 4);
  binding->variable_column = int(lhs_start);
  binding->expression_start = int(expression_start);
  binding->expression_end = int(cursor);
  return true;
}

qstring infer_containing_class(cfunc_t *cfunc)
{
  qstring function_name = get_short_name(cfunc->entry_ea);
  std::string name(function_name.c_str());
  const size_t separator = name.rfind("::");
  qstring candidate;
  if ( separator != std::string::npos )
  {
    candidate = name.substr(0, separator).c_str();
  }
  else
  {
    itanium_method_t method;
    if ( !parse_itanium_method(function_name, &method) )
      return qstring();
    candidate = method.class_name;
  }
  qstring vtable_name;
  ea_t vtable_ea = BADADDR;
  return find_class_vtable(candidate, &vtable_name, &vtable_ea)
       ? candidate
       : qstring();
}

void collect_indirect_vtable_markers(
      cfunc_t *cfunc,
      vtable_markers_t *markers)
{
  qvector<indirect_vtable_binding_t> bindings;
  qvector<vtable_pointer_alias_t> aliases;
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
  {
    qstring plain_qstr;
    tag_remove(&plain_qstr, cfunc->sv[line_number].line);
    const std::string plain(plain_qstr.c_str());

    size_t equals = 0;
    size_t lhs_start = 0;
    size_t lhs_end = 0;
    const bool has_assignment =
      find_assigned_variable(plain, &equals, &lhs_start, &lhs_end);
    const std::string assigned_variable = has_assignment
      ? plain.substr(lhs_start, lhs_end - lhs_start)
      : std::string();

    vtable_pointer_alias_t new_alias;
    const bool has_new_alias =
      find_vtable_pointer_alias_assignment(plain, &new_alias);
    if ( has_assignment )
    {
      for ( auto alias = aliases.begin(); alias != aliases.end(); )
      {
        if ( alias->variable == assigned_variable )
          alias = aliases.erase(alias);
        else
          ++alias;
      }
    }
    if ( has_new_alias )
    {
      qstring class_name, vtable_name;
      ea_t vtable_ea = BADADDR;
      if ( !find_object_vtable(
            cfunc,
            new_alias.object_name,
            &class_name,
            &vtable_name,
            &vtable_ea) )
      {
        new_alias.class_name_override = infer_containing_class(cfunc);
      }
      if ( !new_alias.class_name_override.empty() || !class_name.empty() )
        aliases.push_back(new_alias);
    }

    indirect_vtable_binding_t binding;
    bool found_binding = find_vtable_assignment(plain, &binding);
    if ( !found_binding )
    {
      for ( const vtable_pointer_alias_t &alias : aliases )
      {
        if ( find_vtable_alias_slot_assignment(plain, alias, &binding) )
        {
          found_binding = true;
          break;
        }
      }
    }
    if ( !found_binding )
      continue;
    binding.assignment_line = line_number;

    if ( binding.class_name_override.empty() )
    {
      qstring class_name, vtable_name;
      ea_t vtable_ea = BADADDR;
      if ( !find_object_vtable(
            cfunc,
            binding.object_name,
            &class_name,
            &vtable_name,
            &vtable_ea) )
      {
        binding.class_name_override = infer_containing_class(cfunc);
      }
      if ( binding.class_name_override.empty() && class_name.empty() )
        continue;
    }
    bindings.push_back(binding);
  }

  for ( const indirect_vtable_binding_t &binding : bindings )
  {
    for ( int line_number = binding.assignment_line;
          line_number < cfunc->sv.size();
          ++line_number )
    {
      qstring plain_qstr;
      tag_remove(&plain_qstr, cfunc->sv[line_number].line);
      const std::string plain(plain_qstr.c_str());
      if ( line_number != binding.assignment_line )
      {
        size_t equals = 0;
        size_t lhs_start = 0;
        size_t lhs_end = 0;
        if ( find_assigned_variable(plain, &equals, &lhs_start, &lhs_end)
          && plain.substr(lhs_start, lhs_end - lhs_start) == binding.variable )
        {
          break;
        }
      }
      size_t token = line_number == binding.assignment_line
                   ? size_t(binding.expression_start)
                   : plain.find(binding.variable + "(");
      if ( token == std::string::npos )
        continue;
      if ( line_number != binding.assignment_line
        && token > 0 && is_identifier_char(plain[token - 1]) )
        continue;

      vtable_marker_t &marker = markers->push_back();
      marker.line = line_number;
      marker.start_column = int(token);
      marker.end_column = line_number == binding.assignment_line
        ? binding.expression_end
        : int(token + binding.variable.length());
      marker.byte_offset = binding.byte_offset;
      marker.slot = binding.byte_offset / pointer_size;
      marker.object_name = binding.object_name;
      marker.class_name_override = binding.class_name_override;
      marker.assignment_reference = line_number == binding.assignment_line;
    }
  }
}

bool normalize_vtable_colors(simpleline_t *line)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, line->line);
  const std::string plain(plain_qstr.c_str());
  const qstring original = line->line;

  size_t search_from = 0;
  bool changed = false;
  qstring rewritten;
  while ( search_from < plain.size() )
  {
    const size_t arrow = plain.find("->VTABLE[", search_from);
    if ( arrow == std::string::npos )
      break;

    size_t object_start = arrow;
    while ( object_start > search_from
         && is_identifier_char(plain[object_start - 1]) )
    {
      --object_start;
    }
    if ( object_start == arrow || !is_identifier_start(plain[object_start]) )
    {
      search_from = arrow + 2;
      continue;
    }

    const size_t number_start = arrow + 9;
    const size_t token_end = plain.find(']', number_start);
    if ( token_end == std::string::npos )
      break;

    const std::string object =
      plain.substr(object_start, arrow - object_start);
    const std::string number =
      plain.substr(number_start, token_end - number_start);
    if ( number.empty() )
    {
      search_from = token_end + 1;
      continue;
    }

    const char *raw_begin = original.c_str();
    const char *raw_search_from = tag_advance(raw_begin, int(search_from));
    const char *raw_object_start = tag_advance(raw_begin, int(object_start));
    const char object_color_value =
      find_identifier_color(original, object, token_end + 1);
    const char object_color[] = { object_color_value, '\0' };
    rewritten.append(raw_search_from, raw_object_start - raw_search_from);
    append_colored(&rewritten, object.c_str(), object_color);
    append_colored(&rewritten, "->", SCOLOR_SYMBOL);
    append_colored(&rewritten, "VTABLE", SCOLOR_DEFAULT);
    append_colored(&rewritten, "[", SCOLOR_SYMBOL);
    append_colored(&rewritten, number.c_str(), SCOLOR_NUMBER);
    append_colored(&rewritten, "]", SCOLOR_SYMBOL);

    search_from = token_end + 1;
    changed = true;
  }

  if ( changed )
  {
    const char *raw_tail = tag_advance(original.c_str(), int(search_from));
    rewritten.append(raw_tail);
    line->line.swap(rewritten);
  }
  return changed;
}

void collect_rendered_vtable_markers(
      const simpleline_t &line,
      int line_number,
      vtable_markers_t *markers)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, line.line);
  const std::string plain(plain_qstr.c_str());
  size_t token_start = plain.find("VTABLE[");
  while ( token_start != std::string::npos )
  {
    const size_t number_start = token_start + 7;
    const size_t token_end = plain.find(']', number_start);
    if ( token_end == std::string::npos )
      break;

    if ( token_start >= 2 && plain.compare(token_start - 2, 2, "->") == 0 )
    {
      size_t object_start = token_start - 2;
      while ( object_start > 0 && is_identifier_char(plain[object_start - 1]) )
        --object_start;

      const std::string number =
        plain.substr(number_start, token_end - number_start);
      char *number_end = nullptr;
      const uval_t slot = uval_t(::strtoull(number.c_str(), &number_end, 0));
      if ( object_start < token_start - 2
        && is_identifier_start(plain[object_start])
        && number_end != number.c_str()
        && *number_end == '\0' )
      {
        bool duplicate = false;
        for ( const vtable_marker_t &existing : *markers )
        {
          if ( existing.line == line_number
            && existing.start_column == int(token_start) )
          {
            duplicate = true;
            break;
          }
        }
        if ( !duplicate )
        {
          vtable_marker_t &marker = markers->push_back();
          marker.line = line_number;
          marker.start_column = int(token_start);
          marker.end_column = int(token_end + 1);
          marker.slot = slot;
          marker.byte_offset = slot * (inf_is_64bit() ? 8 : 4);
          marker.object_name =
            plain.substr(object_start, token_start - 2 - object_start).c_str();
        }
      }
    }
    token_start = plain.find("VTABLE[", token_end + 1);
  }
}

void apply_named_vtable_tokens(cfunc_t *cfunc, vtable_markers_t *markers)
{
  for ( vtable_marker_t &marker : *markers )
    get_named_vtable_entry(cfunc, &marker);

  for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
  {
    qvector<vtable_marker_t *> line_markers;
    for ( vtable_marker_t &marker : *markers )
    {
      if ( marker.line == line_number
        && (!marker.display_name.empty() || marker.assignment_reference) )
        line_markers.push_back(&marker);
    }
    if ( line_markers.empty() )
      continue;
    std::sort(
      line_markers.begin(),
      line_markers.end(),
      [](const vtable_marker_t *left, const vtable_marker_t *right)
      {
        return left->start_column < right->start_column;
      });

    simpleline_t &line = cfunc->sv[line_number];
    const qstring original = line.line;
    qstring rewritten;
    int previous_column = 0;
    int column_delta = 0;
    for ( vtable_marker_t *marker : line_markers )
    {
      const int old_start = marker->start_column;
      const int old_end = marker->end_column;
      const char *raw_previous = tag_advance(original.c_str(), previous_column);
      const char *raw_start = tag_advance(original.c_str(), old_start);
      rewritten.append(raw_previous, raw_start - raw_previous);

      qstring replacement;
      if ( marker->assignment_reference )
      {
        replacement = "&";
        replacement.append(marker->object_name);
        replacement.append("->");
        if ( !marker->display_name.empty() )
        {
          replacement.append(marker->display_name);
        }
        else
        {
          replacement.append("VTABLE[0x");
          replacement.cat_sprnt("%" FMT_64 "X]", uint64(marker->slot));
        }
      }
      else
      {
        replacement = marker->display_name;
      }
      if ( marker->assignment_reference )
      {
        append_colored(&rewritten, "&", SCOLOR_SYMBOL);
        const char object_color_value =
          find_identifier_color(original, marker->object_name.c_str(), old_start);
        const char object_color[] = { object_color_value, '\0' };
        append_colored(&rewritten, marker->object_name.c_str(), object_color);
        append_colored(&rewritten, "->", SCOLOR_SYMBOL);
        if ( !marker->display_name.empty() )
        {
          append_colored(&rewritten, marker->display_name.c_str(), SCOLOR_CODNAME);
        }
        else
        {
          append_colored(&rewritten, "VTABLE", SCOLOR_DEFAULT);
          append_colored(&rewritten, "[", SCOLOR_SYMBOL);
          qstring slot_text;
          slot_text.sprnt("0x%" FMT_64 "X", uint64(marker->slot));
          append_colored(&rewritten, slot_text.c_str(), SCOLOR_NUMBER);
          append_colored(&rewritten, "]", SCOLOR_SYMBOL);
        }
      }
      else
      {
        append_colored(&rewritten, replacement.c_str(), SCOLOR_CODNAME);
      }

      const int replacement_start = old_start + column_delta;
      marker->start_column = marker->assignment_reference
        ? replacement_start + int(marker->object_name.length()) + 3
        : replacement_start;
      marker->end_column = replacement_start + int(replacement.length());
      column_delta += int(replacement.length()) - (old_end - old_start);
      previous_column = old_end;
    }
    rewritten.append(tag_advance(original.c_str(), previous_column));
    line.line.swap(rewritten);
  }
}

void collect_named_vtable_markers(cfunc_t *cfunc, vtable_markers_t *markers)
{
  const size_t pointer_size = inf_is_64bit() ? 8 : 4;
  const lvars_t *lvars = cfunc->get_lvars();
  for ( const lvar_t &lvar : *lvars )
  {
    qstring class_name;
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_object_vtable(
          cfunc,
          lvar.name,
          &class_name,
          &vtable_name,
          &vtable_ea) )
    {
      continue;
    }

    size_t slot_count = size_t(get_item_size(vtable_ea)) / pointer_size;
    if ( slot_count <= 1 )
      slot_count = 64;
    for ( size_t slot = 0; slot < slot_count; ++slot )
    {
      vtable_marker_t candidate;
      candidate.object_name = lvar.name;
      candidate.slot = slot;
      candidate.byte_offset = slot * pointer_size;
      if ( !get_named_vtable_entry(cfunc, &candidate) )
      {
        if ( get_item_size(vtable_ea) <= pointer_size )
          break;
        continue;
      }

      const std::string pattern =
        std::string(lvar.name.c_str()) + "->" + candidate.display_name.c_str();
      for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
      {
        qstring plain_qstr;
        tag_remove(&plain_qstr, cfunc->sv[line_number].line);
        const std::string plain(plain_qstr.c_str());
        size_t token_start = plain.find(pattern);
        while ( token_start != std::string::npos )
        {
          const size_t method_start = token_start + lvar.name.length() + 2;
          const size_t method_end = method_start + candidate.display_name.length();
          if ( method_end < plain.size() && plain[method_end] == '(' )
          {
            candidate.line = line_number;
            candidate.start_column = int(method_start);
            candidate.end_column = int(method_end);
            markers->push_back(candidate);
            break;
          }
          token_start = plain.find(pattern, token_start + pattern.length());
        }
      }
    }
  }
}

bool vtable_rewrite_self_test()
{
  simpleline_t line;
  line.line = "return *(*";
  append_colored(&line.line, "a1", SCOLOR_LOCNAME);
  line.line.append(" + ");
  append_colored(&line.line, "0x10", SCOLOR_NUMBER);
  line.line.append(")(a1, 0);");

  vtable_markers_t markers;
  if ( !rewrite_vtable_line(&line, 0, &markers) || markers.size() != 1 )
    return false;
  normalize_vtable_colors(&line);

  qstring plain;
  tag_remove(&plain, line.line);
  if ( plain != "return a1->VTABLE[0x2](a1, 0);" )
    return false;

  const std::string raw(line.line.c_str());
  const std::string colored_object =
    std::string(SCOLOR_ON) + SCOLOR_LIBNAME + "a1"
    + SCOLOR_OFF + SCOLOR_LIBNAME;
  const std::string colored_name =
    std::string(SCOLOR_ON) + SCOLOR_DEFAULT + "VTABLE"
    + SCOLOR_OFF + SCOLOR_DEFAULT;
  const std::string colored_number =
    std::string(SCOLOR_ON) + SCOLOR_NUMBER + "0x2"
    + SCOLOR_OFF + SCOLOR_NUMBER;
  indirect_vtable_binding_t typed_binding;
  indirect_vtable_binding_t raw_binding;
  indirect_vtable_binding_t aliased_binding;
  vtable_pointer_alias_t pointer_alias;
  const bool indirect_patterns_ok =
    find_vtable_assignment(
      "v19 = *(this->VTable + 0x163);", &typed_binding)
    && typed_binding.variable == "v19"
    && typed_binding.object_name == "this"
    && typed_binding.byte_offset == 0xB18
    && find_vtable_assignment(
      "v19 = *(*this + 0xB18LL);", &raw_binding)
    && raw_binding.variable == "v19"
    && raw_binding.object_name == "this"
    && raw_binding.byte_offset == 0xB18
    && find_vtable_pointer_alias_assignment(
      "VTable = this->VTable;", &pointer_alias)
    && pointer_alias.variable == "VTable"
    && pointer_alias.object_name == "this"
    && find_vtable_alias_slot_assignment(
      "RequestRespawn_Validate = VTable[0x271];",
      pointer_alias,
      &aliased_binding)
    && aliased_binding.variable == "RequestRespawn_Validate"
    && aliased_binding.object_name == "this"
    && aliased_binding.byte_offset == 0x1388;
  itanium_method_t parsed_itanium;
  qstring remangled;
  const bool itanium_ok = parse_itanium_method(
        "_ZN16ATICharacterBase20execSpawnPieceOfMeatEv",
        &parsed_itanium)
    && parsed_itanium.class_name == "ATICharacterBase"
    && parsed_itanium.method_name == "execSpawnPieceOfMeat"
    && mangle_itanium_method(
      "ATICharacterBase::SpawnPieceOfMeat", &remangled)
    && remangled == "_ZN16ATICharacterBase16SpawnPieceOfMeatEv";

  return raw.find(colored_object) != std::string::npos
      && raw.find(colored_name) != std::string::npos
      && raw.find(colored_number) != std::string::npos
      && markers[0].byte_offset == 0x10
      && markers[0].slot == 2
      && indirect_patterns_ok
      && itanium_ok;
}

struct xref_entry_t
{
  ea_t from = BADADDR;
  uchar type = 0;
};

using xref_entries_t = qvector<xref_entry_t>;

struct xref_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];

  ea_t target;
  const xref_entries_t &entries;

  xref_popup_t(ea_t target_, const xref_entries_t &entries_, const char *title_)
    : chooser_t(
        CH_MODAL | CH_KEEP,
        4,
        widths,
        headers,
        title_),
      target(target_),
      entries(entries_)
  {
    deflt_col = 2;
  }

  size_t idaapi get_count() const override
  {
    return entries.size();
  }

  ea_t idaapi get_ea(size_t n) const override
  {
    return entries[n].from;
  }

  void idaapi get_row(
        qstrvec_t *cols_,
        int *,
        chooser_item_attrs_t *,
        size_t n) const override
  {
    const xref_entry_t &entry = entries[n];
    qstrvec_t &cols = *cols_;
    cols[0] = entry.from < target ? "Up" : entry.from > target ? "Down" : "";
    cols[1].sprnt("%c", xrefchar(entry.type));
    cols[2].sprnt("%a", entry.from);
    generate_disasm_line(&cols[3], entry.from, GENDSM_REMOVE_TAGS);
  }
};

const int xref_popup_t::widths[] =
{
  6,
  4,
  CHCOL_HEX | 16,
  60,
};

const char *const xref_popup_t::headers[] =
{
  "Direction",
  "Type",
  "Address",
  "Instruction",
};

bool show_xref_popup(ea_t target)
{
  xref_entries_t entries;
  xrefblk_t xb;
  for ( bool ok = xb.first_to(target, XREF_ALL); ok; ok = xb.next_to() )
  {
    xref_entry_t &entry = entries.push_back();
    entry.from = xb.from;
    entry.type = xb.type;
  }

  qstring target_name;
  get_ea_name(&target_name, target);
  if ( target_name.empty() )
    target_name.sprnt("%a", target);

  qstring title;
  title.sprnt("Xrefs to %s", target_name.c_str());
  if ( entries.empty() )
  {
    warning("There are no cross-references to %s", target_name.c_str());
    return false;
  }

  xref_popup_t popup(target, entries, title.c_str());
  const ssize_t selected = popup.choose();
  if ( selected < 0 || selected >= entries.size() )
    return true;

  jumpto(entries[selected].from);
  return true;
}

void jump_to_disassembly(ea_t target)
{
  TWidget *disassembly = find_widget("IDA View-A");
  if ( disassembly == nullptr )
    disassembly = open_disasm_window("IDA View-A");
  if ( disassembly != nullptr )
    activate_widget(disassembly, true);
  jumpto(target);
}

struct hierarchy_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];
  const hierarchy_targets_t &entries;
  mutable int activated_column = 2;

  hierarchy_popup_t(const hierarchy_targets_t &entries_, const char *title_)
    : chooser_t(CH_MODAL | CH_KEEP, 4, widths, headers, title_), entries(entries_)
  {
    deflt_col = 0;
  }

  size_t idaapi get_count() const override { return entries.size(); }
  ea_t idaapi get_ea(size_t) const override { return BADADDR; }

  cbret_t idaapi enter(size_t n) override
  {
    activated_column = 2;
#ifdef __NT__
    if ( (GetKeyState(VK_RETURN) & 0x8000) == 0 )
    {
      HWND window = GetForegroundWindow();
      POINT cursor;
      RECT client;
      if ( window != nullptr
        && GetCursorPos(&cursor)
        && ScreenToClient(window, &cursor)
        && GetClientRect(window, &client)
        && client.right > client.left )
      {
        UINT dpi = GetDpiForWindow(window);
        if ( dpi == 0 )
          dpi = 96;
        const int char_width = MulDiv(9, int(dpi), 96);
        const int base_padding = MulDiv(14, int(dpi), 96);
        const int separator_padding = MulDiv(5, int(dpi), 96);
        const int class_end = 24 * char_width + base_padding;
        const int vtable_end = (24 + 28) * char_width
                             + base_padding + separator_padding;
        const int implementation_end = (24 + 28 + 40) * char_width
                                      + base_padding + 2 * separator_padding;
        activated_column = cursor.x < class_end ? 0
                         : cursor.x < vtable_end ? 1
                         : cursor.x < implementation_end ? 2
                         : 3;
      }
    }
#endif
    return chooser_t::enter(n);
  }

  void idaapi get_row(
        qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const override
  {
    const hierarchy_target_t &entry = entries[n];
    qstrvec_t &cols = *cols_;
    cols[0] = entry.class_name;
    cols[1] = entry.vtable_name;
    cols[2] = get_short_name(entry.target);
    cols[3].sprnt("%a", entry.target);
  }
};

const int hierarchy_popup_t::widths[] = { 24, 28, 40, CHCOL_HEX | 16 };
const char *const hierarchy_popup_t::headers[] =
  { "Class", "VTABLE", "Implementation", "Address" };

struct declaring_class_popup_t final : chooser_t
{
  static const int widths[];
  static const char *const headers[];
  const qvector<qstring> &classes;

  declaring_class_popup_t(const qvector<qstring> &classes_, const char *title_)
    : chooser_t(CH_MODAL | CH_KEEP, 1, widths, headers, title_), classes(classes_)
  {
  }

  size_t idaapi get_count() const override { return classes.size(); }

  void idaapi get_row(
        qstrvec_t *cols_, int *, chooser_item_attrs_t *, size_t n) const override
  {
    (*cols_)[0] = classes[n];
  }
};

const int declaring_class_popup_t::widths[] = { 40 };
const char *const declaring_class_popup_t::headers[] = { "First declaring class" };

bool show_xrefs(vdui_t *vu)
{
  if ( vu == nullptr || !vu->get_current_item(USE_KEYBOARD) )
    return false;

  ea_t target = BADADDR;
  if ( vu->item.citype == VDI_FUNC && vu->item.f != nullptr )
  {
    target = vu->item.f->entry_ea;
  }
  else if ( vu->item.is_citem()
         && vu->item.it != nullptr
         && vu->item.it->is_expr()
         && vu->item.e->op == cot_obj )
  {
    target = vu->item.e->obj_ea;
  }

  if ( target != BADADDR )
    return show_xref_popup(target);

  warning("The item under the cursor does not have an addressable xref target");
  return false;
}

struct show_xrefs_action_t final : action_handler_t
{
  int idaapi activate(action_activation_ctx_t *ctx) override
  {
    if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
      return 0;

    return show_xrefs(get_widget_vdui(ctx->widget)) ? 1 : 0;
  }

  action_state_t idaapi update(action_update_ctx_t *ctx) override
  {
    return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
         ? AST_ENABLE_FOR_WIDGET
         : AST_DISABLE_FOR_WIDGET;
  }
};

show_xrefs_action_t show_xrefs_action;

ssize_t idaapi decompiler_callback(void *, hexrays_event_t, va_list);

struct pseudocode_xrefs_plugmod_t final : plugmod_t
{
  struct ui_listener_t final : event_listener_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit ui_listener_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
      if ( code != ui_preprocess_action )
        return 0;
      const char *action_name = va_arg(va, const char *);
      if ( action_name == nullptr )
        return 0;

      TWidget *widget = get_current_widget();
      if ( widget == nullptr || get_widget_type(widget) != BWN_PSEUDOCODE )
        return 0;
      vdui_t *vu = get_widget_vdui(widget);
      if ( strcmp(action_name, "hx:Rename") == 0 )
        return plugin->rename_vtable_target(vu) ? 1 : 0;
      return 0;
    }
  };

  struct view_listener_t final : event_listener_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit view_listener_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    ssize_t idaapi on_event(ssize_t code, va_list va) override
    {
      TWidget *view = va_arg(va, TWidget *);
      if ( view == nullptr || get_widget_type(view) != BWN_PSEUDOCODE )
        return 0;

      if ( code == view_keydown )
      {
        const int key_code = va_arg(va, int);
        const int state = va_arg(va, int);
        if ( state == 0 && (key_code == 'N' || key_code == 'n') )
        {
          debug_log("view key N: view=%p", view);
          return plugin->rename_vtable_target(get_widget_vdui(view)) ? 1 : 0;
        }
        return 0;
      }

      if ( code != view_dblclick )
        return 0;

      const view_mouse_event_t *event = va_arg(va, const view_mouse_event_t *);

      debug_log(
        "view double click: view=%p screen=(%u,%u) renderer=(%d,%d)",
        view,
        event != nullptr ? event->x : 0,
        event != nullptr ? event->y : 0,
        event != nullptr ? event->renderer_pos.cx : -1,
        event != nullptr ? event->renderer_pos.cy : -1);
      return plugin->jump_to_vtable_target(
        get_widget_vdui(view),
        USE_MOUSE,
        false) ? 1 : 0;
    }
  };

  struct jump_vtable_target_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit jump_vtable_target_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->jump_to_vtable_target(
        get_widget_vdui(ctx->widget),
        USE_KEYBOARD,
        true) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct show_vtable_index_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit show_vtable_index_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->show_vtable_index(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct rename_vtable_target_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit rename_vtable_target_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->rename_vtable_target(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return AST_DISABLE_FOR_WIDGET;
      vtable_marker_t fallback;
      return plugin->find_vtable_marker(
               get_widget_vdui(ctx->widget),
               USE_KEYBOARD,
               &fallback) != nullptr
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct hierarchy_xrefs_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit hierarchy_xrefs_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      if ( plugin->show_hierarchy_versions(get_widget_vdui(ctx->widget)) )
        return 1;
      return process_ui_action("hx:JmpXref") ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct hierarchy_graph_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit hierarchy_graph_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->show_hierarchy_graph(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return AST_DISABLE_FOR_WIDGET;
      vtable_marker_t fallback;
      return plugin->find_vtable_marker(
               get_widget_vdui(ctx->widget),
               USE_KEYBOARD,
               &fallback) != nullptr
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct hide_inherited_graph_nodes_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit hide_inherited_graph_nodes_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      return ctx != nullptr && plugin->toggle_inherited_graph_nodes(ctx->widget)
           ? 1
           : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      const hierarchy_graph_data_t *graph = ctx != nullptr
                                          ? plugin->find_hierarchy_graph(ctx->widget)
                                          : nullptr;
      if ( graph == nullptr )
        return AST_DISABLE_FOR_WIDGET;
      update_action_checked(
        VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME,
        graph->hide_inherited);
      return AST_ENABLE_FOR_WIDGET;
    }
  };

  struct set_declaring_class_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit set_declaring_class_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx == nullptr || ctx->widget_type != BWN_PSEUDOCODE )
        return 0;
      return plugin->set_declaring_class(get_widget_vdui(ctx->widget)) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
           ? AST_ENABLE_FOR_WIDGET
           : AST_DISABLE_FOR_WIDGET;
    }
  };

  struct edit_vtable_type_action_t final : action_handler_t
  {
    pseudocode_xrefs_plugmod_t *plugin;

    explicit edit_vtable_type_action_t(pseudocode_xrefs_plugmod_t *plugin_)
      : plugin(plugin_)
    {
    }

    int idaapi activate(action_activation_ctx_t *ctx) override
    {
      if ( ctx != nullptr
        && ctx->widget_type == BWN_PSEUDOCODE
        && plugin->edit_vtable_function_type(get_widget_vdui(ctx->widget)) )
      {
        return 1;
      }
      const char *fallback = ctx != nullptr && ctx->widget_type == BWN_PSEUDOCODE
                           ? "hx:SetType"
                           : "SetType";
      return process_ui_action(fallback) ? 1 : 0;
    }

    action_state_t idaapi update(action_update_ctx_t *ctx) override
    {
      return ctx != nullptr ? AST_ENABLE_FOR_WIDGET : AST_DISABLE_FOR_WIDGET;
    }
  };

  qmap<ea_t, vtable_markers_t> vtable_markers;
  qmap<ea_t, vtable_call_xrefs_t> vtable_call_xrefs;
  qmap<TWidget *, hierarchy_graph_data_t *> hierarchy_graphs;
  ui_listener_t ui_listener;
  view_listener_t view_listener;
  jump_vtable_target_action_t jump_vtable_target_action;
  show_vtable_index_action_t show_vtable_index_action;
  rename_vtable_target_action_t rename_vtable_target_action;
  hierarchy_xrefs_action_t hierarchy_xrefs_action;
  hierarchy_graph_action_t hierarchy_graph_action;
  hide_inherited_graph_nodes_action_t hide_inherited_graph_nodes_action;
  set_declaring_class_action_t set_declaring_class_action;
  edit_vtable_type_action_t edit_vtable_type_action;
  qstring native_xref_shortcut;
  qstring native_hexrays_type_shortcut;
  qstring native_disasm_type_shortcut;
  int hierarchy_graph_position_request_id = 0;

  pseudocode_xrefs_plugmod_t()
    : ui_listener(this),
      view_listener(this),
      jump_vtable_target_action(this),
      show_vtable_index_action(this),
      rename_vtable_target_action(this),
      hierarchy_xrefs_action(this),
      hierarchy_graph_action(this),
      hide_inherited_graph_nodes_action(this),
      set_declaring_class_action(this),
      edit_vtable_type_action(this)
  {
    g_active_plugin = this;

    const action_desc_t xref_desc = ACTION_DESC_LITERAL_PLUGMOD(
      ACTION_NAME,
      ACTION_LABEL,
      &show_xrefs_action,
      this,
      ACTION_HOTKEY,
      "Show cross-references to the pseudocode item under the cursor",
      -1);

    if ( !register_action(xref_desc) )
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, ACTION_NAME);

    const action_desc_t vtable_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_ACTION_NAME,
      VTABLE_ACTION_LABEL,
      &jump_vtable_target_action,
      this,
      VTABLE_ACTION_HOTKEY,
      "Jump through a typed object's matching class vtable",
      -1);

    if ( !register_action(vtable_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_ACTION_NAME);

    const action_desc_t index_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_INDEX_ACTION_NAME,
      VTABLE_INDEX_ACTION_LABEL,
      &show_vtable_index_action,
      this,
      VTABLE_INDEX_ACTION_HOTKEY,
      "Show the selected virtual method's vtable index and byte offset",
      -1);
    if ( !register_action(index_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_INDEX_ACTION_NAME);

    const action_desc_t rename_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_RENAME_ACTION_NAME,
      VTABLE_RENAME_ACTION_LABEL,
      &rename_vtable_target_action,
      this,
      nullptr,
      "Rename the function stored in the selected vtable slot",
      -1);
    if ( !register_action(rename_desc) )
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_RENAME_ACTION_NAME);

    get_action_shortcut(&native_xref_shortcut, "hx:JmpXref");
    update_action_shortcut("hx:JmpXref", nullptr);
    const action_desc_t hierarchy_xref_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_XREF_ACTION_NAME,
      VTABLE_XREF_ACTION_LABEL,
      &hierarchy_xrefs_action,
      this,
      "X",
      "Show all implementations at this hierarchy VTABLE slot; otherwise use native xrefs",
      -1);
    if ( !register_action(hierarchy_xref_desc) )
    {
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, VTABLE_XREF_ACTION_NAME);
      update_action_shortcut("hx:JmpXref", native_xref_shortcut.c_str());
      native_xref_shortcut.clear();
    }

    const action_desc_t hierarchy_graph_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_GRAPH_ACTION_NAME,
      VTABLE_GRAPH_ACTION_LABEL,
      &hierarchy_graph_action,
      this,
      VTABLE_GRAPH_ACTION_HOTKEY,
      "Show a graph of possible descendant implementations for this VTABLE slot",
      -1);
    if ( !register_action(hierarchy_graph_desc) )
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, VTABLE_GRAPH_ACTION_NAME);

    const action_desc_t hide_inherited_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME,
      VTABLE_GRAPH_HIDE_INHERITED_ACTION_LABEL,
      &hide_inherited_graph_nodes_action,
      this,
      nullptr,
      "Hide graph nodes that dispatch to the same target as a direct parent",
      -1);
    if ( register_action(hide_inherited_desc) )
    {
      update_action_checkable(VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME, true);
    }
    else
    {
      msg(
        "%s: failed to register action %s\n",
        PLUGIN.wanted_name,
        VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME);
    }

    const action_desc_t declaring_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_DECLARING_ACTION_NAME,
      VTABLE_DECLARING_ACTION_LABEL,
      &set_declaring_class_action,
      this,
      nullptr,
      "Set the first class that declares this virtual method slot",
      -1);
    if ( !register_action(declaring_desc) )
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, VTABLE_DECLARING_ACTION_NAME);

    get_action_shortcut(&native_hexrays_type_shortcut, "hx:SetType");
    get_action_shortcut(&native_disasm_type_shortcut, "SetType");
    update_action_shortcut("hx:SetType", nullptr);
    update_action_shortcut("SetType", nullptr);
    const action_desc_t type_desc = ACTION_DESC_LITERAL_PLUGMOD(
      VTABLE_TYPE_ACTION_NAME,
      VTABLE_TYPE_ACTION_LABEL,
      &edit_vtable_type_action,
      this,
      "Y",
      "Apply a function signature across this VTABLE declaration hierarchy; otherwise use native Set type",
      -1);
    if ( !register_action(type_desc) )
    {
      msg("%s: failed to register action %s\n", PLUGIN.wanted_name, VTABLE_TYPE_ACTION_NAME);
      update_action_shortcut("hx:SetType", native_hexrays_type_shortcut.c_str());
      update_action_shortcut("SetType", native_disasm_type_shortcut.c_str());
      native_hexrays_type_shortcut.clear();
      native_disasm_type_shortcut.clear();
    }

    if ( !install_hexrays_callback(decompiler_callback, this) )
      msg("%s: failed to install the pseudocode keyboard callback\n", PLUGIN.wanted_name);
    if ( !hook_event_listener(HT_VIEW, &view_listener) )
      msg("%s: failed to install the pseudocode mouse callback\n", PLUGIN.wanted_name);
    if ( !hook_event_listener(HT_UI, &ui_listener) )
      msg("%s: failed to install the pseudocode rename callback\n", PLUGIN.wanted_name);
    debug_log("plugin initialized: version=1.14.0");
  }

  ~pseudocode_xrefs_plugmod_t() override
  {
    if ( hierarchy_graph_position_request_id != 0 )
      cancel_exec_request(hierarchy_graph_position_request_id);
    if ( g_active_plugin == this )
      g_active_plugin = nullptr;

    if ( !native_xref_shortcut.empty() )
      update_action_shortcut("hx:JmpXref", native_xref_shortcut.c_str());
    if ( !native_hexrays_type_shortcut.empty() )
      update_action_shortcut("hx:SetType", native_hexrays_type_shortcut.c_str());
    if ( !native_disasm_type_shortcut.empty() )
      update_action_shortcut("SetType", native_disasm_type_shortcut.c_str());
    remove_hexrays_callback(decompiler_callback, this);
  }

  bool idaapi run(size_t) override
  {
    return false;
  }

  hierarchy_graph_data_t *find_hierarchy_graph(TWidget *widget)
  {
    const auto found = hierarchy_graphs.find(widget);
    return found != hierarchy_graphs.end() ? found->second : nullptr;
  }

  void schedule_hierarchy_graph_position(const qstring &title, int root_node)
  {
    if ( hierarchy_graph_position_request_id != 0 )
      cancel_exec_request(hierarchy_graph_position_request_id);
    hierarchy_graph_position_request_id = execute_ui_requests(
      new hierarchy_graph_position_request_t(title, root_node),
      nullptr);
  }

  bool toggle_inherited_graph_nodes(TWidget *widget)
  {
    hierarchy_graph_data_t *graph_data = find_hierarchy_graph(widget);
    graph_viewer_t *viewer = get_graph_viewer(widget);
    if ( graph_data == nullptr || viewer == nullptr )
      return false;

    graph_data->hide_inherited = !graph_data->hide_inherited;
    update_action_checked(
      VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME,
      graph_data->hide_inherited);
    refresh_viewer(viewer);
    const int root_node = find_hierarchy_graph_node(*graph_data, graph_data->root_class);
    schedule_hierarchy_graph_position(graph_data->title, root_node);
    return true;
  }

  void rewrite_vtable_calls(cfunc_t *cfunc)
  {
    vtable_markers_t &markers = vtable_markers[cfunc->entry_ea];
    markers.clear();
    for ( int line_number = 0; line_number < cfunc->sv.size(); ++line_number )
    {
      rewrite_vtable_line(&cfunc->sv[line_number], line_number, &markers);
      normalize_vtable_colors(&cfunc->sv[line_number]);
      collect_rendered_vtable_markers(
        cfunc->sv[line_number],
        line_number,
        &markers);
    }
    collect_indirect_vtable_markers(cfunc, &markers);
    if ( markers.empty() )
      collect_named_vtable_markers(cfunc, &markers);
    else
      apply_named_vtable_tokens(cfunc, &markers);
    debug_log(
      "func_printed: function=%a markers=%" FMT_Z,
      cfunc->entry_ea,
      markers.size());
    sync_vtable_xrefs(cfunc, markers);
  }

  // Recognized VTABLE[...] calls only ever existed as text-pattern matches
  // over rendered pseudocode - nothing before this ever told IDA's own
  // analysis engine that a given call site dispatches to a specific
  // implementation. As a result, native xrefs (Ctrl-X / the Xrefs subview) on
  // an implementation function only ever showed the vtable's own
  // "dq offset sub_..." data reference, never the indirect call sites that
  // reach it through the vtable. This registers real add_cref() code
  // cross-references for every resolved marker so IDA's native xref system
  // picks them up too, alongside this plugin's own "K"/hierarchy actions.
  //
  // Idempotent and self-correcting: the (call site, target) pairs
  // synthesized for this function on the previous pass are cached (keyed by
  // cfunc->entry_ea, mirroring the vtable_markers cache above) and diffed
  // against the freshly recognized set every time. Re-decompiling the same
  // function does not re-issue redundant add_cref() calls, and if a slot's
  // resolved target changes (e.g. after renaming/retyping a vtable entry
  // changes what it points to), the stale xref to the old target is removed
  // with del_cref() instead of being left behind.
  void sync_vtable_xrefs(cfunc_t *cfunc, const vtable_markers_t &markers)
  {
    vtable_call_xrefs_t current;
    for ( const vtable_marker_t &marker : markers )
    {
      if ( marker.target == BADADDR || !is_mapped(marker.target) )
        continue;

      ea_t call_ea = BADADDR;
      if ( !resolve_marker_call_ea(cfunc, marker, &call_ea)
        || call_ea == marker.target )
      {
        continue;
      }

      vtable_call_xref_t entry;
      entry.call_ea = call_ea;
      entry.target = marker.target;
      current.push_back(entry);
    }
    std::sort(current.begin(), current.end());
    current.erase(std::unique(current.begin(), current.end()), current.end());

    vtable_call_xrefs_t &previous = vtable_call_xrefs[cfunc->entry_ea];
    std::sort(previous.begin(), previous.end());

    for ( const vtable_call_xref_t &old_entry : previous )
    {
      if ( !std::binary_search(current.begin(), current.end(), old_entry) )
        del_cref(old_entry.call_ea, old_entry.target, false);
    }
    for ( const vtable_call_xref_t &new_entry : current )
    {
      if ( !std::binary_search(previous.begin(), previous.end(), new_entry) )
        add_cref(new_entry.call_ea, new_entry.target, cref_t(fl_CN | XREF_USER));
    }

    previous.swap(current);
  }

  bool parse_rendered_vtable_marker(
        vdui_t *vu,
        vtable_marker_t *marker,
        bool allow_sole_token)
  {
    if ( vu->cpos.lnnum < 0 || vu->cpos.lnnum >= vu->cfunc->sv.size() )
      return false;

    qstring plain_line;
    tag_remove(&plain_line, vu->cfunc->sv[vu->cpos.lnnum].line);
    const std::string plain(plain_line.c_str());
    vtable_marker_t sole_marker;
    size_t valid_token_count = 0;
    size_t token_start = plain.find("VTABLE[");
    while ( token_start != std::string::npos )
    {
      const size_t number_start = token_start + 7;
      const size_t token_end = plain.find(']', number_start);
      if ( token_end == std::string::npos )
        break;

      if ( token_start >= 2 && plain.compare(token_start - 2, 2, "->") == 0 )
      {
        size_t object_start = token_start - 2;
        while ( object_start > 0 && is_identifier_char(plain[object_start - 1]) )
          --object_start;
        if ( object_start == token_start - 2
          || !is_identifier_start(plain[object_start]) )
        {
          token_start = plain.find("VTABLE[", token_end + 1);
          continue;
        }

        const std::string number =
          plain.substr(number_start, token_end - number_start);
        char *number_end = nullptr;
        const uval_t slot = uval_t(::strtoull(number.c_str(), &number_end, 0));
        if ( number_end == number.c_str() || *number_end != '\0' )
        {
          token_start = plain.find("VTABLE[", token_end + 1);
          continue;
        }

        vtable_marker_t candidate;
        candidate.line = vu->cpos.lnnum;
        candidate.start_column = int(token_start);
        candidate.end_column = int(token_end + 1);
        candidate.slot = slot;
        candidate.byte_offset = slot * (inf_is_64bit() ? 8 : 4);
        candidate.object_name =
          plain.substr(object_start, token_start - 2 - object_start).c_str();
        sole_marker = candidate;
        ++valid_token_count;

        if ( vu->cpos.x >= int(token_start) && vu->cpos.x <= int(token_end) )
        {
          *marker = candidate;
          debug_log(
            "rendered fallback exact: line=%d x=%d object=%s slot=0x%" FMT_64 "X text=%s",
            vu->cpos.lnnum,
            vu->cpos.x,
            marker->object_name.c_str(),
            uint64(marker->slot),
            plain.c_str());
          return true;
        }
      }
      token_start = plain.find("VTABLE[", token_end + 1);
    }

    if ( allow_sole_token && valid_token_count == 1 )
    {
      *marker = sole_marker;
      debug_log(
        "rendered fallback sole-token: line=%d x=%d range=%d..%d object=%s slot=0x%" FMT_64 "X text=%s",
        vu->cpos.lnnum,
        vu->cpos.x,
        marker->start_column,
        marker->end_column,
        marker->object_name.c_str(),
        uint64(marker->slot),
        plain.c_str());
      return true;
    }
    return false;
  }

  const vtable_marker_t *find_vtable_marker(
        vdui_t *vu,
        input_device_t input_device,
        vtable_marker_t *fallback)
  {
    if ( vu == nullptr
      || vu->cfunc == nullptr
      || !vu->refresh_cpos(input_device) )
    {
      debug_log("marker lookup failed: no vdui/cfunc/cursor");
      return nullptr;
    }

    const auto found = vtable_markers.find(vu->cfunc->entry_ea);
    if ( found != vtable_markers.end() )
    {
      for ( const vtable_marker_t &marker : found->second )
      {
        debug_log(
          "marker candidate: cursor=(%d,%d) marker=(%d,%d..%d) object=%s slot=0x%" FMT_64 "X",
          vu->cpos.lnnum,
          vu->cpos.x,
          marker.line,
          marker.start_column,
          marker.end_column,
          marker.object_name.c_str(),
          uint64(marker.slot));
        if ( marker.line == vu->cpos.lnnum
          && vu->cpos.x >= marker.start_column
          && vu->cpos.x < marker.end_column )
        {
          return &marker;
        }
      }
    }

    debug_log(
      "stored marker miss: function=%a cursor=(%d,%d), trying rendered fallback",
      vu->cfunc->entry_ea,
      vu->cpos.lnnum,
      vu->cpos.x);
    return parse_rendered_vtable_marker(
      vu,
      fallback,
      input_device == USE_KEYBOARD) ? fallback : nullptr;
  }

  bool show_vtable_index(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker =
      find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
    {
      warning("Place the cursor on a resolved virtual method and press I");
      return false;
    }

    info(
      "%s uses VTABLE[0x%" FMT_64 "X] (byte offset 0x%" FMT_64 "X)",
      marker->display_name.empty() ? "Virtual call" : marker->display_name.c_str(),
      uint64(marker->slot),
      uint64(marker->byte_offset));
    return true;
  }

  bool rename_vtable_target(vdui_t *vu, const char *requested_name = nullptr)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker =
      find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class;
    qstring selected_vtable;
    ea_t selected_vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc,
          *marker,
          &selected_class,
          &selected_vtable,
          &selected_vtable_ea) )
    {
      warning("Could not resolve the VTABLE for '%s'", marker->object_name.c_str());
      return true;
    }

    ea_t selected_target = marker->target;
    if ( selected_target == BADADDR
      && !get_vtable_entry_target(vu->cfunc, *marker, &selected_target) )
    {
      warning(
        "%s[0x%" FMT_64 "X] does not contain a mapped function address",
        selected_vtable.c_str(),
        uint64(marker->slot));
      return true;
    }

    qstring new_name;
    if ( requested_name != nullptr )
    {
      new_name = requested_name;
    }
    else
    {
      itanium_method_t existing_itanium;
      if ( parse_itanium_method(get_name(selected_target), &existing_itanium) )
      {
        new_name = existing_itanium.class_name;
        new_name.append("::");
        new_name.append(existing_itanium.method_name);
      }
      else
      {
        new_name = get_short_name(selected_target);
        std::string display(new_name.c_str());
        const size_t namespace_separator = display.rfind("::");
        if ( namespace_separator != std::string::npos )
          display.erase(0, namespace_separator + 2);
        const std::string selected_prefix =
          std::string(identifier_from_type_name(selected_class).c_str()) + "_";
        if ( display.rfind(selected_prefix, 0) == 0 )
          display.erase(0, selected_prefix.length());
        new_name = display.c_str();
      }
      if ( !ask_str(
            &new_name,
            HIST_IDENT,
            "Rename VTABLE[0x%" FMT_64 "X]. Use Class::Method for Itanium mangling or Class: as a declaration-only hint.",
            uint64(marker->slot)) )
      {
        return true;
      }
    }

    qstring declaring_class = selected_class;
    qstring method_name = new_name;
    qvector<qstring> ancestors;
    collect_ancestor_hierarchy(selected_class, &ancestors);
    size_t declaration_hint_length = 0;
    for ( const qstring &ancestor : ancestors )
    {
      qstring hint = ancestor;
      hint.append(':');
      if ( new_name.length() >= hint.length()
        && strncmp(new_name.c_str(), hint.c_str(), hint.length()) == 0
        && (new_name.length() == hint.length()
          || new_name[hint.length()] != ':')
        && hint.length() > declaration_hint_length )
      {
        declaring_class = ancestor;
        method_name = new_name.substr(hint.length());
        declaration_hint_length = hint.length();
      }
    }

    size_t scoped_declaration_length = 0;
    for ( const qstring &ancestor : ancestors )
    {
      qstring prefix = ancestor;
      prefix.append("::");
      if ( declaration_hint_length == 0
        && method_name.length() > prefix.length()
        && strncmp(method_name.c_str(), prefix.c_str(), prefix.length()) == 0
        && prefix.length() > scoped_declaration_length )
      {
        declaring_class = ancestor;
        scoped_declaration_length = prefix.length();
      }
    }

    const bool scoped_name = strstr(method_name.c_str(), "::") != nullptr;
    qstring mangled_probe;
    if ( scoped_name && !mangle_itanium_method(method_name, &mangled_probe) )
    {
      warning("Only basic Class::Method scoped names can be Itanium-mangled");
      return true;
    }
    if ( !set_declaring_class_metadata(
          selected_class,
          declaring_class,
          marker->slot) )
    {
      warning(
        "Could not set %s as the declaration boundary for VTABLE[0x%" FMT_64 "X]",
        declaring_class.c_str(),
        uint64(marker->slot));
      return true;
    }

    hierarchy_targets_t targets;
    size_t vtable_count = 0;
    collect_hierarchy_targets(
      selected_class,
      marker->slot,
      &targets,
      &vtable_count);
    if ( targets.empty() )
    {
      warning(
        "No mapped functions found at or below %s for VTABLE[0x%" FMT_64 "X]",
        declaring_class.c_str(),
        uint64(marker->slot));
      return true;
    }
    new_name = method_name;

    size_t renamed_count = 0;
    for ( const hierarchy_target_t &entry : targets )
    {
      if ( new_name.empty() )
      {
        if ( del_global_name(entry.target) )
        {
          ++renamed_count;
          debug_log(
            "N hierarchy unname: class=%s vtable=%s slot=0x%" FMT_64 "X target=%a",
            entry.class_name.c_str(),
            entry.vtable_name.c_str(),
            uint64(marker->slot),
            entry.target);
        }
        continue;
      }
      qstring applied_name;
      if ( scoped_name )
      {
        const char *last_separator = strrchr(method_name.c_str(), ':');
        qstring scoped_target = entry.class_name;
        scoped_target.append("::");
        scoped_target.append(last_separator != nullptr ? last_separator + 1 : method_name.c_str());
        if ( !mangle_itanium_method(scoped_target, &applied_name) )
          continue;
      }
      else if ( targets.size() == 1 )
      {
        applied_name = new_name;
      }
      else
      {
        applied_name = identifier_from_type_name(entry.class_name);
        applied_name.append('_');
        applied_name.append(new_name);
      }
      if ( force_name(entry.target, applied_name.c_str(), SN_NON_AUTO) )
      {
        ++renamed_count;
        debug_log(
          "N hierarchy rename: class=%s vtable=%s slot=0x%" FMT_64 "X target=%a name=%s",
          entry.class_name.c_str(),
          entry.vtable_name.c_str(),
          uint64(marker->slot),
          entry.target,
          applied_name.c_str());
      }
    }
    if ( renamed_count == 0 )
    {
      warning(
        new_name.empty()
          ? "Could not remove any function names in the %s hierarchy"
          : "Could not rename any functions in the %s hierarchy",
        selected_class.c_str());
      return true;
    }
    if ( new_name.empty() )
      msg(
        "IDA-VTable-Utility: removed %" FMT_Z " implementation names at slot 0x%" FMT_64 "X\n",
        renamed_count,
        uint64(marker->slot));
    else
      msg(
        "IDA-VTable-Utility: renamed %" FMT_Z " implementations at slot 0x%" FMT_64 "X"
        " across %" FMT_Z " named VTABLEs\n",
        renamed_count,
        uint64(marker->slot),
        vtable_count);
    vu->cfunc->refresh_func_ctext();
    return true;
  }

  bool show_hierarchy_versions(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc,
          *marker,
          &selected_class,
          &vtable_name,
          &vtable_ea) )
      return false;

    hierarchy_targets_t entries;
    collect_all_hierarchy_targets(selected_class, marker->slot, &entries);
    if ( entries.empty() )
    {
      warning("No implementations found for VTABLE[0x%" FMT_64 "X]", uint64(marker->slot));
      return true;
    }

    qstring title;
    title.sprnt(
      "%s hierarchy: VTABLE[0x%" FMT_64 "X] implementations",
      selected_class.c_str(),
      uint64(marker->slot));
    hierarchy_popup_t popup(entries, title.c_str());
    const ssize_t selected = popup.choose();
    if ( selected < 0 || selected >= entries.size() )
      return true;

    const hierarchy_target_t &entry = entries[selected];
    switch ( popup.activated_column )
    {
      case 0:
      {
        const int32 ordinal = get_type_ordinal(nullptr, entry.class_name.c_str());
        if ( ordinal > 0 )
          open_loctypes_window(ordinal);
        else
          warning("Local type '%s' was not found", entry.class_name.c_str());
        break;
      }
      case 1:
      {
        const size_t pointer_size = inf_is_64bit() ? 8 : 4;
        jump_to_disassembly(entry.vtable_ea + marker->slot * pointer_size);
        break;
      }
      case 2:
        open_pseudocode(entry.target, 0);
        break;
      case 3:
        jump_to_disassembly(entry.target);
        break;
    }
    return true;
  }

  bool show_hierarchy_graph(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc,
          *marker,
          &selected_class,
          &vtable_name,
          &vtable_ea) )
    {
      return false;
    }

    qstring title;
    title.sprnt(
      "%s VTABLE[0x%" FMT_64 "X] implementation graph",
      selected_class.c_str(),
      uint64(marker->slot));
    TWidget *existing = find_widget(title.c_str());
    if ( existing != nullptr )
    {
      activate_widget(existing, true);
      graph_viewer_t *viewer = get_graph_viewer(existing);
      if ( viewer != nullptr )
      {
        refresh_viewer(viewer);
        hierarchy_graph_data_t *graph_data = find_hierarchy_graph(existing);
        const int root_node = graph_data != nullptr
                            ? find_hierarchy_graph_node(*graph_data, selected_class)
                            : 0;
        schedule_hierarchy_graph_position(title, root_node);
      }
      return true;
    }

    auto *graph_data = new hierarchy_graph_data_t;
    build_hierarchy_graph_data(selected_class, marker->slot, graph_data);
    debug_log(
      "H graph built: class=%s slot=0x%" FMT_64 "X nodes=%" FMT_Z " edges=%" FMT_Z,
      selected_class.c_str(),
      uint64(marker->slot),
      graph_data->nodes.size(),
      graph_data->edges.size());
    if ( graph_data->nodes.empty() )
    {
      delete graph_data;
      warning(
        "No descendant implementations found for %s VTABLE[0x%" FMT_64 "X]",
        selected_class.c_str(),
        uint64(marker->slot));
      return true;
    }

    graph_data->title = title;

    netnode graph_id;
    graph_id.create("$ pseudocode_xrefs hierarchy graph");
    graph_viewer_t *viewer = create_graph_viewer(
      graph_data->title.c_str(),
      graph_id,
      hierarchy_graph_callback,
      graph_data,
      0);
    if ( viewer == nullptr )
    {
      delete graph_data;
      warning("Could not create the hierarchy graph viewer");
      return true;
    }

    hierarchy_graphs[viewer] = graph_data;
    attach_action_to_popup(
      viewer,
      nullptr,
      VTABLE_GRAPH_HIDE_INHERITED_ACTION_NAME);
    display_widget(viewer, WOPN_DP_TAB);
    const int root_node = find_hierarchy_graph_node(*graph_data, selected_class);
    schedule_hierarchy_graph_position(graph_data->title, root_node);
    return true;
  }

  bool set_declaring_class(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc,
          *marker,
          &selected_class,
          &vtable_name,
          &vtable_ea) )
    {
      return false;
    }

    qvector<qstring> ancestors;
    collect_ancestor_hierarchy(selected_class, &ancestors);
    qstring title;
    title.sprnt(
      "Set declaring class for VTABLE[0x%" FMT_64 "X]",
      uint64(marker->slot));
    declaring_class_popup_t popup(ancestors, title.c_str());
    const ssize_t selected = popup.choose();
    if ( selected < 0 || selected >= ancestors.size() )
      return true;

    const qstring &declaring_class = ancestors[selected];
    if ( !set_declaring_class_metadata(
          selected_class,
          declaring_class,
          marker->slot) )
    {
      warning(
        "Could not store declaring class '%s' for VTABLE[0x%" FMT_64 "X]",
        declaring_class.c_str(),
        uint64(marker->slot));
      return true;
    }

    msg(
      "IDA-VTable-Utility: VTABLE[0x%" FMT_64 "X] is first declared by %s\n",
      uint64(marker->slot),
      declaring_class.c_str());
    return true;
  }

  bool edit_vtable_function_type(vdui_t *vu)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    ea_t target = marker->target;
    if ( target == BADADDR
      && !get_vtable_entry_target(vu->cfunc, *marker, &target) )
    {
      warning(
        "VTABLE[0x%" FMT_64 "X] does not contain a mapped function",
        uint64(marker->slot));
      return true;
    }
    func_t *target_function = get_func(target);
    if ( target_function == nullptr )
    {
      warning("The VTABLE target at %a is not defined as a function", target);
      return true;
    }

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc, *marker, &selected_class, &vtable_name, &vtable_ea) )
    {
      warning("Could not resolve the class hierarchy for this VTABLE slot");
      return true;
    }

    tinfo_t current_type;
    bool have_current_type = false;
    if ( is_userti(target) )
    {
      have_current_type = get_tinfo(&current_type, target);
      if ( have_current_type )
        debug_log("Y default type source: user target type at %a", target);
    }
    if ( !have_current_type )
    {
      have_current_type = get_vtable_slot_function_type(
        vtable_ea, marker->slot, &current_type);
      if ( have_current_type && is_placeholder_function_type(current_type) )
        have_current_type = false;
      if ( have_current_type )
        debug_log("Y default type source: VTABLE slot %s[0x%" FMT_64 "X]", vtable_name.c_str(), uint64(marker->slot));
    }
    if ( !have_current_type )
    {
      tinfo_t target_type;
      if ( get_tinfo(&target_type, target)
        && extract_function_type(target_type, &current_type)
        && !is_placeholder_function_type(current_type) )
      {
        have_current_type = true;
        debug_log("Y default type source: target type at %a", target);
      }
    }
    if ( !have_current_type )
    {
      cfuncptr_t implementation = decompile_func(target_function);
      if ( implementation != nullptr )
        have_current_type = implementation->get_func_type(&current_type);
      if ( have_current_type && is_placeholder_function_type(current_type) )
        have_current_type = false;
      if ( have_current_type )
        debug_log("Y default type source: Hex-Rays implementation at %a", target);
    }
    if ( !have_current_type )
    {
      tinfo_t fallback_type;
      have_current_type = get_tinfo(&fallback_type, target)
                       && extract_function_type(fallback_type, &current_type);
      if ( !have_current_type )
        have_current_type = guess_tinfo(&current_type, target) > 0;
    }

    qstring prototype_name = marker->display_name;
    if ( prototype_name.empty() )
      prototype_name = get_short_name(target);
    const char *parameters = strchr(prototype_name.c_str(), '(');
    if ( parameters != nullptr )
      prototype_name.resize(parameters - prototype_name.c_str());
    const char *scope = strrchr(prototype_name.c_str(), ':');
    if ( scope != nullptr )
      prototype_name = scope + 1;
    if ( prototype_name.empty() )
      prototype_name = "method";
    qstring declaration;
    if ( !have_current_type
      || !current_type.is_func()
      || !current_type.print(&declaration, prototype_name.c_str(), PRTYPE_1LINE) )
    {
      warning("Could not determine the current function prototype at %a", target);
      return true;
    }
    if ( !ask_str(
          &declaration,
          HIST_TYPE,
          "Set VTABLE[0x%" FMT_64 "X] prototype for %s and descendants",
          uint64(marker->slot),
          selected_class.c_str()) )
    {
      return true;
    }

    tinfo_t edited_type;
    qstring parsed_name;
    qstring parsed_declaration = declaration;
    parsed_declaration.trim2();
    if ( parsed_declaration.empty()
      || parsed_declaration[parsed_declaration.length() - 1] != ';' )
    {
      parsed_declaration.append(';');
    }
    if ( !parse_decl(
          &edited_type,
          &parsed_name,
          nullptr,
          parsed_declaration.c_str(),
          PT_SIL | PT_RELAXED) )
    {
      warning("The entered declaration is not a valid function prototype");
      return true;
    }
    tinfo_t normalized_function_type;
    if ( !extract_function_type(edited_type, &normalized_function_type) )
    {
      warning("The entered declaration is not a function or function-pointer prototype");
      return true;
    }
    edited_type = normalized_function_type;

    hierarchy_targets_t targets;
    size_t vtable_count = 0;
    collect_hierarchy_targets(
      selected_class, marker->slot, &targets, &vtable_count);
    size_t applied_count = 0;
    for ( const hierarchy_target_t &entry : targets )
    {
      tinfo_t target_type;
      if ( retarget_this_pointer_type(edited_type, entry.class_name, &target_type)
        && apply_tinfo(entry.target, target_type, TINFO_DEFINITE) )
      {
        ++applied_count;
      }
    }
    if ( applied_count == 0 )
    {
      warning("Could not apply the prototype to any hierarchy implementation");
      return true;
    }

    vu->cfunc->refresh_func_ctext();
    msg(
      "IDA-VTable-Utility: applied prototype to %" FMT_Z
      " implementations across %" FMT_Z " named VTABLEs\n",
      applied_count,
      vtable_count);
    return true;
  }

  bool apply_vtable_function_type(
        vdui_t *vu,
        const tinfo_t &function_type,
        const char *function_name = nullptr)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker = find_vtable_marker(vu, USE_KEYBOARD, &fallback);
    if ( marker == nullptr )
      return false;

    qstring selected_class, vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc, *marker, &selected_class, &vtable_name, &vtable_ea) )
    {
      warning("Could not resolve the class hierarchy for this VTABLE slot");
      return true;
    }

    tinfo_t normalized_function_type;
    if ( !extract_function_type(function_type, &normalized_function_type) )
    {
      warning("The supplied declaration is not a function or function-pointer prototype");
      return true;
    }

    hierarchy_targets_t targets;
    size_t vtable_count = 0;
    collect_hierarchy_targets(
      selected_class, marker->slot, &targets, &vtable_count);

    size_t applied_count = 0;
    for ( const hierarchy_target_t &entry : targets )
    {
      tinfo_t target_type;
      if ( retarget_this_pointer_type(
             normalized_function_type, entry.class_name, &target_type)
        && apply_tinfo(entry.target, target_type, TINFO_DEFINITE) )
      {
        ++applied_count;
      }
    }

    if ( applied_count == 0 )
    {
      warning("Could not apply the prototype to any hierarchy implementation");
      return true;
    }

    msg(
      "IDA-VTable-Utility: applied prototype to %" FMT_Z
      " implementations at VTABLE[0x%" FMT_64 "X] across %" FMT_Z
      " named VTABLEs\n",
      applied_count,
      uint64(marker->slot),
      vtable_count);

    if ( function_name != nullptr && function_name[0] != '\0' )
      rename_vtable_target(vu, function_name);

    vu->cfunc->refresh_func_ctext();
    return true;
  }

  bool jump_to_vtable_target(
        vdui_t *vu,
        input_device_t input_device,
        bool warn_if_missing)
  {
    vtable_marker_t fallback;
    const vtable_marker_t *marker =
      find_vtable_marker(vu, input_device, &fallback);
    if ( marker == nullptr )
    {
      debug_log(
        "VTABLE navigation ignored: no marker under %s cursor",
        input_device == USE_MOUSE ? "mouse" : "keyboard");
      if ( warn_if_missing )
        warning("Place the cursor on a VTABLE[...] token and press J");
      return false;
    }
    debug_log(
      "J navigation start: object=%s slot=0x%" FMT_64 "X offset=0x%" FMT_64 "X",
      marker->object_name.c_str(),
      uint64(marker->slot),
      uint64(marker->byte_offset));

    qstring class_name;
    qstring vtable_name;
    ea_t vtable_ea = BADADDR;
    if ( !find_marker_vtable(
          vu->cfunc, *marker, &class_name, &vtable_name, &vtable_ea) )
    {
      warning(
        "Could not determine a class VTABLE for '%s'",
        marker->object_name.c_str());
      return true;
    }
    debug_log(
      "J vtable resolved: class=%s symbol=%s ea=%a",
      class_name.c_str(),
      vtable_name.c_str(),
      vtable_ea);
    if ( vtable_ea == BADADDR )
    {
      warning("Could not find vtable symbol '%s'", vtable_name.c_str());
      return true;
    }

    const size_t pointer_size = inf_is_64bit() ? 8 : 4;
    const ea_t entry_ea = vtable_ea + marker->slot * pointer_size;
    if ( !is_loaded(entry_ea) )
    {
      warning(
        "VTABLE slot 0x%" FMT_64 "X is not loaded at %a",
        uint64(marker->slot),
        entry_ea);
      return true;
    }

    const ea_t target =
      pointer_size == 8 ? ea_t(get_qword(entry_ea)) : ea_t(get_dword(entry_ea));
    debug_log(
      "J slot resolved: entry=%a target=%a mapped=%d",
      entry_ea,
      target,
      is_mapped(target));
    if ( target == BADADDR || !is_mapped(target) )
    {
      warning(
        "VTABLE slot 0x%" FMT_64 "X does not contain a mapped function address",
        uint64(marker->slot));
      return true;
    }

    jumpto(target);
    debug_log("J navigation success: target=%a", target);
    return true;
  }
};

std::string trimmed_plain_text(const qstring &tagged)
{
  qstring plain_qstr;
  tag_remove(&plain_qstr, tagged);
  std::string plain(plain_qstr.c_str());
  size_t begin = 0;
  size_t end = plain.size();
  while ( begin < end && std::isspace(uchar(plain[begin])) != 0 )
    ++begin;
  while ( end > begin && std::isspace(uchar(plain[end - 1])) != 0 )
    --end;
  return plain.substr(begin, end - begin);
}

// Once Hex-Rays reaches its final ctree maturity stage (right before
// pseudocode text is generated), drop the explicit receiver argument from
// calls our text-based rewrite recognizes as virtual calls. The receiver is
// already shown via the "object->Method(...)" rendering produced later in
// hxe_func_printed, so repeating it as the first call argument is redundant.
// Doing this at the ctree level (rather than as more text patching) means it
// works correctly even when Hex-Rays wraps the call's arguments across
// several pseudocode lines.
struct vtable_receiver_hider_t : public ctree_visitor_t
{
  cfunc_t *cfunc;
  explicit vtable_receiver_hider_t(cfunc_t *f) : ctree_visitor_t(CV_FAST), cfunc(f) {}

  int idaapi visit_expr(cexpr_t *e) override
  {
    if ( e->op != cot_call || e->a == nullptr || e->a->empty() )
      return 0;

    qstring call_text_tagged;
    e->print1(&call_text_tagged, cfunc);
    const std::string call_text = trimmed_plain_text(call_text_tagged);

    size_t match_start = 0, match_end = 0, object_start = 0, object_end = 0;
    uval_t byte_offset = 0;
    if ( !find_vtable_pattern(
          call_text, 0, &match_start, &match_end, &object_start, &object_end, &byte_offset) )
    {
      return 0;
    }

    const std::string object_name =
      call_text.substr(object_start, object_end - object_start);

    qstring first_arg_tagged;
    e->a->front().print1(&first_arg_tagged, cfunc);
    if ( trimmed_plain_text(first_arg_tagged) == object_name )
      e->a->erase(e->a->begin());

    return 0;
  }
};

ssize_t idaapi decompiler_callback(
        void *user_data,
        hexrays_event_t event,
        va_list va)
{
  auto *plugin = static_cast<pseudocode_xrefs_plugmod_t *>(user_data);
  if ( event == hxe_maturity )
  {
    cfunc_t *cfunc = va_arg(va, cfunc_t *);
    const ctree_maturity_t new_maturity = ctree_maturity_t(va_arg(va, int));
    if ( new_maturity == CMAT_FINAL )
    {
      vtable_receiver_hider_t hider(cfunc);
      hider.apply_to(&cfunc->body, nullptr);
    }
    return 0;
  }

  if ( event == hxe_func_printed )
  {
    plugin->rewrite_vtable_calls(va_arg(va, cfunc_t *));
    return 0;
  }

  if ( event == hxe_double_click )
  {
    vdui_t *vu = va_arg(va, vdui_t *);
    const int shift_state = va_arg(va, int);
    if ( shift_state != 0 )
      return 0;

    debug_log(
      "double click: vu=%p function=%a",
      vu,
      vu != nullptr && vu->cfunc != nullptr ? vu->cfunc->entry_ea : BADADDR);
    return plugin->jump_to_vtable_target(vu, USE_MOUSE, false) ? 1 : 0;
  }

  if ( event == hxe_populating_popup )
  {
    TWidget *widget = va_arg(va, TWidget *);
    TPopupMenu *popup = va_arg(va, TPopupMenu *);
    vdui_t *vu = va_arg(va, vdui_t *);
    vtable_marker_t fallback;
    if ( plugin->find_vtable_marker(vu, USE_KEYBOARD, &fallback) != nullptr )
    {
      attach_action_to_popup(
        widget,
        popup,
        VTABLE_GRAPH_ACTION_NAME,
        "IDA-VTable-Utility/");
      attach_action_to_popup(
        widget,
        popup,
        VTABLE_DECLARING_ACTION_NAME,
        "IDA-VTable-Utility/");
    }
    return 0;
  }

  if ( event != hxe_keyboard )
    return 0;

  vdui_t *vu = va_arg(va, vdui_t *);
  const int key_code = va_arg(va, int);
  const int shift_state = va_arg(va, int);
  if ( shift_state != 0 )
    return 0;

  if ( key_code == 'N' || key_code == 'n' )
    return plugin->rename_vtable_target(vu) ? 1 : 0;
  if ( key_code == 'K' || key_code == 'k' )
  {
    show_xrefs(vu);
    return 1;
  }
  if ( key_code == 'J' || key_code == 'j' )
  {
    debug_log(
      "keyboard J: vu=%p shift=%d function=%a",
      vu,
      shift_state,
      vu != nullptr && vu->cfunc != nullptr ? vu->cfunc->entry_ea : BADADDR);
    plugin->jump_to_vtable_target(vu, USE_KEYBOARD, true);
    return 1;
  }
  if ( key_code == 'I' || key_code == 'i' )
  {
    plugin->show_vtable_index(vu);
    return 1;
  }
  if ( key_code == 'H' || key_code == 'h' )
  {
    return plugin->show_hierarchy_graph(vu) ? 1 : 0;
  }
  return 0;
}

plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr;
  if ( !vtable_rewrite_self_test() )
  {
    warning("IDA-VTable-Utility: internal VTABLE rewrite test failed");
    return nullptr;
  }
  if ( !hierarchy_graph_classification_self_test() )
  {
    warning("IDA-VTable-Utility: internal hierarchy graph test failed");
    return nullptr;
  }
  return new pseudocode_xrefs_plugmod_t;
}

} // namespace

extern "C" __declspec(dllexport) bool idaapi pseudocode_xrefs_apply_vtable_type(
      vdui_t *vu,
      const tinfo_t *function_type)
{
  return g_active_plugin != nullptr
      && function_type != nullptr
      && g_active_plugin->apply_vtable_function_type(vu, *function_type);
}

extern "C" __declspec(dllexport) bool idaapi pseudocode_xrefs_apply_vtable_type_and_name(
      vdui_t *vu,
      const tinfo_t *function_type,
      const char *function_name)
{
  return g_active_plugin != nullptr
      && function_type != nullptr
      && g_active_plugin->apply_vtable_function_type(vu, *function_type, function_name);
}

extern "C" __declspec(dllexport) bool idaapi pseudocode_xrefs_rename_vtable_target(vdui_t *vu)
{
  return g_active_plugin != nullptr
      && g_active_plugin->rename_vtable_target(vu);
}

extern "C" __declspec(dllexport) bool idaapi pseudocode_xrefs_rename_vtable_target_to(
      vdui_t *vu,
      const char *function_name)
{
  return g_active_plugin != nullptr
      && function_name != nullptr
      && g_active_plugin->rename_vtable_target(vu, function_name);
}

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "Improves virtual-call display, navigation, editing, and hierarchy cross-references.",
  "",
  "IDA-VTable-Utility",
  ""
};

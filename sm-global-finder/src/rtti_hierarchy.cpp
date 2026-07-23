#include "rtti_hierarchy.h"

#include <bytes.hpp>

namespace
{

constexpr uint32 MAX_BASE_CLASSES = 64;
constexpr size_t MAX_TYPE_NAME_LEN = 512;

// x64 MSVC RTTI layout (all image-relative offsets are 32-bit DWORDs stored
// relative to the module's image base -- see rtti_hierarchy.h / the task
// spec this mirrors).
struct col_raw_t
{
  uint32 signature;
  uint32 offset;
  uint32 cdOffset;
  uint32 pTypeDescriptorOffset;
  uint32 pClassDescriptorOffset;
  uint32 pSelfOffset;
};

struct chd_raw_t
{
  uint32 signature;
  uint32 attributes;
  uint32 numBaseClasses;
  uint32 pBaseClassArrayOffset;
};

struct bcd_raw_t
{
  uint32 pTypeDescriptorOffset;
  uint32 numContainedBases;
  uint32 mdisp;
  uint32 pdisp;
  uint32 vbptrOffset;
  uint32 attributes;
};

bool read_dword_checked(ea_t ea, uint32 *out)
{
  if ( !is_mapped(ea) )
    return false;
  *out = get_dword(ea);
  return true;
}

bool read_qword_checked(ea_t ea, uint64 *out)
{
  if ( !is_mapped(ea) )
    return false;
  *out = get_qword(ea);
  return true;
}

bool read_col(ea_t ea, col_raw_t *out)
{
  return read_dword_checked(ea + 0, &out->signature)
      && read_dword_checked(ea + 4, &out->offset)
      && read_dword_checked(ea + 8, &out->cdOffset)
      && read_dword_checked(ea + 12, &out->pTypeDescriptorOffset)
      && read_dword_checked(ea + 16, &out->pClassDescriptorOffset)
      && read_dword_checked(ea + 20, &out->pSelfOffset);
}

bool read_chd(ea_t ea, chd_raw_t *out)
{
  return read_dword_checked(ea + 0, &out->signature)
      && read_dword_checked(ea + 4, &out->attributes)
      && read_dword_checked(ea + 8, &out->numBaseClasses)
      && read_dword_checked(ea + 12, &out->pBaseClassArrayOffset);
}

bool read_bcd(ea_t ea, bcd_raw_t *out)
{
  return read_dword_checked(ea + 0, &out->pTypeDescriptorOffset)
      && read_dword_checked(ea + 4, &out->numContainedBases)
      && read_dword_checked(ea + 8, &out->mdisp)
      && read_dword_checked(ea + 12, &out->pdisp)
      && read_dword_checked(ea + 16, &out->vbptrOffset)
      && read_dword_checked(ea + 20, &out->attributes);
}

// Reads a NUL-terminated byte string starting at ea, bailing defensively if
// any byte is unmapped or the string runs past a sane cap.
bool read_cstr_at(ea_t ea, qstring *out, size_t max_len = MAX_TYPE_NAME_LEN)
{
  out->qclear();
  for ( size_t i = 0; i < max_len; ++i )
  {
    ea_t cur = ea + i;
    if ( !is_mapped(cur) )
      return false;
    uchar b = get_byte(cur);
    if ( b == 0 )
      return true;
    out->append(char(b));
  }
  return true; // hit the cap without a NUL -- still usable, just truncated.
}

// Extracts the real class name out of a _TypeDescriptor's embedded mangled
// name, e.g. ".?AVClassName@@" (class) or ".?AUClassName@@" (struct).
// Namespace-qualified names are stored most-nested-first and '@'-separated,
// e.g. ".?AVClassName@Outer@Inner@@" means "Inner::Outer::ClassName" --
// mirrors extract_class_name()'s approach in rtti_scan.cpp, adapted for this
// different mangled-name shape.
//
// NOTE: qstring::substr(pos, end) takes an *ending index*, not a length
// (unlike std::string::substr) -- every call below passes an end index.
qstring extract_class_name_from_type_descriptor(const qstring &raw_name)
{
  bool is_class_or_struct =
      raw_name.length() > 4
      && raw_name[0] == '.'
      && raw_name[1] == '?'
      && raw_name[2] == 'A'
      && (raw_name[3] == 'V' || raw_name[3] == 'U');
  if ( !is_class_or_struct )
    return raw_name; // unexpected shape -- return as-is so it's still visible

  qstring body = raw_name.substr(4, raw_name.length());
  if ( body.length() >= 2
    && body[body.length() - 2] == '@'
    && body[body.length() - 1] == '@' )
  {
    body = body.substr(0, body.length() - 2);
  }
  if ( body.empty() )
    return body;

  qvector<qstring> parts;
  size_t start = 0;
  for ( size_t i = 0; i <= body.length(); ++i )
  {
    if ( i == body.length() || body[i] == '@' )
    {
      parts.push_back(body.substr(start, i));
      start = i + 1;
    }
  }

  qstring result;
  for ( size_t i = parts.size(); i-- > 0; )
  {
    if ( !result.empty() )
      result += "::";
    result += parts[i];
  }
  return result;
}

bool resolve_type_descriptor_name(ea_t image_base, uint32 offset, qstring *out_name, qstring *reason)
{
  if ( offset == 0 )
  {
    *reason = "type descriptor offset is 0";
    return false;
  }
  ea_t td_ea = image_base + offset;
  if ( !is_mapped(td_ea) )
  {
    *reason = "type descriptor address is unmapped";
    return false;
  }

  // _TypeDescriptor layout: QWORD pVFTable, QWORD spare, char name[].
  ea_t name_ea = td_ea + 16;
  qstring raw_name;
  if ( !read_cstr_at(name_ea, &raw_name) || raw_name.empty() )
  {
    *reason = "failed to read type descriptor name string";
    return false;
  }

  *out_name = extract_class_name_from_type_descriptor(raw_name);
  if ( out_name->empty() )
  {
    *reason = "extracted class name was empty";
    return false;
  }
  return true;
}

} // namespace

bool resolve_class_hierarchy(ea_t vft_ea, hierarchy_info_t *out, qstring *reason)
{
  if ( vft_ea == BADADDR )
  {
    *reason = "invalid vtable address";
    return false;
  }

  // The RTTI Complete Object Locator pointer sits at vft_ea - 8, immediately
  // before the vtable's first virtual-function pointer.
  ea_t col_ptr_ea = vft_ea - 8;
  uint64 col_ea_raw = 0;
  if ( !read_qword_checked(col_ptr_ea, &col_ea_raw) || col_ea_raw == 0 )
  {
    *reason = "could not read _RTTICompleteObjectLocator pointer at vft-8";
    return false;
  }
  ea_t col_ea = ea_t(col_ea_raw);
  if ( !is_mapped(col_ea) )
  {
    *reason = "_RTTICompleteObjectLocator address is unmapped";
    return false;
  }

  col_raw_t col;
  if ( !read_col(col_ea, &col) )
  {
    *reason = "failed to read _RTTICompleteObjectLocator fields";
    return false;
  }

  ea_t image_base = get_imagebase();

  qstring class_name;
  qstring name_reason;
  if ( !resolve_type_descriptor_name(image_base, col.pTypeDescriptorOffset, &class_name, &name_reason) )
  {
    *reason = name_reason;
    return false;
  }

  if ( col.pClassDescriptorOffset == 0 )
  {
    *reason = "class hierarchy descriptor offset is 0";
    return false;
  }
  ea_t chd_ea = image_base + col.pClassDescriptorOffset;
  if ( !is_mapped(chd_ea) )
  {
    *reason = "_RTTIClassHierarchyDescriptor address is unmapped";
    return false;
  }

  chd_raw_t chd;
  if ( !read_chd(chd_ea, &chd) )
  {
    *reason = "failed to read _RTTIClassHierarchyDescriptor fields";
    return false;
  }

  if ( chd.numBaseClasses == 0 || chd.numBaseClasses > MAX_BASE_CLASSES )
  {
    *reason = "numBaseClasses is 0 or unreasonably large";
    return false;
  }

  if ( chd.pBaseClassArrayOffset == 0 )
  {
    *reason = "base class array offset is 0";
    return false;
  }
  ea_t base_array_ea = image_base + chd.pBaseClassArrayOffset;

  qvector<base_class_info_t> bases;
  for ( uint32 i = 0; i < chd.numBaseClasses; ++i )
  {
    ea_t slot_ea = base_array_ea + i * 4;
    uint32 desc_offset = 0;
    if ( !read_dword_checked(slot_ea, &desc_offset) || desc_offset == 0 )
    {
      *reason = "failed to read base-class array entry";
      return false;
    }

    ea_t bcd_ea = image_base + desc_offset;
    if ( !is_mapped(bcd_ea) )
    {
      *reason = "_RTTIBaseClassDescriptor address is unmapped";
      return false;
    }

    bcd_raw_t bcd;
    if ( !read_bcd(bcd_ea, &bcd) )
    {
      *reason = "failed to read _RTTIBaseClassDescriptor fields";
      return false;
    }

    // Index 0 is always the class itself -- already captured via the COL's
    // own type descriptor above, so skip it here.
    if ( i == 0 )
      continue;

    qstring base_name;
    qstring base_name_reason;
    if ( !resolve_type_descriptor_name(image_base, bcd.pTypeDescriptorOffset, &base_name, &base_name_reason) )
    {
      *reason = base_name_reason;
      return false;
    }

    base_class_info_t base;
    base.class_name = base_name;
    base.mdisp = int32(bcd.mdisp);
    // Per the standard MSVC ABI convention: pdisp == -1 means this base is
    // reached by a plain member displacement (mdisp); any other value means
    // it's reached through a vbtable, i.e. virtual inheritance.
    base.is_virtual = int32(bcd.pdisp) != -1;
    bases.push_back(base);
  }

  out->class_name = class_name;
  out->vft_ea = vft_ea;
  out->bases = bases;
  out->is_multiple_inheritance = (chd.attributes & 1) != 0;
  return true;
}

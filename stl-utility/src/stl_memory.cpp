#include "stl_memory.h"

#include <bytes.hpp>
#include <dbg.hpp>
#include <segment.hpp>

#include <cctype>
#include <string>
#include <utility>

namespace stl_utility
{

stl_read_result_t stl_read_memory(ea_t ea, size_t size)
{
  if ( ea == BADADDR || size == 0 )
    return {};

  if ( is_debugger_on() )
  {
    bytevec_t buf;
    buf.resize(size);
    const ssize_t got = read_dbg_memory(ea, buf.begin(), size);
    if ( got == ssize_t(size) )
    {
      stl_read_result_t result;
      result.ok = true;
      result.from_debugger = true;
      result.data = std::move(buf);
      return result;
    }
  }

  bytevec_t buf;
  buf.resize(size);
  if ( get_bytes(buf.begin(), ssize_t(size), ea) == ssize_t(size) )
  {
    stl_read_result_t result;
    result.ok = true;
    result.from_debugger = false;
    result.data = std::move(buf);
    return result;
  }
  return {};
}

bool looks_like_stack_address(ea_t ea)
{
  if ( ea == BADADDR )
    return false;

  segment_t *seg = getseg(ea);
  if ( seg == nullptr )
  {
    // No fixed segment at all (e.g. a live-only heap/stack address that
    // only exists once a debugger session created it): treat as non-static.
    return true;
  }

  qstring name;
  get_segm_name(&name, seg);
  std::string lowered(name.c_str());
  for ( char &c : lowered )
    c = char(std::tolower(static_cast<unsigned char>(c)));
  return lowered.find("stack") != std::string::npos;
}

} // namespace stl_utility

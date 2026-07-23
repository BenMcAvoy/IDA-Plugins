#pragma once

#include <pro.h>
#include <ida.hpp>

namespace stl_utility
{

struct stl_read_result_t
{
  bool ok = false;
  bool from_debugger = false;
  bytevec_t data;
};

// Reads `size` bytes at `ea`: from the live debuggee if a debugger session
// is attached (falling back to static bytes if the live read fails, e.g. the
// page isn't currently mapped), otherwise from the static database image
// (.rdata/.data initializer bytes).
stl_read_result_t stl_read_memory(ea_t ea, size_t size);

// True if `ea` looks like a stack address rather than a fixed global/static
// address -- i.e. content there is only meaningful with a live debugger
// positioned at the right frame, and a static read would return garbage or
// merely the image's uninitialized stack-segment bytes.
bool looks_like_stack_address(ea_t ea);

} // namespace stl_utility

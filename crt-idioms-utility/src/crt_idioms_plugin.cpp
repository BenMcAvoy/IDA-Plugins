// IDA-CRT-Idioms-Utility: recognizes compiler-inlined CRT idioms (currently:
// inlined `strlen` loops) and collapses them into a readable call. Mirrors
// the build/plugin conventions of the sister IDA-STL-Utility plugin.

#include "strlen_match.h"

#include <hexrays.hpp>
#include <kernwin.hpp>
#include <diskio.hpp>
#include <fpro.h>

#include <cstdarg>

namespace
{

using namespace crt_idioms;

// Writes to %APPDATA%\Hex-Rays\IDA Pro\IDA-CRT-Idioms-Utility.log, mirroring
// the sister plugins' debug_log convention.
void debug_log(const char *format, ...)
{
  qstring path;
  path.sprnt("%s/IDA-CRT-Idioms-Utility.log", get_user_idadir());
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

ssize_t idaapi decompiler_callback(void *, hexrays_event_t event, va_list va)
{
  if ( event == hxe_maturity )
  {
    cfunc_t *cfunc = va_arg(va, cfunc_t *);
    const ctree_maturity_t new_maturity = ctree_maturity_t(va_arg(va, int));
    if ( new_maturity == CMAT_FINAL )
    {
      const int collapsed = collapse_strlen_idioms(cfunc);
      if ( collapsed > 0 )
        debug_log("collapsed %d inlined strlen idiom(s) in function=%a", collapsed, cfunc->entry_ea);
    }
    return 0;
  }

  return 0;
}

struct crt_idioms_plugmod_t final : plugmod_t
{
  crt_idioms_plugmod_t()
  {
    if ( !install_hexrays_callback(decompiler_callback, this) )
      msg("%s: failed to install the Hex-Rays callback\n", PLUGIN.wanted_name);

    debug_log("plugin initialized: version=0.1.0");
  }

  ~crt_idioms_plugmod_t() override
  {
    remove_hexrays_callback(decompiler_callback, this);
  }

  bool idaapi run(size_t) override
  {
    return false;
  }
};

plugmod_t *idaapi init()
{
  if ( !init_hexrays_plugin() )
    return nullptr;
  return new crt_idioms_plugmod_t;
}

} // namespace

plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_HIDE | PLUGIN_MULTI,
  init,
  nullptr,
  nullptr,
  "Recognizes compiler-inlined CRT idioms (currently: inlined strlen loops) and collapses them into a readable call.",
  "",
  "IDA-CRT-Idioms-Utility",
  ""
};

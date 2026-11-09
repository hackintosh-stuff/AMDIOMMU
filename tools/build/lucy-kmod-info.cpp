// lucy-kmod-info.cpp — generates kmod_info and the C++ runtime entry point for RTL812xLucy.
//
// Why this file is needed:
//   When a kext is built with xcodebuild, Xcode runs CreateKModInfo.perl to
//   generate a .c file containing the kmod_info structure and links it in. We
//   bypass Xcode and invoke clang directly, so we must provide it ourselves;
//   otherwise the linked binary has no _kmod_info symbol and kextload rejects
//   it ("not a valid kext").
//
// This matches how AMDMapperProbe does it (KMOD_EXPLICIT_DECL + _realmain/_antimain),
// which is the public approach Apple documents in mach/kmod.h; no private
// scripts are involved.
//
// The driver itself does not define _realmain (it is started through IOKit
// personality matching and needs no kext-level entry point), so _realmain /
// _antimain are left empty here. C++ static construction is still handled by
// libkmodc++'s _start.

#include <mach/kmod.h>
#include <libkern/OSKextLib.h>

extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);

#ifndef LUCY_KMOD_VERSION
#define LUCY_KMOD_VERSION "1.1.239"
#endif
KMOD_EXPLICIT_DECL(com.insanelymac.RTL812xLucy, LUCY_KMOD_VERSION, _start, _stop);

__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = nullptr;
__attribute__((visibility("hidden"))) kmod_stop_func_t  *_antimain = nullptr;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}

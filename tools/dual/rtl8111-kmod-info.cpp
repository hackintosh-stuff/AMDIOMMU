// R54 standalone CLT build entry; upstream driver copyrights stay in its sources.
#include <mach/kmod.h>
#include <libkern/OSKextLib.h>

extern "C" {
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
#ifndef RTL8111_KMOD_VERSION
#define RTL8111_KMOD_VERSION "3.0.54"
#endif
KMOD_EXPLICIT_DECL(com.insanelymac.RealtekRTL8111, RTL8111_KMOD_VERSION, _start, _stop);
__attribute__((visibility("hidden"))) kmod_start_func_t *_realmain = nullptr;
__attribute__((visibility("hidden"))) kmod_stop_func_t *_antimain = nullptr;
__attribute__((visibility("hidden"))) int _kext_apple_cc = __APPLE_CC__;
}

// lucy-kmod-info.cpp — 为 RTL812xLucy 生成 kmod_info 与 C++ 运行时入口。
//
// 为什么需要这个文件：
//   用 xcodebuild 构建 kext 时，Xcode 会跑 CreateKModInfo.perl 自动生成一个
//   含 kmod_info 结构体的 .c 文件并链进去。我们绕开 Xcode 用 clang 直接构建，
//   就必须自己提供它，否则链接出来的二进制没有 _kmod_info 符号，
//   kextload 会拒绝加载（"not a valid kext"）。
//
// 与 AMDMapperProbe 的写法一致（KMOD_EXPLICIT_DECL + _realmain/_antimain），
// 这是 Apple 在 mach/kmod.h 里给的公开方式，不需要任何私有脚本。
//
// 驱动本身没有定义 _realmain（它靠 IOKit 的 personality 匹配启动，
// 不需要 kext 级入口），所以这里把 _realmain / _antimain 留空。
// C++ 静态构造仍由 libkmodc++ 的 _start 负责。

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

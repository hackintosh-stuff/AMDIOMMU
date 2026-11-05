// AMDMapperProbeDebug.hpp -- boot-arg parsers for the retired M2 experiment
// modes (arm/mmio/write/table/enable/cmd/pgt/pgt4k/pgthold/pgtsleep/pgt3l).
//
// Only included by the Debug build (AMD_MAPPER_PROBE_DEBUG=1); the production
// build's main switch accepts just amdiommu=auto / auto-attach. The legacy
// experiment modules live in kext/*Debug.cpp and are built by
// tools/build-m1a-debug.sh.

#ifndef AMDMapperProbeDebug_hpp
#define AMDMapperProbeDebug_hpp

#include <pexpert/pexpert.h>
#include <libkern/libkern.h>

#if AMD_MAPPER_PROBE_DEBUG

// ---- parseM22b2Delay (original lines 5295..5308) ----
// 解析 m2b2delay=<秒>，返回毫秒。上限 300 秒，避免挂一个永不触发的定时器。
static inline bool parseM22b2Delay(uint32_t *outMS) {
    char val[32];
    if (!PE_parse_boot_argn("m2b2delay", val, sizeof(val))) return false;
    int secs = 0;
    for (int i = 0; val[i] && i < 8; i++) {
        if (val[i] < '0' || val[i] > '9') return false;
        secs = secs * 10 + (val[i] - '0');
        if (secs > 300) return false;
    }
    if (secs <= 0) return false;
    *outMS = (uint32_t)secs * 1000;
    return true;
}

// ---- parseArmBootArg (original lines 7419..7437) ----
// ------------------------------------------------------------------ 生命周期

// 解析启动参数里的 amdiommu=arm。
//
// 为什么用 boot-arg 而不是自动检测：
//   装了 RTL8127 不等于应该放行。一旦放行，Lucy 的描述符环映射会真的
//   经过我们，若我们的实现有缺陷，后果是网卡不工作甚至 panic。
//   所以做成**显式开关**：没有 `amdiommu=arm` 时行为与 0.5.0 完全一致，
//   随时可以去掉参数回到安全状态。
//
// 用 PE_parse_boot_argn 而不是查 IORegistry：boot-arg 是内核早期解析的，
// 我们的 start() 运行时它一定已经可用。
static inline bool parseArmBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "arm", 3) == 0;
}

// ---- boot-arg parsers (original lines 7439..7583) ----
// 解析 amdiommu=mmio —— M2-1 的 MMIO 探测门控。
//
// 为什么必须单独一个值而不是复用 "arm"：
//   arm 只影响 B2-b（让网卡映射经过我们），已在本机验证稳定。
//   mmio 会让代码第一次去访问 IOMMU 的 MMIO 窗口，风险性质不同。
//   两者必须能独立开关：出问题时能只关 mmio 而保留 arm，
//   从而把变量隔离到最小。
//
// 注意 PE_parse_boot_argn 只能取到一个值，所以不能同时写
// amdiommu=arm 和 amdiommu=mmio。本轮的用法是：
//   amdiommu=mmio  → 只跑 MMIO 探测，不放行网卡（最安全）
//   amdiommu=arm   → 只放行网卡，不碰 MMIO（B2-b 状态）
static inline bool parseMmioBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "mmio", 4) == 0;
}

// 解析 amdiommu=write —— M2-2a-1 的最小写测试门控。
//
// 三级递进，每级风险不同，必须能独立开关：
//   amdiommu=arm    → 只放行网卡（B2-b 已验证稳定）
//   amdiommu=mmio   → 只读 MMIO（M2-1 已验证通过）
//   amdiommu=write  → 允许写 MMIO（M2-2a-1，本轮新增）
//
// 为什么用独立的值而不是在 mmio 上加一个子标志：
//   PE_parse_boot_argn 一次只能取一个值，用独立值最清晰，
//   且出问题时能把变量隔离到"是否允许写"这一个维度上。
static inline bool parseWriteBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "write", 5) == 0;
}

// 解析 amdiommu=table —— M2-2a-2 的门控。
//
// 四级递进，风险递增：
//   arm   → 放行网卡（B2-b）
//   mmio  → 只读 MMIO（M2-1）
//   write → 单寄存器写测试（M2-2a-1）
//   table → 建设备表并写基址寄存器（M2-2a-2，本轮）
static inline bool parseTableBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "table", 5) == 0;
}

// 解析 amdiommu=enable —— M2-2a-3 的门控。
//
// 五级递进，风险递增：
//   arm    → 放行网卡（B2-b）
//   mmio   → 只读 MMIO（M2-1）
//   write  → 单寄存器写测试（M2-2a-1）
//   table  → 建设备表（M2-2a-2）
//   enable → 使能 IOMMU（M2-2a-3，本轮，最高风险）
//
// 注意 strncmp 的长度：必须用完整字符串长度，否则 "enable" 会匹配 "enableX"。
// 这里 6 = strlen("enable")。
static inline bool parseEnableBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "enable", 6) == 0;
}

// 解析 amdiommu=cmd —— M2-2b-1 命令通道验证的门控。
//
// 六级递进：
//   arm → mmio → write → table → enable → cmd
// 每一级都是独立可回退的开关，出问题时能把变量隔离到最小。
static inline bool parseCmdBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "cmd", 3) == 0;
}

// 解析 amdiommu=pgt —— M2-2b-2 的门控。
//
// 七级递进：
//   arm → mmio → write → table → enable → cmd → pgt
//
// 这是 M2 里第一次让硬件**真的用我们建的页表去翻译 DMA**。
// 前面六步全部是"配置寄存器"或"全直通"，硬件从不看页表。
static inline bool parsePgtBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    // 注意：必须用 strncmp(val, "pgt", 3)，这样 "pgt4k" 也匹配——
    // 它是 pgt 的变体（4 KiB 叶子模式），门控应当同样打开。
    return strncmp(val, "pgt", 3) == 0;
}

// 解析 amdiommu=pgt4k —— 4 KiB 叶子页判别实验。
//
// 必须比 parsePgtBootArg 更严格：用完整 5 字符比较，
// 否则 "pgt" 也会命中。
static inline bool parsePgt4kBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgt4k", 5) == 0;
}

// 解析 amdiommu=pgthold —— 保持翻译生效的长时间观察模式。
//
// 与前两个模式的区别：pgthold 把观察窗口从 2 秒延长到 20 秒，
// 期间 DTE 一直指向翻译表。这样可以从外部用 netstat 观察
// en2 的收发包计数是否继续增长——那才是"页表能不能用"的直接证据。
static inline bool parsePgtHoldBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgthold", 7) == 0;
}

// 解析 amdiommu=pgtsleep —— 纯睡眠对照（保持直通，只做同样的长睡眠）。
static inline bool parsePgtSleepBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgtsleep", 8) == 0;
}

// 解析 amdiommu=pgt3l —— 3 级页表模式。
static inline bool parsePgt3lBootArg() {
    char val[32];
    if (!PE_parse_boot_argn("amdiommu", val, sizeof(val))) {
        return false;
    }
    return strncmp(val, "pgt3l", 5) == 0;
}

#endif /* AMD_MAPPER_PROBE_DEBUG */
#endif /* AMDMapperProbeDebug_hpp */

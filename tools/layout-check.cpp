// layout-check.cpp — 离线验证 IOMapper 子类布局假设，不加载任何 kext。
//
// 目的：确认「SDK 视图」与「XNU_KERNEL_PRIVATE 视图」下 fIsSystem 的偏移一致。
// 若不一致，M1-A 探针会写错内存，绝对不能部署。
//
// 构建（在 Mac 上）：
//   xcrun clang++ -std=c++17 -O0 -o /tmp/layout-check layout-check.cpp
//   /tmp/layout-check
//
// 说明：这里用纯 C++ 结构复刻两种布局，不依赖内核头文件，
//       因此可以在用户态直接跑。头文件里的字段顺序见 docs/m1a-probe.md §4.1。

#include <cstdint>
#include <cstdio>
#include <cstddef>

// ---- 复刻 A：SDK 公开视图（IOMapper.sdk.h:73-74）----
struct LayoutSdk {
    uint64_t __reserved[8];
    bool     fIsSystem;
};

// ---- 复刻 B：XNU_KERNEL_PRIVATE 视图（IOMapper.xnu-12377.121.6.h:74-81）----
struct LayoutXnu {
    uint64_t __reservedA[6];
    void    *fAllocName;   // kern_allocation_name_t
    uint32_t __reservedB;
    uint32_t fPageSize;
    bool     fIsSystem;
};

int main() {
    const size_t offSdk = offsetof(LayoutSdk, fIsSystem);
    const size_t offXnu = offsetof(LayoutXnu, fIsSystem);

    printf("sizeof(LayoutSdk)      = %zu\n", sizeof(LayoutSdk));
    printf("sizeof(LayoutXnu)      = %zu\n", sizeof(LayoutXnu));
    printf("offsetof fIsSystem SDK = %zu\n", offSdk);
    printf("offsetof fIsSystem XNU = %zu\n", offXnu);
    printf("offsetof fAllocName XNU= %zu\n", offsetof(LayoutXnu, fAllocName));

    int rc = 0;

    if (offSdk != offXnu) {
        printf("RESULT: FAIL  fIsSystem offset differs (%zu vs %zu)\n", offSdk, offXnu);
        printf("        M1-A probe MUST NOT be deployed: fIsSystem write would land at the wrong offset.\n");
        rc = 1;
    } else if (offSdk != 64) {
        printf("RESULT: FAIL  fIsSystem offset is %zu, expected 64 per the header arithmetic.\n", offSdk);
        rc = 1;
    } else {
        printf("RESULT: PASS  fIsSystem at offset 64 in both views.\n");
    }

    // 附带确认 fAllocName 落在 SDK 视图的 __reserved[0] 区间内（0..63），
    // 即内核写入它是写进我们的保留区，而不是写穿到对象之外。
    const size_t offAlloc = offsetof(LayoutXnu, fAllocName);
    if (offAlloc + sizeof(void *) <= 64) {
        printf("RESULT: PASS  fAllocName [%zu..%zu) lies inside __reserved[8] (0..63).\n",
               offAlloc, offAlloc + sizeof(void *));
    } else {
        printf("RESULT: FAIL  fAllocName [%zu..%zu) escapes the 64-byte reserved area.\n",
               offAlloc, offAlloc + sizeof(void *));
        rc = 1;
    }

    // 若 fPageSize 也在保留区内，说明 SDK 视图的 64 字节完全覆盖内核写入的字段。
    const size_t offPage = offsetof(LayoutXnu, fPageSize);
    if (offPage + sizeof(uint32_t) <= 64) {
        printf("RESULT: PASS  fPageSize [%zu..%zu) lies inside __reserved[8].\n",
               offPage, offPage + sizeof(uint32_t));
    } else {
        printf("RESULT: FAIL  fPageSize [%zu..%zu) escapes the reserved area.\n",
               offPage, offPage + sizeof(uint32_t));
        rc = 1;
    }

    // ---- 关键：证明 __reserved[6] 与 fAllocName 是同一个存储 ----
    //
    // 背景：IOMemoryDescriptor::dmaMapRecord() 在映射**成功**后会执行
    //     if ((alloc = mapper->fAllocName)) kern_allocation_update_size(alloc, ...);
    // 第三方 kext 看不到 fAllocName（它在 XNU_KERNEL_PRIVATE 视图里），
    // 只能通过 SDK 视图的 __reserved[] 间接控制它。
    //
    // 若 __reserved[6] 确实别名到 fAllocName，我们就可以在 initHardware()
    // 里把它清零，让 dmaMapRecord 走 NULL 分支（合法状态），
    // 从而避免把未初始化的残留值当指针解引用而 panic。
    //
    // 这里同时验证「清零 __reserved[6] 不会破坏 fPageSize」——
    // 因为 IOMapper::start() 之后还会写 fPageSize。
    const size_t offRes6 = offsetof(LayoutSdk, __reserved) + 6 * sizeof(uint64_t);
    printf("offsetof __reserved[6]  = %zu\n", offRes6);

    if (offRes6 == offAlloc) {
        printf("RESULT: PASS  __reserved[6] aliases fAllocName (both at %zu).\n", offRes6);
    } else {
        printf("RESULT: FAIL  __reserved[6]=%zu does not alias fAllocName=%zu.\n",
               offRes6, offAlloc);
        rc = 1;
    }

    if (offRes6 + sizeof(uint64_t) <= offPage) {
        printf("RESULT: PASS  zeroing __reserved[6] cannot clobber fPageSize (%zu <= %zu).\n",
               offRes6 + sizeof(uint64_t), offPage);
    } else {
        printf("RESULT: FAIL  __reserved[6] overlaps fPageSize.\n");
        rc = 1;
    }

    return rc;
}

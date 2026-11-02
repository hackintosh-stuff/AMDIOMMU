// ===========================================================================
// 第十轮：重新实现 m2b2ScanTxDone()
// ===========================================================================
//
// 【为什么这个函数被重写而不是"找回原文"】
//
//   第十轮把 v2 读取器拼进 AMDMapperProbe.cpp 时，拼接区间的终点取在
//   `m2b2PublishDmaDefaults()` 之前，而 m2b2ScanTxDone() 恰好位于这两个
//   标记之间——它的**定义**被整段替换掉了，只剩头文件里的声明和第 16d 步
//   的调用。链接阶段才暴露：kmutil 报
//
//     Failed to bind '__ZN26org_example_AMDMapperProbe14m2b2ScanTxDoneEv'
//     ... could not find a kext which exports this symbol
//
//   这正是第九轮反复出现的那种失效形态：编译通过、安装"成功"、集合重建
//   失败，而唯一症状是证据里什么都没有。本轮把它当成缺陷修掉，并把
//   "链接后必须能解析所有 driver 符号"写进 deploy 脚本。
//
// 【它做什么】
//
//   读一次 TX 环，返回 `doneWithAddr` —— 既已交还（DescOwn 清零）又带
//   非零地址的描述符数量。
//
//   这个数**不是**完成证据。DescOwn 在本芯片上不被硬件清除，所以这个
//   差值连续四轮都恒为 0（done == zeroaddr）。保留它只有一个用途：
//   让"DescOwn 不是完成信号"这件事每次实验都可见，而不是变成一段传闻。
//   真正的完成证据是驱动自己写的 tx-done 记录与硬件关闭指针。
//
// 【为什么先过两道门】
//
//   plausibleRingBase()  —— 寄存器里的地址看起来像不像一个环
//   readVerdictDeviceReported() —— 这个物理地址能不能安全读
//
//   两者任一不通过就返回 -1，绝不"读读看"。第七轮的教训：把设备报的地址
//   直接映射进来读过一次，代价是两次 panic。
int org_example_AMDMapperProbe::m2b2ScanTxDone() {
    if (!fM22b2Dma.ran || !fM22b2Dma.haveTxRing) return -1;

    const UInt64 bytes = 1024ULL * amdobs::TX_DESC_STRIDE;
    const char *why = nullptr;
    if (!amdobs::plausibleRingBase(fM22b2Dma.txRingBase, bytes,
                                   M2B2_IDENTITY_LIMIT, &why) ||
        amdobs::readVerdictDeviceReported(fM22b2Dma.txRingBase, bytes,
                            fM22b2Policy) != amdobs::RD_OK) {
        return -1;
    }

    IOMemoryDescriptor *md =
        IOMemoryDescriptor::withPhysicalAddress(fM22b2Dma.txRingBase, bytes,
                                                kIODirectionIn);
    if (!md) return -1;

    int done = -1;
    IOMemoryMap *m = md->map(kIOMapInhibitCache | kIOMapReadOnly);
    if (m) {
        const UInt8 *rb = (const UInt8 *)(uintptr_t)m->getVirtualAddress();
        // doneWithAddr, NOT done: an unused slot has DescOwn clear and
        // would otherwise be counted as a completion.
        done = (int)amdobs::scanTxRing(rb, 1024).doneWithAddr;
        m->release();
    }
    md->release();
    return done;
}


# Round16 M2-3a 驱动端：有限显式 TX Map/Retire

## run2：page-aligned real TX staging

驱动 **1.1.201**（plist short/version 与 kmod trailer 一致）。[模板](<driver-template.py>)通过[生成器](<../apply-lucy-obs2.py>)接入真实 outputStart；[共享 ABI](<../lucy-obs/RTL812xTxMap.hpp>)不改二进制布局。driver构建阶段没有修改probe，也未部署/重启；其后父流程已部署并完成run2，最终实机结论见[round16结果](<../../docs/m2-3a-round16-result.md>)。

Install 使用正常 `IOBufferMemoryDescriptor::inTaskWithOptions(kernel_task, kIODirectionOut | kIOMemoryPhysicallyContiguous | kIOMemoryHostPhysicallyContiguous | kIOMemoryMapperNone, 4096, 4096)` 预分配四个真实 TX DMA buffer；无高 PA mask。每份 prepare 后独立验证 bytes 指针、长度>=4096、`getPhysicalSegment(0,...,kIOMemoryMapperNone)` span>=4096、PA非零/4096对齐/不溢出，且四份PA互不相同。初始化失败不安装 callback；prepare失败不算成功prepare，已prepare的缓冲区只有complete成功才release（失败故意pin，不释放不确定资源）。

non-AppleVTD 实际 `getPhysicalSegmentsWithCoalesce` 后、所有 descriptor count/index 修改与任何 OWN 前：

1. 识别安装 token 的 req1..4，独占原子slot；忙/禁用/超期/无效/预算不足均drop，无identity fallback。probe显式同BDF安装callback/context及retained owner，driver不发现probe。
2. 原始cursor输入允许1..8段，逐段验证非零PA/length、无溢出、原通用预算；**staging前端仅支持总长1..4096字节，且等于 `mbuf_pkthdr_len(m)`**。大于一页明确拒绝，不做截断。通用backend跨页/多段能力不变。
3. `mbuf_copydata(m,0,total,staging.bytes)` 复制整个真实业务帧。不是独立synthetic/test buffer；NIC描述符只指向这份包含完整真实帧的DMA backing。
4. `UInt32 &count` 将调用者 `numSegs` 改为1，`segments[0]={stagingPA,total}`，然后把真实PA/length交给backend Map。此处早于OSAddAtomic、txNextDescIndex、txTailPtr0、lastSeg及descriptor forloop，因此实际descriptor accounting全部按1运行。
5. 验证Map输出后实际descriptor使用返回IOVA。原mbuf保留metadata及原有所有权，不作为选中包DMA backing。TX ring `txMbufArray[last]` 为NULL，reset/普通completion不会free它。

四份真实DMA buffer保持prepare/alive。成功Retire后不释放staging或原mbuf，而将buffer slot与原mbuf一起quarantine；后续请求用下一份不同PA。四请求均从offset0映射，backend重用同一IOVA页时也重用**精确同一IOVA地址**，而非仅页槽。

## 生命周期与退出

状态 `Idle→Mapping→Submitted→Pending→Retiring→Idle`，control用commandGate与Idle CAS。hardware close-pointer completion仅在真实descriptor消费循环中记录tDone/close sample并发布Pending；没有callback、失效等待或mapped mbuf free。独立10ms workloop timer执行Retire。失败保留handle、native buffer与原mbuf；成功后才允许IOVA复用。

Map失败且handle=0必须由后端保证无残留映射/命令，driver可free原mbuf并重用仍prepared的staging slot；不确定时必须返回非零handle，driver pin并排队Retire。非零handle的坏返回同样处理。

正常退出：Disarm停止新Map，Busy不得恢复DTE；等待真实completion和延迟Retire成功；Detach获取Idle后先complete所有native buffers。任一complete失败则返回失败，保留所有buffer/原mbuf/backend owner；已complete成功的buffer记为未prepared，下次Detach可重试而不重复complete。只有全部complete成功，才release各native buffer并free对应原mbuf；每份 **tFree在这两个实际owner释放动作之后**记录。最终清callback/context并释放backend owner。必须Detach成功才恢复DTE/卸载，不能以一次Query=Idle代替barrier。

reset/stop没有真实close completion时，不虚构完成、不Retire Submitted；取消timer但保留outstanding mapping、native buffers、原mbuf、backend owner及state allocation，故意fail-closed pin/leak。正常Detach也保留小型state/token分类至stop；一次start仅一次Install，Detach后同token req1..4继续drop。`Configure.handle`输出保留0，避免读callback并发修改的request。

## 原始证据与mode

- `rtl812x-txmap-mode = page-aligned-real-tx-staging-v1`
- `rtl812x-txmap-staging-page-bytes = 4096`
- `rtl812x-txmap-staging-count = 4`
- `rtl812x-txmap-staging-copy-bytes`：实际完整copy累计字节（含copy后backend Map失败的尝试；正常四份74B时为296）。

`rtl812x-txmap-raw`自然x86_64布局仍为Request312、Witness544、Snapshot2216；头40字节，Witness doneClose344/closeMask348/descriptors352。**physical[]是真正被Map且被NIC读取的staging PA，不是原cursor PA**，mode明确区分。IOVA/descriptor/handle/OWN/close/Retire/free均为真实见证；成功Retire才commit witness，Detach释放后更新tFree。

## 测试与构建

[测试入口](<test-driver.py>)编译实际模板方法，IOKit/mbuf/clock stub，case在[staging cases](<test-staging-main.inc>)。Mac clang ASan+UBSan通过：原2段跨页输入合并为1并完整字节复制；四份不同aligned PA/精确相同IOVA、ring wrap、busy/drop、错误slot无完成、真实close仅入队、Retire失败pin重试、prepare失败/PA不对齐拒绝、Detach complete失败pin重试、双owner释放后tFree、4096接受/4097拒绝、copy失败/VTD拒绝、stop保留owner。

独立 `/Users/ling/r16-driver-staging-agent` 完整build/link/internal undefined检查/plist/ad-hoc codesign成功，生成器重复运行通过。本段仅记录构建阶段，当时运行系统未改；后续run2部署/16项见证检查见上方最终结果。binary SHA256 `9455170a2039d018a67a5dfae87d319dc37ab5e579b204d6e7289eec942eaf61`，UUID `CFB1FD8C-BB30-3CE3-A9EA-8FD0508206C1`。构建成功本身不能替代硬件验证；现已完成的run2硬件结论以最终结果为准。

## run1保留

run1版本1.1.200直接映射mbuf物理segments，raw offset为bb6/9b6/3b6/1b6；虽4/4真实TX成功，只有IOVA页槽复用，**精确IOVA复用不满足**，不放宽analyzer。

旧 `/Users/ling/r16-driver-agent` 完全未改；新构建前Python有界归档原generated源码/linux/KernelSPI/MacKernelSDK、生成器/头/kmod-info、bundle及log（排除.o）：1316文件、17,601,184输入字节，压缩3,323,006字节。归档已复制至[run1 source identity](<../../docs/evidence/r16-run1-20261101/driver-source-identity/r16-driver-run1-preserved.tar.gz>)，旁有[逐文件manifest](<../../docs/evidence/r16-run1-20261101/driver-source-identity/r16-driver-run1-preserved.tar.gz.manifest.json>)。archive SHA256 `06f670c1e66fcf8de41a25fb420d3046effe90ee76e8897b5288ba6e3b13fd15`；原binary SHA256 `f8e82e073efdb02b564a09f3ed38a237ba2df6be81c95a2df019abc206d70f0d`，UUID `E68B67E7-D7DC-33D0-A2FD-C0B261697F97`与run1 captured loaded UUID一致。未重放旧构建；run1更广的probe/toolchain补充归档未执行，不以run2归档替代run1原始来源。

## run2 capture后归档与scratch replay

[归档及重放记录](<../../docs/evidence/r16-run2-20261101/driver-source-identity/REPLAY.md>)包含真实driver/probe源码、SDK必要头/库闭包、构建日志、原built bundle及installed/captured UUID比较；原archive与layout-check小型补充均逐成员hash验证。driver scratch重建SHA/UUID/完整bundle manifest精确匹配。probe plain及一次debug-prefix归一化均非bit-identical：归一化后所有8个file-backed section与外部符号名相同，但N_OSO对象绝对路径及时间戳不同，故不宣称probe字节/UUID可重现。未再重建、未部署或重启；run1仍未replay。

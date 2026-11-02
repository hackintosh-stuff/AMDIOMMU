#!/usr/bin/env python3
"""Insert the round-5 section into README.md.

Run from MSI_X570/amd-iommu/:
    py -3 tools/insert-readme-round5.py
"""
import io
import sys

P = "README.md"
ANCHOR = "### M2 分步与闸门"

SECTION = """### M2-2b-2 第五轮：修正 2 MiB 叶子编码，补齐验收阻断项（2026-10-31）

探针 **0.20.0**。完整记录见 [m2-2b-2-round5-result.md](<MSI_X570/amd-iommu/docs/m2-2b-2-round5-result.md>)。

#### 确认的缺陷

第四轮把**每一个** 2 MiB 叶子都写成"扩展页"：

```c
pte = PAGE_SIZE_PTE(pa, 2MiB) | PM_LEVEL_ENC(7) | PR | FC | IR | IW
```

但 Linux v6.6 `iommu_v1_map_pages()`（`io_pgtable.c:394-398`）只有 `count > 1` 才走这条分支，而 `PAGE_SIZE_PTE_COUNT(2 MiB) = 1`，所以 2 MiB 走的是不带 NextLevel 的 `else` 分支。

规范 48882 Rev 3.10 §2.2.3（p.80）原文：NextLevel=7 的页大小"**must be larger than** the default page size and smaller than the default page size for the next higher level"。2 MiB **恰好等于** level 2 的默认值，既不更大也不更小，因此是**非法编码**。2 MiB 只有一种合法写法：**level 2 表里 NextLevel=0**。

| | 第四轮 | 第五轮 |
|---|---|---|
| 叶子 PTE（PA `0x384400000`） | `0x70000003844ffe01` | `0x7000000384400001` |
| NextLevel | 7（扩展页） | 0（该级默认页） |
| 与 Linux 分支 | `count > 1` | `count == 1` |
| 按规范 | **非法** | 合法 |

改的是叶子 PTE 的 NextLevel，**不是**把 DTE 的 Mode=4 改成 Mode=0。

#### 为什么前三轮的自检没抓住

同一个错误假设在**三处重复**，所以整条链一致地错：

| 位置 | 第四轮的判据 | 后果 |
|---|---|---|
| 构表 | 无条件 `ENC(7)` | 写出非法表 |
| 软件走表 | `lvl == 7 && pageSize == 2MiB` | 与构表同错，**必然通过** |
| 离线解码器 | 无层级参数，只比地址掩码 | 掩掉 bit0..20 后无法区分，**判"正确"** |

第四轮"导出的页表完全正确"这个结论，正是这条链的产物。

#### 第二个解码错误：事件标志字段

第四轮把标志读成 `dword1 & 0xFFFF`。按规范表 57，**标志域是 bit24:16**，低半字是 DomainID/PASID。本实验 domain 恒为 0，所以低半字永远是 `0x0000`，把 PR=1、RW 一起藏掉了。

用正确字段重解第四轮保存的 8 条原始事件：

```text
type=2 IO_PAGE_FAULT devid=0x2500 domain=0x0000
  flags=0x030  PR=1 RW=1 PE=0 RZ=0 TR=0 I=0   (写)
  flags=0x010  PR=1 RW=0 PE=0 RZ=0 TR=0 I=0   (读)
```

规范对 RZ 的定义：`RZ=0` 表示"fault caused by an **invalid level encoding**"，且 **RZ 只在 PR=1 时有意义**。`PR=1` 且 `RZ=0` 正是"页存在但层级编码非法"——与上面的缺陷精确对应。**第四轮保存的字节一直指向这个结论，只是被错误的字段偏移掩盖了。**

#### 改了什么

- **新增 `kext/amd_iommu_pte_core.hpp`**：编码/解码只实现一次，生产 kext 与 host 测试**包含同一个文件**。`decodePte(pte, level)` 没有 level 就编译不过，从结构上消灭"忘记带层级"。采用规范的 1-based 层级（表 15）。
- **生产代码**：`m2b2LargeLeaf()` 改为 `makeDefaultLeaf(LEVEL_2M, ...)`；删除 `m2b2PtePageSize()`（无层级参数，是缺陷载体）与 `M2B2_LEVEL_7`；第 4 步与第 17 步的走表改调 `amdpte::walkPageTable()`，并区分 present / absent / **illegal**；导出时每级 PTE **连同表级**一起发布。
- **解码器**：读 `m2-b2-dump-root-level`，逐级走，校验整条路径；**拒绝没有层级信息的旧采集**而不是猜一个层级。
- **恢复状态机**：`STATUS[4] = CmdBufRun`（规范 §3.4.16，Linux v6.6 **未定义**这一位）现在被有界等待并读回；停止阶段不再把原始使能位写回（旧代码 `c |= (origCtrl & CMDBUF_EN)` 会在"停止"时**重新使能**命令缓冲）；`winPre`/`winMain` 显式初始化并新增 `*-window-ran`；`winPre` 无效即阻止后续翻译实验；`pgtsleep` 控制判定不被覆盖；每个 abort 站点保留首个失败阶段。
- **逐命令记录**：命令字、预期完成值、观测完成值、阶段、等待轮数。
- **窗口归属**：新增前置积压计数与截断标记，不再把切换过程的事件算作主窗口新事件。

#### 实际执行的测试

| 类型 | 内容 | 结果 |
|---|---|---|
| **生产代码** | [tests/pte-core-test.cpp](<MSI_X570/amd-iommu/tests/pte-core-test.cpp>) 编译并执行共享核心的真实函数，8 组 109 项 | **109/109 PASS** |
| 变异测试 | 把 `makeDefaultLeaf()` 改回第四轮写法 | **25 项失败**（证明测试能抓住缺陷） |
| 模型 | [verify-identity-exhaustive.py](<MSI_X570/amd-iommu/tools/verify-identity-exhaustive.py>) 按生产实际布局重建并走完 8192 页 | 正确表 0 失败；第四轮的表 **8192/8192 全部拒绝** |
| 解码器 | [test-decoder.py](<MSI_X570/amd-iommu/tools/test-decoder.py>) 用第四轮真实 PDE 构造合成采集 | 4/4 PASS（错误叶子被拒、正确叶子通过、跳级被拒、缺失被拒） |
| 统一驱动 | [verify-round5.py](<MSI_X570/amd-iommu/tools/verify-round5.py>) | **ALL 7 OFFLINE CHECKS PASS** |

覆盖内容：错误叶子在 level 2 必须被拒、修正叶子通过、level 1 默认 4 KiB、真正 count>1 的扩展尺寸（32 KiB→8 项、4 MiB→2 项）、地址偏移/页边界/2 MiB 边界/16 GiB 末端、缺失路径与非法层级不得被报成"解码正确"、用实机 PDE 逐位复算。

**明确区分**：构表模型检查（Python 重建）／生产代码检查（编译执行共享核心）／实机导出字节检查（读真实 PTE）／硬件功能验证（实机窗口）。四者不混用。

#### 实机复测（1 次，单变量＝叶子编码修复）

证据：[20261031-180500](<MSI_X570/amd-iommu/docs/evidence/20261031-180500/>)（`props.txt`、`system.txt`、`dma-window.tsv`）。

```text
版本 0.20.0   二进制 SHA-256 c85425725822fa5145ab77c6167d52e7fe55fc83b5e184dc51ef2e5d27b9a7ff
kext UUID 08562CA3-B7DF-35A5-B75E-2505419169AB   启动参数 amdiommu=pgt
目标 devid 0x2500（RTL8127 / en2）  domain 0  page mode 4
根表 PA 0x2e9c0000  19 页 = 76 KiB   命令 3 提交 / 3 完成
```

`analyze-round5.py` 独立判定有效性（不读探针自己的 verdict）：**21 项全部通过 → 实验有效**。停止阶段的实际读回值可复核：`cmdbuf-stop-status=0x2`（CmdBufRun=0）、`evtlog-stop-status=0x2`、`final-control=0x220000000400` 等于 `orig-control`。

#### 结果：故障形态根本变化

| | 第四轮（0.19.0） | 第五轮（0.20.0） |
|---|---|---|
| 窗口内事件数 | 14 / 17 | **1** |
| 落在映射范围内 | 8（导出样本全部） | **0** |
| 落在映射范围外 | 0 | **1** |
| 故障地址 | 全部 < 16 GiB | `0x405d1999c`（16.09 GiB） |
| PR | 1 | **0** |

**原先"页表里有正确项、硬件却报 fault"的矛盾消失了。** 现在唯一的 fault 是"访问了没有映射的地址"——16 GiB 映射只覆盖 RAM，`0x405d1999c` 落在 16 GiB 以上的 MMIO 空洞。

**首次取得 DMA 完成证据。** 内核读不到接口计数器（`IONetworkData::readBytes` 是 protected，`struct ifnet` 在 SDK 里是不完整类型），所以由用户态 `netstat -i -b` 采样，用探针发布的**墙钟边界**（`m2-b2-win-wall-start/end`）对齐：

```text
PRE  (DTE 直通)   ipkts +2   opkts +148   错误 +0
MAIN (DTE 翻译)   ipkts +4   opkts  +52   错误 +0
```

翻译窗口内目标接口搬了 **56 个包、零错误**。每个包都需要设备 DMA 读写描述符与缓冲区，所以翻译路径承载了真实流量。**这是"没 fault"与"能工作"的区别：fault 只证明请求被拒绝，静默什么都不能证明，流量证明完成。**

#### 支持 / 不支持

**支持**：叶子编码缺陷真实且已修正（规范 + Linux 分支 + 变异测试三重确认）；修正后 in-range fault 消失；翻译窗口内完成 56 个包零错误；观测/命令/恢复三项可复核。

**不支持**：**"翻译功能已通过验收"**——仍剩 1 条 out-of-range fault，其来源未解释，不能排除"设备大部分访问没走到这张表"；"整张页表已验证"（只校验了根表页，8192 个叶子项从未在实机验证）；"缓存可见性或 DOMID 已排除"（未测）。

**关于历史死锁**：2026-10-30 两次死锁已确认的机制是"IOMMU 已使能时提前释放设备表内存，硬件继续按野指针表翻译"。本轮修复的是同一类**风险路径**（使能后裸 return、停用未确认就释放），但"这是唯一成因"缺少当时证据——当时代码没有发布中间状态。

#### 下一步：唯一优先事项

**解释那条唯一的 out-of-range fault `0x405d1999c`。**

在窗口内同时记录该地址的高位构成与该设备**实际编程的 DMA 地址范围**（探针已有 `m1bb-*` 观测设施）：

- 若该地址**出现**在设备自己提交的地址里 → 驱动按错误地址编程描述符，与 IOMMU 无关；
- 若**不出现** → 该访问来自设备固件/硬件预取，需判断是否影响功能（本次 56 包零错误，可能不影响）。

判据是**该地址是否出现在设备提交的地址集合里**（二值），不是 fault 计数（本轮已证明计数会漂移）。在此之前不建议做任何其他改动。

**仍不进入 M2-3。**

"""


def main():
    with io.open(P, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    if "\r" in src:
        print("ERROR: README contains CR bytes", file=sys.stderr)
        return 1
    if src.count(ANCHOR) != 1:
        print("ERROR: anchor appears {} times".format(src.count(ANCHOR)),
              file=sys.stderr)
        return 1
    if "### M2-2b-2 第五轮" in src:
        print("ERROR: round-5 section already present", file=sys.stderr)
        return 1

    src = src.replace(ANCHOR, SECTION + ANCHOR)
    with io.open(P, "w", encoding="utf-8", newline="") as f:
        f.write(src)
    print("README round-5 section inserted")
    print("CR bytes: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())

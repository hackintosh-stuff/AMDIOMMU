#!/usr/bin/env python3
"""Update README.md for round 5 (v0.20.0).

Run from MSI_X570/amd-iommu/:
    py -3 tools/update-readme-round5.py
"""
import io
import sys

P = "README.md"

# Each entry: (anchor that must appear exactly once, replacement)
EDITS = [
    # ---- header version list ----
    (
        "最新实验记录涉及探针 0.15.0 / 0.16.0 / 0.17.0 / 0.18.0 / 0.19.0；",
        "最新实验记录涉及探针 0.15.0 / 0.16.0 / 0.17.0 / 0.18.0 / 0.19.0 / 0.20.0；",
    ),
    # ---- status table row ----
    (
        "| **M2-2b-2** | **未通过：目标网卡在翻译窗口内冻结，恢复直通后恢复工作** | "
        "第四轮已取得**首次全部有效的实验**（观测/命令/DMA/恢复四项独立通过），"
        "并在有效条件下观察到具体失败：目标设备 14~17 条 `IO_PAGE_FAULT`，"
        "而导出到实机的页表字节独立解码为完全正确的恒等映射。**硬件是否读到该页表仍未证** |",
        "| **M2-2b-2** | **未通过：仍剩 1 条 out-of-range fault 未解释** | "
        "第五轮查明并修正了一个真实的编码缺陷：2 MiB 叶子错用了 NextLevel=7，"
        "而 2 MiB 恰好等于 level 2 的默认页大小，按规范 48882 §2.2.3 属于非法编码。"
        "修正后 in-range `IO_PAGE_FAULT` 从 14~17 条降到 **0**，只剩 1 条落在 "
        "16 GiB 映射之外；同时首次取得翻译窗口内 **DMA 完成**证据"
        "（TX +52 包、零错误） |",
    ),
    # ---- latest-results pointer ----
    (
        "最新结果见 [第四轮记录](<MSI_X570/amd-iommu/docs/m2-2b-2-round4-result.md>)、",
        "最新结果见 [第五轮记录](<MSI_X570/amd-iommu/docs/m2-2b-2-round5-result.md>)、"
        "[第四轮记录](<MSI_X570/amd-iommu/docs/m2-2b-2-round4-result.md>)、",
    ),
    # ---- headline paragraph ----
    (
        "**第四轮修好了实验基础设施**：",
        "**第五轮修正了 2 MiB 叶子编码**：构表、软件走表、离线解码器三处共享了"
        "同一个错误假设（2 MiB 叶子必须 NextLevel=7），所以自检一致地判“正确”。"
        "现已抽出共享核心 `kext/amd_iommu_pte_core.hpp`，**强制显式传入表级**，"
        "并由 109 项 host 测试直接执行生产代码（变异测试：把缺陷改回去会报 25 项失败）。"
        "同时修正了事件标志的字段偏移（应为 DWORD1 bit24:16，不是低半字）。\n\n"
        "**第四轮修好了实验基础设施**：",
    ),
    # ---- third-round corrections paragraph ----
    (
        "当前待查方向收敛为一个可直接检验的二分：**硬件是否读到我们这张根表**。",
        "当前待查方向收敛为一条具体现象：**那条落在 16 GiB 之外的 "
        "`IO_PAGE_FAULT`（`0x405d1999c`）来自哪里**。",
    ),
]

# Sections whose claims are now superseded; prepend a correction banner.
BANNER_TARGETS = [
    (
        "### M2-2b-2 第四轮：修好实验基础设施，取得一次有效基线（2026-10-31）",
        "> **⚠️ 本节部分结论已被第五轮推翻。** “导出页表完全正确”不成立："
        "该叶子按规范是非法编码，当时的解码器与构表同错；"
        "“实验基础设施全部有效”只对观测/命令/恢复三项成立。"
        "更正见[第五轮记录](<MSI_X570/amd-iommu/docs/m2-2b-2-round5-result.md>)。\n\n",
    ),
    (
        "### M2-2b-2 第三轮：先修掉让所有计数判据失效的缺陷（2026-10-31）",
        "> **⚠️ 本节“8192 项逐项验证正确”已被更正**：那是 Python 重建模型，"
        "不是实机字节。第五轮实机只校验了根表页。\n\n",
    ),
]


def main():
    with io.open(P, "r", encoding="utf-8", newline="") as f:
        src = f.read()
    if "\r" in src:
        print("ERROR: README contains CR bytes", file=sys.stderr)
        return 1

    for i, (old, new) in enumerate(EDITS):
        n = src.count(old)
        if n != 1:
            print("ERROR: edit {} anchor appears {} times:\n  {}\n".format(
                i, n, old[:80]), file=sys.stderr)
            return 1
        src = src.replace(old, new)

    for anchor, banner in BANNER_TARGETS:
        if src.count(anchor) != 1:
            print("ERROR: banner anchor appears {} times: {}".format(
                src.count(anchor), anchor[:60]), file=sys.stderr)
            return 1
        src = src.replace(anchor, anchor + "\n\n" + banner.rstrip("\n"))

    if "0.20.0" not in src:
        print("ERROR: README does not mention 0.20.0", file=sys.stderr)
        return 1

    with io.open(P, "w", encoding="utf-8", newline="") as f:
        f.write(src)
    print("README updated for round 5")
    print("CR bytes: 0")
    return 0


if __name__ == "__main__":
    sys.exit(main())

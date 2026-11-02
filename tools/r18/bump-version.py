#!/usr/bin/env python3
"""Round18 version bump: probe 0.28.0, Lucy 1.1.203. Idempotent, refuses drift."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

PLIST = ROOT / 'kext' / 'AMDMapperProbe-Info.plist'
HISTORY = """        0.28.0 M2-3c 第十八轮：标准 IOMapper / IODMACommand 接入真实 TX。
                驱动为每个报文建立 IOMemoryDescriptor，并用探针自身的
                IOMapper（非 system mapper）构造 IODMACommand；由 IOKit 在
                prepare() 内实际调用 iovmMapMemory() 生成非恒等 IOVA，
                描述符使用该 IOVA；complete() 由框架实际调用
                iovmUnmapMemory() 完成撤图与失效，之后才释放 descriptor、
                command 与 mbuf。只支持单段物理连续的报文布局，其余在
                prepare() 之前明确拒绝。同时修正退休定时器的主动收割：
                先非阻塞取得 __POLLING，占用时跳过，释放后再做 retire 与
                IOMMU 失效等待。
"""


def main():
    text = PLIST.read_text(encoding='utf-8')
    if '0.27.0' in text:
        text = text.replace('<string>0.27.0</string>', '<string>0.28.0</string>')
        marker = '      匹配 IOResources 而非任何 PCI 设备'
        if marker not in text:
            print('refused: version-history marker missing')
            return 1
        text = text.replace(marker, HISTORY + '\n' + marker, 1)
        PLIST.write_text(text, encoding='utf-8', newline='\n')
        print('probe version -> 0.28.0')
    elif '0.28.0' in text:
        print('probe version already 0.28.0')
    else:
        print('refused: unexpected probe version')
        return 1
    if text.count('0.28.0') < 2:
        print('refused: probe plist lost one of its two version strings')
        return 1

    build = ROOT / 'tools' / 'build-lucy.sh'
    btext = build.read_text(encoding='utf-8')
    if '1.1.202' in btext:
        btext = btext.replace('1.1.202', '1.1.203')
        build.write_text(btext, encoding='utf-8', newline='\n')
        print('lucy version -> 1.1.203')
    elif '1.1.203' in btext:
        print('lucy version already 1.1.203')
    else:
        print('refused: unexpected lucy version')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

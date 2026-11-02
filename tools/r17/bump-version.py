#!/usr/bin/env python3
"""Round17 version bump: probe 0.27.0, Lucy 1.1.202. Idempotent, refuses drift."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

PLIST = ROOT / 'kext' / 'AMDMapperProbe-Info.plist'
HISTORY = """        0.27.0 M2-3b 第十七轮：原生 mbuf 的非恒等 TX 映射与逐包回收。
                不再使用 staging 拷贝：直接把报文自己的 physical segments
                交给映射后端，保持每段长度、顺序与页内偏移，描述符使用
                返回的非恒等 IOVA。每个请求在硬件完成与撤图失效之后立即
                释放自己的 mbuf 并允许复用 IOVA/页槽，不再累积到 Detach。
                有限的是证据数组（32 代）与命令预算（160 次提交），
                不是 DMA 持有者；预算不足时明确拒绝且不留下映射。
                新增提交/完成交接状态（kPosting/kSubmitted/kPending），
                使极快 completion 不能跨代读写同一份 witness。
"""


def main():
    text = PLIST.read_text(encoding='utf-8')
    if '0.26.0' in text:
        text = text.replace('<string>0.26.0</string>', '<string>0.27.0</string>')
        marker = '      匹配 IOResources 而非任何 PCI 设备'
        if marker not in text:
            print('refused: version-history marker missing')
            return 1
        text = text.replace(marker, HISTORY + '\n' + marker, 1)
        PLIST.write_text(text, encoding='utf-8', newline='\n')
        print('probe version -> 0.27.0')
    elif '0.27.0' in text:
        print('probe version already 0.27.0')
    else:
        print('refused: unexpected probe version')
        return 1
    if text.count('0.27.0') < 2:
        print('refused: probe plist lost one of its two version strings')
        return 1

    build = ROOT / 'tools' / 'build-lucy.sh'
    btext = build.read_text(encoding='utf-8')
    if '1.1.201' in btext:
        btext = btext.replace('1.1.201', '1.1.202')
        build.write_text(btext, encoding='utf-8', newline='\n')
        print('lucy version -> 1.1.202')
    elif '1.1.202' in btext:
        print('lucy version already 1.1.202')
    else:
        print('refused: unexpected lucy version')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

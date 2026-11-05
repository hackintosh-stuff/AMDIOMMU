// bizwalk.cpp -- appended to AMDMapperProbePgtDebug.cpp by tools/r11/splice-bizwalk.py.
//
// WHY THIS IS A SEPARATE GENERATED BLOCK
// --------------------------------------
// AMDMapperProbePgtDebug.cpp is 2,237 lines. Inserting a ~260-line function by hand
// into it is how a previous round lost a definition entirely (m2b2ScanTxDone,
// which only surfaced at link time as a kmutil bind failure). So the block is
// kept here, spliced at a named anchor, and the splice is verified by compiling.

void org_example_AMDMapperProbe::m2b2WalkBusinessRanges(
        const volatile UInt64 *dte, UInt32 tgt,
        const volatile UInt64 *ptv, UInt64 ptBase, UInt64 ptBytes) {
    fM22b2Dma.bizWalkCount = 0;
    fM22b2Dma.bizWalkOk = 0;
    fM22b2Dma.bizWalkFail = 0;

    // ---- 起点：本次实验里**实际**写到设备表里的那条 DTE ----
    //
    // 第十轮的分析器有一项 "the root table is the one the DTE names"，判据是
    //
    //     pte_get('m2-b2-win0-pte0-table') == pte_get('m2-b2-dte-root')
    //         or pte_get('m2-b2-dte-root') is None
    //
    // 而 m2-b2-dte-root 这个属性**从来没有被发布过**，于是右边恒为真，
    // 这一项从未检查任何东西。现在改为从 dte[] 读回真实值，并把它一起
    // 导出，使"根表来自实际 DTE"成为可核对的事实而不是一句声明。
    const UInt64 dteRaw = (UInt64)dte[tgt * 4 + 0];
    const UInt64 dteMode =
        (dteRaw >> M2B2_DEV_ENTRY_MODE_SHIFT) & M2B2_DEV_ENTRY_MODE_MASK;
    const UInt64 dteRootPA = dteRaw & M2B2_PTE_ADDR_MASK;
    const bool dteValid = (dteRaw & DTE_V) != 0;
    const bool dteTranslate = (dteRaw & DTE_TV) != 0 && dteMode != 0;
    const unsigned rootLevel =
        (dteMode == 3) ? amdpte::LEVEL_1G
                       : (dteMode == 4 ? amdpte::LEVEL_512G : 0);

    setHexProperty(this, "m2-b2-bizwalk-dte-raw", dteRaw);
    setHexProperty(this, "m2-b2-bizwalk-dte-mode", dteMode);
    setHexProperty(this, "m2-b2-bizwalk-dte-root-pa", dteRootPA);
    setHexProperty(this, "m2-b2-bizwalk-root-level", (UInt64)rootLevel);
    setProperty("m2-b2-bizwalk-dte-state",
                !dteValid ? "not-valid"
                          : (!dteTranslate ? "passthrough-not-translating"
                                           : "translation"));

    if (!dteValid || !dteTranslate || rootLevel == 0) {
        // The DTE is not in a state where a walk means anything. Every range
        // is reported as unproven rather than silently skipped: a caller must
        // not be able to read "0 failures" as success.
        setProperty("m2-b2-bizwalk", "SKIP-dte-not-translating");
        setProperty("m2-b2-bizwalk-why",
                    !dteValid ? "dte-not-valid"
                              : (!dteTranslate ? "dte-passthrough"
                                               : "dte-mode-unsupported"));
        return;
    }

    // ---- 读取页表内存的唯一入口 ----
    //
    // 与第 17b 步相同的边界检查：只允许读本次分配的页表块，越界返回 0
    // （0 的 PR=0，解码为 absent，不会伪造出叶子）。
    const UInt64 ptEnd = ptBase + ptBytes;
    if (!ptv || ptEnd <= ptBase) {
        setProperty("m2-b2-bizwalk", "SKIP-no-page-table-memory");
        return;
    }

    // ---- 走一个地址，导出逐级事实 ----
    //
    // 返回 true 表示命中了合法叶子；叶子信息通过 out 参数带回。
    struct LeafInfo {
        bool ok;
        UInt64 leafPA;
        UInt64 leafSize;
        unsigned leafLevel;
        UInt64 pteRaw;
        unsigned depth;
    };
    struct LevelFact {
        UInt64 tablePA;
        unsigned index;
        unsigned level;
        UInt64 pte;
    };
    LevelFact facts[fM22b2Dma.kBizWalkMaxLevels];

    auto walkOne = [&](UInt64 addr, unsigned *depthOut, LeafInfo *leaf,
                       LevelFact *outFacts) -> bool {
        unsigned n = 0;
        unsigned lvl = rootLevel;
        UInt64 tablePA = dteRootPA;
        leaf->ok = false;
        leaf->leafPA = 0;
        leaf->leafSize = 0;
        leaf->leafLevel = 0;
        leaf->pteRaw = 0;
        leaf->depth = 0;

        while (n < fM22b2Dma.kBizWalkMaxLevels) {
            if (tablePA < ptBase || tablePA >= ptEnd) break;
            const UInt64 byteOff = tablePA - ptBase;
            const unsigned ix = amdpte::indexAt(lvl, addr);
            if (byteOff + 8ULL * ix + 8ULL > (ptEnd - ptBase)) break;

            const UInt64 pte = (UInt64)ptv[byteOff / 8 + ix];
            outFacts[n].tablePA = tablePA;
            outFacts[n].index = ix;
            outFacts[n].level = lvl;
            outFacts[n].pte = pte;
            n++;

            const amdpte::DecodedPte d = amdpte::decodePte(pte, lvl);
            if (d.kind == amdpte::PTE_TABLE) {
                lvl = d.childLevel;
                tablePA = d.outPA;
                continue;
            }
            if (d.kind == amdpte::PTE_LEAF_DEFAULT ||
                d.kind == amdpte::PTE_LEAF_LARGE) {
                leaf->ok = true;
                leaf->leafPA = d.outPA;
                leaf->leafSize = d.pageSize;
                leaf->leafLevel = lvl;
                leaf->pteRaw = pte;
                leaf->depth = n;
                *depthOut = n;
                return true;
            }
            break;   // absent or illegal
        }
        *depthOut = n;
        return false;
    };

    // ---- 逐请求、逐方向、逐段 ----
    //
    // 区间是 [addr, addr+len)，不是"地址所在的那一页"。跨页、跨叶子、
    // 以及 addr+len 溢出都必须处理：一条 74 字节的报文完全可能跨过 2 MiB
    // 叶子边界，而只检查起始页会漏掉后半段。
    const amdobs::ObsJoin &j = fM22b2ObsJoin;
    UInt32 count = 0;
    UInt32 ok = 0, fail = 0;

    auto recordRange = [&](UInt32 reqId, UInt8 isRx, UInt8 segIdx,
                           UInt64 addr, UInt32 len) {
        if (count >= fM22b2Dma.kBizWalkMaxSegs) return;
        if (addr == 0 || len == 0) return;

        auto &w = fM22b2Dma.bizWalk[count];
        w.reqId = reqId;
        w.isRx = isRx;
        w.segIndex = segIdx;
        w.addr = addr;
        w.len = len;
        w.rootPA = dteRootPA;
        w.rootLevel = rootLevel;
        w.dteRaw = dteRaw;
        w.leafPA = 0;
        w.leafSize = 0;
        w.leafLevel = 0;
        w.pagesChecked = 0;
        w.pagesBad = 0;
        w.overflow = 0;
        w.why = "ok";

        const UInt64 end = addr + (UInt64)len;
        if (end < addr) {          // 64-bit wrap
            w.overflow = 1;
            w.covered = 0;
            w.permOk = 0;
            w.depth = 0;
            w.why = "range-overflows";
            fM22b2Dma.bizWalkFail++;
            count++;
            return;
        }

        // Walk the first byte's page and export the chain.
        unsigned depth = 0;
        LeafInfo leaf;
        bool firstOk = walkOne(addr, &depth, &leaf, facts);
        w.depth = (UInt8)(depth > fM22b2Dma.kBizWalkMaxLevels
                              ? fM22b2Dma.kBizWalkMaxLevels : depth);
        for (UInt32 k = 0; k < w.depth; k++) {
            w.tablePA[k] = facts[k].tablePA;
            w.index[k] = facts[k].index;
            w.level[k] = facts[k].level;
            w.pte[k] = facts[k].pte;
        }
        if (!firstOk) {
            w.covered = 0;
            w.permOk = 0;
            w.why = "start-not-a-legal-leaf";
            fM22b2Dma.bizWalkFail++;
            count++;
            return;
        }
        w.leafPA = leaf.leafPA;
        w.leafSize = leaf.leafSize;
        w.leafLevel = (UInt8)leaf.leafLevel;

        // Permission for THIS direction:
        //   TX: the device READS the buffer  -> IR must be set
        //   RX: the device WRITES the buffer -> IW must be set
        // Leaf and every directory entry on the path are checked, because a
        // directory without IR makes the leaf unreachable for a read even if
        // the leaf itself carries IR.
        bool permOk = true;
        for (UInt32 k = 0; k < w.depth; k++) {
            if (isRx) {
                if ((w.pte[k] & amdpte::PTE_IW) == 0) permOk = false;
            } else {
                if ((w.pte[k] & amdpte::PTE_IR) == 0) permOk = false;
            }
        }
        w.permOk = permOk ? 1 : 0;

        // Coverage: every page the range touches must resolve to a legal leaf
        // that actually contains the address. Checking only the first page is
        // the mistake that lets a 74-byte range straddling a leaf boundary
        // look fully mapped.
        UInt32 pages = 0, bad = 0;
        UInt64 cur = addr;
        while (cur < end) {
            unsigned d2 = 0;
            LeafInfo l2;
            const bool good = walkOne(cur, &d2, &l2, facts);
            pages++;
            if (!good) {
                bad++;
            } else {
                // The leaf must cover `cur`: base <= cur < base + size.
                if (!(l2.leafPA <= cur && cur < l2.leafPA + l2.leafSize))
                    bad++;
                // And it must translate back to itself (identity map), which
                // is the property this whole experiment relies on.
                else if ((l2.leafPA | (cur & (l2.leafSize - 1))) != cur)
                    bad++;
            }
            // Advance to the next page boundary, bounded: if a leaf is huge
            // this jumps a long way, which is correct and keeps the loop
            // bounded by the number of distinct pages the range touches.
            const UInt64 pageSize = (l2.ok && l2.leafSize) ? l2.leafSize
                                                           : 4096ULL;
            const UInt64 next = (cur & ~(pageSize - 1)) + pageSize;
            if (next <= cur) break;         // defensive: no infinite loop
            cur = next;
        }
        w.pagesChecked = pages;
        w.pagesBad = bad;
        w.covered = (bad == 0) ? 1 : 0;
        if (!w.covered) w.why = "range-not-fully-covered";

        if (w.covered && w.permOk) ok++;
        else                       fail++;
        count++;
    };

    for (UInt32 k = 0; k < j.bizCount; k++) {
        const amdobs::ObsBizOp &b = j.biz[k];
        if (b.segCount == 0) continue;
        for (UInt32 s = 0; s < b.segCount && s < amdobs::OBS_MAX_SEGS; s++) {
            recordRange(b.reqId, 0, (UInt8)s, b.segAddr[s], b.segLen[s]);
        }
        if (b.haveRx) {
            recordRange(b.reqId, 1, 0, b.rxAddr, b.rxLen);
        }
    }

    fM22b2Dma.bizWalkCount = count;
    fM22b2Dma.bizWalkOk = ok;
    fM22b2Dma.bizWalkFail = fail;

    setHexProperty(this, "m2-b2-bizwalk-count", (UInt64)count);
    setHexProperty(this, "m2-b2-bizwalk-ok", (UInt64)ok);
    setHexProperty(this, "m2-b2-bizwalk-fail", (UInt64)fail);
    setProperty("m2-b2-bizwalk",
                count == 0 ? "SKIP-no-business-ranges"
                           : (fail == 0 ? "all-covered" : "SOME-NOT-COVERED"));

    // ---- 逐段发布 ----
    //
    // 每段的每一级都发布：表物理地址、索引、级别、原始 PTE。这是"这条
    // 业务 DMA 区间经过了哪条真实页表路径"的唯一可复核形式；分析器据此
    // 独立解码，不依赖这里的任何结论字符串。
    for (UInt32 i = 0; i < count; i++) {
        const auto &w = fM22b2Dma.bizWalk[i];
        char k[64];
        snprintf(k, sizeof(k), "m2-b2-bw%u-req", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.reqId);
        snprintf(k, sizeof(k), "m2-b2-bw%u-dir", (unsigned)i);
        setProperty(k, w.isRx ? "rx" : "tx");
        snprintf(k, sizeof(k), "m2-b2-bw%u-seg", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.segIndex);
        snprintf(k, sizeof(k), "m2-b2-bw%u-addr", (unsigned)i);
        setHexProperty(this, k, w.addr);
        snprintf(k, sizeof(k), "m2-b2-bw%u-len", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.len);
        snprintf(k, sizeof(k), "m2-b2-bw%u-depth", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.depth);
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaf-pa", (unsigned)i);
        setHexProperty(this, k, w.leafPA);
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaf-size", (unsigned)i);
        setHexProperty(this, k, w.leafSize);
        snprintf(k, sizeof(k), "m2-b2-bw%u-leaf-level", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.leafLevel);
        snprintf(k, sizeof(k), "m2-b2-bw%u-covered", (unsigned)i);
        setProperty(k, w.covered ? "yes" : "no");
        snprintf(k, sizeof(k), "m2-b2-bw%u-perm-ok", (unsigned)i);
        setProperty(k, w.permOk ? "yes" : "no");
        snprintf(k, sizeof(k), "m2-b2-bw%u-pages", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.pagesChecked);
        snprintf(k, sizeof(k), "m2-b2-bw%u-pages-bad", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.pagesBad);
        snprintf(k, sizeof(k), "m2-b2-bw%u-why", (unsigned)i);
        setProperty(k, w.why);
        // 走表起点：与 DTE 同源，使"根表来自实际 DTE"可核对
        snprintf(k, sizeof(k), "m2-b2-bw%u-root-pa", (unsigned)i);
        setHexProperty(this, k, w.rootPA);
        snprintf(k, sizeof(k), "m2-b2-bw%u-root-level", (unsigned)i);
        setHexProperty(this, k, (UInt64)w.rootLevel);
        snprintf(k, sizeof(k), "m2-b2-bw%u-dte", (unsigned)i);
        setHexProperty(this, k, w.dteRaw);

        for (UInt32 L = 0; L < w.depth; L++) {
            snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u-table", (unsigned)i,
                     (unsigned)L);
            setHexProperty(this, k, w.tablePA[L]);
            snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u-index", (unsigned)i,
                     (unsigned)L);
            setHexProperty(this, k, (UInt64)w.index[L]);
            snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u-level", (unsigned)i,
                     (unsigned)L);
            setHexProperty(this, k, (UInt64)w.level[L]);
            snprintf(k, sizeof(k), "m2-b2-bw%u-pte%u", (unsigned)i,
                     (unsigned)L);
            setHexProperty(this, k, w.pte[L]);
        }
    }
}

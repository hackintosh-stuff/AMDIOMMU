    // ---- 第 15b 步：把观察窗口内**全部** fault 事件解出来 ----
    //
    // 【2026-10-31 修正】这一块原先有两个缺陷，导致此前所有结论都建立在
    // 一个 4 条事件的小样本上：
    //
    //   缺陷 1：从 evtBuf[0] 开始解析。
    //     事件缓冲是**环形**的，head/tail 是**字节偏移**。硬件把新事件写在
    //     tail 处并推进 tail，head 只在软件消费时前进。我们在观察窗口前把
    //     head/tail 都归零，所以窗口内第一条确实落在 0；但窗口里可能有
    //     几十条事件，一旦超过缓冲容量就会回绕，或 head 被别处推进后
    //     起始点不再是 0。正确做法是从 evtHead % SIZE 开始走。
    //
    //   缺陷 2：只解前 4 条（kMaxDump=4）。
    //     实测 evt-count2 是 0x38（56 条），也就是**只看了 7%**。
    //     剩下 52 条的地址分布完全未知——它们可能全部落在映射范围外，
    //     那样"页表正确却仍然 fault"的结论就站不住。
    //
    // 现在：解全部事件，统计类型/标志/地址分布，对每条在范围内的地址
    // 做软件走表。这样"页表是否覆盖了硬件实际访问的地址"才有定论。
    const UInt64 evtBaseHead = evtHead2 % M2B2_EVT_BUFFER_SIZE;
    UInt32 evtTotal = 0;
    UInt32 evtTypeCount[16] = { 0 };
    UInt32 evtFlagRW = 0;       // EVENT_FLAG_RW  0x020
    UInt32 evtFlagI  = 0;       // EVENT_FLAG_I   0x008
    UInt32 evtBadDevid = 0;     // 事件不属于目标设备
    UInt32 evtInRange = 0;      // fault 地址落在映射范围内
    UInt32 evtOutOfRange = 0;   // fault 地址超出映射范围
    UInt32 evtWalkPresent = 0;  // 范围内且页表命中
    UInt32 evtWalkAbsent = 0;   // 范围内但页表缺项
    UInt64 evtMinAddr = 0;
    UInt64 evtMaxAddr = 0;
    UInt64 evtFirstAbsent = 0;
    UInt64 evtFirstOA = 0;
    const UInt64 evtMapLimit = fM22b2Use4K ? M2B2_4K_MAP_LIMIT
                                           : M2B2_IDENTITY_LIMIT;
    const UInt32 evtMaxSlots = (UInt32)(M2B2_EVT_BUFFER_SIZE / 16);

    for (UInt32 n = 0; n < evtCount2 && n < evtMaxSlots; n++) {
        // 环形偏移：从 head 起，按 16 字节步进，回绕到缓冲开头
        const UInt64 byteOff =
            (evtBaseHead + (UInt64)n * 16) % M2B2_EVT_BUFFER_SIZE;
        const UInt32 q = (UInt32)(byteOff / 4);

        const UInt32 r0 = evtBuf[q + 0];
        const UInt32 r1 = evtBuf[q + 1];
        const UInt32 r2 = evtBuf[q + 2];
        const UInt32 r3 = evtBuf[q + 3];

        const UInt32 t = (r1 >> M2B2_EVENT_TYPE_SHIFT) &
                         M2B2_EVENT_TYPE_MASK;
        const UInt32 fl = (r1 >> 16) & 0xFFF;      // EVENT_FLAGS_MASK
        const UInt32 dv = r0 & M2B2_EVENT_DEVID_MASK;
        const UInt64 addr = ((UInt64)r3 << 32) | r2;

        if (t == 0) continue;                      // 空槽位
        evtTotal++;
        if (t < 16) evtTypeCount[t]++;
        if (fl & 0x020) evtFlagRW++;
        if (fl & 0x008) evtFlagI++;
        if (dv != tgt) evtBadDevid++;

        if (evtMinAddr == 0 || addr < evtMinAddr) evtMinAddr = addr;
        if (addr > evtMaxAddr) evtMaxAddr = addr;

        // 只对 IO_PAGE_FAULT 的地址做范围判定与走表：
        // 其他类型的 address 字段语义不同（例如 ILL_CMD 是命令缓冲偏移）。
        if (t != M2B2_EVENT_IO_FAULT) continue;

        if (addr >= evtMapLimit) {
            evtOutOfRange++;
            continue;
        }
        evtInRange++;

        // ---- 软件走表：这张表里到底有没有这个地址？----
        const UInt32 i3 = (UInt32)((addr >> 39) & 0x1FF);
        const UInt32 i2 = (UInt32)((addr >> 30) & 0x1FF);
        const UInt32 i1 = (UInt32)((addr >> 21) & 0x1FF);
        const UInt32 i0 = (UInt32)((addr >> 12) & 0x1FF);

        bool present = false;
        UInt64 oa = 0;
        const UInt64 pte3 = root[fM22b2Use3L ? i2 : i3];
        if (pte3 & M2B2_PTE_PR) {
            if (fM22b2Use3L) {
                const UInt64 paLeaf = pte3 & M2B2_PTE_ADDR_MASK;
                if (paLeaf >= (UInt64)ptPA && paLeaf < (UInt64)ptPA + ptBytes) {
                    volatile UInt64 *lf = (volatile UInt64 *)
                        ((UInt8 *)pt + (paLeaf - (UInt64)ptPA));
                    const UInt64 pte1 = lf[i1];
                    if (pte1 & M2B2_PTE_PR) {
                        present = true;
                        oa = (pte1 & M2B2_PTE_ADDR_MASK) &
                             ~(M2B2_LARGE_PAGE - 1);
                    }
                }
            } else {
                const UInt64 pa2 = pte3 & M2B2_PTE_ADDR_MASK;
                if (pa2 >= (UInt64)ptPA && pa2 < (UInt64)ptPA + ptBytes) {
                    volatile UInt64 *l2v = (volatile UInt64 *)
                        ((UInt8 *)pt + (pa2 - (UInt64)ptPA));
                    const UInt64 pte2 = l2v[i2];
                    if (pte2 & M2B2_PTE_PR) {
                        const UInt64 pa1 = pte2 & M2B2_PTE_ADDR_MASK;
                        if (pa1 >= (UInt64)ptPA &&
                            pa1 < (UInt64)ptPA + ptBytes) {
                            volatile UInt64 *lvl1t = (volatile UInt64 *)
                                ((UInt8 *)pt + (pa1 - (UInt64)ptPA));
                            if (fM22b2Use4K) {
                                const UInt64 pteL1 = lvl1t[i1];
                                if (pteL1 & M2B2_PTE_PR) {
                                    const UInt64 paL =
                                        pteL1 & M2B2_PTE_ADDR_MASK;
                                    if (paL >= (UInt64)ptPA &&
                                        paL < (UInt64)ptPA + ptBytes) {
                                        volatile UInt64 *lf =
                                            (volatile UInt64 *)
                                            ((UInt8 *)pt +
                                             (paL - (UInt64)ptPA));
                                        const UInt64 pte1 = lf[i0];
                                        if (pte1 & M2B2_PTE_PR) {
                                            present = true;
                                            oa = pte1 & M2B2_PTE_ADDR_MASK;
                                        }
                                    }
                                }
                            } else {
                                const UInt64 pte1 = lvl1t[i1];
                                if (pte1 & M2B2_PTE_PR) {
                                    present = true;
                                    oa = (pte1 & M2B2_PTE_ADDR_MASK) &
                                         ~(M2B2_LARGE_PAGE - 1);
                                }
                            }
                        }
                    }
                }
            }
        }

        if (present) {
            evtWalkPresent++;
            if (evtFirstOA == 0) evtFirstOA = oa;
        } else {
            evtWalkAbsent++;
            if (evtFirstAbsent == 0) evtFirstAbsent = addr;
        }
    }

    // ---- 发布统计 ----
    setHexProperty(this, "m2-b2-evt-total", evtTotal);
    setHexProperty(this, "m2-b2-evt-head-mod", evtBaseHead);
    for (UInt32 t = 1; t < 16; t++) {
        if (evtTypeCount[t] == 0) continue;
        char k[40];
        snprintf(k, sizeof(k), "m2-b2-evt-type%u-count", t);
        setHexProperty(this, k, evtTypeCount[t]);
    }
    setHexProperty(this, "m2-b2-evt-flag-rw", evtFlagRW);
    setHexProperty(this, "m2-b2-evt-flag-i", evtFlagI);
    setHexProperty(this, "m2-b2-evt-bad-devid", evtBadDevid);
    setHexProperty(this, "m2-b2-fault-inrange", evtInRange);
    setHexProperty(this, "m2-b2-fault-outofrange", evtOutOfRange);
    setHexProperty(this, "m2-b2-fault-walk-present", evtWalkPresent);
    setHexProperty(this, "m2-b2-fault-walk-absent", evtWalkAbsent);
    setHexProperty(this, "m2-b2-fault-addr-min", evtMinAddr);
    setHexProperty(this, "m2-b2-fault-addr-max", evtMaxAddr);
    if (evtFirstAbsent) {
        setHexProperty(this, "m2-b2-fault-walk-1stabsent", evtFirstAbsent);
    }
    if (evtFirstOA) {
        setHexProperty(this, "m2-b2-fault-walk-1stoa", evtFirstOA);
    }

    // 类型名（只报最常见的那一种，避免属性爆炸）
    {
        UInt32 bestT = 0, bestN = 0;
        for (UInt32 t = 1; t < 16; t++) {
            if (evtTypeCount[t] > bestN) { bestN = evtTypeCount[t]; bestT = t; }
        }
        const char *tn = "none";
        switch (bestT) {
        case M2B2_EVENT_ILL_DEV:      tn = "ILL_DEV_TABLE_ENTRY"; break;
        case M2B2_EVENT_IO_FAULT:     tn = "IO_PAGE_FAULT"; break;
        case M2B2_EVENT_DEV_TAB_ERR:  tn = "DEV_TAB_ERR"; break;
        case M2B2_EVENT_PAGE_TAB_ERR: tn = "PAGE_TAB_ERR"; break;
        case M2B2_EVENT_ILL_CMD:      tn = "ILL_CMD"; break;
        case M2B2_EVENT_CMD_HARD_ERR: tn = "CMD_HARD_ERR"; break;
        case M2B2_EVENT_INV_DEV_REQ:  tn = "INV_DEV_REQ"; break;
        default: break;
        }
        setProperty("m2-b2-evt-dominant", tn);
        setHexProperty(this, "m2-b2-evt-dominant-count", bestN);
    }

    // ---- 判据：把"页表覆盖"与"硬件不认"彻底分开 ----
    //
    // 只有这三种结论是有区分力的：
    //   TABLE-MISSING-ENTRIES   范围内有地址在页表里查不到 -> 页表真的缺项
    //   TABLE-OK-HARDWARE-SIDE  范围内每条地址页表都命中 -> 问题在硬件侧
    //   NO-IN-RANGE-FAULT       所有 fault 都在范围外 -> 我们根本没测到
    if (evtInRange == 0 && evtOutOfRange > 0) {
        setProperty("m2-b2-fault-walk-verdict", "NO-IN-RANGE-FAULT");
        setProperty("m2-b2-fault-walk-meaning",
            "all-faults-outside-mapped-range-test-invalid");
    } else if (evtWalkAbsent > 0) {
        setProperty("m2-b2-fault-walk-verdict", "TABLE-MISSING-ENTRIES");
        setProperty("m2-b2-fault-walk-meaning",
            "pagetable-really-lacks-mapped-address");
    } else if (evtWalkPresent > 0) {
        setProperty("m2-b2-fault-walk-verdict", "TABLE-OK-HARDWARE-SIDE");
        setProperty("m2-b2-fault-walk-meaning",
            "every-in-range-fault-address-is-mapped-problem-is-hardware");
    } else {
        setProperty("m2-b2-fault-walk-verdict", "no-faults");
        setProperty("m2-b2-fault-walk-meaning", "nothing-to-walk");
    }

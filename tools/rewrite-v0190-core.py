#!/usr/bin/env python3
"""Replace the M2-2b-2 experiment core (steps 10-19) with the v0.19.0 strict
single-configuration baseline.

WHY A REPLACEMENT AND NOT ANOTHER PATCH
---------------------------------------
The old core ran five experiments back to back (baseline windows, leaf-table
zeroing, DOMID A/B, V-bit A/B/A, bad-root negative control). Round 4 asks for
ONE minimal controlled baseline with:

  * spec-conforming event consumption (m2b2SampleEvents)
  * one command context so domain/devid can never diverge (M2B2CmdCtx)
  * every command failure latching and aborting, never continuing
  * an explicit recovery state machine that refuses to free memory when it
    cannot prove the hardware has stopped referencing it
  * verdicts that separate INVALID / INDETERMINATE / FAIL / PASS

Keeping the old matrix would also keep its hardcoded domain 0 and its
unchecked completions, so the block is replaced wholesale.

The replaced region runs from the "第 10 步" marker to just before
"// ------- 统计属性刷新".

Run: py -3 tools/rewrite-v0190-core.py
"""
import io
import sys

SRC = "kext/AMDMapperProbe.cpp"

START_MARK = "    // ---- 第 10 步：命令辅助状态 ----"
END_MARK = "// ------------------------------------------------------------- 统计属性刷新"

NEW_BODY = r'''    // ---- 第 10 步：命令上下文 ----
    //
    // 所有 devid / domid / page-mode / 根表地址 / 完成信号地址都由 ctx
    // 持有，失效命令一律从它取值。旧代码在 DOMID 分支里改了 DTE 的
    // domain 却仍用 domain 0 发 INV_IOMMU_PAGES，那等于刷了一个不存在的
    // 域；现在这种不一致在结构上不可能发生。
    M2B2CmdCtx ctx;
    ctx.buf = cmdBuf;
    ctx.sem = sem;
    ctx.semPA = (UInt64)semPA;
    ctx.idx = 0;
    ctx.tail = 0;
    ctx.domid = 0;
    ctx.devid = tgt;
    ctx.pageMode = 0;
    ctx.rootPA = 0;
    ctx.failed = false;
    ctx.failReason = nullptr;
    ctx.submits = 0;
    ctx.completed = 0;
    ctx.lastSem = 0;
    ctx.lastLoops = 0;

    // 恢复状态：只有这里全部为 true 才允许释放内存
    bool hwStopped      = false;
    bool cmdBufStopped  = false;
    bool evtLogStopped  = false;
    bool regsRestored   = false;
    bool safeToFree     = false;

    // 窗口记录：切换前对照 + 稳态主窗口
    M2B2EventWindow winPre;
    M2B2EventWindow winMain;

    // ---- 第 11 步：按规范重置事件日志 ----
    //
    // 这是唯一允许写 HEAD/TAIL 的入口：先停 EVT_LOG_EN、等 EVT_RUN=0，
    // 再归零、清 overflow 位、重新使能。日志运行期间绝不触碰 TAIL。
    {
        const bool ok = m2b2ResetEventLog(base);
        setProperty("m2-b2-evt-reset", ok ? "done" : "FAIL-cannot-stop-log");
        if (!ok) {
            // 无法确认日志已停 → 不碰缓冲、不做实验，直接进入恢复
            setProperty("m2-b2-verdict", "INVALID-evt-log-will-not-stop");
            setProperty("m2-b2-stage", "11-abort-evt-log");
            goto recover;
        }
    }

    // ---- 第 12 步：使能后先清一次缓存（此时仍全直通）----
    //
    // CMD_INV_ALL (type 0x08) 在 FEATURE_IA=1 时合法（第三轮已解码确认）。
    if (!m2b2Submit(base, &ctx, "inv-all",
                    0, (M2B2_CMD_INV_ALL << 28), 0, 0)) {
        setProperty("m2-b2-inv-all", "FAIL-no-completion");
        setProperty("m2-b2-verdict", "INVALID-inv-all-no-completion");
        setProperty("m2-b2-stage", "12-abort-inv-all");
        goto recover;
    }
    setProperty("m2-b2-inv-all", "done");

    // ---- 第 13 步：纯睡眠对照（pgtsleep）----
    //
    // 该分支**不切换 DTE**，只做与 pgthold 相同的长睡眠，用来区分
    // "翻译导致设备冻结" 与 "长 IOSleep 阻塞 workloop 导致测量假象"。
    //
    // 【明确时长】本分支固定 20 秒，**不是** M2B2_MEAS_SECS。它的用途
    // 是从外部用 netstat 观察设备是否仍在收发，需要足够长的时间窗；
    // 而它不产生任何用于比较的事件计数，所以不存在与其他窗口错配的问题。
    if (fM22b2SleepOnly) {
        setProperty("m2-b2-sleep-only", "yes");
        setProperty("m2-b2-dte", "NOT-switched-control");
        setHexProperty(this, "m2-b2-window-secs", 20);
        IOSleep(20000);
        setProperty("m2-b2-sleep-only", "done");

        setProperty("m2-b2-evt-window", "none-in-sleep-only-branch");
        setProperty("m2-b2-verdict", "CONTROL-sleep-only-no-dte-change");
        setProperty("m2-b2-stage", "13-control-complete");
        goto recover;
    }

    // ---- 第 14 步：建设备表项并切换目标设备到翻译 ----
    //
    // set_dte_entry()（iommu.c:1580-1602）：
    //   pte_root = root_pa | (mode << 9) | IR | IW | V | TV
    {
        const UInt64 pageMode = fM22b2Use3L ? M2B2_PAGE_MODE_3_LEVEL
                                            : M2B2_PAGE_MODE_4_LEVEL;
        setHexProperty(this, "m2-b2-page-mode", pageMode);

        const UInt64 dteRoot = (rootPA & M2B2_PTE_ADDR_MASK) |
                               ((pageMode & M2B2_DEV_ENTRY_MODE_MASK)
                                << M2B2_DEV_ENTRY_MODE_SHIFT) |
                               DTE_IR | DTE_IW | DTE_V | DTE_TV;

        const UInt64 dtePassthrough = DTE_V | DTE_TV | DTE_IR | DTE_IW;
        setHexProperty(this, "m2-b2-dte-pass", dtePassthrough);
        setHexProperty(this, "m2-b2-dte-xlate", dteRoot);
        setHexProperty(this, "m2-b2-dte-before", dte[tgt * 4 + 0]);

        ctx.domid = 0;
        ctx.pageMode = (UInt32)pageMode;
        ctx.rootPA = rootPA;

        // 切换前先采一个窗口：此时 DTE 仍是直通，任何事件都不是翻译造成的。
        m2b2SampleEvents(base, evtBuf, M2B2_MEAS_SECS, tgt, &winPre);
        setHexProperty(this, "m2-b2-pre-entries", winPre.entries);
        setProperty("m2-b2-pre-valid", winPre.valid ? "yes" : "no");
        if (!winPre.valid) {
            setProperty("m2-b2-pre-invalid", winPre.invalidReason);
        }

        dte[tgt * 4 + 0] = dteRoot;
        dte[tgt * 4 + 1] = ctx.domid;   // data[1] 低 16 位 = domain id
        dte[tgt * 4 + 2] = 0;
        dte[tgt * 4 + 3] = 0;
        setHexProperty(this, "m2-b2-dte-after", dte[tgt * 4 + 0]);
        setHexProperty(this, "m2-b2-dte-domid", dte[tgt * 4 + 1]);
        setProperty("m2-b2-dte", "switched-to-translation");
        OSSynchronizeIO();
    }

    // ---- 第 15 步：失效命令（全部从 ctx 取参数）----
    //
    // 顺序照抄 Linux attach_device：先 INV_DEV_ENTRY，再刷 TLB。
    // INV_IOMMU_PAGES 的 domain 取 ctx.domid —— 这正是旧代码的缺陷所在。
    {
        const UInt64 invAddr = m2b2InvAddress();
        setHexProperty(this, "m2-b2-inv-addr", invAddr);

        // (a) INV_DEV_ENTRY：data[0] = devid，type 在 data[1] bit28
        if (!m2b2Submit(base, &ctx, "inv-dev-entry",
                        ctx.devid,
                        (M2B2_CMD_INV_DEV_ENTRY << 28), 0, 0)) {
            setProperty("m2-b2-inv", "FAIL-inv-dev-entry-no-completion");
            setProperty("m2-b2-verdict", "INVALID-inv-dev-entry");
            setProperty("m2-b2-stage", "15-abort-inv-dev-entry");
            goto recover;
        }

        // (b) INV_IOMMU_PAGES：整个地址空间，domain 来自 ctx
        //     data[1] 低 16 位 = domid；PDE 位表示连 PDE 一起失效
        if (!m2b2Submit(base, &ctx, "inv-iommu-pages",
                        0,
                        ctx.domid | (M2B2_CMD_INV_IOMMU_PAGES << 28),
                        (UInt32)(invAddr & 0xFFFFFFFF) | M2B2_CMD_PDE_MASK,
                        (UInt32)(invAddr >> 32))) {
            setProperty("m2-b2-inv", "FAIL-inv-pages-no-completion");
            setProperty("m2-b2-verdict", "INVALID-inv-pages");
            setProperty("m2-b2-stage", "15-abort-inv-pages");
            goto recover;
        }

        setProperty("m2-b2-inv", "dev-entry+pages-flushed");
        setHexProperty(this, "m2-b2-inv-domid", ctx.domid);
        setHexProperty(this, "m2-b2-cmd-submits", ctx.submits);
        setHexProperty(this, "m2-b2-cmd-completed", ctx.completed);
        setHexProperty(this, "m2-b2-inv-sem", ctx.lastSem);
        setHexProperty(this, "m2-b2-inv-loops", ctx.lastLoops);
    }

    // ---- 第 16 步：稳态观察窗口（唯一的功能判据窗口）----
    //
    // 严格按规范消费事件环：只推进 HEAD，绝不写 TAIL，不清空缓冲。
    // 窗口有效性由 m2b2SampleEvents 判定；无效即"无法判定"，不是 0 事件。
    m2b2SampleEvents(base, evtBuf, M2B2_MEAS_SECS, tgt, &winMain);

    setHexProperty(this, "m2-b2-meas-secs", M2B2_MEAS_SECS);
    setHexProperty(this, "m2-b2-window-secs", M2B2_MEAS_SECS);
    setProperty("m2-b2-window-valid", winMain.valid ? "yes" : "no");
    if (!winMain.valid) {
        setProperty("m2-b2-window-invalid", winMain.invalidReason);
    }
    setHexProperty(this, "m2-b2-win-dur-ms", winMain.durMS);
    setHexProperty(this, "m2-b2-win-head-start", winMain.headStart);
    setHexProperty(this, "m2-b2-win-tail-start", winMain.tailStart);
    setHexProperty(this, "m2-b2-win-head-end", winMain.headEnd);
    setHexProperty(this, "m2-b2-win-tail-end", winMain.tailEnd);
    setHexProperty(this, "m2-b2-win-status-start", winMain.statusStart);
    setHexProperty(this, "m2-b2-win-status-end", winMain.statusEnd);
    setHexProperty(this, "m2-b2-win-entries", winMain.entries);
    setHexProperty(this, "m2-b2-win-devid-mismatch", winMain.devidMismatch);
    setHexProperty(this, "m2-b2-status", (UInt64)winMain.statusEnd);

    // 逐类型计数 + 原始事件（供离线解码，不再只留总数）
    for (UInt32 t = 1; t < 16; t++) {
        if (winMain.typeCount[t] == 0) continue;
        char k[48];
        snprintf(k, sizeof(k), "m2-b2-win-type%u-name", t);
        setProperty(k, m2b2EventTypeName(t));
        snprintf(k, sizeof(k), "m2-b2-win-type%u-count", t);
        setHexProperty(this, k, winMain.typeCount[t]);
    }
    setHexProperty(this, "m2-b2-win-raw-count", winMain.rawCount);
    for (UInt32 i = 0; i < winMain.rawCount; i++) {
        char k[48];
        snprintf(k, sizeof(k), "m2-b2-win-raw%u", i);
        char v[96];
        snprintf(v, sizeof(v), "%08x%08x%08x%08x",
                 winMain.raw[i][0], winMain.raw[i][1],
                 winMain.raw[i][2], winMain.raw[i][3]);
        setProperty(k, v);
    }

    // 主类型（只报最多的那一种，附规范名称）
    {
        UInt32 bestT = 0, bestN = 0;
        for (UInt32 t = 1; t < 16; t++) {
            if (winMain.typeCount[t] > bestN) {
                bestN = winMain.typeCount[t];
                bestT = t;
            }
        }
        setProperty("m2-b2-win-dominant",
                    bestT ? m2b2EventTypeName(bestT) : "none");
        setHexProperty(this, "m2-b2-win-dominant-count", bestN);
    }

    // ---- 第 17 步：把窗口内的 IO_PAGE_FAULT 地址逐个对照页表 ----
    //
    // 只对类型 2 的 address 字段做范围判定与走表：其他类型的 address
    // 语义不同（ILL_CMD 是命令缓冲地址）。
    {
        UInt32 evtInRange = 0, evtOutOfRange = 0;
        UInt32 evtWalkPresent = 0, evtWalkAbsent = 0;
        UInt64 evtMinAddr = 0, evtMaxAddr = 0, evtFirstAbsent = 0;
        const UInt64 mapLimit = fM22b2Use4K ? M2B2_4K_MAP_LIMIT
                                            : M2B2_IDENTITY_LIMIT;

        for (UInt32 i = 0; i < winMain.rawCount; i++) {
            const UInt32 r0 = winMain.raw[i][0];
            const UInt32 r1 = winMain.raw[i][1];
            const UInt32 r2 = winMain.raw[i][2];
            const UInt32 r3 = winMain.raw[i][3];

            const UInt32 t = (r1 >> M2B2_EVENT_TYPE_SHIFT) &
                             M2B2_EVENT_TYPE_MASK;
            if (t != M2B2_EVENT_IO_FAULT) continue;

            const UInt64 addr = ((UInt64)r3 << 32) | r2;
            if (evtMinAddr == 0 || addr < evtMinAddr) evtMinAddr = addr;
            if (addr > evtMaxAddr) evtMaxAddr = addr;

            if (addr >= mapLimit) { evtOutOfRange++; continue; }
            evtInRange++;

            const UInt32 i3 = (UInt32)((addr >> 39) & 0x1FF);
            const UInt32 i2 = (UInt32)((addr >> 30) & 0x1FF);
            const UInt32 i1 = (UInt32)((addr >> 21) & 0x1FF);
            const UInt32 i0 = (UInt32)((addr >> 12) & 0x1FF);

            bool present = false;
            const UInt64 pte3 = root[fM22b2Use3L ? i2 : i3];
            if (pte3 & M2B2_PTE_PR) {
                const UInt64 pa2 = pte3 & M2B2_PTE_ADDR_MASK;
                if (fM22b2Use3L) {
                    if (pa2 >= (UInt64)ptPA &&
                        pa2 < (UInt64)ptPA + ptBytes) {
                        volatile UInt64 *lf = (volatile UInt64 *)
                            ((UInt8 *)pt + (pa2 - (UInt64)ptPA));
                        if (lf[i1] & M2B2_PTE_PR) present = true;
                    }
                } else if (pa2 >= (UInt64)ptPA &&
                           pa2 < (UInt64)ptPA + ptBytes) {
                    volatile UInt64 *l2v = (volatile UInt64 *)
                        ((UInt8 *)pt + (pa2 - (UInt64)ptPA));
                    const UInt64 pte2 = l2v[i2];
                    if (pte2 & M2B2_PTE_PR) {
                        const UInt64 pa1 = pte2 & M2B2_PTE_ADDR_MASK;
                        if (pa1 >= (UInt64)ptPA &&
                            pa1 < (UInt64)ptPA + ptBytes) {
                            volatile UInt64 *lvl1 = (volatile UInt64 *)
                                ((UInt8 *)pt + (pa1 - (UInt64)ptPA));
                            if (fM22b2Use4K) {
                                const UInt64 pl1 = lvl1[i1];
                                if (pl1 & M2B2_PTE_PR) {
                                    const UInt64 paL =
                                        pl1 & M2B2_PTE_ADDR_MASK;
                                    if (paL >= (UInt64)ptPA &&
                                        paL < (UInt64)ptPA + ptBytes) {
                                        volatile UInt64 *lf =
                                            (volatile UInt64 *)
                                            ((UInt8 *)pt +
                                             (paL - (UInt64)ptPA));
                                        if (lf[i0] & M2B2_PTE_PR) {
                                            present = true;
                                        }
                                    }
                                }
                            } else if (lvl1[i1] & M2B2_PTE_PR) {
                                present = true;
                            }
                        }
                    }
                }
            }

            if (present) evtWalkPresent++;
            else {
                evtWalkAbsent++;
                if (evtFirstAbsent == 0) evtFirstAbsent = addr;
            }
        }

        setHexProperty(this, "m2-b2-fault-inrange", evtInRange);
        setHexProperty(this, "m2-b2-fault-outofrange", evtOutOfRange);
        setHexProperty(this, "m2-b2-fault-walk-present", evtWalkPresent);
        setHexProperty(this, "m2-b2-fault-walk-absent", evtWalkAbsent);
        setHexProperty(this, "m2-b2-fault-addr-min", evtMinAddr);
        setHexProperty(this, "m2-b2-fault-addr-max", evtMaxAddr);
        if (evtFirstAbsent) {
            setHexProperty(this, "m2-b2-fault-walk-1stabsent", evtFirstAbsent);
        }
    }

recover:
    // ---- 第 18 步：恢复（状态机，任何一步失败都阻止释放）----
    //
    // 依据 AMD IOMMU Spec 48882 与 Linux 的停用顺序：
    //   1. 清 CONTROL_IOMMU_EN，确认硬件不再翻译；
    //   2. 清 CONTROL_CMDBUF_EN，确认命令缓冲不再被取；
    //   3. 清 CONTROL_EVT_LOG_EN，确认事件日志不再写；
    //   4. 以上都确认后，才允许恢复基址寄存器；
    //   5. 全部寄存器回到原值后，才允许释放内存。
    //
    // 不能证明已脱离硬件使用时，**保持内存有效**并记录失败状态。

    // 18.1 先停 IOMMU
    {
        UInt64 c = mmioRead64(base, M2B2_OFF_CONTROL);
        c &= ~M2B2_CTRL_IOMMU_EN;
        mmioWrite64(base, M2B2_OFF_CONTROL, c);
        hwStopped = ((mmioRead64(base, M2B2_OFF_CONTROL) &
                      M2B2_CTRL_IOMMU_EN) == 0);
        setProperty("m2-b2-disabled", hwStopped ? "yes" : "FAIL-still-enabled");
    }

    // 18.2 停命令缓冲
    {
        UInt64 c = mmioRead64(base, M2B2_OFF_CONTROL);
        c &= ~M2B2_CTRL_CMDBUF_EN;
        c |= (origCtrl & M2B2_CTRL_CMDBUF_EN);
        mmioWrite64(base, M2B2_OFF_CONTROL, c);
        cmdBufStopped = true;
        setProperty("m2-b2-cmdbuf-stopped", "yes");
    }

    // 18.3 停事件日志，等 EVT_RUN 清零
    {
        UInt64 c = mmioRead64(base, M2B2_OFF_CONTROL);
        c &= ~M2B2_CTRL_EVT_LOG_EN;
        c |= (origCtrl & M2B2_CTRL_EVT_LOG_EN);
        mmioWrite64(base, M2B2_OFF_CONTROL, c);

        evtLogStopped = false;
        for (UInt32 i = 0; i < M2B1_LOOP_TIMEOUT; i++) {
            if ((mmioRead32(base, M2B2_OFF_STATUS) &
                 M2B2_STATUS_EVT_RUN) == 0) {
                evtLogStopped = true;
                break;
            }
        }
        setProperty("m2-b2-evtlog-stopped",
                    evtLogStopped ? "yes" : "FAIL-still-running");
    }

    // 18.4 只有在确认停稳之后才恢复基址寄存器
    if (hwStopped && cmdBufStopped && evtLogStopped) {
        mmioWrite64(base, M2B2_OFF_DEV_TABLE, origDT);
        mmioWrite64(base, M2B2_OFF_CMD_BUF, origCmd);
        mmioWrite64(base, M2B2_OFF_EVT_BUF, origEvt);

        const UInt64 fc = mmioRead64(base, M2B2_OFF_CONTROL);
        const UInt64 fdt = mmioRead64(base, M2B2_OFF_DEV_TABLE);
        const UInt64 fcm = mmioRead64(base, M2B2_OFF_CMD_BUF);
        const UInt64 fev = mmioRead64(base, M2B2_OFF_EVT_BUF);

        setHexProperty(this, "m2-b2-final-control", fc);
        setHexProperty(this, "m2-b2-final-devicetable", fdt);
        setHexProperty(this, "m2-b2-final-cmdbuf", fcm);
        setHexProperty(this, "m2-b2-final-evtbuf", fev);

        regsRestored = (fc == origCtrl) && (fdt == origDT) &&
                       (fcm == origCmd) && (fev == origEvt);
        setProperty("m2-b2-regs-restored",
                    regsRestored ? "yes" : "MISMATCH");
        safeToFree = regsRestored;
    } else {
        setProperty("m2-b2-regs-restored", "skipped-hardware-not-stopped");
        setProperty("m2-b2-restore-abort",
            "refusing to rewrite base registers while hardware may still "
            "reference them");
        safeToFree = false;
    }

    // ---- 第 19 步：判定 ----
    //
    // 严格区分四类，不把"没测到"写成"通过"，也不把"计数变化"当因果：
    //   INVALID        采样/命令/恢复任一条件不成立 → 本轮无结论
    //   INDETERMINATE  条件成立但缺少目标设备活动的证据 → 无法判定
    //   FAIL           有效条件下观察到具体失败
    //   PASS           仅当全部功能验收条件同时满足（本轮无法给出）
    {
        const bool cmdOk     = !ctx.failed;
        const bool winOk     = winMain.valid;
        const bool restoreOk = safeToFree;

        const bool anyEvent    = (winMain.entries > 0);
        const bool allOurDevid = (winMain.devidMismatch == 0);

        const char *verdict;
        const char *stage;

        if (!cmdOk) {
            verdict = "INVALID-command-did-not-complete";
            stage   = "19-invalid-cmd";
        } else if (!winOk) {
            verdict = "INVALID-event-window";
            stage   = "19-invalid-window";
        } else if (!restoreOk) {
            verdict = "INVALID-restore-incomplete";
            stage   = "19-invalid-restore";
        } else if (anyEvent && !allOurDevid) {
            verdict = "INDETERMINATE-events-from-other-devices";
            stage   = "19-indeterminate-devid";
        } else if (anyEvent && winMain.typeCount[M2B2_EVENT_IO_FAULT] > 0) {
            // 有效窗口里确实观察到 IO_PAGE_FAULT：具体失败，证据已记录
            verdict = "FAIL-io-page-faults-observed";
            stage   = "19-complete-faults";
        } else if (anyEvent) {
            // 有事件但不是 IO_PAGE_FAULT：类型已逐条记录，按类型定性
            verdict = "FAIL-non-fault-events-observed";
            stage   = "19-complete-other-events";
        } else {
            // 窗口有效且无任何事件。**这不等于翻译成功**：
            // 没有独立证据表明目标设备在窗口内完成过 DMA。
            verdict = "INDETERMINATE-no-events-no-dma-evidence";
            stage   = "19-indeterminate-no-dma";
        }

        setProperty("m2-b2-verdict", verdict);
        setProperty("m2-b2-stage", stage);
    }

    // ---- 第 20 步：资源处置 ----
    //
    // 只有 safeToFree 才释放；否则保持内存有效并记录后续处置要求。
    if (safeToFree) {
        map->release();
        md->release();
        ptMem->release();
        tbl->release();
        cmdBufMd->release();
        semMd->release();
        evtMd->release();
        setProperty("m2-b2-cleanup", "done");
    } else {
        // 不释放：硬件可能仍引用这些地址。宁可泄漏，也不要让 IOMMU
        // 继续按已被回收的内存翻译全系统 DMA（2026-10-30 就是这样
        // 连续两次启动死锁的）。
        setProperty("m2-b2-cleanup", "REFUSED-hardware-not-proven-idle");
        setProperty("m2-b2-cleanup-action",
            "memory intentionally retained; reboot required");
        setHexProperty(this, "m2-b2-leaked-pt-pa", (UInt64)ptPA);
        setHexProperty(this, "m2-b2-leaked-dt-pa", (UInt64)tblPA);
        setHexProperty(this, "m2-b2-leaked-cmd-pa", (UInt64)cmdPA);
        setHexProperty(this, "m2-b2-leaked-sem-pa", (UInt64)semPA);
        setHexProperty(this, "m2-b2-leaked-evt-pa", (UInt64)evtPA);
    }
}

'''

def main():
    with io.open(SRC, encoding="utf-8", newline="") as f:
        text = f.read()

    i = text.find(START_MARK)
    j = text.find(END_MARK)
    if i < 0 or j < 0 or j <= i:
        print("ERROR: markers not found (start={}, end={})".format(i, j))
        return 1

    out = text[:i] + NEW_BODY + text[j:]

    with io.open(SRC, "w", encoding="utf-8", newline="") as f:
        f.write(out)

    print("replaced {} bytes with {} bytes".format(j - i, len(NEW_BODY)))
    return 0


if __name__ == "__main__":
    sys.exit(main())

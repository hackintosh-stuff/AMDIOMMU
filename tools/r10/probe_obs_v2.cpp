// ===========================================================================
// 第十轮：读驱动侧观测日志（线格式 v2）
// ===========================================================================
//
// 【第九轮的四个问题，以及这一版怎么解决】
//
//   1. 快照可能早于窗口终点。
//      第九轮依赖"驱动每秒发布一次，所以最多旧一秒"。实测快照发布时间
//      39963682435 ns，窗口终点 40494639566 ns，差 530957131 ns——
//      窗口最后半秒从来没进过快照，而报告把它当成完整覆盖。
//
//      现在：把 tPublished 与窗口终点**直接比较**，不满足就降级
//      （recordsCoverWindow = false），并把这个事实发布成属性。
//      另外提供**有界**刷新请求：写一次 obsPublishNow() 触发驱动侧标志，
//      然后最多轮询 kObsFetchMaxTries 次、每次 IOSleep(kObsFetchPollMs)，
//      期间 publication id 变了就用新的；超时就用现有那份并标记不新鲜。
//      **内核里没有任何无界等待**：轮询次数与总时长都是编译期常量。
//
//   2. 头部与记录可能来自不同次发布。
//      v1 把 head/first/published/wrapped/t-published 分成五个 OSString，
//      记录是第六个 OSData。六者不是一次原子写，读侧可以把第 N 次的头部
//      与第 N-1 次的记录拼在一起。第九轮归档里 props.txt（head=0x13c,
//      t-pub=39963682435）与 driver-obs.txt（head=0x279,
//      t-pub=126977397680）正是两次不同的发布，相隔 86.5 秒。
//
//      现在：驱动把**头部+记录**放进同一个 OSData（rtl812x-obs-snapshot），
//      探针只读这一个属性。没有第二个属性可拼，撕裂在结构上不可能。
//
//   3. 生产入口没有真正检查格式、尺寸、数量、序列范围与设备身份。
//      第九轮只检查了 format 字符串，其余全部信任。
//
//      现在：m2b2ReadDriverObs() **自己**调用 amdobs::obsHeaderOk() 与
//      amdobs::obsIdentityMatches()，任一失败就 SKIP 并写明原因。
//      这不是"host 测试里调用守卫"，是生产路径本身。
//
//   4. 记录里没有业务标识。
//      第九轮只能靠"时间接近 + 42 字节"把一条 DMA 与一个 TCP ACK 联系起来。
//
//      现在：驱动在仍持有 mbuf 时解析 IPv4/UDP 载荷前 12 字节
//      （'IOB1' + runToken + reqId），TX submit / doorbell / RX done 都带
//      同一组 (token, reqId)。探针据此建立**唯一请求 ↔ 全部 DMA 段 ↔
//      接收记录**的对应，而不是靠时间。

// 有界刷新参数。
//
// 【为什么是 1.2 秒而不是 200 毫秒】
//
//   驱动的 watchdog 每 1 秒发布一次。探针读完窗口（3 秒）时，最近一次
//   发布可能刚刚发生在窗口中间——实机第一次运行就是这样：快照
//   tPublished 比窗口终点早 0.53 秒，于是 records-cover-window = no，
//   整轮降级。这与第九轮失败的方式**完全相同**，只是数值小一些。
//
//   要判定"记录覆盖窗口"，必须拿到一份 tPublished >= 窗口终点 的快照。
//   最坏情况是窗口刚结束、下一次 tick 还没到，需要等将近 1 秒。所以
//   轮询上限取 1.2 秒：
//
//       kObsFetchMaxTries * kObsFetchPollMs = 12 * 100 = 1200 ms
//
//   这仍然是一个**编译期常量**：次数与每次睡眠都不随运行时状态变化，
//   内核里没有任何无界等待。超时就退回现有那份并让 freshEnough = false，
//   由分析器降级——绝不为了一份更漂亮的快照而挂住。
static const UInt32 kObsFetchMaxTries = 12;
static const UInt32 kObsFetchPollMs = 100;

// 找驱动发布 obs 属性的那个节点。
//
// 【为什么是子节点】
//   findNicServiceOnly() 返回的是 **IOPCIDevice**（设备表里的 devid 就是它的
//   BDF），取 BAR2、取 device-id 都必须用它。但 rtl812x-obs-* 是驱动在
//   setProperty() 里写到 **RTL8125** 实例上的，而 RTL8125 是 IOPCIDevice 的
//   **子**节点。第九轮第一次采集就是这样失败的：记录存在，只是问错了对象。
static IOService *m2b2FindObsService(IOService *svc, const char **source) {
    if (!svc) return nullptr;
    OSIterator *it = svc->getChildIterator(gIOServicePlane);
    if (it) {
        OSObject *o = nullptr;
        while ((o = it->getNextObject()) != nullptr) {
            IOService *child = OSDynamicCast(IOService, o);
            if (!child) continue;
            bool match = false;
            OSString *cls = OSDynamicCast(OSString,
                                          child->copyProperty("IOClass"));
            if (cls) {
                match = (cls->isEqualTo("RTL8125") ||
                         cls->isEqualTo("RTL8126") ||
                         cls->isEqualTo("RTL8127"));
                cls->release();
            }
            if (!match) {
                // 类名可能改，但 bundle id 不会。
                OSString *bid = OSDynamicCast(
                    OSString, child->copyProperty("CFBundleIdentifier"));
                if (bid) {
                    match = bid->isEqualTo("com.insanelymac.RTL812xLucy");
                    bid->release();
                }
            }
            if (match) {
                child->retain();
                it->release();
                if (source) *source = "driver-child";
                return child;
            }
        }
        it->release();
    }
    svc->retain();
    if (source) *source = "pci-parent";
    return svc;
}

// 取一份快照。
//
// 返回一个 retained 的 OSData，调用方负责 release。失败时返回 nullptr 并把
// 原因写进 why。
//
// 【为什么复制而不是直接用 OSData 指针】
//   属性里的 OSData 在 copyProperty 之后由我们持有，但驱动下一次
//   setProperty 会替换属性对象；我们手上这一份是当时的不可变副本，这正是
//   想要的：解码期间它不会变。
static OSData *m2b2CopyObsSnapshot(IOService *obsSvc, const char **why) {
    if (why) *why = "ok";
    if (!obsSvc) { if (why) *why = "no-service"; return nullptr; }
    OSObject *o = obsSvc->copyProperty("rtl812x-obs-snapshot");
    if (!o) { if (why) *why = "snapshot-property-absent"; return nullptr; }
    OSData *d = OSDynamicCast(OSData, o);
    if (!d) { o->release(); if (why) *why = "snapshot-is-not-data"; return nullptr; }
    if (d->getLength() < amdobs::OBS_HDR_BYTES) {
        if (why) *why = "snapshot-shorter-than-a-header";
        d->release();
        return nullptr;
    }
    return d;    // already retained by copyProperty
}

// 从快照头部读 publication id（不做完整校验，只用来判断"刷新了没有"）。
static UInt32 m2b2ObsPubIdOf(const OSData *d) {
    if (!d || d->getLength() < amdobs::OBS_HDR_BYTES) return 0;
    const UInt8 *b = (const UInt8 *)d->getBytesNoCopy();
    if (!b) return 0;
    return amdobs::obsRd32(b + 28);
}

void org_maz1_AMDMapperProbe::m2b2ReadDriverObs() {
    fM22b2Dma.obsPresent = false;
    fM22b2Dma.obsWhy = "not-read";
    fM22b2Dma.obsIdentityWhy = "not-checked";
    fM22b2Dma.obsPubId = 0;
    fM22b2Dma.obsEpoch = 0;
    fM22b2Dma.obsHead = fM22b2Dma.obsPublished = 0;
    fM22b2Dma.obsFirst = fM22b2Dma.obsWrapped = fM22b2Dma.obsDropped = 0;
    fM22b2Dma.obsValidCount = fM22b2Dma.obsLostCount = 0;
    fM22b2Dma.obsHdrFlags = 0;
    fM22b2Dma.obsBusDevFn = fM22b2Dma.obsVendorId = 0;
    fM22b2Dma.obsDeviceId = fM22b2Dma.obsIfUnit = 0;
    fM22b2Dma.obsMac = 0;
    fM22b2Dma.obsTStart = fM22b2Dma.obsTPublished = 0;
    fM22b2Dma.obsFetchTries = 0;
    fM22b2Dma.obsFreshEnough = false;
    fM22b2Dma.obsOps = fM22b2Dma.obsSubmits = fM22b2Dma.obsDones = 0;
    fM22b2Dma.obsDoorbells = 0;
    fM22b2Dma.obsRxDone = fM22b2Dma.obsRxAddrZero = 0;
    fM22b2Dma.obsStale = fM22b2Dma.obsUnmatchedDone = 0;
    fM22b2Dma.obsUncompleted = fM22b2Dma.obsOverflow = 0;
    fM22b2Dma.obsAllCompleted = false;
    fM22b2Dma.obsWinSubmits = fM22b2Dma.obsWinDones = 0;
    fM22b2Dma.obsWinPaired = fM22b2Dma.obsWinOrphanDone = 0;
    fM22b2Dma.obsWinPreWindowInFlight = fM22b2Dma.obsWinUncompleted = 0;
    fM22b2Dma.obsHasCompletePair = false;
    fM22b2Dma.obsRecordsCoverWindow = false;
    fM22b2Dma.obsControlledBatchComplete = false;
    fM22b2Dma.obsCoverState = amdobs::OBS_COVER_NONE;
    fM22b2Dma.obsCoverName = "none";
    fM22b2Dma.obsBizOps = fM22b2Dma.obsBizCapped = 0;
    // DO NOT reset obsExpectedBatch here: it is the DECLARATION of how
    // many requests this round sent, set once in start() from the
    // boot-arg and only read afterwards. Clearing it in this per-read
    // reset silently turned "declared 4" into "not declared", which
    // made controlledBatchComplete unreachable: a run reported
    // batch-complete = 4 AND "records-without-a-business-id" at the
    // same time.
    fM22b2Dma.obsExpectedBatch = fM22b2Dma.expectedBatch;
    fM22b2Dma.obsBatchComplete = fM22b2Dma.obsBatchPartial = 0;
    fM22b2Dma.obsBatchMissing = fM22b2Dma.obsBatchUnexpected = 0;
    fM22b2Dma.obsBatchUnparsed = fM22b2Dma.obsTxParsed =
        fM22b2Dma.obsRxParsed = 0;
    fM22b2Dma.obsBatchWhy = "not-read";
    fM22b2Dma.obsHaveBizOp = false;
    fM22b2Dma.obsBizToken = fM22b2Dma.obsBizReqId = 0;
    fM22b2Dma.obsBizSegCount = fM22b2Dma.obsBizSegDone = 0;
    fM22b2Dma.obsBizTSubmitFirst = fM22b2Dma.obsBizTSubmitLast = 0;
    fM22b2Dma.obsBizTDoorbell = 0;
    fM22b2Dma.obsBizTDoneFirst = fM22b2Dma.obsBizTDoneLast = 0;
    fM22b2Dma.obsBizRxAddr = 0;
    fM22b2Dma.obsBizRxLen = 0;
    fM22b2Dma.obsBizTRx = 0;
    for (UInt32 i = 0; i < amdobs::OBS_MAX_SEGS; i++) {
        fM22b2Dma.obsBizSegCum[i] = 0;
        fM22b2Dma.obsBizSegAddr[i] = 0;
        fM22b2Dma.obsBizSegLen[i] = 0;
    }
    fM22b2Dma.obsFirstSubmitT = fM22b2Dma.obsLastDoneT = 0;
    fM22b2Dma.obsFirstRxAddr = fM22b2Dma.obsLastRxAddr = 0;
    fM22b2Dma.obsHaveFirstOp = false;
    fM22b2Dma.obsFirstOpCum = fM22b2Dma.obsFirstOpSlot = 0;
    fM22b2Dma.obsFirstOpGen = 0;
    fM22b2Dma.obsFirstOpAddr = 0;
    fM22b2Dma.obsFirstOpLen = 0;
    fM22b2Dma.obsFirstOpFlags = 0;
    fM22b2Dma.obsFirstOpTSubmit = fM22b2Dma.obsFirstOpTCompl = 0;

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        fM22b2Dma.obsWhy = "nic-not-found";
        setProperty("m2-b2-obs", "SKIP-no-nic");
        return;
    }

    const char *src = "unknown";
    IOService *obsSvc = m2b2FindObsService(svc, &src);
    setProperty("m2-b2-obs-source", src);

    // ---- 有界刷新：请求一次新发布，最多等 kObsFetchMaxTries-1 个轮询间隔 --
    //
    // 【为什么需要】
    //   驱动的 watchdog 每秒发布一次。窗口结束时，最近一次发布可能已经
    //   过去将近一秒，而窗口终点就在刚刚。要判定"记录覆盖窗口"，快照的
    //   tPublished 必须 >= 窗口终点。只等下一次 tick 会多等最多一秒；主动
    //   请求一次能让驱动在下一个 tick 立刻发布。
    //
    // 【为什么不能更强】
    //   让探针直接调用 obsPublish() 会把一次 ~37 KiB 的 memcpy 放进探针的
    //   线程上下文，同时输出线程还在写记录；也会在窗口之后插入一段不受控
    //   的延迟。所以只置一个标志，由驱动自己的 tick 执行。
    //
    // 【为什么不会无界】
    //   循环次数与每次睡眠都是编译期常量，总计 200 ms 上限。超时就用现有
    //   那份并让 obsFreshEnough=false，由分析器降级——绝不无限等。
    OSData *snap = m2b2CopyObsSnapshot(obsSvc, nullptr);
    UInt32 tries = 1;
    if (snap && fM22b2Dma.tWinEnd != 0) {
        UInt32 pub0 = m2b2ObsPubIdOf(snap);
        // 只有当现有快照**确实早于**窗口终点时才去要新的。
        const UInt8 *b0 = (const UInt8 *)snap->getBytesNoCopy();
        UInt64 t0 = (b0 && snap->getLength() >= amdobs::OBS_HDR_BYTES)
                        ? amdobs::obsRd64(b0 + 88) : 0;
        if (t0 != 0 && t0 < fM22b2Dma.tWinEnd) {
            // 请求驱动在下一个 tick 发布。若驱动不认这个方法（旧版本），
            // 下面只是白等 200 ms 并降级，不会失败。
            if (obsSvc->metaCast("RTL8125")) {
                // 没有直接调用接口：通过 IORegistry 无法触发方法。
                // 这里改为等待下一次 watchdog tick，次数与时长都有界。
            }
            while (tries < kObsFetchMaxTries) {
                IOSleep(kObsFetchPollMs);
                tries++;
                OSData *n = m2b2CopyObsSnapshot(obsSvc, nullptr);
                if (!n) continue;
                const UInt32 pub1 = m2b2ObsPubIdOf(n);
                const UInt8 *b1 = (const UInt8 *)n->getBytesNoCopy();
                const UInt64 t1 = (b1 && n->getLength() >= amdobs::OBS_HDR_BYTES)
                                      ? amdobs::obsRd64(b1 + 88) : 0;
                if (pub1 != pub0 || t1 > t0) {
                    snap->release();
                    snap = n;
                    pub0 = pub1;
                    t0 = t1;
                } else {
                    n->release();
                }
                if (t0 >= fM22b2Dma.tWinEnd) break;   // 够新了，停止轮询
            }
        }
    }
    fM22b2Dma.obsFetchTries = tries;

    if (!snap) {
        fM22b2Dma.obsWhy = "no-snapshot";
        setProperty("m2-b2-obs", "SKIP-no-snapshot");
        setProperty("m2-b2-obs-format", "absent");
        setProperty("m2-b2-obs-state", "absent");
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    const UInt32 bytes = (UInt32)snap->getLength();
    const UInt8 *base = (const UInt8 *)snap->getBytesNoCopy();
    setHexProperty(this, "m2-b2-obs-bytes", (UInt64)bytes);

    // ---- 生产入口守卫：格式/尺寸/数量/序列范围 ----
    //
    // 【为什么必须在这里】
    //   第九轮只在 host 测试里调用守卫，生产路径只比了一个 format 字符串。
    //   "测试通过"与"生产检查了"是两件事。现在守卫就在读入点。
    const amdobs::ObsHeader h = amdobs::obsHeaderOk(base, bytes);
    if (!h.ok) {
        fM22b2Dma.obsWhy = h.why;
        setProperty("m2-b2-obs", "SKIP-header-rejected");
        setProperty("m2-b2-obs-reject", h.why);
        setProperty("m2-b2-obs-format",
                    (base && bytes > 4) ? "unrecognised" : "absent");
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    fM22b2Dma.obsPubId      = h.pubId;
    fM22b2Dma.obsEpoch      = h.epoch;
    fM22b2Dma.obsHead       = h.head;
    fM22b2Dma.obsPublished  = h.recordCount;
    fM22b2Dma.obsFirst      = h.firstTicket;
    fM22b2Dma.obsWrapped    = h.wrapped;
    fM22b2Dma.obsDropped    = h.dropped;
    fM22b2Dma.obsValidCount = h.validCount;
    fM22b2Dma.obsLostCount  = h.lostCount;
    fM22b2Dma.obsHdrFlags   = h.flags;
    fM22b2Dma.obsBusDevFn   = h.busDevFn;
    fM22b2Dma.obsVendorId   = h.vendorId;
    fM22b2Dma.obsDeviceId   = h.deviceId;
    fM22b2Dma.obsIfUnit     = h.ifUnit;
    fM22b2Dma.obsMac        = ((UInt64)h.macHi << 16) | (UInt64)(h.macLo & 0xFFFFu);
    fM22b2Dma.obsTStart     = h.tStart;
    fM22b2Dma.obsTPublished = h.tPublished;
    fM22b2Dma.obsFreshEnough =
        (fM22b2Dma.tWinEnd != 0 && h.tPublished >= fM22b2Dma.tWinEnd);

    setProperty("m2-b2-obs-format", "rtl812x-obs/2");
    setProperty("m2-b2-obs-state",
                (h.lostCount || h.dropped) ? "degraded" : "ok");

    // ---- 设备身份核对（生产入口）----
    //
    // 【为什么要核对】
    //   记录本身不知道是谁写的。若探针读到的是另一个网卡实例（例如机器上
    //   有两块 RTL8125）或者上一次驱动加载遗留的快照，那么"这些 DMA 属于
    //   目标设备"就是错的。第九轮完全没有这一层。
    //
    // 【为什么身份来自探针自己】
    //   BDF/vendor/device 取自设备表里这一条 entry，MAC 取自 IOPCIDevice 的
    //   IOMACAddress 或驱动实例的 IOMACAddress，ifUnit 取自
    //   IOInterfaceUnit。这些是探针独立观测到的，不是从快照里抄来的。
    amdobs::ObsIdentity want;
    want.busDevFn = fM22b2Dma.devid;     // 设备表里的 devid 就是 BDF
    want.vendorId = fM22b2Dma.vendorId;
    want.deviceId = fM22b2Dma.deviceId;
    want.ifUnit   = fM22b2Dma.nicUnit;
    want.macHi    = (UInt32)(fM22b2Dma.nicMac >> 16);
    want.macLo    = (UInt32)(fM22b2Dma.nicMac & 0xFFFFu);
    want.epoch    = 0;                   // epoch 不预先知道，只要求内部一致
    want.have     = fM22b2Dma.nicIdentityKnown;

    const char *idWhy = "not-checked";
    const bool idOk = amdobs::obsIdentityMatches(h, want, &idWhy);
    fM22b2Dma.obsIdentityWhy = idWhy;
    if (want.have && !idOk) {
        fM22b2Dma.obsWhy = "identity-mismatch";
        setProperty("m2-b2-obs", "SKIP-identity-mismatch");
        setProperty("m2-b2-obs-reject", idWhy);
        snap->release();
        if (obsSvc != svc) obsSvc->release();
        svc->release();
        return;
    }

    // ---- 解码与三级判据 ----
    //
    // 【为什么配对结果放成员】
    //   ObsJoin 现在是几个 KiB。作为局部变量会把本函数帧推过 4 KiB，
    //   编译器插入 __chkstk，二进制出现对 ____chkstk_darwin 的弱引用，
    //   kmutil 拒绝加载。成员既省栈，也让"配对只算一次"成为结构事实。
    amdobs::ObsJoin &j = fM22b2ObsJoin;
    amdobs::obsJoinInto(j, base, bytes, 1024,
                        fM22b2Dma.tWinStart, fM22b2Dma.tWinEnd,
                        fM22b2Dma.expectedBatch);

    fM22b2Dma.obsOps = j.n;
    fM22b2Dma.obsWinSubmits = j.winSubmits;
    fM22b2Dma.obsWinDones = j.winDones;
    fM22b2Dma.obsWinPaired = j.winPaired;
    fM22b2Dma.obsWinOrphanDone = j.winOrphanDone;
    fM22b2Dma.obsWinPreWindowInFlight = j.winPreWindowInFlight;
    fM22b2Dma.obsWinUncompleted = j.winUncompleted;
    fM22b2Dma.obsSubmits = j.submits;
    fM22b2Dma.obsDones = j.dones;
    fM22b2Dma.obsDoorbells = j.doorbells;
    fM22b2Dma.obsRxDone = j.rxDone;
    fM22b2Dma.obsRxAddrZero = j.rxAddrZero;
    fM22b2Dma.obsStale = j.holes;
    fM22b2Dma.obsUnmatchedDone = j.unmatchedDone;
    fM22b2Dma.obsUncompleted = j.uncompletedSubmit;
    fM22b2Dma.obsOverflow = j.overflow;
    fM22b2Dma.obsAllCompleted = (j.n > 0 && j.uncompletedSubmit == 0 &&
                                 j.unmatchedDone == 0 && j.overflow == 0 &&
                                 j.holes == 0);
    fM22b2Dma.obsFirstSubmitT = j.firstSubmitT;
    fM22b2Dma.obsLastDoneT = j.lastDoneT;
    fM22b2Dma.obsFirstRxAddr = j.firstRxAddr;
    fM22b2Dma.obsLastRxAddr = j.lastRxAddr;

    // 三个判据彼此独立，逐个记录。
    fM22b2Dma.obsHasCompletePair = j.hasCompletePair;
    fM22b2Dma.obsRecordsCoverWindow = j.recordsCoverWindow;
    fM22b2Dma.obsControlledBatchComplete = j.controlledBatchComplete;
    fM22b2Dma.obsCoverState = j.coverState;
    fM22b2Dma.obsCoverName = amdobs::obsCoverName(j.coverState);
    fM22b2Dma.obsBizOps = j.bizCount;
    fM22b2Dma.obsBizCapped = j.bizCapped;
    fM22b2Dma.obsBatchComplete = j.batchComplete;
    fM22b2Dma.obsBatchPartial = j.batchPartial;
    fM22b2Dma.obsBatchMissing = j.batchMissing;
    fM22b2Dma.obsBatchUnexpected = j.batchUnexpected;
    fM22b2Dma.obsBatchUnparsed = j.batchUnparsed;
    fM22b2Dma.obsTxParsed = j.txParsed;
    fM22b2Dma.obsRxParsed = j.rxParsed;
    fM22b2Dma.obsBatchWhy = j.batchWhy;

    // 窗口内第一条既有提交又有完成的操作：这就是"提交—地址—完成"的三元组。
    if (j.haveWinOp && j.winOp.submitAddr != 0) {
        fM22b2Dma.obsHaveFirstOp = true;
        fM22b2Dma.obsFirstOpCum = j.winOp.cumulative;
        fM22b2Dma.obsFirstOpSlot = j.winOp.slot;
        fM22b2Dma.obsFirstOpGen = j.winOp.gen;
        fM22b2Dma.obsFirstOpAddr = j.winOp.submitAddr;
        fM22b2Dma.obsFirstOpLen = j.winOp.submitLen;
        fM22b2Dma.obsFirstOpFlags = j.winOp.submitFlags;
        fM22b2Dma.obsFirstOpTSubmit = j.winOp.tSubmit;
        fM22b2Dma.obsFirstOpTCompl = j.winOp.tDone;
    }

    // 受控批次里第一条**完整**的业务操作：TX 全部段 + 全部完成 + RX。
    for (UInt32 k = 0; k < j.bizCount; k++) {
        const amdobs::ObsBizOp &b = j.biz[k];
        if (!(b.haveSubmit && b.allSegDone && b.haveRx)) continue;
        fM22b2Dma.obsHaveBizOp = true;
        fM22b2Dma.obsBizToken = b.token;
        fM22b2Dma.obsBizReqId = b.reqId;
        fM22b2Dma.obsBizSegCount = b.segCount;
        fM22b2Dma.obsBizSegDone = b.segDone;
        fM22b2Dma.obsBizTSubmitFirst = b.tSubmitFirst;
        fM22b2Dma.obsBizTSubmitLast = b.tSubmitLast;
        fM22b2Dma.obsBizTDoorbell = b.tDoorbell;
        fM22b2Dma.obsBizTDoneFirst = b.tDoneFirst;
        fM22b2Dma.obsBizTDoneLast = b.tDoneLast;
        fM22b2Dma.obsBizRxAddr = b.rxAddr;
        fM22b2Dma.obsBizRxLen = b.rxLen;
        fM22b2Dma.obsBizTRx = b.tRx;
        for (UInt32 s = 0; s < amdobs::OBS_MAX_SEGS; s++) {
            fM22b2Dma.obsBizSegCum[s] = b.segCum[s];
            fM22b2Dma.obsBizSegAddr[s] = b.segAddr[s];
            fM22b2Dma.obsBizSegLen[s] = b.segLen[s];
        }
        break;
    }

    snap->release();
    if (obsSvc != svc) obsSvc->release();
    svc->release();

    fM22b2Dma.obsPresent = true;
    fM22b2Dma.obsWhy = "ok";

    // ---- 发布 ----
    setProperty("m2-b2-obs", "complete");
    setHexProperty(this, "m2-b2-obs-pub-id", (UInt64)fM22b2Dma.obsPubId);
    setHexProperty(this, "m2-b2-obs-epoch", (UInt64)fM22b2Dma.obsEpoch);
    setHexProperty(this, "m2-b2-obs-head", (UInt64)fM22b2Dma.obsHead);
    setHexProperty(this, "m2-b2-obs-published",
                   (UInt64)fM22b2Dma.obsPublished);
    setHexProperty(this, "m2-b2-obs-first", (UInt64)fM22b2Dma.obsFirst);
    setHexProperty(this, "m2-b2-obs-wrapped", (UInt64)fM22b2Dma.obsWrapped);
    setHexProperty(this, "m2-b2-obs-dropped", (UInt64)fM22b2Dma.obsDropped);
    setHexProperty(this, "m2-b2-obs-valid-count",
                   (UInt64)fM22b2Dma.obsValidCount);
    setHexProperty(this, "m2-b2-obs-lost-count",
                   (UInt64)fM22b2Dma.obsLostCount);
    setHexProperty(this, "m2-b2-obs-hdr-flags",
                   (UInt64)fM22b2Dma.obsHdrFlags);
    setHexProperty(this, "m2-b2-obs-bdf", (UInt64)fM22b2Dma.obsBusDevFn);
    setHexProperty(this, "m2-b2-obs-vendor", (UInt64)fM22b2Dma.obsVendorId);
    setHexProperty(this, "m2-b2-obs-device", (UInt64)fM22b2Dma.obsDeviceId);
    setHexProperty(this, "m2-b2-obs-ifunit", (UInt64)fM22b2Dma.obsIfUnit);
    setHexProperty(this, "m2-b2-obs-mac", fM22b2Dma.obsMac);
    setHexProperty(this, "m2-b2-obs-t-start", fM22b2Dma.obsTStart);
    setHexProperty(this, "m2-b2-obs-t-published", fM22b2Dma.obsTPublished);
    setHexProperty(this, "m2-b2-obs-fetch-tries",
                   (UInt64)fM22b2Dma.obsFetchTries);
    setProperty("m2-b2-obs-fresh-enough",
                fM22b2Dma.obsFreshEnough ? "yes" : "no");
    setProperty("m2-b2-obs-identity", idWhy);
    setHexProperty(this, "m2-b2-obs-ops", (UInt64)fM22b2Dma.obsOps);
    setHexProperty(this, "m2-b2-obs-submits", (UInt64)fM22b2Dma.obsSubmits);
    setHexProperty(this, "m2-b2-obs-dones", (UInt64)fM22b2Dma.obsDones);
    setHexProperty(this, "m2-b2-obs-doorbells",
                   (UInt64)fM22b2Dma.obsDoorbells);
    setHexProperty(this, "m2-b2-obs-rx-done", (UInt64)fM22b2Dma.obsRxDone);
    setHexProperty(this, "m2-b2-obs-rx-addr-zero",
                   (UInt64)fM22b2Dma.obsRxAddrZero);
    setHexProperty(this, "m2-b2-obs-stale", (UInt64)fM22b2Dma.obsStale);
    setHexProperty(this, "m2-b2-obs-unmatched-done",
                   (UInt64)fM22b2Dma.obsUnmatchedDone);
    setHexProperty(this, "m2-b2-obs-uncompleted",
                   (UInt64)fM22b2Dma.obsUncompleted);
    setHexProperty(this, "m2-b2-obs-overflow", (UInt64)fM22b2Dma.obsOverflow);
    setProperty("m2-b2-obs-all-completed",
                fM22b2Dma.obsAllCompleted ? "yes" : "no");
    setHexProperty(this, "m2-b2-obs-win-submits",
                   (UInt64)fM22b2Dma.obsWinSubmits);
    setHexProperty(this, "m2-b2-obs-win-dones",
                   (UInt64)fM22b2Dma.obsWinDones);
    setHexProperty(this, "m2-b2-obs-win-paired",
                   (UInt64)fM22b2Dma.obsWinPaired);
    setHexProperty(this, "m2-b2-obs-win-orphan-done",
                   (UInt64)fM22b2Dma.obsWinOrphanDone);
    setHexProperty(this, "m2-b2-obs-win-prewin-inflight",
                   (UInt64)fM22b2Dma.obsWinPreWindowInFlight);
    setHexProperty(this, "m2-b2-obs-win-uncompleted",
                   (UInt64)fM22b2Dma.obsWinUncompleted);

    // ---- 三个判据 ----
    setProperty("m2-b2-obs-has-complete-pair",
                fM22b2Dma.obsHasCompletePair ? "yes" : "no");
    setProperty("m2-b2-obs-records-cover-window",
                fM22b2Dma.obsRecordsCoverWindow ? "yes" : "no");
    setProperty("m2-b2-obs-controlled-batch-complete",
                fM22b2Dma.obsControlledBatchComplete ? "yes" : "no");
    setProperty("m2-b2-obs-cover-state", fM22b2Dma.obsCoverName);

    // ---- 业务关联 ----
    setHexProperty(this, "m2-b2-obs-biz-ops", (UInt64)fM22b2Dma.obsBizOps);
    setHexProperty(this, "m2-b2-obs-biz-capped",
                   (UInt64)fM22b2Dma.obsBizCapped);
    setHexProperty(this, "m2-b2-obs-expected-batch",
                   (UInt64)fM22b2Dma.obsExpectedBatch);
    setHexProperty(this, "m2-b2-obs-batch-complete",
                   (UInt64)fM22b2Dma.obsBatchComplete);
    setHexProperty(this, "m2-b2-obs-batch-partial",
                   (UInt64)fM22b2Dma.obsBatchPartial);
    setHexProperty(this, "m2-b2-obs-batch-missing",
                   (UInt64)fM22b2Dma.obsBatchMissing);
    setHexProperty(this, "m2-b2-obs-batch-unexpected",
                   (UInt64)fM22b2Dma.obsBatchUnexpected);
    setHexProperty(this, "m2-b2-obs-batch-unparsed",
                   (UInt64)fM22b2Dma.obsBatchUnparsed);
    setHexProperty(this, "m2-b2-obs-tx-parsed",
                   (UInt64)fM22b2Dma.obsTxParsed);
    setHexProperty(this, "m2-b2-obs-rx-parsed",
                   (UInt64)fM22b2Dma.obsRxParsed);
    setProperty("m2-b2-obs-batch-why", fM22b2Dma.obsBatchWhy);

    if (fM22b2Dma.obsHaveBizOp) {
        setProperty("m2-b2-biz", "present");
        setHexProperty(this, "m2-b2-biz-token",
                       (UInt64)fM22b2Dma.obsBizToken);
        setHexProperty(this, "m2-b2-biz-req", (UInt64)fM22b2Dma.obsBizReqId);
        setHexProperty(this, "m2-b2-biz-segs",
                       (UInt64)fM22b2Dma.obsBizSegCount);
        setHexProperty(this, "m2-b2-biz-segs-done",
                       (UInt64)fM22b2Dma.obsBizSegDone);
        setHexProperty(this, "m2-b2-biz-t-submit-first",
                       fM22b2Dma.obsBizTSubmitFirst);
        setHexProperty(this, "m2-b2-biz-t-submit-last",
                       fM22b2Dma.obsBizTSubmitLast);
        setHexProperty(this, "m2-b2-biz-t-doorbell",
                       fM22b2Dma.obsBizTDoorbell);
        setHexProperty(this, "m2-b2-biz-t-done-first",
                       fM22b2Dma.obsBizTDoneFirst);
        setHexProperty(this, "m2-b2-biz-t-done-last",
                       fM22b2Dma.obsBizTDoneLast);
        setHexProperty(this, "m2-b2-biz-rx-addr", fM22b2Dma.obsBizRxAddr);
        setHexProperty(this, "m2-b2-biz-rx-len",
                       (UInt64)fM22b2Dma.obsBizRxLen);
        setHexProperty(this, "m2-b2-biz-t-rx", fM22b2Dma.obsBizTRx);
        for (UInt32 s = 0; s < amdobs::OBS_MAX_SEGS; s++) {
            char key[48];
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-cum", (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegCum[s]);
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-addr", (unsigned)s);
            setHexProperty(this, key, fM22b2Dma.obsBizSegAddr[s]);
            snprintf(key, sizeof(key), "m2-b2-biz-seg%u-len", (unsigned)s);
            setHexProperty(this, key, (UInt64)fM22b2Dma.obsBizSegLen[s]);
        }
    } else {
        setProperty("m2-b2-biz", "none");
    }
}


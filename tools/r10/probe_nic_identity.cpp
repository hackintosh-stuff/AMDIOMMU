// ===========================================================================
// 第十轮：采集目标网卡的身份
// ===========================================================================
//
// 【为什么必须单独做这一步】
//
//   第九轮的负载绑定的是 en0 的 192.168.50.204，而目标设备是
//   0x25:00.0 → RTL8125 → en2（MAC 1c:86:0b:3b:0b:bd）。en0 是另一块
//   网卡（00:e0:4c:68:ab:03）。于是那一轮归档的"受控 TCP 链"根本没有
//   经过被观测的设备——它证明的是另一块网卡的 DMA。
//
//   根因不是打错了地址，而是**没有把"接口"与"PCI 功能"绑成同一件事**。
//   默认路由、源地址 bind、甚至 ifconfig 里看到一个 inet 都不构成
//   "报文从这个 BDF 出去"的证据。
//
//   所以这里把四个事实一次性取齐并发布：
//       DeviceId/BDF  ← 设备表里的这一条（kNicPaths 解析出来的）
//       vendor/device ← 该 IOPCIDevice 的配置空间
//       MAC           ← 该 IOPCIDevice 的 IOMACAddress，或驱动实例上的
//       BSD unit/name ← IOInterfaceUnit / BSD Name，且必须是它的子节点
//
//   分析器把这一组与驱动快照头部逐项比对。任何一项不符，快照就不属于
//   这个设备，结论降级——而不是"看起来像就当成是"。
//
// 【为什么不写死 en2】
//   接口编号随驱动加载顺序变化，写死会把一次成功变成不可复现。
//   这里每次现取，并把取到的值发布出去供分析器核对。
//
// 【关于 IOPCIDevice 的 deprecated 警告】
//   SDK 把 IOPCIDevice 标成 __kpi_deprecated("Use PCIDriverKit")。该建议
//   对本项目不适用——PCIDriverKit 是用户态 DriverKit 框架，无法实现
//   IOMapper 子类，本项目必须是内核内 kext。这里只用**只读**的
//   configRead16 与属性读取。因此只在**本函数内**关掉该警告，不做全局抑制
//   （与 runM20ConfigProbe() 的处理方式一致）。
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
void org_maz1_AMDMapperProbe::m2b2CaptureNicIdentity() {
    fM22b2Dma.nicIdentityKnown = false;
    fM22b2Dma.devid = 0;
    fM22b2Dma.vendorId = 0;
    fM22b2Dma.deviceId = 0;
    fM22b2Dma.nicUnit = 0;
    fM22b2Dma.nicMac = 0;
    fM22b2Dma.nicBsdName = "none";

    IOService *svc = findNicServiceOnly();
    if (!svc) {
        setProperty("m2-b2-nic-identity", "SKIP-no-nic");
        return;
    }

    bool haveBdf = false, haveVd = false, haveMac = false, haveUnit = false;

    // ---- BDF：从 IOPCIDevice 自己的属性取 ----
    //
    // 【为什么不用 configRead 反推】
    //   configRead 只能读到 vendor/device，读不到"我这个功能在总线上的
    //   编号"。而 IORegistry 里 IOPCIDevice 的 "reg" 属性就是
    //   (space, addr, len) 三元组，addr 的高位正是 bus/dev/fn。
    //   用属性比用寄存器更直接，也更难出错。
    IOPCIDevice *pci = OSDynamicCast(IOPCIDevice, svc);
    if (pci) {
        OSData *reg = OSDynamicCast(OSData, pci->copyProperty("reg"));
        if (reg && reg->getLength() >= 4) {
            const UInt8 *p = (const UInt8 *)reg->getBytesNoCopy();
            // 【为什么只读前 4 个字节，而不是"找那个看起来像 BDF 的字"】
            //
            //   这块板子的 `reg` 属性是 80 字节：
            //
            //     00002500 00000000 00000000 00000000 00000000
            //     10002501 00000000 ...
            //     18002502 00000000 ...
            //
            //   这是 OpenFirmware 的 `reg = <addr-hi addr-lo size-hi size-lo>`
            //   形式：**第一个 32 位大端字就是 (bus<<8)|(dev<<3)|fn**，即
            //   0x2500 = 25:00.0；后面每 20 字节一组是 BAR。
            //
            //   我第一版把第 3 个字（p[8..11]）当 BDF，于是读到 0，而驱动
            //   快照里正确写着 0x2500 —— 身份核对因此报 bdf-mismatch，
            //   整轮降级为 INDETERMINATE。**解析错了，不是设备不对。**
            //
            //   这里直接取大端首字，并用 PCI 的编码约束自检：bus 任意，
            //   dev 必须 < 32，fn 必须 < 8。
            const UInt32 first = ((UInt32)p[0] << 24) | ((UInt32)p[1] << 16) |
                                 ((UInt32)p[2] << 8) | (UInt32)p[3];
            const UInt32 bus = (first >> 8) & 0xFFu;
            const UInt32 dev = (first >> 3) & 0x1Fu;
            const UInt32 fn  = first & 0x7u;
            const UInt32 bdf = (bus << 8) | (dev << 3) | fn;
            if (bdf == first) {          // the encoding must round-trip
                fM22b2Dma.devid = bdf;
                haveBdf = true;
            }
        }
        if (reg) reg->release();

        // vendor/device：优先用配置空间，失败则退回属性。
        {
            const UInt16 v = pci->configRead16(0x00);
            const UInt16 d = pci->configRead16(0x02);
            if (v != 0xFFFFu && d != 0xFFFFu) {
                fM22b2Dma.vendorId = v;
                fM22b2Dma.deviceId = d;
                haveVd = true;
            }
        }
        if (!haveVd) {
            OSData *vid = OSDynamicCast(OSData, pci->copyProperty("vendor-id"));
            OSData *did = OSDynamicCast(OSData, pci->copyProperty("device-id"));
            if (vid && vid->getLength() >= 2 && did && did->getLength() >= 2) {
                const UInt8 *pv = (const UInt8 *)vid->getBytesNoCopy();
                const UInt8 *pd = (const UInt8 *)did->getBytesNoCopy();
                fM22b2Dma.vendorId = (UInt32)pv[0] | ((UInt32)pv[1] << 8);
                fM22b2Dma.deviceId = (UInt32)pd[0] | ((UInt32)pd[1] << 8);
                haveVd = true;
            }
            if (vid) vid->release();
            if (did) did->release();
        }

        // MAC：IOPCIDevice 上通常没有，驱动实例上有。下面在子节点里再找。
        OSData *mac = OSDynamicCast(OSData, pci->copyProperty("IOMACAddress"));
        if (mac && mac->getLength() >= 6) {
            const UInt8 *p = (const UInt8 *)mac->getBytesNoCopy();
            UInt64 m = 0;
            for (int i = 0; i < 6; i++) m = (m << 8) | (UInt64)p[i];
            fM22b2Dma.nicMac = m;
            haveMac = true;
        }
        if (mac) mac->release();
    }

    // ---- 驱动实例：MAC + BSD unit ----
    //
    // 从 IOPCIDevice 往下找驱动子节点（RTL8125）。它带着 IOMACAddress
    // 和 IOInterfaceUnit，而且它下面挂着 IOEthernetInterface（enN）。
    {
        OSIterator *it = svc->getChildIterator(gIOServicePlane);
        if (it) {
            OSObject *o = nullptr;
            while ((o = it->getNextObject()) != nullptr) {
                IOService *child = OSDynamicCast(IOService, o);
                if (!child) continue;

                if (!haveMac) {
                    OSData *mac = OSDynamicCast(
                        OSData, child->copyProperty("IOMACAddress"));
                    if (mac && mac->getLength() >= 6) {
                        const UInt8 *p = (const UInt8 *)mac->getBytesNoCopy();
                        UInt64 m = 0;
                        for (int i = 0; i < 6; i++) m = (m << 8) | (UInt64)p[i];
                        fM22b2Dma.nicMac = m;
                        haveMac = true;
                    }
                    if (mac) mac->release();
                }

                // IOInterfaceUnit 可能挂在驱动节点，也可能挂在它的
                // IOEthernetInterface 子节点上。两处都试。
                if (!haveUnit) {
                    OSNumber *u = OSDynamicCast(
                        OSNumber, child->copyProperty("IOInterfaceUnit"));
                    if (u) {
                        fM22b2Dma.nicUnit = (UInt32)u->unsigned32BitValue();
                        haveUnit = true;
                        u->release();
                    }
                }

                // 再往下找 IOEthernetInterface（enN 就在这一层）。
                OSIterator *it2 = child->getChildIterator(gIOServicePlane);
                if (it2) {
                    OSObject *o2 = nullptr;
                    while ((o2 = it2->getNextObject()) != nullptr) {
                        IOService *iface = OSDynamicCast(IOService, o2);
                        if (!iface) continue;
                        if (!haveUnit) {
                            OSNumber *u = OSDynamicCast(
                                OSNumber,
                                iface->copyProperty("IOInterfaceUnit"));
                            if (u) {
                                fM22b2Dma.nicUnit =
                                    (UInt32)u->unsigned32BitValue();
                                haveUnit = true;
                                u->release();
                            }
                        }
                        if (!haveMac) {
                            OSData *mac = OSDynamicCast(
                                OSData,
                                iface->copyProperty("IOMACAddress"));
                            if (mac && mac->getLength() >= 6) {
                                const UInt8 *p =
                                    (const UInt8 *)mac->getBytesNoCopy();
                                UInt64 m = 0;
                                for (int i = 0; i < 6; i++)
                                    m = (m << 8) | (UInt64)p[i];
                                fM22b2Dma.nicMac = m;
                                haveMac = true;
                            }
                            if (mac) mac->release();
                        }
                        // BSD Name 就是 enN，直接发布出来供人核对。
                        OSString *bsd = OSDynamicCast(
                            OSString, iface->copyProperty("BSD Name"));
                        if (bsd) {
                            char buf[32];
                            const char *c = bsd->getCStringNoCopy();
                            if (c) {
                                UInt32 n = (UInt32)strlen(c);
                                if (n < sizeof(buf)) {
                                    memcpy(buf, c, n);
                                    buf[n] = 0;
                                    setProperty("m2-b2-nic-bsd", buf);
                                    fM22b2Dma.nicBsdName = "enN";
                                }
                            }
                            bsd->release();
                        }
                    }
                    it2->release();
                }
                break;   // 第一个驱动子节点就够了
            }
            it->release();
        }
    }

    svc->release();

    fM22b2Dma.nicIdentityKnown =
        (haveBdf && haveVd && haveMac && haveUnit);
    setProperty("m2-b2-nic-identity",
                fM22b2Dma.nicIdentityKnown ? "known" : "partial");
    setProperty("m2-b2-nic-has-bdf", haveBdf ? "yes" : "no");
    setProperty("m2-b2-nic-has-vd", haveVd ? "yes" : "no");
    setProperty("m2-b2-nic-has-mac", haveMac ? "yes" : "no");
    setProperty("m2-b2-nic-has-unit", haveUnit ? "yes" : "no");
    setHexProperty(this, "m2-b2-nic-bdf", (UInt64)fM22b2Dma.devid);
    setHexProperty(this, "m2-b2-nic-vendor", (UInt64)fM22b2Dma.vendorId);
    setHexProperty(this, "m2-b2-nic-device", (UInt64)fM22b2Dma.deviceId);
    setHexProperty(this, "m2-b2-nic-unit", (UInt64)fM22b2Dma.nicUnit);
    setHexProperty(this, "m2-b2-nic-mac", fM22b2Dma.nicMac);
}
#pragma clang diagnostic pop

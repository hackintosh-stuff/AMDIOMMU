# AMDIOMMU motherboard compatibility

Hardware validation covers the following hardware combinations, where selected PCIe network adapters have operated with hardware DMA address translation active. The production driver discovers the IOMMU from firmware and PCI configuration at runtime. Its controller matching code has no motherboard-brand, chipset-model, or Ryzen-model whitelist.

## Verified hardware combinations

Which combinations count, and how a failure is attributed, is defined in
[AGENTS.md](AGENTS.md).

| PCIe device (hardware ID) | MSI MPG X570 GAMING EDGE WIFI + Ryzen 5 3600 |
| --- | --- |
| Mellanox ConnectX-4 Lx (`15b3:1015`, dual port) | `AppleEthernetMLX5` — **fully working** |
| Realtek RTL8127 (`10ec:8127`) | `AppleEthernetRL` — **fully working** |

## Conditions that decide compatibility

- **Endpoint routing.** The driver reads the ACPI I/O Virtualization Reporting Structure (IVRS) to identify the IOMMU responsible for the selected PCIe device. It checks the controller's PCI capability and MMIO base against firmware. The production path handles PCI segment 0 and rejects a target that requires a requester-ID alias, redirection, or a nonzero IVHD device data setting.
- **Controller state and capacity.** If firmware supplies an Extended Feature Register (EFR) value, it must agree with the hardware reading. The driver declines to take over a controller whose translation engine, command buffer, or event log is already enabled. Up to 16 selected devices can have translation domains (slots allocated on demand), and they must share one IOMMU.
- **Firmware memory requirements.** The parser recognizes I/O Virtualization Memory Definition (IVMD) entries. The production mapping path does not implement the reserved or unity mappings those entries can require for a device. The MSI firmware sample contains no IVMD entries, so its successful runs leave that case open.
- **Power management.** The mapper registers its own sleep/wake interest and keeps under its own control every register that S3 destroys — device table and ring bases, ring positions, enable and run bits — so it repairs a controller that lost its image, including a wake that delivered no notification. Real sleep/wake cycles have run with translation active on this board, both with one domain and with four at once — the two ConnectX-4 Lx ports driven by the MLX5 DriverKit extension, the RTL8127 and the on-board RTL8111H (`10ec:8168`): 213 s asleep, RTC wake, controller suspend/resume 1/1, one suspend and one resume per domain, the register image restored from the hardware reading, zero resume failures, zero target faults, and DHCP re-acquired seconds after wake. The suspend is retained rather than stopped, because requesters still hold live mappings when the notification arrives; the controller keeps translating, and the wake path rebuilds it from the first DMA call. No row below claims sleep/wake support: the clients those rows name are Apple's own Ethernet kexts and none of them has been through a cycle yet. The RTL8111H itself is absent from the table because its driver is a third-party stack, which is out of scope here. Criteria and the published evidence keys are in [README.md](README.md#power-management).

## Next validation

The most informative next test is the **another vendor's X570 with the same PCIe NIC**. Confirm that the card's DTE becomes active, traffic passes in both directions, and the IOMMU records no faults for that requester during the test. A pass would establish compatibility for that board, CPU, firmware, and adapter combination.

## Sources

- **Controller discovery and device policy** — `kext/AMDMapperProbeDiscovery.cpp` (lines 108–165), `kext/AMDMapperProbeAuto.cpp` (lines 625–689), `kext/AMDMapperProbe.hpp` (line 105), and `kext/AMDMapperProbe-Info.plist` (lines 175–188).
- **Firmware parsing and the MSI sample** — `src/Ivrs.cpp`, `include/amd_iommu/Ivrs.hpp`, and `tests/InspectorSmoke.py`.
- **Hardware test records** — the parent project's `amd-iommu/docs/` directory.
- **AMD platform specifications** — [Socket AM4 chipsets](https://www.amd.com/en/products/processors/chipsets/am4.html) and [Socket AM5 chipsets](https://www.amd.com/en/products/processors/chipsets/am5.html).

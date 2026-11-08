# AMDIOMMU motherboard compatibility

Hardware validation covers the following hardware combinations, where selected PCIe network adapters have operated with hardware DMA address translation active. The production driver discovers the IOMMU from firmware and PCI configuration at runtime. Its controller matching code has no motherboard-brand, chipset-model, or Ryzen-model whitelist.

## Verified hardware combinations

Which combinations count, and how a failure is attributed, is defined in
[AGENTS.md](AGENTS.md).

| PCIe device (hardware ID) | MSI MPG X570 GAMING EDGE WIFI + Ryzen 5 3600 |
| --- | --- |
| Mellanox ConnectX-4 Lx (`15b3:1015`, dual port) | `AppleEthernetMLX5` — **fully working** |
| Realtek RTL8127 (`10ec:8127`) | `AppleEthernetRL` — networking **fully working**, sleep/wake **not usable**<br>[`RTL812xLucy`](https://github.com/hackintosh-stuff/RTL812xLucy) — **fully working**|

## Conditions that decide compatibility

- **Endpoint routing.** The IOMMU is the one named for the selected device by the ACPI IVRS entry, and its PCI capability and MMIO base are checked against firmware. Only PCI segment 0 is handled; a device that needs a requester-ID alias, a redirection, or a nonzero IVHD device data setting is refused.
- **Controller state and capacity.** A firmware-supplied EFR must agree with the hardware. A controller whose translation engine, command buffer, or event log is already enabled is left alone. Up to 16 selected devices share one IOMMU, with domains allocated on demand.
- **Firmware memory requirements.** IVMD entries are parsed, but the reserved and unity mappings they can require are not implemented. The MSI firmware sample contains none, so that case stays open.
- **Power management.** The mapper runs sleep and wake itself and restores a controller that lost its register image, including a wake that delivered no suspend notification. A client driver that cannot survive the transition stays out of reach. Mechanism and evidence keys are in [DEBUG.md](DEBUG.md#power-management).

## Next validation

The most informative next test is the **another vendor's X570 with the same PCIe NIC**. Confirm that the card's DTE becomes active, traffic passes in both directions, and the IOMMU records no faults for that requester during the test. A pass would establish compatibility for that board, CPU, firmware, and adapter combination.

## Sources

- **Controller discovery and device policy** — `probe/AMDMapperProbeDiscovery.cpp` (lines 108–165), `probe/AMDMapperProbeAuto.cpp` (lines 625–689), `probe/AMDMapperProbe.hpp` (line 105), and `probe/AMDMapperProbe-Info.plist` (lines 175–188).
- **Firmware parsing and the MSI sample** — `src/Ivrs.cpp`, `include/amd_iommu/Ivrs.hpp`, and `tests/InspectorSmoke.py`.
- **Hardware test records** — the parent project's `amd-iommu/docs/` directory.
- **AMD platform specifications** — [Socket AM4 chipsets](https://www.amd.com/en/products/processors/chipsets/am4.html) and [Socket AM5 chipsets](https://www.amd.com/en/products/processors/chipsets/am5.html).

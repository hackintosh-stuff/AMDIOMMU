# AMDIOMMU motherboard compatibility

November 6, 2026 · `AMDMapperProbe` 0.97.0 · Local commit `d5fea92`

Hardware validation covers the **MSI MPG X570 GAMING EDGE WIFI with a Ryzen 5 3600**, where selected PCIe network adapters have operated with hardware DMA address translation active. The production driver discovers the IOMMU from firmware and PCI configuration at runtime. Its controller matching code has no motherboard-brand, chipset-model, or Ryzen-model whitelist.

## Compatibility across four motherboard changes

| Motherboard change | Assessment | What matters on the target board |
| --- | --- | --- |
| **Different brand, same chipset — MSI X570 to ASRock X570** | **Closest candidate for reuse.** The ASRock board still needs a hardware test with this driver. | The project's ASRock X570 Steel Legend uses a Ryzen 9 5900X, so both the board and CPU change. Its RTL8127 optical adapter was tested in the MSI system. Moving that same card back to the ASRock provides a known endpoint for checking the new firmware and slot topology. |
| **Different chipset, same generation — X570 to B550** | **Direct reuse is plausible** with the same CPU and adapter. | A B550 board that supports the Ryzen 5 3600 allows both to remain fixed. Slot routing can change the card's PCI bus/device/function address. If the configuration specifies `amdiommu_devices`, use the requester ID reported on the B550 system. |
| **Different chipset generation, same socket — X570 to B450** | **Direct reuse is also plausible.** The driver has no 500-series requirement. | A B450 board whose BIOS supports the same Ryzen 5 3600 provides a comparable test. The code gives no basis for ranking it below B550 solely because it is older. The target slot's firmware description and any device-specific memory requirements carry more weight. |
| **Different socket and generation — X570 to X870** | **Architecturally plausible, with the least direct evidence.** | X870 moves to AM5 and requires a different CPU. The driver reads the target controller's register base and feature information and recognizes IVHD types `0x10`, `0x11`, and `0x40`. The project's Gigabyte B650M with a Ryzen 7 9700X is a planned AM5 test target. No X870 hardware translation result was found. |

## Conditions that decide compatibility

- **Endpoint routing.** The driver reads the ACPI I/O Virtualization Reporting Structure (IVRS) to identify the IOMMU responsible for the selected PCIe device. It checks the controller's PCI capability and MMIO base against firmware. The production path handles PCI segment 0 and rejects a target that requires a requester-ID alias, redirection, or a nonzero IVHD device data setting.
- **Controller state and capacity.** If firmware supplies an Extended Feature Register (EFR) value, it must agree with the hardware reading. The driver declines to take over a controller whose translation engine, command buffer, or event log is already enabled. Up to 16 selected devices can have translation domains (slots allocated on demand), and they must share one IOMMU.
- **Firmware memory requirements.** The parser recognizes I/O Virtualization Memory Definition (IVMD) entries. The production mapping path does not implement the reserved or unity mappings those entries can require for a device. The MSI firmware sample contains no IVMD entries, so its successful runs leave that case open.

## Hardware evidence and next validation

On the MSI system, a **ConnectX-4 Lx reached approximately 9.4 Gbit/s** in the R70 tests. R71 subsequently recorded two active translation domains, with each hardware device table entry (DTE) pointing to its allocated page table. R71 tested a 0.97.0 build with explicit requester IDs and predates the default device-list change in `d5fea92`.

The most informative next test is the **ASRock X570 Steel Legend with the same RTL8127 optical adapter**. Confirm that the card's DTE becomes active, traffic passes in both directions, and the IOMMU records no faults for that requester during the test. A pass would establish compatibility for that board, CPU, firmware, and adapter combination.

## Sources

- **Controller discovery and device policy** — `kext/AMDMapperProbeDiscovery.cpp` (lines 108–165), `kext/AMDMapperProbeAuto.cpp` (lines 625–689), `kext/AMDMapperProbe.hpp` (line 105), and `kext/AMDMapperProbe-Info.plist` (lines 175–188), at commit `d5fea92`.
- **Firmware parsing and the MSI sample** — `src/Ivrs.cpp`, `include/amd_iommu/Ivrs.hpp`, and `tests/InspectorSmoke.py`.
- **Hardware test records** in the parent project's `amd-iommu/docs/` directory — `m2-3bb-round70-mellanox-personality.md` (§8) and `m2-3bd-round71-first-map-growth.md` (§9).
- **AMD platform specifications** — [Socket AM4 chipsets](https://www.amd.com/en/products/processors/chipsets/am4.html) and [Socket AM5 chipsets](https://www.amd.com/en/products/processors/chipsets/am5.html).

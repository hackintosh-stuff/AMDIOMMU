#include "amd_iommu/Ivrs.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

// Offline regular-file inspection only. Firmware addresses are never mapped.
int main(int argc, char **argv) {
    if (argc == 2 && std::strcmp(argv[1], "--help") == 0) {
        std::puts("Usage: ivrs-inspect IVRS.bin\n"
                  "Reads a raw ACPI IVRS table (max 16 MiB). Structural checks only.\n"
                  "Exit: 0 structurally valid, 2 usage/IO error, 3 invalid structure.\n"
                  "Does NOT collect firmware, access MMIO, or prove IOMMU support.");
        return 0;
    }
    if (argc != 2) {
        std::fputs("Usage: ivrs-inspect IVRS.bin\n", stderr);
        return 2;
    }
    FILE *file = std::fopen(argv[1], "rb");
    if (!file) { std::perror("open IVRS input"); return 2; }
    if (std::fseek(file, 0, SEEK_END) != 0) {
        std::fclose(file); std::fputs("Input must be a seekable file\n", stderr); return 2;
    }
    const long size = std::ftell(file);
    if (size < 0 || size > 16 * 1024 * 1024 || std::fseek(file, 0, SEEK_SET) != 0) {
        std::fclose(file); std::fputs("Invalid input size (max 16 MiB)\n", stderr); return 2;
    }
    // Keep nonnull backing storage even for the deliberately invalid empty file.
    std::vector<std::uint8_t> bytes(size ? static_cast<std::size_t>(size) : 1);
    const std::size_t read = std::fread(bytes.data(), 1, static_cast<std::size_t>(size), file);
    const bool ioError = std::ferror(file) != 0;
    std::fclose(file);
    if (ioError || read != static_cast<std::size_t>(size)) {
        std::fputs("Could not read complete input\n", stderr); return 2;
    }
    const auto r = amd_iommu::parseIvrs(bytes.data(), read);
    if (!r) {
        std::fprintf(stderr, "IVRS rejected at offset %zu: %s\n", r.errorOffset,
                     amd_iommu::ivrsErrorString(r.error));
        return 3;
    }
    std::printf("IVRS structurally valid: tableBytes=%zu inputBytes=%zu\n"
                "blocks=%zu IVHD=%zu IVMD=%zu devices=%zu unknownBlocks=%zu unknownDevices=%zu\n"
                "NOT hardware validation; unknown entries are opaque; no device ownership policy.\n",
                r.tableLength, read, r.blockCount, r.ivhdCount, r.ivmdCount,
                r.deviceCount, r.unknownBlockCount, r.unknownDeviceCount);
    return 0;
}

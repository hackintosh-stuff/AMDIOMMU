// Bounded, allocation-free identity updates for caller-owned DMA ranges.
// Bootstrap runs while the table is inactive. A live caller holds its domain
// lock and confirms invalidation before exposing a new physical DMA address.
// No RAM-top inference, physical-memory probing or leaf splitting is performed.
#pragma once
#include "amd_iommu_pte_core.hpp"

namespace amdsparse {
typedef amdpte::u64 u64;
struct Arena {
    volatile u64 *words;
    u64 base;
    unsigned pages;
    unsigned next;       // first unused page; includes existing bad-root reserve
    unsigned rootLevel;
    u64 rootPA;
    unsigned addedPages;
    unsigned addedLeaves;
    const char *why;
};
inline volatile u64 *table(Arena &a, u64 pa) {
    if (!a.words || (pa & 4095ULL) || pa < a.base ||
        pa - a.base >= (u64)a.pages * 4096ULL) return nullptr;
    return a.words + (pa - a.base) / 8;
}
inline bool mapPage(Arena &a, u64 addr) {
    u64 pa = a.rootPA;
    for (unsigned level = a.rootLevel; level; --level) {
        volatile u64 *t = table(a, pa);
        if (!t) { a.why = "table-outside-owned-arena"; return false; }
        const unsigned ix = amdpte::indexAt(level, addr);
        const u64 raw = t[ix];
        const amdpte::DecodedPte d = amdpte::decodePte(raw, level);
        if (d.kind == amdpte::PTE_LEAF_DEFAULT ||
            d.kind == amdpte::PTE_LEAF_LARGE) {
            if (d.outPA + (addr & (d.pageSize - 1)) != addr ||
                (raw & (amdpte::PTE_IR | amdpte::PTE_IW)) !=
                    (amdpte::PTE_IR | amdpte::PTE_IW)) {
                a.why = "existing-leaf-not-identity-rw"; return false;
            }
            return true;
        }
        if (d.kind == amdpte::PTE_TABLE) {
            if ((raw & (amdpte::PTE_IR | amdpte::PTE_IW)) !=
                (amdpte::PTE_IR | amdpte::PTE_IW)) {
                a.why = "existing-parent-not-rw"; return false;
            }
            pa = d.outPA;
            continue;
        }
        if (d.kind != amdpte::PTE_ABSENT) {
            a.why = "existing-entry-illegal"; return false;
        }
        const u64 perms = amdpte::PTE_IR | amdpte::PTE_IW;
        if (level == 1) {
            t[ix] = amdpte::makeDefaultLeaf(1, addr, perms);
            ++a.addedLeaves;
            return true;
        }
        if (a.next >= a.pages) {
            a.why = "sparse-table-page-budget"; return false;
        }
        const u64 child = a.base + (u64)a.next++ * 4096ULL;
        volatile u64 *ct = table(a, child);
        if (!ct) { a.why = "new-table-outside-arena"; return false; }
        for (unsigned j = 0; j < 512; ++j) ct[j] = 0;
        t[ix] = amdpte::makeTablePde(level - 1, child, perms);
        ++a.addedPages;
        pa = child;
    }
    a.why = "no-leaf"; return false;
}
inline bool mapOwnedRange(Arena &a, u64 addr, u64 bytes) {
    a.why = nullptr;
    if (a.rootLevel != 3 && a.rootLevel != 4) {
        a.why = "unsupported-root-level"; return false;
    }
    const u64 top = 1ULL << (12 + 9 * a.rootLevel);
    if (!addr || !bytes || addr >= top || bytes > top - addr) {
        a.why = "zero-overflow-or-address-width"; return false;
    }
    const u64 end = addr + bytes;
    for (u64 p = addr & ~4095ULL; p < end; p += 4096ULL)
        if (!mapPage(a, p)) return false;
    return true;
}
// The native ring drops its initial physical aliases only after every slot
// publishes IOVA OWN. Keep table pages so stop can reuse them for current PA.
inline bool unmapOwnedPage(Arena &a, u64 addr, unsigned &removed) {
    u64 pa = a.rootPA;
    for (unsigned level = a.rootLevel; level; --level) {
        volatile u64 *t = table(a, pa);
        if (!t) { a.why = "table-outside-owned-arena"; return false; }
        const unsigned ix = amdpte::indexAt(level, addr);
        const u64 raw = t[ix];
        const amdpte::DecodedPte d = amdpte::decodePte(raw, level);
        if (d.kind == amdpte::PTE_ABSENT) return true;
        if ((raw & (amdpte::PTE_IR | amdpte::PTE_IW)) !=
            (amdpte::PTE_IR | amdpte::PTE_IW)) {
            a.why = "retire-entry-not-rw"; return false;
        }
        if (d.kind == amdpte::PTE_TABLE) {
            pa = d.outPA;
            continue;
        }
        if (level != 1 || d.kind != amdpte::PTE_LEAF_DEFAULT ||
            d.outPA != addr) {
            a.why = "retire-leaf-not-4k-identity"; return false;
        }
        t[ix] = 0;
        ++removed;
        return true;
    }
    a.why = "no-leaf"; return false;
}
template<class KeepPage>
inline bool unmapOwnedRange(Arena &a, u64 addr, u64 bytes,
                           KeepPage keep, unsigned &removed) {
    a.why = nullptr;
    if (a.rootLevel != 3 && a.rootLevel != 4) {
        a.why = "unsupported-root-level"; return false;
    }
    const u64 top = 1ULL << (12 + 9 * a.rootLevel);
    if (!addr || !bytes || addr >= top || bytes > top - addr) {
        a.why = "zero-overflow-or-address-width"; return false;
    }
    const u64 end = addr + bytes;
    for (u64 p = addr & ~4095ULL; p < end; p += 4096ULL)
        if (!keep(p) && !unmapOwnedPage(a, p, removed)) return false;
    return true;
}
} // namespace amdsparse

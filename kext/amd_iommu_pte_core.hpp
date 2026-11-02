// AMD-Vi (IOMMU v1) page-table entry encoding and decoding -- shared core.
//
// WHY THIS FILE EXISTS
// --------------------
// Round 4 shipped a 2 MiB leaf encoded as NextLevel=7 with size bits, and
// three separate pieces of code all repeated the same wrong assumption:
// the builder, the in-kext software walker, and the offline decoder. Each
// "verified" the other, so nothing caught it.
//
// This header is the single implementation of the encoding rules. The
// production kext includes it, and the host regression tests include the
// very same file and run the very same functions. A test that passes here
// therefore exercises production logic, not a Python restatement of it.
//
// It deliberately depends on NOTHING: no IOKit, no libkern, no libc++. That
// is what makes it usable both inside the kext and in a plain host binary.
//
// LEVEL NUMBERING -- READ THIS BEFORE EDITING
// -------------------------------------------
// There are two conventions in circulation and mixing them is how the round-4
// bug survived review:
//
//   * Linux `amd_iommu_types.h` uses a 0-based "shift index": level L is the
//     table indexed by PM_LEVEL_SHIFT(L) = 12 + 9L. So 2 MiB lives at L=1.
//   * AMD IOMMU Spec 48882 Table 15 ("Page Table Level Parameters") is
//     1-based: Level 1 = 4 KiB, Level 2 = 2 MiB, Level 3 = 1 GiB, Level 4 =
//     512 GiB.
//
// This file uses the SPEC numbering (1-based), because that is the numbering
// the hardware's NextLevel field and the spec's tables use. So:
//
//   level 1 -> index bits 20:12, default page size 4 KiB
//   level 2 -> index bits 29:21, default page size 2 MiB
//   level 3 -> index bits 38:30, default page size 1 GiB
//   level 4 -> index bits 47:39, default page size 512 GiB
//
// The DTE Mode field equals the number of levels; a Mode=4 table therefore
// has a level-4 root, and a PDE stored in a level-N table encodes NextLevel
// = N-1, the level of the table it points to. (This matches both Linux's
// PM_LEVEL_PDE() output and QEMU's amdvi_page_walk().)
//
// THE RULE THAT WAS BROKEN
// ------------------------
// NextLevel == 0 means "a leaf that maps the DEFAULT page size of the level
// the PTE resides in". It does NOT mean 4 KiB. A PTE in a level-2 table with
// NextLevel == 0 maps 2 MiB.
//
// NextLevel == 7 means "an enlarged page, size encoded in the OA low bits".
// Spec 48882 Rev 3.10 section 2.2.3, p. 80:
//
//     "The page size specified by this method must be larger than the default
//      page size and smaller than the default page size for the next higher
//      level."
//
// So NextLevel=7 encoding EXACTLY the level's default size is not a legal
// alternative spelling -- it violates "must be larger". A 2 MiB page at
// level 2 must use NextLevel=0. That is the round-4 defect.

#pragma once

namespace amdpte {

typedef unsigned long long u64;

// ---- table levels (spec numbering, 1-based) ----
enum {
    LEVEL_4K   = 1,   // index bits 20:12, default 4 KiB
    LEVEL_2M   = 2,   // index bits 29:21, default 2 MiB
    LEVEL_1G   = 3,   // index bits 38:30, default 1 GiB
    LEVEL_512G = 4,   // index bits 47:39, default 512 GiB
    LEVEL_MAX  = 6    // spec Table 15 goes up to level 6
};

// ---- PTE bit fields (amd_iommu_types.h:376-380, spec Table 17) ----
static const u64 PM_ADDR_MASK   = 0x000FFFFFFFFFF000ULL;
static const u64 PTE_PR         = 1ULL << 0;
static const u64 PTE_FC         = 1ULL << 60;
static const u64 PTE_IR         = 1ULL << 61;
static const u64 PTE_IW         = 1ULL << 62;

static const unsigned NEXT_LEVEL_SHIFT = 9;
static const u64      NEXT_LEVEL_MASK  = 0x7ULL;

// The value that marks an enlarged ("large page") translation entry.
static const unsigned NEXT_LEVEL_LEAF   = 0;
static const unsigned NEXT_LEVEL_LARGE  = 7;

// ---- level arithmetic ----------------------------------------------------

// First bit of the virtual address used to index a table at this level.
inline unsigned indexShift(unsigned level) { return 9u * level + 3u; }
// Mask of the index field for this level.
inline u64 indexMask(unsigned level) { return 0x1FFULL << indexShift(level); }

inline unsigned indexAt(unsigned level, u64 iova) {
    return (unsigned)((iova >> indexShift(level)) & 0x1FFULL);
}

// Default page size for a leaf residing in a table at this level.
inline u64 defaultPageSize(unsigned level) {
    return 1ULL << indexShift(level);
}

inline unsigned nextLevelOf(u64 pte) {
    return (unsigned)((pte >> NEXT_LEVEL_SHIFT) & NEXT_LEVEL_MASK);
}

inline u64 levelEnc(unsigned level) {
    return ((u64)level << NEXT_LEVEL_SHIFT) & 0xE00ULL;
}

// Inverse of defaultPageSize(); returns 0 when ps is not a level default.
inline unsigned levelOfDefaultPageSize(u64 ps) {
    for (unsigned l = LEVEL_4K; l <= LEVEL_MAX; l++) {
        if (defaultPageSize(l) == ps) return l;
    }
    return 0;
}

// PAGE_SIZE_LEVEL(): the level whose default page size is `ps`.
inline unsigned pageSizeLevel(u64 ps) {
    unsigned n = 0;
    u64 p = ps;
    while (p > 1) { p >>= 1; n++; }
    return (n >= 12) ? (n - 12) / 9 + 1 : 0;
}

// PAGE_SIZE_PTE_COUNT(): how many consecutive PTEs a mapping of `ps` occupies.
// This is the number of times an enlarged PTE must be replicated.
inline u64 pageSizePteCount(u64 ps) {
    unsigned n = 0;
    u64 p = ps;
    while (p > 1) { p >>= 1; n++; }
    if (n < 12) return 0;
    return 1ULL << ((n - 12) % 9);
}

// ---- encoding ------------------------------------------------------------

// Non-leaf PTE: points at a table of the given level.
// Mirrors Linux PM_LEVEL_PDE() exactly: address | NextLevel | PR | IR | IW.
// NOTE: no FC -- Linux sets FC only on leaf entries (io_pgtable.c:396/398).
inline u64 makeTablePde(unsigned childLevel, u64 pa, u64 perms) {
    return (pa & PM_ADDR_MASK) | levelEnc(childLevel) |
           PTE_PR | (perms & (PTE_IR | PTE_IW));
}

// Leaf mapping the DEFAULT page size of `level`. NextLevel stays 0.
//
// Linux io_pgtable.c:398 (the `count == 1` branch):
//     __pte = paddr | IOMMU_PTE_PR | IOMMU_PTE_FC;
//     ... then IR/IW from prot
// i.e. no PM_LEVEL_ENC at all. This is the branch a 2 MiB mapping at level 2
// takes, because PAGE_SIZE_PTE_COUNT(2 MiB) == 1.
inline u64 makeDefaultLeaf(unsigned level, u64 pa, u64 perms) {
    (void)level;   // the size is implied by the level; the encoding is identical
    return (pa & PM_ADDR_MASK) | PTE_PR | PTE_FC |
           (perms & (PTE_IR | PTE_IW));
}

// Leaf mapping an ENLARGED page (NextLevel=7, size in the OA low bits).
//
// Linux io_pgtable.c:395-396 (the `count > 1` branch):
//     __pte = PAGE_SIZE_PTE(paddr, pgsize);
//     __pte |= PM_LEVEL_ENC(7) | IOMMU_PTE_PR | IOMMU_PTE_FC;
// where PAGE_SIZE_PTE(a,ps) = ((a | (ps-1)) & ~(ps>>1)) & PM_ADDR_MASK.
//
// Callers must NOT use this for a page size equal to the level default; see
// validateExtendedSize() and use makeDefaultLeaf() instead.
inline u64 makeLargeLeaf(u64 pa, u64 pageSize, u64 perms) {
    u64 base = ((pa | (pageSize - 1)) & ~(pageSize >> 1)) & PM_ADDR_MASK;
    return base | levelEnc(NEXT_LEVEL_LARGE) | PTE_PR | PTE_FC |
           (perms & (PTE_IR | PTE_IW));
}

// ---- decoding ------------------------------------------------------------

// PTE_PAGE_SIZE(): 1 << (1 + ffz(pte | 0xfff)), i.e. the page size implied by
// the run of 1 bits at bit 12 and above.
inline u64 encodedLargePageSize(u64 pte) {
    u64 x = pte | 0xFFFULL;
    unsigned i = 0;
    while (i < 63 && ((x >> i) & 1ULL)) i++;
    return 1ULL << (1 + i);
}

enum PteKind {
    PTE_ABSENT = 0,   // PR == 0
    PTE_TABLE,        // non-leaf, points at a lower-level table
    PTE_LEAF_DEFAULT, // NextLevel == 0: maps the level's default page size
    PTE_LEAF_LARGE,   // NextLevel == 7: maps an enlarged page
    PTE_ILLEGAL       // well-formed bits, but not a legal encoding here
};

struct DecodedPte {
    PteKind  kind;
    unsigned level;      // level of the table the PTE was read from
    u64      raw;
    u64      pageSize;   // valid for PTE_LEAF_DEFAULT and PTE_LEAF_LARGE
    u64      outPA;      // page base address, valid for both leaf kinds
    u64      pteCount;   // replication count for PTE_LEAF_LARGE (else 1)
    unsigned childLevel; // valid for PTE_TABLE
    const char *reason;  // why PTE_ABSENT / PTE_ILLEGAL; else nullptr
};

// Is this enlarged page size legal for a leaf at `level`?
// Spec: strictly larger than the level default, strictly smaller than the
// next higher level's default.
inline bool validateExtendedSize(unsigned level, u64 ps, const char **why) {
    const u64 lo = defaultPageSize(level);
    const u64 hi = (level < LEVEL_MAX) ? defaultPageSize(level + 1) : 0;
    if (ps <= lo) {
        if (why) *why = "enlarged page size is not larger than the level "
                        "default; this must be encoded as NextLevel=0";
        return false;
    }
    if (hi != 0 && ps >= hi) {
        if (why) *why = "enlarged page size reaches the next level's default; "
                        "use a table at that level instead";
        return false;
    }
    if ((ps & (ps - 1)) != 0) {
        if (why) *why = "enlarged page size is not a power of two";
        return false;
    }
    return true;
}

// Decode one PTE, given the level of the table it was read from.
//
// This is the function the round-4 code lacked: without the level there is no
// way to tell whether NextLevel=0 means 4 KiB or 2 MiB, and no way to notice
// that NextLevel=7 is being abused to spell a size it must not spell.
inline DecodedPte decodePte(u64 pte, unsigned level) {
    DecodedPte d;
    d.kind = PTE_ABSENT;
    d.level = level;
    d.raw = pte;
    d.pageSize = 0;
    d.outPA = 0;
    d.pteCount = 1;
    d.childLevel = 0;
    d.reason = nullptr;

    if ((pte & PTE_PR) == 0) {
        d.reason = "PR=0 (entry not present)";
        return d;
    }

    const unsigned nl = nextLevelOf(pte);

    if (nl == NEXT_LEVEL_LARGE) {
        const u64 ps = encodedLargePageSize(pte);
        const char *why = nullptr;
        if (!validateExtendedSize(level, ps, &why)) {
            d.kind = PTE_ILLEGAL;
            d.pageSize = ps;
            d.reason = why;
            return d;
        }
        d.kind = PTE_LEAF_LARGE;
        d.pageSize = ps;
        d.outPA = (pte & PM_ADDR_MASK) & ~(ps - 1);
        d.pteCount = pageSizePteCount(ps);
        return d;
    }

    if (nl == NEXT_LEVEL_LEAF) {
        // NextLevel 0 = the default page size FOR THIS LEVEL, not "4 KiB".
        d.kind = PTE_LEAF_DEFAULT;
        d.pageSize = defaultPageSize(level);
        d.outPA = pte & PM_ADDR_MASK;
        d.pteCount = 1;
        return d;
    }

    // 1..6: a page-directory entry. It must point at the immediately lower
    // level; level skipping is not supported (Linux io_pgtable.c:269-271,
    // "No level skipping support yet").
    if (nl != level - 1) {
        d.kind = PTE_ILLEGAL;
        d.childLevel = nl;
        d.reason = "NextLevel does not point at the next level down "
                   "(level skipping is not supported)";
        return d;
    }
    d.kind = PTE_TABLE;
    d.childLevel = nl;
    d.outPA = pte & PM_ADDR_MASK;
    return d;
}

// ---- walking -------------------------------------------------------------

struct WalkResult {
    bool     ok;         // a present, legal leaf was reached
    bool     illegal;    // an illegal encoding was found
    bool     absent;     // a PTE was simply not present
    u64      pageSize;   // valid when ok
    u64      outPA;      // translated physical address when ok
    unsigned leafLevel;  // level of the table holding the leaf
    unsigned depth;      // number of PTEs examined
    const char *reason;  // why not ok
};

// Walk a page table for `iova`, starting at the table at `rootPA` whose level
// is `rootLevel`.
//
// `readEntry` is a callback so the same walker serves both the kext (reading
// its own memory) and the tests (reading a plain array):
//
//     u64 readEntry(u64 tablePA, unsigned index);
//
// It must return the 64-bit PTE at `tablePA + index*8`.
template <typename ReadFn>
inline WalkResult walkPageTable(ReadFn readEntry, unsigned rootLevel,
                                u64 rootPA, u64 iova) {
    WalkResult r;
    r.ok = false;
    r.illegal = false;
    r.absent = false;
    r.pageSize = 0;
    r.outPA = 0;
    r.leafLevel = 0;
    r.depth = 0;
    r.reason = "no leaf reached";

    if (rootLevel < LEVEL_4K || rootLevel > LEVEL_MAX) {
        r.reason = "root level out of range";
        return r;
    }

    unsigned level = rootLevel;
    u64 tablePA = rootPA;

    for (;;) {
        const u64 pte = readEntry(tablePA, indexAt(level, iova));
        r.depth++;
        const DecodedPte d = decodePte(pte, level);

        if (d.kind == PTE_ABSENT) {
            r.absent = true;
            r.reason = d.reason;
            return r;
        }
        if (d.kind == PTE_ILLEGAL) {
            r.illegal = true;
            r.reason = d.reason;
            return r;
        }
        if (d.kind == PTE_LEAF_DEFAULT || d.kind == PTE_LEAF_LARGE) {
            r.ok = true;
            r.pageSize = d.pageSize;
            r.leafLevel = level;
            // Page base from the PTE, low bits from the IOVA.
            r.outPA = d.outPA | (iova & (d.pageSize - 1));
            r.reason = nullptr;
            return r;
        }
        // PTE_TABLE
        if (level <= LEVEL_4K) {
            r.illegal = true;
            r.reason = "page directory entry below the 4 KiB level";
            return r;
        }
        level = d.childLevel;
        tablePA = d.outPA;
    }
}

}  // namespace amdpte

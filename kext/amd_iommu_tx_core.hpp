// Round32 bounded dynamic IOVA arena. Active-record indices do not choose
// addresses: each mapping reserves only the pages its physical layout needs.
// All operations run under the owning domain lock; there are no hardware waits.
#pragma once
#include "amd_iommu_sparse_core.hpp"
namespace amdtx {
using amdpte::u64;
static constexpr u64 kBase = 0x1000000000ULL; //64GiB, outside identity bootstrap
static constexpr unsigned kPages = 256, kSegments = 16;
static constexpr unsigned kSlots = 16, kMapPages = 32;
static constexpr unsigned kRxFirstPage = 512; // RX starts at the next L1 table
struct Allocator {
    u64 used[kPages / 64], ever[kPages / 64];
    unsigned livePages, peakPages, reusedAllocations;
};
inline bool allocate(Allocator &a, unsigned pages, unsigned &basePage) {
    if (!pages || pages > kMapPages) return false;
    for (unsigned base = 0; base <= kPages - pages; ++base) {
        bool free = true;
        for (unsigned j = 0; j < pages; ++j) {
            const unsigned p = base + j;
            if (a.used[p / 64] & (1ULL << (p % 64))) { free = false; break; }
        }
        if (!free) continue;
        bool reused = false;
        for (unsigned j = 0; j < pages; ++j) {
            const unsigned p = base + j;
            const u64 bit = 1ULL << (p % 64);
            reused = reused || (a.ever[p / 64] & bit);
            a.used[p / 64] |= bit;
            a.ever[p / 64] |= bit;
        }
        a.livePages += pages;
        if (a.livePages > a.peakPages) a.peakPages = a.livePages;
        if (reused) ++a.reusedAllocations;
        basePage = base;
        return true;
    }
    return false;
}
inline bool release(Allocator &a, unsigned basePage, unsigned pages) {
    if (!pages || pages > kMapPages || basePage > kPages - pages ||
        a.livePages < pages) return false;
    for (unsigned j = 0; j < pages; ++j) {
        const unsigned p = basePage + j;
        if (!(a.used[p / 64] & (1ULL << (p % 64)))) return false;
    }
    for (unsigned j = 0; j < pages; ++j) {
        const unsigned p = basePage + j;
        a.used[p / 64] &= ~(1ULL << (p % 64));
    }
    a.livePages -= pages;
    return true;
}
struct Segment { u64 pa, bytes, iova; };
struct Plan {
    unsigned count, pages, basePage;
    Segment segments[kSegments];
    // Mapping-local pages. The absolute PTE index is basePage + j.
    u64 physical[kMapPages];
};
inline bool plan(Plan &p, const Segment *s, unsigned n, unsigned basePage = 0) {
    p = {};
    if (!s || !n || n > kSegments || basePage >= kPages) return false;
    unsigned at = 0;
    for (unsigned i = 0; i < n; ++i) {
        const u64 off = s[i].pa & 4095ULL;
        if (!s[i].pa || !s[i].bytes || s[i].pa >= (1ULL<<52) ||
            s[i].bytes > (1ULL<<52) - s[i].pa ||
            s[i].bytes > kMapPages*4096ULL)
            return false;
        const unsigned pages = (unsigned)((off + s[i].bytes + 4095) / 4096);
        if (pages > kMapPages - at || pages > kPages - basePage - at) return false;
        p.segments[i] = {s[i].pa, s[i].bytes, kBase + (basePage+at)*4096ULL + off};
        for (unsigned j = 0; j < pages; ++j)
            p.physical[at+j] = (s[i].pa & ~4095ULL) + j*4096ULL;
        at += pages;
    }
    p.count = n; p.pages = at; p.basePage = basePage;
    return true;
}
// Build only absent branches in a reserved inactive arena. Never split or
// overwrite an existing mapping; owned RX/bootstrap mappings remain untouched.
inline volatile u64 *prepareAt(amdsparse::Arena &a, u64 iova, unsigned pages) {
    if (a.rootLevel != 3 && a.rootLevel != 4) return nullptr;
    const unsigned ix = amdpte::indexAt(1, iova);
    if (!pages || (iova & 4095ULL) || pages > 512 - ix) return nullptr;
    u64 pa = a.rootPA;
    for (unsigned level = a.rootLevel; level > 1; --level) {
        volatile u64 *t = amdsparse::table(a, pa);
        if (!t) return nullptr;
        const unsigned parent = amdpte::indexAt(level, iova);
        const u64 raw = t[parent];
        const auto d = amdpte::decodePte(raw, level);
        if (d.kind == amdpte::PTE_TABLE) {
            if ((raw & (amdpte::PTE_IR|amdpte::PTE_IW)) !=
                       (amdpte::PTE_IR|amdpte::PTE_IW)) return nullptr;
            pa = d.outPA; continue;
        }
        if (d.kind != amdpte::PTE_ABSENT || a.next >= a.pages) return nullptr;
        pa = a.base + a.next++*4096ULL;
        volatile u64 *child = amdsparse::table(a, pa);
        if (!child) return nullptr;
        for (unsigned j = 0; j < 512; ++j) child[j] = 0;
        t[parent] = amdpte::makeTablePde(level-1, pa, amdpte::PTE_IR|amdpte::PTE_IW);
    }
    volatile u64 *t = amdsparse::table(a, pa);
    if (!t) return nullptr;
    for (unsigned j = 0; j < pages; ++j) if (t[ix+j]) return nullptr;
    return t+ix;
}
inline volatile u64 *prepare(amdsparse::Arena &a) {
    return prepareAt(a, kBase, kPages);
}
inline bool publish(volatile u64 *leaves, const Plan &p) {
    if (!leaves || !p.pages || p.pages > kMapPages ||
        p.basePage > kPages - p.pages) return false;
    for (unsigned i = 0; i < p.pages; ++i) if (leaves[p.basePage+i]) return false;
    for (unsigned i = 0; i < p.pages; ++i)
        leaves[p.basePage+i] = amdpte::makeDefaultLeaf(1, p.physical[i], amdpte::PTE_IR);
    return true;
}
inline void clear(volatile u64 *leaves, unsigned basePage = 0, unsigned pages = kPages) {
    if (leaves && pages <= kPages && basePage <= kPages - pages)
        for (unsigned i = 0; i < pages; ++i) leaves[basePage+i] = 0;
}

// ---- round 20: identity coverage for objects the device reads by PA --------
//
// The bootstrap table maps [0, limit) identity. A normal TX packet keeps its
// physical addresses (the driver's cursor fills the descriptors), so any byte
// of it at or above `limit` is not readable by the device. Round 20 adds only
// the 2 MiB chunks that contain the actual segments of an object the driver is
// about to hand to hardware -- not a wholesale aperture extension.
//
// The mapping is placed in the same identity subtree (root -> level-3 table ->
// level-2 table), using a default level-2 leaf (2 MiB). If a chunk is already
// backed by a level-1 table (the RX owned ranges are mapped at 4 KiB), the
// exact 4 KiB pages of this object are verified/added there instead, so an
// existing mapping is never overwritten with a coarser one.
//
// Every byte written is identity; nothing here maps a foreign PA. The caller
// must invalidate the domain before the hardware uses the new entries.
//
// Coverage is planned before it is built. `coverIdentity` runs ONE walk twice:
// once as a dry run that only validates and counts, and once as the build. The
// dry run is what makes a capacity failure safe -- it proves the arena has every
// table page the build will consume BEFORE the first PTE is written, so a build
// that fails on budget cannot leave a half-published branch behind (round 20
// did leave one: the second chunk's table page was allocated and linked while
// the third hit the budget, and the next call reused a page that was already
// referenced, mis-translating 0x400000100 to 0x480000100).
//
// Note the dry run must account for the level-2 table page exactly the way the
// build will CLAIM it: the first chunk that lands in an absent 1 GiB entry
// consumes one page and every later chunk in that SAME 1 GiB entry reuses it.
// Counting per chunk would over-reserve; counting nothing would under-reserve.
struct CoverResult {
    unsigned pages;    // new table pages consumed from the arena
    unsigned chunks;   // new 2 MiB identity leaves
    unsigned present;  // chunks already covered by an identity leaf
    unsigned leaves;   // new 4 KiB identity leaves inside an existing table
};

inline bool coverIdentityWalk(amdsparse::Arena &a, u64 limit,
                              const Segment *s, unsigned n, CoverResult &r,
                              bool build) {
    r = {};
    if (!s || !n || n > kSegments) {
        a.why = "cover-invalid-input";
        return false;
    }
    if (a.rootLevel != 3 && a.rootLevel != 4) {
        a.why = "cover-unsupported-root-level";
        return false;
    }
    const u64 rw = amdpte::PTE_IR | amdpte::PTE_IW;
    // Table pages this walk has already committed (build) or reserved (dry) and
    // the level-3 entries they belong to. Only the 1 GiB entry identity matters:
    // a single absent level-3 entry needs one page no matter how many chunks of
    // it are covered.
    u64 claimed1G[2 * kSegments] = {};
    unsigned claimed = 0;
    for (unsigned i = 0; i < n; ++i) {
        const u64 pa = s[i].pa, bytes = s[i].bytes;
        if (!pa || !bytes || pa >= (1ULL << 52) ||
            bytes > (1ULL << 52) - pa) {
            a.why = "cover-zero-overflow-or-width";
            return false;
        }
        const u64 end = pa + bytes;
        const u64 from = pa < limit ? limit : pa;
        for (u64 chunk = from & ~0x1FFFFFULL; chunk < end; chunk += 0x200000ULL) {
            if (chunk + 0x200000ULL <= limit) continue;  // base map covers it
            // Level-3 table (root entry covers 1 GiB). In 3-level mode the root
            // itself is that table; in 4-level mode root[0] points at it.
            volatile u64 *t3;
            if (a.rootLevel == 4) {
                volatile u64 *root = amdsparse::table(a, a.rootPA);
                if (!root) { a.why = "cover-root-outside-arena"; return false; }
                const u64 e = root[amdpte::indexAt(4, chunk)];
                const auto d = amdpte::decodePte(e, 4);
                if (d.kind != amdpte::PTE_TABLE) {
                    a.why = "cover-missing-level3-table";
                    return false;
                }
                if ((e & rw) != rw) { a.why = "cover-level3-not-rw"; return false; }
                t3 = amdsparse::table(a, d.outPA);
                if (!t3) { a.why = "cover-level3-outside-arena"; return false; }
            } else {
                t3 = amdsparse::table(a, a.rootPA);
                if (!t3) { a.why = "cover-root-outside-arena"; return false; }
            }
            const u64 gbBase = chunk & ~((1ULL << 30) - 1);
            const unsigned gb = amdpte::indexAt(3, chunk);
            const u64 e3 = t3[gb];
            const auto d3 = amdpte::decodePte(e3, 3);
            volatile u64 *t2 = nullptr;
            if (d3.kind == amdpte::PTE_ABSENT) {
                // This 1 GiB entry has no level-2 table. Reserve/claim exactly
                // one page for it, no matter how many chunks of it follow.
                bool already = false;
                for (unsigned k = 0; k < claimed; ++k)
                    if (claimed1G[k] == gbBase) { already = true; break; }
                if (!already) {
                    if (a.next >= a.pages) {
                        a.why = "cover-table-page-budget";
                        return false;
                    }
                    if (claimed >= sizeof(claimed1G) / sizeof(claimed1G[0])) {
                        a.why = "cover-too-many-1g-entries";
                        return false;
                    }
                    claimed1G[claimed++] = gbBase;
                    if (build) {
                        const u64 child = a.base + (u64)a.next * 4096ULL;
                        t2 = amdsparse::table(a, child);
                        if (!t2) {
                            a.why = "cover-new-table-outside-arena";
                            return false;
                        }
                        for (unsigned j = 0; j < 512; ++j) t2[j] = 0;
                        t3[gb] = amdpte::makeTablePde(2, child, rw);
                        ++r.pages;
                    }
                    a.next++;   // both: the page is now spoken for
                } else if (build) {
                    // A previous chunk in this same 1 GiB entry already created
                    // the table; look it up through the entry we just wrote.
                    const auto dNow = amdpte::decodePte(t3[gb], 3);
                    if (dNow.kind != amdpte::PTE_TABLE) {
                        a.why = "cover-claimed-table-missing";
                        return false;
                    }
                    t2 = amdsparse::table(a, dNow.outPA);
                    if (!t2) { a.why = "cover-parent-outside-arena"; return false; }
                } else {
                    continue;   // dry run: nothing else to check for this chunk
                }
            } else if (d3.kind == amdpte::PTE_TABLE) {
                if ((e3 & rw) != rw) { a.why = "cover-parent-not-rw"; return false; }
                t2 = amdsparse::table(a, d3.outPA);
                if (!t2) { a.why = "cover-parent-outside-arena"; return false; }
            } else if (d3.kind == amdpte::PTE_LEAF_DEFAULT ||
                       d3.kind == amdpte::PTE_LEAF_LARGE) {
                // A 1 GiB identity leaf already answers this whole chunk.
                if (d3.pageSize != (1ULL << 30) || d3.outPA != gbBase ||
                    (e3 & rw) != rw) {
                    a.why = "cover-existing-1g-leaf-not-identity";
                    return false;
                }
                ++r.present;
                continue;
            } else {
                a.why = "cover-illegal-parent";
                return false;
            }
            if (!t2) continue;      // dry run, first chunk of a fresh 1 GiB entry
            const unsigned ix = amdpte::indexAt(2, chunk);
            const u64 e2 = t2[ix];
            const auto d2 = amdpte::decodePte(e2, 2);
            if (d2.kind == amdpte::PTE_ABSENT) {
                if (build) t2[ix] = amdpte::makeDefaultLeaf(2, chunk, rw);
                ++r.chunks;
            } else if (d2.kind == amdpte::PTE_TABLE) {
                if ((e2 & rw) != rw) { a.why = "cover-4k-parent-not-rw"; return false; }
                volatile u64 *t1 = amdsparse::table(a, d2.outPA);
                if (!t1) { a.why = "cover-4k-table-outside-arena"; return false; }
                const u64 cend = chunk + 0x200000ULL;
                const u64 first = (pa > chunk ? pa : chunk) & ~4095ULL;
                const u64 last = ((end < cend ? end : cend) - 1) & ~4095ULL;
                for (u64 p = first; p <= last; p += 4096ULL) {
                    const unsigned li = amdpte::indexAt(1, p);
                    const u64 e1 = t1[li];
                    const auto d1 = amdpte::decodePte(e1, 1);
                    if (d1.kind == amdpte::PTE_ABSENT) {
                        if (build) t1[li] = amdpte::makeDefaultLeaf(1, p, rw);
                        ++r.leaves;
                    } else if (d1.kind == amdpte::PTE_LEAF_DEFAULT) {
                        if (d1.outPA != p || (e1 & rw) != rw) {
                            a.why = "cover-existing-4k-not-identity";
                            return false;
                        }
                    } else {
                        a.why = "cover-illegal-4k-entry";
                        return false;
                    }
                }
            } else if (d2.kind == amdpte::PTE_LEAF_DEFAULT ||
                       d2.kind == amdpte::PTE_LEAF_LARGE) {
                if (d2.pageSize != 0x200000ULL || d2.outPA != chunk ||
                    (e2 & rw) != rw) {
                    a.why = "cover-existing-2m-leaf-not-identity";
                    return false;
                }
                ++r.present;
            } else {
                a.why = "cover-illegal-level2-entry";
                return false;
            }
        }
    }
    a.why = nullptr;
    return true;
}

// Public entry: validate + count in a throwaway arena copy, then build for real
// only if the whole plan fits. `a.next` is advanced by the build alone, so a
// refused call leaves the caller's allocation state exactly as it was.
inline bool coverIdentity(amdsparse::Arena &a, u64 limit,
                          const Segment *s, unsigned n, CoverResult &r) {
    amdsparse::Arena dry = a;
    CoverResult plan;
    if (!coverIdentityWalk(dry, limit, s, n, plan, false)) {
        a.why = dry.why;
        return false;
    }
    // The dry run consumed exactly the pages the build will; re-check against
    // the real arena because the dry copy shared nothing but numbers.
    if (dry.next > a.pages) {
        a.why = "cover-table-page-budget";
        return false;
    }
    if (!coverIdentityWalk(a, limit, s, n, r, true)) return false;
    return true;
}
} // namespace amdtx

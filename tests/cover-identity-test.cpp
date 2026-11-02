#include <cstdio>
#include <cstring>
#include <cassert>
#include <cstdint>
#include "amd_iommu_tx_core.hpp"
static int checks = 0;
#define CHECK(x) do { assert(x); ++checks; } while(0)
int main() {
    const amdpte::u64 rw = amdpte::PTE_IR | amdpte::PTE_IW;
    const amdpte::u64 limit = 0x400000000ULL;   /* 16 GiB */
    static amdpte::u64 words[512 * 8];
    /* root at 0x100000, its level-3 child at 0x101000 (= words[512]).
     * `pages` is the arena size and `next` the first free page, so the number of
     * usable table pages is pages - next. */
    auto reset = [&](unsigned pages, unsigned next) {
        memset(words, 0, sizeof(words));
        words[0] = amdpte::makeTablePde(3, 0x101000, rw);
        return amdsparse::Arena{words, 0x100000, pages, next, 4, 0x100000, 0, 0, nullptr};
    };
    /* Level-3 indices inside the 1 GiB table, for the chunks used below. */
    const unsigned gb400 = amdpte::indexAt(3, 0x400000000ULL);  /* 16 */
    const unsigned gb480 = amdpte::indexAt(3, 0x480000000ULL);  /* 18 */
    const unsigned gb500 = amdpte::indexAt(3, 0x500000000ULL);  /* 20 */

    /* (A) two chunks in one fresh 1 GiB entry cost ONE page, and the third
     * chunk in a second fresh 1 GiB entry costs the second. */
    {
        amdsparse::Arena a = reset(4, 2);          /* exactly 2 free pages */
        amdtx::Segment s[3] = {
            {0x400100100ULL, 64, 0},   /* 1 GiB entry 16 */
            {0x400800100ULL, 64, 0},   /* 1 GiB entry 16 */
            {0x480000100ULL, 64, 0},   /* 1 GiB entry 18 */
        };
        amdtx::CoverResult cr;
        if (!amdtx::coverIdentity(a, limit, s, 3, cr)) printf("A failed why=%s\n", a.why?a.why:"(null)");
        printf("A pages=%u chunks=%u present=%u next=%u\n", cr.pages, cr.chunks, cr.present, a.next);
        CHECK(cr.pages == 2 && cr.chunks == 3);
        CHECK(a.next == 4);
        CHECK(words[512 + gb400] != 0 && words[512 + gb480] != 0);
    }
    /* (B) THE round-20 corruption: three chunks in THREE fresh 1 GiB entries but
     * only two free pages. The call must be refused with no side effect at all --
     * no page consumed, no level-3 entry written. */
    {
        amdsparse::Arena b = reset(4, 2);
        amdtx::Segment s[3] = {
            {0x400100100ULL, 64, 0},
            {0x480000100ULL, 64, 0},
            {0x500000100ULL, 64, 0},
        };
        amdtx::CoverResult cr;
        CHECK(!amdtx::coverIdentity(b, limit, s, 3, cr));
        CHECK(strcmp(b.why, "cover-table-page-budget") == 0);
        CHECK(b.next == 2);                       /* allocation state untouched */
        CHECK(words[512 + gb400] == 0);           /* nothing published */
        CHECK(words[512 + gb480] == 0);
        CHECK(words[512 + gb500] == 0);
        /* and a later, affordable request still succeeds from a clean state */
        amdtx::Segment one[1] = {{0x400100100ULL, 64, 0}};
        CHECK(amdtx::coverIdentity(b, limit, one, 1, cr));
        CHECK(cr.pages == 1 && cr.chunks == 1 && b.next == 3);
    }
    /* (C) three chunks inside ONE 1 GiB entry need a single table page. */
    {
        amdsparse::Arena a = reset(3, 2);          /* exactly 1 free page */
        amdtx::Segment s[3] = {
            {0x400100100ULL, 64, 0},
            {0x400800100ULL, 64, 0},
            {0x400a00100ULL, 64, 0},
        };
        amdtx::CoverResult cr;
        CHECK(amdtx::coverIdentity(a, limit, s, 3, cr));
        CHECK(cr.pages == 1 && cr.chunks == 3);
        CHECK(a.next == 3);
    }
    /* (D) idempotent second call consumes nothing and does not advance next. */
    {
        amdsparse::Arena a = reset(3, 2);
        amdtx::Segment s1[1] = {{0x400100100ULL, 64, 0}};
        amdtx::CoverResult cr;
        CHECK(amdtx::coverIdentity(a, limit, s1, 1, cr));
        CHECK(cr.pages == 1 && cr.chunks == 1);
        const unsigned after1 = a.next;
        CHECK(amdtx::coverIdentity(a, limit, s1, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 0 && cr.present == 1);
        CHECK(a.next == after1);
    }
    /* (E) below the bootstrap limit nothing is touched and nothing is consumed. */
    {
        amdsparse::Arena a = reset(3, 2);
        amdtx::Segment lo[1] = {{0x1000, 4096, 0}};
        amdtx::CoverResult cr;
        CHECK(amdtx::coverIdentity(a, limit, lo, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 0 && cr.present == 0);
        CHECK(a.next == 2);
    }
    printf("cover-identity: %d checks passed\n", checks);
}
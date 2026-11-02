#include "../kext/amd_iommu_tx_core.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
static unsigned checks;
#define CHECK(x) do { assert(x); ++checks; } while(0)
int main() {
    alignas(4096) amdpte::u64 words[8*512] = {};
    amdsparse::Arena a={words,0x100000,8,1,4,0x100000,0,0,nullptr};
    volatile auto *leaves=amdtx::prepare(a);
    CHECK(leaves); CHECK(a.next==4); CHECK(amdtx::prepare(a)==leaves);
    amdtx::Segment s[2]={{0x1234fff,4098,0},{0x98765080,300,0}};
    amdtx::Plan p;
    CHECK(amdtx::plan(p,s,2)); CHECK(p.pages==4);
    CHECK(p.segments[0].iova==amdtx::kBase+4095);
    CHECK(p.segments[1].iova==amdtx::kBase+3*4096+128);
    CHECK(p.physical[0]==0x1234000); CHECK(p.physical[2]==0x1236000);
    CHECK(amdtx::publish(leaves,p)); CHECK(!amdtx::publish(leaves,p));
    for(unsigned j=0;j<p.pages;++j) {
        auto d=amdpte::decodePte(leaves[j],1);
        CHECK(d.outPA==p.physical[j]); CHECK((leaves[j]&amdpte::PTE_IW)==0);
    }
    CHECK(!amdtx::prepare(a));
    amdtx::clear(leaves);
    for(unsigned j=0;j<amdtx::kPages;++j) CHECK(leaves[j]==0);
    s[0].pa=0x2234fff;
    CHECK(amdtx::plan(p,s,1)); CHECK(p.segments[0].iova==amdtx::kBase+4095);
    CHECK(amdtx::publish(leaves,p)); CHECK(amdpte::decodePte(leaves[0],1).outPA==0x2234000);
    amdtx::clear(leaves);
    CHECK(!amdtx::plan(p,s,0)); CHECK(!amdtx::plan(p,s,9));
    s[0].bytes=65536; CHECK(!amdtx::plan(p,s,1));
    s[0].bytes=1; s[0].pa=(1ULL<<52); CHECK(!amdtx::plan(p,s,1));
    s[0].pa=(1ULL<<52)-1; s[0].bytes=2; CHECK(!amdtx::plan(p,s,1));
    s[0].pa=0; CHECK(!amdtx::plan(p,s,1));
    memset(words,0,sizeof(words)); a.next=1; a.pages=1;
    CHECK(!amdtx::prepare(a));
    memset(words,0,sizeof(words)); a.next=1; a.pages=8;
    words[0]=amdpte::makeDefaultLeaf(4,0,amdpte::PTE_IR|amdpte::PTE_IW);
    CHECK(!amdtx::prepare(a));
    memset(words,0,sizeof(words)); a.next=1; a.pages=8; a.rootLevel=3;
    words[0]=amdpte::makeDefaultLeaf(3,0,amdpte::PTE_IR|amdpte::PTE_IW);
    const auto bootstrap=words[0];
    leaves=amdtx::prepare(a); CHECK(leaves); CHECK(a.next==3);
    CHECK(words[0]==bootstrap); // 64GiB subtree never changes bootstrap
    s[0]={0x401234,8192,0}; CHECK(amdtx::plan(p,s,1));
    CHECK(p.pages==3); CHECK(amdtx::publish(leaves,p));
    CHECK(words[0]==bootstrap); amdtx::clear(leaves);

    /* ---- round 20: per-object identity coverage above the bootstrap limit ---- */
    {
        const amdpte::u64 rw2 = amdpte::PTE_IR | amdpte::PTE_IW;
        const amdpte::u64 limit = 0x400000000ULL;   /* 16 GiB */
        auto reset = [&]() {
            memset(words, 0, sizeof(words));
            a = {words, 0x100000, 8, 0, 4, 0x100000, 0, 0, nullptr};
        };
        auto walkPA = [&](amdpte::u64 iova) -> amdpte::u64 {
            amdpte::u64 pa = a.rootPA;
            for (unsigned lvl = 4; lvl >= 1; --lvl) {
                if (pa < a.base || pa - a.base >= sizeof(words)) return 0;
                auto *t = &words[(pa - a.base) / 8];
                auto d = amdpte::decodePte(t[amdpte::indexAt(lvl, iova)], lvl);
                if (lvl == 1) {
                    if (d.kind != amdpte::PTE_LEAF_DEFAULT || d.pageSize != 4096)
                        return 0;
                    return d.outPA + (iova & 4095);
                }
                if (d.kind == amdpte::PTE_TABLE) { pa = d.outPA; continue; }
                if (d.kind == amdpte::PTE_LEAF_DEFAULT) {
                    if (iova - d.outPA >= d.pageSize) return 0;
                    return d.outPA + (iova & (d.pageSize - 1));
                }
                return 0;
            }
            return 0;
        };

        reset();
        words[0] = amdpte::makeTablePde(3, a.base + 4096, rw2);
        words[512 + 0] = amdpte::makeDefaultLeaf(3, 0, rw2);   /* 0..1GiB id */
        a.next = 2;
        amdtx::Segment hi[1] = {{0x400a66000ULL, 74, 0}};
        amdtx::CoverResult cr;
        CHECK(amdtx::coverIdentity(a, limit, hi, 1, cr));
        CHECK(cr.pages == 1 && cr.chunks == 1 && cr.leaves == 0);
        CHECK(a.next == 3);
        CHECK(walkPA(0x400a66000ULL) == 0x400a66000ULL);
        CHECK(walkPA(0x400a67810ULL) == 0x400a67810ULL);
        CHECK(walkPA(0x400000000ULL) == 0);   /* only the used chunk, not 1 GiB */
        /* idempotent: nothing new, the chunk is already identity */
        CHECK(amdtx::coverIdentity(a, limit, hi, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 0 && cr.present == 1);
        CHECK(a.next == 3);
        /* a different chunk in the same 1 GiB entry costs no new table page */
        amdtx::Segment hi2[1] = {{0x400c66000ULL, 4096, 0}};
        CHECK(amdtx::coverIdentity(a, limit, hi2, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 1 && a.next == 3);
        CHECK(walkPA(0x400c66000ULL) == 0x400c66000ULL);
        /* below the bootstrap limit: no chunk at all */
        amdtx::Segment lo[1] = {{0x1000, 4096, 0}};
        CHECK(amdtx::coverIdentity(a, limit, lo, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 0 && cr.present == 0);
        /* an existing non-identity 2 MiB leaf is never papered over */
        reset();
        words[0] = amdpte::makeTablePde(3, a.base + 4096, rw2);
        a.next = 2;
        CHECK(amdtx::coverIdentity(a, limit, hi, 1, cr));
        words[1024 + 5] = amdpte::makeDefaultLeaf(2, 0x400000000ULL, rw2);
        CHECK(!amdtx::coverIdentity(a, limit, hi, 1, cr));
        CHECK(strcmp(a.why, "cover-existing-2m-leaf-not-identity") == 0);
        /* budget exhaustion is explicit, not a silent partial map */
        reset();
        words[0] = amdpte::makeTablePde(3, a.base + 4096, rw2);
        a.next = 2; a.pages = 2;
        CHECK(!amdtx::coverIdentity(a, limit, hi, 1, cr));
        CHECK(strcmp(a.why, "cover-table-page-budget") == 0);
        /* an existing 4 KiB identity subtree is reused, not overwritten */
        reset();
        words[0] = amdpte::makeTablePde(3, a.base + 4096, rw2);
        words[512 + 16] = amdpte::makeTablePde(2, a.base + 8192, rw2);
        words[1024 + 5] = amdpte::makeTablePde(1, a.base + 12288, rw2);
        words[1536 + 102] = amdpte::makeDefaultLeaf(1, 0x400a66000ULL, rw2);
        a.next = 4;
        CHECK(amdtx::coverIdentity(a, limit, hi, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 0 && cr.leaves == 0);
        CHECK(words[1024 + 5] == amdpte::makeTablePde(1, a.base + 12288, rw2));
        /* and a missing 4 KiB page next to it is added at 4 KiB granularity */
        amdtx::Segment hi3[1] = {{0x400a67000ULL, 4096, 0}};
        CHECK(amdtx::coverIdentity(a, limit, hi3, 1, cr));
        CHECK(cr.pages == 0 && cr.chunks == 0 && cr.leaves == 1);
        CHECK(walkPA(0x400a67000ULL) == 0x400a67000ULL);
    }
    printf("tx-domain: %u checks passed\n",checks);
}

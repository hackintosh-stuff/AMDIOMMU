#!/usr/bin/env python3
"""Check DOMID semantics: is DOMID 0 legal for a paging domain?

Evidence gathered from linux/drivers/iommu/amd/:
  iommu.c:1895   return ida_alloc_range(&pdom_ids, 1, MAX_DOMAIN_ID - 1, GFP_ATOMIC);
                 -> Linux NEVER hands out domain id 0.
  iommu.c:2205   if (old_domid) { amd_iommu_flush_tlb_domid(iommu, old_domid); }
                 -> id 0 is treated as "no domain" sentinel.
  set_dte_entry  new->data[1] |= FIELD_PREP(DTE_DOMID_MASK, domid);

This script prints the analysis table so the reasoning is reproducible
instead of living only in prose.
"""

MAX_DOMAIN_ID = 65536  # DTE_DOMID_MASK is GENMASK_ULL(15,0)

def main():
    print("=" * 78)
    print("DOMID analysis for the M2-2b-2 probe")
    print("=" * 78)
    print()
    print("Linux domain-id allocator:")
    print("  ida_alloc_range(&pdom_ids, 1, MAX_DOMAIN_ID - 1, GFP_ATOMIC)")
    print("  -> legal range handed out: 1 .. %d" % (MAX_DOMAIN_ID - 1))
    print("  -> domain id 0 is never allocated to a paging domain")
    print()
    print("Why 0 is special:")
    print("  iommu.c:2205  if (old_domid) { flush_tlb_domid(...) }")
    print("  A zero old_domid skips the flush, i.e. 0 is the 'no previous")
    print("  domain' sentinel, not a real domain identifier.")
    print()
    print("Our probe:")
    print("  m2b2WriteCmd(... INV_IOMMU_PAGES ...)  data[1] low 16 bits = 0")
    print("  DTE data[1] = 0            (domid field = 0)")
    print()
    print("-" * 78)
    print("Two consequences if the hardware honours the same convention:")
    print("-" * 78)
    print("  1. TLB invalidations tagged with domid 0 may be ignored, so stale")
    print("     entries from the passthrough era survive the switch.")
    print("  2. The DTE carrying domid 0 may be treated as 'no domain', which")
    print("     would make translation fail for every DMA of that device.")
    print()
    print("This is a REAL divergence from Linux that we never tested:")
    print("every single M2-2b-2 run used domid 0.")
    print()
    print("Cheap discriminating experiment: keep everything identical but use")
    print("a non-zero domid (e.g. 1) in BOTH the DTE data[1] and the")
    print("INV_IOMMU_PAGES command data[1]. If the device starts working, the")
    print("zero-domid hypothesis is confirmed. If nothing changes, it is")
    print("eliminated at the cost of one reboot.")


if __name__ == "__main__":
    main()

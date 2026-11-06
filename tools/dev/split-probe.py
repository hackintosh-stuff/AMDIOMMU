#!/usr/bin/env python3
"""split-probe.py -- split kext/AMDMapperProbe.cpp into functional modules.

WHY
---
The file had grown to 8,017 lines / 360 KB. Every edit recompiled the whole
probe, a merge conflict touched unrelated subsystems, and "where does the DMA
observation live" had no answer from the file name.

HOW IT WORKS (and why it is safe)
---------------------------------
This script does not rewrite code. It:

  1. locates each function/member definition by its SIGNATURE, not by a
     hand-written line number, so the ranges cannot silently drift;
  2. moves whole line ranges, in original file order, into module files;
  3. puts the shared file-scope helpers into one internal header, keeping them
     `static` / `static inline` so each translation unit gets its own copy --
     exactly as the single file did, with no new global state;
  4. VERIFIES that the modules' bodies concatenate back to the original body
     line for line, and refuses to write anything if they do not.

Point 4 is the important one. A split that merely "compiles" can still have
silently dropped a function, duplicated a comment block, or reordered a static
initialiser. The reconstruction check turns that into a hard failure.

USAGE
-----
    py -3 tools/dev/split-probe.py --dry-run     # report only
    py -3 tools/dev/split-probe.py               # write files
"""
import argparse
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SRC = os.path.join(ROOT, 'kext', 'AMDMapperProbe.cpp')
INTERNAL_NAME = 'AMDMapperProbeInternal.hpp'
INTERNAL = os.path.join(ROOT, 'kext', INTERNAL_NAME)
GUARD = 'AMDMapperProbeInternal_hpp'


def find_line(lines, needle, what):
    for i, ln in enumerate(lines):
        if ln.startswith(needle):
            return i + 1
    raise SystemExit('cannot find %s: %r' % (what, needle))


def block_end(lines, start):
    """1-based line of the closing brace of a braced definition."""
    depth = 0
    started = False
    for i in range(start - 1, len(lines)):
        ln = lines[i]
        if '//' in ln:
            ln = ln[:ln.index('//')]
        if '/*' in ln:
            ln = ln[:ln.index('/*')]
        for ch in ln:
            if ch == '{':
                depth += 1
                started = True
            elif ch == '}':
                depth -= 1
                if started and depth == 0:
                    return i + 1
    raise SystemExit('unbalanced braces starting at line %d' % start)


def leading_comments(lines, start):
    """1-based line of the first comment line attached above `start`.

    Every definition in this file is preceded by a documentation block, often
    separated from the signature by one or more blank lines:

        // ---------------- M2-0b: PCI config space read-only probe
        //
        // why ...
        (blank)
        void org_maz1_AMDMapperProbe::runM20ConfigProbe() {

    Those comments belong to the function, not to the file, so they move with
    it. Blank lines between the comment block and the signature are swallowed
    only when a comment block was actually found above them -- a lone
    separator blank line therefore stays where it was.
    """
    i = start - 2                      # 0-based index of the line above
    first = start
    saw_comment = False
    while i >= 0:
        t = lines[i].strip()
        if t.startswith('//'):
            first = i + 1
            saw_comment = True
            i -= 1
            continue
        # `#pragma clang diagnostic push/ignored/pop` is scoped to a definition
        # (e.g. the IOPCIDevice deprecation suppression around the M2-0 probe).
        # It belongs to that definition, not to the file, so the walk crosses it
        # and keeps looking for the doc block above.
        if t.startswith('#pragma'):
            first = i + 1
            i -= 1
            continue
        if t == '':
            j = i - 1
            while j >= 0 and lines[j].strip() == '':
                j -= 1
            if j >= 0 and (lines[j].strip().startswith('//') or
                           lines[j].strip().startswith('#pragma')):
                i = j
                continue
            if saw_comment:
                # blanks between the comment block and the signature
                i -= 1
                continue
        break
    return first


def statement_end(lines, start):
    """1-based line of a declaration ending in ';'."""
    for i in range(start - 1, len(lines)):
        ln = lines[i]
        if '//' in ln:
            ln = ln[:ln.index('//')]
        if ln.rstrip().endswith(';'):
            return i + 1
    raise SystemExit('no terminating semicolon from line %d' % start)


SHARED = [
    ('static inline IOMapper *probeRawMapper', 'fn', 'probeRawMapper'),
    ('static void setHexProperty', 'fn', 'setHexProperty'),
    ('static void setHexTagged', 'fn', 'setHexTagged'),
    ('static void setStrTagged', 'fn', 'setStrTagged'),
    ('static bool iommuNameMatches', 'fn', 'iommuNameMatches'),
    ('struct ProbeRun {', 'fn', 'struct ProbeRun'),
    ('static ProbeRun probeSegmentRun', 'fn', 'probeSegmentRun'),
    ('static const char *kNicPaths[]', 'array', 'kNicPaths'),
    ('#define M21_MMIO_BASE', 'macrorun', 'M2-1 MMIO constants'),
    ('#define M22B_DTE_SIZE', 'macrorun', 'DTE and device-table constants'),
    ('#define M2B2_PAGE_MODE_4_LEVEL', 'macrorun',
     'M2-2b-2 page-table constants'),
    ('#define M23_CMD_BUF_SIZE', 'macrorun', 'M2-3 command-ring constants'),
    ('#define M2B1_CMD_COMPL_WAIT', 'macrorun_to_fn', 'M2-1 command macros + writeCmd'),
    ('#define M2B2_CMD_LOG_MAX', 'macrorun', 'M2-2b-1 command-log bounds'),
    ('static inline UInt64 mmioRead64', 'fn', 'mmioRead64'),
    ('static inline UInt32 mmioRead32', 'fn', 'mmioRead32'),
    ('static inline void mmioWrite64', 'fn', 'mmioWrite64'),
    ('static inline void mmioWrite32', 'fn', 'mmioWrite32'),
    ('static bool parseMmioBootArg();', 'declrun', 'boot-arg forward declarations'),
    ('static inline UInt64 m2b2SmallLeaf', 'fn', 'm2b2SmallLeaf'),
    ('static inline UInt64 m2b2LargeLeaf', 'fn', 'm2b2LargeLeaf'),
    ('static inline UInt64 m2b2TablePte', 'fn', 'm2b2TablePte'),
    ('static inline void m2b2WriteCmd', 'fn', 'm2b2WriteCmd'),
    ('static inline UInt64 m2b2InvAddress', 'fn', 'm2b2InvAddress'),
    ('#define M2B2_MEAS_SECS', 'constline', 'M2B2 measurement window'),
    ('static inline UInt64 m2b2NowNS', 'fn', 'm2b2NowNS'),
    ('static UInt64 m2b2ToMS', 'fn', 'm2b2ToMS'),
    ('static UInt64 m2b2WallSecs', 'fn', 'm2b2WallSecs'),
    ('struct M2b2PostSample {', 'fn', 'struct M2b2PostSample'),
    ('struct M2B2CmdRecord {', 'fn', 'struct M2B2CmdRecord'),
    ('struct M2B2CmdCtx {', 'fn', 'struct M2B2CmdCtx'),
    ('static bool m2b2ResetEventLog', 'fn', 'm2b2ResetEventLog'),
    ('static void m2b2DoPostSample', 'fn', 'm2b2DoPostSample'),
    ('static void m2b2SampleEvents', 'fn', 'm2b2SampleEvents'),
    ('static const char *m2b2EventTypeName', 'fn', 'm2b2EventTypeName'),
    ('static bool m2b2Submit', 'fn', 'm2b2Submit'),
    ('static bool m2b2ReadBar64', 'fn', 'm2b2ReadBar64'),
    ('static const UInt32 kObsFetchMaxTries', 'const2', 'obs fetch bounds'),
    ('static IOService *m2b2FindObsService', 'fn', 'm2b2FindObsService'),
    ('static OSData *m2b2CopyObsSnapshot', 'fn', 'm2b2CopyObsSnapshot'),
    ('static UInt32 m2b2ObsPubIdOf', 'fn', 'm2b2ObsPubIdOf'),
    ('static bool parseM22b2Delay(uint32_t *outMS);', 'decl', 'parseM22b2Delay decl'),
    ('static bool parseM22b2Delay(uint32_t *outMS) {', 'fn', 'parseM22b2Delay'),
    ('static bool parseArmBootArg()', 'fn', 'parseArmBootArg'),
    ('static bool parseMmioBootArg() {', 'block_until', 'boot-arg parsers'),
]

# This remains the historical monolith migration tool, not a generator for
# today's independently maintained modules. MEMBERS also records their owner;
# src/Ivrs*.cpp are reused library units registered directly in build-m1a.sh.
MEMBERS = [
    ('AMDMapperProbe.cpp', 'entry point, IOMapper contract, kmod glue', [
        'bool org_maz1_AMDMapperProbe::initHardware',
        'bool org_maz1_AMDMapperProbe::init(',
        'bool org_maz1_AMDMapperProbe::start',
        'void org_maz1_AMDMapperProbe::stop',
        'IOReturn org_maz1_AMDMapperProbe::callPlatformFunction',
        'IOReturn org_maz1_AMDMapperProbe::iovmMapMemory',
        'IOReturn org_maz1_AMDMapperProbe::iovmUnmapMemory',
        'IOReturn org_maz1_AMDMapperProbe::iovmInsert',
        'uint64_t org_maz1_AMDMapperProbe::getPageSize',
        'uint64_t org_maz1_AMDMapperProbe::mapToPhysicalAddress',
    ]),
    ('AMDMapperProbeNic.cpp', 'NIC discovery, publish notifier, arming', [
        'bool org_maz1_AMDMapperProbe::findTarget',
        'bool org_maz1_AMDMapperProbe::publishHandler',
        'bool org_maz1_AMDMapperProbe::armNic',
        'void org_maz1_AMDMapperProbe::installPublishNotifier',
        'bool org_maz1_AMDMapperProbe::findNic(',
        'IOService *org_maz1_AMDMapperProbe::findNicServiceOnly',
    ]),
    ('AMDMapperProbeAuto.cpp', 'persistent per-device hardware lifecycle', [
        'bool org_maz1_AMDMapperProbe::StartAuto',
        'bool org_maz1_AMDMapperProbe::AttachAuto',
        'bool org_maz1_AMDMapperProbe::StopAuto',
        'bool org_maz1_AMDMapperProbe::Invalidate',
        'bool org_maz1_AMDMapperProbe::SuspendAuto',
        'bool org_maz1_AMDMapperProbe::ResumeAuto',
        'void org_maz1_AMDMapperProbe::PublishAuto',
    ]),
    ('AMDMapperProbeDiscovery.cpp', 'runtime IVRS and PCI controller discovery', [
        'bool DiscoverHardware',
    ]),
    ('AMDMapperProbeMapper.cpp', 'ordinary IOMapper allocation and translation', [
        'bool org_maz1_AMDMapperProbe::PrepareMappings',
        'bool org_maz1_AMDMapperProbe::QuiesceMappings',
        'bool org_maz1_AMDMapperProbe::ReleaseMappings',
        'UInt32 org_maz1_AMDMapperProbe::LiveMappings',
        'IOReturn org_maz1_AMDMapperProbe::MapMemory',
        'IOReturn org_maz1_AMDMapperProbe::UnmapMemory',
        'bool org_maz1_AMDMapperProbe::Translate',
        'IOReturn org_maz1_AMDMapperProbe::PowerTransition',
        'void org_maz1_AMDMapperProbe::PublishMappings',
    ]),
    ('AMDMapperProbeMapperBindingDebug.cpp', 'M1 B1: target device names our mapper', [
        'void org_maz1_AMDMapperProbe::runB1SelfTest',
    ]),
    ('AMDMapperProbeDmaContractDebug.cpp', 'M1 B2: IODMACommand contract through our mapper', [
        'void org_maz1_AMDMapperProbe::runB2SelfTest',
    ]),
    ('AMDMapperProbeContigMapDebug.cpp', 'M1 B2-a: contiguous maps, fragmented rejects', [
        'void org_maz1_AMDMapperProbe::runB2OneTest',
        'void org_maz1_AMDMapperProbe::runB2aSelfTest',
    ]),
    ('AMDMapperProbeMapTableDebug.cpp', 'M1 B2-b: active mapping table and statistics', [
        'org_maz1_AMDMapperProbe::MapEntry *',
        'bool org_maz1_AMDMapperProbe::freeMapEntry',
        'uint32_t org_maz1_AMDMapperProbe::usedMapEntries',
        'void org_maz1_AMDMapperProbe::publishB2bStats',
        'void org_maz1_AMDMapperProbe::publishMapStats',
    ]),
    ('AMDMapperProbeMmioDebug.cpp', 'M2-0/1/2a-1 MMIO read and write probes', [
        'void org_maz1_AMDMapperProbe::runM20ConfigProbe',
        'void org_maz1_AMDMapperProbe::runM21MmioProbe',
        'void org_maz1_AMDMapperProbe::runM22aWriteProbe',
    ]),
    ('AMDMapperProbeTableDebug.cpp', 'M2-2a-2/2a-3 device table, enable, cmd channel', [
        'void org_maz1_AMDMapperProbe::runM22bTableProbe',
        'void org_maz1_AMDMapperProbe::runM23EnableProbe',
        'void org_maz1_AMDMapperProbe::runM2b1CmdProbe',
    ]),
    ('AMDMapperProbeDmaDebug.cpp', 'DMA observation: rings, segments, event log', [
        'bool org_maz1_AMDMapperProbe::m2b2ReadCloPtr',
        'bool org_maz1_AMDMapperProbe::m2b2ReadTailPtr',
        'void org_maz1_AMDMapperProbe::m2b2CollectTxSegments',
        'void org_maz1_AMDMapperProbe::m2b2CollectRxSegments',
        'void org_maz1_AMDMapperProbe::m2b2ScanTxWindowAfter',
        'void org_maz1_AMDMapperProbe::m2b2PublishDmaDefaults',
        'void org_maz1_AMDMapperProbe::observeDeviceDma',
    ]),
    ('AMDMapperProbeObsDebug.cpp', 'driver observation log (wire v2) reader', [
        'UInt32 org_maz1_AMDMapperProbe::m2b2ReadDeclaredBatch',
        'int org_maz1_AMDMapperProbe::m2b2ScanTxDone',
        'void org_maz1_AMDMapperProbe::m2b2CaptureNicIdentity',
        'void org_maz1_AMDMapperProbe::m2b2ReadDriverObs',
    ]),
    ('AMDMapperProbePgtDebug.cpp', 'M2-2b-2 page-table experiment', [
        'bool org_maz1_AMDMapperProbe::scheduleM22b2',
        'void org_maz1_AMDMapperProbe::m22b2TimerFired',
        'void org_maz1_AMDMapperProbe::runM22b2PageTableProbe',
    ]),
]

PROLOGUE_FIRST = '#include "AMDMapperProbe.hpp"'
PROLOGUE_LAST = '#endif'
METACLASS_FIRST = '#define super IOMapper'
METACLASS_LAST = 'OSDefineMetaClassAndStructors(org_maz1_AMDMapperProbe, IOMapper);'
# The kmod trailer must appear in exactly one translation unit.
KMOD_FIRST = 'extern "C" {'
KMOD_LAST = '}'
KMOD_OWNER = 'AMDMapperProbe.cpp'


# Module-local macro blocks that must travel with their module.
#
# A #define is not part of any function body, so the reconstruction check
# (which compares function bodies) is blind to one being dropped. These are
# pinned explicitly; the compiler is the thing that catches a miss.
# Module-local blocks pinned to their module. Banners are added
# automatically below (see AUTO_BANNER_OWNERS); this list is for #define blocks
# and similar that have no banner of their own.
EXTRA_OWNED = [
    ('AMDMapperProbeMmioDebug.cpp', '#define M22_OFF_DEV_TABLE',
     'M2-2a-1 write constants'),
]

# Section banners are NOT listed by hand: a banner belongs to whichever module
# owns the next function definition below it. Deriving this avoids the mistake
# of assigning a banner by its text (B1 was once sent to the NIC module that
# way, which silently moved a whole section).
BANNER_RE = r'^// -{20,}'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dry-run', action='store_true')
    args = ap.parse_args()

    lines = open(SRC, encoding='utf-8').read().split('\n')
    total = len(lines)
    print('source: %d lines, %d bytes' % (total, os.path.getsize(SRC)))
    print()

    claims = {}

    def claim(a, b, who):
        for i in range(a, b + 1):
            if i in claims:
                raise SystemExit('line %d claimed twice: %s and %s'
                                 % (i, claims[i], who))
            claims[i] = who

    inc_a = find_line(lines, PROLOGUE_FIRST, 'first include')
    # The prologue ends at the first column-0 `#endif` after the includes:
    # that closes the IOKIT_ENABLE_SHARED_PTR feature check.
    inc_b = None
    for i in range(inc_a, len(lines)):
        if lines[i].startswith('#endif'):
            inc_b = i + 1
            break
    if inc_b is None:
        raise SystemExit('cannot find the prologue #endif')
    claim(inc_a, inc_b, 'prologue-includes')

    mc_a = find_line(lines, METACLASS_FIRST, 'super macro')
    mc_b = find_line(lines, METACLASS_LAST, 'metaclass glue')
    claim(mc_a, mc_b, 'metaclass-glue')

    # The kmod trailer is the LAST `extern "C" {` in the file.
    km_a = None
    for i, ln in enumerate(lines):
        if ln.startswith(KMOD_FIRST):
            km_a = i + 1
    if km_a is None:
        raise SystemExit('cannot find the kmod trailer')
    km_b = block_end(lines, km_a)
    claim(km_a, km_b, 'kmod-trailer')

    shared_ranges = []
    for sig, kind, name in SHARED:
        a = find_line(lines, sig, name)
        if kind == 'fn':
            b = block_end(lines, a)
        elif kind == 'block_until':
            # Up to (but not including) the next member definition.
            b = a
            for j in range(a, len(lines)):
                if lines[j].startswith('bool org_maz1_AMDMapperProbe::') or \
                   lines[j].startswith('void org_maz1_AMDMapperProbe::') or \
                   lines[j].startswith('IOReturn org_maz1_AMDMapperProbe::'):
                    b = j          # 1-based line of that definition is j+1
                    break
            else:
                b = len(lines)
        elif kind == 'declrun':
            # A run of forward declarations separated by comments. Extend while
            # the next non-blank, non-comment line is still a declaration.
            b = statement_end(lines, a)
            while True:
                j = b
                while j < len(lines) and (lines[j].strip() == '' or
                                          lines[j].strip().startswith('//')):
                    j += 1
                if j < len(lines) and lines[j].startswith('static bool parse'):
                    b = statement_end(lines, j + 1)
                else:
                    break
        elif kind == 'constline':
            # Exactly this one line (plus its doc block, pulled in below by
            # leading_comments). Used for a lone constant that must not absorb
            # the comment block belonging to the next helper.
            b = a
        elif kind == 'macrorun':
            # A run of #define lines, optionally introduced by a comment
            # banner. Comments and blank lines inside the run are part of it;
            # the run ends at the last #define it contains.
            b = a
            # skip the banner to the first #define
            while b < len(lines) and not lines[b].strip().startswith('#define'):
                if lines[b].strip().startswith('//') or lines[b].strip() == '':
                    b += 1
                else:
                    break
            last_define = b
            while b < len(lines):
                t = lines[b].strip()
                if t.startswith('#define'):
                    # Follow backslash continuations. The check must look at
                    # the line just consumed (b), not b-1 after incrementing,
                    # or the last continuation line is left behind.
                    while b < len(lines):
                        consumed = lines[b]
                        b += 1
                        if not consumed.rstrip().endswith(chr(92)):
                            break
                    last_define = b
                elif t == '' or t.startswith('//'):
                    b += 1
                else:
                    break
            b = last_define
        elif kind == 'macrorun_to_fn':
            # A run of #define lines followed by a small inline function; they
            # form one logical unit (the command-ring helpers).
            b = a
            while b < len(lines):
                t = lines[b].strip()
                if t.startswith('#define'):
                    while b < len(lines):
                        consumed = lines[b]
                        b += 1
                        if not consumed.rstrip().endswith(chr(92)):
                            break
                elif t == '' or t.startswith('//'):
                    b += 1
                else:
                    break
            # now at the function definition
            if b < len(lines):
                b = block_end(lines, b + 1)
        elif kind == 'const2':
            # Two consecutive constant declarations: take both.
            b = statement_end(lines, a)
            b2 = statement_end(lines, b + 1)
            b = b2
        else:
            b = statement_end(lines, a)
        # Pull in the doc block directly above, so it travels with the code.
        a2 = leading_comments(lines, a)
        shared_ranges.append((a2, b, kind, name))
        claim(a2, b, 'shared:' + name)

    member_ranges = []
    for fn, desc, sigs in MEMBERS:
        for sig in sigs:
            try:
                a = find_line(lines, sig, sig)
            except SystemExit:
                if sig.endswith('::init('):
                    continue
                raise
            b = block_end(lines, a)
            a2 = leading_comments(lines, a)
            member_ranges.append((fn, desc, a2, b, sig))
            claim(a2, b, fn)

    print('%-32s %6s  %s' % ('module', 'lines', 'role'))
    print('-' * 80)
    n_shared = sum(b - a + 1 for a, b, _k, _n in shared_ranges)
    print('%-32s %6d  shared helpers + forward declarations'
          % (INTERNAL_NAME, n_shared))
    for fn, desc, _sigs in MEMBERS:
        n = sum(b - a + 1 for m, _d, a, b, _s in member_ranges if m == fn)
        print('%-32s %6d  %s' % (fn, n, desc))
    print()

    out = []
    out.append('// %s -- helpers shared by the probe modules.' % INTERNAL_NAME)
    out.append('//')
    out.append('// GENERATED by tools/dev/split-probe.py from the original single-file')
    out.append('// AMDMapperProbe.cpp. Everything here was a file-scope `static` in that')
    out.append('// file. It stays `static` / `static inline`, so each translation unit')
    out.append('// gets its own copy exactly as before: no new global state is introduced')
    out.append('// and there is no cross-module ODR coupling.')
    out.append('//')
    out.append('// To change one of these, change it here -- this is the single')
    out.append('// definition every module sees.')
    out.append('')
    out.append('#ifndef %s' % GUARD)
    out.append('#define %s' % GUARD)
    out.append('')
    out.append('#include "AMDMapperProbe.hpp"')
    out.append('#include <IOKit/IOBufferMemoryDescriptor.h>')
    out.append('#include <IOKit/IOTimerEventSource.h>')
    out.append('#include <IOKit/IOWorkLoop.h>')
    out.append('')
    out.append('// IOPCIDevice is deprecated in this SDK. The suppression is scoped to the')
    out.append('// include: this kext must be an in-kernel IOMapper subclass, and PCIDriverKit')
    out.append('// (a user-space framework) cannot provide one.')
    out.append('#pragma clang diagnostic push')
    out.append('#pragma clang diagnostic ignored "-Wdeprecated-declarations"')
    out.append('#pragma clang diagnostic ignored "-Winconsistent-missing-override"')
    out.append('#include <IOKit/pci/IOPCIDevice.h>')
    out.append('#pragma clang diagnostic pop')
    out.append('')
    out.append('#include <pexpert/pexpert.h>')
    out.append('#include <mach/kmod.h>')
    out.append('#include <mach/mach_time.h>')
    out.append('#include <kern/clock.h>')
    out.append('#include <libkern/OSByteOrder.h>')
    out.append('#include "amd_iommu_pte_core.hpp"')
    out.append('')
    out.append('#if defined(IOKIT_ENABLE_SHARED_PTR)')
    out.append('    #define M1A_HAS_SHARED_PTR 1')
    out.append('#else')
    out.append('    #define M1A_HAS_SHARED_PTR 0')
    out.append('#endif')
    out.append('')
    for a, b, kind, name in shared_ranges:
        body = lines[a - 1:b]
        # A standalone `#pragma clang diagnostic pop` closes a push that lives
        # inside a MODULE's function body. Copying it into the shared header
        # would leave every including module with an unmatched pop. Drop it
        # here; the owning module still carries it at the end of its function.
        if any(ln.strip() == '#pragma clang diagnostic pop' for ln in body):
            body = [ln for ln in body
                    if ln.strip() != '#pragma clang diagnostic pop']
            if not any(ln.strip() for ln in body):
                continue
        out.append('// ---- %s (original lines %d..%d) ----' % (name, a, b))
        # Promote EVERY file-scope `static` function in the header to
        # `static inline`, regardless of which rule adopted it.
        #
        # WHY: the header is included by all eight modules, but each helper is
        # called by only some of them. A plain `static` definition that a
        # module never calls trips -Wunused-function, and this project builds
        # with -Werror. `static inline` gives each translation unit its own
        # copy (so there is still no cross-module state or ODR coupling) while
        # telling the compiler that an unused copy is expected.
        #
        # Deciding this by CONTENT rather than by `kind` matters: a helper can
        # be adopted by the macro-run or block rules, and those paths used to
        # skip the promotion, which is exactly how ten -Wunused-function errors
        # appeared after the first successful split.
        for ln in body:
            if re.match(r'^static\s+(?!inline)', ln) and \
                    ('(' in ln or ln.rstrip().endswith('{')):
                ln = re.sub(r'^static\s+', 'static inline ', ln, count=1)
            out.append(ln)
        out.append('')
    out.append('#endif /* %s */' % GUARD)
    out.append('')
    internal_text = '\n'.join(out)

    prologue_text = '\n'.join(lines[inc_a - 1:inc_b])
    metaclass_text = '\n'.join(lines[mc_a - 1:mc_b])


    # Pin module-local macro blocks to their module, AFTER every other pass.
    #
    # A #define is not part of a function body, so the reconstruction check is
    # blind to one being dropped -- the compiler is what catches that. Running
    # this last means the catch-all sweep cannot reassign the lines again.
    for owner_fn, first_line, label in EXTRA_OWNED:
        a = find_line(lines, first_line, label)
        b = a
        # Walk forward over comments, blanks and #define lines. Stop at the
        # first real statement (a function definition).
        while b < len(lines):
            t = lines[b].strip()
            if t.startswith('#define') or t == '' or t.startswith('//') \
                    or t.startswith('#'):
                b += 1
            else:
                break
        while b > a and lines[b - 1].strip() == '':
            b -= 1
        for k in range(a, b + 1):
            claims[k] = owner_fn
        print('  pinned %s lines %d..%d -> %s' % (label, a, b, owner_fn))

    # Attach every unowned #define run to the module that owns the NEXT function
    # definition below it. These are module-local constants; leaving them to the
    # catch-all sweep put M23_*/M22B_*/DTE_* in the wrong module and only the
    # compiler noticed.
    for i, ln in enumerate(lines, 1):
        if not ln.strip().startswith('#define'):
            continue
        if i in claims:
            # Already owned (by a module OR by the shared header). The shared
            # header is the correct home for a constant the helpers use.
            continue
        # find the next claimed line that belongs to a module
        j = i
        owner = None
        while j < total:
            j += 1
            if j in claims and not claims[j].startswith('shared:'):
                owner = claims[j]
                break
        if owner is None:
            continue
        # Claim this contiguous run of #define/comment/blank lines, but ONLY
        # the ones nobody owns yet. An earlier pass (the shared header) may
        # already have taken some of them, and silently overwriting that
        # produced duplicate macro definitions.
        k = i
        while k < total:
            t = lines[k - 1].strip()
            if t.startswith('#define') or t == '' or t.startswith('//') \
                    or t.startswith('#'):
                if k not in claims:
                    claims[k] = owner
                k += 1
            else:
                break

    # Attach each section banner to the module that owns the NEXT function
    # definition below it. This is derived, not listed, so it cannot drift.
    import re as _re
    banner_re = _re.compile(BANNER_RE)
    for i, ln in enumerate(lines, 1):
        if not banner_re.match(ln):
            continue
        # find the next claimed line that belongs to a module
        j = i
        owner = None
        while j < total:
            j += 1
            if j in claims and not claims[j].startswith('shared:'):
                owner = claims[j]
                break
        if owner is None:
            continue
        # Claim the banner run (comments/blanks) down to that line, again only
        # where nobody has claimed already.
        k = i
        while k < j:
            t = lines[k - 1].strip()
            if t == '' or t.startswith('//') or t.startswith('#'):
                if k not in claims:
                    claims[k] = owner
                k += 1
            else:
                break


    # Rebuild member ranges from the final `claims` map.
    #
    # The attachment passes above extend ownership of comment banners and
    # blank lines to the block they introduce. `member_ranges` was computed
    # before that, so emitting from it would drop exactly the lines the passes
    # adopted -- which is what the reconstruction check caught. Recomputing
    # min/max per owner makes the emitted files and the check agree by
    # construction.
    owner_lines = {}
    for line_no, owner in claims.items():
        owner_lines.setdefault(owner, []).append(line_no)

    # Split each owner's lines into CONTIGUOUS runs. Using min/max alone would
    # span the gaps between a module's functions and swallow every other
    # module's code in between -- which is why the module body count exploded.
    def contiguous_runs(owned):
        runs = []
        run = [owned[0]]
        for x in owned[1:]:
            if x == run[-1] + 1:
                run.append(x)
            else:
                runs.append((run[0], run[-1]))
                run = [x]
        runs.append((run[0], run[-1]))
        return runs

    member_ranges = []
    for fn, desc, sigs in MEMBERS:
        owned = sorted(owner_lines.get(fn, []))
        if not owned:
            continue
        for a, b in contiguous_runs(owned):
            member_ranges.append((fn, desc, a, b, fn))

    # Shared helpers likewise: emit contiguous runs of their owned lines.
    shared_ranges = []
    for sig, kind, name in SHARED:
        owned = sorted(owner_lines.get('shared:' + name, []))
        if not owned:
            continue
        for a, b in contiguous_runs(owned):
            shared_ranges.append((a, b, kind, name))
    shared_ranges.sort()

    for fn, _d, _s in MEMBERS:
        rs = [(a, b) for m, _dd, a, b, _ss in member_ranges if m == fn]
        tot = sum(b - a + 1 for a, b in rs)
        print('  cover %-32s %4d lines in %2d run(s): %s'
              % (fn, tot, len(rs), rs[:6]))

    produced = {}
    for fn, desc, _sigs in MEMBERS:
        parts = ['// %s -- %s' % (fn, desc),
                 '//',
                 '// Part of the AMDMapperProbe kext. Split out of the original',
                 '// single-file AMDMapperProbe.cpp by tools/dev/split-probe.py; the',
                 '// function bodies are unchanged and in their original order.',
                 '',
                 prologue_text,
                 '',
                 '#include "%s"' % INTERNAL_NAME,
                 '']
        if fn == 'AMDMapperProbe.cpp':
            parts.extend([metaclass_text, ''])
        for m, _d, a, b, sig in member_ranges:
            if m != fn:
                continue
            parts.append('// ===== %s (original lines %d..%d) =====' % (sig, a, b))
            # Skip any line that was reassigned to the shared header (a macro
            # promoted there must not be redefined here) or to another module.
            body = [lines[i - 1] for i in range(a, b + 1)
                    if claims.get(i) == fn]
            parts.extend(body)
            parts.append('')
        if fn == KMOD_OWNER:
            parts.append('// ===== kmod trailer (original lines %d..%d) ====='
                         % (km_a, km_b))
            parts.extend(lines[km_a - 1:km_b])
            parts.append('')
        produced[fn] = '\n'.join(parts)
    produced[INTERNAL_NAME] = internal_text

    # Report any line that no rule claimed BEFORE attempting reconstruction:
    # an unclaimed comment block is exactly the kind of thing that makes the
    # reconstruction fail with a confusing "first difference" message.
    # A `#pragma clang diagnostic pop` that closes a `push` opened INSIDE a
    # definition is part of that definition's tail. The push lives at the top
    # of runM20ConfigProbe(); the pop lands right after its closing brace.
    # Leaving the pop behind would strip a suppression the module still needs.
    #
    # It must NEVER be adopted by a shared-helper banner: putting a pop in the
    # internal header leaves every including module with an unmatched pop
    # ("could not pop, no matching push") because the matching push is inside
    # one module's function body. So attach pops to the preceding block only,
    # and only when that block is a member function (not a shared helper).
    for i in range(1, total + 1):
        if i not in claims and lines[i - 1].strip().startswith('#pragma') \
                and (i - 1) in claims:
            owner = claims[i - 1]
            if not owner.startswith('shared:'):
                claims[i] = owner

    # Absorb trailing blank lines into the block above them. Without this the
    # split leaves a scattering of orphan blank lines, and the reconstruction
    # check (which ignores blanks) would pass while the files still had holes.
    for i in range(1, total):
        if i not in claims and lines[i - 1].strip() == '' and (i - 1) in claims:
            claims[i] = claims[i - 1]

    # Attach orphan comment banners to the definition BELOW them.
    #
    # A banner looks like:
    #     // ------------------------------ M2-2a-1：最小 MMIO 写测试
    #     (blank)
    #     void org_maz1_AMDMapperProbe::runM22aWriteProbe() {
    # It introduces the code beneath it, so it belongs to that block. Walking
    # forward over unclaimed comments and blanks, and stopping at the first
    # claimed line, gives exactly that.
    i = 1
    while i <= total:
        if i in claims:
            i += 1
            continue
        # Start of an orphan run: a maximal sequence of unclaimed lines that
        # are blank, comments, or preprocessor directives. All three kinds are
        # "attached to the code below": a banner, a doc block, and the module's
        # own #define constants.
        j = i
        while j <= total and j not in claims:
            t = lines[j - 1].strip()
            if t == '' or t.startswith('//') or t.startswith('#'):
                j += 1
            else:
                break
        if j > i and j <= total and j in claims:
            owner = claims[j]
            for k in range(i, j):
                claims[k] = owner
        # ALWAYS advance. Setting i = j does not move when j == i (an
        # unclaimed line that is none of the three kinds), which spun forever.
        i = j if j > i else i + 1

    # Final sweep: attach every remaining all-comment/blank run to the nearest
    # claimed line, preferring the next one. This is a catch-all so that a new
    # banner or doc block added later cannot silently break the split; it never
    # moves code, only comment lines.
    i = 1
    while i <= total:
        if i in claims:
            i += 1
            continue
        j = i
        while j <= total and j not in claims:
            t = lines[j - 1].strip()
            if t == '' or t.startswith('//') or t.startswith('#'):
                j += 1
            else:
                break
        # j is now the first non-absorbable line (or past the end)
        if j > i:
            if j <= total and j in claims:
                owner = claims[j]
            else:
                # fall back to the nearest claimed line above
                k = i - 1
                while k >= 1 and k not in claims:
                    k -= 1
                owner = claims.get(k)
            if owner:
                for k2 in range(i, j):
                    claims[k2] = owner
        i = j if j > i else i + 1
    unclaimed = [i for i in range(1, total + 1) if i not in claims]
    if unclaimed:
        gaps = []
        run = [unclaimed[0]]
        for x in unclaimed[1:]:
            if x == run[-1] + 1:
                run.append(x)
            else:
                gaps.append((run[0], run[-1]))
                run = [x]
        gaps.append((run[0], run[-1]))
        print('UNCLAIMED line ranges (every line must belong to a rule):')
        for a, b in gaps:
            print('  %5d..%-5d  %s' % (a, b, lines[a - 1].strip()[:70]))
        return 1

    skip = set()
    for a, b in [(inc_a, inc_b), (mc_a, mc_b)]:
        for i in range(a, b + 1):
            skip.add(i)
    for a, b, _k, _n in shared_ranges:
        for i in range(a, b + 1):
            skip.add(i)

    # Verification, derived from the SAME final `claims` map the emitter uses.
    #
    # expected: every claimed line that belongs to a module (i.e. not prologue,
    #           not metaclass, not a shared helper)
    # actual  : every line covered by the ranges that were actually emitted
    #
    # If the two differ, the emitter and the ownership map have diverged --
    # which is exactly the bug class this check exists to catch.
    module_owners = {fn for fn, _d, _s in MEMBERS}
    expected_lines = sorted(i for i, owner in claims.items()
                            if owner in module_owners)
    actual_lines = set()
    for m, _d, a, b, _s in member_ranges:
        for i in range(a, b + 1):
            if claims.get(i) == m:
                actual_lines.add(i)
    actual_lines = sorted(actual_lines)

    original_body = [lines[i - 1] for i in expected_lines
                     if lines[i - 1].strip() != '']
    module_body = [lines[i - 1] for i in actual_lines
                   if lines[i - 1].strip() != '']

    if module_body != original_body:
        print('VERIFY FAILED: module bodies do not reconstruct the original')
        for i, (x, y) in enumerate(zip(original_body, module_body)):
            if x != y:
                print('  first difference at body line %d' % i)
                print('    original: %r' % x[:100])
                print('    module  : %r' % y[:100])
                break
        print('  counts: original %d, modules %d'
              % (len(original_body), len(module_body)))
        return 1
    print('verify: %d body lines reconstruct the original exactly OK'
          % len(original_body))
    print()

    if args.dry_run:
        print('dry run: nothing written')
        return 0

    for fn, text in produced.items():
        path = os.path.join(ROOT, 'kext', fn)
        with open(path, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        print('wrote %-34s %7d bytes' % (fn, len(text.encode('utf-8'))))
    return 0


if __name__ == '__main__':
    sys.exit(main())

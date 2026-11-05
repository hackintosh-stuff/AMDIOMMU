"""Add IPv6 TSO to the accepted ordinary mapped TX observation path.

Reuse R45's counter type and actual post/retire methods, selecting the counter
set from the descriptor's GiantSendv4/v6 bit. Mapping, admission and completion
keep their accepted behavior; no additional queue or ownership path is added.
"""
from pathlib import Path
import runpy

BASE = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'r45/driver-template.py'))

MEMBERS = '''
    /* Round46: independent IPv6 counters, retained across interface down/up. */
    R45TsoStats r46Tso;
    void r46PublishTSO();
    static IOReturn r46SnapshotAction(OSObject *, void *, void *, void *, void *);
'''

METHODS = r'''
void RTL8125::r46PublishTSO()
{
    if (!r44NormalMapped) return;
    /* Sample both families through the same gate; R45 property names remain
     * stable and continue to report the IPv4 counters and shared resources. */
    r45PublishTSO();
#define R46_PROP(name, member) \
    setProperty("rtl812x-r46-tso6-" name, \
        __atomic_load_n(&r46Tso.member, __ATOMIC_ACQUIRE), 64)
    R46_PROP("posted", posted);
    R46_PROP("completed", completed);
    R46_PROP("stop-retired", stopRetired);
    R46_PROP("posted-bytes", postedBytes);
    R46_PROP("completed-bytes", completedBytes);
    R46_PROP("max-length", maxLength);
    R46_PROP("max-segments", maxSegments);
    R46_PROP("max-mss", maxMss);
#undef R46_PROP
    setProperty("rtl812x-r46-snapshot-seq", ++r46Tso.snapshotSequence, 64);
}

IOReturn RTL8125::r46SnapshotAction(OSObject *owner, void *, void *, void *, void *)
{
    RTL8125 *me = OSDynamicCast(RTL8125, owner);
    if (!me || !me->r44NormalMapped) return kIOReturnNotReady;
    me->r46PublishTSO();
    return kIOReturnSuccess;
}
'''


def base_method(name, following):
    text = BASE['METHODS']
    start = text.index('void RTL8125::' + name + '(')
    end = text.index('void RTL8125::' + following + '(', start)
    return text[start:end]


SELECT = '''    R45TsoStats *stats = (command & GiantSendv4) ? &r45Tso :
        ((command & GiantSendv6) ? &r46Tso : NULL);
    if (!r44NormalMapped || !stats) return;'''
POST_OLD = base_method('r45Tso4PostedPacket', 'r45Tso4RetiredPacket')
RETIRE_OLD = base_method('r45Tso4RetiredPacket', 'r45PublishTSO')


def dispatch(body):
    return body.replace('if (!r44NormalMapped || !(command & GiantSendv4)) return;',
                        SELECT.strip()).replace('&r45Tso.', '&stats->')


RPC_OLD = '    OSObject *request = dict ? dict->getObject("R45Snapshot") : NULL;'
RPC_NEW = '''    OSObject *request = dict ? dict->getObject("R46Snapshot") : NULL;
    const bool round46 = request != NULL;
    if (!request) request = dict ? dict->getObject("R45Snapshot") : NULL;'''
ACTION_OLD = '    return commandGate->runAction(r45SnapshotAction);'
ACTION_NEW = '    return commandGate->runAction(round46 ? r46SnapshotAction : r45SnapshotAction);'
INIT_OLD = '        bzero(&r45Tso, sizeof(r45Tso));\n'
INIT_NEW = '        bzero(&r46Tso, sizeof(r46Tso));\n' + INIT_OLD
DISABLE_OLD = BASE['DISABLE_NEW']
DISABLE_NEW = DISABLE_OLD.replace('r45PublishTSO();', 'r46PublishTSO();')
SUM_OLD = '''    for (i = 0; i < 16; i++) {
        csum32 += ntohs(ip6Hdr->ip6_src.__u6_addr.__u6_addr16[i]);
        csum32 += (csum32 >> 16);
        csum32 &= 0xffff;
    }'''
SUM_NEW = '''    /* The two IPv6 addresses each contain eight words. Sum both arrays
     * explicitly instead of indexing past the end of ip6_src into ip6_dst. */
    for (i = 0; i < 8; i++) {
        csum32 += ntohs(ip6Hdr->ip6_src.__u6_addr.__u6_addr16[i]);
        csum32 += (csum32 >> 16);
        csum32 &= 0xffff;
        csum32 += ntohs(ip6Hdr->ip6_dst.__u6_addr.__u6_addr16[i]);
        csum32 += (csum32 >> 16);
        csum32 &= 0xffff;
    }'''


def rewrite(text):
    """Expected R45 blocks after this extension, also used by freshness checks."""
    for old, new in ((POST_OLD, dispatch(POST_OLD)),
                     (RETIRE_OLD, dispatch(RETIRE_OLD)),
                     (RPC_OLD, RPC_NEW), (ACTION_OLD, ACTION_NEW),
                     (INIT_OLD, INIT_NEW), (DISABLE_OLD, DISABLE_NEW),
                     (SUM_OLD, SUM_NEW)):
        text = text.replace(old, new)
    return text.replace('r45Tso4PostedPacket', 'r46TsoPostedPacket').replace(
        'r45Tso4RetiredPacket', 'r46TsoRetiredPacket')


def patch(hpp, cpp, setup):
    for anchor in (POST_OLD, RETIRE_OLD, RPC_OLD, ACTION_OLD, INIT_OLD, DISABLE_OLD, SUM_OLD):
        if cpp.count(anchor) != 1:
            raise SystemExit('refused: round46 ordinary TSO anchor count %d' % cpp.count(anchor))
    hpp, cpp, setup = (rewrite(text) for text in (hpp, cpp, setup))
    anchor = '    bool hasSensor;\n'
    if hpp.count(anchor) != 1:
        raise SystemExit('refused: round46 counter declaration anchor')
    # R45TsoStats is declared immediately after hasSensor, so append after the
    # complete R45 declaration block rather than referring to it too early.
    base_members = rewrite(BASE['MEMBERS'])
    if hpp.count(base_members) != 1:
        raise SystemExit('refused: round46 inherited counter declaration')
    hpp = hpp.replace(base_members, base_members + MEMBERS, 1)
    anchor = '\n#pragma mark --- statistics update methods ---\n'
    if cpp.count(anchor) != 1:
        raise SystemExit('refused: round46 method insertion anchor')
    cpp = cpp.replace(anchor, '\n' + METHODS + anchor, 1)
    return hpp, cpp, setup


def is_current(hpp, cpp, setup):
    import re
    norm = lambda text: re.sub(r'\s+', ' ', text).strip()
    return (norm(MEMBERS) in norm(hpp) and norm(METHODS) in norm(cpp) and
            norm(SUM_NEW) in norm(cpp) and
            'r46TsoPostedPacket(cmd, len, numSegs, opts2);' in cpp and
            'r46TsoRetiredPacket(r45Command,' in setup)

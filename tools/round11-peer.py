#!/usr/bin/env python3
"""round11-peer.py -- the peer for round 11's controlled batch.

WHY UDP RATHER THAN TCP
-----------------------
See round11-client.py: a UDP echo makes "one request" mean exactly one datagram,
and the identifier in the payload is what the driver records, so the join is by
value rather than by timing.

WIRE FORMAT
-----------
The payload starts with 12 bytes the driver parses:

    offset 0..3   magic  'IOB1' = 0x31424F49  (big endian)
    offset 4..7   runToken  (big endian)
    offset 8..11  reqId     (big endian)

The peer echoes the WHOLE payload verbatim. It does not rebuild it, because a
rebuilt payload would be a different object and a mismatch would then be a
property of the peer rather than of the network.

WHAT IT LOGS, AND WHY EACH FIELD
--------------------------------
    peer_recv token=0x<tok> req=<n> len=<bytes> from=<ip>:<port> t=<ns>
    peer_sent token=0x<tok> req=<n> len=<bytes> to=<ip>:<port> t=<ns>

`from=<ip>:<port>` is what makes a log containing several runs unambiguous: the
analyser selects this run by the CLIENT'S SOURCE PORT, not by "the last block"
and not by the token alone (a token can be reused, and an earlier run of the
same token is still in the file).

A SECOND, HUMAN-READABLE LINE IS ALSO WRITTEN
---------------------------------------------
    RECV <len> bytes from <ip>:<port> head=<24 hex>

`head` is the first 12 payload bytes in hex. It lets a person (and the
analyser, which accepts both forms) see the identifier without decoding the
structured line. Round 10's capture archived only this form, so an analyser that
knew only the structured one would have declared a working exchange absent.

Usage:
  round11-peer.py --bind 0.0.0.0 --port 9110 --log peer.log [--count 4]
"""
import argparse
import socket
import sys
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--bind', default='0.0.0.0')
    ap.add_argument('--port', type=int, default=9110)
    ap.add_argument('--log', required=True)
    ap.add_argument('--count', type=int, default=0,
                    help='stop after N datagrams (0 = run until interrupted)')
    ap.add_argument('--timeout', type=float, default=0.0,
                    help='idle seconds before giving up (0 = never)')
    a = ap.parse_args()

    log = open(a.log, 'a', encoding='utf-8', newline='\n')

    def emit(s):
        log.write(s + '\n')
        log.flush()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((a.bind, a.port))
    emit('peer_start bind=%s:%d count=%d at=%d'
         % (a.bind, a.port, a.count, time.monotonic_ns()))

    # HOW THE IDLE TIMEOUT IS IMPLEMENTED, AND WHY NOT WITH settimeout()
    #
    # The first version called s.settimeout(1.0) inside the loop and treated
    # socket.timeout as "no datagram yet". On Windows that produces
    #     ConnectionResetError: [WinError 10054]
    # as soon as the peer's reply is not delivered to a socket that has been
    # put into non-blocking-with-timeout mode -- the ICMP port-unreachable from
    # an earlier probe is surfaced as a reset on the next recvfrom().
    #
    # A timeout on recvfrom() is also the wrong tool for "give up after N idle
    # seconds": it changes the socket's mode for every subsequent call. So the
    # socket stays BLOCKING and the idle deadline is checked with select().
    idle = a.timeout
    seen = 0
    last = time.monotonic()
    try:
        import select
    except ImportError:            # pragma: no cover - select is stdlib
        select = None

    try:
      while True:
          if idle and (time.monotonic() - last) > idle:
              emit('peer_idle_timeout after=%.1fs' % idle)
              break
          if select is not None:
              # Wait at most one second, so the idle deadline is honoured without
              # changing the socket's blocking behaviour.
              ready, _, _ = select.select([s], [], [], 1.0)
              if not ready:
                  continue
          try:
              data, addr = s.recvfrom(4096)
          except OSError as e:
              # A reset from a previous probe is not a reason to stop serving.
              emit('peer_recv_error %s' % e)
              continue
          trecv = time.monotonic_ns()
          last = time.monotonic()
          seen += 1

          head = data[:12]
          if len(head) >= 12:
              magic, tok, req = (
                  int.from_bytes(head[0:4], 'big'),
                  int.from_bytes(head[4:8], 'big'),
                  int.from_bytes(head[8:12], 'big'))
              emit('peer_recv token=0x%08x req=%d len=%d from=%s:%d t=%d'
                   % (tok, req, len(data), addr[0], addr[1], trecv))
              emit('RECV %d bytes from %s:%d head=%s'
                   % (len(data), addr[0], addr[1], head.hex()))
          else:
              magic = 0
              emit('peer_recv_short len=%d from=%s:%d t=%d'
                   % (len(data), addr[0], addr[1], trecv))
              emit('RECV %d bytes from %s:%d head=%s'
                   % (len(data), addr[0], addr[1], data.hex()))

          # Echo the payload VERBATIM. A rebuilt payload would be a different
          # object, and a mismatch would then be a property of this peer
          # rather than of the network.
          try:
              s.sendto(data, addr)
              emit('peer_sent token=0x%08x req=%d len=%d to=%s:%d t=%d'
                   % (int.from_bytes(head[4:8], 'big') if len(head) >= 12 else 0,
                      int.from_bytes(head[8:12], 'big') if len(head) >= 12 else 0,
                      len(data), addr[0], addr[1], time.monotonic_ns()))
          except OSError as e:
              emit('peer_send_fail to=%s:%d %s' % (addr[0], addr[1], e))

          if a.count and seen >= a.count:
              emit('peer_count_reached %d' % seen)
              break
    except KeyboardInterrupt:
        emit('peer_interrupted after=%d' % seen)
    finally:
        emit('peer_stop seen=%d at=%d' % (seen, time.monotonic_ns()))
        log.close()
        s.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())

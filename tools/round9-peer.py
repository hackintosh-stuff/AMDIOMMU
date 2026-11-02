#!/usr/bin/env python3
"""round9-peer.py -- the PEER side of the round-9 controlled transfer.

WHY A PEER AT ALL
-----------------
Rounds 6-8 could show that the NIC's close pointer advanced, and round 8 could
attribute that advance to specific descriptors. None of that shows that a
REQUEST reached anyone. A descriptor completion proves the NIC handed the
buffer back; it does not prove the bytes on the wire were a request the peer
received, nor that a reply came back through the RX path.

This script is the other end. It accepts ONE TCP connection and, until the
client closes it:
  * reads length-prefixed requests, each with a unique sequence number,
  * verifies the magic and the payload shape,
  * echoes a numbered acknowledgement,
  * and logs a monotonic timestamp per event.

The log is the peer's independent record. Correlating it with the Mac-side
client log and with the probe's descriptor records is what turns "the NIC did
something" into "this request was sent, arrived, was answered, and the answer
came back".

WHY IT IS DURATION-BOUNDED, NOT COUNT-BOUNDED
---------------------------------------------
Round 9's first attempt used a fixed count of 8. Eight small requests complete
in a few milliseconds -- far too short to overlap a 3 s measurement window --
and the run landed 24 s before the window opened. The peer therefore accepts
whatever arrives for as long as the connection stays open, and the CLIENT
decides how long to keep sending. Both sides log the span, so "did traffic
overlap the window" is answered from the logs rather than assumed.

Usage:
    py -3 round9-peer.py <logfile> [port] [idle-timeout-secs]
Exit 0 = at least one request arrived and every one was answered.
"""
import socket
import sys
import time

MAGIC = b"R9REQ"


def now_ns():
    return time.monotonic_ns()


def main():
    if len(sys.argv) < 2:
        print("usage: round9-peer.py <logfile> [port] [idle-timeout]")
        return 2
    logpath = sys.argv[1]
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9109
    idle = float(sys.argv[3]) if len(sys.argv) > 3 else 300.0

    log = open(logpath, "w", encoding="utf-8", newline="\n")
    log.write("peer_start_ns %d\n" % now_ns())
    log.write("peer_bind_port %d\n" % port)
    log.write("peer_idle_timeout_s %.0f\n" % idle)
    log.flush()

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    srv.settimeout(idle)
    log.write("peer_listening_ns %d\n" % now_ns())
    log.flush()

    try:
        conn, addr = srv.accept()
    except socket.timeout:
        log.write("peer_result TIMEOUT-no-connection\n")
        log.close()
        srv.close()
        return 1

    log.write("peer_accept_ns %d\n" % now_ns())
    log.write("peer_peer %s:%d\n" % (addr[0], addr[1]))
    log.flush()

    conn.settimeout(idle)
    got = 0
    sent = 0
    bad = 0
    first_recv = 0
    last_recv = 0
    buf = b""
    try:
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                log.write("peer_eof_after %d\n" % got)
                break
            buf += chunk
            while True:
                if len(buf) < 8:
                    break
                if buf[:5] != MAGIC:
                    bad += 1
                    log.write("peer_bad_magic %r\n" % buf[:8])
                    buf = b""
                    break
                seq = (buf[5] << 8) | buf[6]
                plen = buf[7]
                if len(buf) < 8 + plen:
                    break
                payload = buf[8:8 + plen]
                buf = buf[8 + plen:]
                t = now_ns()
                got += 1
                if first_recv == 0:
                    first_recv = t
                last_recv = t
                want = ("REQ-%05d-PAYLOAD" % seq).encode("ascii")
                # The client pads the payload to a fixed size so that one
                # request is one packet. Check the PREFIX, not equality: an
                # equality test rejected every request in round 9's first run
                # (bad=1186 of 1186) purely because of the padding.
                okp = payload.startswith(want)
                log.write(
                    "peer_recv seq=%d len=%d t_ns=%d payload_ok=%s payload=%s\n"
                    % (seq, plen, t, "yes" if okp else "no",
                       payload.decode("ascii", "replace")))
                if not okp:
                    bad += 1
                body = ("ACK-%05d" % seq).encode("ascii")
                conn.sendall(MAGIC + bytes([seq >> 8, seq & 0xFF,
                                            len(body)]) + body)
                sent += 1
                log.flush()
    except socket.timeout:
        log.write("peer_result TIMEOUT-mid-stream after %d\n" % got)
    except OSError as e:
        log.write("peer_socket_error %s\n" % e)

    span = (last_recv - first_recv) if first_recv else 0
    log.write("peer_summary got=%d sent=%d bad=%d span_ns=%d\n" % (
        got, sent, bad, span))
    log.write("peer_result %s\n" % (
        "OK" if (got > 0 and bad == 0 and sent == got) else "INCOMPLETE"))
    log.write("peer_end_ns %d\n" % now_ns())
    log.close()
    conn.close()
    srv.close()
    return 0 if (got > 0 and bad == 0 and sent == got) else 1


if __name__ == "__main__":
    sys.exit(main())

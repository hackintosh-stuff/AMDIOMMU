#!/usr/bin/env python3
"""round9-client.py -- the Mac side of the round-9 controlled transfer.

WHAT IT DOES THAT A ping DOES NOT
---------------------------------
Round 8's load was ICMP to the gateway plus a UDP datagram and a TCP connect
attempt. None of those carries an identifier the peer can echo back, so the
peer's log could not be matched to a specific descriptor. This client:

  * opens ONE TCP connection to a named peer and port,
  * sends numbered requests for a chosen DURATION (not a fixed count),
  * waits for each numbered acknowledgement,
  * and logs, per request, the monotonic send and receive times.

The sequence number is the join key between three independent records:
  - this client's log (what the application asked for),
  - the peer's log (what actually arrived and was answered),
  - the probe's descriptor records (which DMA carried it).

WHY DURATION AND NOT COUNT
--------------------------
Round 9's first attempt sent 8 requests. They completed in a few milliseconds,
the whole run finished 24 s before the probe's measurement window opened, and
nothing overlapped. A count says nothing about overlap; a duration does. The
caller passes how many seconds of traffic it wants, and this client keeps
sending until that much time has elapsed, logging the actual span.

BINDING
-------
The socket is bound to the target interface's address explicitly. Without
that, the kernel may route the connection out of a different NIC, and the
descriptors observed on the RTL8125 would belong to unrelated traffic. Round 8
did not bind, which is one reason its netstat growth could not be attributed.

Usage:
    py -3 round9-client.py <logfile> <peer-ip> <local-ip> <port> <seconds>
Exit 0 = the connection was made, at least one request was acknowledged, and
         every acknowledgement matched its request.
"""
import socket
import sys
import time

MAGIC = b"R9REQ"


def now_ns():
    return time.monotonic_ns()


def main():
    if len(sys.argv) < 6:
        print("usage: round9-client.py <logfile> <peer-ip> <local-ip> "
              "<port> <seconds>")
        return 2
    logpath = sys.argv[1]
    peer_ip = sys.argv[2]
    local_ip = sys.argv[3]
    port = int(sys.argv[4])
    seconds = float(sys.argv[5])

    log = open(logpath, "w", encoding="utf-8", newline="\n")
    log.write("client_start_ns %d\n" % now_ns())
    log.write("client_local %s\n" % local_ip)
    log.write("client_peer %s:%d\n" % (peer_ip, port))
    log.write("client_seconds %.3f\n" % seconds)
    log.flush()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.bind((local_ip, 0))
    log.write("client_bound %s:%d\n" % s.getsockname())
    log.flush()

    t0 = now_ns()
    try:
        s.connect((peer_ip, port))
    except OSError as e:
        log.write("client_connect FAIL %s\n" % e)
        log.write("client_result CONNECT-FAILED\n")
        log.close()
        s.close()
        return 1
    log.write("client_connected_ns %d\n" % now_ns())
    log.flush()

    s.settimeout(10.0)
    ok = 0
    bad = 0
    seq = 0
    first_sent = 0
    last_recv = 0
    deadline = time.monotonic() + seconds

    # 64-byte requests: small enough that one packet is one descriptor, so a
    # completion can be attributed to a single request rather than a burst.
    pad = "x" * (64 - len(MAGIC) - 3 - len("REQ-00000-PAYLOAD"))

    try:
        while time.monotonic() < deadline:
            seq += 1
            payload = ("REQ-%05d-PAYLOAD" % seq).encode("ascii") + \
                      pad.encode("ascii")
            frame = MAGIC + bytes([seq >> 8, seq & 0xFF, len(payload)]) + payload
            ts = now_ns()
            if first_sent == 0:
                first_sent = ts
            s.sendall(frame)
            log.write("client_sent seq=%d len=%d t_ns=%d\n" % (
                seq, len(payload), ts))

            # Read the acknowledgement for this sequence number.
            buf = b""
            done = False
            while not done:
                if len(buf) >= 8 and buf[:5] == MAGIC:
                    rseq = (buf[5] << 8) | buf[6]
                    rlen = buf[7]
                    if len(buf) >= 8 + rlen:
                        body = buf[8:8 + rlen]
                        tr = now_ns()
                        last_recv = tr
                        want = ("ACK-%05d" % seq).encode("ascii")
                        if rseq == seq and body == want:
                            ok += 1
                        else:
                            bad += 1
                            log.write(
                                "client_mismatch want=%d got=%d body=%s\n"
                                % (seq, rseq,
                                   body.decode("ascii", "replace")))
                        log.write("client_recv seq=%d t_ns=%d\n" % (rseq, tr))
                        done = True
                        break
                chunk = s.recv(4096)
                if not chunk:
                    log.write("client_eof_at seq=%d\n" % seq)
                    raise EOFError("peer closed")
                buf += chunk
            # Pace the requests so the traffic spans the window instead of
            # arriving as one burst at the start of it.
            time.sleep(0.010)
    except (socket.timeout, EOFError, OSError) as e:
        log.write("client_stopped seq=%d reason=%s\n" % (seq, e))

    span = (last_recv - first_sent) if (first_sent and last_recv) else 0
    log.write("client_summary sent=%d acked=%d bad=%d span_ns=%d\n" % (
        seq, ok, bad, span))
    log.write("client_result %s\n" % (
        "OK" if (ok > 0 and bad == 0) else "INCOMPLETE"))
    log.write("client_end_ns %d\n" % now_ns())
    log.close()
    s.close()
    return 0 if (ok > 0 and bad == 0) else 1


if __name__ == "__main__":
    sys.exit(main())

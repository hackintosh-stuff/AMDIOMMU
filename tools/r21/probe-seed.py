"""Prove the en2 path to the peer works BEFORE spending another reboot.

Binds the en2 address the load will use, sends the same seed the load sends, and
reports whether the echo came back. This is the exact test that was failing, done
in advance instead of discovered afterwards.
"""
import socket
import sys

SEED = bytes(1024)
LOCAL = sys.argv[1] if len(sys.argv) > 1 else '192.168.50.216'
PEER = ('192.168.50.122', 9110)

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((LOCAL, 0))
s.settimeout(2.0)
s.sendto(SEED, PEER)
try:
    data, addr = s.recvfrom(8192)
except socket.timeout:
    print('TIMEOUT: no echo from %s via %s' % (PEER, LOCAL))
    raise SystemExit(1)
print('echo len=%d from=%s:%d match=%s' % (len(data), addr[0], addr[1], data == SEED))
raise SystemExit(0 if data == SEED else 1)

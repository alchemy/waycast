#!/usr/bin/env python3
"""Private-namespace test utility: inject a UDP frame onto the fake TV veth."""
import json
import subprocess
import os
import socket
import struct
import sys
from pathlib import Path

assert Path("/proc/self/ns/net").readlink() != Path(os.environ["WAYCAST_PARENT_NETNS"])
dport, sport, source, expected = sys.argv[1:5]
destination = sys.argv[5] if len(sys.argv) > 5 else "192.168.49.1"
receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
receiver.bind(("0.0.0.0", int(dport)))
receiver.settimeout(0.3)
payload = b"waycast-firewall-probe"
udp = struct.pack("!HHHH", int(sport), int(dport), 8 + len(payload), 0) + payload
ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                 socket.inet_aton(source), socket.inet_aton(destination))
words = struct.unpack("!10H", ip)
total = sum(words)
while total >> 16:
    total = (total & 0xffff) + (total >> 16)
ip = ip[:10] + struct.pack("!H", (~total) & 0xffff) + ip[12:]
mac = lambda dev: bytes.fromhex(json.loads(subprocess.check_output(["/usr/bin/ip", "-j", "link", "show", dev]))[0]["address"].replace(":", ""))
target_mac = b"\xff" * 6 if destination == "255.255.255.255" else mac("p2p-test")
frame = target_mac + mac("sink-test") + b"\x08\x00" + ip + udp
sender = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
sender.bind(("sink-test", 0))
sender.send(frame)
try:
    data, _ = receiver.recvfrom(2048)
    received = data == payload
except TimeoutError:
    received = False
assert received == (expected == "allow"), f"UDP {source}:{sport} -> {destination}:{dport}: expected {expected}, received={received}"

#!/usr/bin/env python3
"""Run the kernel firewall test in a fresh user/network namespace, never the host."""
import os
from pathlib import Path

os.environ["WAYCAST_PARENT_NETNS"] = str(Path("/proc/self/ns/net").readlink())
os.environ["WAYCAST_PRIVATE_NETNS"] = "1"
os.execvp("unshare", ["unshare", "--user", "--map-root-user", "--net",
                     "cargo", "test", "-p", "waycast-networkd", "--lib",
                     "kernel_ufw_lifecycle", "--offline", "--", "--ignored", "--nocapture"])

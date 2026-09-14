#!/usr/bin/env python3
"""Install/stage the Omarchy integration; no per-session rules are persisted."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

DECL = "# BEGIN WAYCAST CHAIN\n:waycast-input - [0:0]\n# END WAYCAST CHAIN\n"
HOOK = "# BEGIN WAYCAST HOOK\n-F waycast-input\n-A ufw-before-input -j waycast-input\n# END WAYCAST HOOK\n"


def remove_block(text, start, end):
    if start not in text:
        if end in text:
            raise ValueError("Incomplete Waycast installation marker")
        return text
    if text.count(start) != 1 or text.count(end) != 1:
        raise ValueError("Invalid Waycast installation markers")
    first = text.index(start)
    last = text.index(end, first) + len(end)
    return text[:first] + text[last:]


def ufw_hook(text, remove=False):
    """Preserve administrator rules while installing an empty private chain."""
    text = remove_block(text, "# BEGIN WAYCAST CHAIN\n", "# END WAYCAST CHAIN\n")
    text = remove_block(text, "# BEGIN WAYCAST HOOK\n", "# END WAYCAST HOOK\n")
    if remove:
        return text
    if text.count("*filter\n") != 1 or ":ufw-before-input " not in text:
        raise ValueError("Expected stock UFW before.rules filter table")
    if "waycast-input" in text:
        raise ValueError("Unmanaged waycast-input chain already exists")
    text = text.replace("*filter\n", "*filter\n" + DECL, 1)
    begin = text.index("*filter\n")
    end = text.index("COMMIT", begin)
    # Jump before existing rules, but after chain declarations.
    positions = [text.find("\n" + prefix, begin, end) for prefix in ("-A ", "-I ", "-F ")]
    positions = [p + 1 for p in positions if p >= 0]
    index = min(positions) if positions else end
    return text[:index] + HOOK + text[index:]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destdir", type=Path, help="Stage files without changing the running system")
    parser.add_argument("--binary", type=Path, default=Path("target/release/waycast-networkd"))
    parser.add_argument("--uninstall", action="store_true")
    parser.add_argument("--configure-only", action="store_true",
                        help="Configure UFW/service lifecycle only; package manager owns installed files")
    args = parser.parse_args()
    root = args.destdir or Path("/")
    live = args.destdir is None
    if live and os.geteuid() != 0:
        parser.error("Installation requires administrator access")
    source = Path(__file__).resolve().parent
    targets = {
        "waycast-networkd.service": "usr/lib/systemd/system/waycast-networkd.service",
        "org.waycast.Network1.service": "usr/share/dbus-1/system-services/org.waycast.Network1.service",
        "org.waycast.Network1.conf": "usr/share/dbus-1/system.d/org.waycast.Network1.conf",
        "org.waycast.network.policy": "usr/share/polkit-1/actions/org.waycast.network.policy",
        "60-waycast-network.rules": "etc/polkit-1/rules.d/60-waycast-network.rules",
    }
    before = root / "etc/ufw/before.rules"
    original = before.read_text()
    updated = ufw_hook(original, args.uninstall)
    binary = root / "usr/lib/waycast/waycast-networkd"
    # Validate inputs before changing the system.
    if not args.uninstall and not args.configure_only and not args.binary.is_file():
        parser.error("Build waycast-networkd first, or supply --binary")
    if live:
        # Prevent D-Bus activation racing an upgrade/removal. A failed install
        # remains masked until a successful rerun completes it.
        subprocess.run(["/usr/bin/systemctl", "mask", "--runtime", "waycast-networkd.service"], check=True)
        subprocess.run(["/usr/bin/systemctl", "stop", "waycast-networkd.service"], check=False)
    if args.uninstall:
        if live and binary.exists():
            subprocess.run([str(binary), "--cleanup"], check=True)
            subprocess.run(["/usr/bin/systemctl", "disable", "waycast-networkd.service"], check=True)
        if not args.configure_only:
            for target in targets.values():
                (root / target).unlink(missing_ok=True)
            binary.unlink(missing_ok=True)
    elif not args.configure_only:
        binary.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(args.binary, binary)
        binary.chmod(0o755)
        if live:
            os.chown(binary, 0, 0)
        for name, target in targets.items():
            destination = root / target
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, destination)
            destination.chmod(0o644)
            if live:
                os.chown(destination, 0, 0)
    if original != updated:
        backup = before.with_name("before.rules.pre-waycast")
        if not backup.exists():
            shutil.copy2(before, backup)
        temporary = before.with_name("before.rules.waycast-new")
        temporary.write_text(updated)
        temporary.chmod(before.stat().st_mode & 0o777)
        temporary.replace(before)
    if live:
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], check=True)
        # D-Bus reloads policy/config files without terminating desktop clients.
        subprocess.run(["/usr/bin/systemctl", "reload", "dbus.service"], check=True)
        subprocess.run(["/usr/bin/ufw", "reload"], check=True)
        # Pacman removes files after pre_remove returns; keep activation blocked
        # until its post_remove hook has reloaded the bus and service manager.
        if not (args.configure_only and args.uninstall):
            subprocess.run(["/usr/bin/systemctl", "unmask", "--runtime", "waycast-networkd.service"], check=True)
        if not args.uninstall:
            subprocess.run(["/usr/bin/systemctl", "enable", "--now", "waycast-networkd.service"], check=True)
    print("Waycast networking integration " + ("removed" if args.uninstall else "installed"))


if __name__ == "__main__":
    main()

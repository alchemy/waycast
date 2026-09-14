# Automatic networking on Omarchy

Waycast's daemon now uses `waycast-networkd` to create its Wi-Fi Direct group
and manage temporary firewall allowances. Mirror, extend and audio share this
integration. The initial supported host configuration is Omarchy with active
UFW, its standard allow-outgoing policy, NetworkManager and wpa_supplicant.

Install the integration once with administrator privileges. Afterwards, an
active local desktop user can select a TV and cast without entering a password
or editing firewall rules. The ordinary Waycast process remains unprivileged.
`doctor` has not been changed into a firewall rules parser. A single P2P radio
is selected automatically; only multi-radio systems require `--interface`.

## Installation

The Arch branch of `install.sh` installs the helper along with the application.
For a development checkout, run from the repository root:

```bash
cargo build --release -p waycast-cli -p waycast-networkd
sudo python3 contrib/networkd/install.py
./target/release/waycast --interface wlp0s20f3 daemon --sink '<TV name or MAC>'
```

The helper installation requires Python 3, systemd, D-Bus, Polkit, iproute2,
iptables (including the `devgroup` match), and an existing UFW configuration.
It installs:

- `/usr/lib/waycast/waycast-networkd`, root-owned and executable.
- A systemd service and system D-Bus activation/policy files.
- A Polkit action and a rule permitting that action for active local sessions.
- An empty `waycast-input` chain and jump in `/etc/ufw/before.rules`.

The installer preserves existing UFW rules, creates a one-time
`before.rules.pre-waycast` backup, reloads UFW and enables the service. Re-running
it updates the installed components without duplicating the hook. Network
permissions are not recorded as persistent per-session `ufw allow` rules.
A UFW reload ends any active casting session.

Installation can be staged without touching the running system:

```bash
# The staging tree must already contain etc/ufw/before.rules.
python3 contrib/networkd/install.py --destdir /tmp/waycast-package-root
```

Remove only the helper integration with:

```bash
sudo python3 contrib/networkd/install.py --uninstall
```

Removal stops the helper, clears its temporary chain, removes its policy/service
files and managed UFW blocks, and reloads UFW. It preserves unrelated rules and
the main Waycast executable. Package-manager updates/removal still require normal
administrator authorization. A Nix-built application alone does not install
host systemd, Polkit or UFW integration.

## Privilege boundary

`org.waycast.Network1`, at `/org/waycast/Network1`, exposes four methods:

| Method | Responsibility |
| --- | --- |
| `BeginSession(radio, peer MAC)` | Check Polkit, resolve the currently discovered sink on that radio, activate its group and return interface/address information. |
| `AuthorizeMedia(control fd, RTP fd, RTCP fd, sink RTCP port)` | Validate passed sockets and authorize the negotiated incoming RTCP flow before SETUP succeeds. |
| `EndSession()` | Release the caller's rules and NetworkManager activation. Idempotent once no session remains. |
| `SessionAlive()` | Report whether this caller still owns a session. |

Authorization uses the system bus sender's unique name. The helper does not
accept a claimed UID or caller-supplied shell commands. Other callers cannot
change or end an existing session. One session is supported at a time.

The helper independently resolves the peer from NetworkManager's P2P peer list,
checks that it advertises Miracast sink capabilities, and selects the exact
`p2p-dev-<radio>` device. It subscribes to the selected supplicant interface's
GroupStarted signal before activating the connection. Managed setup requires
that signal; it does not trust journal fallback guesses.

A group interface must have a valid kernel name and belong to the selected
radio's `phy80211`. The helper records its interface index and assigns reserved
network-device group `0x574644`. Rules match both the exact interface name and
this device group. A newly created interface that reuses the name starts without
the tag and cannot inherit the old allowances while cleanup is pending. Existing
custom nonzero device groups are rejected. The tag belongs to the transient P2P
interface; a surviving helper tag is accepted on a later validated activation.
The [kernel's network-device group attribute](https://github.com/torvalds/linux/blob/master/Documentation/ABI/testing/sysfs-class-net)
and [iptables devgroup match](https://www.man7.org/linux/man-pages/man8/iptables-extensions.8.html)
provide this protection.

The helper validates a connected IPv4 stream control socket and two datagram
media sockets. Their local addresses must match the P2P address, RTP must be an
unprivileged even port, and RTCP must be its consecutive odd port. The control
connection must use local source port 7236 or the sink's advertised remote port. When the TV owns the group, its
address must equal the selected GO address; when Waycast owns the group, the
peer must be another unicast host in the group's /24. This is network-session
validation, not cryptographic TV identity. Passed descriptors are retained until
cleanup so another application cannot reuse the permitted ports prematurely.

The systemd unit limits capabilities to `CAP_NET_ADMIN`, prevents privilege
gain, and makes persistent system paths read-only. It shares the host network
namespace deliberately. The helper executes fixed absolute iptables/ip binaries
with validated arguments, a clean environment, and bounded command timeouts.

## Setup and teardown ordering

1. Authorize the caller before starting TV pairing.
2. Activate a volatile NetworkManager connection bound to a dedicated D-Bus
   connection. This bus is owned by the helper session, not shared across sessions.
3. On GroupStarted, validate/tag the actual interface and permit inbound RTSP
   plus DHCP client replies. If Waycast is GO, also permit DHCP requests **before**
   explicitly reapplying NetworkManager's shared IPv4 configuration.
4. Wait for the exact group's IPv4 address, then narrow RTSP to the local address.
5. Reserve RTP/RTCP sockets during SETUP. Ask the helper to validate them, narrow
   RTSP to the connected TV, and install incoming RTCP when negotiated.
6. Only after authorization succeeds, advertise the media ports and start playback.

The UFW hook enters a regular chain inside UFW's own input processing. Updates
use `iptables-restore --noflush` with the xtables lock, flushing only
`waycast-input`. No independent ACCEPT chain is assumed to override UFW drops.
The installer includes an explicit flush of that chain in the persisted hook,
so a reload never restores obsolete per-session allowances.

Normal teardown clears the chain and explicitly deactivates the NetworkManager
connection. On client crash, the helper detects disappearance of its dedicated
D-Bus name. Background RTSP/health tasks hold non-owning helper references, so
they cannot indefinitely retain an abandoned session.

The supervisor polls every 500 ms for caller loss, inactive NetworkManager
activation, interface replacement or changed firewall rules. Cleanup latency is
bounded by polling plus D-Bus/firewall-command timeouts, not instantaneous. On
firewall cleanup failure it exits for systemd recovery. `ExecStopPost` runs the
same idempotent cleanup after helper termination; startup clears leftover rules
before claiming the bus name. NetworkManager's bind-activation setting also
releases the P2P group when the helper's bus connection disappears.

A UFW reload or removal of the hook ends the session instead of re-creating
permissions from stale state. The unprivileged daemon polls helper health and
stops sharing if that session disappears. Reconnect after a reload.

## Tests and limits

```bash
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
python3 -m unittest discover -s contrib/networkd
python3 contrib/networkd/run_firewall_test.py
```

The last command uses `unshare` to create fresh user/network namespaces and
refuses the parent namespace. It requires permission to create namespaces and
operate iptables inside them. It creates a private UFW-style input chain and a
veth pair, verifies actual DHCP/RTCP packets, rejects wrong peers/ports and
untagged interfaces, clears rules after caller D-Bus loss, and preserves an
unrelated allowance. It never changes the host firewall.

Private D-Bus tests verify authorization denial before network operations,
correct radio selection, and receipt of a GroupStarted event emitted before the
activation method returns. RTSP tests verify that a failed authorization does
not produce a successful SETUP response. Installer tests verify idempotence,
reversal and preservation of existing rules.

Real-radio/TV testing is still required for both GO roles, both RTSP connection
directions and mirror/extend/audio. A custom second firewall, VPN kill switch,
reverse-path filtering or incompatible radio remains outside the initial UFW
integration. The helper does not alter these policies, disable UFW, open DNS,
forward Internet traffic, or provide HDCP. The unmanaged `waycast-net` library
connection API remains available for component examples; production daemon and
CLI pairing use the installed helper and do not silently bypass it.

# Networking requirements

This document describes the implementation, updated for the networking helper on 2026-09-12.
See [Automatic networking on Omarchy](network-helper.md) for installation and lifecycle details.
“Source” means the Linux machine running waycast; “sink” means the display.
Requirements below distinguish executable daemon paths from library helpers and
future use cases. Hardware observations in older test reports are not guarantees
for every TV model.

## Use cases

| Use case | Network requirements and current behavior |
| --- | --- |
| Mirror: `waycast --interface wlp0s20f3 daemon --sink <name-or-MAC>` | Wi-Fi Direct discovery, group formation and IPv4, followed by TCP RTSP and unicast UDP media. Defaults to accepting the sink's TCP connection. |
| Extend: add `--extend` | Same network as mirror. Creates a local 1080p30 virtual output and targets 10 Mbit/s video. No additional network service or port. |
| External output: add `--external auto`, `720`, `1080`, or `4k` | Same transport. Mode negotiation and sink decoding still constrain resolution; selecting 4K does not establish WFD 2.0 support. |
| Audio: add `--audio` to either mode | AAC audio joins video in the same MPEG-TS/RTP stream. No separate audio port; default audio bitrate is 128 kbit/s. |
| Sink expects source to initiate RTSP: add `--client` | Source dials the sink's advertised TCP RTSP port. P2P discovery and IPv4 are still required. This flag does not choose the Wi-Fi Direct role. |
| Discovery only: `discover --timeout 15` | NetworkManager P2P discovery and radio access; no RTSP or media sockets, DHCP lease, router, or Internet connection required. |
| Pairing diagnostic: `connect --sink <name-or-MAC>` | Discovery, group formation and IP configuration only. It explicitly ends the helper session after reporting; this is not a persistent preparation step for a later stream command. |
| `disconnect` | Calls NetworkManager StopFind; currently stops discovery rather than explicitly deactivating an existing group. Daemon teardown calls the helper to remove rules and deactivate its group. |
| `stream` | Configures a pipeline targeting `127.0.0.1:5004`, then returns without starting playback. It is not an IP-address casting CLI. |
| `doctor` / `status` | Local checks/reporting; neither verifies that a TV can reach RTSP or receive media. |
| Protocol tests and standalone RTSP examples | Can use loopback or an explicitly supplied reachable address without Wi-Fi Direct. These exercise components, not the production discovery-to-capture workflow. Check each example's bind address and port before running it on a LAN. |
| Ethernet-only, ordinary shared Wi-Fi LAN, routed/VPN/Internet casting | No production CLI path: daemon always discovers a P2P peer. No Miracast-over-Infrastructure/MS-MICE discovery, NAT traversal, or relay implementation. Library socket APIs accepting an IP address do not provide these workflows. |
| Multiple displays at once | The helper permits one managed session at a time across callers; concurrent casting requests are rejected. |

Mirror/extend affect capture and encoding, not who owns the wireless group or
which direction media flows. Video always travels source → sink.

## Product requirement: automatic setup on stock Omarchy

The supported baseline for firewall integration is **Omarchy's out-of-the-box
configuration**, not the customized rules on a developer's computer. Users must
be able to select a TV and cast without entering firewall commands. This is a
requirement implemented by the new [networking helper](network-helper.md).
Hardware validation of the complete integration remains necessary.

The installed Omarchy source reviewed on 2026-09-12,
`/usr/share/omarchy/install/config/firewall.sh`, enables UFW with incoming denied
and outgoing allowed. It adds LocalSend TCP/UDP 53317 and Docker-specific DNS
exceptions and installs ufw-docker rules. It does not add Miracast RTSP, GO DHCP
server, or dynamic RTCP exceptions. UFW's packaged before-rules normally allow
DHCP client replies and established traffic; integration tests must use the
stock package rules rather than assume a customized live host is representative.

Integration requirements (implementation and validation details are in the helper guide):

1. Install a narrowly scoped, root-owned firewall helper with waycast. Authorize
   its use through system policy during installation or a desktop authentication
   prompt before pairing. Keep screen capture and the main daemon unprivileged.
   No manual port configuration should be part of the user workflow.
2. Before group activation, acquire a session lease with the helper. Observe and
   validate the actual NetworkManager P2P interface as it appears; install DHCP
   server allowance early enough for source-GO address acquisition, and RTSP
   allowance before the sink attempts connection. A name prefix alone is not
   sufficient proof that an interface belongs to the requesting session.
3. Support both GO roles without user selection: preserve DHCP-client replies
   (UDP 67 to 68); permit DHCP-server requests (UDP 68 to 67) on the session's
   P2P interface when the source owns the group. DHCP bootstrap must permit
   unspecified source addresses and broadcast destinations. Permit the actual
   RTSP listener port on that interface, then restrict to the validated peer
   where possible.
4. Reserve the media sockets and authorize incoming RTCP from the peer to the
   reserved local RTCP port before sending the successful SETUP response.
   Outbound RTP/RTCP already fits the stock outgoing policy. The current ordering
   requires a hook inside RTSP setup, not just after `wait_for_peer_play()`.
5. Integrate allowances into UFW's effective packet-processing path. A separate
   nftables base chain containing ACCEPT rules cannot override a later UFW DROP.
   Do not disable UFW, change its default policies, flush unrelated rules, or
   assume that enabling routed traffic helps locally generated media.
6. Own only waycast's rules. Track session ownership, preserve pre-existing
   administrator rules, and remove allowances on disconnect, setup failure,
   daemon crash, and helper restart. A privileged supervisor should monitor
   client lifetime; a Rust destructor alone cannot clean up after SIGKILL.
   Define recovery after UFW reload and interface removal/recreation, including
   preventing stale rules from authorizing a different interface with the same name.
7. Complete authorization before the TV's short pairing timeout begins. If
   authorization is denied or setup fails, report a clear setup error and unwind
   the session. Custom firewalls beyond the stock UFW baseline need explicit
   detection/support rather than a claim that opening ports guarantees delivery.

The user experience is: install waycast with its networking integration, select
mirror/extend and a TV, authorize network setup if required by policy, and cast.
No DHCP, RTSP or RTCP port numbers should appear in the ordinary setup flow.

Acceptance tests must start from stock Omarchy/UFW rules and cover mirror and
extend with each GO role, normal and outbound RTSP, audio, dynamic RTCP feedback,
authorization denial, failed negotiation, repeated sessions, abrupt process
termination and UFW reload. Assert that unrelated interfaces remain protected
and pre-existing rules survive cleanup. Use an isolated test environment;
do not reset a developer's customized firewall to simulate defaults.

## Host and radio prerequisites

- A Wi-Fi adapter, driver, and firmware that expose a working P2P device to
  NetworkManager (device type 30). Ordinary Wi-Fi connectivity alone is insufficient.
  The sink must be discoverable in its screen-sharing mode and accept pairing.
- A running system D-Bus and NetworkManager with Wi-Fi P2P support. The implementation
  also uses `fi.w1.wpa_supplicant1` for group-start events; it is designed around
  wpa_supplicant. The older unmanaged library path retains a journal fallback;
  the privileged helper requires authoritative D-Bus group events. An alternative Wi-Fi
  backend is not a validated equivalent.
- Permission to discover and activate NetworkManager connections and to reapply
  IPv4 settings when the source becomes group owner. The helper performs activation/reapply as root; the desktop user needs P2P
  discovery permission and authorization for the helper's configure action. Running the entire desktop
  capture session as root is not a prerequisite.
- `ip` from iproute2 for interface address lookup. If the wpa_supplicant event API
  is inaccessible, managed setup fails before activation; the journal fallback
  is available only to unmanaged library callers. Role detection is especially important
  when waycast must switch to serving DHCP.
- NetworkManager's shared-IPv4 dependencies must be available when the source is
  group owner, including the DHCP/DNS helper supplied by the distribution
  (commonly dnsmasq). Avoid a separately configured DHCP server competing on the
  same group interface.

`--interface` defaults to `auto`, selecting the sole available P2P radio.
If several are present, choose the actual radio name from `iw dev`.
The manager now matches NetworkManager's P2P device to
`p2p-dev-<interface>` rather than choosing the first device of type 30.
Managed connections require GroupStarted on the corresponding supplicant
interface, and the helper verifies that the data interface belongs to that radio.

The data interface is created dynamically, for example `p2p-wlp0s20f3-0` or
`p2p0`; firewall rules on only `wlp0s20f3` can miss the traffic. Code recognizes
`p2p-*` and `p2p0` in its address scan.

Internet access and membership of the TV's home Wi-Fi network are unnecessary.
Keeping ordinary Wi-Fi Internet access while casting depends on the adapter's
supported concurrent interface/channel combinations (`iw list`), the driver and
sink. Waycast does not select the P2P band/channel or guarantee concurrent STA
operation. Ethernet can provide an independent uplink while P2P carries video.

## Address assignment and routing

| Negotiated Wi-Fi Direct role | Source requirements | Sink requirements |
| --- | --- | --- |
| Source is group client, sink is group owner (GO) | Starts with NetworkManager `ipv4.method=auto`; must acquire a usable local IPv4 address. Accept DHCP replies when DHCP is used. | Provides group addressing, via DHCP or the P2P allocation information observed for some sinks. |
| Source is GO, sink is group client | Reapplies `ipv4.method=shared` and explicitly requests `192.168.49.1/24`; waits for that exact address before RTSP. Must serve DHCP to the sink. | Acquires an address on that group and initiates RTSP in the normal daemon path. |

The source's fixed GO subnet is an implementation choice for interoperability,
not evidence that every Miracast sink uses that subnet. When the sink is GO,
waycast uses observed GO information or guesses the local IPv4 address's `.1`.
Nonstandard addressing without GO information can therefore fail. Internally,
`Sink.ip_address` after connection holds the **source's local address**, not the
TV's address; reverse RTSP obtains the actual sink address from the accepted peer.

IPv4 is required by the production address discovery path. IPv6 is configured as
`auto`, `may-fail=true`, but there is no complete IPv6-only daemon workflow.
Both families have `never-default=true`: the P2P profile should not replace the
normal default route. NetworkManager shared mode also manages DHCP/DNS and NAT;
forwarding to an uplink is not necessary for local screen transport. These
NetworkManager behaviors are described in its
[IPv4 settings reference](https://www.networkmanager.dev/docs/api/latest/settings-ipv4.html).

Ensure the route to the sink uses the P2P interface. A LAN, container network, or
VPN overlapping `192.168.49.0/24`, a VPN kill switch, or policy routing can divert
or reject traffic even when pairing succeeds. Source sockets bind the local
control address for media and outbound RTSP, but the application does not install
policy routes or bind sockets to a device with `SO_BINDTODEVICE`.

## Connections and firewall policy

The following describes traffic on the P2P link, not ports to expose to the
Internet. Permit established TCP replies and scope rules to the actual group
interface and, after address assignment, the sink IP where practical.

| Function | Initiator / packet direction | Ports |
| --- | --- | --- |
| P2P discovery, negotiation, association | Both radios, before IP | Wi-Fi management traffic; opening a UDP discovery port does not enable it. No mDNS/SSDP discovery implementation. |
| DHCP when source is client | Source → GO; GO → source replies | UDP 68 → 67; UDP 67 → 68, including broadcasts. |
| DHCP when source is GO | Sink → source; source → sink replies | UDP 68 → 67 inbound to source; UDP 67 → 68 outbound. Initial packets can originate at `0.0.0.0`, so do not require a leased source subnet for this rule. |
| Normal RTSP | Sink ephemeral TCP port → source listener | TCP 7236, the port advertised by Waycast as the source. |
| `--client` RTSP | Source ephemeral TCP port → sink listener | Sink's advertised TCP port, default 7236. Also permit inbound RTSP for the fallback below. |
| Video and optional audio RTP | Source → sink | UDP from reserved even local port `P` to sink's negotiated RTP port `R`; 5004 is a fallback, not a universal port. |
| RTCP sender/receiver reports | Source ↔ sink | Local UDP `P+1` ↔ sink RTCP port `C`, when a nonzero second `client_port=R-C` is offered in SETUP. |
| ARP | Both peers | Required IPv4 neighbor resolution, no TCP/UDP port. |

The normal daemon listens on its local P2P IP and drives WFD requests over the
accepted TCP connection. It is implemented using `RtspClient::accept_reverse`,
not the older passive `RtspServer` helper. The accept window is 15 seconds. The
peer must match the expected IP or share its IPv4 /24; this is a plausibility
check, not authenticated sink identity. The daemon refuses to listen when the local P2P address is unavailable.

`--client` retries the outbound connection up to 20 times with 500 ms between
attempts, then falls back to listening. Connection attempt duration adds to that
budget. If the source is GO, it immediately listens instead of dialing itself.
Some TVs abandon the group before a lengthy fallback completes; use the default
for sinks that initiate RTSP. The inbound listener and local WFD advertisement both use TCP 7236; the
sink's advertised port is used for outbound RTSP connections.

The RTSP TCP connection stays open for the session. The keepalive loop responds
to peer requests and sends GET_PARAMETER after 25 seconds without incoming data.
TCP EOF or TEARDOWN ends the session. UDP media does not replace this connection.

`MediaTransport::bind()` asks the OS for an ephemeral even UDP port and reserves
the next port for RTCP. SETUP advertises the actual pair as `server_port=P-P+1`;
GStreamer reuses those sockets. There is no CLI option for a fixed source range.
The installed helper permits the negotiated RTCP return port before SETUP
succeeds. Unmanaged library callers must configure their own allowances. Do not assume allowing inbound
5004/5005 is sufficient, or that RTSP conntrack helpers automatically open UDP
pinholes. When no sink RTCP port is offered, the RTCP socket is reserved but
GStreamer does not attach RTCP input/output.

No RTP-over-TCP interleaving fallback is wired into the stream pipeline. A
TCP-only network policy can allow negotiation while preventing all video.
NetworkManager may expose DNS as part of shared mode, but waycast exchanges
numeric addresses and does not require DNS queries to cast. UIBC/input backchannel,
coupled sinks and standby/resume are advertised as `none`; no corresponding extra
ports are required. HDCP helper code exists, but current daemon negotiation
advertises content protection `none` and does not call those handshake helpers.
Opening an HDCP port does not enable protected media or fix an HDCP-required sink.

## Capacity and display modes

| Configuration | Configured video target |
| --- | --- |
| Default mirror | 8 Mbit/s |
| `--extend` | 10 Mbit/s, 1080p30 |
| Fixed external 4K | 20 Mbit/s, subject to successful mode negotiation |
| Other external selections | 8 Mbit/s |

Allow throughput above video plus optional 0.128 Mbit/s AAC for MPEG-TS, RTP,
UDP/IP, Wi-Fi overhead and encoder bursts. These are encoder targets, not measured
minimum radio link rates or an assurance of 4K support. The WFD advertisement's
200 Mbit/s field is a capability value, not a bandwidth reservation. There is no
network-congestion-driven bitrate controller in the daemon; low loss, adequate
sustained throughput and stable latency matter even for a mostly static extended
desktop. Hardware/software H.264 and H.265 use the same network port scheme;
codec negotiation and HDCP compatibility remain separate constraints.

## Read-only diagnostic sequence

Replace example interface and IP values with those from this session.

```bash
# Radio and service visibility
nmcli device status
iw dev
iw list
nmcli general permissions
systemctl status NetworkManager wpa_supplicant

# Discovery and then a full session
waycast --interface wlp0s20f3 discover --timeout 15
RUST_LOG=waycast_net=debug,waycast_daemon=debug,waycast_rtsp=debug waycast --interface wlp0s20f3 daemon --sink '<name-or-MAC>'

# In another terminal while the session is active
journalctl -u wpa_supplicant --since '2 minutes ago' --no-pager
ip -4 -brief address
ip -4 route
ip rule
ip route get 192.168.49.10 from 192.168.49.1
ss -ltnp
ss -uanp
sudo nft list ruleset
sysctl net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter
cat /proc/sys/net/ipv4/conf/p2p-wlp0s20f3-0/rp_filter
nstat -az
sudo tcpdump -ni p2p-wlp0s20f3-0 'arp or udp or tcp'
```

The first two groups inspect state or run discovery/casting; the remaining
commands inspect the live session without changing firewall or routing settings.
Packet capture can contain screen/audio data; use it for the session being diagnosed.

| Symptom | What to verify |
| --- | --- |
| No sink found | P2P device type, correct radio, sink sharing mode, radio availability and discovery permissions. IP firewall rules cannot repair missing P2P discovery. |
| Group forms but no IP | Actual GO/client role; access to group-start events/journal; DHCP traffic in both directions; shared-mode reapply and helper startup; source GO address settling at `192.168.49.1`. |
| TV sends SYN repeatedly | Correct listener address/port, every active firewall input chain, route to peer, reverse-path filtering. |
| Outbound RTSP refused | Sink may require the default inbound role; verify advertised port and readiness before using `--client`. |
| RTSP succeeds but no picture | Negotiated RTP destination and actual packets first, then codec/capture/decoder compatibility. Verify RTCP ports rather than assuming 5005. |
| Drops during playback | RTSP EOF/TEARDOWN, Wi-Fi group loss, media loss, keepalives and sink codec/HDCP requirements. |
| Internet drops while casting | Radio concurrency/channel limitations, VPN policy and route overlap; `never-default` alone cannot guarantee radio concurrency. |

Inspect all firewall managers/tables: an allow rule in one chain does not undo a
drop elsewhere. Do not apply a global port-open rule or flush the firewall as a
substitute for identifying the P2P interface and negotiated ports.

Strict reverse-path filtering can reject traffic when its reverse route differs
from the incoming interface. Confirm routes and counters before changing it.
Linux uses the maximum of `conf/all/rp_filter` and the interface setting: 1 is
strict and 2 is loose. `conf/default` supplies defaults for newly created
interfaces; it does not rewrite an existing P2P interface. See the
[kernel IP sysctl documentation](https://kernel.org/doc/html/latest/networking/ip-sysctl.html).

## Implementation map and validation limits

- [Network manager](../crates/net/src/lib.rs): `find_p2p_device`, `discover_sinks`,
  `connect`, group-start D-Bus/journal parsing, address lookup and lifetime binding.
- [Daemon](../crates/daemon/src/lib.rs): `negotiate`, `determine_sink_role`,
  `negotiate_as_client`, `negotiate_as_reverse_client`,
  `exchange_rtsp_capabilities`, `start_negotiated_stream`.
- [RTSP](../crates/rtsp/src/lib.rs): `accept_reverse`, `MediaTransport::bind`,
  `build_peer_request_response`, `run_keepalive`. The standalone `RtspServer`
  path does not have the same socket-reservation wiring as the active daemon path.
- [Streaming](../crates/stream/src/lib.rs): `StreamConfig`,
  `new_pipewire_with_audio`, `set_transport` implement muxing and socket reuse.
- [CLI](../crates/cli/src/main.rs): command scope and flags.
- [Doctor](../crates/doctor/src/lib.rs): local prerequisite checks, not an end-to-end
  firewall, DHCP, radio concurrency or sink compatibility test.
- [Media tests](../crates/stream/tests/media_transport.rs) and
  [RTSP tests](../crates/rtsp/src/lib.rs) exercise transport behavior locally;
  [hardware scenarios](MIRACAST_TEST_SCENARIOS.md) describe broader testing.

This review did not initiate a hardware casting session or modify host networking.
Loopback tests cannot establish real radio, DHCP, firewall or TV compatibility.

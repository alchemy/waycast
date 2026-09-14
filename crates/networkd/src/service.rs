//! Privileged system-bus endpoint. One validated P2P session at a time.
use crate::{
    firewall::{self, GroupInterface, Rules},
    SessionInfo,
};
use anyhow::{bail, Context, Result};
use socket2::{Socket, Type};
use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
    time::Duration,
};
use tokio::sync::Mutex;
use waycast_net::{P2pConfig, P2pConnection, P2pManager};

struct Session {
    owner: String,
    connection: P2pConnection,
    rules: Rules,
    // Pin the permitted sockets until session cleanup; prevent port reuse.
    sockets: Option<(Socket, Socket, Socket)>,
}

/// D-Bus service state. Installation policy, not caller-supplied UID, grants access.
#[derive(Clone, Default)]
pub struct NetworkService {
    session: Arc<Mutex<Option<Session>>>,
}

fn failed(error: impl std::fmt::Display) -> zbus::fdo::Error {
    zbus::fdo::Error::Failed(error.to_string())
}

fn sender(header: &zbus::message::Header<'_>) -> zbus::fdo::Result<String> {
    header
        .sender()
        .map(ToString::to_string)
        .ok_or_else(|| zbus::fdo::Error::AccessDenied("Missing bus sender".into()))
}

fn require_owner(actual: &str, expected: &str) -> Result<()> {
    if actual != expected {
        bail!("The caller does not own this network session");
    }
    Ok(())
}

async fn owner_present(bus: &zbus::Connection, owner: &str) -> bool {
    let Ok(proxy) = zbus::fdo::DBusProxy::new(bus).await else {
        return false;
    };
    let Ok(name) = owner.try_into() else {
        return false;
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), proxy.name_has_owner(name)).await,
        Ok(Ok(true))
    )
}

async fn wait_for_owner_loss(bus: &zbus::Connection, owner: &str) {
    loop {
        if !owner_present(bus, owner).await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

async fn authorize(bus: &zbus::Connection, owner: &str) -> Result<()> {
    let proxy = zbus::Proxy::new(
        bus,
        "org.freedesktop.PolicyKit1",
        "/org/freedesktop/PolicyKit1/Authority",
        "org.freedesktop.PolicyKit1.Authority",
    )
    .await?;
    let subject = (
        "system-bus-name",
        HashMap::from([("name", zvariant::Value::from(owner))]),
    );
    let details: HashMap<&str, &str> = HashMap::new();
    let (allowed, _, _): (bool, bool, HashMap<String, String>) = tokio::time::timeout(
        Duration::from_secs(30),
        proxy.call(
            "CheckAuthorization",
            &(subject, "org.waycast.network.configure", details, 1u32, ""),
        ),
    )
    .await??;
    if !allowed {
        bail!("Wireless display network authorization was denied");
    }
    Ok(())
}

async fn clear_rules() {
    if let Err(error) = firewall::cleanup().await {
        tracing::error!(%error, "Cannot clear temporary rules; exiting for systemd recovery");
        std::process::exit(1);
    }
}

async fn close_session(session: Session) -> Result<()> {
    // Clear rules even if NM no longer knows the active connection, and drop the
    // dedicated activation bus even if deactivation fails.
    let firewall_result = firewall::cleanup().await;
    let network_result =
        tokio::time::timeout(Duration::from_secs(5), session.connection.close()).await;
    drop(session);
    if let Err(error) = firewall_result {
        tracing::error!(%error, "Cannot clear temporary rules; exiting for systemd recovery");
        std::process::exit(1);
    }
    // Dropping the dedicated activation bus also releases the group when NM
    // has already removed it or cannot complete explicit deactivation.
    if !matches!(network_result, Ok(Ok(()))) {
        tracing::warn!("NetworkManager deactivation did not complete; activation bus released");
    }
    Ok(())
}

#[zbus::interface(name = "org.waycast.Network1")]
impl NetworkService {
    /// Authorize, validate the discovered peer, and activate its P2P group.
    async fn begin_session(
        &self,
        radio: &str,
        peer: &str,
        #[zbus(header)] header: zbus::message::Header<'_>,
        #[zbus(connection)] bus: &zbus::Connection,
    ) -> zbus::fdo::Result<SessionInfo> {
        let owner = sender(&header)?;
        firewall::validate_name(radio).map_err(failed)?;
        if peer.len() != 17 || !peer.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
            return Err(failed("Invalid discovered peer address"));
        }
        authorize(bus, &owner).await.map_err(failed)?;
        let mut guard = self
            .session
            .try_lock()
            .map_err(|_| failed("Wireless display network setup is busy"))?;
        if guard.is_some() {
            return Err(failed("A wireless display session is already active"));
        }
        firewall::ensure_hook().await.map_err(failed)?;
        clear_rules().await;
        let prepared = Arc::new(Mutex::new(None));
        let prepare_store = prepared.clone();
        let setup = async {
            let manager = P2pManager::new(P2pConfig {
                interface_name: radio.into(),
                group_name: "waycast-managed".into(),
            })
            .await?;
            let radio_owned = manager.radio().to_owned();
            let sink = manager.resolve_sink(peer).await?;
            if sink.rtsp_port < 1024 {
                bail!("TV advertises an unsupported privileged RTSP port");
            }
            let rtsp = waycast_net::SOURCE_RTSP_PORT;
            let connection = manager
                .connect_with_prepare(&sink, move |name, group_owner| async move {
                    let result: Result<()> = async {
                        let interface = GroupInterface::validate(&radio_owned, &name)?;
                        interface.claim().await?;
                        let rules = Rules {
                            interface,
                            group_owner,
                            rtsp,
                            local: None,
                            peer: None,
                            rtcp: None,
                        };
                        rules.apply().await?;
                        *prepare_store.lock().await = Some(rules);
                        Ok(())
                    }
                    .await;
                    result.map_err(|e| waycast_net::NetError::ConnectionFailed(e.to_string()))
                })
                .await?;
            Ok::<_, anyhow::Error>(connection)
        };
        let result = tokio::select! {
            result = tokio::time::timeout(Duration::from_secs(60), setup) => result.context("P2P setup timed out").and_then(|r| r),
            _ = wait_for_owner_loss(bus, &owner) => Err(anyhow::anyhow!("Caller disconnected during P2P setup")),
        };
        let connection = match result {
            Ok(connection) => connection,
            Err(error) => {
                clear_rules().await;
                return Err(failed(error));
            }
        };
        let finalize = async {
            let mut rules = prepared
                .lock()
                .await
                .take()
                .context("Missing prepared interface")?;
            let local: Ipv4Addr = connection
                .sink
                .ip_address
                .as_deref()
                .context("Missing local IPv4")?
                .parse()?;
            rules.local = Some(local);
            rules.apply().await?;
            let info = SessionInfo {
                interface: connection.interface.clone(),
                local_ip: local.to_string(),
                go_ip: connection
                    .sink
                    .go_ip_address
                    .clone()
                    .context("Missing group owner IPv4")?,
                rtsp_port: connection.sink.rtsp_port,
            };
            Ok::<_, anyhow::Error>((rules, info))
        }
        .await;
        match finalize {
            Ok((rules, info)) => {
                tracing::info!(%owner, interface = %info.interface, local_ip = %info.local_ip, "Wireless display network ready");
                *guard = Some(Session {
                    owner,
                    connection,
                    rules,
                    sockets: None,
                });
                Ok(info)
            }
            Err(error) => {
                let _ = connection.close().await;
                drop(connection);
                clear_rules().await;
                Err(failed(error))
            }
        }
    }

    /// Validate actual sockets passed over D-Bus, then authorize precisely their RTCP flow.
    async fn authorize_media(
        &self,
        control: zvariant::OwnedFd,
        rtp: zvariant::OwnedFd,
        rtcp: zvariant::OwnedFd,
        sink_rtcp: u16,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let owner = sender(&header)?;
        let mut guard = self.session.lock().await;
        let session = guard
            .as_mut()
            .ok_or_else(|| failed("No active network session"))?;
        require_owner(&owner, &session.owner).map_err(failed)?;
        let sockets = (
            Socket::from(std::os::fd::OwnedFd::from(control)),
            Socket::from(std::os::fd::OwnedFd::from(rtp)),
            Socket::from(std::os::fd::OwnedFd::from(rtcp)),
        );
        let (peer, port) =
            validate_sockets(&session.rules, &session.connection, &sockets).map_err(failed)?;
        let mut rules = session.rules.clone();
        rules.peer = Some(peer);
        rules.rtcp = (sink_rtcp != 0).then_some((port, sink_rtcp));
        rules.apply().await.map_err(failed)?;
        session.rules = rules;
        session.sockets = Some(sockets);
        Ok(())
    }

    /// Idempotent teardown for the caller that owns the session.
    async fn end_session(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<()> {
        let owner = sender(&header)?;
        let mut guard = self.session.lock().await;
        if let Some(session) = guard.as_ref() {
            require_owner(&owner, &session.owner).map_err(failed)?;
        }
        if let Some(session) = guard.take() {
            close_session(session).await.map_err(failed)?;
        }
        Ok(())
    }

    /// Polling health endpoint bound to the caller; never returns another user's state.
    async fn session_alive(
        &self,
        #[zbus(header)] header: zbus::message::Header<'_>,
    ) -> zbus::fdo::Result<bool> {
        let owner = sender(&header)?;
        Ok(self
            .session
            .lock()
            .await
            .as_ref()
            .is_some_and(|s| s.owner == owner))
    }
}

fn ipv4(address: socket2::SockAddr) -> Result<SocketAddrV4> {
    address
        .as_socket_ipv4()
        .context("Only IPv4 sockets are supported")
}

fn validate_sockets(
    rules: &Rules,
    connection: &P2pConnection,
    sockets: &(Socket, Socket, Socket),
) -> Result<(Ipv4Addr, u16)> {
    if sockets.0.r#type()? != Type::STREAM
        || sockets.1.r#type()? != Type::DGRAM
        || sockets.2.r#type()? != Type::DGRAM
    {
        bail!("Expected a TCP control socket and two UDP media sockets");
    }
    let control = ipv4(sockets.0.local_addr()?)?;
    let peer = ipv4(sockets.0.peer_addr()?)?;
    let rtp = ipv4(sockets.1.local_addr()?)?;
    let rtcp = ipv4(sockets.2.local_addr()?)?;
    validate_addresses(
        rules.local.context("No local group address")?,
        &connection
            .sink
            .go_ip_address
            .clone()
            .context("Missing group owner")?
            .parse()?,
        rules.group_owner,
        connection.sink.rtsp_port,
        control,
        peer,
        rtp,
        rtcp,
    )?;
    Ok((*peer.ip(), rtcp.port()))
}

#[allow(clippy::too_many_arguments)]
fn validate_addresses(
    local: Ipv4Addr,
    go: &Ipv4Addr,
    group_owner: bool,
    rtsp_port: u16,
    control: SocketAddrV4,
    peer: SocketAddrV4,
    rtp: SocketAddrV4,
    rtcp: SocketAddrV4,
) -> Result<()> {
    if [control.ip(), rtp.ip(), rtcp.ip()]
        .iter()
        .any(|ip| **ip != local)
    {
        bail!("Sockets must bind the session's local P2P address");
    }
    if control.port() != waycast_net::SOURCE_RTSP_PORT && peer.port() != rtsp_port {
        bail!("Control socket does not use the negotiated RTSP port");
    }
    let peer_ip = *peer.ip();
    if peer_ip == local
        || peer_ip.is_loopback()
        || peer_ip.is_multicast()
        || peer_ip.is_unspecified()
        || peer_ip.octets()[3] == 0
        || peer_ip.octets()[3] == 255
    {
        bail!("Invalid control peer");
    }
    if group_owner {
        if peer_ip.octets()[..3] != local.octets()[..3] {
            bail!("Control peer is outside the P2P group");
        }
    } else if peer_ip != *go {
        bail!("Control peer is not the selected group owner");
    }
    if rtp.port() < 1024
        || !rtp.port().is_multiple_of(2)
        || rtp.port().checked_add(1) != Some(rtcp.port())
    {
        bail!("Expected reserved consecutive even RTP / odd RTCP ports");
    }
    Ok(())
}

impl NetworkService {
    /// Monitor caller lifetime and the exact rule/interface state. A reload ends
    /// the session instead of reopening permissions from potentially stale data.
    pub async fn supervise(&self, bus: zbus::Connection) {
        loop {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Ok(mut guard) = self.session.try_lock() else {
                continue;
            };
            let Some(session) = guard.as_ref() else {
                continue;
            };
            if !owner_present(&bus, &session.owner).await
                || !session.connection.is_active().await
                || !session.rules.intact().await
            {
                if let Some(session) = guard.take() {
                    if let Err(error) = close_session(session).await {
                        tracing::error!(%error, "Network session cleanup failed; exiting for systemd cleanup");
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

/// Test-only supervisor exercise; caller must create a fresh network namespace
/// and install the supplied rules there first.
#[cfg(test)]
pub(crate) async fn test_caller_loss(rules: Rules) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    assert_ne!(
        std::fs::read_link("/proc/self/ns/net").unwrap(),
        std::path::PathBuf::from(std::env::var("WAYCAST_PARENT_NETNS").unwrap())
    );
    let mut child = tokio::process::Command::new("dbus-daemon")
        .args(["--session", "--nofork", "--print-address=1"])
        .stdout(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let address = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .next_line()
        .await
        .unwrap()
        .unwrap();
    let service = NetworkService::default();
    let bus = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .name(crate::BUS_NAME)
        .unwrap()
        .serve_at(crate::OBJECT_PATH, service.clone())
        .unwrap()
        .build()
        .await
        .unwrap();
    let owner = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let stranger = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let sink = waycast_net::Sink {
        name: "test".into(),
        address: "00:11:22:33:44:55".into(),
        peer_path: None,
        ip_address: Some("192.168.49.1".into()),
        go_ip_address: Some("192.168.49.1".into()),
        rtsp_port: 7236,
        wfd_capabilities: None,
    };
    *service.session.lock().await = Some(Session {
        owner: owner.unique_name().unwrap().to_string(),
        connection: P2pConnection::managed(sink, "p2p-test".into(), bus.clone()),
        rules,
        sockets: None,
    });
    let proxy = crate::NetworkProxy::new(&stranger).await.unwrap();
    assert!(
        proxy.end_session().await.is_err(),
        "another caller cannot remove a session"
    );
    assert!(service.session.lock().await.is_some());
    // Closing the owning bus models SIGKILL: there is no EndSession call.
    owner.close().await.unwrap();
    let worker = service.clone();
    let task = tokio::spawn(async move {
        worker.supervise(bus).await;
    });
    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if service.session.lock().await.is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("lost caller must be cleaned up");
    task.abort();
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_is_per_bus_connection_not_per_uid_or_session_name() {
        assert!(require_owner(":1.10", ":1.10").is_ok());
        assert!(require_owner(":1.11", ":1.10").is_err());
    }
    fn check(peer: &str, local_socket: &str, rtp_port: u16, rtcp_port: u16) -> Result<()> {
        validate_addresses(
            "192.168.49.10".parse().unwrap(),
            &"192.168.49.1".parse().unwrap(),
            false,
            7236,
            format!("{local_socket}:7236").parse().unwrap(),
            format!("{peer}:40000").parse().unwrap(),
            format!("{local_socket}:{rtp_port}").parse().unwrap(),
            format!("{local_socket}:{rtcp_port}").parse().unwrap(),
        )
    }
    #[test]
    fn accepts_real_group_endpoints_and_rejects_forged_socket_metadata() {
        assert!(check("192.168.49.1", "192.168.49.10", 45000, 45001).is_ok());
        for (peer, local, rtp, rtcp) in [
            ("192.168.1.1", "192.168.49.10", 45000, 45001),
            ("192.168.49.1", "0.0.0.0", 45000, 45001),
            ("192.168.49.1", "192.168.49.10", 500, 501),
            ("192.168.49.1", "192.168.49.10", 45000, 45003),
            ("192.168.49.10", "192.168.49.10", 45000, 45001),
        ] {
            assert!(check(peer, local, rtp, rtcp).is_err());
        }
    }
    #[test]
    fn custom_sink_port_does_not_change_the_sources_listening_port() {
        let local = "192.168.49.10".parse().unwrap();
        let go = "192.168.49.1".parse().unwrap();
        let rtp = "192.168.49.10:45000".parse().unwrap();
        let rtcp = "192.168.49.10:45001".parse().unwrap();
        assert!(validate_addresses(
            local,
            &go,
            false,
            8000,
            "192.168.49.10:7236".parse().unwrap(),
            "192.168.49.1:40000".parse().unwrap(),
            rtp,
            rtcp
        )
        .is_ok());
        assert!(validate_addresses(
            local,
            &go,
            false,
            8000,
            "192.168.49.10:40000".parse().unwrap(),
            "192.168.49.1:8000".parse().unwrap(),
            rtp,
            rtcp
        )
        .is_ok());
        assert!(validate_addresses(
            local,
            &go,
            false,
            8000,
            "192.168.49.10:8000".parse().unwrap(),
            "192.168.49.1:40000".parse().unwrap(),
            rtp,
            rtcp
        )
        .is_err());
    }

    struct DenyPolicy;
    #[zbus::interface(name = "org.freedesktop.PolicyKit1.Authority")]
    impl DenyPolicy {
        async fn check_authorization(
            &self,
            subject: (String, HashMap<String, zvariant::OwnedValue>),
            action: String,
            _details: HashMap<String, String>,
            flags: u32,
            _cancel: String,
        ) -> (bool, bool, HashMap<String, String>) {
            assert_eq!(subject.0, "system-bus-name");
            assert!(subject.1.contains_key("name"));
            assert_eq!(action, "org.waycast.network.configure");
            assert_eq!(flags, 1);
            (false, false, HashMap::new())
        }
    }

    #[tokio::test]
    async fn dbus_denial_precedes_network_or_firewall_access() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        let mut child = tokio::process::Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let address = BufReader::new(child.stdout.take().unwrap())
            .lines()
            .next_line()
            .await
            .unwrap()
            .unwrap();
        let _server = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .name(crate::BUS_NAME)
            .unwrap()
            .name("org.freedesktop.PolicyKit1")
            .unwrap()
            .serve_at(crate::OBJECT_PATH, NetworkService::default())
            .unwrap()
            .serve_at("/org/freedesktop/PolicyKit1/Authority", DenyPolicy)
            .unwrap()
            .build()
            .await
            .unwrap();
        let client = zbus::connection::Builder::address(address.as_str())
            .unwrap()
            .build()
            .await
            .unwrap();
        let proxy = crate::NetworkProxy::new(&client).await.unwrap();
        let error = proxy
            .begin_session("wlan0", "00:11:22:33:44:55")
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("authorization was denied"),
            "{error}"
        );
        assert!(!proxy.session_alive().await.unwrap());
        proxy.end_session().await.unwrap();
        proxy.end_session().await.unwrap();
    }
}

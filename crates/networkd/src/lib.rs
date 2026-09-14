//! Client for the privileged, session-scoped Omarchy/UFW networking service.
use std::os::fd::AsFd;
use std::sync::Arc;
use std::time::Duration;
use waycast_net::{P2pConnection, Sink};

pub mod firewall;
pub mod service;

/// System bus name and interface of the installed helper.
pub const BUS_NAME: &str = "org.waycast.Network1";
/// Object path of the installed helper.
pub const OBJECT_PATH: &str = "/org/waycast/Network1";

/// Addressing returned by the helper after group configuration completes.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, zvariant::Type)]
pub struct SessionInfo {
    /// Kernel P2P data interface (not the discovery device).
    pub interface: String,
    /// Local IPv4 address on the group.
    pub local_ip: String,
    /// IPv4 address of the group owner.
    pub go_ip: String,
    /// RTSP port advertised by the validated sink.
    pub rtsp_port: u16,
}

#[zbus::proxy(
    interface = "org.waycast.Network1",
    default_service = "org.waycast.Network1",
    default_path = "/org/waycast/Network1"
)]
trait Network {
    fn begin_session(&self, radio: &str, peer: &str) -> zbus::Result<SessionInfo>;
    fn authorize_media(
        &self,
        control: zvariant::Fd<'_>,
        rtp: zvariant::Fd<'_>,
        rtcp: zvariant::Fd<'_>,
        sink_rtcp: u16,
    ) -> zbus::Result<()>;
    fn end_session(&self) -> zbus::Result<()>;
    fn session_alive(&self) -> zbus::Result<bool>;
}

/// Owns a dedicated bus connection. Losing its final reference releases the
/// helper session even if the caller never reaches explicit teardown.
#[derive(Debug)]
pub struct NetworkSession {
    connection: Arc<zbus::Connection>,
}

/// Non-owning access for RTSP and health tasks; cannot keep an abandoned session alive.
#[derive(Debug, Clone)]
pub struct NetworkSessionRef {
    connection: std::sync::Weak<zbus::Connection>,
}

impl NetworkSessionRef {
    /// Authorize media if the session owner still exists.
    pub async fn authorize_media(
        &self,
        control: &tokio::net::TcpStream,
        rtp: &std::net::UdpSocket,
        rtcp: &std::net::UdpSocket,
        sink_rtcp: Option<u16>,
    ) -> anyhow::Result<()> {
        let connection = self
            .connection
            .upgrade()
            .ok_or_else(|| anyhow::anyhow!("Network session ended"))?;
        NetworkSession { connection }
            .authorize_media(control, rtp, rtcp, sink_rtcp)
            .await
    }

    /// Return false if either the local session owner or the service disappeared.
    pub async fn alive(&self) -> bool {
        let Some(connection) = self.connection.upgrade() else {
            return false;
        };
        NetworkSession { connection }.alive().await
    }
}

impl NetworkSession {
    /// Obtain non-owning access for background tasks.
    pub fn downgrade(&self) -> NetworkSessionRef {
        NetworkSessionRef {
            connection: Arc::downgrade(&self.connection),
        }
    }

    /// Begin a validated P2P session through the installed service.
    pub async fn begin(radio: &str, sink: &Sink) -> anyhow::Result<(Self, P2pConnection)> {
        // A new connection per session is deliberate: a process-wide bus would
        // keep abandoned sessions alive until the entire process exits.
        let connection = zbus::Connection::system().await?;
        let proxy = NetworkProxy::new(&connection).await?;
        let info = tokio::time::timeout(Duration::from_secs(120), proxy.begin_session(radio, &sink.address))
            .await.map_err(|_| anyhow::anyhow!("Timed out preparing the wireless display network"))?
            .map_err(|e| anyhow::anyhow!("Wireless display network setup failed: {e}. Install/enable waycast-networkd using the Waycast installer."))?;
        let mut sink = sink.clone();
        sink.ip_address = Some(info.local_ip);
        sink.go_ip_address = Some(info.go_ip);
        sink.rtsp_port = info.rtsp_port;
        let p2p = P2pConnection::managed(sink, info.interface, connection.clone());
        Ok((
            Self {
                connection: Arc::new(connection),
            },
            p2p,
        ))
    }

    /// Ask the helper to validate the live control and media sockets and permit
    /// RTCP before advertising the local media ports to the TV.
    pub async fn authorize_media(
        &self,
        control: &tokio::net::TcpStream,
        rtp: &std::net::UdpSocket,
        rtcp: &std::net::UdpSocket,
        sink_rtcp: Option<u16>,
    ) -> anyhow::Result<()> {
        let proxy = NetworkProxy::new(&self.connection).await?;
        tokio::time::timeout(
            Duration::from_secs(10),
            proxy.authorize_media(
                zvariant::Fd::from(control.as_fd()),
                zvariant::Fd::from(rtp.as_fd()),
                zvariant::Fd::from(rtcp.as_fd()),
                sink_rtcp.unwrap_or(0),
            ),
        )
        .await??;
        Ok(())
    }

    /// Explicit teardown; loss of the bus connection is a fallback.
    pub async fn end(&self) -> anyhow::Result<()> {
        let proxy = NetworkProxy::new(&self.connection).await?;
        tokio::time::timeout(Duration::from_secs(15), proxy.end_session()).await??;
        Ok(())
    }

    /// Whether the helper still owns this caller's session. Used to stop capture
    /// after interface loss, helper restart, or a firewall reload.
    pub async fn alive(&self) -> bool {
        let Ok(proxy) = NetworkProxy::new(&self.connection).await else {
            return false;
        };
        matches!(
            tokio::time::timeout(Duration::from_secs(3), proxy.session_alive()).await,
            Ok(Ok(true))
        )
    }
}

//! Private D-Bus integration test for the pre-address firewall hook.
use super::*;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use tokio::io::{AsyncBufReadExt, BufReader};

struct MockNm;
#[zbus::interface(name = "org.freedesktop.NetworkManager")]
impl MockNm {
    async fn get_devices(&self) -> Vec<zvariant::OwnedObjectPath> {
        vec!["/nm/device".try_into().unwrap()]
    }
    async fn add_and_activate_connection2(
        &self,
        _config: HashMap<String, HashMap<String, zvariant::OwnedValue>>,
        _device: zvariant::OwnedObjectPath,
        _peer: zvariant::OwnedObjectPath,
        _options: HashMap<String, zvariant::OwnedValue>,
        #[zbus(connection)] bus: &Connection,
    ) -> (
        zvariant::OwnedObjectPath,
        zvariant::OwnedObjectPath,
        HashMap<String, zvariant::OwnedValue>,
    ) {
        let properties = HashMap::from([
            (
                "interface_object",
                zvariant::Value::from(zvariant::ObjectPath::try_from("/wpa/group").unwrap()),
            ),
            ("role", zvariant::Value::from("GO")),
        ]);
        // Emit BEFORE returning activation, exercising the subscription race.
        bus.emit_signal(
            None::<&str>,
            "/wpa/p2p",
            "fi.w1.wpa_supplicant1.Interface.P2PDevice",
            "GroupStarted",
            &(properties,),
        )
        .await
        .unwrap();
        (
            "/nm/profile".try_into().unwrap(),
            "/nm/active".try_into().unwrap(),
            HashMap::new(),
        )
    }
}
struct MockDevice;
#[zbus::interface(name = "org.freedesktop.NetworkManager.Device")]
impl MockDevice {
    #[zbus(property)]
    fn device_type(&self) -> u32 {
        30
    }
    #[zbus(property)]
    fn interface(&self) -> &str {
        "p2p-dev-wlan0"
    }
}
struct MockWpa;
#[zbus::interface(name = "fi.w1.wpa_supplicant1")]
impl MockWpa {
    #[zbus(property)]
    fn interfaces(&self) -> Vec<zvariant::OwnedObjectPath> {
        vec![
            "/wpa/unrelated".try_into().unwrap(),
            "/wpa/p2p".try_into().unwrap(),
        ]
    }
}
struct MockInterface(&'static str);
#[zbus::interface(name = "fi.w1.wpa_supplicant1.Interface")]
impl MockInterface {
    #[zbus(property)]
    fn ifname(&self) -> &str {
        self.0
    }
}

#[tokio::test]
async fn managed_setup_prepares_group_before_waiting_for_ip_and_does_not_miss_early_event() {
    check_managed_setup("p2p-dev-wlan0").await;
}

#[tokio::test]
async fn managed_setup_accepts_supplicant_radio_interface() {
    check_managed_setup("wlan0").await;
}

async fn check_managed_setup(supplicant_ifname: &'static str) {
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
        .name("org.freedesktop.NetworkManager")
        .unwrap()
        .name("fi.w1.wpa_supplicant1")
        .unwrap()
        .serve_at("/org/freedesktop/NetworkManager", MockNm)
        .unwrap()
        .serve_at("/nm/device", MockDevice)
        .unwrap()
        .serve_at("/fi/w1/wpa_supplicant1", MockWpa)
        .unwrap()
        .serve_at("/wpa/unrelated", MockInterface("wlan1"))
        .unwrap()
        .serve_at("/wpa/p2p", MockInterface(supplicant_ifname))
        .unwrap()
        .serve_at("/wpa/group", MockInterface("p2p-wlan0-0"))
        .unwrap()
        .build()
        .await
        .unwrap();
    let client = zbus::connection::Builder::address(address.as_str())
        .unwrap()
        .build()
        .await
        .unwrap();
    let automatic = P2pManager::from_connection(
        P2pConfig {
            interface_name: "auto".into(),
            group_name: "test".into(),
        },
        client.clone(),
    )
    .await
    .unwrap();
    assert_eq!(automatic.radio(), "wlan0");
    // Do not silently select a P2P device from another radio.
    assert!(P2pManager::from_connection(
        P2pConfig {
            interface_name: "wlan1".into(),
            group_name: "test".into()
        },
        client.clone()
    )
    .await
    .is_err());
    let manager = P2pManager::from_connection(
        P2pConfig {
            interface_name: "wlan0".into(),
            group_name: "test".into(),
        },
        client,
    )
    .await
    .unwrap();
    let sink = Sink {
        name: "TV".into(),
        address: "00:11:22:33:44:55".into(),
        peer_path: Some("/nm/peer".try_into().unwrap()),
        ip_address: None,
        go_ip_address: None,
        rtsp_port: 7236,
        wfd_capabilities: None,
    };
    let called = Arc::new(AtomicBool::new(false));
    let flag = called.clone();
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        manager.connect_with_prepare(&sink, move |name, owner| async move {
            assert_eq!(name, "p2p-wlan0-0");
            assert!(owner);
            flag.store(true, Ordering::SeqCst);
            // Deliberate failure ensures no IP reconfiguration happens before this hook.
            Err(NetError::ConnectionFailed("test firewall denied".into()))
        }),
    )
    .await
    .expect("Preparation should not wait for DHCP");
    assert!(
        matches!(result, Err(NetError::ConnectionFailed(message)) if message == "test firewall denied")
    );
    assert!(called.load(Ordering::SeqCst));
}

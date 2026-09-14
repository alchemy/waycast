//! UFW-owned hook and temporary rules. No user-supplied command is executed.
use anyhow::{bail, Context, Result};
use std::{net::Ipv4Addr, process::Stdio, time::Duration};
use tokio::{io::AsyncWriteExt, process::Command};

/// Dedicated chain installed by the root-owned installer in UFW before.rules.
pub const CHAIN: &str = "waycast-input";
// Reserved network-device group, paired with the exact interface name. A new
// interface reusing that name starts in group 0 and cannot inherit these rules.
const DEVICE_GROUP: u32 = 0x574644;

/// Validated interface identity; a name alone is not sufficient authorization.
#[derive(Debug, Clone)]
pub struct GroupInterface {
    /// Kernel interface name.
    pub name: String,
    /// Kernel interface index, checked before every firewall update.
    pub index: u32,
    phy: std::path::PathBuf,
}

impl GroupInterface {
    /// Resolve an interface from a trusted supplicant event and ensure it belongs
    /// to the radio selected through NetworkManager.
    pub fn validate(radio: &str, name: &str) -> Result<Self> {
        validate_name(radio)?;
        validate_name(name)?;
        if !(name.starts_with("p2p-") || name == "p2p0") {
            bail!("Not a P2P data interface");
        }
        let phy = std::fs::canonicalize(format!("/sys/class/net/{radio}/phy80211"))?;
        let result = Self {
            name: name.into(),
            index: interface_index(name)?,
            phy,
        };
        if !result.identity_matches() {
            bail!("P2P interface is not on the selected radio");
        }
        Ok(result)
    }

    /// Tag this helper-owned interface so name reuse cannot inherit allowances.
    pub async fn claim(&self) -> Result<()> {
        if !self.identity_matches() {
            bail!("P2P interface was replaced before setup");
        }
        let group = device_group(&self.name)?;
        if group != 0 && group != DEVICE_GROUP {
            bail!("P2P interface already has a custom device group");
        }
        run(
            "/usr/bin/ip",
            &[
                "link",
                "set",
                "dev",
                &self.name,
                "group",
                &DEVICE_GROUP.to_string(),
            ],
            None,
        )
        .await?;
        if !self.exists() {
            bail!("P2P interface changed while tagging it");
        }
        Ok(())
    }

    /// Detect deletion/replacement before reusing an interface-scoped allowance.
    pub fn exists(&self) -> bool {
        self.identity_matches() && device_group(&self.name).ok() == Some(DEVICE_GROUP)
    }

    fn identity_matches(&self) -> bool {
        interface_index(&self.name).ok() == Some(self.index)
            && std::fs::canonicalize(format!("/sys/class/net/{}/phy80211", self.name))
                .ok()
                .as_ref()
                == Some(&self.phy)
    }
}

/// Restrict strings interpolated into iptables-restore to kernel interface names.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
    {
        bail!("Invalid network interface name");
    }
    Ok(())
}

fn device_group(name: &str) -> Result<u32> {
    Ok(
        std::fs::read_to_string(format!("/sys/class/net/{name}/netdev_group"))?
            .trim()
            .parse()?,
    )
}

fn interface_index(name: &str) -> Result<u32> {
    Ok(
        std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
            .trim()
            .parse()?,
    )
}

/// Complete desired rules for the single supported casting session.
#[derive(Debug, Clone)]
pub struct Rules {
    /// Interface validated from the selected radio's group-start signal.
    pub interface: GroupInterface,
    /// Whether the source serves DHCP.
    pub group_owner: bool,
    /// Source RTSP listening port, matching its WFD advertisement.
    pub rtsp: u16,
    /// Local IPv4 after address configuration.
    pub local: Option<Ipv4Addr>,
    /// Peer learned from the connected control socket.
    pub peer: Option<Ipv4Addr>,
    /// (Local port, remote port) for RTCP; absent if sink didn't negotiate RTCP.
    pub rtcp: Option<(u16, u16)>,
}

impl Rules {
    /// Render only this session's allowances. All other traffic returns to UFW.
    pub fn lines(&self) -> Result<Vec<String>> {
        validate_name(&self.interface.name)?;
        if self.rtsp < 1024 {
            bail!("Refusing a privileged RTSP port");
        }
        let prefix = format!(
            "-A {CHAIN} -i {} -m devgroup --src-group 0x{DEVICE_GROUP:x}",
            self.interface.name
        );
        let mut rules = vec![format!("{prefix} -p udp --sport 67 --dport 68 -j ACCEPT")];
        if self.group_owner {
            // A DHCPDISCOVER has no leased source address yet.
            rules.push(format!("{prefix} -p udp --sport 68 --dport 67 -j ACCEPT"));
        }
        let local = self
            .local
            .map(|ip| format!(" -d {ip}/32"))
            .unwrap_or_default();
        let peer = self
            .peer
            .map(|ip| format!(" -s {ip}/32"))
            .unwrap_or_default();
        rules.push(format!(
            "{prefix}{local}{peer} -p tcp --dport {} -j ACCEPT",
            self.rtsp
        ));
        if let Some((local_port, remote_port)) = self.rtcp {
            if self.local.is_none() || self.peer.is_none() || local_port < 1024 || remote_port == 0
            {
                bail!("RTCP requires validated local/peer addresses and ports");
            }
            rules.push(format!(
                "{prefix}{local}{peer} -p udp --sport {remote_port} --dport {local_port} -j ACCEPT"
            ));
        }
        Ok(rules)
    }

    /// Apply a single atomic filter-table transaction without flushing UFW.
    pub async fn apply(&self) -> Result<()> {
        if !self.interface.exists() {
            bail!("P2P interface disappeared or was replaced");
        }
        ensure_hook().await?;
        let lines = self.lines()?;
        restore(&format!(
            "*filter\n-F {CHAIN}\n{}\nCOMMIT\n",
            lines.join("\n")
        ))
        .await
    }

    /// Detect reloads or external changes. Never recreate allowances from stale state.
    pub async fn intact(&self) -> bool {
        if !self.interface.exists() || ensure_hook().await.is_err() {
            return false;
        }
        let Ok(output) = iptables(&["-S", CHAIN]).await else {
            return false;
        };
        let Ok(expected) = self.lines() else {
            return false;
        };
        // iptables canonicalizes -p by adding -m tcp/udp, and /32 addresses.
        let actual: Vec<_> = output
            .lines()
            .filter(|line| line.starts_with("-A "))
            .map(normalize_rule)
            .collect();
        actual
            == expected
                .iter()
                .map(|s| normalize_rule(s))
                .collect::<Vec<_>>()
    }
}

fn normalize_rule(s: &str) -> String {
    let clean = s.replace(" -m tcp", "").replace(" -m udp", "");
    let tokens: Vec<_> = clean.split_whitespace().collect();
    let mut pairs: Vec<_> = tokens.chunks(2).map(|pair| pair.join(" ")).collect();
    pairs.sort();
    pairs.join(" ")
}

async fn run(binary: &str, args: &[&str], input: Option<&str>) -> Result<String> {
    let mut command = Command::new(binary);
    command
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/usr/sbin")
        .env("LC_ALL", "C")
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(test)]
    if let Ok(parent) = std::env::var("WAYCAST_PARENT_NETNS") {
        command.env("WAYCAST_PARENT_NETNS", parent);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("Starting {binary}"))?;
    let result = tokio::time::timeout(Duration::from_secs(8), async {
        if let Some(input) = input {
            child
                .stdin
                .take()
                .context("Missing command stdin")?
                .write_all(input.as_bytes())
                .await?;
        }
        let output = child.wait_with_output().await?;
        if !output.status.success() {
            bail!(
                "{binary}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    })
    .await
    .context("Firewall command timed out")?;
    result
}

async fn iptables(args: &[&str]) -> Result<String> {
    let mut all = vec!["--wait", "5"];
    all.extend_from_slice(args);
    run("/usr/bin/iptables", &all, None).await
}

async fn restore(input: &str) -> Result<()> {
    run(
        "/usr/bin/iptables-restore",
        &["--wait", "5", "--noflush"],
        Some(input),
    )
    .await?;
    Ok(())
}

/// Verify the installation hook is loaded in the actual UFW rules.
pub async fn ensure_hook() -> Result<()> {
    iptables(&["-C", "ufw-before-input", "-j", CHAIN])
        .await
        .context("Waycast UFW hook is not loaded; run the installed networking setup")?;
    Ok(())
}

/// Remove only Waycast allowances. Called by teardown, startup and ExecStopPost.
pub async fn cleanup() -> Result<()> {
    // A UFW flush can remove the chain altogether; there is then nothing to remove.
    let table = iptables(&["-S"]).await?;
    if table.lines().any(|line| line == format!("-N {CHAIN}")) {
        iptables(&["-F", CHAIN]).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn rules(owner: bool) -> Rules {
        Rules {
            interface: GroupInterface {
                name: "p2p-wlan0-0".into(),
                index: 10,
                phy: "/fake".into(),
            },
            group_owner: owner,
            rtsp: 7236,
            local: None,
            peer: None,
            rtcp: None,
        }
    }
    #[test]
    fn dhcp_bootstrap_is_role_scoped_without_requiring_a_lease() {
        assert_eq!(rules(false).lines().unwrap().len(), 2);
        let lines = rules(true).lines().unwrap();
        assert!(lines
            .iter()
            .any(|line| line.contains("--sport 68 --dport 67")));
        assert!(lines.iter().all(|line| line.contains("-i p2p-wlan0-0")));
        assert!(!lines.iter().any(|line| line.contains(" -s ")));
    }
    #[test]
    fn media_rules_are_exact_and_do_not_open_fixed_5005() {
        let mut r = rules(false);
        r.local = Some("192.168.49.10".parse().unwrap());
        r.peer = Some("192.168.49.1".parse().unwrap());
        r.rtcp = Some((45001, 19007));
        assert!(r
            .lines()
            .unwrap()
            .last()
            .unwrap()
            .contains("-d 192.168.49.10/32 -s 192.168.49.1/32 -p udp --sport 19007 --dport 45001"));
    }
    #[test]
    fn rejects_injection_and_unvalidated_media() {
        for name in ["", "p2p+", "eth0\n-F INPUT", "../../etc", "-i eth0"] {
            assert!(validate_name(name).is_err());
        }
        let mut r = rules(false);
        r.rtcp = Some((45001, 5005));
        assert!(r.lines().is_err());
        r.rtcp = None;
        r.rtsp = 22;
        assert!(r.lines().is_err());
    }
    #[tokio::test]
    #[ignore = "Must run in a fresh private network namespace; see docs/network-helper.md"]
    async fn kernel_ufw_lifecycle() {
        assert_eq!(std::env::var("WAYCAST_PRIVATE_NETNS").as_deref(), Ok("1"));
        assert_ne!(
            std::fs::read_link("/proc/self/ns/net").unwrap(),
            std::path::PathBuf::from(
                std::env::var("WAYCAST_PARENT_NETNS")
                    .expect("Use contrib/networkd/run_firewall_test.py")
            ),
            "Refusing to alter the host network namespace"
        );
        // A new namespace is required, not just any non-host namespace.
        assert!(!iptables(&["-S"]).await.unwrap().contains("-A "));
        for args in [
            vec![
                "link",
                "add",
                "p2p-test",
                "type",
                "veth",
                "peer",
                "name",
                "sink-test",
            ],
            vec!["addr", "add", "192.168.49.1/24", "dev", "p2p-test"],
            vec!["link", "set", "p2p-test", "up"],
            vec!["link", "set", "sink-test", "up"],
        ] {
            run("/usr/bin/ip", &args, None).await.unwrap();
        }
        restore("*filter\n:ufw-before-input - [0:0]\n:waycast-input - [0:0]\n-P INPUT DROP\n-A INPUT -j ufw-before-input\n-A ufw-before-input -j waycast-input\n-A ufw-before-input -p udp --dport 53317 -j ACCEPT\nCOMMIT\n").await.unwrap();
        let mut r = rules(true);
        r.interface.name = "p2p-test".into();
        run(
            "/usr/bin/ip",
            &[
                "link",
                "set",
                "dev",
                "p2p-test",
                "group",
                &DEVICE_GROUP.to_string(),
            ],
            None,
        )
        .await
        .unwrap();
        r.local = Some("192.168.49.1".parse().unwrap());
        r.peer = Some("192.168.49.2".parse().unwrap());
        r.rtcp = Some((45001, 19007));
        let lines = r.lines().unwrap();
        restore(&format!(
            "*filter\n-F {CHAIN}\n{}\nCOMMIT\n",
            lines.join("\n")
        ))
        .await
        .unwrap();
        ensure_hook().await.unwrap();
        let actual = iptables(&["-S", CHAIN]).await.unwrap();
        assert_eq!(
            actual
                .lines()
                .filter(|l| l.starts_with("-A "))
                .map(normalize_rule)
                .collect::<Vec<_>>(),
            lines.iter().map(|l| normalize_rule(l)).collect::<Vec<_>>()
        );
        // Exercise packets on the veth link, not just rule text or loopback.
        let probe = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contrib/networkd/probe_udp.py"
        );
        run(
            "/usr/bin/python3",
            &[probe, "67", "68", "0.0.0.0", "allow", "255.255.255.255"],
            None,
        )
        .await
        .unwrap();
        let mut client_rules = r.clone();
        client_rules.group_owner = false;
        restore(&format!(
            "*filter\n-F {CHAIN}\n{}\nCOMMIT\n",
            client_rules.lines().unwrap().join("\n")
        ))
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "67", "68", "0.0.0.0", "deny", "255.255.255.255"],
            None,
        )
        .await
        .unwrap();
        restore(&format!(
            "*filter\n-F {CHAIN}\n{}\nCOMMIT\n",
            lines.join("\n")
        ))
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "67", "68", "192.168.49.2", "allow"],
            None,
        )
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "45001", "19007", "192.168.49.2", "allow"],
            None,
        )
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "45001", "19008", "192.168.49.2", "deny"],
            None,
        )
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "45001", "19007", "192.168.49.3", "deny"],
            None,
        )
        .await
        .unwrap();
        // A replacement interface has the same name but no helper tag: even
        // before the supervisor polls, kernel rules must reject its packets.
        run(
            "/usr/bin/ip",
            &["link", "set", "dev", "p2p-test", "group", "0"],
            None,
        )
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "45001", "19007", "192.168.49.2", "deny"],
            None,
        )
        .await
        .unwrap();
        run(
            "/usr/bin/ip",
            &[
                "link",
                "set",
                "dev",
                "p2p-test",
                "group",
                &DEVICE_GROUP.to_string(),
            ],
            None,
        )
        .await
        .unwrap();
        cleanup().await.unwrap();
        cleanup().await.unwrap(); // crash/startup cleanup is idempotent
        run(
            "/usr/bin/python3",
            &[probe, "45001", "19007", "192.168.49.2", "deny"],
            None,
        )
        .await
        .unwrap();
        run(
            "/usr/bin/python3",
            &[probe, "53317", "19007", "192.168.49.2", "allow"],
            None,
        )
        .await
        .unwrap();
        // The persisted installation hook resets the chain on UFW reload.
        restore(&format!(
            "*filter\n-F {CHAIN}\n{}\nCOMMIT\n",
            lines.join("\n")
        ))
        .await
        .unwrap();
        restore("*filter\n-F waycast-input\nCOMMIT\n")
            .await
            .unwrap();
        assert!(!iptables(&["-S", CHAIN]).await.unwrap().contains("-A "));
        ensure_hook().await.unwrap();
        restore(&format!(
            "*filter\n-F {CHAIN}\n{}\nCOMMIT\n",
            lines.join("\n")
        ))
        .await
        .unwrap();
        crate::service::test_caller_loss(r).await;
        assert!(!iptables(&["-S", CHAIN]).await.unwrap().contains("-A "));
        iptables(&[
            "-C",
            "ufw-before-input",
            "-p",
            "udp",
            "--dport",
            "53317",
            "-j",
            "ACCEPT",
        ])
        .await
        .unwrap();
    }
}

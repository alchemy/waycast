use waycast_networkd::{firewall, service::NetworkService, BUS_NAME, OBJECT_PATH};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("waycast_networkd=info,waycast_net=info")
        .init();
    match std::env::args().nth(1).as_deref() {
        Some("--cleanup") => return firewall::cleanup().await,
        Some(_) => anyhow::bail!("Usage: waycast-networkd [--cleanup]"),
        None => {}
    }
    // Crash leftovers are removed before exposing the D-Bus name.
    firewall::cleanup().await?;
    let service = NetworkService::default();
    let connection = zbus::connection::Builder::system()?
        .serve_at(OBJECT_PATH, service.clone())?
        .name(BUS_NAME)?
        .build()
        .await?;
    service.supervise(connection).await;
    Ok(())
}

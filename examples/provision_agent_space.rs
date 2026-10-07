//! Exercise the real local provisioner with an installed Cua CLI. No host UI.
#[cfg(feature = "agent-host")]
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use proxy_node_server::agent_host::space::{CuaSpaceManager, SpaceResources};
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 4 {
        return Err("usage: provision_agent_space CUA_BINARY PRIVATE_CUA_HOME AGENT_ID".into());
    }
    let manager = CuaSpaceManager::open(&args[1], &args[2])?;
    let first = manager
        .ensure_agent_space(&args[3], SpaceResources::default())
        .await?;
    let second = manager
        .ensure_agent_space(&args[3], SpaceResources::default())
        .await?;
    assert_eq!(
        first.binding, second.binding,
        "same agent resumes the same owned guest"
    );
    println!("{}", serde_json::to_string_pretty(&first)?);
    Ok(())
}
#[cfg(not(feature = "agent-host"))]
fn main() {
    eprintln!("enable the agent-host feature");
}

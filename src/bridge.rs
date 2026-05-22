//! The `rsh-bridge` subcommand: rsync's transport, carried over russh.
//!
//! `rsync` is told to use this as its remote shell (its `-e` option). For each
//! transfer rsync runs `ssh-mcp rsh-bridge <host> <remote command...>`; the
//! bridge connects to the host over russh — the same agent authentication and
//! known_hosts checks as the rest of ssh-mcp — opens a channel for that remote
//! command, and relays rsync's stdin and stdout across it.
//!
//! The daemon hands the bridge the resolved connection chain through a file
//! named by `$SSH_MCP_BRIDGE_CHAIN`, so the bridge never reads the inventory
//! itself — the daemon stays the inventory's only reader.

use anyhow::{Context, Result, bail};
use russh::ChannelMsg;
use tokio::io::{AsyncWriteExt, copy};

use crate::ssh::{Hop, SshConnector};

/// The environment variable naming the file that holds the JSON hop chain.
pub const CHAIN_ENV: &str = "SSH_MCP_BRIDGE_CHAIN";

/// Entry point for the rsync transport bridge. `args` is everything after the
/// `rsh-bridge` subcommand: the placeholder host token, then the remote
/// command rsync wants run.
pub fn run(args: Vec<String>) -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(bridge(args))
}

async fn bridge(args: Vec<String>) -> Result<()> {
    // rsync invokes us as `<bin> rsh-bridge <host> <command words...>`. The host
    // is a placeholder — the real connection comes from the chain file — so the
    // remote command is every argument after it.
    let Some((_host, command_words)) = args.split_first() else {
        bail!("the rsync bridge was invoked without a host or command");
    };
    if command_words.is_empty() {
        bail!("the rsync bridge was invoked without a remote command");
    }
    // Joining with spaces matches how `ssh host word1 word2` passes a command:
    // the remote shell re-splits it, which is what rsync expects of a transport.
    let command = command_words.join(" ");

    let chain = load_chain()?;
    let connector = SshConnector::new()?;
    let handle = connector
        .connect(&chain)
        .await
        .context("connecting for the rsync transfer")?;
    let channel = handle
        .channel_open_session()
        .await
        .context("opening a channel for rsync")?;
    channel
        .exec(true, command)
        .await
        .context("starting the remote rsync")?;

    let (mut read_half, write_half) = channel.split();

    // rsync's stdin flows to the channel; the channel's output flows back to
    // rsync's stdout, and the remote's stderr to ours.
    let to_remote = async {
        let mut stdin = tokio::io::stdin();
        let mut writer = write_half.make_writer();
        copy(&mut stdin, &mut writer)
            .await
            .context("relaying rsync's input to the remote")?;
        writer.flush().await.ok();
        drop(writer);
        write_half.eof().await.ok();
        Ok::<(), anyhow::Error>(())
    };
    let from_remote = async {
        let mut stdout = tokio::io::stdout();
        let mut stderr = tokio::io::stderr();
        let mut exit_code = 0;
        while let Some(message) = read_half.wait().await {
            match message {
                ChannelMsg::Data { data } => stdout
                    .write_all(&data)
                    .await
                    .context("relaying the remote's output")?,
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr
                    .write_all(&data)
                    .await
                    .context("relaying the remote's errors")?,
                ChannelMsg::ExitStatus { exit_status } => exit_code = exit_status as i32,
                _ => {}
            }
        }
        stdout.flush().await.ok();
        stderr.flush().await.ok();
        Ok::<i32, anyhow::Error>(exit_code)
    };

    let (write_result, read_result) = tokio::join!(to_remote, from_remote);
    write_result?;
    let exit_code = read_result?;
    // rsync inspects its transport's exit status; mirror the remote command's.
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

/// Load the connection chain the daemon wrote for this bridge invocation.
fn load_chain() -> Result<Vec<Hop>> {
    let path = std::env::var(CHAIN_ENV).with_context(|| {
        format!("{CHAIN_ENV} is not set; the bridge must be launched by the ssh-mcp daemon")
    })?;
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("reading the connection chain from {path}"))?;
    serde_json::from_str(&text).context("parsing the connection chain")
}

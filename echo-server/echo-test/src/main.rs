use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::thread;
use aya::{maps::SockHash, programs::SkMsg};
use aya::maps::SockMap;
use aya::programs::{CgroupAttachMode, CgroupSock, KProbe};
use echo_test_common::SockKey;
#[rustfmt::skip]
use log::{debug, info, warn};
use tokio::signal;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/echo-test"
    )))?;

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    let prog: &mut CgroupSock = ebpf.program_mut("cgroup__sock_create").unwrap().try_into()?;
    // root cgroup to get all events.
    let cgroup = std::fs::File::open("/sys/fs/cgroup/")?;
    prog.load()?;
    prog.attach(&cgroup, CgroupAttachMode::Single)?;
    info!("Attached!");

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}

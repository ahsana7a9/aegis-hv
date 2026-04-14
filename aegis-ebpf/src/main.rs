#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

#[map]
static mut EVENTS: PerfEventArray<[u8; 1024]> = PerfEventArray::new(0);

#[classifier]
pub fn aegis_sniff(ctx: TcContext) -> i32 {
    match try_aegis_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // TC_ACT_OK
    }
}

fn try_aegis_sniff(ctx: TcContext) -> Result<i32, ()> {
    // 1. Basic packet parsing (L2 -> L3)
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth_hdr.ether_type != EtherType::Ipv4 {
        return Ok(0);
    }

    // 2. Capture the payload (up to 1024 bytes for analysis)
    let mut buf = [0u8; 1024];
    let len = ctx.load_bytes(0, &mut buf).map_err(|_| ())?;

    // 3. Push to Userspace (the Daemon)
    unsafe {
        EVENTS.output(&ctx, &buf[..len], 0);
    }

    Ok(0) // Allow the packet to continue
}

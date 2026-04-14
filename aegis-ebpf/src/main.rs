#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier, map},
    maps::PerfEventArray,
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
};

// Constant for "Allow packet to pass"
const TC_ACT_OK: i32 = 0;

#[map]
static mut EVENTS: PerfEventArray<[u8; 1024]> = PerfEventArray::new(0);

#[classifier]
pub fn aegis_sniff(ctx: TcContext) -> i32 {
    match try_aegis_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, 
    }
}

fn try_aegis_sniff(ctx: TcContext) -> Result<i32, ()> {
    // 1. Parse Ethernet Header
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    
    // Only sniff IPv4 traffic for the MVP
    if eth_hdr.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }

    // 2. Capture packet slice (up to 1024 bytes)
    // This provides enough entropy data for the ThreatAnalyzer in userspace
    let mut buf = [0u8; 1024];
    let len = ctx.load_bytes(0, &mut buf).map_err(|_| ())?;

    // 3. Push to the 'EVENTS' Perf Ring Buffer
    // This is where the Daemon's monitor.rs picks it up
    unsafe {
        EVENTS.output(&ctx, &buf[..len], 0);
    }

    Ok(TC_ACT_OK) 
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_SHOT, // Added: The "Drop Packet" signal
    macros::{classifier, map},
    maps::{HashMap, PerfEventArray},
    programs::TcContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr, // Added: To parse IP addresses for blocking
};

// --- CRYPTOGRAPHIC OWNERSHIP MARK ---
#[no_mangle]
#[link_section = ".aegis_identity"]
pub static AEGIS_MARKER: [u8; 64] = *b"4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9";

const TC_ACT_OK: i32 = 0;

/// Map to store blocked destination IPs. 
/// The Daemon writes to this map when entropy thresholds are breached.
#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static mut EVENTS: PerfEventArray<[u8; 1024]> = PerfEventArray::new(0);

#[classifier]
pub fn aegis_sniff(ctx: TcContext) -> i32 {
    let _mark = core::hint::black_box(AEGIS_MARKER);
    
    match try_aegis_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, 
    }
}

fn try_aegis_sniff(ctx: TcContext) -> Result<i32, ()> {
    // 1. Parse Ethernet Header
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth_hdr.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }

    // 2. Parse IPv4 Header to find Destination IP
    let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let dst_ip = u32::from_be_bytes(ipv4_hdr.dst_addr);

    // 3. ACTIVE MITIGATION: Check the Blocklist
    // If the destination IP is in our kernel map, drop the packet immediately (TC_ACT_SHOT).
    if unsafe { BLOCKLIST.get(&dst_ip).is_some() } {
        return Ok(TC_ACT_SHOT);
    }

    // 4. SHADOW MONITORING: Capture payload for entropy analysis
    let mut buf = [0u8; 1024];
    let len = ctx.load_bytes(0, &mut buf).map_err(|_| ())?;

    unsafe {
        EVENTS.output(&ctx, &buf[..len], 0);
    }

    Ok(TC_ACT_OK) 
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

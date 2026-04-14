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

// --- CRYPTOGRAPHIC OWNERSHIP MARK ---
// This constant is baked into the eBPF bytecode. 
// It can be verified using `llvm-objdump -s -j .aegis_identity`
#[no_mangle]
#[link_section = ".aegis_identity"]
pub static AEGIS_MARKER: [u8; 64] = *b"4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9";

const TC_ACT_OK: i32 = 0;

#[map]
static mut EVENTS: PerfEventArray<[u8; 1024]> = PerfEventArray::new(0);

#[classifier]
pub fn aegis_sniff(ctx: TcContext) -> i32 {
    // Reference the marker to ensure the compiler doesn't optimize it away
    let _mark = core::hint::black_box(AEGIS_MARKER);
    
    match try_aegis_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, 
    }
}

fn try_aegis_sniff(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    
    if eth_hdr.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }

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

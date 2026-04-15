#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::TC_ACT_SHOT,
    macros::{classifier, map, tracepoint}, // Added tracepoint
    maps::{HashMap, PerfEventArray},
    programs::{TcContext, TracePointContext}, // Added TracePointContext
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// --- CRYPTOGRAPHIC OWNERSHIP MARK ---
#[no_mangle]
#[link_section = ".aegis_identity"]
pub static AEGIS_MARKER: [u8; 64] = *b"4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9";

const TC_ACT_OK: i32 = 0;

// --- KERNEL MAPS ---

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static mut EVENTS: PerfEventArray<[u8; 1024]> = PerfEventArray::new(0);

/// Map for Process Visibility: Tracks PIDs attempting specific syscalls
#[map]
static PROC_VISIBILITY: HashMap<u32, u32> = HashMap::with_max_entries(2048, 0);

// --- 1. NETWORK HOOK (Traffic Control) ---

#[classifier]
pub fn aegis_sniff(ctx: TcContext) -> i32 {
    let _mark = core::hint::black_box(AEGIS_MARKER);
    match try_aegis_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK, 
    }
}

fn try_aegis_sniff(ctx: TcContext) -> Result<i32, ()> {
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth_hdr.ether_type != EtherType::Ipv4 { return Ok(TC_ACT_OK); }

    let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let dst_ip = u32::from_be_bytes(ipv4_hdr.dst_addr);

    // Active Mitigation
    if unsafe { BLOCKLIST.get(&dst_ip).is_some() } {
        return Ok(TC_ACT_SHOT);
    }

    let mut buf = [0u8; 1024];
    let len = ctx.load_bytes(0, &mut buf).map_err(|_| ())?;
    unsafe { EVENTS.output(&ctx, &buf[..len], 0); }

    Ok(TC_ACT_OK) 
}

// --- 2. SYSCALL INTERCEPTION (Process Visibility) ---

/// Intercepts the 'execve' syscall to monitor when an agent tries to spawn a new process.
/// This provides low-level, real-time visibility into the agent's behavior.
#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn aegis_trace_exec(ctx: TracePointContext) -> i32 {
    let pid = ctx.pid();
    
    // Log the PID to our visibility map
    // The Daemon can read this map to see exactly which agents are spawning sub-processes
    unsafe {
        let _ = PROC_VISIBILITY.insert(&pid, &1, 0);
    }
    
    0 // Continue execution
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

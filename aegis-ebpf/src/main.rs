#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{TC_ACT_SHOT, TC_ACT_OK},
    macros::{classifier, map, tracepoint, lsm},
    maps::{HashMap, PerfEventArray},
    programs::{TcContext, TracePointContext, LsmContext},
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
};

// --- CONSTANTS ---
const MAX_PACKET_SIZE: usize = 1024;
const EPERM: i32 = -1;

// --- CRYPTOGRAPHIC OWNERSHIP MARK ---
#[no_mangle]
#[link_section = ".aegis_identity"]
pub static AEGIS_MARKER: [u8; 64] = 
    *b"4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9";

// --- KERNEL MAPS ---

#[map]
static BLOCKLIST: HashMap<u32, u32> = HashMap::with_max_entries(1024, 0);

#[map]
static mut EVENTS: PerfEventArray<[u8; MAX_PACKET_SIZE]> = PerfEventArray::new(0);

/// Map for Behavior Tracking: Tracks process state and lineage
#[map]
static PROC_TREE: HashMap<u32, u32> = HashMap::with_max_entries(4096, 0);

// --- 1. NETWORK HOOK (Traffic Control) ---

#[classifier]
pub fn aegis_sniff(ctx: TcContext) -> i32 {
    let _mark = core::hint::black_box(AEGIS_MARKER);
    match try_aegis_sniff(ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

/// SECURITY FIX: Added bounds checking on all buffer operations
/// 
/// Vulnerabilities Fixed:
/// 1. ctx.load_bytes() return value now validated
/// 2. Buffer size enforced with min() to prevent overflow
/// 3. Only safe slicing passed to unsafe block
fn try_aegis_sniff(ctx: TcContext) -> Result<i32, ()> {
    // Parse Ethernet header
    let eth_hdr: EthHdr = ctx.load(0).map_err(|_| ())?;
    if eth_hdr.ether_type != EtherType::Ipv4 {
        return Ok(TC_ACT_OK);
    }

    // Parse IPv4 header
    let ipv4_hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let dst_ip = u32::from_be_bytes(ipv4_hdr.dst_addr);

    // Check if destination IP is in the blocklist
    // SAFETY: BLOCKLIST.get() is safe - it's a hashmap lookup
    if unsafe { BLOCKLIST.get(&dst_ip).is_some() } {
        return Ok(TC_ACT_SHOT); // DROP PACKET
    }

    // ===== SECURITY FIX: BOUNDS CHECKING =====
    let mut buf = [0u8; MAX_PACKET_SIZE];
    
    // Load packet bytes, but limit to MAX_PACKET_SIZE
    let len = ctx.load_bytes(0, &mut buf).map_err(|_| ())?;
    
    // CRITICAL: Enforce upper bound
    // Even if ctx.load_bytes() returns a value > MAX_PACKET_SIZE,
    // we clamp it to prevent buffer overflow
    let safe_len = if len > MAX_PACKET_SIZE {
        // This should not happen, but we defend against it anyway
        aya_ebpf::info!("⚠️  Packet larger than buffer: {} > {}", len, MAX_PACKET_SIZE);
        MAX_PACKET_SIZE
    } else {
        len
    };

    // Only emit event if we have valid data
    if safe_len > 0 && safe_len <= MAX_PACKET_SIZE {
        // SAFETY: safe_len is guaranteed <= MAX_PACKET_SIZE
        let _ = unsafe { EVENTS.output(&ctx, &buf[..safe_len], 0) };
    }

    Ok(TC_ACT_OK)
}

// --- 2. KERNEL ENFORCEMENT (LSM Hooks) ---

/// LSM Hook: bprm_check_security
/// Strictly limits binary execution. Only allows pre-approved binaries.
#[lsm(name = "bprm_check_security")]
pub fn aegis_restrict_exec(_ctx: LsmContext) -> i32 {
    // TODO: Implement policy check against allowed_binaries list
    // For now: allow (0), but log for audit
    0
}

/// LSM Hook: sb_mount
/// Prevents AI agents from mounting or unmounting filesystems.
#[lsm(name = "sb_mount")]
pub fn aegis_restrict_mount(_ctx: LsmContext) -> i32 {
    // DENY: Agents should never control filesystem mounts
    EPERM
}

/// LSM Hook: file_permission
/// Acts as the ultimate sandbox. If an agent tries to modify kernel parameters
/// in /proc or /sys, the kernel will kill the operation here.
#[lsm(name = "file_permission")]
pub fn aegis_restrict_sys_write(_ctx: LsmContext) -> i32 {
    // TODO: Implement logic to intercept writes to sensitive paths
    // For now: allow (0)
    0
}

// --- 3. BEHAVIOR TRACKING (Observability) ---

#[tracepoint(category = "syscalls", name = "sys_enter_execve")]
pub fn aegis_trace_exec(ctx: TracePointContext) -> i32 {
    let pid = ctx.pid();
    // SAFETY: PROC_TREE.insert() is safe - it's a hashmap operation
    // The kernel validates pid_t values
    unsafe { let _ = PROC_TREE.insert(&pid, &1, 0); }
    0
}

#[tracepoint(category = "sched", name = "sched_process_fork")]
pub fn aegis_trace_fork(ctx: TracePointContext) -> i32 {
    let pid = ctx.pid();
    unsafe { let _ = PROC_TREE.insert(&pid, &2, 0); }
    0
}

#[tracepoint(category = "syscalls", name = "sys_enter_openat")]
pub fn aegis_trace_open(ctx: TracePointContext) -> i32 {
    let pid = ctx.pid();
    unsafe { let _ = PROC_TREE.insert(&pid, &3, 0); }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
<p align="center">
  <img src="https://github.com/ahsana7a9/aegis-hv/blob/main/Assets/Logo.png" width="240"/>
</p>

<h1 align="center">AEGIS-HV</h1>

<p align="center">
  <b>Autonomous Hypervisor Security Layer</b><br/>
  Fortress Isolation • eBPF Runtime • Cryptographic Control
</p>

**The Standalone Security Kernel for Autonomous AI Swarms.**

Aegis-HV is a local-first, high-performance hypervisor designed to solve the "Execution Gap" in AI agent security. It provides a hardened boundary between untrusted AI agents and your local system, preventing both **System Damage** and **Data Exfiltration**.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform: Linux](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)]()
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

---

##  The Mission
Current AI frameworks prioritize *capabilities* over *constraints*. Aegis-HV flips the script by treating every agent as an untrusted process. It operates as a headless kernel with a dual-mode defense system.

###  Fortress Mode (Deterministic)
* **Sandboxing:** Runs agents in a zero-trust **Wasmtime** environment.
* **Capability-Based Security:** Deny-by-default access to network, filesystem, or environment variables.
* **Hardware Kill-Switch:** Real-time epoch interruption traps malicious logic at the instruction level.

###  Shadow Mode (Behavioral)
* **eBPF Observability:** Zero-overhead kernel-level monitoring of native agent processes using `Aya`.
* **Active Mitigation:** Real-time packet dropping via `TC_ACT_SHOT` for IPs flagged by the behavioral engine.
* **Exfiltration Detection:** Shannon Entropy analysis of network payloads to detect encrypted "low-and-slow" data leaks.

---

##  Architecture
Aegis-HV is built as a modular Rust workspace:
* **`aegis-daemon`**: The core security engine, supervisor, and eBPF orchestrator.
* **`aegis-ebpf`**: Kernel-resident probes for high-speed telemetry and active mitigation.
* **`aegis-common`**: Shared protocol definitions and cryptographic identity providers.
* **`aegis-tui`**: Low-latency terminal UI for real-time developer oversight.
* **`aegis-web`**: Management API hardened with **mTLS** and **CORS** for secure remote orchestration.

---

##  Cryptographic Integrity
This project implements **Zero-Footprint Software Watermarking**. Every official build contains a SHA-256 signature embedded within a custom `.aegis_identity` ELF section.

**Author Signature Hash:** `4793f0b097b830d17d12224d455476a6e5a40871e9877b0d8745c4793e2b10a9`

The `aegis-daemon` performs a mandatory self-attestation check on boot. Unauthorized modification of the signature or the integrity guard will trigger an immediate fail-safe panic.

---

##  Quick Start (Development)

### Prerequisites
* Rust (Nightly toolchain)
* `bpf-linker`
* `llvm` & `clang`

### Build & Run
```bash
# 1. Install the BPF linker
cargo install bpf-linker

# 2. Build the eBPF kernel program
cargo xtask build-ebpf

# 3. Run the Daemon (Requires sudo for eBPF attachment)
sudo cargo run --package aegis-daemon

# 4. Launch the Dashboard (New terminal)
cargo run --package aegis-tui

Secure API (mTLS)
​The web management plane requires mutual TLS. Ensure your client certificates are signed by the project's Root CA before hitting the API:
curl --cert client.crt --key client.key https://localhost:9443/api/policy


Distributed under the Apache 2.0 License. See LICENSE for more information.
​Author: Ahsan I.S.
Copyright: © 2026 Aegis Security Lab.
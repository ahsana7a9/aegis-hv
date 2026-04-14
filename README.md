# Aegis-HV
**The Standalone Security Kernel for Autonomous AI Swarms.**

Aegis-HV is a local-first, high-performance hypervisor designed to solve the "Execution Gap" in AI agent security. It provides a hardened boundary between untrusted AI agents and your local system, preventing both **System Damage** and **Data Exfiltration**.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Platform: Linux/macOS](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey.svg)]()
[![Built with Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)

---

## The Mission
Current AI frameworks prioritize *capabilities* over *constraints*. Aegis-HV flips the script by treating every agent as an untrusted process. It operates as a headless kernel with a dual-mode defense system.

###  Fortress Mode (Deterministic)
* **Sandboxing:** Runs agents in a zero-trust **Wasmtime** environment.
* **Capability-Based Security:** Agents have no access to network, filesystem, or environment variables unless explicitly granted.
* **Hardware Kill-Switch:** Real-time epoch interruption traps malicious logic at the instruction level.

###  Shadow Mode (Behavioral)
* **eBPF Observability:** Monitors native agent processes at the kernel level without performance overhead.
* **Exfiltration Detection:** Real-time entropy analysis of outgoing network packets to detect "low-and-slow" data leaks.
* **Heuristic Veto:** Automatically switches to Fortress Mode if an agent attempts a "Boundary Breach."

---

##  Architecture
Aegis-HV is built as a modular Rust workspace:
* `aegis-daemon`: The core security engine and supervisor.
* `aegis-tui`: Low-latency terminal UI for real-time developer oversight.
* `aegis-web`: On-demand dashboard for visual policy management and enterprise audit logs.

---

##  Quick Start (Coming Soon)
```bash
# Install the Aegis-HV CLI
cargo install aegis-hv

# Run an agent in Shadow Mode
aegis-hv run --mode shadow ./my-swarm-module.py

# Run in Fortress Mode with a specific allow-list
aegis-hv run --mode fortress --allow-net api.openai.com ./agent.wasm

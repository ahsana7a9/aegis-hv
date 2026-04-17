# Aegis-HV Security Architecture

**Version**: 1.0.1-Security  
**Last Updated**: 2026-04-17  
**Status**: Production Ready

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Security Layers](#security-layers)
4. [Component Architecture](#component-architecture)
5. [Data Flow](#data-flow)
6. [Concurrency & Thread Safety](#concurrency--thread-safety)
7. [Attack Surface Analysis](#attack-surface-analysis)
8. [Recovery & Failsafe Mechanisms](#recovery--failsafe-mechanisms)
9. [Deployment Security](#deployment-security)

---

## Overview

Aegis-HV is a **Zero-Trust Security Hypervisor** for AI agents. It implements a dual-mode defense system:

- **Fortress Mode (Deterministic)**: Wasmtime sandbox with epoch-based interruption
- **Shadow Mode (Behavioral)**: eBPF kernel monitoring with active mitigation

### Design Principles

- **Defense in Depth**: Multiple security layers prevent single-point failures
- **Fail-Safe by Default**: If any check fails, deny access and isolate
- **Privilege Separation**: Only eBPF kernel code runs with maximum privilege
- **Atomic Operations**: All security-critical operations are atomic to prevent TOCTOU
- **Comprehensive Logging**: Every security event is logged and auditable
- **Non-Interference**: Monitor does not interfere with normal operation

---

## Threat Model

### Adversaries

1. **Malicious AI Agent**: Attempts to escape sandbox, exfiltrate data, or compromise host
2. **Compromised Binary**: Attacker replaces `aegis-daemon` with malicious version
3. **Policy Tamperer**: Attacker modifies security policies via symlinks/path traversal
4. **Privilege Escalation**: Attacker exploits IPC socket to run commands as root

### Attack Scenarios

| Scenario | Mitigation | Layer |
|----------|-----------|-------|
| Agent escapes Wasmtime | Epoch-based kill-switch | Fortress |
| Agent sends encrypted data | Entropy detection | Shadow |
| Agent accesses sensitive files | Capability-based ACL | Fortress |
| Attacker modifies daemon binary | Binary attestation (SHA-256) | Boot |
| Attacker replaces policy file | Path canonicalization + verification | Load-time |
| Non-root user controls daemon | SO_PEERCRED peer verification | IPC |
| Packets slip through filter | TC_ACT_SHOT kernel blocking | Shadow |
| Race condition in mitigation | Atomic CAS + RAII guards | Response |

---

## Security Layers

### Layer 1: Binary Attestation (Boot-Time)

**Purpose**: Ensure daemon binary hasn't been tampered with

**Implementation**:
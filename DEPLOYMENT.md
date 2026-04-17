cat > DEPLOYMENT.md << 'EOF'
# Aegis-HV Deployment Guide

## Prerequisites

- Linux kernel 5.8+ (for eBPF support)
- Rust 1.70+
- systemd
- Root access

## Installation Steps

### 1. Clone and Build

```bash
git clone https://github.com/ahsana7a9/aegis-hv.git
cd aegis-hv
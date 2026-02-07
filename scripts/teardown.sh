#!/bin/bash
set -euxo pipefail

ip link del zstun0 || true
ip link del dummy0 || true

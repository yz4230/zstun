#!/bin/bash
set -euxo pipefail

ip link del gztun0 || true
ip link del dummy0 || true

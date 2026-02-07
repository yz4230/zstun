#!/bin/bash
set -euxo pipefail

make insmod

ip link add dummy0 type dummy
ip link set dummy0 up

ip link add zstun0 link dummy0 type zstun
ip link set dev zstun0 up
ip addr add 10.0.0.0/24 dev zstun0

#!/bin/bash
set -euxo pipefail

make insmod

ip link add dummy0 type dummy
ip link set dummy0 up

ip link add gztun0 link dummy0 type gztun
ip link set dev gztun0 up
ip addr add 10.0.0.0/24 dev gztun0

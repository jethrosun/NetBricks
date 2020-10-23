#!/bin/bash

# This script generates perf results that we can use to get a flamegraph.

#set -x
set -euo pipefail

# clean the states of transmission
sudo rm -rf downloads/*
sudo rm -rf config/*
mkdir -p config downloads

sudo rm -rf /data/downloads/*
sudo rm -rf /data/config/*
sudo mkdir -p /data/config /data/downloads

NF_NAME=pvn-p2p-nat
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh profile $NF_NAME -n "\n=========== Running RDR Proxy ============\n" -m $M_CORE  \
    -c 4 -c 5 \
    -p $PORT_ONE -p $PORT_TWO

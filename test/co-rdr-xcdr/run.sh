#!/bin/bash

#set -x
set -euo pipefail

# clean the states of transmission
sudo rm -rf output_videos/*
# sudo rm -rf config/*
# mkdir -p config downloads
#
# sudo rm -rf /data/downloads/*
# sudo rm -rf /data/config/*
# sudo mkdir -p /data/config /data/downloads

export RUST_BACKTRACE=full
NF_NAME=pvn-transcoder-groupby-app

M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh run $NF_NAME -n "\n=========== Running P2P ============\n" -m $M_CORE  \
    -c 4 -c 5 \
    -p $PORT_ONE -p $PORT_TWO | tee output.out

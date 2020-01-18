#!/bin/bash

# This script generates perf results that we can use to get a flamegraph.

#set -x
set -euo pipefail

NF_NAME=pvn-tlsv
M_CORE=1

PORT_ONE="0000:01:00.0"
PORT_TWO="0000:01:00.1"

../../build.sh profile $NF_NAME -n " =========== Running TLS Validator ============  " -m $M_CORE  \
    -c 4 -c 5  \
    -p $PORT_ONE -p $PORT_TWO

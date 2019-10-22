#!/bin/bash
# Lists all the examples in Bess. This is used by the build script.
export examples=(
        test/framework-test
        test/delay-test
        test/shutdown-test
        test/lpm
        test/lpm-embedded
        test/nat
        test/tcp-check
        test/sctp-test
        test/config-test
        test/reset-parse
        test/packet_generation
        test/embedded-scheduler-test
        test/embedded-scheduler-dependency-test
        test/tcp_payload
        test/macswap
        # ZCSI examples
        test/acl-fw
        test/tcp-reconstruction
        test/maglev
        test/chain-test
        test/packet_test
        # PVN examples
        test/tls-validator
        test/compression-proxy
        test/wd-rdr-proxy
        test/rdr-proxy
        test/p2p
        test/pktgen-test
        test/adv-acl
        # Additional building blocks
        test/job_scheduler
)


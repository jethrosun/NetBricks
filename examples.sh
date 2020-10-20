#!/bin/bash
# Lists all the examples in Bess. This is used by the build script.
export examples=(
	# test/framework-test
	# test/delay-test
	# test/shutdown-test
	# test/lpm
	# test/lpm-embedded
	# test/nat
	# test/tcp-check
	# test/sctp-test
	# test/config-test
	# test/reset-parse
	# test/packet_generation
	# test/embedded-scheduler-test
	# test/embedded-scheduler-dependency-test
	# test/tcp_payload
	# test/macswap
	# ZCSI examples
	# test/acl-fw
	# test/tcp-reconstruction
	# test/maglev
	# test/chain-test
	# test/lpm-test
	# test/packet_test
	# PVN application
	test/app-tlsv_g
	test/app-tlsv_t
	test/app-rdr_g
	test/app-rdr_t
	test/app-p2p_g
	test/app-p2p_t
	test/app-xcdr_g
	test/app-xcdr_t
	# PVN NF libraries
	pvnf/tlsv-groupby
	pvnf/tlsv-transform
	pvnf/rdr-groupby
	pvnf/rdr-transform
	pvnf/p2p-groupby
	pvnf/p2p-transform
	pvnf/xcdr-groupby
	pvnf/xcdr-transform
	# PVN chain
	test/chain-rdr-tlsv_g
)


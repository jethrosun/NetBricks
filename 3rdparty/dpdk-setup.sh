#!/bin/bash
set -e

echo "installing packages.."
sudo apt install -y gcc-multilib libnuma-dev libpcap-dev dpdk-igb-uio-dkms \
 numactl patch 

echo "setup huge pages..."
#default_hugepagesz=1G hugepagesz=1G hugepages=8
#echo 8 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
#echo 8 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_overcommit_hugepages

sudo mkdir -p /mnt/huge

echo "setup /etc/fstab"
echo "nodev /mnt/huge_1GB hugetlbfs pagesize=1GB 0 0"

#!/bin/bash

# Default is 8192 2MB hugepages (this reserves 16GB RAM from the OS)

echo 8192 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /dev/hugepages || true
mount -t hugetlbfs -opagesize=2M nodev /dev/hugepages

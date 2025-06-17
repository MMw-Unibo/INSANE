#!/bin/bash

# Default is 1024 2MB hugepages (this reserves 2GB RAM from the OS)

echo 1024 | sudo tee /sys/devices/system/node/node*/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge || true
mount -t hugetlbfs -opagesize=2M nodev /mnt/huge

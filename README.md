# Setup HugePages

To setup HugePages, you need to be root. First, check if HugePages are enabled on your system:

```sh
cat /proc/meminfo | grep Huge
```

Set the number of HugePages to 1024:

```sh
echo 1024 > /proc/sys/vm/nr_hugepages
# or
sysctl -w vm.nr_hugepages=1024
```

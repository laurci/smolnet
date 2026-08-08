tap := "tap0"
host_ip := "10.30.0.1/24"

setup:
    sudo ip tuntap add dev {{tap}} mode tap user $USER
    sudo ip addr add {{host_ip}} dev {{tap}}
    sudo ip link set {{tap}} up
    sudo sysctl -w net.ipv6.conf.tap0.disable_ipv6=1

teardown:
    sudo ip link del {{tap}}

neigh:
    watch -n 1 ip neigh show dev {{tap}}

ping:
    ping 10.30.0.2

dump:
    sudo tcpdump -i {{tap}} -e -vv
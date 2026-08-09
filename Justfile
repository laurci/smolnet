# UDP netcat examples
# nc -u -l 10.30.0.5 7777
# nc -u 10.30.0.2 7878

# TCP netcat examples
# nc -l 10.30.0.5 7777
# nc 10.30.0.2 7878

wan := "enp5s0"
tap := "tap0"
host_ip := "10.30.0.1/24"
alias_ip := "10.30.0.5/24"

setup:
    sudo ip tuntap add dev {{tap}} mode tap user $USER
    sudo ip addr add {{host_ip}} dev {{tap}}
    sudo ip link set {{tap}} up

    sudo ufw allow in on {{tap}}

    sudo sysctl -w net.ipv6.conf.tap0.disable_ipv6=1
    sudo sysctl -w net.ipv4.ip_forward=1
    
alias:
    sudo ip addr add {{alias_ip}} dev {{tap}}

unalias:
    sudo ip addr del {{alias_ip}} dev {{tap}}

nat:
    sudo sysctl -w net.ipv4.ip_forward=1
    sudo iptables -t nat -A POSTROUTING -s 10.30.0.0/24 -o {{wan}} -j MASQUERADE
    sudo iptables -A FORWARD -i {{tap}} -o {{wan}} -j ACCEPT
    sudo iptables -A FORWARD -i {{wan}} -o {{tap}} -m state --state RELATED,ESTABLISHED -j ACCEPT

unnat:
    sudo iptables -t nat -D POSTROUTING -s 10.30.0.0/24 -o {{wan}} -j MASQUERADE
    sudo iptables -D FORWARD -i {{tap}} -o {{wan}} -j ACCEPT
    sudo iptables -D FORWARD -i {{wan}} -o {{tap}} -m state --state RELATED,ESTABLISHED -j ACCEPT

teardown:
    sudo ip link del {{tap}}

neigh:
    watch -n 1 ip neigh show dev {{tap}}

ping:
    ping 10.30.0.2

dump:
    sudo tcpdump -i {{tap}} -e -vv
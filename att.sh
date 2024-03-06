# set your interfaces: Upstream, Gateway, ATT Residential Gateway
US_IF="<eno1>"
GW_IF="<eno2>"
RG_IF="<eno3>"
RG_MAC="<YOUR ATT RG's MAC>"

# wait for interfaces
while !   (ip link show $US_IF > /dev/null \
        && ip link show $GW_IF > /dev/null \
        && ip link show $RG_IF > /dev/null);
do sleep 1; done

# Maybe tune your interface like this if no adaptive irq coalescing
# verify interface support before usage
COAL=100
RING=32768
ethtool -C $US_IF rx-usecs $COAL
# ethtool -C $US_IF tx-usecs $COAL
ethtool -G $US_IF rx $RING
ethtool -G $US_IF tx $RING


unshare -mn sleep 2 &
ns_pid=$!
sleep 0.1

nsenter -at $ns_pid mount -t sysfs sysfs /sys
nsenter -at $ns_pid mount -t bpf bpf /sys/fs/bpf

ip link set $US_IF netns $ns_pid
ip link set $GW_IF netns $ns_pid
ip link set $RG_IF netns $ns_pid

nsenter -at $ns_pid ip link set $US_IF promisc on
nsenter -at $ns_pid ip link set $GW_IF promisc on
nsenter -at $ns_pid ip link set $RG_IF promisc on

nsenter -at $ns_pid ip link set $US_IF up
nsenter -at $ns_pid ip link set $GW_IF up
nsenter -at $ns_pid ip link set $RG_IF up

# nsenter -at $ns_pid $PWD/$(dirname $0)/att $US_IF $GW_IF $RG_IF $RG_MAC
nsenter -at $ns_pid $PWD/$(dirname $0)/att -c $US_IF $GW_IF $RG_IF $RG_MAC

wait $ns_pid
sleep 1
ip link set $US_IF promisc off
ip link set $GW_IF promisc off
ip link set $RG_IF promisc off

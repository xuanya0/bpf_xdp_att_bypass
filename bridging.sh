unshare -mn sleep 5 &
ns_pid=$!
sleep 0.1

UPSTREAM="<Upstream ONT facing interface>"
RG="<ATT RG's ONT facing interface>"

ip link set $UPSTREAM netns $ns_pid
ip link set $RG netns $ns_pid

nsenter -at $ns_pid mount -t sysfs sysfs /sys

nsenter -at $ns_pid ip link add pon-bridge type bridge group_fwd_mask 65528 stp_state 0
nsenter -at $ns_pid ip link set pon-bridge up
nsenter -at $ns_pid ip link set $UPSTREAM master pon-bridge
nsenter -at $ns_pid ip link set $UPSTREAM up
nsenter -at $ns_pid ip link set $RG master pon-bridge
nsenter -at $ns_pid ip link set $RG up

echo "entering namespace shell"
nsenter -at $ns_pid

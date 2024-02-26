# Bypass ATT's Gateway using eBPF XDP

Inspired by [Bypassing At&t U-verse hardware NAT table limits](http://blog.0xpebbles.org/Bypassing-At-t-U-verse-hardware-NAT-table-limits)

## Step 1: Capture network startup

Modify and run `bridging.sh` and capture 802.1x exchange to understand your particular ATT configuration. You may need to adjust the scripts accordingly (for VLAN, for example).

## Step 2: Compile & Run BPF

Compile the bpf program on your platform, modify `att.sh` and run.

The code was developed on Rockylinux 9.3.0. Follow this [RHEL article](https://developers.redhat.com/blog/2021/04/01/get-started-with-xdp) for prerequisites.

```
Make
sh att.sh
```

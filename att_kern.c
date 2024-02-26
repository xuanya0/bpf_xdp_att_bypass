// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <arpa/inet.h>
#include <string.h>

const unsigned char eth_len[ETH_ALEN];

#define NR_IFACE 3
// MAC addresses
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, eth_len);
	__uint(max_entries, NR_IFACE);
} att_mac_map SEC(".maps");

// Interfaces
struct {
	__uint(type, BPF_MAP_TYPE_DEVMAP);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
	__uint(max_entries, NR_IFACE);
} att_redir_map SEC(".maps");

/* map elements
 *
 * 0: Upstream, connected to the OLT
 * 1: Internal gateway, connected to openwrt, *sense, etc
 * 2: ATT residential gateway
 */

const __u32 upstream = 0;
const __u32 gateway = 1;
const __u32 att_rg = 2;

SEC("xdp")
int us_redir(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 *mac;

	if (!(ctx->data + sizeof(struct ethhdr) <= ctx->data_end))
		return XDP_ABORTED;

	// if upstream sends 802.1X, out to ATT RG
	if (eth->h_proto == htons(ETH_P_PAE))
		return bpf_redirect_map(&att_redir_map, att_rg, 0);
	
	// else (whether ip or ipv6): modify dst mac and out to GW
	if (!(mac = bpf_map_lookup_elem(&att_mac_map, &gateway)))
		return XDP_ABORTED;
	memcpy(eth->h_dest, mac, ETH_ALEN);
	return bpf_redirect_map(&att_redir_map, gateway, 0);
}

SEC("xdp")
int gw_redir(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	__u64 *mac;

	if (!(ctx->data + sizeof(struct ethhdr) <= ctx->data_end))
		return XDP_ABORTED;

	// modify src mac to RG's and out to upstream
	if (!(mac = bpf_map_lookup_elem(&att_mac_map, &att_rg)))
		return XDP_ABORTED;
	memcpy(eth->h_source, mac, ETH_ALEN);
	return bpf_redirect_map(&att_redir_map, upstream, 0);
}

SEC("xdp")
int rg_redir(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;

	if (!(ctx->data + sizeof(struct ethhdr) <= ctx->data_end))
		return XDP_ABORTED;

	// only allow 802.1X
	if (eth->h_proto == htons(ETH_P_PAE))
		return bpf_redirect_map(&att_redir_map, upstream, 0);

	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";

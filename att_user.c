// SPDX-License-Identifier: GPL-2.0
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

#include "att.skel.c"

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [OPTS] <upstream interface> <gateway_interface> <att_rg interface> <att_rg_mac>\n"
		"\nOPTS:\n"
		"    -c    run without confirmation.\n"
		"    -h    show help.\n",
		prog);
}

static void print_mac(const unsigned char *mac)
{
	for (int i = 0; i < ETH_ALEN; i++)
		fprintf(stderr, ":%.2x", (unsigned char)mac[i]);
	fprintf(stderr,"\n");
}

static void get_if_info(const char *if_name, int *ifindex, unsigned char *mac)
{
	int sock;
	struct ifreq ifr;
	strcpy(ifr.ifr_name, if_name);

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock < 0) {
		perror("failed to create a DGRAM socket");
		exit(errno);
	}

	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("failed to ioctl");
		exit(errno);
	}
	*ifindex = ifr.ifr_ifindex;

	if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) {
		perror("failed to ioctl");
		exit(errno);
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	close(sock);
}

int main(int argc, char **argv)
{
	int opt;
	bool confirmed = false;
	int us_ifindex, gw_ifindex, rg_ifindex;
	unsigned char us_mac[ETH_ALEN], gw_mac[ETH_ALEN], rg_mac[ETH_ALEN];

	while ((opt = getopt(argc, argv, ":ch")) != -1) {
		switch (opt) {
		case 'c':
			confirmed = true;
			break;
		case 'h':
			usage(basename(argv[0]));
			return 0;
		default:
			usage(basename(argv[0]));
			return 1;
		}
	}

	if (argc - optind != 4) {
		usage(basename(argv[0]));
		return 1;
	}


	// get interface information
	get_if_info(argv[optind++], &us_ifindex, us_mac);
	fprintf(stderr, "\t0: UPSTREAM: \tIfindex: %d \tMAC ", us_ifindex);
	print_mac(us_mac);

	get_if_info(argv[optind++], &gw_ifindex, gw_mac);
	fprintf(stderr, "\t1: GATEWAY: \tIfindex: %d \tMAC ", gw_ifindex);
	print_mac(gw_mac);

	get_if_info(argv[optind++], &rg_ifindex, rg_mac);
	fprintf(stderr, "\t2: ATT_RG: \tIfindex: %d \tMAC ", rg_ifindex);
	print_mac(rg_mac);

	for (int i = 0; i < ETH_ALEN; i++) {
		rg_mac[i] = strtoul(&argv[optind][i*3], NULL, 16);
	}
	fprintf(stderr, "\t2: ATT_RG: \tArg Input \tMAC ");
	print_mac(rg_mac);

	if (!confirmed) {
		fprintf(stderr, "Press ENTER to continue======================================");
		getchar();
	}

	fprintf(stderr, "Loading Program...\n");
	struct att_prog *prog = att_prog__open_and_load();
	if (!prog) {
		perror("failed to load BPF Prog");
		exit(errno);
	}

	// designate interfaces
	bpf_map__update_elem(prog->maps.att_redir_map,
			     &prog->rodata->upstream, sizeof(prog->rodata->upstream),
			     &us_ifindex, sizeof(us_ifindex), 0);
	bpf_map__update_elem(prog->maps.att_redir_map,
			     &prog->rodata->gateway, sizeof(prog->rodata->gateway),
			     &gw_ifindex, sizeof(gw_ifindex), 0);
	bpf_map__update_elem(prog->maps.att_redir_map,
			     &prog->rodata->att_rg, sizeof(prog->rodata->att_rg),
			     &rg_ifindex, sizeof(rg_ifindex), 0);

	// set MAC addresses, only need gateway and ATT's as of now.
	bpf_map__update_elem(prog->maps.att_mac_map,
			     &prog->rodata->gateway, sizeof(prog->rodata->gateway),
			     gw_mac, ETH_ALEN, 0);
	bpf_map__update_elem(prog->maps.att_mac_map,
			     &prog->rodata->att_rg, sizeof(prog->rodata->att_rg),
			     rg_mac, ETH_ALEN, 0);

	fprintf(stderr, "Attaching to interfaces...\n");
	bpf_xdp_attach(us_ifindex, bpf_program__fd(prog->progs.us_redir), 0, NULL);
	bpf_xdp_attach(gw_ifindex, bpf_program__fd(prog->progs.gw_redir), 0, NULL);
	bpf_xdp_attach(rg_ifindex, bpf_program__fd(prog->progs.rg_redir), 0, NULL);

	fprintf(stderr, "Program Running, press ENTER to exit=========================");
	getchar();

	bpf_xdp_detach(us_ifindex, 0, NULL);
	bpf_xdp_detach(gw_ifindex, 0, NULL);
	bpf_xdp_detach(rg_ifindex, 0, NULL);
	att_prog__destroy(prog);
	return 0;
}


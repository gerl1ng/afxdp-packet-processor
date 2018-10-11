// SPDX-License-Identifier: GPL-2.0
#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <asm/byteorder.h>

#include "bpf_helpers.h"
#include "reqrouter.h"

struct bpf_map_def SEC("maps") xsks_map = {
	.type = BPF_MAP_TYPE_XSKMAP,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(int),
	.max_entries = PORT_RANGE_UPPER,
};

struct bpf_map_def SEC("maps") num_socks_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(uint16_t),
	.max_entries = PORT_RANGE_UPPER,
};

struct bpf_map_def SEC("maps") num_queues_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(uint16_t),
	.max_entries = 1,
};

struct bpf_map_def SEC("maps") rr_map = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(uint16_t),
	.max_entries = PORT_RANGE_UPPER,
};

/* Parse the ETH, IP and UDP header and match if the packet should
 * be processed by the RequestRouter
 *
 * returns 0 if the Packet could not be processed, the Port 
 * number otherwise
 */
static __always_inline
uint16_t parse_header(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *ethh = data;

	u64 offset = sizeof(*ethh);
	/* Check if the Packet contains a whole ethhdr */
	if ((void *)ethh + offset > data_end)
		return 0;

	u16 eth_type = ntohs(ethh->h_proto);
	/* Skip Ethernet II Packets. Focus is on 802.3 packets */
	if (eth_type < ETH_P_802_3_MIN)
		return 0;

	/* Todo: 802.1q, 802.1ad, QinQ etc */

	/* Chedk if it is a IPv4 Packet */
	if (eth_type != ETH_P_IP)
		return 0;

	struct iphdr *iph = data + offset;
	/* Check if the Packet contains a whole iphdr */
	if ((void *)iph + sizeof(*iph) > data_end)
		return 0;

	/* Focus only on UDP Packets */
	if (iph->protocol != IPPROTO_UDP)
		return 0;

	offset += sizeof(*iph);
	struct udphdr *udph = data + offset;
	/* Check if the packet contains a whole udphdr */
	if ((void *)udph + sizeof(*udph) > data_end)
		return 0;

	u16 dport = ntohs(udph->dest);
	/* Check if the port is in the designated Port range */
	if (dport < PORT_RANGE_LOWER || dport > PORT_RANGE_UPPER)
		return 0;
	return dport;
}


SEC("xdp_requestrouter")
int xdp_sock_prog(struct xdp_md *ctx)
{
	unsigned int port = parse_header(ctx), offset = 0;
	uint16_t *rr, *num_socks, *num_queues;
	
	/* Skip Packet if Port is 0 */
	if (port == 0)
		return XDP_PASS;

	/* Reduce on MAX_SOCKS */
	port = port - (port & (MAX_SOCKS - 1));
	
	/* Check how many queues exist */
	num_queues = bpf_map_lookup_elem(&num_queues_map, &offset);
	if (!num_queues)
		return XDP_ABORTED;
	if (*num_queues > 1) {
		offset = MAX_SOCKS / *num_queues;
		offset = offset * ctx->rx_queue_index;
		port = port + offset;
	}

	/* Check if multiple sockets for the port exist */
	num_socks = bpf_map_lookup_elem(&num_socks_map, &port);
	if (!num_socks)
		return XDP_ABORTED;
	if (*num_socks > 1) {
		/* Add Round-Robin Value to port */
		rr = bpf_map_lookup_elem(&rr_map, &port);
		if (!rr)
			return XDP_ABORTED;
		*rr = (*rr + 1) % *num_socks;
		port = port + *rr;
	}
	
	/* Forward Packet to xsks Socket */
	return bpf_redirect_map(&xsks_map, port, 0);
}

char _license[] SEC("license") = "GPL";

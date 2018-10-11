	// SPDX-License-Identifier: GPL-2.0
	/* Copyright(c) 2017 - 2018 Intel Corporation. */
	/* Extended by Marius Gerling 2018 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <locale.h>
#include <sys/types.h>
#include <poll.h>

#include <bpf/libbpf.h>
#include "bpf_util.h"
#include <bpf/bpf.h>

#include <linux/ip.h>
#include <linux/udp.h>

#include "reqrouter.h"

#include "../common/functions.h"

#ifndef SOL_XDP
#define SOL_XDP 283
#endif

#ifndef AF_XDP
#define AF_XDP 44
#endif

#ifndef PF_XDP
#define PF_XDP AF_XDP
#endif

#define NUM_FRAMES 131072
#define FRAME_HEADROOM 0
#define FRAME_SIZE 2048
#define NUM_DESCS 1024
#define BATCH_SIZE 16

#define FQ_NUM_DESCS 1024
#define CQ_NUM_DESCS 1024

#define DEBUG_HEXDUMP 0

typedef __u64 u64;
typedef __u32 u32;
typedef __u16 u16;

static unsigned long prev_time;

static unsigned int header_length = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);

static u32 opt_xdp_flags;
static const char *opt_if = "";
static int opt_ifindex;
static int opt_queues = 1;
static int opt_poll;
static int opt_threads = 1;
static u32 opt_xdp_bind_flags;

struct xdp_umem_uqueue {
	u32 cached_prod;
	u32 cached_cons;
	u32 mask;
	u32 size;
	u32 *producer;
	u32 *consumer;
	u64 *ring;
	void *map;
};

struct xdp_umem {
	char *frames;
	struct xdp_umem_uqueue fq;
	struct xdp_umem_uqueue cq;
	int fd;
};

struct xdp_uqueue {
	u32 cached_prod;
	u32 cached_cons;
	u32 mask;
	u32 size;
	u32 *producer;
	u32 *consumer;
	struct xdp_desc *ring;
	void *map;
};

struct xdpsock {
	struct xdp_uqueue rx;
	struct xdp_uqueue tx;
	int sfd;
	struct xdp_umem *umem;
	u32 outstanding_tx;
};

struct xdpsock *xsks[PORT_RANGE_UPPER];

struct sock_port{
	struct xdpsock **xsks;
	int *ports;
	int length;
	int id;
};

static unsigned long get_nsecs(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000000000UL + ts.tv_nsec;
}

#define lassert(expr)							\
	do {								\
		if (!(expr)) {						\
			fprintf(stderr, "%s:%s:%i: Assertion failed: "	\
				#expr ": errno: %d/\"%s\"\n",		\
				__FILE__, __func__, __LINE__,		\
				errno, strerror(errno));		\
			exit(EXIT_FAILURE);				\
		}							\
	} while (0)

#define barrier() __asm__ __volatile__("": : :"memory")
#ifdef __aarch64__
#define u_smp_rmb() __asm__ __volatile__("dmb ishld": : :"memory")
#define u_smp_wmb() __asm__ __volatile__("dmb ishst": : :"memory")
#else
#define u_smp_rmb() barrier()
#define u_smp_wmb() barrier()
#endif
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline u32 umem_nb_free(struct xdp_umem_uqueue *q, u32 nb)
{
	u32 free_entries = q->cached_cons - q->cached_prod;

	if (free_entries >= nb)
		return free_entries;

	/* Refresh the local tail pointer */
	q->cached_cons = *q->consumer + q->size;

	return q->cached_cons - q->cached_prod;
}

static inline u32 xq_nb_free(struct xdp_uqueue *q, u32 ndescs)
{
	u32 free_entries = q->cached_cons - q->cached_prod;

	if (free_entries >= ndescs)
		return free_entries;

	/* Refresh the local tail pointer */
	q->cached_cons = *q->consumer + q->size;
	return q->cached_cons - q->cached_prod;
}

static inline u32 umem_nb_avail(struct xdp_umem_uqueue *q, u32 nb)
{
	u32 entries = q->cached_prod - q->cached_cons;

	if (entries == 0) {
		q->cached_prod = *q->producer;
		entries = q->cached_prod - q->cached_cons;
	}

	return (entries > nb) ? nb : entries;
}

static inline u32 xq_nb_avail(struct xdp_uqueue *q, u32 ndescs)
{
	u32 entries = q->cached_prod - q->cached_cons;

	if (entries == 0) {
		q->cached_prod = *q->producer;
		entries = q->cached_prod - q->cached_cons;
	}

	return (entries > ndescs) ? ndescs : entries;
}

static inline int umem_fill_to_kernel(struct xdp_umem_uqueue *fq, u64 *d,
				      size_t nb)
{
	u32 i;

	if (umem_nb_free(fq, nb) < nb)
		return -ENOSPC;

	for (i = 0; i < nb; i++) {
		u32 idx = fq->cached_prod++ & fq->mask;

		fq->ring[idx] = d[i];
	}

	u_smp_wmb();

	*fq->producer = fq->cached_prod;

	return 0;
}

static inline size_t umem_complete_from_kernel(struct xdp_umem_uqueue *cq,
					       u64 *d, size_t nb)
{
	u32 idx, i, entries = umem_nb_avail(cq, nb);

	u_smp_rmb();

	for (i = 0; i < entries; i++) {
		idx = cq->cached_cons++ & cq->mask;
		d[i] = cq->ring[idx];
	}

	if (entries > 0) {
		u_smp_wmb();

		*cq->consumer = cq->cached_cons;
	}

	return entries;
}

static inline void *xq_get_data(struct xdpsock *xsk, u64 addr)
{
	return &xsk->umem->frames[addr];
}

static inline int xq_enq(struct xdp_uqueue *uq,
			 const struct xdp_desc *descs,
			 unsigned int ndescs)
{
	struct xdp_desc *r = uq->ring;
	unsigned int i;

	if (xq_nb_free(uq, ndescs) < ndescs)
		return -ENOSPC;

	for (i = 0; i < ndescs; i++) {
		u32 idx = uq->cached_prod++ & uq->mask;

		r[idx].addr = descs[i].addr;
		r[idx].len = descs[i].len;
	}

	u_smp_wmb();

	*uq->producer = uq->cached_prod;
	return 0;
}

static inline int xq_deq(struct xdp_uqueue *uq,
			 struct xdp_desc *descs,
			 int ndescs)
{
	struct xdp_desc *r = uq->ring;
	unsigned int idx;
	int i, entries;

	entries = xq_nb_avail(uq, ndescs);

	u_smp_rmb();

	for (i = 0; i < entries; i++) {
		idx = uq->cached_cons++ & uq->mask;
		descs[i] = r[idx];
	}

	if (entries > 0) {
		u_smp_wmb();

		*uq->consumer = uq->cached_cons;
	}

	return entries;
}

static bool swap_header(void *data, u64 l)
{
	if (l < header_length) {
		return false;
	}
	//Eth-Header (MAC Adresses)
	struct ether_header *eth = (struct ether_header *)data;
	struct ether_addr *src_addr = (struct ether_addr *)&eth->ether_shost;
	struct ether_addr *dst_addr = (struct ether_addr *)&eth->ether_dhost;
	struct ether_addr eth_tmp;

	eth_tmp = *src_addr;
	*src_addr = *dst_addr;
	*dst_addr = eth_tmp;

	u64 offset = sizeof(*eth);

	//IP-Header (IP-Adresses)
	struct iphdr *iph = (struct iphdr *)(data + offset);
	u32 ip_tmp = iph->saddr;
	iph->saddr = iph->daddr;
	iph->daddr = ip_tmp;
	//Checksum stays the same. Change of length requires recalculation
	offset += sizeof(*iph);

	//UDP-Header (Ports)
	struct udphdr *udph = (struct udphdr *)(data + offset);
	u16 udp_tmp = udph->source;
	udph->source = udph->dest;
	udph->dest = udp_tmp;
	//Clear the checksum
	udph->check = 0;
	
	return true;
}

static struct xdp_umem *xdp_umem_configure(int sfd)
{
	int fq_size = FQ_NUM_DESCS, cq_size = CQ_NUM_DESCS;
	struct xdp_mmap_offsets off;
	struct xdp_umem_reg mr;
	struct xdp_umem *umem;
	socklen_t optlen;
	void *bufs;

	umem = calloc(1, sizeof(*umem));
	lassert(umem);

	lassert(posix_memalign(&bufs, getpagesize(), /* PAGE_SIZE aligned */
			       NUM_FRAMES * FRAME_SIZE) == 0);

	mr.addr = (__u64)bufs;
	mr.len = NUM_FRAMES * FRAME_SIZE;
	mr.chunk_size = FRAME_SIZE;
	mr.headroom = FRAME_HEADROOM;

	lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_REG, &mr, sizeof(mr)) == 0);
	lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_FILL_RING, &fq_size,
			   sizeof(int)) == 0);
	lassert(setsockopt(sfd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &cq_size,
			   sizeof(int)) == 0);

	optlen = sizeof(off);
	lassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
			   &optlen) == 0);

	umem->fq.map = mmap(0, off.fr.desc +
			    FQ_NUM_DESCS * sizeof(u64),
			    PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_POPULATE, sfd,
			    XDP_UMEM_PGOFF_FILL_RING);
	lassert(umem->fq.map != MAP_FAILED);

	umem->fq.mask = FQ_NUM_DESCS - 1;
	umem->fq.size = FQ_NUM_DESCS;
	umem->fq.producer = umem->fq.map + off.fr.producer;
	umem->fq.consumer = umem->fq.map + off.fr.consumer;
	umem->fq.ring = umem->fq.map + off.fr.desc;
	umem->fq.cached_cons = FQ_NUM_DESCS;

	umem->cq.map = mmap(0, off.cr.desc +
			     CQ_NUM_DESCS * sizeof(u64),
			     PROT_READ | PROT_WRITE,
			     MAP_SHARED | MAP_POPULATE, sfd,
			     XDP_UMEM_PGOFF_COMPLETION_RING);
	lassert(umem->cq.map != MAP_FAILED);

	umem->cq.mask = CQ_NUM_DESCS - 1;
	umem->cq.size = CQ_NUM_DESCS;
	umem->cq.producer = umem->cq.map + off.cr.producer;
	umem->cq.consumer = umem->cq.map + off.cr.consumer;
	umem->cq.ring = umem->cq.map + off.cr.desc;

	umem->frames = bufs;
	umem->fd = sfd;

	return umem;
}

static struct xdpsock *xsk_configure(struct xdp_umem *umem, int queue)
{
	struct sockaddr_xdp sxdp = {};
	struct xdp_mmap_offsets off;
	int sfd, ndescs = NUM_DESCS;
	struct xdpsock *xsk;
	bool shared = true;
	socklen_t optlen;
	u64 i;

	sfd = socket(PF_XDP, SOCK_RAW, 0);
	lassert(sfd >= 0);

	xsk = calloc(1, sizeof(*xsk));
	lassert(xsk);

	xsk->sfd = sfd;
	xsk->outstanding_tx = 0;

	if (!umem) {
		shared = false;
		xsk->umem = xdp_umem_configure(sfd);
	} else {
		xsk->umem = umem;
	}

	lassert(setsockopt(sfd, SOL_XDP, XDP_RX_RING,
			   &ndescs, sizeof(int)) == 0);
	lassert(setsockopt(sfd, SOL_XDP, XDP_TX_RING,
			   &ndescs, sizeof(int)) == 0);
	optlen = sizeof(off);
	lassert(getsockopt(sfd, SOL_XDP, XDP_MMAP_OFFSETS, &off,
			   &optlen) == 0);

	/* Rx */
	xsk->rx.map = mmap(NULL,
			   off.rx.desc +
			   NUM_DESCS * sizeof(struct xdp_desc),
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, sfd,
			   XDP_PGOFF_RX_RING);
	lassert(xsk->rx.map != MAP_FAILED);

	if (!shared) {
		for (i = 0; i < NUM_DESCS * FRAME_SIZE; i += FRAME_SIZE)
			lassert(umem_fill_to_kernel(&xsk->umem->fq, &i, 1)
				== 0);
	}

	/* Tx */
	xsk->tx.map = mmap(NULL,
			   off.tx.desc +
			   NUM_DESCS * sizeof(struct xdp_desc),
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_POPULATE, sfd,
			   XDP_PGOFF_TX_RING);
	lassert(xsk->tx.map != MAP_FAILED);

	xsk->rx.mask = NUM_DESCS - 1;
	xsk->rx.size = NUM_DESCS;
	xsk->rx.producer = xsk->rx.map + off.rx.producer;
	xsk->rx.consumer = xsk->rx.map + off.rx.consumer;
	xsk->rx.ring = xsk->rx.map + off.rx.desc;

	xsk->tx.mask = NUM_DESCS - 1;
	xsk->tx.size = NUM_DESCS;
	xsk->tx.producer = xsk->tx.map + off.tx.producer;
	xsk->tx.consumer = xsk->tx.map + off.tx.consumer;
	xsk->tx.ring = xsk->tx.map + off.tx.desc;
	xsk->tx.cached_cons = NUM_DESCS;

	sxdp.sxdp_family = PF_XDP;
	sxdp.sxdp_ifindex = opt_ifindex;
	sxdp.sxdp_queue_id = queue;

	if (shared) {
		sxdp.sxdp_flags = XDP_SHARED_UMEM;
		sxdp.sxdp_shared_umem_fd = umem->fd;
	} else {
		sxdp.sxdp_flags = opt_xdp_bind_flags;
	}

	lassert(bind(sfd, (struct sockaddr *)&sxdp, sizeof(sxdp)) == 0);

	return xsk;
}

static void int_exit(int sig)
{
	(void)sig;
	bpf_set_link_xdp_fd(opt_ifindex, -1, opt_xdp_flags);
	exit(EXIT_SUCCESS);
}

static struct option long_options[] = {
	{"interface", required_argument, 0, 'i'},
	{"queues", required_argument, 0, 'q'},
	{"poll", no_argument, 0, 'p'},
	{"xdp-skb", no_argument, 0, 'S'},
	{"xdp-native", no_argument, 0, 'N'},
	{"threads", required_argument, 0, 't'},
	{0, 0, 0, 0}
};

static void usage(const char *prog)
{
	const char *str =
		"  Usage: %s [OPTIONS]\n"
		"  Options:\n"
		"  -i, --interface=n	Run on interface n\n"
		"  -q, --queues=n	Number of queues (defaults to 1)\n"
		"  -p, --poll		Use poll syscall\n"
		"  -S, --xdp-skb=n	Use XDP skb-mod\n"
		"  -N, --xdp-native=n	Enfore XDP native mode\n"
		"  -t, --threads=n	Specify worker threads (default to 1).\n"
		"\n";
	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;

	opterr = 0;

	for (;;) {
		c = getopt_long(argc, argv, "i:q:pSNt:", long_options,
				&option_index);
		if (c == -1)
			break;

		switch (c) {
		case 'i':
			opt_if = optarg;
			break;
		case 'q':
			opt_queues = atoi(optarg);
			break;
		case 'p':
			opt_poll = 1;
			break;
		case 'S':
			opt_xdp_flags |= XDP_FLAGS_SKB_MODE;
			opt_xdp_bind_flags |= XDP_COPY;
			break;
		case 'N':
			opt_xdp_flags |= XDP_FLAGS_DRV_MODE;
			break;
		case 't':
			opt_threads = atoi(optarg);
			break;
		default:
			usage(basename(argv[0]));
		}
	}

	opt_ifindex = if_nametoindex(opt_if);
	if (!opt_ifindex) {
		fprintf(stderr, "ERROR: interface \"%s\" does not exist\n",
			opt_if);
		usage(basename(argv[0]));
	}
}

static void kick_tx(int fd)
{
	int ret;

	ret = sendto(fd, NULL, 0, MSG_DONTWAIT, NULL, 0);
	if (ret >= 0 || errno == ENOBUFS || errno == EAGAIN || errno == EBUSY)
		return;
	lassert(0);
}

static inline void complete_tx(struct xdpsock *xsk)
{
	u64 descs[BATCH_SIZE];
	unsigned int rcvd;
	size_t ndescs;

	if (!xsk->outstanding_tx)
		return;

	kick_tx(xsk->sfd);
	ndescs = (xsk->outstanding_tx > BATCH_SIZE) ? BATCH_SIZE :
		 xsk->outstanding_tx;

	// re-add completed Tx buffers
	rcvd = umem_complete_from_kernel(&xsk->umem->cq, descs, ndescs);
	if (rcvd > 0) {
		umem_fill_to_kernel(&xsk->umem->fq, descs, rcvd);
		xsk->outstanding_tx -= rcvd;
	}
}

static int create_socket(int port, int queue, int thread) 
{
	int offset = MAX_SOCKS / opt_queues;
	offset = offset * queue;
	offset = offset + thread;
	offset = offset + port;
	// Check if offset is valid
	if (offset > PORT_RANGE_UPPER || offset < PORT_RANGE_LOWER || offset >= port + MAX_SOCKS)
		return -1;
	// Create socket at queue
	xsks[offset] = xsk_configure(NULL, queue);
	return offset;
}

static void * requestHandler(void *arg)
{
	int timeout = 1000, ret = 0;
	struct sock_port *sp = (struct sock_port*) arg;
	struct xdp_desc descs[BATCH_SIZE];
	unsigned int rcvd, i, l;
	char *pkt = NULL;
	function func[sp->length];
	struct pollfd pfd[sp->length];
	memset(&pfd, 0, sizeof(pfd));
	for (l = 0; l < sp->length; l++) {
		func[l] = get_function(sp->ports[l]);
		if (func == NULL) {
			fprintf(stderr, "No Function defined...\n");
			return NULL;
		}
		pfd[l].fd = sp->xsks[l]->sfd;
		pfd[l].events = POLLIN;
	}

	for (;;) {
		if (opt_poll) { // Poll new data
			ret = poll(pfd, sp->length, timeout);
			if (ret <= 0) {
				fprintf(stdout, "Timeout(%d)\n", sp->id);
				fflush(stdout);
				continue;
			}
		}

		for (l = 0; l < sp->length; l++) {
			if (opt_poll && pfd[l].revents == 0)
				continue;
			rcvd = xq_deq(&sp->xsks[l]->rx, descs, BATCH_SIZE);
			if (rcvd == 0)
				continue;

			// Execute the function for every packet 
			for (i = 0; i < rcvd; i++) {
				pkt = xq_get_data(sp->xsks[l], descs[i].addr);

#if DEBUG_HEXDUMP
				fprintf(stdout, "Port %d: ", sp->ports[l]);
				hex_dump(pkt, descs[i].len, descs[i].addr);
				fflush(stdout);
#endif
				// Swap ETH, IP and UDP header
				if (!swap_header(pkt, descs[i].len)) {
					fprintf(stderr, "Port %d: Header to short\n", sp->ports[l]);
					continue;
				}

				if (!(*func[l])(pkt, &descs[i].len, header_length)) {
					fprintf(stderr, "Port %d: Function failed\n", sp->ports[l]);
					continue;
				} // Todo: Calculate checksum if length changed
			}
		
			// Back to the Kernel by TX
			ret = xq_enq(&sp->xsks[l]->tx, descs, rcvd);
			lassert(ret == 0);
			sp->xsks[l]->outstanding_tx += rcvd;
			// Complete the TX
			complete_tx(sp->xsks[l]);
		}
	}
	free(sp->xsks);
	free(sp->ports);
	free(sp);
}

int main(int argc, char **argv)
{
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type	= BPF_PROG_TYPE_XDP,
	};
	int prog_fd, xsks_map, rr_map, num_socks_map, num_queues_map;
	struct bpf_object *obj;
	char xdp_filename[256];
	struct bpf_map *map;
	int t, q, p, pqt, key = 0, ret;
	int ports[] = {1232};
	int len_ports = (sizeof(ports) / sizeof(ports[0]));
	struct sock_port *sp = NULL;
	
	pthread_t pt[PORT_RANGE_UPPER];
	
	parse_command_line(argc, argv);

	if (setrlimit(RLIMIT_MEMLOCK, &r)) {
		fprintf(stderr, "ERROR: setrlimit(RLIMIT_MEMLOCK) \"%s\"\n",
			strerror(errno));
		exit(EXIT_FAILURE);
	}

	snprintf(xdp_filename, sizeof(xdp_filename), "%s_kern.o", argv[0]);
	prog_load_attr.file = xdp_filename;

	if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
		exit(EXIT_FAILURE);
	if (prog_fd < 0) {
		fprintf(stderr, "ERROR: no program found: %s\n",
			strerror(prog_fd));
		exit(EXIT_FAILURE);
	}
	
	map = bpf_object__find_map_by_name(obj, "xsks_map");
	xsks_map = bpf_map__fd(map);
	if (xsks_map < 0) {
		fprintf(stderr, "ERROR: no xsks map found: %s\n",
			strerror(xsks_map));
		exit(EXIT_FAILURE);
	}

	map = bpf_object__find_map_by_name(obj, "num_socks_map");
	num_socks_map = bpf_map__fd(map);
	if (num_socks_map < 0) {
		fprintf(stderr, "ERROR: no num_socks map found: %s\n",
			strerror(num_socks_map));
		exit(EXIT_FAILURE);
	}

	map = bpf_object__find_map_by_name(obj, "rr_map");
	rr_map = bpf_map__fd(map);
	if (rr_map < 0) {
		fprintf(stderr, "ERROR: no rr map found: %s\n",
			strerror(rr_map));
		exit(EXIT_FAILURE);
	}

	map = bpf_object__find_map_by_name(obj, "num_queues_map");
	num_queues_map = bpf_map__fd(map);
	if (rr_map < 0) {
		fprintf(stderr, "ERROR: no rr map found: %s\n",
			strerror(num_queues_map));
		exit(EXIT_FAILURE);
	}

	if (bpf_set_link_xdp_fd(opt_ifindex, prog_fd, opt_xdp_flags) < 0) {
		fprintf(stderr, "ERROR: link set xdp fd failed\n");
		exit(EXIT_FAILURE);
	}
	fprintf(stdout, "Let's create Sockets!\n");

	/* Create sockets... */
	for (p = 0; p < len_ports; p++) { // ports[p] -> port
		for (q = 0; q < opt_queues; q++) { // q -> queue
			for (t = 0; t < opt_threads; t++) { // t -> thread
				pqt = create_socket(ports[p], q, t);
				if ( pqt < 0 ) {
					fprintf(stderr,
						"ERROR: Socket creation failed\n");
					exit(EXIT_FAILURE);
				}
				ret = bpf_map_update_elem(xsks_map, &pqt, &xsks[pqt]->sfd, 0);
				if (ret) {
					fprintf(stderr, "Error: bpf_map_update_elem %d\n", pqt);
					fprintf(stderr, "ERRNO: %d\n", errno);
					fprintf(stderr, strerror(errno));
					exit(EXIT_FAILURE);
				}

				// Configure and start the consumer thread
				sp = malloc(sizeof(struct sock_port));
				(*sp).length = 1;
				(*sp).xsks = malloc(sizeof(struct xdpsock *) * (*sp).length);
				(*sp).xsks[0] = xsks[pqt];
				(*sp).ports = malloc(sizeof(int) * (*sp).length);
				(*sp).ports[0] = ports[p];
				(*sp).id = pqt;
				pthread_create(&pt[pqt], NULL, requestHandler, sp);
				fprintf(stdout, "Socket %d created\n", pqt);
				
				if (t == 0) {
					// Set the number of threads per queue
					ret = bpf_map_update_elem(num_socks_map, &pqt, &opt_threads, 0);
					if (ret) {
						fprintf(stderr, "Error: bpf_map_update_elem %d\n", pqt);
						fprintf(stderr, "ERRNO: %d\n", errno);
						fprintf(stderr, strerror(errno));
						exit(EXIT_FAILURE);
					}
				}
			}
		}
		fprintf(stdout, "Started %d Threads for Port %d\n", opt_threads * opt_queues, ports[p]);
	}
	// Set the number of queues
	ret = bpf_map_update_elem(num_queues_map, &key, &opt_queues, 0);
	if (ret) {
		fprintf(stderr, "Error: bpf_map_update_elem\n");
		fprintf(stderr, "ERRNO: %d\n", errno);
		fprintf(stderr, strerror(errno));
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, int_exit);
	signal(SIGTERM, int_exit);
	signal(SIGABRT, int_exit);

	setlocale(LC_ALL, "");

	prev_time = get_nsecs();

	sleep(72000); //Sleep for 20 hours

	return 0;
}

/* pktgen.c */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <getopt.h>
#include <libgen.h>
#include <pthread.h>

static unsigned long opt_addr;
static char *opt_addr_str;
static unsigned int opt_port;
static unsigned int opt_threads = 1;
static unsigned int opt_packetsize = 200;
static unsigned int opt_num_sockets = 1;
static unsigned int opt_mmsg = 32;

#define HEADER_SIZE 42 //ETH-HEADER + IPv4 HEADER + UDP-HEADER

static void error_exit(char *errormessage) 
{
	fprintf(stderr, "%s: %s\n", errormessage, strerror(errno));
	exit(EXIT_FAILURE);
}

static struct option long_options[] = {
	{"bytes", optional_argument, 0, 'b'},
	{"server", required_argument, 0, 's'},
	{"port", required_argument, 0, 'p'},
	{"threads", optional_argument, 0, 't'},
	{"numSocks", optional_argument, 0, 'n'},
	{"mmsg", optional_argument, 0, 'm'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0}
};
static void usage(const char *prog)
{
	const char *str =
		" Usage %s [OPTIONS]\n"
		" Options: \n"
		" -s	IP_ADRESS\n"
		" -p	PORT\n"
		" -t    THREADS (Defaults to 1)\n"
		" -n    SOCKS (Sockets per Thread defaults to 1)\n"
		" -b    BYTES (Packet size defaults to 200)\n"
		" -m    MMSG (Multiple messages simultaneous sent defaults to 32)\n"
	        " -h    prints this Message\n";
	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;
	opterr = 0;
	for (;;) {
		c = getopt_long(argc, argv, "b:s:p:t:n:m:h", long_options, 
				&option_index);
		if (c == -1)
			break;
		switch(c) {
		case 'b':
			opt_packetsize = atoi(optarg);
			break;
		case 's':
			if ((opt_addr = inet_addr(optarg)) == INADDR_NONE) {
				usage(basename(argv[0]));
			}
			opt_addr_str = optarg;
			break;
		case 'p':
			opt_port = atoi(optarg);
			break;
		case 't':
			opt_threads = atoi(optarg);
			break;
		case 'n':
			opt_num_sockets = atoi(optarg);
			break;
		case 'm':
			opt_mmsg = atoi(optarg);
			break;
		case 'h':
		default:
			usage(basename(argv[0]));
			break;
		}
	}
}

static void* sendpkg (void* arg) {
	char *payload = (char*) arg;

	struct sockaddr_in server;
	int sock[opt_num_sockets];
	char buffer[2048];
	memset(buffer, 0, sizeof(char)*2048);
	int len = 16, i;
	int payload_len = strlen(payload);

	//mmsg Settings
	struct mmsghdr msg[opt_mmsg];
	struct iovec msg_single[opt_mmsg];
	memset(msg, 0, sizeof(msg));
	memset(msg_single, 0, sizeof(msg_single));
	for (i = 0; i < opt_mmsg; i++) {
		msg_single[i].iov_base = payload;
		msg_single[i].iov_len = payload_len;
		msg[i].msg_hdr.msg_iov = &msg_single[i];
		msg[i].msg_hdr.msg_iovlen = 1;
	}

	char addr[len];
	inet_ntop(AF_INET, &opt_addr, addr, len);
	fprintf(stdout, "IP-Adress: %lu\nIP-Adress: %s\nPort: %d\n", 
			opt_addr, opt_addr_str, opt_port); 
	//Set Server Connection
	memset(&server, 0, sizeof(server));
	memcpy((char *)&server.sin_addr, &opt_addr, sizeof(opt_addr));
	server.sin_port = htons(opt_port);
	server.sin_family = AF_INET;

	for (i = 0; i < opt_num_sockets; i++) {
		//Create Socket
		sock[i] = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if (sock[i] < 0)
			error_exit ("Socket creation failed\n");
		fprintf(stdout, "Socket created\n");

		if (connect(sock[i], (struct sockaddr*)&server, sizeof(server)) < 0)
			error_exit("Connection failed\n");
		fprintf(stdout, "Connection established\n");
	}
//	int recv_len = 0;

//	unsigned long i = 0;
//	for (i = 0; i < 2999999999999; i++) {
	for (;;) {
		for (i = 0; i < opt_num_sockets; i++) {
			if (sendmmsg(sock[i], msg, opt_mmsg, 0) != opt_mmsg) {
			//if (send(sock[i], payload, payload_len, 0) != payload_len) {
				error_exit("send() failed\n");
			/*} else {
				recv_len = recvfrom(sock, buffer, 2048, 0, NULL, 0);
				if (recv_len != payload_len)
					error_exit("recv() failed\n");
				fprintf(stdout, "Got %d bytes - Payload_len %d\n", recv_len, payload_len);
				for (int j = 0; j < recv_len; j++) {
					fprintf(stdout, "(%d): %c ", j, buffer[j]); 
				}*/
			}
		}
	}

	fprintf(stdout, "Payload sent\n");
	for (i = 0; i < opt_num_sockets; i++) {
		close(sock[i]);
		fprintf(stdout, "Socket closed\n");
	}
	return NULL;
}

int main (int argc, char **argv) 
{
	parse_command_line(argc, argv);
	char payload[2048];
	int payload_len = opt_packetsize - HEADER_SIZE;
	for (int i = 0; i < payload_len; i++) {
		payload[i] = 48 + (i % 10);
	}
	payload[payload_len] = 0;
	
	pthread_t pt[opt_threads];
	
	fprintf(stdout, "%d threads to start\n", opt_threads);
	for (int i = 0; i < opt_threads; i++){
		pthread_create(&pt[i], NULL, sendpkg, payload);
		fprintf(stdout, "Thread started");
	}

	sleep(1200);


	return EXIT_SUCCESS;
}

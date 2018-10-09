/* reqrouter.c */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
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
#include <poll.h>

#include "../common/functions.h"

static unsigned int opt_port = 1232;
static unsigned int opt_threads = 1;
static bool opt_unoptimized = false;

#define BUFLEN 2048
#define MMSGLEN 1024
#define HEADER_SIZE 42 //ETH-HEADER + IPv4 HEADER + UDP-HEADER

static void error_exit(char *errormessage) 
{
	fprintf(stderr, "%s: %s\n", errormessage, strerror(errno));
	exit(EXIT_FAILURE);
}

static struct option long_options[] = {
	{"port", optional_argument, 0, 'p'},
	{"threads", optional_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	{"unoptimized", no_argument, 0, 'u'},
	{0, 0, 0, 0}
};
static void usage(const char *prog)
{
	const char *str =
		" Usage %s [OPTIONS]\n"
		" Options: \n"
		" -p	PORT (Defaults to 1234)\n"
		" -t    THREADS (Defaults to 1)\n"
	        " -h    prints this Message\n"
	        " -u    turn off the optimizations\n";
	fprintf(stderr, str, prog);
	exit(EXIT_FAILURE);
}

static void parse_command_line(int argc, char **argv)
{
	int option_index, c;
	opterr = 0;
	for (;;) {
		c = getopt_long(argc, argv, "p:t:uh", long_options, 
				&option_index);
		if (c == -1)
			break;
		switch(c) {
		case 'p':
			opt_port = atoi(optarg);
			break;
		case 't':
			opt_threads = atoi(optarg);
			if (opt_threads < 1) {
				fprintf(stdout, "To few threads, defaulting to 1 Thread\n");
				opt_threads = 1;
			}
			break;
		case 'u':
			opt_unoptimized = true;
			break;
		case 'h':
		default:
			usage(basename(argv[0]));
			break;
		}
	}
}

static void* recvpkg_unoptimized (void* arg)
{
	struct sockaddr_in server, client;
	int sock, recv_len;
	unsigned int sockaddr_len = sizeof(client);
	char buffer[BUFLEN];
	memset(buffer, 0, sizeof(buffer));

	// Get the function
	function func = get_function(opt_port);
	if (func == NULL){
		fprintf(stderr, "No Function defined...\n");
		return NULL;
	}

	// Create Socket
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		error_exit ("Socket creation failed\n");
	fprintf(stdout, "Socket created\n");

	// Set Server Connection
	memset(&server, 0, sizeof(server));
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(opt_port);
	server.sin_family = AF_INET;
	
	if (bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0)
		error_exit("Socket bind failed\n");
	fprintf(stdout, "Socket bound\n");

	for (;;) {
		recv_len = recvfrom(sock, buffer, BUFLEN, 0, (struct sockaddr*) &client, &sockaddr_len);
		if (recv_len < 0) {
			error_exit("recvfrom() failed\n");
		} else if (recv_len > 0) {
			// Execute function
			if (!(func)(buffer, &recv_len, 0)) {
				error_exit("Function failed\n");
			}

			//Answer
			if (sendto(sock, buffer, recv_len, 0, (struct sockaddr*)&client, sockaddr_len) != recv_len) {
				error_exit("sendto() failed\n");
			}
		}
	}
	close(sock);
	return NULL;
}

static void* recvpkg (void* arg)
{
	int sock, recv_len, i;
	struct sockaddr_in server, clients[MMSGLEN];
	struct mmsghdr msgs[MMSGLEN];
	struct iovec iovecs[MMSGLEN];
	char buffer[MMSGLEN][BUFLEN];

	// Enabling the timeout has a performance impact
//	struct timespec timeout;
//	timeout.tv_sec = 1;
//	timeout.tv_nsec = 0;

	// Initialize data structures
	memset(buffer, 0, sizeof(buffer));
	memset(msgs, 0, sizeof(msgs));
	for (i = 0; i < MMSGLEN; i++) {
		iovecs[i].iov_base = buffer[i];
		iovecs[i].iov_len = BUFLEN;
		msgs[i].msg_hdr.msg_iov = &iovecs[i];
		msgs[i].msg_hdr.msg_iovlen = 1;
		msgs[i].msg_hdr.msg_name = &clients[i];
		msgs[i].msg_hdr.msg_namelen = sizeof(clients[i]);
	}
	
	// Get the function
	function func = get_function(opt_port);
	if (func == NULL){
		fprintf(stderr, "No Function defined...\n");
		return NULL;
	}

	// Create Socket
	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0)
		error_exit ("Socket creation failed\n");
	fprintf(stdout, "Socket created\n");

	// Set Server Connection
	memset(&server, 0, sizeof(server));
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(opt_port);
	server.sin_family = AF_INET;
	
	// Set SO_REUSEPORT to allow multithreading on the same socket
	int opt_val = 1;
	setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt_val, sizeof(opt_val));

	if (bind(sock, (struct sockaddr*)&server, sizeof(server)) < 0)
		error_exit("Socket bind failed\n");
	fprintf(stdout, "Socket bound\n");

	for (;;) {
		// Receive up to MMSGLEN messages from the socket
		// Timeout disabled because of performance impact
//		recv_len = recvmmsg(sock, msgs, MMSGLEN, MSG_WAITFORONE, &timeout);
		recv_len = recvmmsg(sock, msgs, MMSGLEN, MSG_WAITFORONE, 0);
		
		if (recv_len < 0) { // Length negative if recvmmsg failed
			error_exit("recvmmsg() failed\n");
		} else if (recv_len > 0) {
			// Read every packet
			for (i = 0; i < recv_len; i++) {
				// Execute function
				if (!(func)(msgs[i].msg_hdr.msg_iov[0].iov_base, &msgs[i].msg_len, 0)) {
					error_exit("Function failed\n");
				}
				// Set the return message size
				msgs[i].msg_hdr.msg_iov[0].iov_len = msgs[i].msg_len;
			}
			// Respond to the requests (Up to MMSGLEN)
			if (sendmmsg(sock, msgs, recv_len, 0) != recv_len) {
				error_exit("sendmmsg() failed\n");
			}
			// Reset the iov_len to BUFLEN. Was changed to sendmmsg
			for (i = 0; i < recv_len; i++) {
				msgs[i].msg_hdr.msg_iov[0].iov_len = BUFLEN;
			}
		}
	}

	close(sock);
	return NULL;
}

static void prog_exit(int sig)
{
	fprintf(stdout, "Signal %d catched. Exiting...\n", sig);
	fflush(stdout);
	// Todo: Stop all threads and close the sockets
	exit(EXIT_SUCCESS);
}

int main (int argc, char **argv) 
{
	parse_command_line(argc, argv);
	
	//Start x threads
	pthread_t pt[opt_threads];
	if (opt_unoptimized) {
		fprintf(stdout, "Unoptimized version. Single thread will be started");
		pthread_create(&pt[0], NULL, recvpkg_unoptimized, NULL);
	} else {
		fprintf(stdout, "Optimized version. %d threads to start\n", opt_threads);
		for (int i = 0; i < opt_threads; i++){
			pthread_create(&pt[i], NULL, recvpkg, NULL);
			fprintf(stdout, "Thread started");
		}
	}
	
	// Set signal Handlers
	signal(SIGINT, prog_exit);
	signal(SIGTERM, prog_exit);
	signal(SIGABRT, prog_exit);

	sleep(72000); // Wait up to 20 Hours

	exit(EXIT_SUCCESS);
}

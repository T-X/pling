/* SPDX-License-Identifier: MIT */
/*
 * Copyright (c) 2021, Linus Lüssing
 */

#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include "main.h"

#include "ether.h"
#include "list.h"
#include "times.h"

#define LLCMP_ETHER_TYPE 0x4304
#define MAX_EVENTS 32

#define STRLEN(s) ((sizeof(s)/sizeof(s[0])) - 1)
#define ETH_STRLEN STRLEN("00:11:22:33:44:55")

#define REQUEST_TIME_CACHE_SIZE 64

static int term = 0;

static struct epoll_event events[MAX_EVENTS];
static int epoll_fd;
static int sd;

enum llcmp_types {
	LLCMP_ECHO_REQUEST = 128,
	LLCMP_ECHO_REPLY = 129,
};

/* structure similar to ICMPv6 Echo Request/Reply */
struct pling_header {
	struct ethhdr ethhdr;
	uint8_t reserved1;	/* later: hoplimit (number of switches it may pass) */
	uint8_t reserved2;	/* later: traffic class */
	__be16 payload_len;	/* length of msg date beyond this header */
	uint8_t type;
	uint8_t reserved3;	/* later: code */
	uint16_t reserved4;	/* later: checksum */
	__be16 identifier;
	__be16 seqno;
	uint8_t replyto[6];
} __attribute__((packed));

struct pling_config pling_config;

/* echo request specific storage */
static struct pling_header *request_buffer;
static struct timespec request_time_cache[REQUEST_TIME_CACHE_SIZE];
static int rtcidx = REQUEST_TIME_CACHE_SIZE - 1;
static int request_reply_count = 0;


static void sigint_handler(int signo) {
	term = 1;
}

static int init_socket(void)
{
	struct ifreq ifreq;
	const char *ifname =  pling_config.ifname;
	int ret;
	struct epoll_event event;

	/* create socket */
	sd = socket(AF_PACKET, SOCK_RAW, htons(LLCMP_ETHER_TYPE));
	if (sd < 0) {
		fprintf(stderr,
			"Error: Can't open a raw socket for ether type 0x%04x\n",
			LLCMP_ETHER_TYPE);
		return -EPERM;
	}

	/* bind socket to specific interface */
	ret = setsockopt(sd, SOL_SOCKET, SO_BINDTODEVICE, ifname,
			 strlen(ifname));
	if (ret < 0) {
		fprintf(stderr, "Error: Can't bind to device %s\n", ifname);
		goto err;
	}

	/* get MAC address and index of interface */
	memset(&ifreq, 0, sizeof(ifreq));
	strcpy(ifreq.ifr_name, ifname);

	ret = ioctl(sd, SIOCGIFHWADDR, &ifreq);
	if (ret < 0) {
		fprintf(stderr, "Error: Can't get mac address of interface\n");
		goto err;
	}
	eth_copy(pling_config.ifaddr,
		 (unsigned char *)ifreq.ifr_hwaddr.sa_data);

	ret = ioctl(sd, SIOCGIFINDEX, &ifreq);
	if (ret < 0) {
		fprintf(stderr, "Error: Can't get interface index\n");
		goto err;
	}
	pling_config.ifindex = ifreq.ifr_ifindex;

	/* add socket to epoll */
	memset(&event, 0, sizeof(event));
	event.events = EPOLLIN;
	event.data.fd = sd;

	if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sd, &event)) {
		fprintf(stderr, "Error: Can't add socket to epoll.\n");
		ret = -EPERM;
		goto err;
	}

	return 0;

err:
	close(sd);
	return ret;
}

static void usage(const char *progname)
{
	printf("Usage: %s -h|--help\n"
	       "       %s -I|--interface <IFACE> -l|--listen\n"
	       "       %s -I|--interface <IFACE> [-c <CNT>] [-s <SIZE>] [-i <SECS>] [-r HOST] HOST [ HOST ... ]\n"
	       "\n"
	       "Options:\n"
	       "  -I, --interface       The interface to send or receive on\n"
	       "  -l, --listen          listen-mode\n"
	       "  -c, --count CNT       Send only CNT pings\n"
	       "  -s, --size SIZE       Send SIZE data bytes in packets (default 56)\n"
	       "  -i, --interval SECS   Interval\n"
	       "  -r, --replyto HOST    The host address to reply to (default: source address)\n",
	       progname, progname, progname);
}

static int config_add_host(const char *host) {
	struct pling_host *pling_host;

	pling_host = malloc(sizeof(*pling_host));
	if (!pling_host) {
		fprintf(stderr,
			"Error: Can't allocate host: out-of-memory\n");
		return -ENOMEM;
	}

	if (eth_str2bin(host, pling_host->host) < 0) {
		free(pling_host);
		fprintf(stderr, "Error: invalid MAC address: %s\n", host);
		return -EINVAL;
	}

	if (eth_is_zero(pling_host->host)) {
		free(pling_host);
		fprintf(stderr,
			"Error: zero MAC address not allowed\n");
		return -EINVAL;
	}

	list_add_tail(&pling_host->node, &pling_config.hosts);

	return 0;
}

static void config_free_hosts(void) {
	struct pling_host *host, *tmp;

	list_for_each_entry_safe(host, tmp, &pling_config.hosts, node) {
		list_del(&host->node);
		free(host);
	}
}

static int init_args(int argc, char *argv[])
{
	int opt;
	int opt_idx;
	float interval;
	char *endptr;

	struct option long_opts[] =
	{
		{"help",	no_argument,		0, 'h'},
		{"listen",	no_argument,		0, 'l'},
		{"interface",	required_argument,	0, 'I'},
		{"count",	required_argument,	0, 'c'},
		{"size",	required_argument,	0, 's'},
		{"interval",	required_argument,	0, 'i'},
		{"replyto",	required_argument,	0, 'r'},
		{0, 0, 0, 0}
        };

	while(1) {
		opt = getopt_long(argc, argv, "hlc:s:i:I:r:", long_opts, &opt_idx);
		if (opt == -1)
			break;

		errno = 0;

		switch(opt) {
		case 'h':
			usage(argv[0]);
			exit(2);
			break;
		case 'l':
			pling_config.listen = 1;
			break;
		case 'c':
			pling_config.count = strtoul(optarg, &endptr, 10);
			if (errno != 0 || endptr == optarg ||
			    pling_config.count == 0)
				goto parse_err;
			break;
		case 's':
			pling_config.size = strtoul(optarg, &endptr, 10);
			if (errno != 0 || endptr == optarg)
				goto parse_err;
			break;
		case 'i':
			if (sscanf(optarg, "%f", &interval) == EOF ||
			    interval <= 0 || interval > UINT16_MAX)
				goto parse_err;

			pling_config.interval = (unsigned long)(1000 * interval);
			if (pling_config.interval == 0)
				goto parse_err;
			break;
		case 'I':
			pling_config.ifname = optarg;
			break;
		case 'r':
			if (eth_str2bin(optarg, pling_config.replyto) < 0) {
				fprintf(stderr, "Error: invalid MAC address: %s\n\n",
					argv[optind]);
				exit(2);
			}
			if (eth_is_zero(pling_config.replyto)) {
				fprintf(stderr,
					"Error: zero MAC address not allowed\n\n");
				exit(2);
			}
			break;
		default:
			fprintf(stderr, "\n");
			usage(argv[0]);
			exit(2);
		}
	}

	if (pling_config.listen &&
	    (pling_config.count || pling_config.size ||
	     pling_config.interval ||
	     !eth_is_zero(pling_config.replyto))) {
		fprintf(stderr,
			"Error: options invalid for listen-mode selected\n\n");
		usage(argv[0]);
		exit(2);
	}


	if (!pling_config.ifname) {
		fprintf(stderr, "Error: no interface specified\n\n");
		usage(argv[0]);
		exit(2);
	}

	if (pling_config.listen) {
		/* listener mode */
		if (optind != argc) {
			fprintf(stderr,
				"Error: too many non-option arguments\n\n");
			usage(argv[0]);
			exit(2);
		}
	} else {
		/* sender mode */
		while (optind < argc) {
			if (config_add_host(argv[optind++]) < 0) {
				config_free_hosts();
				exit(2);
			}
		}

		if (list_empty(&pling_config.hosts)) {
			fprintf(stderr, "Error: no host specified\n\n");
			usage(argv[0]);
			exit(2);
		}
	}

	if (!pling_config.listen && !pling_config.interval)
		pling_config.interval = 1000;

	return 0;

parse_err:
	fprintf(stderr,
		"Error: argument for option %c is not a positive integer or out-of-range!\n\n",
		opt);
	usage(argv[0]);
	exit(2);

	return 1;
}

static int init_request_buffer(void)
{
	__be16 identifier;
	unsigned int len;

	len = sizeof(identifier);
	if (syscall(SYS_getrandom, &identifier, len, 0) != len)
		return -EBUSY;

	len = sizeof(struct pling_header) + pling_config.size;

	request_buffer = malloc(len);
	if (!request_buffer)
		return -ENOMEM;

	memset(request_buffer, 0, len);
	eth_copy(request_buffer->ethhdr.h_source, pling_config.ifaddr);
	request_buffer->ethhdr.h_proto = htons(LLCMP_ETHER_TYPE);

	request_buffer->payload_len = htons(pling_config.size);
	request_buffer->type = LLCMP_ECHO_REQUEST;
	request_buffer->identifier = identifier;

	if (eth_is_zero(pling_config.replyto))
		eth_copy(request_buffer->replyto, pling_config.ifaddr);
	else
		eth_copy(request_buffer->replyto, pling_config.replyto);

	return 0;
}

static int init_pling(int argc, char *argv[])
{
	int ret;

	INIT_LIST_HEAD(&pling_config.hosts);

	ret = init_args(argc, argv);
	if (ret < 0)
		return -EINVAL;

	epoll_fd = epoll_create1(0);
	if (epoll_fd < 0) {
		fprintf(stderr, "Can't create epoll file descriptor.\n");
		return -EPERM;
	}

	ret = init_socket();
	if (ret < 0)
		goto err1;

	if (signal(SIGINT, sigint_handler) == SIG_ERR) {
		fprintf(stderr, "Can't establish SIGINT handler.\n");
		ret = -EPERM;
		goto err2;
	}

	if (!pling_config.listen) {
		ret = init_request_buffer();
		if (ret < 0) {
			fprintf(stderr,
				"Can't allocate request buffer: %s\n",
				(ret == -EBUSY) ?
					"no entropy" : "out-of-memory");
			goto err2;
		}
	}

	return 0;

err2:
	close(sd);
err1:
	close(epoll_fd);

	return ret;
}

static int send_packet(struct pling_header *plhdr)
{
	struct sockaddr_ll addr;
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.sll_ifindex = pling_config.ifindex;

	ret = sendto(sd, plhdr, sizeof(*plhdr) + ntohs(plhdr->payload_len), 0,
		     (struct sockaddr*)&addr, sizeof(addr));
	if (ret < 0) {
		fprintf(stderr, "Error: Could not send packet: %s\n", strerror(errno));
		return ret;
	}

	return 0;
}

static int send_echo_request(void)
{
	uint16_t seqno = ntohs(request_buffer->seqno) + 1;
	struct pling_host *host;
	int ret;

	request_buffer->seqno = htons(seqno);

	list_for_each_entry(host, &pling_config.hosts, node) {
		eth_copy(request_buffer->ethhdr.h_dest, host->host);

		ret = send_packet(request_buffer);
		if (ret < 0)
			return ret;
	}

	rtcidx = (rtcidx + 1) % REQUEST_TIME_CACHE_SIZE;
	clock_gettime(CLOCK_MONOTONIC, &request_time_cache[rtcidx]);

	return 0;
}

static void print_echo_request(struct pling_header *plhdr)
{
	char src[ETH_STRLEN+1];
	char dst[ETH_STRLEN+1];
	char replyto[ETH_STRLEN+1];
	char type[64];
	unsigned int paylen, pktlen;

	paylen = ntohs(plhdr->payload_len);
	pktlen = sizeof(*plhdr) - sizeof(plhdr->ethhdr) + paylen;

	eth_bin2str(plhdr->ethhdr.h_source, src);
	eth_bin2str(plhdr->ethhdr.h_dest, dst);
	eth_bin2str(plhdr->replyto, replyto);

	if (plhdr->type == LLCMP_ECHO_REQUEST)
		snprintf(type, sizeof(type), "echo request");
	else if (plhdr->type == LLCMP_ECHO_REPLY)
		snprintf(type, sizeof(type), "echo reply");
	else
		snprintf(type, sizeof(type), "unknown");

	printf("%s > %s, LLCMP, %s, reply-to %s, id 0x%04x, seq %u, length %u(%u)\n",
		src, dst, type, replyto, ntohs(plhdr->identifier),
		ntohs(plhdr->seqno), paylen, pktlen);
}

static int recv_echo_request(struct pling_header *plhdr)
{
	print_echo_request(plhdr);

	plhdr->type = LLCMP_ECHO_REPLY;
	eth_copy(plhdr->ethhdr.h_dest, plhdr->replyto);
	eth_copy(plhdr->ethhdr.h_source, pling_config.ifaddr);
	eth_copy(plhdr->replyto, pling_config.ifaddr);

	return send_packet(plhdr);
}

static int check_seqno_range(const uint16_t recv_seqno)
{
	uint16_t send_seqno = ntohs(request_buffer->seqno);
	uint16_t last_seqno = 1;

	if (send_seqno > REQUEST_TIME_CACHE_SIZE)
		last_seqno = send_seqno - REQUEST_TIME_CACHE_SIZE + 1;

	/* no seqno wrap-around supported yet */
	if (send_seqno > recv_seqno ||
	    recv_seqno < last_seqno)
		return -ERANGE;

	return 0;
}

static int echo_reply_timediffus_get(unsigned long *timediff,
				     const uint16_t seqno)
{
	struct timespec now;
	int ret, idx;
	int64_t diff;

	ret = check_seqno_range(seqno);
	if (ret < 0)
		return ret;

	idx = (seqno - 1) % REQUEST_TIME_CACHE_SIZE;
	clock_gettime(CLOCK_MONOTONIC, &now);
	diff = timespec_diffus(request_time_cache[idx], now);
	diff = diff < 0 ? 0 : diff;

	if (diff > ULONG_MAX)
		return -ERANGE;

	*timediff = (unsigned long)diff;
	return 0;
}

static int recv_echo_reply(struct pling_header *plhdr)
{
	char src[ETH_STRLEN+1];
	char replyto[ETH_STRLEN+1];
	unsigned int paylen, pktlen;
	unsigned long timediff_us;

	request_reply_count++;

	paylen = ntohs(plhdr->payload_len);
	pktlen = sizeof(*plhdr) - sizeof(plhdr->ethhdr) + paylen;

	eth_bin2str(plhdr->ethhdr.h_source, src);
	eth_bin2str(plhdr->replyto, replyto);

	if (echo_reply_timediffus_get(&timediff_us, ntohs(plhdr->seqno)) < 0)
		printf("%u(%u) bytes from %s (via %s): pling_seq=%u\n",
		       paylen, pktlen, replyto, src, ntohs(plhdr->seqno));
	else
		printf("%u(%u) bytes from %s (via %s): pling_seq=%u time=%lu.%03lu ms\n",
		       paylen, pktlen, replyto, src, ntohs(plhdr->seqno),
		       timediff_us / 1000, timediff_us % 1000);

	return 0;
}

static int recv_check_header(struct pling_header *plhdr, int len)
{
	if (len < sizeof(*plhdr)) {
		fprintf(stderr,
			"Warning: received malformed packet: too short (%i < %zu bytes)\n",
			len, sizeof(*plhdr));
		return -EINVAL;
	}

	if (ntohs(plhdr->payload_len) > len - sizeof(*plhdr)) {
		fprintf(stderr,
			"Warning: received malformed packet: payload_len too large (%i > %zu bytes)\n",
			ntohs(plhdr->payload_len), (size_t)len - sizeof(*plhdr));
		return -EINVAL;
	}

	if (ntohs(plhdr->ethhdr.h_proto) != LLCMP_ETHER_TYPE) {
		fprintf(stderr,
			"Warning: received malformed packet: invalid ether type (0x%04x, expected 0x%04x)\n",
			ntohs(plhdr->ethhdr.h_proto), LLCMP_ETHER_TYPE);
		return -EINVAL;
	}

	/* source check: ignore own frames */
	if (eth_is_own(plhdr->ethhdr.h_source))
		return -EADDRNOTAVAIL;

	/* destination check: only accept multicast and for own address */
	if (!eth_is_own(plhdr->ethhdr.h_dest) &&
	    !eth_is_multicast(plhdr->ethhdr.h_dest))
		return -EADDRNOTAVAIL;

	return 0;
}

static int recv_packet(int sd)
{
	unsigned char buffer[BUFSIZ];
	struct pling_header *plhdr = (struct pling_header *)buffer;
	int len, ret;

	len = recvfrom(sd, buffer, sizeof(buffer), 0, NULL, 0);
	ret = recv_check_header(plhdr, len);

	/* ignore what's not for us */
	if (ret == -EADDRNOTAVAIL)
		return 0;
	/* malformed packet */
	else if (ret < 0)
		return ret;

	switch (plhdr->type) {
	case LLCMP_ECHO_REQUEST:
		/* only for listeners */
		if (!pling_config.listen)
			return 0;

		ret = recv_echo_request(plhdr);
		break;
	case LLCMP_ECHO_REPLY:
		/* only for requesters */
		if (pling_config.listen)
			return 0;

		/* ignore echo replies which are not from our session */
		if (plhdr->identifier != request_buffer->identifier)
			return 0;

		ret = recv_echo_reply(plhdr);
		break;
	default:
		fprintf(stderr,
			"Warning: unknown pling type: %u\n", plhdr->type);
		return -EINVAL;
	}

	return ret;
}

static int get_next_timeout()
{
	struct timespec now, add, next;
	int64_t diff;

	clock_gettime(CLOCK_MONOTONIC, &now);

	add.tv_sec = pling_config.interval / 1000;
	add.tv_nsec = (pling_config.interval % 1000) * (1000*1000);
	next = timespec_sum(request_time_cache[rtcidx], add);

	diff = timespec_diffus(now, next) / 1000;
	if (diff < 0)
		return 0;

	return (diff > INT_MAX) ? INT_MAX : (int)diff;
}

int main(int argc, char *argv[])
{
	int ret, timeout, ev_count = 0;
	unsigned long count;

	ret = init_pling(argc, argv);
	if (ret < 0) {
		config_free_hosts();
		exit(2);
	}

	count = pling_config.count;
	timeout = pling_config.interval ? pling_config.interval : - 1;

	while(!term) {
		if (!pling_config.listen) {
			if (!ev_count) {
				if (count &&
				    count <= ntohs(request_buffer->seqno))
					break;

				send_echo_request();
			}

			timeout = get_next_timeout();
		}

		ev_count = epoll_wait(epoll_fd, events, MAX_EVENTS,
				      timeout);

		for(int i = 0; i < ev_count; i++)
			recv_packet(events[i].data.fd);
	}

	close(epoll_fd);
	config_free_hosts();

	if (request_buffer)
		free(request_buffer);

	if (!pling_config.listen &&
	    request_reply_count == 0)
		exit(1);

	return 0;
}

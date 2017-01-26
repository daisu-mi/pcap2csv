/*
 * Copyright (c) 2017 Daisuke Miyamoto. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *							notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *							notice, this list of conditions and the following disclaimer in the
 *							documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.			IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>

#include <pcap.h>

#include "p2c_ether.h"
#include "p2c_ip.h"
#include "p2c_ip6.h"
#include "p2c_ipproto.h"
#include "p2c_icmp.h"
#include "p2c_icmp6.h"
#include "p2c_tcp.h"
#include "p2c_udp.h"

#include "p2c.h"


static char *progname;
static int debug = P2C_FALSE;

/* for IPv6 */
int use6 = P2C_FALSE;

/* for Counter */
long counter = 0;

int main (int argc, char *argv[]) {
	char *dumpfile = NULL;
	char *device = NULL;
	char *filter = NULL;
	int op;

	progname = argv[0];

	/* getopt */
#ifdef USE_INET6
	while ((op = getopt (argc, argv, "i:r:R:6dh?")) != -1)
#else
	while ((op = getopt (argc, argv, "i:r:R:dh?")) != -1)
#endif
		{

		switch (op) {
			case 'd':		/* show debug */
				debug = P2C_TRUE;
				break;

#ifdef USE_INET6
			case '6':		/* use inet6 */
				use6 = P2C_TRUE;
				break;
#endif

			case 'i':		/* interface specified */
				device = optarg;
				break;

			case 'r':		/* read local files */
				dumpfile = optarg;
				break;

			case 'h':
			case '?':		/* usage */
				p2c_usage ();
				break;
			}
		}

	if (argv[optind] != NULL) {
			filter = argv[optind];
	}

	p2c_pcap (dumpfile, device, filter);

	exit (EXIT_SUCCESS);
}

void p2c_pcap (char *dumpfile, char *device, char *filter) {
	pcap_t *pd;											/* pcap descriptor */
	char errbuf[PCAP_ERRBUF_SIZE];	/* errbuf for pcap */
	uint32_t localnet, netmask;			/* network for interface */
	pcap_handler callback;					/* pcap callback function */
	int datalink;										/* pcap datalink */

	/* pcap filter */
	struct bpf_program fcode;	/* compiled pcap filter */

	if (dumpfile != NULL) {
		/* pcap offline mode : read dump file */
		if ((pd = pcap_open_offline (dumpfile, errbuf)) == NULL) {
			fprintf (stderr, "pcap_open_offline: %s\n", errbuf);
			exit (EXIT_FAILURE);
		}
		localnet = 0;
		netmask = 0;
	}
	else {
		if (device == NULL) {
			if ((device = pcap_lookupdev (errbuf)) == NULL) {
				fprintf (stderr, "pcap_lookup: %s", errbuf);
				exit (EXIT_FAILURE);
			}
		}
		if (debug == P2C_TRUE) {
			printf ("device = %s\n", device);
		}

		/* open pcap with promisc mode */
		if ((pd = pcap_open_live (device, P2C_SNAPLEN, 1, 500, errbuf)) == NULL) {
			fprintf (stderr, "pcap_open_live: %s\n", errbuf);
			exit (EXIT_FAILURE);
		}
		/* get netmask */
		if (pcap_lookupnet (device, &localnet, &netmask, errbuf) < 0) {
			fprintf (stderr, "pcap_lookupnet: %s\n", errbuf);
		}
	}

	if (pcap_compile (pd, &fcode, filter, 0, netmask) < 0) {
		fprintf (stderr, "pcap_compile: %s\n", pcap_geterr (pd));
		exit (EXIT_FAILURE);
	}	

	/* set filter */
	if (pcap_setfilter (pd, &fcode) < 0) {
		fprintf (stderr, "pcap_setfilter: %s\n", pcap_geterr (pd));
		exit (EXIT_FAILURE);
	}

	/* get datalink type */
	if ((datalink = pcap_datalink (pd)) < 0) {
		fprintf (stderr, "pcap_datalink: %s\n", pcap_geterr (pd));
		exit (EXIT_FAILURE);
	}

	/* select callback function */
	switch (datalink) {
		case DLT_NULL:
			if (debug == P2C_TRUE) {
				printf ("linktype = LoopBack\n");
			}
			callback = p2c_lback;
			break;

		case DLT_EN10MB:
			if (debug == P2C_TRUE) {
				printf ("linktype = Ethernet\n");
			}
			callback = p2c_ether;
			break;

		default:
			fprintf (stderr, "linktype = Unknown\n");
			exit (EXIT_FAILURE);
		}

	/* Loop -> pcap read packets and excute callback funcation */
	if (pcap_loop (pd, -1, callback, NULL) < 0) {
		fprintf (stderr, "pcap_loop: %s\n", pcap_geterr (pd));
		exit (EXIT_FAILURE);
	}
	pcap_close (pd);

	return;
}

void p2c_usage (void) {
	printf ("usage: %s \n", progname);
	printf ("			-i [ Monitor device ] (optional)\n");
	printf ("			-r [ Pcap dump file ] (optional)\n");
	printf ("			-d ( Show debug information: optional)\n");
	printf ("			[ pcap filter expression ] (optional)\n");
	printf ("			(if -u specified, then [ UNIX domain socket path ]) \n");
	printf ("\n");
	printf (" ex) %s -i eth0 \"port not 22\"\n", progname);
	printf ("\n");

	exit (EXIT_SUCCESS);
}

/* process Loop Back */
void p2c_lback (u_char * userdata, const struct pcap_pkthdr *h, const u_char * p) {

	counter += 1;

	/* paranoia NULL check */
	if (userdata == NULL || h == NULL || p == NULL)
		return;
	/* if capture size is too short */
	if (h->caplen < NULL_HDRLEN)
		return;
	else
		p2c_ip ((u_char *) (p + NULL_HDRLEN), (u_int) (h->len - NULL_HDRLEN), h);
	return;
}

/* process IEEE 802.3 Ethernet */
void p2c_ether (u_char * userdata, const struct pcap_pkthdr *h, const u_char * p) {
	struct ether_header *ep;
	u_int ether_type;
	int skiplen = ETHER_HDRLEN;

	counter += 1;

	/* if capture size is too short */
	if (h->caplen < ETHER_HDRLEN)
		return;
	else
		ep = (struct ether_header *) p;

	ether_type = ntohs (ep->ether_type);

	if (ether_type == ETHERTYPE_8021Q) {
		ep = (struct ether_header *) (p + 4);
		ether_type = ntohs (ep->ether_type);
		skiplen += 4;
	}

	switch (ether_type) {
		case ETHERTYPE_IP:
			p2c_ip ((u_char *) (p + skiplen), (u_int) (h->len - skiplen), h);
			break;

		case ETHERTYPE_IPV6:
			p2c_ip6 ((u_char *) (p + skiplen), (u_int) (h->len - skiplen), h);
			break;

		default:
			break;
	}
	/* after p2c_ip() ends */
	return;
}

/* process ip header */
void p2c_ip (u_char * p, u_int len, const struct pcap_pkthdr *h) {
	struct ip *ip;
	char srcip[P2C_BUFSIZ];
	char dstip[P2C_BUFSIZ];
	u_short ip_id;
	char mesgbuf[P2C_BUFSIZ];
	u_char *packet;

	/* if ip is too short */
	if (len < sizeof (struct ip)) {
		return;
	}
	else {
		ip = (struct ip *) p;
	}

	/* if not ipv4 or not tcp or udp */
	if (ip->ip_v != IPVERSION) {
		return;
	}

	memset ((void *) &srcip, '\0', P2C_BUFSIZ);
	memset ((void *) &dstip, '\0', P2C_BUFSIZ);

	inet_ntop (AF_INET, (void *) (&ip->ip_src), srcip, P2C_BUFSIZ);
	inet_ntop (AF_INET, (void *) (&ip->ip_dst), dstip, P2C_BUFSIZ);
	ip_id = ip->ip_id;

	switch (ip->ip_p) {
		case IPPROTO_TCP:
			p2c_tcp ((u_char *) (p + ip->ip_hl * 4), (u_int) (len - ip->ip_hl * 4),
				 srcip, dstip, ip_id, mesgbuf, h);
			break;

		case IPPROTO_UDP:
			p2c_udp ((u_char *) (p + ip->ip_hl * 4), (u_int) (len - ip->ip_hl * 4),
				 srcip, dstip, ip_id, mesgbuf, h);
			break;

		case IPPROTO_ICMP:
			p2c_icmp ((u_char *) (p + ip->ip_hl * 4), (u_int) (len - ip->ip_hl * 4),
		srcip, dstip, ip_id, mesgbuf, h);
			break;

		default:
			return;
	}
	return;
}

/* process ipv6 header */
void p2c_ip6 (u_char * p, u_int len, const struct pcap_pkthdr *h) {
	struct ip6_hdr *ip6;
	char srcip[P2C_BUFSIZ];
	char dstip[P2C_BUFSIZ];
	char mesgbuf[P2C_BUFSIZ];
	u_char *packet;

	if (len < sizeof (struct ip6_hdr)) {
		return;
	}
	else {
		ip6 = (struct ip6_hdr *) p;
	}

	memset ((void *) &srcip, '\0', P2C_BUFSIZ);
	memset ((void *) &dstip, '\0', P2C_BUFSIZ);
	inet_ntop (AF_INET6, (void *) (&ip6->ip6_src), srcip, P2C_BUFSIZ);
	inet_ntop (AF_INET6, (void *) (&ip6->ip6_dst), dstip, P2C_BUFSIZ);

	switch (ip6->ip6_nxt) {
		case IPPROTO_TCP:
			p2c_tcp ((u_char *) (p + ntohs (ip6->ip6_plen)),
				 (u_int) (len - ntohs (ip6->ip6_plen)),
				 srcip, dstip, 0, mesgbuf, h);
			break;

		case IPPROTO_UDP:
			p2c_udp ((u_char *) (p + ntohs (ip6->ip6_plen)),
				 (u_int) (len - ntohs (ip6->ip6_plen)),
				 srcip, dstip, 0, mesgbuf, h);
			break;

		case IPPROTO_ICMPV6:
			p2c_icmp6 ((u_char *) (p + ntohs (ip6->ip6_plen)),
		 (u_int) (len - ntohs (ip6->ip6_plen)),
		 srcip, dstip, 0, mesgbuf, h);
			break;

		default:
			return;
	}
}


/* process tcp header */
void p2c_tcp (u_char * p, u_int len, char *srcip, char *dstip, u_short ip_id, char *mesgbuf, const struct pcap_pkthdr *h) {
	struct tcphdr *th;

	if (len < TCP_HDRLEN) {
		return;
	}
	else {
		th = (struct tcphdr *) p;
	}

	printf("%ld,%ld,%lu,%s,%s,%d,%d,%d\n",
		h->ts.tv_sec, h->ts.tv_usec, counter,
		srcip, dstip, ntohs (th->th_sport), ntohs (th->th_dport), IPPROTO_TCP);
	return;
}

/* process udp header */
void p2c_udp (u_char * p, u_int len, char *srcip, char *dstip, u_short ip_id, char *mesgbuf, const struct pcap_pkthdr *h) {
	struct udphdr *uh;

	if (len < UDP_HDRLEN) {
		return;
	}
	else {
		uh = (struct udphdr *) p;
	}

	printf("%ld,%ld,%lu,%s,%s,%d,%d,%d\n",
		h->ts.tv_sec, h->ts.tv_usec, counter,
		srcip, dstip, ntohs (uh->uh_sport), ntohs (uh->uh_dport), IPPROTO_UDP);
	return;
}

/* process icmp header */
void p2c_icmp (u_char * p, u_int len, char *srcip, char *dstip, u_short ip_id, char *mesgbuf, const struct pcap_pkthdr *h) {
	struct icmphdr *ih;

	if (len < ICMP_MIN_HDRLEN) {
		return;
	}
	else {
		ih = (struct icmphdr *) p;
	}

	printf("%ld,%ld,%lu,%s,%s,%d,%d,%d\n",
		h->ts.tv_sec, h->ts.tv_usec, counter,
		srcip, dstip,  (int)(ih->icmp_type), (int)(ih->icmp_code), IPPROTO_ICMP);
	return;
}

/* process icmp6 header */
void p2c_icmp6 (u_char * p, u_int len, char *srcip, char *dstip, u_short ip_id, char *mesgbuf, const struct pcap_pkthdr *h) {
	struct icmp6hdr *ih6;

	/* ikutu dakke ...*/
	if (len < ICMP_MIN_HDRLEN) {
		return;
	}
	else {
		ih6 = (struct icmp6hdr *) p;
	}

	printf("%ld,%ld,%lu,%s,%s,%d,%d,%d\n",
		h->ts.tv_sec, h->ts.tv_usec, counter,
		srcip, dstip,  (int)(ih6->icmp6_type), (int)(ih6->icmp6_code), IPPROTO_ICMP);
	return;
}


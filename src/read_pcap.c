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

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include "p2c_ether.h"
#include "p2c_ip.h"
#include "p2c_ip6.h"
#include "p2c_ipproto.h"
#include "p2c_icmp.h"
#include "p2c_icmp6.h"
#include "p2c_tcp.h"
#include "p2c_udp.h"

#include "p2c.h"
#include "aslookup.h"
#include "patricia.h"

static char *progname;
static int debug = P2C_FALSE;

patricia_tree_t *cf_tree;

/* for IPv6 */
int use6 = P2C_FALSE;

/* word2vec */
int word2vec = P2C_FALSE;
int word2vec_flag = P2C_FALSE;
int word2vec256 = P2C_FALSE;
int word2vec256_flag = P2C_FALSE;
int word2vecmax = 0;

/* aslookup */
int aslookup = P2C_FALSE;

/* counter */
uint32_t counter = 0;
uint32_t counter_limit = 0;

int main (int argc, char *argv[]) {
	char *dumpfile = NULL;
	char *device = NULL;
	char *filter = NULL;
	char configfile[P2C_BUFSIZ];
	int op;
	int counter_tmp = 0;

	progname = argv[0];

	setvbuf(stdout, 0, _IONBF, 0);

	if ((cf_tree = New_Patricia(PATRICIA_MAXBITS)) == NULL){
		fprintf(stderr, "fatal error in creating patricia trie\n");
		exit(EXIT_FAILURE);
	}

	/* getopt */
#ifdef USE_INET6
	while ((op = getopt (argc, argv, "c:i:r:l:x:X:6dh?")) != -1)
#else
	while ((op = getopt (argc, argv, "c:i:r:l:x:X:dh?")) != -1)
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

			case 'l':		/* aslookup */
				if (optarg == NULL){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				strncpy(configfile, optarg, P2C_BUFSIZ);
				if (p2c_aslookup_config_load(cf_tree, configfile) != P2C_TRUE){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				if (cf_tree == NULL){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				aslookup = P2C_TRUE;
        break;

			case 'c':		/* capture count */
				if (optarg == NULL){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				counter_tmp = (int)strtol(optarg, (char **)NULL, 10);
				if (counter_tmp <= 0){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				else {
					counter_limit = (uint32_t)counter_tmp;
				}
				break;

			case 'X':   /* word2vec256 (-> make 65536 matrix) */
				if (optarg == NULL){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				else if (word2vec == P2C_TRUE){
					p2c_usage();
					exit(EXIT_FAILURE);
				}	
				word2vec256_flag = (int)strtol(optarg, (char **)NULL, 10);
				if (word2vec256_flag < 0){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				word2vec256 = P2C_TRUE;
				word2vecmax = 256;
				break;

			case 'x':   /* word2vec (-> make 256 matrix : default) */
				if (optarg == NULL){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				else if (word2vec256 == P2C_TRUE){
					p2c_usage();
					exit(EXIT_FAILURE);
				}	
				word2vec_flag = (int)strtol(optarg, (char **)NULL, 10);
				if (word2vec_flag < 0){
					p2c_usage();
					exit(EXIT_FAILURE);
				}
				word2vec = P2C_TRUE;
				word2vecmax = 16;
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
	printf ("			-l [ Routeview file for aslookup ] (optional)\n");
	printf ("			-d ( Show debug information: optional)\n");
	printf ("			-x [ Make Word2vec: 3 is L3, 4 is L4, 7 is L7, 0 is All ]\n");
	printf ("			[ pcap filter expression ] (optional)\n");
	printf ("\n");
	printf (" ex) %s -i eth0 \"port not 22\"\n", progname);
	printf ("\n");

	exit (EXIT_SUCCESS);
}

/* process Loop Back */
void p2c_lback (u_char * userdata, const struct pcap_pkthdr *h, const u_char * p) {
	struct pcap_csv *pc;

	if ((pc = (struct pcap_csv *)malloc(sizeof(struct pcap_csv))) == NULL){
		fprintf(stderr, "malloc failed\n");
		exit(EXIT_FAILURE);
	}
	else {
		memset ((void *) pc, '\0', sizeof(struct pcap_csv));
	}

	counter += 1;
	if (counter_limit > 0 && counter > counter_limit){
		exit(EXIT_SUCCESS);
	}
	pc->counter = counter;

	do {
		/* paranoia NULL check */
		if (userdata == NULL || h == NULL || p == NULL){
			break;
		}

		/* if capture size is too short */
		if (h->caplen < NULL_HDRLEN) {
			break;
		}
		else {
			p2c_ip ((u_char *) (p + NULL_HDRLEN), (u_int) (h->caplen - NULL_HDRLEN), h, pc);
		}
	} while(0);

	free(pc);

	return;
}

/* process IEEE 802.3 Ethernet */
void p2c_ether (u_char * userdata, const struct pcap_pkthdr *h, const u_char * p) {
	struct pcap_csv *pc;
	struct ether_header *ep;
	u_int ether_type;
	u_int skiplen = ETHER_HDRLEN;

	if ((pc = (struct pcap_csv *)malloc(sizeof(struct pcap_csv))) == NULL){
		fprintf(stderr, "malloc failed\n");
		exit(EXIT_FAILURE);
	}
	else {
		memset ((void *) pc, '\0', sizeof(struct pcap_csv));
	}

	counter += 1;
	if (counter_limit > 0 && counter > counter_limit){
		exit(EXIT_SUCCESS);
	}
	pc->counter = counter;

	do {
		/* if capture size is too short */
		if (h->caplen < ETHER_HDRLEN){
			break;
		}

		ep = (struct ether_header *) p;
		ether_type = ntohs (ep->ether_type);

		if (ether_type == ETHERTYPE_8021Q) {
			ep = (struct ether_header *) (p + 4);
			ether_type = ntohs (ep->ether_type);
			skiplen += 4;
		}

		switch (ether_type) {
			case ETHERTYPE_IP:
				p2c_ip ((u_char *) (p + skiplen), (u_int) (h->caplen - skiplen), h, pc);
				break;

			case ETHERTYPE_IPV6:
				p2c_ip6 ((u_char *) (p + skiplen), (u_int) (h->caplen - skiplen), h, pc);
				break;

			default:
				break;
		}
	} while(0);

	/* after p2c_ip() ends */

	free(pc);
	return;
}

/* process ip header */
void p2c_ip (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	struct ip *ip;

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

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, (u_int)ip->ip_hl * 4, P2C_WORD2VEC_L3, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, (u_int)ip->ip_hl * 4, P2C_WORD2VEC_L3, pc);
	}

	memset ((void *) pc->srcip, '\0', P2C_BUFSIZ);
	memset ((void *) pc->dstip, '\0', P2C_BUFSIZ);
	inet_ntop (AF_INET, (void *) (&ip->ip_src), pc->srcip, P2C_BUFSIZ);
	inet_ntop (AF_INET, (void *) (&ip->ip_dst), pc->dstip, P2C_BUFSIZ);
	pc->ttl = (int)ip->ip_ttl;

	if (aslookup == P2C_TRUE){
		if (p2c_aslookup_lookup(cf_tree, pc->srcip, pc->srcasn) != P2C_TRUE){
			strcpy(pc->srcasn, "0");
		}
		if (p2c_aslookup_lookup(cf_tree, pc->dstip, pc->dstasn) != P2C_TRUE){
			strcpy(pc->dstasn, "0");
		}
	}

	switch (ip->ip_p) {
		case IPPROTO_TCP:
			p2c_tcp ((u_char *) (p + ip->ip_hl * 4), (u_int) (len - ip->ip_hl * 4), h, pc);
			break;

		case IPPROTO_UDP:
			p2c_udp ((u_char *) (p + ip->ip_hl * 4), (u_int) (len - ip->ip_hl * 4), h, pc);
			break;

		case IPPROTO_ICMP:
			p2c_icmp ((u_char *) (p + ip->ip_hl * 4), (u_int) (len - ip->ip_hl * 4), h, pc);
			break;

		default:
			break;
	}
	return;
}

/* process ipv6 header */
void p2c_ip6 (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	struct ip6_hdr *ip6;

	if (len < IP6_HDRLEN) {
		return;
	}
	else {
		ip6 = (struct ip6_hdr *) p;
	}

	memset ((void *) pc->srcip, '\0', P2C_BUFSIZ);
	memset ((void *) pc->dstip, '\0', P2C_BUFSIZ);
	inet_ntop (AF_INET6, (void *) (&ip6->ip6_src), pc->srcip, P2C_BUFSIZ);
	inet_ntop (AF_INET6, (void *) (&ip6->ip6_dst), pc->dstip, P2C_BUFSIZ);
	pc->ttl = (int)ip6->ip6_hops;

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, (u_int)(sizeof(struct ip6_hdr)), P2C_WORD2VEC_L3, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, (u_int)(sizeof(struct ip6_hdr)), P2C_WORD2VEC_L3, pc);
	}

	if (aslookup == P2C_TRUE){
		if (p2c_aslookup_lookup(cf_tree, pc->srcip, pc->srcasn) != P2C_TRUE){
			strcpy(pc->srcasn, "0");
		}
		if (p2c_aslookup_lookup(cf_tree, pc->dstip, pc->dstasn) != P2C_TRUE){
			strcpy(pc->dstasn, "0");
		}
	}

	switch (ip6->ip6_nxt) {
		case IPPROTO_TCP:
			p2c_tcp ((u_char *) (p + IP6_HDRLEN), (u_int) (len - IP6_HDRLEN), h, pc);
			break;

		case IPPROTO_UDP:
			p2c_udp ((u_char *) (p + IP6_HDRLEN), (u_int) (len - IP6_HDRLEN), h, pc);
			break;

		case IPPROTO_ICMPV6:
			p2c_icmp6 ((u_char *) (p + IP6_HDRLEN), (u_int) (len - IP6_HDRLEN), h, pc);
			break;

		default:
			break;
	}
	return;
}


/* process tcp header */
void p2c_tcp (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	struct tcphdr *th;
	u_int tcplength = 0;

	if (len < TCP_HDRLEN) {
		return;
	}
	else {
		th = (struct tcphdr *) p;
	}

	tcplength = (u_int)(TH_OFF(th) * 4);

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, tcplength, P2C_WORD2VEC_L4, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, tcplength, P2C_WORD2VEC_L4, pc);
	}

	pc->proto = IPPROTO_TCP;
	pc->sport = ntohs(th->th_sport);
	pc->dport = ntohs(th->th_dport);

	if (len <= tcplength){
		p2c_data((u_char *)p, (u_int)0, h, pc);
	}
	else {
		p2c_data((u_char *)(p + tcplength), (u_int)(len - tcplength), h, pc);
	}
	return;
}

/* process udp header */
void p2c_udp (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	struct udphdr *uh;

	if (len < UDP_HDRLEN) {
		return;
	}
	else {
		uh = (struct udphdr *) p;
	}

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, (u_int)UDP_HDRLEN, P2C_WORD2VEC_L4, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, (u_int)UDP_HDRLEN, P2C_WORD2VEC_L4, pc);
	}

	pc->proto = IPPROTO_UDP;
	pc->sport = ntohs(uh->uh_sport);
	pc->dport = ntohs(uh->uh_dport);

	p2c_data((u_char *)(p + UDP_HDRLEN), (u_int)(len - UDP_HDRLEN), h, pc);
	return;
}

/* process icmp header */
void p2c_icmp (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	struct icmphdr *ih;

	if (len < ICMP_MIN_HDRLEN) {
		return;
	}
	else {
		ih = (struct icmphdr *) p;
	}

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, (u_int)ICMP_MIN_HDRLEN, P2C_WORD2VEC_L4, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, (u_int)ICMP_MIN_HDRLEN, P2C_WORD2VEC_L4, pc);
	}

	pc->proto = IPPROTO_ICMP;
	pc->sport = (short)(ih->icmp_type);
	pc->dport = (short)(ih->icmp_code);

	p2c_data((u_char *)(p + ICMP_MIN_HDRLEN), (u_int)(len - ICMP_MIN_HDRLEN), h, pc);
	return;
}

/* process icmp6 header */
void p2c_icmp6 (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	struct icmp6hdr *ih6;

	/* ikutu dakke ...*/
	if (len < ICMP_MIN_HDRLEN) {
		return;
	}
	else {
		ih6 = (struct icmp6hdr *) p;
	}

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, (u_int)ICMPV6_MIN_HDRLEN, P2C_WORD2VEC_L4, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, (u_int)ICMPV6_MIN_HDRLEN, P2C_WORD2VEC_L4, pc);
	}

	pc->proto = IPPROTO_ICMPV6;
	pc->sport = (short)(ih6->icmp6_type);
	pc->dport = (short)(ih6->icmp6_code);

	p2c_data((u_char *)(p + ICMPV6_MIN_HDRLEN), (u_int)(len - ICMPV6_MIN_HDRLEN), h, pc);
	return;
}

void p2c_data (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	int i = 0, j = 0;
	int max = word2vecmax;

	if (word2vec == P2C_TRUE){
		p2c_word2vec4(p, (u_int)len, P2C_WORD2VEC_L7, pc);
	}
	else if (word2vec256 == P2C_TRUE){
		p2c_word2vec8(p, (u_int)len, P2C_WORD2VEC_L7, pc);
	}

	printf("%ld,%ld,%lu,%s,%s,%s,%s,%d,%d,%d",
		h->ts.tv_sec, h->ts.tv_usec,
		(long)pc->counter,
		pc->srcip, pc->dstip, pc->srcasn, pc->dstasn,
		(int)(pc->sport), (int)(pc->dport), (int)(pc->proto));


	if (word2vec == P2C_TRUE){
		for (i = 0; i < max; i++){
			for (j = 0; j < max; j++){
				switch(word2vec_flag){
					case P2C_WORD2VEC_L3:
						printf(",%d", pc->vec_l3[i][j]);
						break;

					case P2C_WORD2VEC_L4:
						printf(",%d", pc->vec_l4[i][j]);
						break;

					case P2C_WORD2VEC_L7:
						printf(",%d", pc->vec_l7[i][j]);
						break;

					case P2C_WORD2VEC_LALL:
						printf(",%d", (pc->vec_l3[i][j] + pc->vec_l4[i][j] + pc->vec_l7[i][j]));
						break;

					default:
						break;
				}
			}
		}
	}

	printf("\n");	

	return;
}

void p2c_word2vec8 (u_char * p, u_int len, int layer, struct pcap_csv *pc) {
	u_int i = 0;
	u_int j = 1;
	uint8_t *first = NULL, *second = NULL;

	for (i = 0; j < len; i++){
		j = i + 1;

		if (j >= len){
			break;
		}

		first = (uint8_t *)(p + i);
		second = (uint8_t *)(p + j);

		/*
		printf("%d,%02d,%02d\n", i, *first, *second); 
		*/

		switch(layer){
			case P2C_WORD2VEC_L3:
				pc->vec_l3[*first][*second] += 1;
				break;
				
			case P2C_WORD2VEC_L4:
				pc->vec_l4[*first][*second] += 1;
				break;

			case P2C_WORD2VEC_L7:
				pc->vec_l7[*first][*second] += 1;
				break;

			default:
				break;
		}
	}
	return;
}

void p2c_word2vec4 (u_char * p, u_int len, int layer, struct pcap_csv *pc) {
	u_int i = 0;
	u_int j = 1;
	uint8_t *first8 = NULL, *second8 = NULL;
	uint8_t first4 = 0;
	uint8_t second4 = 0;
	uint8_t third4 = 0;
	uint8_t fourth4 = 0;
	uint8_t backup4 = 0;

	if ((int)len < 0){
		return;
	}

	for (i = 0; j < len; i++){
		j = i + 1;

		/*
				Given buffer is 4 5 0 0 (imagine tcpdump: IPv4, IHL = 5words, no TOS)
				then first8 is "45" and second8 is "00".
				This function will split these 8bit values as follows:
				first4  = 4
				second4 = 5
				third4  = 0
				fourth4 = 0
		*/	

		first8 = (uint8_t *)(p + i);
		second8 = (uint8_t *)(p + j);

		first4 =  ((*first8 & 0xf0) >> 4);
		second4 = (*first8 & 0x0f);
		third4 = ((*second8 & 0xf0) >> 4);
		fourth4 = (*second8 & 0x0f);

		/*
		printf("%d,%02d,%02d\n", i, first4, second4); 
		printf("%d,%02d,%02d\n", i, second4, third4); 
		printf("%d,%02d,%02d\n", i, third4, fourth4); 
		*/

		switch(layer){

			case P2C_WORD2VEC_L3:
				if (i == 0){
					pc->vec_l3[first4][second4] += 1;
				}
				if (j < len){
					pc->vec_l3[second4][third4] += 1;
					pc->vec_l3[third4][fourth4] += 1;
				}
/*
				if (i != 0){
					pc->vec_l3[backup4][first4] += 1;
				}
*/
				break;
				
			case P2C_WORD2VEC_L4:
				if (i == 0){
					pc->vec_l4[first4][second4] += 1;
				}
				if (j < len){
					pc->vec_l4[second4][third4] += 1;
					pc->vec_l4[third4][fourth4] += 1;
				}
/*
				if (i != 0){
					pc->vec_l4[backup4][first4] += 1;
				}
*/
				break;

			case P2C_WORD2VEC_L7:
				if (i == 0){
					pc->vec_l7[first4][second4] += 1;
				}
				if (j < len){
					pc->vec_l7[second4][third4] += 1;
					pc->vec_l7[third4][fourth4] += 1;
				}
/*
				if (i != 0){
					pc->vec_l7[backup4][first4] += 1;
				}
*/
				break;

			default:
				break;
		}
		backup4 = fourth4;
	}
	return;
}

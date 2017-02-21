/*
 * Copyright (c) 2017 Daisuke Miyamoto. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#ifndef __P2C_H__
#define __P2C_H__

#ifndef P2C_SNAPLEN
#define P2C_SNAPLEN	128
#endif

#ifndef P2C_BUFSIZ
#define P2C_BUFSIZ	1024
#endif

#ifndef P2C_TRUE
#define P2C_TRUE		1
#endif

#ifndef P2C_FALSE
#define P2C_FALSE		-1
#endif

#ifndef P2C_WORD2VEC_L3
#define P2C_WORD2VEC_L3  3
#endif

#ifndef P2C_WORD2VEC_L4
#define P2C_WORD2VEC_L4  4
#endif

#ifndef P2C_WORD2VEC_L7
#define P2C_WORD2VEC_L7  7
#endif

#ifndef P2C_WORD2VEC_LALL
#define P2C_WORD2VEC_LALL	0  
#endif

#ifndef NULL_HDRLEN
#define NULL_HDRLEN	4
#endif

#ifndef ETHER_HDRLEN
#define ETHER_HDRLEN    14
#endif

#ifndef IP_HDRLEN
#define IP_HDRLEN				20
#endif

#ifndef IP6_HDRLEN
#define IP6_HDRLEN			40
#endif

#ifndef TCP_HDRLEN
#define TCP_HDRLEN			20
#endif

#ifndef UDP_HDRLEN			
#define UDP_HDRLEN			8
#endif

#ifndef ICMP_MIN_HDRLEN	/* type 8bit, code 8bit, checksum 16bit */
#define ICMP_MIN_HDRLEN	4
#endif

#ifndef ICMPV6_MIN_HDRLEN	/* type 8bit, code 8bit, checksum 16bit */
#define ICMPV6_MIN_HDRLEN	4
#endif

#include <pcap.h>

struct pcap_csv {
	long counter;
	char srcip[P2C_BUFSIZ];
	char dstip[P2C_BUFSIZ];
	char srcasn[P2C_BUFSIZ];
	char dstasn[P2C_BUFSIZ];
	uint16_t proto;
	uint16_t sport;
	uint16_t dport;
	int vec_l3[256][256];
	int vec_l4[256][256];
	int vec_l7[256][256];
};

void p2c_init();
void p2c_pcap(char *, char *, char *);
void p2c_usage(void);
void p2c_lback(u_char *, const struct pcap_pkthdr *, const u_char *);
void p2c_ether(u_char *, const struct pcap_pkthdr *, const u_char *);
void p2c_ip(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_ip6(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_tcp(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_udp(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_icmp(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_icmp6(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_data(u_char *, u_int, const struct pcap_pkthdr *, struct pcap_csv *);
void p2c_word2vec4 (u_char *, u_int, int, struct pcap_csv *);
void p2c_word2vec8 (u_char *, u_int, int, struct pcap_csv *);

#endif


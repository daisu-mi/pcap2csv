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

#define P2C_SNAPLEN	128
#define P2C_BUFSIZ	1024

#define P2C_TRUE		1
#define P2C_FALSE		-1

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

#ifndef ICMP_MIN_HDRLEN			/* 8 bit for ICMP type, 8 bit for ICMP code */
#define ICMP_MIN_HDRLEN	2
#endif

#include <pcap.h>

void p2c_init();
void p2c_pcap(char *, char *, char *);
void p2c_usage(void);
void p2c_lback(u_char *, const struct pcap_pkthdr *, const u_char *);
void p2c_ether(u_char *, const struct pcap_pkthdr *, const u_char *);
void p2c_ip(u_char *, u_int, const struct pcap_pkthdr *);
void p2c_ip6(u_char *, u_int, const struct pcap_pkthdr *);
void p2c_tcp(u_char *, u_int, char *, char *, u_short, char *, const struct pcap_pkthdr *);
void p2c_udp(u_char *, u_int, char *, char *, u_short, char *, const struct pcap_pkthdr *);
void p2c_icmp(u_char *, u_int, char *, char *, u_short, char *, const struct pcap_pkthdr *);
void p2c_icmp6(u_char *, u_int, char *, char *, u_short, char *, const struct pcap_pkthdr *);

#endif


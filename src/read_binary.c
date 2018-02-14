/*
 * Copyright (c) 2018 Daisuke Miyamoto. All rights reserved.
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

#include "b2c.h"

static char *progname;
static int debug = B2C_FALSE;

patricia_tree_t *cf_tree;

/* for IPv6 */
int use6 = B2C_FALSE;

/* word2vec */
int word2vec = B2C_FALSE;
int word2vec256 = B2C_FALSE;

/* aslookup */
int aslookup = B2C_FALSE;

/* counter */
uint32_t counter = 0;
uint32_t counter_limit = 0;

int main (int argc, char *argv[]) {
	char *dumpfile = NULL;
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
	while ((op = getopt (argc, argv, "c:i:r:l:xX6dh?")) != -1)
#else
	while ((op = getopt (argc, argv, "c:i:r:l:xXdh?")) != -1)
#endif
		{

		switch (op) {
			case 'd':		/* show debug */
				debug = B2C_TRUE;
				break;

#ifdef USE_INET6
			case '6':		/* use inet6 */
				use6 = B2C_TRUE;
				break;
#endif

			case 'r':		/* read local files */
				dumpfile = optarg;
				break;

			case 'c':		/* capture count */
				if (optarg == NULL){
					b2c_usage();
					exit(EXIT_FAILURE);
				}
				counter_tmp = (int)strtol(optarg, (char **)NULL, 10);
				if (counter_tmp <= 0){
					b2c_usage();
					exit(EXIT_FAILURE);
				}
				else {
					counter_limit = (uint32_t)counter_tmp;
				}
				break;

			case 'X':   /* word2vec256 (-> make 65536 matrix) */
				if (optarg == NULL){
					b2c_usage();
					exit(EXIT_FAILURE);
				}
				else if (word2vec == B2C_TRUE){
					b2c_usage();
					exit(EXIT_FAILURE);
				}	
				word2vec256 = B2C_TRUE;
				break;

			case 'x':   /* word2vec (-> make 256 matrix : default) */
				if (optarg == NULL){
					b2c_usage();
					exit(EXIT_FAILURE);
				}
				else if (word2vec256 == B2C_TRUE){
					b2c_usage();
					exit(EXIT_FAILURE);
				}	
				word2vec = B2C_TRUE;
				break;

			case 'h':
			case '?':		/* usage */
				b2c_usage ();
				break;
			}
		}

	if (argv[optind] != NULL) {
			filter = argv[optind];
	}

	b2c_file (dumpfile);

	exit (EXIT_SUCCESS);
}

void b2c_pcap (char *dumpfile){
	if (dumpfile == NULL) {
		b2c_usage();
		exit(EXIT_FAILURE);
	}
	else {
		
		

		if ((pd = pcap_open_offline (dumpfile, errbuf)) == NULL) {
			fprintf (stderr, "pcap_open_offline: %s\n", errbuf);
			exit (EXIT_FAILURE);
		}
		localnet = 0;
		netmask = 0;
	}
	else {
		
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
			if (debug == B2C_TRUE) {
				printf ("linktype = LoopBack\n");
			}
			callback = b2c_lback;
			break;

		case DLT_EN10MB:
			if (debug == B2C_TRUE) {
				printf ("linktype = Ethernet\n");
			}
			callback = b2c_ether;
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

void b2c_usage (void) {
	printf ("usage: %s \n", progname);
	printf ("			-r [ Pcap dump file ] (optional)\n");
	printf ("			-d ( Show debug information: optional)\n");
	printf ("			-x [ Make Word2vec ]\n");
	printf ("\n");
	printf (" ex) %s -r tcpflowoutput\n", progname);
	printf ("\n");

	exit (EXIT_SUCCESS);
}

void b2c_data (u_char * p, u_int len, const struct pcap_pkthdr *h, struct pcap_csv *pc) {
	int i = 0, j = 0;
	int max = 16;

	if (word2vec == B2C_TRUE){
		b2c_word2vec4(p, (u_int)len, B2C_WORD2VEC_L7, pc);
	}
	else if (word2vec256 == B2C_TRUE){
		b2c_word2vec8(p, (u_int)len, B2C_WORD2VEC_L7, pc);
	}

	printf("%ld,%ld,%lu,%s,%s,%s,%s,%d,%d,%d",
		h->ts.tv_sec, h->ts.tv_usec,
		(long)pc->counter,
		pc->srcip, pc->dstip, pc->srcasn, pc->dstasn,
		(int)(pc->sport), (int)(pc->dport), (int)(pc->proto));


	if (word2vec == B2C_TRUE){
		for (i = 0; i < max; i++){
			for (j = 0; j < max; j++){
				printf(",%d", (pc->vec_l3[i][j] + pc->vec_l4[i][j] + pc->vec_l7[i][j]));
			}
		}
	}

	printf("\n");	

	return;
}

void b2c_word2vec8 (u_char * p, u_int len, int layer, struct pcap_csv *pc) {
	u_int i = 0;
	u_int j = 1;
	uint8_t *first = NULL, *second = NULL;

	for (i = 0; j < len; i++){
		j = i + 1;

		first = (uint8_t *)(p + i);
		second = (uint8_t *)(p + j);

		/*
		printf("%d,%02d,%02d\n", i, *first, *second); 
		*/

		switch(layer){
			case B2C_WORD2VEC_L3:
				pc->vec_l3[*first][*second] += 1;
				break;
				
			case B2C_WORD2VEC_L4:
				pc->vec_l4[*first][*second] += 1;
				break;

			case B2C_WORD2VEC_L7:
				pc->vec_l7[*first][*second] += 1;
				break;

			default:
				break;
		}
	}
	return;
}

void b2c_word2vec4 (u_char * p, u_int len, int layer, struct pcap_csv *pc) {
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
			case B2C_WORD2VEC_L3:
				pc->vec_l3[first4][second4] += 1;
				pc->vec_l3[second4][third4] += 1;
				pc->vec_l3[third4][fourth4] += 1;
				if (i != 0){
					pc->vec_l3[backup4][first4] += 1;
				}
				break;
				
			case B2C_WORD2VEC_L4:
				pc->vec_l4[first4][second4] += 1;
				pc->vec_l4[second4][third4] += 1;
				pc->vec_l4[third4][fourth4] += 1;
				if (i != 0){
					pc->vec_l4[backup4][first4] += 1;
				}
				break;

			case B2C_WORD2VEC_L7:
				pc->vec_l7[first4][second4] += 1;
				pc->vec_l7[second4][third4] += 1;
				pc->vec_l7[third4][fourth4] += 1;
				if (i != 0){
					pc->vec_l7[backup4][first4] += 1;
				}
				break;

			default:
				break;
		}
		backup4 = fourth4;
	}
	return;
}

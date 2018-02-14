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
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include "b2c.h"

static char *progname;
static int debug = B2C_FALSE;

/* word2vec */
int word2vec = B2C_TRUE;

int main (int argc, char *argv[]) {
	char *filename = NULL;
	int op;

	progname = argv[0];

	setvbuf(stdout, 0, _IONBF, 0);

	/* getopt */
	while ((op = getopt (argc, argv, "r:dh?")) != -1)
	{

		switch (op) {
			case 'd':		/* show debug */
				debug = B2C_TRUE;
				break;

			case 'r':		/* read local files */
				filename = optarg;
				break;

			case 'h':
			case '?':		/* usage */
				b2c_usage ();
				break;
			}
		}

	b2c_file (filename);

	exit (EXIT_SUCCESS);
}

void b2c_file (char *filename){
  struct binary_csv *bc;
	int fd;
	struct stat fs;
	u_int filesize = 0;

	if (filename == NULL) {
		b2c_usage();
		exit(EXIT_FAILURE);
	}

	if ((fd = open(filename, O_RDONLY)) < 0){
		perror("open");
		exit(EXIT_FAILURE);
	}

	if (stat(filename, &fs) < 0){
		perror("stat");
		exit(EXIT_FAILURE);
	}
	else {
		filesize = fs.st_size;
	}

  if ((bc = (struct binary_csv *)malloc(sizeof(struct binary_csv))) == NULL){
    fprintf(stderr, "malloc failed\n");
    exit(EXIT_FAILURE);
  }
  else {
    memset ((void *) bc, 0, sizeof(struct binary_csv));
  }

	/*
	printf("filesize:%d\n", filesize);
	printf("buf:%s\n", (char *)buf);
	*/

	b2c_data(fd, filesize, bc);

	close (fd);
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

void b2c_data (int fd, u_int len, struct binary_csv *bc) {
	int i = 0, j = 0;
	int max = 16;

	b2c_word2vec4(fd, (u_int)len, bc);

	for (i = 0; i < max; i++){
		for (j = 0; j < max; j++){
			printf("%d", (bc->vec[i][j])); 

			if ((max - i) > 1 || (max - j) > 1){
				printf(",");
			}
		}
	}

	printf("\n");	

	return;
}

void b2c_word2vec4 (int fd, u_int len, struct binary_csv *bc) {
	u_int i = 0;
	u_int j = 1;
	uint8_t *first8 = NULL, *second8 = NULL;
	uint8_t first4 = 0;
	uint8_t second4 = 0;
	uint8_t third4 = 0;
	uint8_t fourth4 = 0;
	u_char buf[B2C_BUFSIZ];
	u_char *p;
	u_int first = 0;
	u_int second = 1;

	if ((int)len < 0){
		return;
	}

	for (i = 0; j < len; i++){
		j = i + 1;

		if (j > len){
			break;
		}

		if (lseek(fd, i, SEEK_SET) < 0){
			perror("lseek");
			exit(EXIT_FAILURE);
		}

		if (read(fd, buf, 2) < 0){
			perror("lseek");
			exit(EXIT_FAILURE);
		}

		p = (u_char *) buf;

		/*
				Given buffer is 4 5 0 0 (imagine tcpdump: IPv4, IHL = 5words, no TOS)
				then first8 is "45" and second8 is "00".
				This function will split these 8bit values as follows:
				first4  = 4
				second4 = 5
				third4  = 0
				fourth4 = 0
		*/	

		first8 = (uint8_t *)(p + first);
		second8 = (uint8_t *)(p + second);


		first4 =  ((*first8 & 0xf0) >> 4);
		second4 = (*first8 & 0x0f);
		third4 = ((*second8 & 0xf0) >> 4);
		fourth4 = (*second8 & 0x0f);

		/*
		if (i == 0){
			printf("%d,%02d,%02d\n", i, first4, second4); 
		}
		if (j < len){
			printf("%d,%02d,%02d\n", i, second4, third4); 
			printf("%d,%02d,%02d\n", i, third4, fourth4); 
		}
		*/

		if (i == 0){
			bc->vec[first4][second4] += 1;
		}
		if (j < len){
			bc->vec[second4][third4] += 1;
			bc->vec[third4][fourth4] += 1;
		}
	}
	return;
}

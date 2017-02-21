/*-
 * Copyright (C) 2017 Daisuke Miyamoto
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_CONFIG_H
#include "../config.h"
#endif

#include "p2c.h"
#include "aslookup.h"
#include "patricia.h"

/* extern patricia_tree_t *cf_tree; */

int p2c_aslookup_lookup(patricia_tree_t *cf_tree, char *cf_key, char *cf_value)
{
	int ret = P2C_FALSE;
	patricia_node_t *cf_node;
	prefix_t *prefix = NULL;

	do {
		if (cf_tree == NULL){
			fprintf(stderr, "p2c_aslookup: cf_tree is null\r\n");
			break;
		}

		if (p2c_aslookup_buffer_trim(cf_key) < 0){
			break;
		}

		if ((prefix = ascii2prefix(AF_INET, cf_key)) == NULL){
			break;
		}

		if ((cf_node = patricia_search_best(cf_tree, prefix)) == NULL){
			break;
		}

		if (cf_node->data == NULL){
			fprintf(stderr, "p2c_aslookup : bogas memory data key %s\n", cf_key);
			break;
		}

		memcpy((void *)cf_value, cf_node->data, P2C_BUFSIZ);
		ret = P2C_TRUE;

	} while(0);

	/* 
	if (ret == P2C_TRUE){
		printf("p2c_aslookup : Query:%s, Answer:%s\n", cf_key, cf_value);
	}
	*/

	return ret;
}

int p2c_aslookup_config_load(patricia_tree_t *cf_tree, char *filename)
{
	FILE *fp;
	patricia_node_t *node;
	int	 ret = P2C_FALSE;
	char buf[P2C_BUFSIZ];				/* store each lines in config file */
	char network[P2C_BUFSIZ];			/* network value */
	char netmask[P2C_BUFSIZ];			/* secnod value */
	char asnumber[P2C_BUFSIZ];			/* asnumber value */
	char key[P2C_BUFSIZ];				/* key of hash : maybe "network netmask" */

	if ((fp = fopen(filename, "r")) == NULL){
		fprintf(stderr, "p2c_aslookup : configuration %s is not readable\n", filename);
		return P2C_FALSE;
	}

	while(fgets(buf, P2C_BUFSIZ, fp) != NULL){
		/*
			broken line : break
		*/
		if (buf == NULL || strlen(buf) < 1 ){
			break;
		}

		/*
			comment line : read next
		*/
		if (buf[0] == '#'){
			continue;
		}

		/*
			trimming buffer 
		*/
		if (p2c_aslookup_buffer_trim(buf) < 1){
			continue;
		}

		memset(network, '\0', P2C_BUFSIZ);	
		memset(netmask, '\0', P2C_BUFSIZ);	
		memset(asnumber, '\0', P2C_BUFSIZ);	

		sscanf(buf, "%s\t%s\t%s", (char *)&network, (char *)&netmask, (char *)&asnumber);

		snprintf(key, P2C_BUFSIZ, "%s/%s", network, netmask);

		/* printf("%s,%s,%s\n", network, netmask, asnumber); */

    if ((node = make_and_lookup(cf_tree, key)) == NULL){
      fprintf(stderr, "whois : libpatricia failed (fatal error)\n");
    }
    else {
      char *value;
      if ((value = (char *)malloc(P2C_BUFSIZ)) == NULL){
        ret = P2C_FALSE;
				break;
      }
      memcpy((void *)value, (void *)asnumber, P2C_BUFSIZ);
      node->data = value;
			ret = P2C_TRUE;
    }
	}
	fclose(fp);	

	/*
	if (cf_tree != NULL){
		printf("kitayo not null\n");
		p2c_aslookup_destroy_tree(cf_tree);	
	}	
	else {
		printf("konaiyo\n");
	}
	*/

	return ret;
}

int p2c_aslookup_buffer_trim(char buf[])
{
	char newbuf[P2C_BUFSIZ];
	int i, j, space, frontspace;

	/* init variables */
	frontspace = space = i = j = 0;

	for (i = 0; i < strlen(buf); i++){
		if (frontspace == 0 && (buf[i] == '\t' || buf[i] == ' ')){
				continue;
		}
		else {
			frontspace = 1;
		}	

		switch(buf[i]){
			case '\r':
			case '\n':
				break;

			case '\t': 
			case ' ':
				if (space == 0){
					newbuf[j++] = ' ';
					space = 1;
				}
				break;

			default:
				newbuf[j++] = buf[i];
				space = 0;
				break;
		}
	}
	newbuf[j] = '\0';

	/* copy */
	memcpy((void *)buf, (void *)newbuf, P2C_BUFSIZ);

	return j;
}

void p2c_aslookup_config_reload(patricia_tree_t *cf_tree, char *configfile) {

  if ((cf_tree = New_Patricia(PATRICIA_MAXBITS)) == NULL){
    fprintf(stderr, "fatal error in creating patricia tree\n");
		exit(EXIT_FAILURE);
  }

	if (p2c_aslookup_config_load(cf_tree, configfile) != P2C_TRUE){
		fprintf(stderr, "p2c_aslookup : cannnot reconstruct tree\n");
		exit(EXIT_FAILURE);
	}

	if (cf_tree == NULL){
		fprintf(stderr, "p2c_aslookup : parameter missing\n");
		p2c_usage();
		exit(EXIT_FAILURE);
	}

  return;
}

void p2c_aslookup_destroy_tree(patricia_tree_t *cf_tree) {
	if (cf_tree != NULL){
		Destroy_Patricia(cf_tree, (void *)p2c_aslookup_destroy_func);
	}
	return;
}

void *p2c_aslookup_destroy_func(void *data) {
	char *tmp;
	if (data == NULL){
		return data;
	}
	else {
		tmp = (char *)data;
		free(tmp);
	}
	return data;
}

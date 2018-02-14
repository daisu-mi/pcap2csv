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

#ifndef __B2C_H__
#define __B2C_H__

#ifndef B2C_BUFSIZ
#define B2C_BUFSIZ	1024
#endif

#ifndef B2C_TRUE
#define B2C_TRUE		1
#endif

#ifndef B2C_FALSE
#define B2C_FALSE		-1
#endif

struct binary_csv {
  uint32_t counter;
  int ttl;
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

void b2c_init();
void b2c_usage(void);
void b2c_data(u_char *, u_int);
void b2c_word2vec4 (u_char *, u_int, struct binary_csv *);
void b2c_word2vec8 (u_char *, u_int, struct binary_csv *);
void b2c_bof (u_char *, u_int, int, struct binary_csv *);

#endif


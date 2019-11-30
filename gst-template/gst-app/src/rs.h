#ifndef __RS_H
#define __RS_H 

/* User include file for the Reed-Solomon codec
 * Copyright 2002, Phil Karn KA9Q
 * May be used under the terms of the GNU General Public License (GPL)
 */

// Modified to compile under OS X 10.6 by Ethan Funk, April 2011

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdlib.h>
#include <string.h>

/* General purpose RS codec, 8-bit symbols */
/* Reed-Solomon codec control block */
struct rs {
	unsigned int mm;              /* Bits per symbol */
	unsigned int nn;              /* Symbols per block (= (1<<mm)-1) */
	unsigned char *alpha_to;      /* log lookup table */
	unsigned char *index_of;      /* Antilog lookup table */
	unsigned char *genpoly;       /* Generator polynomial */
	unsigned int nroots;     /* Number of generator roots = number of parity symbols */
	unsigned char fcr;        /* First consecutive root, index form */
	unsigned char prim;       /* Primitive element, index form */
	unsigned char iprim;      /* prim-th root of 1, index form */
	
};

static inline int modnn(struct rs *rs, unsigned int x){
	while (x >= rs->nn) {
		x -= rs->nn;
		x = (x >> rs->mm) + (x & rs->nn);
	}
	return x;
}

/*
static inline int modnn(struct rs *rs, unsigned int x){
	return x % rs->nn;
}
*/

#if defined(__cplusplus)
extern "C"
{
#endif
	
void encode_rs_char(void *p, unsigned char *data, unsigned char *parity);
int decode_rs_char(void *p, unsigned char *data, unsigned char *eras_pos, int no_eras);
void *init_rs_char(unsigned int symsize, unsigned int gfpoly, unsigned int fcr, unsigned int prim, unsigned int nroots);
void free_rs_char(void *p);

unsigned char checkSum(unsigned char *data, size_t length);
unsigned int chksum_crc32 (unsigned char *block, size_t length, unsigned int *table);
void chksum_crc32gentab(unsigned int *table);
	
#if defined(__cplusplus)
}
#endif

#endif

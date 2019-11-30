/* Reed-Solomon decoder
 * Copyright 2002 Phil Karn, KA9Q
 * May be used under the terms of the GNU General Public License (GPL)
 */

// Modified to compile under OS X 10.6 by Ethan Funk, April 2011

#include "rs.h"

void free_rs_char(void *p)
{
	struct rs *rs = (struct rs *)p;
	
	free(rs->alpha_to);
	free(rs->index_of);
	free(rs->genpoly);
	free(rs);
}

/* Initialize a Reed-Solomon codec
 * symsize = symbol size, bits (1-8)
 * gfpoly = Field generator polynomial coefficients
 * fcr = first root of RS code generator polynomial, index form
 * prim = primitive element to generate polynomial roots
 * nroots = RS code generator polynomial degree (number of roots)
 */
void *init_rs_char(unsigned int symsize, unsigned int gfpoly, unsigned int fcr, unsigned int prim, unsigned int nroots)
{
	struct rs *rs;
	int i, j, sr,root,iprim;
	
	if(symsize > 8*sizeof(unsigned char))
		return NULL; /* Need version with ints rather than chars */
	
	if(fcr >= (1<<symsize))
		return NULL;
	if(prim == 0 || prim >= (1<<symsize))
		return NULL;
	if(nroots >= (1<<symsize))
		return NULL; /* Can't have more roots than symbol values! */
	
	rs = (struct rs *)calloc(1,sizeof(struct rs));
	rs->mm = symsize;
	rs->nn = (1<<symsize)-1;
	
	rs->alpha_to = (unsigned char *)malloc(sizeof(unsigned char)*(rs->nn+1));
	if(rs->alpha_to == NULL){
		free(rs);
		return NULL;
	}
	rs->index_of = (unsigned char *)malloc(sizeof(unsigned char)*(rs->nn+1));
	if(rs->index_of == NULL){
		free(rs->alpha_to);
		free(rs);
		return NULL;
	}
	
	/* Generate Galois field lookup tables */
	rs->index_of[0] = rs->nn; /* log(zero) = -inf */
	rs->alpha_to[rs->nn] = 0; /* alpha**-inf = 0 */
	sr = 1;
	for(i=0;i<rs->nn;i++){
		rs->index_of[sr] = i;
		rs->alpha_to[i] = sr;
		sr <<= 1;
		if(sr & (1<<symsize))
			sr ^= gfpoly;
		sr &= rs->nn;
	}
	if(sr != 1){
		/* field generator polynomial is not primitive! */
		free(rs->alpha_to);
		free(rs->index_of);
		free(rs);
		return NULL;
	}
	
	/* Form RS code generator polynomial from its roots */
	rs->genpoly = (unsigned char *)malloc(sizeof(unsigned char)*(nroots+1));
	if(rs->genpoly == NULL){
		free(rs->alpha_to);
		free(rs->index_of);
		free(rs);
		return NULL;
	}
	rs->fcr = fcr;
	rs->prim = prim;
	rs->nroots = nroots;
	
	/* Find prim-th root of 1, used in decoding */
	for(iprim=1;(iprim % prim) != 0;iprim += rs->nn)
		;
	rs->iprim = iprim / prim;
	
	rs->genpoly[0] = 1;
	for (i = 0,root=fcr*prim; i < nroots; i++,root += prim) {
		rs->genpoly[i+1] = 1;
		
		/* Multiply rs->genpoly[] by  @**(root + x) */
		for (j = i; j > 0; j--){
			if (rs->genpoly[j] != 0)
				rs->genpoly[j] = rs->genpoly[j-1] ^ rs->alpha_to[modnn(rs,rs->index_of[rs->genpoly[j]] + root)];
			else
				rs->genpoly[j] = rs->genpoly[j-1];
		}
		/* rs->genpoly[0] can never be zero */
		rs->genpoly[0] = rs->alpha_to[modnn(rs,rs->index_of[rs->genpoly[0]] + root)];
	}
	/* convert rs->genpoly[] to index form for quicker encoding */
	for (i = 0; i <= nroots; i++)
		rs->genpoly[i] = rs->index_of[rs->genpoly[i]];

	return rs;
}

void encode_rs_char(void *p, unsigned char *data, unsigned char *bb)
{
	struct rs *rs = (struct rs *)p;

	int i, j;
	unsigned char feedback;
	
	memset(bb,0,rs->nroots*sizeof(unsigned char));
	
	for(i=0;i<(rs->nn - rs->nroots);i++){
		feedback = rs->index_of[data[i] ^ bb[0]];
		if(feedback != rs->nn){      /* feedback term is non-zero */
#ifdef UNNORMALIZED
			/* This line is unnecessary when rs->genpoly[rs->nroots] is unity, as it must
			 * always be for the polynomials constructed by init_rs()
			 */
			feedback = modnn(rs,rs->nn - rs->genpoly[rs->nroots] + feedback);
#endif
			for(j=1;j<rs->nroots;j++)
				bb[j] ^= rs->alpha_to[modnn(rs,feedback + rs->genpoly[rs->nroots-j])];
		}
		/* Shift */
		memmove(&bb[0],&bb[1],sizeof(unsigned char)*(rs->nroots-1));
		if(feedback != rs->nn)
			bb[rs->nroots-1] = rs->alpha_to[modnn(rs,feedback + rs->genpoly[0])];
		else
			bb[rs->nroots-1] = 0;
	}
}

int decode_rs_char(void *p, unsigned char *data, unsigned char *eras_pos, int no_eras)
{
  struct rs *rs = (struct rs *)p;
	
  int deg_lambda, el, deg_omega;
  int i, j, r,k;
  unsigned char u,q,tmp,num1,num2,den,discr_r;
  unsigned char lambda[rs->nroots+1], s[rs->nroots];	/* Err+Eras Locator poly
					 * and syndrome poly */
  unsigned char b[rs->nroots+1], t[rs->nroots+1], omega[rs->nroots+1];
  unsigned char root[rs->nroots], reg[rs->nroots+1], loc[rs->nroots];
  int syn_error, count;

  /* form the syndromes; i.e., evaluate data(x) at roots of g(x) */
  for(i=0;i<rs->nroots;i++)
	s[i] = data[0];

  for(j=1;j<rs->nn;j++){
	for(i=0;i<rs->nroots;i++){
		if(s[i] == 0){
			s[i] = data[j];
		} else {
			s[i] = data[j] ^ rs->alpha_to[modnn(rs,rs->index_of[s[i]] + (rs->fcr+i)*rs->prim)];
		}
	}
  }

  /* Convert syndromes to index form, checking for nonzero condition */
  syn_error = 0;
  for(i=0;i<rs->nroots;i++){
    syn_error |= s[i];
    s[i] = rs->index_of[s[i]];
  }

  if (!syn_error) {
    /* if syndrome is zero, data[] is a codeword and there are no
     * errors to correct. So return data[] unmodified
     */
    count = 0;
    goto finish;
  }
  memset(&lambda[1],0,rs->nroots*sizeof(lambda[0]));
  lambda[0] = 1;

  if (no_eras > 0) {
    /* Init lambda to be the erasure locator polynomial */
    lambda[1] = rs->alpha_to[modnn(rs,rs->prim*(rs->nn-1-eras_pos[0]))];
    for (i = 1; i < no_eras; i++) {
      u = modnn(rs,rs->prim*(rs->nn-1-eras_pos[i]));
      for (j = i+1; j > 0; j--) {
	tmp = rs->index_of[lambda[j - 1]];
	if(tmp != rs->nn)
	  lambda[j] ^= rs->alpha_to[modnn(rs,u + tmp)];
      }
    }

#if DEBUG >= 1
    /* Test code that verifies the erasure locator polynomial just constructed
       Needed only for decoder debugging. */
    
    /* find roots of the erasure location polynomial */
    for(i=1;i<=no_eras;i++)
      reg[i] = rs->index_of[lambda[i]];

    count = 0;
    for (i = 1,k=rs->iprim-1; i <= rs->nn; i++,k = modnn(rs,k+rs->iprim)) {
      q = 1;
      for (j = 1; j <= no_eras; j++)
	if (reg[j] != rs->nn) {
	  reg[j] = modnn(rs,reg[j] + j);
	  q ^= rs->alpha_to[reg[j]];
	}
      if (q != 0)
	continue;
      /* store root and error location number indices */
      root[count] = i;
      loc[count] = k;
      count++;
    }
    if (count != no_eras) {
      printf("count = %d no_eras = %d\n lambda(x) is WRONG\n",count,no_eras);
      count = -1;
      goto finish;
    }
#if DEBUG >= 2
    printf("\n Erasure positions as determined by roots of Eras Loc Poly:\n");
    for (i = 0; i < count; i++)
      printf("%d ", loc[i]);
    printf("\n");
#endif
#endif
  }
  for(i=0;i<rs->nroots+1;i++)
    b[i] = rs->index_of[lambda[i]];
  
  /*
   * Begin Berlekamp-Massey algorithm to determine error+erasure
   * locator polynomial
   */
  r = no_eras;
  el = no_eras;
  while (++r <= rs->nroots) {	/* r is the step number */
    /* Compute discrepancy at the r-th step in poly-form */
    discr_r = 0;
    for (i = 0; i < r; i++){
      if ((lambda[i] != 0) && (s[r-i-1] != rs->nn)) {
	discr_r ^= rs->alpha_to[modnn(rs,rs->index_of[lambda[i]] + s[r-i-1])];
      }
    }
    discr_r = rs->index_of[discr_r];	/* Index form */
    if (discr_r == rs->nn) {
      /* 2 lines below: B(x) <-- x*B(x) */
      memmove(&b[1],b,rs->nroots*sizeof(b[0]));
      b[0] = rs->nn;
    } else {
      /* 7 lines below: T(x) <-- lambda(x) - discr_r*x*b(x) */
      t[0] = lambda[0];
      for (i = 0 ; i < rs->nroots; i++) {
	if(b[i] != rs->nn)
	  t[i+1] = lambda[i+1] ^ rs->alpha_to[modnn(rs,discr_r + b[i])];
	else
	  t[i+1] = lambda[i+1];
      }
      if (2 * el <= r + no_eras - 1) {
	el = r + no_eras - el;
	/*
	 * 2 lines below: B(x) <-- inv(discr_r) *
	 * lambda(x)
	 */
	for (i = 0; i <= rs->nroots; i++)
	  b[i] = (lambda[i] == 0) ? rs->nn : modnn(rs,rs->index_of[lambda[i]] - discr_r + rs->nn);
      } else {
	/* 2 lines below: B(x) <-- x*B(x) */
	memmove(&b[1],b,rs->nroots*sizeof(b[0]));
	b[0] = rs->nn;
      }
      memcpy(lambda,t,(rs->nroots+1)*sizeof(t[0]));
    }
  }

  /* Convert lambda to index form and compute deg(lambda(x)) */
  deg_lambda = 0;
  for(i=0;i<rs->nroots+1;i++){
    lambda[i] = rs->index_of[lambda[i]];
    if(lambda[i] != rs->nn)
      deg_lambda = i;
  }
  /* Find roots of the error+erasure locator polynomial by Chien search */
  memcpy(&reg[1],&lambda[1],rs->nroots*sizeof(reg[0]));
  count = 0;		/* Number of roots of lambda(x) */
  for (i = 1,k=rs->iprim-1; i <= rs->nn; i++,k = modnn(rs,k+rs->iprim)) {
    q = 1; /* lambda[0] is always 0 */
    for (j = deg_lambda; j > 0; j--){
      if (reg[j] != rs->nn) {
		  reg[j] = modnn(rs,reg[j] + j);
		  q ^= rs->alpha_to[reg[j]];
      }
    }
    if (q != 0)
      continue; /* Not a root */
    /* store root (index-form) and error location number */
#if DEBUG>=2
    printf("count %d root %d loc %d\n",count,i,k);
#endif
    root[count] = i;
    loc[count] = k;
    /* If we've already found max possible roots,
     * abort the search to save time
     */
    if(++count == deg_lambda)
      break;
  }
  if (deg_lambda != count) {
    /*
     * deg(lambda) unequal to number of roots => uncorrectable
     * error detected
     */
    count = -1;
    goto finish;
  }
  /*
   * Compute err+eras evaluator poly omega(x) = s(x)*lambda(x) (modulo
   * x**rs->nroots). in index form. Also find deg(omega).
   */
  deg_omega = 0;
  for (i = 0; i < rs->nroots;i++){
    tmp = 0;
    j = (deg_lambda < i) ? deg_lambda : i;
    for(;j >= 0; j--){
      if ((s[i - j] != rs->nn) && (lambda[j] != rs->nn))
	tmp ^= rs->alpha_to[modnn(rs,s[i - j] + lambda[j])];
    }
    if(tmp != 0)
      deg_omega = i;
    omega[i] = rs->index_of[tmp];
  }
  omega[rs->nroots] = rs->nn;
  
  /*
   * Compute error values in poly-form. num1 = omega(inv(X(l))), num2 =
   * inv(X(l))**(rs->fcr-1) and den = lambda_pr(inv(X(l))) all in poly-form
   */
  for (j = count-1; j >=0; j--) {
    num1 = 0;
    for (i = deg_omega; i >= 0; i--) {
      if (omega[i] != rs->nn)
	num1  ^= rs->alpha_to[modnn(rs,omega[i] + i * root[j])];
    }
    num2 = rs->alpha_to[modnn(rs,root[j] * (rs->fcr - 1) + rs->nn)];
    den = 0;
    
    /* lambda[i+1] for i even is the formal derivative lambda_pr of lambda[i] */
    for (i = ((deg_lambda) < (rs->nroots-1) ? (deg_lambda) : (rs->nroots-1)) & ~1; i >= 0; i -=2) {
      if(lambda[i+1] != rs->nn)
	den ^= rs->alpha_to[modnn(rs,lambda[i+1] + i * root[j])];
    }
    if (den == 0) {
#if DEBUG >= 1
      printf("\n ERROR: denominator = 0\n");
#endif
      count = -1;
      goto finish;
    }
    /* Apply error to data */
    if (num1 != 0) {
      data[loc[j]] ^= rs->alpha_to[modnn(rs,rs->index_of[num1] + rs->index_of[num2] + rs->nn - rs->index_of[den])];
    }
  }
 finish:
  if(eras_pos != NULL){
    for(i=0;i<count;i++)
      eras_pos[i] = loc[i];
  }
  return count;
}

unsigned char checkSum(unsigned char *data, size_t length)
{
	size_t i;
	unsigned char cs;
	
	cs = 0;
	for(i=0; i<length; i++)
		cs = cs + data[i];
	cs = ~cs + 1;
	return cs;
}

// CRC32 checksum: based on implementation by Finn Yannick Jacobs
unsigned int chksum_crc32(unsigned char *block, size_t length, unsigned int *table)
{
	register unsigned int crc;
	size_t i;
	
	crc = 0xFFFFFFFF;
	for (i = 0; i < length; i++)
	{
		crc = ((crc >> 8) & 0x00FFFFFF) ^ table[(crc ^ *block++) & 0xFF];
	}
	return (crc ^ 0xFFFFFFFF);
}

void chksum_crc32gentab(unsigned int *table)
{
	unsigned int crc, poly;
	int i, j;
	
	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 8; j > 0; j--)
		{
			if (crc & 1)
			{
				crc = (crc >> 1) ^ poly;
			}
			else
			{
				crc >>= 1;
			}
		}
		table[i] = crc;
	}
}

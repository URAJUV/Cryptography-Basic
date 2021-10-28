
/*
 * des.h provides the following functions and constants:
 *
 * generate_key, generate_sub_keys, process_message, ENCRYPTION_MODE, DECRYPTION_MODE
 *
 */
#include "des.h"
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "bitarray.h"
#include <ctype.h>

typedef unsigned char BYTE;
typedef unsigned long WORD32;
typedef unsigned long long WORD64;

#define QLEN (sizeof(WORD64))
#define CCN_LEN 16
#define KEY_SIZE
/* Interface: */
int encrypt_128(const BYTE key[KEY_SIZE], BYTE data[CCN_LEN]);
int stop_on_multiple_loops = 0;

/** Convert 64-bit word into array of 8 bytes in bigendian order */
static void word64_to_bytes(BYTE *into, WORD64 outof) {
  *into++ = (BYTE)((outof >> 56) & 0xffL);
  *into++ = (BYTE)((outof >> 48) & 0xffL);
  *into++ = (BYTE)((outof >> 40) & 0xffL);
  *into++ = (BYTE)((outof >> 32) & 0xffL);
  *into++ = (BYTE)((outof >> 24) & 0xffL);
  *into++ = (BYTE)((outof >> 16) & 0xffL);
  *into++ = (BYTE)((outof >>  8) & 0xffL);
  *into++ = (BYTE)( outof        & 0xffL);
}

/** Convert 8-byte array in bigendian order into 64-bit word */
static WORD64 word64_from_bytes(const BYTE *outof) {
  WORD64 into;
  into    = (WORD64)(*outof++ & 0xffL) << 56;
  into   |= (WORD64)(*outof++ & 0xffL) << 48;
  into   |= (WORD64)(*outof++ & 0xffL) << 40;
  into   |= (WORD64)(*outof++ & 0xffL) << 32;
  into   |= (WORD64)(*outof++ & 0xffL) << 24;
  into   |= (WORD64)(*outof++ & 0xffL) << 16;
  into   |= (WORD64)(*outof++ & 0xffL) << 8;
  into   |= (WORD64)(*outof++ & 0xffL);
  return into;
}

int encrypt_128_des(unsigned char *data ,const unsigned char *des_key) {

		short int bytes_read;
		clock_t start, finish;
		unsigned long file_size = 7;
		double time_taken;
		unsigned short int padding;
		// Generate DES key set
		short int bytes_written, process_mode;
		unsigned long block_count = 0, number_of_blocks;
		unsigned char* processed_block = (unsigned char*) malloc(8*sizeof(char));
		key_set* key_sets = (key_set*)malloc(17*sizeof(key_set));

		start = clock();
		generate_sub_keys(des_key, key_sets);
		finish = clock();
		time_taken = (double)(finish - start)/(double)CLOCKS_PER_SEC;

		// Determine process mode
		if (1) {
			process_mode = ENCRYPTION_MODE;
		} else {
			process_mode = DECRYPTION_MODE;
		}
		if (process_mode == ENCRYPTION_MODE) {
					padding = 8 - file_size%8;
					if (padding < 8) { // Fill empty data block bytes with padding
					//memset((data_block + 8 - padding), (unsigned char)padding, padding);
					}

					process_message(data, processed_block, key_sets, process_mode);
					//bytes_written = fwrite(processed_block, 1, 8, output_file);

					if (padding == 8) { // Write an extra block for padding
						memset(data, (unsigned char)padding, 8);
						process_message(data, processed_block, key_sets, process_mode);
						//bytes_written = fwrite(processed_block, 1, 8, output_file);
					}
		} else {
			process_message(data, processed_block, key_sets, process_mode);
			padding = processed_block[7];

			if (padding < 8) {
				//bytes_written = fwrite(processed_block, 1, 8 - padding, output_file);
			}
		}
		memcpy(data,processed_block,8);
}

/** Encrypt exactly 128-bits of data using a 128-bit key, both in 16-byte arrays:
 *  data = E(key, data) */
int encrypt_128(const BYTE key[KEY_SIZE], BYTE data[CCN_LEN]) {
    int r;
    r = encrypt_128_des(data,key);
    return r;
}

void ffsem_prf(BYTE *E, const BYTE *data, size_t nbytes, size_t nbits, const BYTE *key, size_t tweak) {
    /* PRF(x) = [E(k, x||0..0||tweak)]_nbits */
    BYTE B[16]; /* 128-bit encryption block */
    size_t blen = sizeof(B);

    memset(B, 0, blen);
    memcpy(B, data, nbytes);
    B[blen-1] = (BYTE)tweak;
    bit_pr_bytes("B=      ", B, blen, "\n");
    encrypt_128(key, B);    /* B = E(key, B) */
    bit_pr_bytes("E(k,B)= ", B, blen, "\n");
    /* Truncate E(.) to nbits */
    bit_substring(E, B, nbytes, nbits, 0, nbits);
}

static void ffsem_round_common(BYTE *data, size_t nbytes, size_t nbits,
    const BYTE *key, size_t tweak, int encrypt) {
    size_t halfbits = nbits / 2;    // half-length
    size_t hlen = nbytes / 2;
    size_t n, i, index, length;
    BYTE E[8];
    BYTE right[8], left[8];

    assert(8 == nbytes);    /* PRE nbytes == 8 */
    /* Split input data into left and right blocks */
    index = 0;
    length = halfbits;
    n = bit_substring(left, data, nbytes, nbits, index, length);
    bit_pr_bytes("L       ", left, hlen, "\t");
    bit_print("", left, hlen, n, "\n");
    index = halfbits;
    length = halfbits;
    n = bit_substring(right, data, nbytes, nbits, index, length);
    bit_pr_bytes("R       ", right, hlen, "\t");
    bit_print("", right, hlen, n, "\n");

    if (encrypt)
    {
        /* Algorithm:
            INPUT: L || R
            L' = R
            R' = L XOR PRF(R)
            OUTPUT: L' || R'
        */
        /* R' = L XOR PRF(R) */
        ffsem_prf(E, right, hlen, halfbits, key, tweak);
        bit_pr_bytes("E=      ", E, hlen, "\n");
        bit_pr_bytes("L=      ", left, hlen, "\n");
        for (i = 0; i < hlen; i++)
            left[i] = left[i] ^ E[i];
        /* Truncate R' to 54-bits */
        bit_substring(left, left, hlen, halfbits, 0, halfbits);
        bit_pr_bytes("L XOR E=", left, hlen, "\n");
        /* L' || R' = R || (L XOR PRF(R)) */
    }
    else
    {
        /* Algorithm:
            INPUT: L || R
            R' = L
            L' = R XOR PRF(L)
            OUTPUT: L' || R'
        */
        /* L' = R XOR PRF(L) */
        ffsem_prf(E, left, hlen, halfbits, key, tweak);
        bit_pr_bytes("E=      ", E, hlen, "\n");
        bit_pr_bytes("R=      ", right, hlen, "\n");
        for (i = 0; i < hlen; i++)
            right[i] = right[i] ^ E[i];
        /* Truncate L' to 54-bits */
        bit_substring(right, right, hlen, halfbits, 0, halfbits);
        bit_pr_bytes("R XOR E=", right, hlen, "\n");
        /* L' || R' = (R XOR PRF(L)) || L */
    }

    /* Concatenate bitstrings L' || R' */
    bit_pr_bytes("L'=", right, hlen, "\t");
    bit_print("", right, hlen, halfbits, "\n");
    bit_pr_bytes("R'=", left, hlen, "\t");
    bit_print("", left, hlen, halfbits, "\n");
    bit_cat(data, nbytes, right, hlen, halfbits, left, hlen, halfbits);
    bit_print("", data, nbytes, nbits, "\n");
    bit_pr_index("", nbits, "\n");
}

void ffsem_round_encr(BYTE *data, size_t nbytes, size_t nbits, const BYTE *key, size_t tweak) {
    ffsem_round_common(data, nbytes, nbits, key, tweak, 1);
}

void ffsem_round_decr(BYTE *data, size_t nbytes, size_t nbits, const BYTE *key, size_t tweak) {
    ffsem_round_common(data, nbytes, nbits, key, tweak, 0);
}

static int ffsem_crypt_common(WORD64 *ccout, WORD64 ccn, WORD64 ccmax, size_t maxbits,
    BYTE key[8], size_t nrounds, int encrypt) {
    BYTE a[QLEN], b[QLEN], c[QLEN];
    size_t n, nbits, r;
    int loops = 0;

    bit_pr_bytes("KEY=", key, 8, "\n");
    do
    {
        loops++;
        printf("ccn=0x%llx\n", ccn);
        word64_to_bytes(a, ccn);
        bit_pr_bytes("arr=", a, QLEN, "\n");

        // Encode to 54-bit string
        nbits = maxbits;
        n = bit_encode(b, a, QLEN, nbits);
        printf("bit_encode[%lu]=", nbits);
        bit_pr_bytes("", b, n, "\n");
        bit_print("", b, n, nbits, "\n");

        if (encrypt)
        {
            /* Fiestel encryption on blocks of nbits */
            for (r = 1; r <= nrounds; r++)
            {
                printf("-------------------------------- ENCRYPTION Round %lu START-------------------------------\n\n", r);
                bit_pr_bytes("input=  ", b, n, "\n");
                ffsem_round_encr(b, QLEN, nbits, key, r);
                bit_pr_bytes("output= ", b, n, "\n");
                printf("-------------------------------- ENCRYPTION Round %lu END-------------------------------\n\n", r);
				if(r == 6) {
                	printf("-------------------------------- ENCRYPTED CCN-------------------------------\n\n");
           			bit_pr_bytes("FINAL ENCRYPTED CCN:  ", b, n, "\n\n");
				}
            }
        }
        else
        {
            /* Fiestel decryption on blocks of nbits */
            for (r = nrounds; r >= 1; r--)
            {
                printf("-------------------------------- DECRYPTION Round %lu START-------------------------------\n\n", r);
                bit_pr_bytes("input=  ", b, n, "\n");
                ffsem_round_decr(b, QLEN, nbits, key, r);
                bit_pr_bytes("output= ", b, n, "\n");
                printf("-------------------------------- DECRYPTION Round %lu END-------------------------------\n\n", r);
            }
        }

        // Decode to 64-bit QWORD
        n = bit_decode(c, b, QLEN, nbits);
        printf("bit_decode[%lu]=", nbits);
        bit_pr_bytes("", c, QLEN, "\n");
        bit_print("", c, QLEN, QLEN*8, "\n");
        ccn = word64_from_bytes(c);
        printf("ccn=0x%llx\n", ccn);
        printf("ccn=%016lld decimal %s %016lld decimal %s\n", ccn, (ccn <= ccmax ? "<=" : ">"), ccmax,
            (ccn <= ccmax ? "OK" : "Repeat..."));
    } while (ccn > ccmax);

    printf("Found solution in %d loop%s\n", loops, (loops > 1 ? "s" : ""));
    *ccout = ccn;
    return loops;
}

int ffsem_encrypt(WORD64 *ccout, WORD64 ccn, WORD64 ccmax, size_t maxbits, BYTE key[8], size_t nrounds) {
    return ffsem_crypt_common(ccout, ccn, ccmax, maxbits, key, nrounds, 1);
}
int ffsem_decrypt(WORD64 *ccout, WORD64 ccn, WORD64 ccmax, size_t maxbits, BYTE key[8], size_t nrounds) {
    return ffsem_crypt_common(ccout, ccn, ccmax, maxbits, key, nrounds, 0);
}


int ccn_check(char * ccnumber) {
	int isDigit = 1;
	int j=0;
	while(j<16 && isDigit == 1){
		if(isdigit((ccnumber[j])))
			isDigit = 1;
		else
		isDigit = 0;
		j++;
	}
	printf("CCN NUMBER IS NUMERIC :%s \n", isDigit ? "true" : "false");
	return isDigit;
}

int main(int argc, char* argv[]) {

	// Specific for 16-digit decimal numbers..
    const WORD64 ccmax = 9999999999999999;
    const size_t maxbits = 54;
    const size_t nrounds = 6;
    WORD64 ccn, cce, ccd;
    int i, nloops;
	char* endPtr;
	WORD64 parsed_ccn ;

	char ccnumber[CCN_LEN+1]= {0};
	int isDigit = 0;
	if (argc < 2) {
		printf("You must provide at least 1 parameter i.e ./fpe XXXXXXXXXXXXXXXXX (16 Digits CCN) \n");
		return 1;
	}

	if(strlen(argv[1])!=16) {
		printf("Credit Card Number should be 16 digits i.e  XXXXXXXXXXXXXXXXX (16 Digits CCN) given size %lu \n ", strlen(argv[1]));
		return 1;
	}
	strncpy(ccnumber,argv[1],16);
	printf("CCN number is %s\n",ccnumber);
	isDigit = ccn_check(ccnumber);
	if(!isDigit) {
		printf("Credit Card Number should be only digits(0-9) i.e  XXXXXXXXXXXXXXXXX (16 Digits CCN)\n ");
		return 1;
	}

	BYTE key[8] = {    /* (0x)0001020304050607 */
        0x90, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };

   	parsed_ccn =  strtoull(ccnumber, &endPtr,10);
	ccn = parsed_ccn;
	printf("cce=%016lld decimal\n", ccn);
	nloops = ffsem_encrypt(&cce, ccn, ccmax, maxbits, key, nrounds);
    printf("-----------------------------------------------------------------------------\n\n");
	printf("cce=%016lld encryted\n", cce);
	if (stop_on_multiple_loops && nloops > 1)
	{
		printf("Hit enter to continue...");
		getchar();
	}
	// DECRYPT...
	nloops = ffsem_decrypt(&ccd, cce, ccmax, maxbits, key, nrounds);
	printf("ccd=%016lld decimal\n", ccd);
	if (stop_on_multiple_loops && nloops > 1)
	{
		printf("Hit enter to continue...");
		getchar();
	}
	assert(ccd == ccn);

    return 0;
}

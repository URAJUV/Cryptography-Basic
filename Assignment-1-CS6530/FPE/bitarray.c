#include <stdio.h>

typedef unsigned char BYTE;

/*****************/
/* BIT FUNCTIONS */
/*****************/

/*
Bitstrings are represented by a 3-tuple (data, nbytes, nbits).
A bitstring is the first `nbits` bits in the byte array of length `nbytes`.
Encoding a byte array essentially means left-shifting so the most significant bit is the left-most 
bit, the first `nbits` bits are the bitstring itself, and any remaining bits in the array are zero.
Obviously an array of length nbytes can only hold at most nbytes*8 bits.
The user must allocate the memory for each `data` array and remember the values of its associated
(nbytes, nbits) pair.
Example 1: bit_encode(data, 3, 17)
Input: data=0x00DEAD=00000000 11011110 10101101, nbytes=3, nbits=17
Output: 0 11011110 10101101 0000000
                           |-------> padding
Example 2: bit_encode(data, 3, 6)
Input: data=0x00DEAD=00000000 11011110 10101101, nbytes=3, nbits=6
Output: 101101 00 00000000 00000000
              |-------> padding
*/

/*
NOTE that bit_encode() and bit_decode() return a byte count (the minimum number of bytes to hold the result),
but bit_substring() and bit_cat() return the final bit length.
*/

/** Print bitstring as sequence of '0' and '1' with optional prefix and suffix */
void bit_print(const char *prefix, const unsigned char *data, size_t nbytes, size_t nbits, const char *suffix) {
    size_t i, j;
    unsigned char mask;
    size_t nb  = nbits / 8;
    size_t odd = nbits % 8;

    if (nb > nbytes)
    {   /* Catch attempt to print beyond length of byte array */
        nb = nbytes;
        odd = 0;
    }
    if (prefix) printf("%s", prefix);
    for (i = 0; i < nb; i++)
    {
        for (j = 0, mask = 0x80; j < 8; j++)
        {
            printf("%d", (data[i] & mask) ? 1 : 0);
            mask >>= 1;
        }
    }
    if (odd)
    {
        for (j = 0, mask = 0x80; j < odd; j++)
        {
            printf("%d", (data[i] & mask) ? 1 : 0);
            mask >>= 1;
        }
    }
    if (suffix) printf("%s", suffix);
}

/** Print an index 01234... with optional prefix and suffix - useful for debugging */
void bit_pr_index(const char *prefix, size_t nbits, const char *suffix) {
    size_t i;
    if (prefix) printf("%s", prefix);
    for (i = 0; i < nbits; i++)
    {
        printf("%lu", i % 10);
    }
    if (suffix) printf("%s", suffix);
}

/** Print byte array in hex format with optional prefix and suffix */
void bit_pr_bytes(const char *prefix, const unsigned char *b, size_t n, const char *suffix) {
    size_t i;
    if (prefix) printf("%s", prefix);
    for (i = 0; i < n; i++)
    {
        printf("%02X", b[i]);
    }
    if (suffix) printf("%s", suffix);
}

/** Encode byte array of nbytes into "left-aligned, big-endian" bit string, 
 *  truncating if necessary.
 *  @returns minimum number of bytes to store final bitstring.
 *  @remark Essentially shifts left so first \c nbits bits are the bitstring we want.
 *  @pre \c out and \c data are both \c nbytes long
 */
size_t bit_encode(BYTE *out, const BYTE *data, size_t nbytes, size_t nbits) {
    size_t n, byteshift, bitshift, i;

    if (0 == nbytes) return 0;
    n = (nbits + 7) / 8;            /* Min # bytes to hold nbits */
    byteshift = nbytes - n;         /* # of whole bytes to shift */
    bitshift = n * 8 - nbits;       /* # of bits [0,7] to shift */

    if (n > nbytes)
    {   /* Asked for too many bits, so no change */
        n = nbytes;
        byteshift = bitshift = 0;
    }

    /* Copy required # of bytes to output and zero trailing bytes */
    for (i = 0; i < nbytes - byteshift; i++)
        out[i] = data[i+byteshift];
    for ( ; i < nbytes; i++)
        out[i] = 0;

    if (bitshift)
    {   /* Left shift */
        for (i = 0; i < nbytes - 1; i++)
        {
            out[i] = (out[i] << bitshift) | (out[i+1] >> (8 - bitshift));
        }
        out[i] = out[i] << bitshift;
    }

    return n;   /* Min # bytes to store resulting bitstring */
}

/** Decode bitstring into right-justified byte array of length nbytes
 *  @returns minimum number of bytes to store final byte array.
 *  @pre \c out and \c data are both \c nbytes long */
size_t bit_decode(BYTE *out, const BYTE *data, size_t nbytes, size_t nbits) {
    size_t n, byteshift, bitshift, i;

    if (0 == nbytes) return 0;
    n = (nbits + 7) / 8;            /* Min # bytes to hold nbits */
    byteshift = nbytes - n;         /* # of whole bytes to shift */
    bitshift = n * 8 - nbits;       /* # of bits [0,7] to shift */

    if (n > nbytes) 
    {   /* Asked for too many bits, so no change */
        n = nbytes;
        byteshift = bitshift = 0;
    }

    /* Copy required # of bytes to output and zero remainder */
    for (i = nbytes; i > byteshift; i--)
        out[i-1] = data[i-byteshift-1];
    for (; i > 0; i--)
        out[i-1] = 0;

    if (bitshift)
    {   /* Right shift */
        for (i = nbytes - 1; i > 0; i--)
        {
            out[i] = (out[i] >> bitshift) | (out[i-1] << (8 - bitshift));
        }
        out[0] = out[0] >> bitshift;
    }

    return n;   /* Min # bytes to store resulting bitstring */
}

/** Create substring of `length` bits starting at zero-based position `index`
 *  @return number of bits in new bitstring. */
size_t bit_substring(BYTE *out, const BYTE *data, size_t nbytes, size_t nbits,
                     size_t index, size_t length) {
    size_t n, bitshift, i, j, t;
    size_t first, last;
    BYTE mask;

    if (0 == nbytes) return 0;
    if (index >= nbits || 0 == length)
    {   /* Return the empty string */
        for (i = 0; i < nbytes; i++)
            out[i] = 0;
        return 0;
    }
    if (index + length > nbits)
    {   /* Asked for too many bits */
        length = nbits - index;
    }

    first = index / 8;
    last = (index + length) / 8;
    n = last - first + 1;
    bitshift = index % 8;
    /* Copy required # of bytes to output and zero trailing bytes */
    for (i = 0; i < n; i++)
        out[i] = data[i+first];
    for ( ; i < nbytes; i++)
        out[i] = 0;

    if (bitshift)
    {   /* Left shift */
        for (i = 0; i < nbytes - 1; i++)
        {
            out[i] = (out[i] << bitshift) | (out[i+1] >> (8 - bitshift));
        }
        out[i] = out[i] << bitshift;
    }
    /* Clear any surplus bits on the right */
    for (t = 0, i = 0; i < n; i++)
    {
        for (mask = 0x80, j = 0; j < 8; j++, t++, mask >>= 1)
        {
            if (t >= length)
                out[i] &= (~mask);
        }
    }

    return length;
}

/** Concatenate two bitstrings (data1, nbytes1, nbits1) and (data2, nbytes2, nbits2)
 *  into bitstring (out, outbytes, nbits1+nbits2).
 *  @return number of bits in new bitstring or 0 if the output is not large enough.
 *  @remark (out, outbytes) \e must be large enough or it will fail*/
size_t bit_cat(BYTE *out, size_t outbytes,
    const BYTE *data1, size_t nbytes1, size_t nbits1,
    const BYTE *data2, size_t nbytes2, size_t nbits2) {
    size_t n, n2, bitshift, i, j, t, length;

	n = (nbits1 + nbits2 + 7) / 8;
    if (n > outbytes)   /* JUST FAIL */
    {   /* Return the empty string */
        for (i = 0; i < outbytes; i++)
            out[i] = 0;
        return 0;
    }

    /* Copy the first bitstring to the output */
    n = (nbits1 + 7) / 8;
    bitshift = n * 8 - nbits1;
    for (i = 0; i < n; i++)
        out[i] = data1[i];
    for ( ; i < outbytes; i++)
        out[i] = 0;
    /* Copy the second bitstring */
    n2 = (nbits2 + 7) / 8;
    /* Two cases: either we need to shift bits or not */
    if (bitshift)
    {
        out[n-1] |= data2[0] >> (8 - bitshift);
        for (i = 0; i < n2 - 1; i++)
            out[i+n] = (data2[i] << bitshift) | (data2[i+1] >> (8 - bitshift));
    }
    else
    {   /* Just copy the bytes */
        for (i = 0; i < n2; i++)
            out[i+n] = data2[i];
    }

    /* Clear any surplus bits on the right */
    length = nbits1 + nbits2;
    for (t = 0, i = 0; i < outbytes; i++)
    {   BYTE mask;
        for (mask = 0x80, j = 0; j < 8; j++, t++, mask >>= 1)
        {
            if (t >= length)
                out[i] &= (~mask);
        }
    }

    return length;
}

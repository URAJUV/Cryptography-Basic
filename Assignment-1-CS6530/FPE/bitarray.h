#ifndef BITARRAY_H_
#define BITARRAY_H_ 1

#include <stddef.h>     /* for size_t */

size_t bit_encode(unsigned char *out, const unsigned char *data, size_t nbytes, size_t nbits);
size_t bit_decode(unsigned char *out, const unsigned char *data, size_t nbytes, size_t nbits);
size_t bit_substring(unsigned char *out, const unsigned char *data, size_t nbytes, size_t nbits, 
    size_t index, size_t length);
size_t bit_cat(unsigned char *out, size_t outbytes, 
    const unsigned char *data1, size_t nbytes1, size_t nbits1, 
    const unsigned char *data2, size_t nbytes2, size_t nbits2);
void bit_print(const char *prefix, const unsigned char *data, size_t nbytes, size_t nbits, const char *suffix);
void bit_pr_index(const char *prefix, size_t nbits, const char *suffix);
void bit_pr_bytes(const char *prefix, const unsigned char *b, size_t n, const char *suffix);

#endif /* end BITARRAY_H_ */

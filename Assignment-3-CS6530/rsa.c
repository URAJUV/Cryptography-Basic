#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

int main(void)
{
    mpz_t n, d, e, pt, ct, p, p_1, q_1, q;
	mpz_t p_inv, q_inv, d_mod_p, d_mod_q;
 	mpz_t Xp, Xq, Vp, Vq, VpXp, VqXq, pt_crt, SUM;
    mpz_init(pt);
    mpz_init(pt_crt);
    mpz_init(p_1);
    mpz_init(p_inv);
    mpz_init(q_inv);
    mpz_init(q_1);
    mpz_init(ct);
    mpz_init(d_mod_p);
    mpz_init(d_mod_q);
    mpz_init(Xp);
    mpz_init(Xq);
    mpz_init(Vp);
    mpz_init(Vq);
    mpz_init(VpXp);
    mpz_init(VqXq);
    mpz_init(SUM);
    char buffer[100],buffer_crt[100];

    mpz_init_set_str(n, "9516311845790656153499716760847001433441357", 10);
    mpz_init_set_str(e, "65537", 10);
    mpz_init_set_str(d, "5617843187844953170308463622230283376298685", 10);
    mpz_init_set_str(p, "2463574872878749457479", 10);
    mpz_init_set_str(q, "3862806018422572001483", 10);

	gmp_printf("N: is %Zd\n", n);
	gmp_printf("e: is %Zd\n", e);
	gmp_printf("d: is %Zd\n", d);
	gmp_printf("p: is %Zd\n", p);
	gmp_printf("q: is %Zd\n\n", q);

	mpz_invert(p_inv, p, q);
	mpz_invert(q_inv, q, p);
	gmp_printf("Inverse of P:%Zd is %Zd \n", p, p_inv);
	gmp_printf("Inverse of Q:%Zd is %Zd \n\n", q, q_inv);
	mpz_mul(Xp, q, q_inv);
	mpz_mul(Xq, p, p_inv);
	gmp_printf("Xp is %Zd\n", Xp);
	gmp_printf("Xq is %Zd\n\n", Xq);
	mpz_sub_ui(p_1, p, 1);
	mpz_sub_ui(q_1, q, 1);
	gmp_printf("p-1  is %Zd\n", p_1);
	gmp_printf("q-1  is %Zd\n\n", q_1);
	mpz_mod(d_mod_p, d, p_1);
	mpz_mod(d_mod_q, d, q_1);
	gmp_printf("d mod p-1 is %Zd\n", d_mod_p);
	gmp_printf("d mod q-1 is %Zd\n\n", d_mod_q);
    const char *plaintext = "RSA Algorithm";
    mpz_import(pt, strlen(plaintext), 1, 1, 0, 0, plaintext);

    if (mpz_cmp(pt, n) > 0)
        abort();

    mpz_powm(ct, pt, e, n);
    gmp_printf("Encoded Data:   %Zd\n\n", ct);

	/* Calculate Time using normal decoding routine */
	clock_t begin = clock();
    mpz_powm(pt, ct, d, n);
	clock_t end = clock();
	double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("Time Spent In Normal Mode:%f\n", time_spent);
    gmp_printf("Decoded Data in Normal Mode:   %Zd\n", pt);
    mpz_export(buffer, NULL, 1, 1, 0, 0, pt);
    printf("Data as String from Normal mode: %s\n\n", buffer);

	/* Precalculation for Chinese Remainder Theorm (CRT) */
	mpz_powm(Vp, ct, d_mod_p, p);
    mpz_powm(Vq, ct, d_mod_q, q);
	mpz_mul(VpXp,Vp,Xp);
	mpz_mul(VqXq,Vq,Xq);
	mpz_add(SUM,VpXp,VqXq);

 	/* Using CRT for Decryption */
	clock_t begin_crt = clock();
    mpz_mod(pt_crt,SUM,n);
	clock_t end_crt = clock();
	double time_spent_crt = (double)(end_crt - begin_crt) / CLOCKS_PER_SEC;
	printf("Time spent in CRT mode:%f\n", time_spent_crt);
    gmp_printf("Decoded Data in CRT Mode:   %Zd\n", pt_crt);
    mpz_export(buffer_crt, NULL, 1, 1, 0, 0, pt_crt);
    printf("Data as String from CRT: %s\n\n", buffer_crt);
    printf("Optimization Achieved is : %.1lf%%\n\n", (((time_spent-time_spent_crt)/time_spent_crt)*100));

    mpz_clears(pt, ct, n, e, d, NULL);
    mpz_clears(pt_crt, ct, n, e, d, NULL);
    return 0;
}

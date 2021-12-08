#include "ecc.h"
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <fcntl.h>
#include <math.h>


typedef struct cipherec {
	point *c1, *c2;
} cipherec;


typedef struct elgam_ec_ctx {
  mpz_t priv_key, eph_k;
  point *pub_key;
  elliptic_curve *ec;
} elgam_ec_ctx;


void init_elgam_ec(elgam_ec_ctx **eec_ctx)
{
	*eec_ctx = (elgam_ec_ctx*) malloc(sizeof(elgam_ec_ctx));
   	elliptic_curve *ecc = malloc(sizeof(elliptic_curve));
   	(*eec_ctx)->ec = ecc;

   	mpz_set_str(ecc->a, "340E7BE2A280EB74E2BE61BADA745D97E8F7C300", 16);
   	mpz_set_str(ecc->b, "1E589A8595423412134FAA2DBDEC95C8D8675E58", 16);
   	mpz_set_str(ecc->p, "E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16);

	mpz_init((*eec_ctx)->priv_key);
	init_point(&(ecc->base));
	init_point(&((*eec_ctx)->pub_key));

	mpz_set_str(ecc->base->x, "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", 16);
	mpz_set_str(ecc->base->y, "1667CB477A1A8EC338F94741669C976316DA6321", 16);
	gmp_printf("\np = %Zd\n", ecc->p);
	mpz_set_str((*eec_ctx)->priv_key, "7526351870759818498791637802193967358605", 16);
	gmp_printf("X = %Zd\n", (*eec_ctx)->priv_key);

	mpz_t tmp;
	mpz_init_set(tmp, (*eec_ctx)->priv_key);
	(*eec_ctx)->pub_key = ecc_scalar_mul((*eec_ctx)->ec, tmp, ecc->base);
	mpz_clears(tmp, NULL);
	gmp_printf("Base point P = (%Zd,%Zd)\n", ecc->base->x, ecc->base->y);
	gmp_printf("Public key xP =  (%Zd,%Zd)\n\n", ((*eec_ctx)->pub_key)->x, ((*eec_ctx)->pub_key)->y);
}





void destroy_elgam_ec(elgam_ec_ctx *eec_ctx)
{
	if (eec_ctx) {
		mpz_clears(eec_ctx->priv_key, eec_ctx->eph_k, NULL);
		mpz_clears(eec_ctx->ec->a, eec_ctx->ec->b, eec_ctx->ec->p, NULL);
		destroy_point(eec_ctx->ec->base);
		destroy_point(eec_ctx->pub_key);
		if (eec_ctx->ec) {
			free(eec_ctx->ec);
			eec_ctx->ec = NULL;
		}
		free(eec_ctx);
		eec_ctx = NULL;
	}
}


cipherec* encrypt_ec(elgam_ec_ctx *eec, point *pm)
{
	gmp_printf("Message to be encrypted :(%Zd,%Zd)\n", pm->x, pm->y);

	mpz_init(eec->eph_k);
	mpz_set_str(eec->eph_k, "3286956185438058443321138297203732852104", 16);
	gmp_printf("Random key = %Zd\n", eec->eph_k);

	cipherec *cipher = malloc(sizeof(cipherec));
	init_point(&cipher->c1);
	init_point(&cipher->c2);
	mpz_t tmp;
	mpz_init_set(tmp, eec->eph_k);
	cipher->c1 = ecc_scalar_mul(eec->ec, tmp, eec->ec->base);
	mpz_clears(tmp, NULL);

	mpz_init_set(tmp, eec->eph_k);
	cipher->c2 = ecc_scalar_mul(eec->ec, tmp, eec->pub_key);
	mpz_clears(tmp, NULL);
	gmp_printf("Cipher c1: (%Zd,%Zd)\n", cipher->c1->x, cipher->c1->y);
	gmp_printf("Cipher c2 without msg: (%Zd,%Zd)\n", cipher->c2->x, cipher->c2->y);
	cipher->c2 = ecc_addition(eec->ec, cipher->c2, pm);
	gmp_printf("Cipher c2 with msg: (%Zd,%Zd)\n", cipher->c2->x, cipher->c2->y);
	mpz_clears(eec->eph_k, NULL);
	return cipher;
}


point* decrypt_ec(elgam_ec_ctx *eec, cipherec *c)
{
	point *d1, *d2;
	init_point(&d1);
	init_point(&d2);
	mpz_t tmp;
	mpz_init_set(tmp, eec->priv_key);
	d1 = ecc_scalar_mul(eec->ec, tmp, c->c1);

	mpz_clears(tmp, NULL);
	gmp_printf("D1=(%Zd,%Zd)\n", d1->x, d1->y);
	gmp_printf("Before neg: (%Zd,%Zd)\n", d1->x, d1->y);
	mpz_neg(d1->y, d1->y);
	gmp_printf("After neg: (%Zd,%Zd)\n", d1->x, d1->y);
	d2 = ecc_addition(eec->ec, c->c2, d1);
	gmp_printf("Decrypted: (%Zd,%Zd)\n", d2->x, d2->y);
	destroy_point(d1);
	return d2;
}


void destroy_cipherec(cipherec *c)
{
	if (c) {
		destroy_point(c->c1);
		destroy_point(c->c2);
		free(c);
		c = NULL;
	}
}

int main()
{

	elgam_ec_ctx *eec;
	init_elgam_ec(&eec);
	point *p;
	cipherec *c;
	init_point(&p);

	printf("Enter a value of X: ");
	gmp_scanf("%Zd", p->x);
	gmp_printf("p->x %Zd\n", p->x);

	printf("Enter a value of Y: ");
	gmp_scanf("%Zd", p->y);
	gmp_printf("p->x %Zd\n", p->y);

	c = encrypt_ec(eec, p);
	destroy_point(p);
	init_point(&p);

	p = decrypt_ec(eec, c);
	destroy_point(p);
	destroy_cipherec(c);

	destroy_elgam_ec(eec);

}

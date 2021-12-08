/*Elgamal implemented using gmp */
#include <gmp.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <math.h>

#define X "40622201812345"
mpz_t p,q,alpha;  //Prime numbers used for algorithm
mpz_t c1, c2; //output values


void generate_prime()
{
	gmp_randstate_t k_state;

	mpz_inits(p, q, NULL);
	gmp_randinit_mt(k_state);

	//generate seed based on time
	srand(time(0));
	int seed = rand();
	gmp_randseed_ui(k_state, seed);

	//Find random number q
	mpz_urandomb(q, k_state, 512);
	mpz_nextprime(q, q);
	mpz_mul_ui(p, q, 2);
	mpz_add_ui(p, q, 1);

	//Check whether p is prime, if not, keep trying to find prime q and then p
	while (mpz_probab_prime_p(p, 25) != 1) {
		mpz_nextprime(q, q);
		mpz_mul_ui(p, q, 2);
		mpz_add_ui(p, p, 1);
	}

	gmp_randclear(k_state);
}

/*Encrypt the message m */

void encryption(mpz_t m)
{
	int seed;
	mpz_t h, k,alpha,generator,x;
	mpz_t h_pow_k;
	mpz_t p_sub_1_div2, alpha_x, alpha_pow_2, one;
	gmp_randstate_t alpha_state;
	gmp_randstate_t k_state;
	mpz_inits(x,p_sub_1_div2, alpha_x, alpha_pow_2, one, NULL);
	mpz_inits(c1, c2,h, k, x,alpha,generator,h_pow_k, NULL);
	gmp_randinit_mt(alpha_state);
	gmp_randinit_mt(k_state);

	mpz_set_str(x, X, 10);
    //find random alpha
	srand(time(0));
	seed = rand();
	gmp_randseed_ui(alpha_state, seed);
	mpz_urandomb(alpha, alpha_state, 512);
	mpz_set_ui(one, 1);

	mpz_set(p_sub_1_div2, p);
	mpz_submul_ui(p_sub_1_div2, one, 0.5);

	//Generator for p
	while (mpz_cmp(p,alpha)<0)
	{
		mpz_powm(alpha_x, alpha, p_sub_1_div2, p); //alpha^((p-1)/2) mod p
		mpz_powm_ui(alpha_pow_2, alpha, 2, p); //alpha^2 mod p

		if (!(mpz_cmp_ui(alpha_x, 1) == 0) && !(mpz_cmp_ui(alpha_pow_2, 1) == 0)) {
			mpz_set(generator, alpha);
			break;
		}
		else{
			srand(time(0));
			int seed = rand();
			gmp_randseed_ui(alpha_state, seed);
			mpz_urandomb(alpha, alpha_state, 512);
		}
	}


	//find random k
	srand(time(0));
	seed = rand();
	gmp_randseed_ui(k_state, seed);
	mpz_urandomb(k, k_state, 512);
	while( mpz_cmp(p,k)<0)
	{
	  mpz_urandomb(k, k_state, 512);
    }

    gmp_printf("p: %Zd\n", p);
    gmp_printf("k value : %Zd\n", k);
	gmp_printf("x value : %Zd\n", x);
    gmp_printf("alpha: %Zd\n", alpha);

	//Compute c1 = (alpha^k)modp
	mpz_powm(c1, alpha, k, p);

	//Compute h = (alpha^x)modp
	mpz_powm(h, alpha, x, p);
	//Compute (h^k)modp
	mpz_powm(h_pow_k, h, k, p);

	//Compute c2 = m * h^k
	mpz_mul(c2, m, h_pow_k);

	gmp_printf("Cipher C1 and C2 is as follows :\n C1: %Zd\n C2: %Zd\n\n", c1, c2);

	mpz_clear(m);
	mpz_clears(p_sub_1_div2, alpha_pow_2, alpha_x, NULL);
	mpz_clears(x, one, alpha, h_pow_k, h, q, generator, k, NULL);
	gmp_randclear(k_state);
    gmp_randclear(alpha_state);

}

void decryption()
{
	//Decryption Check
	mpz_t x,c1_powx, c1_powx_inv, m2;
	mpz_inits(x,c1_powx, c1_powx_inv, m2, NULL);

	mpz_set_str(x, X, 10);

	//Compute (c1^x)modp
	mpz_powm(c1_powx, c1, x, p);

	//Compute ((c1^x)^-1)modp
	mpz_invert(c1_powx_inv, c1_powx, p);

	//Compute (c2 * (c1^x)^-1)modp
	mpz_mul(m2, c2, c1_powx_inv);
	mpz_mod(m2, m2, p);

	gmp_printf("Decrpyted message: %Zd\n", m2);

	mpz_clears(m2, c1, c2, p, x, c1_powx, c1_powx_inv, NULL);
}

int main()
{
	mpz_t m;

	mpz_init(m);


	generate_prime();

	printf("Enter a value of m: ");
	gmp_scanf("%Zd", m);
	gmp_printf("m: %Zd\n", m);

	encryption(m);

	decryption();

    return 0;
}

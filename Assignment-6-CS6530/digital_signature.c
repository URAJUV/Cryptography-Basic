#include <time.h>
#include <gmp.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>

#include "sha_256.h"

char message[100000] = {};
mpz_t p,q,g,x,y,h;
mpz_t r, s;
mpz_t Hm;

void NISTSigningAlgotithm()
{
    printf("\n\n\n***********************************************************Signature Generation***********************************************************");
    char* HmBuf;;
    int count=0;
    mpz_t k,kinv,t,one;
    gmp_randstate_t k_state;

    mpz_inits(k,kinv,t,one, NULL);
    mpz_set_str(one,"1", 10);
    HmBuf = _SHA1Hash(message);

    mpz_set_str(Hm, HmBuf, 16);

    printf("\nMessage Entered              : %s", message);
    gmp_printf("\nH(m) of message              : %Zd", Hm);

    // Generate random k < q-1
    gmp_randinit_mt(k_state);

    // Check if generated k is less than q-1
    while(1)
    {
        srand(time(0));
        int seed = rand() + count++;
        gmp_randseed_ui(k_state, seed);
        mpz_urandomb(k, k_state, 100);
        mpz_sub(t,q,one);
        if (mpz_cmp(t,k) >= 1) break;
    }
    
    // Calculate r = (g^k mod p) mod q
    mpz_powm(r,g,k,p);
    mpz_mod(r,r,q);
    
    //Find k inverse mod q
    mpz_invert(kinv,k,q);
    
    // Calculate s = [kInv (H(M) + x*r)] mod q
    mpz_mul(t,x, r);
    mpz_add(t,Hm,t);
    mpz_mul(t,t,kinv);
    mpz_mod(s,t,q);

    gmp_printf("\nSignature (r,s) generated    : (%Zd, %Zd)", r , s);
}

void NISTVerificationAlgotithm()
{
    printf("\n\n\n***********************************************************Signature Verification***********************************************************");
    mpz_t w,u1,u2,v,t1,t2;
    mpz_inits(w,u1,u2,v,t1,t2, NULL);

    // calculate w = sInv mod q
    mpz_invert(w,s,q);

    // calculate u1 = [H(M)w] mod q
    mpz_mul(u1,w,Hm);
    mpz_mod(u1,u1,q);
    
    // calculate u2 = rw mod q
    mpz_mul(u2,w,r);
    mpz_mod(u2,u2,q);

    // calculate = [(g^u1 * y^u2) mod p] mod q
    mpz_powm(t1,g,u1,p);
    mpz_powm(t2,y,u2,p);
    mpz_mul(t1,t1,t2);
    mpz_mod(t1,t1,p);
    mpz_mod(v,t1,q);

    gmp_printf("\nReceived r                   : %Zd", r);
    gmp_printf("\nReceived s                   : %Zd", s);
    gmp_printf("\nReceived H(m)                : %Zd", Hm);
    gmp_printf("\nGenerated v                  : %Zd", v);

    if (mpz_cmp(v,r) == 0)
    {
        gmp_printf("\n\nMessage received is VALID\n");
    }
    else
    {
        gmp_printf("\n\nMessage received is INVALID\n");
    }
}

void GenerateSystemVariable()
{
    gmp_randstate_t q_state;
    mpz_t t,pMin1,one;
    int seed;

    mpz_inits(t,pMin1,one, NULL);
    mpz_set_str(one,"1",10);

    // generate prime q randomly
    gmp_randinit_mt(q_state);
    srand(time(0));
    seed = rand();
    gmp_randseed_ui(q_state, seed);
    mpz_urandomb(q, q_state, 100);
    mpz_nextprime(q,q);
    
    gmp_randinit_mt(q_state);
    srand(time(0));
    seed = rand();
    gmp_randseed_ui(q_state, seed);
    mpz_urandomb(t, q_state, 1000);
    mpz_nextprime(t,t);
    
    // generate prime p randomly such that q|(p-1)
    while(1)
    {
        mpz_mul(p,q,t);
        mpz_add(p,p,one);
        if (mpz_probab_prime_p(p, 25)==1) break;
        mpz_add(t,t,one);
    }

    // find generator h of p such that h^((p-1) / q) mod p > 1
    mpz_div(h,p,q);mpz_div(h,h,q);
    mpz_sub(pMin1,p,one);
    while(1)
    {
        // (h^p-1) modp
        mpz_powm(t,h,pMin1,p);
        
        // break if (h^p-1)modp =1
        if (mpz_cmp(t,one) == 0) break;
        mpz_sub(g,g,one);
    }
    
    // calculate (p-1)/q
    mpz_div(pMin1,pMin1,q);

    // calculate g = h^((p-1)/q) mod p
    mpz_powm(g,h,pMin1,p);
}

void GenerateKeys()
{
    gmp_randstate_t x_state;
    int seed;

    // Generate private key x randomly
    gmp_randinit_mt(x_state);
    srand(time(0));
    seed = rand();
    gmp_randseed_ui(x_state, seed);
    mpz_urandomb(x, x_state, 10);

    // Calculate public key y = g^x mod p
    mpz_powm(y,g,x,p);
}

void DSASetup()
{
    mpz_inits(p,q,g,x,y,h, NULL);

    GenerateSystemVariable();
    GenerateKeys();

    printf("\n\n***********************************************************System Elements***********************************************************");
    gmp_printf("\nPrime Number P               : %Zd", p);
    gmp_printf("\nprime divisor of (p-1) Q     : %Zd", q);
    gmp_printf("\nGenerator G                  : %Zd", g);

    printf("\n\n\n***********************************************************Key Generation***********************************************************");
    gmp_printf("\nPrivate key x                : %Zd", x);
    gmp_printf("\nPublic key y                 : %Zd", y);
}

int main()
{
    printf("\n***********************************************************NIST DIGITAL SIGNATURE ALGORITHM***********************************************************");
    printf("\nEnter message to be signed   :");
    gets(message);

    DSASetup();

    NISTSigningAlgotithm();

    NISTVerificationAlgotithm();
    return 0;
}

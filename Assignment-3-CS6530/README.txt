Name: Uraj singh
Roll no: CS21m521
Email:Urajuv1984@gmail.com

Instructions to RUN

1. Install the gmp library on ubuntu
   sudo apt-get install libgmp3-dev
2. Compile the code run
   gcc -o rsa_out rsa.c -lgmp
3. RUN the code
	./rsa_out

Theory:
Algorithm
Encryption and decryption are of the following form, for
some plaintext block M and ciphertext block C.
C = M^e mod n
M = C^d mod n

p, q, two prime numbers (private, chosen)
n = pq (public, calculated)
e, with gcd(f(n), e) = 1; 1 < e < f(n) (public, chosen)
d congurent e inv (mod f(n)) (private, calculated)

Chinese Remainder Theorm Optimization in RSA

We wish to compute the value M = C^d mod n.
Let us define the following intermediate results:
Vp = C^d mod p Vq = C^d mod q
Following the CRT using Equation, define the quantities
Xp = q * (q^-1 mod p) Xq = p * (p^-1 mod q)
M = (VpXp + VqXq) mod n
Furthermore, we can simplify the calculation of Vp and Vq using Fermat’s theorem.
Vp = C^d mod(p-1) mod p
Vq = C^d mod(q-1) mod q
The quantities d mod (p - 1) and d mod (q - 1) can be precalculated.
The end result is that the calculation is approximately four times as fast as evaluating
M = C^d mod n directly.

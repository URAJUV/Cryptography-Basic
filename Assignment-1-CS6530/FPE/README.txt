Name: Uraj singh
Roll no: CS21m521
Email:Urajuv1984@gmail.com

Algorithm

	INPUT: an integer i in the range 0 < i <254;
	  a secret 128-bit key k;
	  the number of rounds r (=6 in our case).
	OUTPUT: Encrypted value c=E(k,i), an integer in the range 0<c<254
	b54 = i encoded as a 54-bit bitstring
	L0 = the leftmost 27 bits of b54
	R0 = the rightmost 27 bits of b54
	for j=1 to r do
	Lj=Rj−1
	Form a 128-bit block B as follows
	B=Rj−1||0…....0||bitstring8(j)
	E=DES-128(k,B)
	Rj=Lj−1 (the leftmost 27 bits of E)
	Return the decoded integer c from the 54-bit bitstring Lr||Rr

Compile the code run
	make

Clean the code run
	make clean

RUN the Format Preseving Encryption
	./fpe XXXXXXXXXXXXXXXX (i.e 16 digit CCN NUMBER)

This will cycle through n-rounds and will generate the encrypted Credit Card Numbers CCN,
wth format preseving encryption. Then it decrypts the cipertext to get back the original
Credit Card Number.


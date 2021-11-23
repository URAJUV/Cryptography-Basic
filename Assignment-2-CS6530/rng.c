#include <stdio.h>
#include <stdlib.h>
#include <math.h>

int calculate_gcd(int a, int b) {
	int temp;
	if(b > a) {
		temp = a;
		a = b;
		b = temp;
	}
	while(b != 0) {
		temp = a % b;
		a = b;
		b = temp;
	}
	return a;
}

void main(int argc, char* argv[]) {
	int i = 0;
	int number1 = 0, number2 = 0, gcd = 0;
	int total_generation = 1000000;
	int gcd_1_generation = 0;
	double approx_pi = 0;
	double gcd_1_probability = 0;
  
	for(i = 0; i < total_generation; i++) {
		number1 = rand();
		number2 = rand();
		gcd = calculate_gcd(number1, number2);
		if(gcd == 1) {
			gcd_1_generation += 1;
		}
	}
  printf("Out of %d random number generations, GCD was 1 during %d generations\n", total_generation, gcd_1_generation);
	gcd_1_probability = (double)(gcd_1_generation)/(double)(total_generation);
  printf("The probability that GCD of two random numbers x and y is 1 is: %f\n", gcd_1_probability);
	approx_pi = sqrt(6/gcd_1_probability);
	printf("Approximate value of pi using statistical determination is: %f\n", approx_pi);
  if(fabs(approx_pi - 3.14) < 0.01) {
    printf("The pseudorandom generator available in system library is not flawed.\n");
  } else {
    printf("The pseudorandom generator available in system library is flawed.\n");
  }
}

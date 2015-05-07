#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void){
   char in1[256] = "./bf_test/private_file";

   char in2[256] = "./bf_test/encrypt_file";
   char in3[256] = "./bf_test/decrypted_file";

   clock_t start, end;
   double extime;

	start = clock();
	decrypt(in1, in2, in3);
	end = clock();
	extime = (double)((end - start)*1000)/ CLOCKS_PER_SEC;

	printf("exec DECRYPT: %lf\n", extime);
}


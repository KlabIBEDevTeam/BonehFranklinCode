#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void){
   char in1[256] = "./bf_test/secret_data/secret_file";
   char in2[256] = "./bf_test/public_data/public_file";

   clock_t start, end;
   double extime;

	start = clock();
	setup(in1, in2);
	end = clock();
	extime = (double)((end - start)*1000)/ CLOCKS_PER_SEC;

	printf("exec SETUP: %lf\n", extime);
}


#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void){
   char in1[256] = "./bf_test/public_file";

   char in2[256] = "./bf_test/encrypt_file";
   char *in3 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
   char *in4 = "akira.kanaoka@is.sci.toho-u.ac.jp";

   clock_t start, end;
   double extime;

	start = clock();
	encrypt(in1, in2, in3, in4);
	end = clock();
	extime = (double)((end - start)*1000)/ CLOCKS_PER_SEC;

	printf("exec ENCRYPT: %lf\n", extime);

}


#include <stdio.h>
#include <string.h>
#include <time.h>

int main(void){
   char in1[256] = "./bf_test/secret_file";
   char in2[256] = "./bf_test/private_file";
   char in3[256] = "akira.kanaoka@is.sci.toho-u.ac.jp";

   clock_t start, end;
   double extime;

	start = clock();
	extract(in1, in2, in3);
	end = clock();
	extime = (double)((end - start)*1000)/ CLOCKS_PER_SEC;

	printf("exec EXTRACT: %lf\n", extime);

}

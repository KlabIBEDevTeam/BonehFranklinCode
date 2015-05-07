#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <tepla/ec.h>
#include <openssl/evp.h>

#define MAX_STRLEN 500
#define MAX_C2_BLOCK 100

char *b64_encode(char *s, int size);
char *b64_decode(char *s, int size);

char b64_itoc(int i);
int b64_ctoi(char c);

char btoc(char *b, int len);
void ctob(char *b, char *c, int ofst, int len);
char bitat(char *c, int ofst);

void setup(const unsigned char *secret, const unsigned char *public);
void extract(const unsigned char *secret, const unsigned char *private, const char *userID);
void encrypt(const unsigned char *public, const unsigned char *encrypt, const unsigned char *plaintext, const char *userID);
void decrypt(const unsigned char *private, const unsigned char *encrypt, const unsigned char *decrypt);

void setup(const unsigned char *secret, const unsigned char *public) {
	
	EC_PAIRING p;
	pairing_init(p, "ECBN254");
	
	mpz_t s;
	EC_POINT P;
	EC_POINT k_pub;	//sP

	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (unsigned long)time(NULL));
	
	FILE *out_setup1, *out_setup2;

	mpz_init(s);
	point_init(P, p->g2);
	point_init(k_pub, p->g2);

	mpz_urandomb(s, state, 254);
	point_random(P);

	point_mul(k_pub, s, P);

	out_setup1 = fopen(secret, "w");
	if(out_setup1 == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	size_t t;
	unsigned char *a;
	mpz_export(NULL, &t, 1, 1, 1, 0, s);
	a = malloc(t);
	mpz_export(a, &t, 1, 1, 1, 0, s);
	
	unsigned char *sec;
	int alen = mpz_sizeinbase(s,16)/2 + mpz_sizeinbase(s,16)%2;
	sec = b64_encode(a, alen);
	free(a);

	fprintf(out_setup1, "%s", sec);
	fclose(out_setup1);

	out_setup2 = fopen(public, "w");
	if(out_setup2 == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int len = point_get_str_length(P);
	char *s1 = (char *)malloc(sizeof(char)*len);
	char *s2 = (char *)malloc(sizeof(char)*len);
	point_get_str(s1, P);
	point_get_str(s2, k_pub);
	
	fprintf(out_setup2, "%s\n%s",s1,s2);

	fclose(out_setup2);

}

void extract(const unsigned char *secret, const unsigned char *private, const char *userID) {
	
	EC_PAIRING p;
	pairing_init(p, "ECBN254");

	EC_POINT q_id;
	EC_POINT d_id;	

	FILE *in_extract, *out_extract;

	point_init(q_id, p->g1);
	point_init(d_id, p->g1);
	
	point_map_to_point(q_id, userID, sizeof(userID), 128);

	in_extract = fopen(secret, "r");
	if(in_extract == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	unsigned char sec[129];
	fscanf(in_extract, "%s", sec);
	fclose(in_extract);

	unsigned char *in_buf;
	in_buf = b64_decode(sec, strlen(sec));

	mpz_t s;
	mpz_init(s);
	mpz_import(s, strlen(in_buf), 1, 1, 1, 0, in_buf);
	
	point_mul(d_id, s, q_id);
	
	out_extract = fopen(private, "w");
	if(out_extract == NULL) {
		printf("cannot open\n");
		exit(1);
	}
	
	int len = point_get_str_length(d_id);
	char *s1 = (char *)malloc(sizeof(char)*len);
	point_get_str(s1, d_id);

    fprintf(out_extract, "%s", s1);
	
	fclose(out_extract);

}

void encrypt(const unsigned char *public, const unsigned char *encrypt, const unsigned char *plaintext, const char *userID) {
	
	EC_PAIRING p;
	pairing_init(p, "ECBN254");
	
	mpz_t r;
	EC_POINT q_id;
	Element g_id;
	EC_POINT C1;
	Element temp;
	
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (unsigned long)time(NULL));
	
	FILE *in_encrypt, *out_encrypt;

	mpz_init(r);
	point_init(q_id, p->g1);
	element_init(g_id, p->g3);
	point_init(C1, p->g2);
	element_init(temp, p->g3);
	
	mpz_urandomb(r, state, 254);
	
        
	point_map_to_point(q_id, userID, sizeof(userID), 128);
	
	in_encrypt = fopen(public, "r");
	if(in_encrypt == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline[MAX_STRLEN];
	char readline2[MAX_STRLEN];
	fgets(readline, MAX_STRLEN, in_encrypt);
	fgets(readline2, MAX_STRLEN, in_encrypt);

	fclose(in_encrypt);

	EC_POINT P, k_pub;
	point_init(P, p->g2);
	point_init(k_pub, p->g2);
	point_set_str(P, readline);
	point_set_str(k_pub, readline2);
	
	pairing_map(g_id, q_id, k_pub, p);

	point_mul(C1, r, P);
	element_pow(temp, g_id, r);

	unsigned char temp_buf[129];
	size_t temp_bufsize;
	element_to_oct(temp_buf, &temp_bufsize, temp);

	const EVP_MD *m;
	OpenSSL_add_all_digests();
	m = EVP_get_digestbyname("SHA512");
	unsigned char md_value[EVP_MAX_MD_SIZE];

	int md_len;
	EVP_MD_CTX *ctx;
	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, m, NULL);
	EVP_DigestUpdate(ctx, temp_buf, temp_bufsize);
	EVP_DigestFinal_ex(ctx, md_value, &md_len);
	EVP_MD_CTX_destroy(ctx);

	int m_split;
	int surplus;
	int i, j;

	m_split = strlen(plaintext)/md_len;
	surplus = strlen(plaintext)%md_len;

	if(surplus != 0) {
		m_split++;
	}
	unsigned char *M[m_split];

	for(i=0; i<m_split; i++) {
		M[i] = (unsigned char *)malloc(sizeof(unsigned char)*md_len);
		strncpy(M[i], plaintext+i*md_len, md_len);
		if(strlen(M[i]) != md_len) {
			for(j=strlen(M[i]); j<md_len; j++) {
				M[i][j] = 0;
			}
		}
	}

	unsigned char *C[m_split];
	for(i=0;i<m_split;i++){
		C[i] = (unsigned char *)malloc(sizeof(unsigned char)*md_len);
		for(j=0;j<md_len;j++){
			C[i][j] = M[i][j]^md_value[j];
		}
	}

	out_encrypt = fopen(encrypt, "w");
	if(out_encrypt == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	int len= point_get_str_length(C1);
	char *s1 = (char *)malloc(sizeof(char)*len);
	point_get_str(s1, C1);
	fprintf(out_encrypt, "%s\n", s1);
	
	unsigned char *sec;
	for(i=0;i<m_split;i++){
		sec = (unsigned char *)malloc(sizeof(unsigned char)*md_len);
		sec = b64_encode(C[i], md_len);
		fprintf(out_encrypt, "%s\n", sec);
	}

	for(i=0;i<m_split;i++){
		free(M[i]);
		free(C[i]);
	}
  
	fclose(out_encrypt);
}

void decrypt(const unsigned char *private, const unsigned char *encrypt, const unsigned char *decrypt) {
	
	EC_PAIRING p;
	pairing_init(p, "ECBN254");
	
	Element decele;
	Element temp;
		
	gmp_randstate_t state;
	gmp_randinit_default(state);
	gmp_randseed_ui(state, (unsigned long)time(NULL));

	FILE *in_decrypt1, *in_decrypt2, *in_decrypt3;

	element_init(decele, p->g3);
	element_init(temp, p->g3);

	in_decrypt1 = fopen(private, "r");
	if(in_decrypt1 == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	char readline[MAX_STRLEN];
	fgets(readline, MAX_STRLEN, in_decrypt1);

	fclose(in_decrypt1);

	EC_POINT d_id;
	point_init(d_id, p->g1);
	point_set_str(d_id, readline);

	in_decrypt2 = fopen(encrypt, "r");
	if(in_decrypt2 == NULL) {
		printf("cannot open\n");
		exit(1);
	}

	fgets(readline, MAX_STRLEN, in_decrypt2);	

	EC_POINT C1;
	point_init(C1, p->g2);
	point_set_str(C1, readline);

	int i,j;
	int c_block = 0;
	unsigned char *C2[MAX_C2_BLOCK];
	while(fgets(readline, MAX_STRLEN, in_decrypt2)!=NULL){
		int pos = 0;
		for(i=0;i<sizeof(readline);i++){
			if(readline[i]=='\n'){
				pos=i;
				i=sizeof(readline);
			}	
		}
		C2[c_block] = b64_decode(readline, pos);
		c_block++;
	}

	fclose(in_decrypt2);

	pairing_map(temp, d_id, C1, p);

	unsigned char temp_buf[129];
	size_t temp_bufsize;
	element_to_oct(temp_buf, &temp_bufsize, temp);
	
	const EVP_MD *m;
	OpenSSL_add_all_digests();
	m = EVP_get_digestbyname("SHA512");
	unsigned char md_value[EVP_MAX_MD_SIZE];

	int md_len;
	EVP_MD_CTX *ctx;
	ctx = EVP_MD_CTX_create();
	EVP_DigestInit_ex(ctx, m, NULL);
	EVP_DigestUpdate(ctx, temp_buf, temp_bufsize);
	EVP_DigestFinal_ex(ctx, md_value, &md_len);
	EVP_MD_CTX_destroy(ctx);

	in_decrypt3 = fopen(decrypt, "w");
	if(in_decrypt3 == NULL) {
		printf("cannot open\n");
		exit(1);
	}
	unsigned char *M;
	for(i=0;i<c_block;i++){
		M = (unsigned char *)malloc(sizeof(unsigned char)*md_len);
		for(j=0;j<md_len;j++){
			M[j] = C2[i][j]^md_value[j];
			if(M[j]!=0)fprintf(in_decrypt3, "%c",M[j]);
		}
	}
	fclose(in_decrypt3);

}


char *b64_encode(char *s, int size){
   int i, ensize = (8 * size + 5) / 6; 
   char b[6 * ensize];
   int eqsize = (ensize + 3) / 4 * 4 - ensize; 
   char *en = (char *)malloc(sizeof(char) * (ensize + eqsize + 1));
   char s0[size + 1];
   memcpy(s0, s, size);
   s0[size] = 0;
   ctob(b, s0, 0, 6 * ensize); 
   for(i = 0; i < ensize; ++i) en[i] = b64_itoc((int)btoc(b + i * 6, 6)); 
   for(i = 0; i < eqsize; ++i) en[ensize + i] = '=';
   en[ensize + eqsize] = '\0';
   return en;
}

char *b64_decode(char *s, int size){
   int i, tsize = 4 * ((size * 3) / 4);
   char c[tsize];
   for(i = 0; i < size; ++i) c[i] = b64_ctoi(s[i]);
   for(i = size; i < tsize; ++i) c[i] = 0;
   char b[6 * tsize];
   for(i = 0; i < tsize; ++i) ctob(b + 6 * i, c + i, 2, 6); // read 6 char for each c with ofst 2
   char *de = (char *)malloc(sizeof(char) * (tsize / 4 * 3 + 1));
   for(i = 0; i < tsize / 4 * 3; ++i) de[i] = btoc(b + 8 * i, 8); // get c from b
   de[tsize / 4 * 3] = '\0';
   return de;
}


char b64_itoc(int i){
   if(i <= 25) return 'A' + i;
   if(i <= 51) return 'a' + i - 26;
   if(i <= 61) return '0' + i - 52;
   if(i == 62) return '+';
   return '/';
}

int b64_ctoi(char c){
   if('A' <= c && c <= 'Z') return c - 'A';
   if('a' <= c && c <= 'z') return c - 'a' + 26;
   if('0' <= c && c <= '9') return c - '0' + 52;
   if(c == '+') return 62;
   if(c == '/') return 63;
   return 0;
}

char btoc(char *b, int len){
   int i;
   char c = 0;
   for(i = 0; i < len; ++i){c <<= 1; c |= b[i];}
   return c;
}

void ctob(char *b, char *c, int ofst, int len){
   int k;
   for(k = 0; k < len; ++k) b[k] = bitat(c, ofst + k);
}

char bitat(char *c, int ofst){
   c += ofst / 8;
   return ((*c) >> (7 - ofst % 8)) & 1;
}



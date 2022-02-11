#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "ecrypt-sync.h"

void ghash(unsigned char* N, unsigned char* A, unsigned char* C, unsigned char* k1, unsigned char* k2, unsigned int N_len, unsigned int A_len, unsigned int C_len, unsigned char* mac) {
	ECRYPT_ctx x;
	unsigned char block_1[32] = { 0, }, block_2[16] = { 0, }, hash[64] = { 0, };
	unsigned char xor_1[32] = { 0, }, xor_2[16] = { 0, };
	unsigned char* test;
	int i = 0, j = 0, k = 0, v = 0;

	
	int xtdSize = ceil((double)(A_len + N_len + C_len + 16) / 48);//384bits로 나뉜 block
	test = (unsigned char*)calloc((xtdSize * 48) , sizeof(unsigned char));

	memcpy(test, N, N_len);
	memcpy(test + N_len, A, A_len);
	memcpy(test + N_len + A_len, C, C_len);
	
	if (xtdSize * 48 - (N_len + A_len + C_len + 16) != 0) {
		v = xtdSize * 48 - (N_len + A_len + C_len + 16);
		memset(test + N_len + A_len + C_len, 0, 
			v+16);
	}


	for (i = 1, j = 1, k = 0; (N_len + A_len + C_len) * 8 > j * 256;i++, j *= 256);
	k = i;

	for (i = 0; i < k; i++) {
		test[N_len + A_len + C_len + v + 16 - k + i] = ((N_len + A_len + C_len) * 8 >> (k - i - 1) * 8);
	
	}

	memcpy(xor_1, k1, 32);
	memcpy(xor_2, k2, 16);


	for (i = 0; i < xtdSize; i++) {
		for (j = 0; j < 32; j++) {
			block_1[j] = test[i * 48 + j] ^ xor_1[j];
		}

		for (j = 0; j < 16; j++) {
			block_2[j] = test[i * 48 + 32 + j] ^ xor_2[j];
		}

		memset(hash, 0, 64);

		ECRYPT_keysetup(&x, block_1, 256, 128); // key를 이용한 설정
		ECRYPT_ivsetup(&x, block_2);
		ECRYPT_encrypt_bytes(&x, hash, hash, 64);

		memcpy(xor_1, hash, 32);
		memcpy(xor_2, hash + 32, 16);
	}

	memcpy(mac, hash, 16);
	
	free(test);
}
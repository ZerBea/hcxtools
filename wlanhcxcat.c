#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdio_ext.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include "common.c"
#include "com_md5_64.c"


bool hex2bin(const char *str, uint8_t *bytes, size_t blen);

struct hcxhrc
{
 uint32_t salt_buf[64];
 uint32_t pke[25];
 uint32_t eapol[64 + 16];
 uint32_t keymic[4];
};
typedef struct hcxhrc hcxhrc_t;

/*===========================================================================*/
/* globale Variablen */

hcx_t *hcxdata;
FILE *fhpot;
/*===========================================================================*/
void ausgabe(hcx_t *hcxrecord, char *password)
{
int i;
hcxhrc_t hashrec;
uint32_t hash[4];
uint32_t block[16];
uint8_t *block_ptr = (uint8_t*)block;
uint8_t *pke_ptr = (uint8_t*)hashrec.pke;
uint8_t *eapol_ptr = (uint8_t*)hashrec.eapol;

char essidstring[36];

hash[0] = 0;
hash[1] = 1;
hash[2] = 2;
hash[3] = 3;
memset(&block, 0, sizeof(block));

memset(&hashrec, 0, sizeof(hashrec));
memcpy(&hashrec.salt_buf, hcxrecord->essid, hcxrecord->essid_len);

memcpy(pke_ptr, "Pairwise key expansion", 23);
if(memcmp(hcxrecord->mac_ap.addr, hcxrecord->mac_sta.addr, 6) < 0)
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_ap.addr,  6);
	memcpy(pke_ptr + 29, hcxrecord->mac_sta.addr, 6);
	}
else
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_sta.addr, 6);
	memcpy(pke_ptr + 29, hcxrecord->mac_ap.addr,  6);
	}

if(memcmp(hcxrecord->nonce_ap, hcxrecord->nonce_sta, 32) < 0)
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_ap,  32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_sta, 32);
	}
else
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_sta, 32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_ap,  32);
	}
for (int i = 0; i < 25; i++)
	{
	hashrec.pke[i] = byte_swap_32(hashrec.pke[i]);
	}

memcpy(eapol_ptr, hcxrecord->eapol, hcxrecord->eapol_len);
memset(eapol_ptr + hcxrecord->eapol_len, 0, (256 +64) -hcxrecord->eapol_len);
eapol_ptr[hcxrecord->eapol_len] = 0x80;

memcpy (&hashrec.keymic, hcxrecord->keymic, 16);

if(hcxrecord->keyver == 1)
	{
	// nothing to do
	}
else
	{
	for(i = 0; i < 64; i++)
		{
		hashrec.eapol[i] = byte_swap_32 (hashrec.eapol[i]);
		}
	hashrec.keymic[0] = byte_swap_32(hashrec.keymic[0]);
	hashrec.keymic[1] = byte_swap_32(hashrec.keymic[1]);
	hashrec.keymic[2] = byte_swap_32(hashrec.keymic[2]);
	hashrec.keymic[3] = byte_swap_32(hashrec.keymic[3]);
	}

memset(&essidstring, 0, 36);
memcpy(&essidstring, hcxrecord->essid, hcxrecord->essid_len);

for(i = 0; i < 16; i++)
	block[i] = hashrec.salt_buf[i];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.pke[i +0];
md5_64(block, hash);

for(i = 0; i < 9; i++)
	block[i] = hashrec.pke[i +16];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +0];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +16];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +32];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i + 48];
md5_64 (block, hash);

for(i = 0; i < 6; i++)
	block_ptr[i +0] = hcxrecord->mac_ap.addr[i];
for(i = 0; i < 6; i++)
	block_ptr[i +6] = hcxrecord->mac_sta.addr[i];
md5_64 (block, hash);

for(i = 0; i < 32; i++)
	block_ptr[i +0] = hcxrecord->nonce_ap[i];
for(i = 0; i < 32; i++)
	block_ptr[i +32] = hcxrecord->nonce_sta[i];
md5_64 (block, hash);

block[0] = hashrec.keymic[0];
block[1] = hashrec.keymic[1];
block[2] = hashrec.keymic[2];
block[3] = hashrec.keymic[3];
md5_64 (block, hash);

memset(&essidstring, 0, 36);
memcpy(&essidstring, hcxrecord->essid, hcxrecord->essid_len);
printf("%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s:%s\n",
	hash[0], hash[1], hash[2], hash[3],
	hcxrecord->mac_ap.addr[0], hcxrecord->mac_ap.addr[1], hcxrecord->mac_ap.addr[2], hcxrecord->mac_ap.addr[3], hcxrecord->mac_ap.addr[4], hcxrecord->mac_ap.addr[5],
	hcxrecord->mac_sta.addr[0], hcxrecord->mac_sta.addr[1], hcxrecord->mac_sta.addr[2], hcxrecord->mac_sta.addr[3], hcxrecord->mac_sta.addr[4], hcxrecord->mac_sta.addr[5],
	essidstring, password);

if(fhpot != NULL)
	{
	fprintf(fhpot, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s:%s\n",
	hash[0], hash[1], hash[2], hash[3],
	hcxrecord->mac_ap.addr[0], hcxrecord->mac_ap.addr[1], hcxrecord->mac_ap.addr[2], hcxrecord->mac_ap.addr[3], hcxrecord->mac_ap.addr[4], hcxrecord->mac_ap.addr[5],
	hcxrecord->mac_sta.addr[0], hcxrecord->mac_sta.addr[1], hcxrecord->mac_sta.addr[2], hcxrecord->mac_sta.addr[3], hcxrecord->mac_sta.addr[4], hcxrecord->mac_sta.addr[5],
	essidstring, password);
	}

return;
}
/*===========================================================================*/
int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
	CMAC_CTX *ctx;
	int ret = -1;
	size_t outlen, i;

	ctx = CMAC_CTX_new();
	if (ctx == NULL)
		return -1;

	if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL))
		goto fail;
	for (i = 0; i < num_elem; i++) {
		if (!CMAC_Update(ctx, addr[i], len[i]))
			goto fail;
	}
	if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16)
		goto fail;

	ret = 0;
fail:
	CMAC_CTX_free(ctx);
	return ret;
}
/*===========================================================================*/
int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
	return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
/*===========================================================================*/
void generatepkeprf(hcx_t *hcxrecord, uint8_t *pke_ptr)
{
memcpy(pke_ptr, "Pairwise key expansion", 22);
if(memcmp(hcxrecord->mac_ap.addr, hcxrecord->mac_sta.addr, 6) < 0)
	{
	memcpy(pke_ptr + 22, hcxrecord->mac_ap.addr,  6);
	memcpy(pke_ptr + 28, hcxrecord->mac_sta.addr, 6);
	}
else
	{
	memcpy(pke_ptr + 22, hcxrecord->mac_sta.addr, 6);
	memcpy(pke_ptr + 28, hcxrecord->mac_ap.addr,  6);
	}
if(memcmp(hcxrecord->nonce_ap, hcxrecord->nonce_sta, 32) < 0)
	{
	memcpy (pke_ptr + 34, hcxrecord->nonce_ap,  32);
	memcpy (pke_ptr + 66, hcxrecord->nonce_sta, 32);
	}
else
	{
	memcpy (pke_ptr + 34, hcxrecord->nonce_sta, 32);
	memcpy (pke_ptr + 66, hcxrecord->nonce_ap,  32);
	}
return;
}
/*===========================================================================*/
void generatepke(hcx_t *hcxrecord, uint8_t *pke_ptr)
{
memcpy(pke_ptr, "Pairwise key expansion", 23);
if(memcmp(hcxrecord->mac_ap.addr, hcxrecord->mac_sta.addr, 6) < 0)
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_ap.addr,  6);
	memcpy(pke_ptr + 29, hcxrecord->mac_sta.addr, 6);
	}
else
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_sta.addr, 6);
	memcpy(pke_ptr + 29, hcxrecord->mac_ap.addr,  6);
	}

if(memcmp(hcxrecord->nonce_ap, hcxrecord->nonce_sta, 32) < 0)
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_ap,  32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_sta, 32);
	}
else
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_sta, 32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_ap,  32);
	}
return;
}
/*===========================================================================*/
void hcxpmk(long int hcxrecords, char *pmkname)
{
int p;

long int c;
hcx_t *zeigerhcx;

uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

if(hex2bin(pmkname, pmkin, 32) != true)
	{
	fprintf(stderr, "error wrong plainmasterkey value (allowed: 64 xdigits)\n");
	exit(EXIT_FAILURE);
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memset(&pkedata, 0, sizeof(mic));
	memcpy(&pmk, &pmkin, 32);
	if(zeigerhcx->keyver == 1)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_md5(), &ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		}

	else if(zeigerhcx->keyver == 2)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		}

	else if(zeigerhcx->keyver == 3)
		{
		generatepkeprf(zeigerhcx, pkedata);
		pkedata_prf[0] = 1;
		pkedata_prf[1] = 0;
		memcpy (pkedata_prf + 2, pkedata, 98);
		pkedata_prf[100] = 0x80;
		pkedata_prf[101] = 1;
		HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
		omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
		}
	if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
		ausgabe(zeigerhcx, pmkname);
	c++;
	}
return;
}
/*===========================================================================*/
void hcxessidpmk(long int hcxrecords, char *essidname, int essidlen, char *pmkname)
{
int p;

long int c;
hcx_t *zeigerhcx;
uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

unsigned char essid[32];

if(hex2bin(pmkname, pmkin, 32) != true)
	{
	fprintf(stderr, "error wrong plainmasterkey value (allowed: 64 xdigits)\n");
	exit(EXIT_FAILURE);
	}

memset(&essid, 0, 32);
memcpy(&essid, essidname, essidlen);

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&essid, zeigerhcx->essid, 32) == 0)
		{
		memset(&pkedata, 0, sizeof(pkedata));
		memset(&pkedata_prf, 0, sizeof(pkedata_prf));
		memset(&ptk, 0, sizeof(ptk));
		memset(&pkedata, 0, sizeof(mic));
		memcpy(&pmk, &pmkin, 32);
		if(zeigerhcx->keyver == 1)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_md5(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			}

		else if(zeigerhcx->keyver == 2)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			}

		else if(zeigerhcx->keyver == 3)
			{
			generatepkeprf(zeigerhcx, pkedata);
			pkedata_prf[0] = 1;
			pkedata_prf[1] = 0;
			memcpy (pkedata_prf + 2, pkedata, 98);
			pkedata_prf[100] = 0x80;
			pkedata_prf[101] = 1;
			HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
			omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
			}

		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			ausgabe(zeigerhcx, pmkname);
		}
	c++;
	}
return;
}
/*===========================================================================*/
void hcxpassword(long int hcxrecords, char *passwordname, int passwordlen)
{
int p;

long int c;
hcx_t *zeigerhcx;
hcx_t *zeigerhcx2;
uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memset(&pkedata, 0, sizeof(mic));
	memcpy(&pmk, &pmkin, 32);
	memset(&mic, 0, 16);
	if(c > 0)
		{
		zeigerhcx2 = hcxdata +c -1;
		if(memcmp(zeigerhcx->essid, zeigerhcx2->essid, 32) != 0)
			{
			if(PKCS5_PBKDF2_HMAC(passwordname, passwordlen, zeigerhcx->essid, zeigerhcx->essid_len, 4096, EVP_sha1(), 32, pmkin) == 0)
				{
				fprintf(stderr, "could not generate plainmasterkey\n");
				return;
				}
			memcpy(&pmk, &pmkin, 32);
			}
		}	
	else if(c == 0)
		{
		if(PKCS5_PBKDF2_HMAC(passwordname, passwordlen, zeigerhcx->essid, zeigerhcx->essid_len, 4096, EVP_sha1(), 32, pmkin) == 0)
			{
			fprintf(stderr, "could not generate plainmasterkey\n");
			return;
			}
		memcpy(&pmk, &pmkin, 32);
		}
	if(zeigerhcx->keyver == 1)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_md5(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		}

	else if(zeigerhcx->keyver == 2)
		{
		generatepke(zeigerhcx, pkedata);
		for (p = 0; p < 4; p++)
			{
			pkedata[99] = p;
			HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
			}
		HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
		}

	else if(zeigerhcx->keyver == 3)
		{
		generatepkeprf(zeigerhcx, pkedata);
		pkedata_prf[0] = 1;
		pkedata_prf[1] = 0;
		memcpy (pkedata_prf + 2, pkedata, 98);
		pkedata_prf[100] = 0x80;
		pkedata_prf[101] = 1;
		HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
		omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
		}

	if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
		ausgabe(zeigerhcx, passwordname);
	c++;
	}
return;
}
/*===========================================================================*/
void hcxessidpassword(long int hcxrecords, char *essidname, int essidlen, char *passwordname, int passwordlen)
{
int p;

long int c;
hcx_t *zeigerhcx;
uint8_t pmk[32];
uint8_t pmkin[32];
uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t mic[16];

unsigned char essid[32];

memset(&essid, 0, 32);
memcpy(&essid, essidname, essidlen);

if(PKCS5_PBKDF2_HMAC(passwordname, passwordlen, essid, essidlen, 4096, EVP_sha1(), 32, pmkin) == 0)
	{
	fprintf(stderr, "could not generate plainmasterkey\n");
	return;
	}

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&essid, zeigerhcx->essid, 32) == 0)
		{
		memset(&pkedata, 0, sizeof(pkedata));
		memset(&pkedata_prf, 0, sizeof(pkedata_prf));
		memset(&ptk, 0, sizeof(ptk));
		memset(&pkedata, 0, sizeof(mic));
		memcpy(&pmk, &pmkin, 32);
		if(zeigerhcx->keyver == 1)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_md5(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			}

		else if(zeigerhcx->keyver == 2)
			{
			generatepke(zeigerhcx, pkedata);
			for (p = 0; p < 4; p++)
				{
				pkedata[99] = p;
				HMAC(EVP_sha1(), pmk, 32, pkedata, 100, ptk + p * 20, NULL);
				}
			HMAC(EVP_sha1(), ptk, 16, zeigerhcx->eapol, zeigerhcx->eapol_len, mic, NULL);
			}

		else if(zeigerhcx->keyver == 3)
			{
			generatepkeprf(zeigerhcx, pkedata);
			pkedata_prf[0] = 1;
			pkedata_prf[1] = 0;
			memcpy (pkedata_prf + 2, pkedata, 98);
			pkedata_prf[100] = 0x80;
			pkedata_prf[101] = 1;
			HMAC(EVP_sha256(), pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
			omac1_aes_128(ptk, zeigerhcx->eapol, zeigerhcx->eapol_len, mic);
			}

		if(memcmp(&mic, zeigerhcx->keymic, 16) == 0)
			ausgabe(zeigerhcx, passwordname);
		}
	c++;
	}
return;
}
/*===========================================================================*/
size_t chop(char *buffer, size_t len)
{
char *ptr = buffer +len -1;

while(len)
	{
	if (*ptr != '\n')
		break;
	*ptr-- = 0;
	len--;
	}

while(len)
	{
	if (*ptr != '\r')
		break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
int fgetline(FILE *inputstream, size_t size, char *buffer)
{
if(feof(inputstream))
	return -1;
char *buffptr = fgets (buffer, size, inputstream);

if(buffptr == NULL)
	return -1;

size_t len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
void hcxwordlist(long int hcxrecords, char *wordlistname)
{
int len;
int p;
FILE * fhpwin = NULL;

char linein[66];

if(wordlistname == NULL)
	return;

if((fhpwin = fopen(wordlistname, "r")) == NULL)
	{
	fprintf(stderr, "error opening %s\n", wordlistname);
	return;
	}

while((len = fgetline(fhpwin, 66, linein)) != -1)
	{
	if(len < 8)
		continue;
	if(len == 64)
		{
		for(p = 0; p < 64; p++)
			if(!(isxdigit(linein[p])))
				continue;
		hcxpmk(hcxrecords, linein);
		continue;
		}
	if(len < 64)
		hcxpassword(hcxrecords, linein, len);
	}

if(fhpwin != NULL)
	fclose(fhpwin);
return;
}
/*===========================================================================*/
void hcxessidwordlist(long int hcxrecords, char *essidname, int essidlen, char *wordlistname)
{
int len;
int p;
FILE * fhpwin = NULL;

char linein[66];

if(wordlistname == NULL)
	return;

if((fhpwin = fopen(wordlistname, "r")) == NULL)
	{
	fprintf(stderr, "error opening %s\n", wordlistname);
	return;
	}

while((len = fgetline(fhpwin, 66, linein)) != -1)
	{
	if(len < 8)
		continue;
	if(len == 64)
		{
		for(p = 0; p < 64; p++)
			if(!(isxdigit(linein[p])))
				continue;
		hcxessidpmk(hcxrecords, essidname, essidlen, linein);
		continue;
		}
	if(len < 64)
		hcxessidpassword(hcxrecords, essidname, essidlen, linein, len);
	}

if(fhpwin != NULL)
	fclose(fhpwin);
return;
}
/*===========================================================================*/
int sort_by_essid(const void *a, const void *b) 
{ 
hcx_t *ia = (hcx_t *)a;
hcx_t *ib = (hcx_t *)b;

return memcmp(ia->essid, ib->essid, 32);
}
/*===========================================================================*/
long int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return 0;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return 0;
	}

if((statinfo.st_size % HCX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return 0;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxinname);
	return 0;
	}

hcxdata = malloc(statinfo.st_size);
if(hcxdata == NULL)	
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		return 0;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
if(hcxsize != statinfo.st_size)	
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return 0;
	}
fclose(fhhcx);

qsort(hcxdata, hcxsize / HCX_SIZE, sizeof(hcx_t), sort_by_essid);
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
bool hex2bin(const char *str, uint8_t *bytes, size_t blen)
{
size_t c;
uint8_t pos;
uint8_t idx0;
uint8_t idx1;

const uint8_t hashmap[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};

for(c = 0; c < blen; c++)
	{
	if(str[c] < '0')
		return false;
	if(str[c] > 'f')
		return false;
	if((str[c] > '9') && (str[c] < 'A'))
		return false;
	if((str[c] > 'F') && (str[c] < 'a'))
		return false;
	}

bzero(bytes, blen);
for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
	{
	idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
	idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
	bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
return true;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage..: %s <options>\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-w <file> : input wordlist, plainmasterkeylist oder mixed word-/plainmasterkeylist\n"
	"          : wordlist input is very slow\n"
	"-e        : input ESSID\n"
	"-p        : input password\n"
	"-P        : input plainmasterkey\n"
	"-o <file> : output recovered network data\n"
	"-h        : this help\n"
	"\n"
	"input option matrix\n"
	"-e and -p\n"
	"-e and -P\n"
	"-e and -w\n"
	"-p\n"
	"-P\n"
	"-w\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int p;
int essidlen = 0;
int passwordlen = 0;
int ret = 0;
long int hcxorgrecords = 0;
hcxdata = NULL;
fhpot = NULL;
struct stat statpot;
struct tm* tm_info;
struct timeval tv;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *essidname = NULL;
char *passwordname = NULL;
char *pmkname = NULL;
char *potname = NULL;
char *wordlistinname = NULL;

char zeitstring[26];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:e:p:P:w:o:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'e':
		essidname = optarg;
		essidlen = strlen(essidname);
		if((essidlen < 1) || (essidlen > 32))
			{
			fprintf(stderr, "error wrong essid len (allowed: 1 .. 32 characters)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'p':
		passwordname = optarg;
		passwordlen = strlen(passwordname);
		if((passwordlen < 8) || (passwordlen > 63))
			{
			fprintf(stderr, "error wrong password len (allowed: 8 .. 63 characters\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'P':
		pmkname = optarg;
		if(strlen(pmkname) != 64)
			{
			fprintf(stderr, "error wrong plainmasterkey len (allowed: 64 xdigits)\n");
			exit(EXIT_FAILURE);
			}
		for(p = 0; p < 64; p++)
			{
			if(!(isxdigit(pmkname[p])))
				{
				fprintf(stderr, "error wrong plainmasterkey len (allowed: 64 xdigits)\n");
				exit(EXIT_FAILURE);
				}
			}
		break;

		case 'o':
		potname = optarg;
		if((fhpot = fopen(potname, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", potname);
			exit(EXIT_FAILURE);
			}
		break;

		case 'w':
		wordlistinname = optarg;
		break;

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

if((essidname == 0) && (passwordname != NULL) && (pmkname != NULL) && (wordlistinname != NULL))
	{
	fprintf(stderr, "nothing to do\n");
	return EXIT_SUCCESS;
	}

hcxorgrecords = readhccapx(hcxinname);

if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

gettimeofday(&tv, NULL);
tm_info = localtime(&tv.tv_sec);
strftime(zeitstring, 26, "%H:%M:%S", tm_info);
printf("started at %s to test %ld records\n", zeitstring, hcxorgrecords);

if((essidname != NULL) && (passwordname != NULL))
	hcxessidpassword(hcxorgrecords, essidname, essidlen, passwordname, passwordlen);

if((essidname != NULL) && (pmkname != NULL))
	hcxessidpmk(hcxorgrecords, essidname, essidlen, pmkname);

if((passwordname != NULL) && (essidname == NULL))
	hcxpassword(hcxorgrecords, passwordname, passwordlen);

if((pmkname != NULL) && (essidname == NULL))
	hcxpmk(hcxorgrecords, pmkname);

if((wordlistinname != NULL) && (essidname != NULL))
	hcxessidwordlist(hcxorgrecords, essidname, essidlen, wordlistinname);

if((wordlistinname != NULL) && (essidname == NULL))
	hcxwordlist(hcxorgrecords, wordlistinname);

gettimeofday(&tv, NULL);
tm_info = localtime(&tv.tv_sec);
strftime(zeitstring, 26, "%H:%M:%S", tm_info);
printf("finished at %s\n", zeitstring);


if(hcxdata != NULL)
	free(hcxdata);

if(fhpot != NULL)
	{
	fclose(fhpot);
	stat(potname, &statpot);
	if(statpot.st_size == 0)
		ret = remove(potname);	
	if(ret != 0)
		fprintf(stderr, "could not remove empty file %s\n", potname);
	}

return EXIT_SUCCESS;
}

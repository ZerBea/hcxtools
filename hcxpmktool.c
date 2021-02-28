#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <getopt.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "include/hcxpmktool.h"
#include "include/ieee80211.h"

static uint8_t pmkcalculated[32];
static uint8_t pmkopt[32];

static uint8_t pmkidcalculated[EVP_MAX_MD_SIZE];
static uint8_t miccalculated[EVP_MAX_MD_SIZE];

static hashlist_t hashlist;

/*===========================================================================*/
/*===========================================================================*/
static bool calculatemic(uint8_t *pmk)
{
static int keyver;
static wpakey_t *wpak;
static uint8_t *pkeptr;
static size_t testptklen;
static size_t testmiclen;
static EVP_MD_CTX *mdctx;
static EVP_PKEY *pkey;

static uint8_t pkedata[102];
static uint8_t testptk[EVP_MAX_MD_SIZE];

wpak = (wpakey_t*)&hashlist.eapol[EAPAUTH_SIZE];
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if(keyver == 2)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&testptk, 0, sizeof(testptk));
	memset(&miccalculated, 0, sizeof(testptk));
	pkeptr = pkedata;
	memcpy(pkeptr, "Pairwise key expansion", 23);
	if(memcmp(hashlist.ap, hashlist.client, 6) < 0)
		{
		memcpy(pkeptr +23, hashlist.ap, 6);
		memcpy(pkeptr +29, hashlist.client, 6);
		}
	else
		{
		memcpy(pkeptr +23, hashlist.client, 6);
		memcpy(pkeptr +29, hashlist.ap, 6);
		}
	if(memcmp(hashlist.nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +35, hashlist.nonce, 32);
		memcpy (pkeptr +67, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +35, wpak->nonce, 32);
		memcpy (pkeptr +67, hashlist.nonce, 32);
		}
	testptklen = 32;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, pkedata, 100) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(mdctx);
	testmiclen = 16;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testptk, 16);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, hashlist.eapol, hashlist.eapauthlen) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, miccalculated, &testmiclen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return true;
	}
else if(keyver == 1)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&testptk, 0, sizeof(testptk));
	memset(&miccalculated, 0, sizeof(testptk));
	pkeptr = pkedata;
	memcpy(pkeptr, "Pairwise key expansion", 23);
	if(memcmp(hashlist.ap, hashlist.client, 6) < 0)
		{
		memcpy(pkeptr +23, hashlist.ap, 6);
		memcpy(pkeptr +29, hashlist.client, 6);
		}
	else
		{
		memcpy(pkeptr +23, hashlist.client, 6);
		memcpy(pkeptr +29, hashlist.ap, 6);
		}
	if(memcmp(hashlist.nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +35, hashlist.nonce, 32);
		memcpy (pkeptr +67, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +35, wpak->nonce, 32);
		memcpy (pkeptr +67, hashlist.nonce, 32);
		}
	testptklen = 32;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, pkedata, 100) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(mdctx);
	testmiclen = 16;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testptk, 16);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_md5(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, hashlist.eapol, hashlist.eapauthlen) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, miccalculated, &testmiclen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return true;
	}
else if(keyver == 3)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&testptk, 0, sizeof(testptk));
	memset(&miccalculated, 0, sizeof(testptk));
	pkedata[0] = 1;
	pkedata[1] = 0;
	pkeptr = pkedata +2;
	memcpy(pkeptr, "Pairwise key expansion", 22);
	if(memcmp(hashlist.ap, hashlist.client, 6) < 0)
		{
		memcpy(pkeptr +22, hashlist.ap, 6);
		memcpy(pkeptr +28, hashlist.client, 6);
		}
	else
		{
		memcpy(pkeptr +22, hashlist.client, 6);
		memcpy(pkeptr +28, hashlist.ap, 6);
		}
	if(memcmp(hashlist.nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +34, hashlist.nonce, 32);
		memcpy (pkeptr +66, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +34, wpak->nonce, 32);
		memcpy (pkeptr +66, hashlist.nonce, 32);
		}
	pkedata[100] = 0x80;
	pkedata[101] = 1;
	testptklen = 32;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, pkedata, 102) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(mdctx);
	testmiclen = 16;
	pkey = EVP_PKEY_new_CMAC_key(NULL, testptk, 16, EVP_aes_128_cbc());
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, hashlist.eapol, hashlist.eapauthlen) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, miccalculated, &testmiclen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	}
return true;
}
/*===========================================================================*/
static bool calculatepmkid(uint8_t *pmk)
{
static size_t pmkidcalculatedlen;
static EVP_MD_CTX *mdctx;
static EVP_PKEY *pkey;
static char *pmkname = "PMK Name";

static uint8_t message[32];

memcpy(&message, pmkname, 8);
memcpy(&message[8], hashlist.ap, 6);
memcpy(&message[14], hashlist.client, 6);
pmkidcalculatedlen = 16;
mdctx = EVP_MD_CTX_new();
if(mdctx == 0) return false;
pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, pmk, 32);
if(pkey == NULL)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
	{
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestSignUpdate(mdctx, message, 20) != 1)
	{
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestSignFinal(mdctx, pmkidcalculated, &pmkidcalculatedlen) <= 0)
	{
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return false;
	}
EVP_PKEY_free(pkey);
EVP_MD_CTX_free(mdctx);
return true;
}
/*===========================================================================*/
static bool dopbkdf2(int psklen, char *psk, int essidlen, uint8_t *essid)
{
if((essid == NULL) || (psk == NULL)) return false;
if(PKCS5_PBKDF2_HMAC_SHA1(psk, psklen, essid, essidlen, 4096, 32, pmkcalculated) == 0) return false;
return true;
}

/*===========================================================================*/
static void base64(const unsigned char* buffer, size_t len, char** b64text)
{
static BIO *bio, *b64;
static BUF_MEM *bufferPtr;

b64 = BIO_new(BIO_f_base64());
bio = BIO_new(BIO_s_mem());
bio = BIO_push(b64, bio);

BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
BIO_write(bio, buffer, len);
(void) BIO_flush(bio);
BIO_get_mem_ptr(bio, &bufferPtr);
(void) BIO_set_close(bio, BIO_NOCLOSE);
BIO_free_all(bio);
*b64text=(*bufferPtr).data;
return;
}
/*===========================================================================*/
static size_t getfield(char *lineptr, size_t bufflen, uint8_t *buff)
{
static size_t p;
static uint8_t idx0;
static uint8_t idx1;

static const uint8_t hashmap[] =
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

memset(buff, 0, bufflen);
p = 0;
while((lineptr[p] != '*') && (lineptr[p] != 0) && (p /2 <= bufflen))
	{
	if(!isxdigit(lineptr[p +0])) return 0;
	if(!isxdigit(lineptr[p +1])) return 0;
	if((lineptr[p +1] == '*') && (lineptr[p +1] == 0)) return 0;
	idx0 = ((uint8_t)lineptr[p +0] &0x1F) ^0x10;
	idx1 = ((uint8_t)lineptr[p +1] &0x1F) ^0x10;
	buff[p /2] = (uint8_t)(hashmap[idx0] <<4) | hashmap[idx1];
	p += 2;
	if((p /2) > bufflen) return 0;
	}
return p /2;
}
/*===========================================================================*/
static bool gethashlinefields(char *hashlinestring)
{
static char *hashlinedupa;
static char *token;
static size_t len;
static size_t p;
static char wpaf[] =
{
"WPA"
};

memset(&hashlist, 0, sizeof(hashlist_t));
if(hashlinestring == NULL) return false;

len = strlen(hashlinestring);
if(len < 69) return false;
if((hashlinestring[3] != '*') || (hashlinestring[6] != '*') || (hashlinestring[39] != '*') || (hashlinestring[52] != '*') || (hashlinestring[65] != '*'))
for(p = 7; p < len; p++)
	{
	if((!isxdigit(hashlinestring[p])) && (hashlinestring[p] != '*')) return false;
	}
hashlinedupa = strdupa(hashlinestring);
if(hashlinedupa == NULL) return false;
token = strsep(&hashlinedupa, "*");
if(token == NULL) return false;
len = strlen(token);
if(len != 3) return false;
if(memcmp(&wpaf, token, 3) != 0) return false;

token = strsep(&hashlinedupa, "*");
if(token == NULL) return false;
len = strlen(token);
if(len != 2) return false;

hashlist.type = strtol(token, NULL, 10);
if((hashlist.type != 1) && (hashlist.type != 2)) return false;

token = strsep(&hashlinedupa, "*");
if(token == NULL) return false;
len = strlen(token);
if(len != 32) return false;
if(getfield(token, HASH_LEN, hashlist.hash) != HASH_LEN) return false;

token = strsep(&hashlinedupa, "*");
if(token == NULL) return false;
len = strlen(token);
if(len != 12) return false;
if(getfield(token, 6, hashlist.ap) != 6) return false;
token = strsep(&hashlinedupa, "*");
if(token == NULL) return false;
len = strlen(token);
if(len != 12) return false;
if(getfield(token, 6, hashlist.client) != 6) return false;

token = strsep(&hashlinedupa, "*");
len = strlen(token);
if(((len %2) != 0) || (len > 64))  return false;
hashlist.essidlen = len /2;
if(getfield(token, hashlist.essidlen, hashlist.essid) != hashlist.essidlen) return false;
if(hashlist.type == 1) return true;

token = strsep(&hashlinedupa, "*");
len = strlen(token);
if(len != 64) return false;
if(getfield(token, 32, hashlist.nonce) != 32) return false;

token = strsep(&hashlinedupa, "*");
len = strlen(token);
if(((len %2) != 0) || (len > EAPOL_AUTHLEN_MAX *2)) return false;
if(getfield(token, EAPOL_AUTHLEN_MAX, hashlist.eapol) != len /2) return false;
hashlist.eapauthlen = len /2;

token = strsep(&hashlinedupa, "*");
len = strlen(token);
if(len != 2) return false;
hashlist.mp = strtol(token, NULL, 10);
free(hashlinedupa);
return true;
}
/*===========================================================================*/
static void showstandardinfohashlineessidpsk(char *hashlinestring, char *essidstring,  char *pskstring)
{
size_t p;
size_t psklen;
size_t essidlen;

if(gethashlinefields(hashlinestring) == false)
	{
	printf("hash line exception\n");
	return;
	}

essidlen = strlen(essidstring);
if((essidlen == 0) || (essidlen > ESSID_LEN_MAX))
	{
	fprintf(stderr, "ESSID length exception\n");
	return;
	}

psklen = strlen(pskstring);
if((psklen == 63) || (psklen > 63))
	{
	fprintf(stderr, "PSK length exception\n");
	return;
	}

if(dopbkdf2(psklen, pskstring, essidlen, (uint8_t*)essidstring) == false) 
	{
	fprintf(stderr, "PBKDF2 calculation error\n");
	return;
	}

if(calculatepmkid(pmkcalculated) == false)
	{
	fprintf(stderr, "MIC calculation error\n");
	return;
	}
else if(hashlist.type == HS_EAPOL)
	{
	if(calculatemic(pmkcalculated) == false)
		{
		fprintf(stderr, "MIC calculation error\n");
		return;
		}
	}
printf("ESSID (option)....: %s\n", essidstring);
printf("ESSID (hash line).: %.*s\n", hashlist.essidlen, hashlist.essid);
printf("PSK...............: %s\n", pskstring);
printf("PMK (ESSID option): ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkcalculated[p]);
printf("\n");
printf("PMKID (calculated): ");
for(p = 0; p < HASH_LEN; p++) printf("%02x", pmkidcalculated[p]);
printf("\n");
if(hashlist.type == HS_PMKID)
	{
	printf("PMKID (hash line).: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", hashlist.hash[p]);
	if(memcmp(&pmkidcalculated, &hashlist.hash, HASH_LEN) == 0) printf(" (equal)\n");
	else printf(" (not equal)\n");
	}
else if(hashlist.type == HS_EAPOL)
	{
	printf("MIC (calculated)..: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", miccalculated[p]);
	printf("\n");
	printf("MIC (hash line)...: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", hashlist.hash[p]);
	if(memcmp(&miccalculated, &hashlist.hash, HASH_LEN) == 0) printf(" (equal)\n");
	else printf(" (not equal)\n");
	}
return;
}
/*===========================================================================*/
static void showstandardinfohashlinepmk(char *hashlinestring, char *pmkstring)
{
size_t p;
size_t pmklen;

if(gethashlinefields(hashlinestring) == false)
	{
	printf("hash line exception\n");
	return;
	}

pmklen = strlen(pmkstring);
if(pmklen != 64)
	{
	fprintf(stderr, "PMK length exception\n");
	return;
	}

if(getfield(pmkstring, 32, pmkopt) != 32)
	{
	fprintf(stderr, "PMK length exception\n");
	return;
	}

if(calculatepmkid(pmkopt) == false)
	{
	fprintf(stderr, "MIC calculation error\n");
	return;
	}
else if(hashlist.type == HS_EAPOL)
	{
	if(calculatemic(pmkopt) == false)
		{
		fprintf(stderr, "MIC calculation error\n");
		return;
		}
	}

printf("ESSID.............: %.*s\n", hashlist.essidlen, hashlist.essid);
printf("PMK...............: ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkopt[p]);
printf("\n");
printf("PMKID (calculated): ");
for(p = 0; p < HASH_LEN; p++) printf("%02x", pmkidcalculated[p]);
printf("\n");
if(hashlist.type == HS_PMKID)
	{
	printf("PMKID (hash line).: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", hashlist.hash[p]);
	if(memcmp(&pmkidcalculated, &hashlist.hash, HASH_LEN) == 0) printf(" (equal)\n");
	else printf(" (not equal)\n");
	}
else if(hashlist.type == HS_EAPOL)
	{
	printf("MIC (calculated)..: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", miccalculated[p]);
	printf("\n");
	printf("MIC (hash line)...: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", hashlist.hash[p]);
	if(memcmp(&miccalculated, &hashlist.hash, HASH_LEN) == 0) printf(" (equal)\n");
	else printf(" (not equal)\n");
	}

return;
}
/*===========================================================================*/
static void showstandardinfohashlinepsk(char *hashlinestring, char *pskstring)
{
size_t p;
size_t psklen;

if(gethashlinefields(hashlinestring) == false)
	{
	printf("hash line exception\n");
	return;
	}

psklen = strlen(pskstring);
if((psklen == 63) || (psklen > 63))
	{
	fprintf(stderr, "PSK length exception\n");
	return;
	}

if(dopbkdf2(psklen, pskstring, hashlist.essidlen, hashlist.essid) == false) 
	{
	fprintf(stderr, "PBKDF2 calculation error\n");
	return;
	}

if(calculatepmkid(pmkcalculated) == false)
	{
	fprintf(stderr, "MIC calculation error\n");
	return;
	}
else if(hashlist.type == HS_EAPOL)
	{
	if(calculatemic(pmkcalculated) == false)
		{
		fprintf(stderr, "MIC calculation error\n");
		return;
		}
	}
printf("ESSID.............: %.*s\n", hashlist.essidlen, hashlist.essid);
printf("PSK  .............: %s\n", pskstring);
printf("PMK...............: ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkcalculated[p]);
printf("\n");
printf("PMKID (calculated): ");
for(p = 0; p < HASH_LEN; p++) printf("%02x", pmkidcalculated[p]);
printf("\n");
if(hashlist.type == HS_PMKID)
	{
	printf("PMKID (hash line).: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", hashlist.hash[p]);
	if(memcmp(&pmkidcalculated, &hashlist.hash, HASH_LEN) == 0) printf(" (equal)\n");
	else printf(" (not equal)\n");
	}
else if(hashlist.type == HS_EAPOL)
	{
	printf("MIC (calculated)..: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", miccalculated[p]);
	printf("\n");
	printf("MIC (hash line)...: ");
	for(p = 0; p < HASH_LEN; p++) printf("%02x", hashlist.hash[p]);
	if(memcmp(&miccalculated, &hashlist.hash, HASH_LEN) == 0) printf(" (equal)\n");
	else printf(" (not equal)\n");
	}
return;
}
/*===========================================================================*/
static void showstandardinfobase64(char *essidstring, char *pmkstring)
{
static size_t p;
static size_t pmklen;
static size_t essidlen;

static char *baseline;

essidlen = strlen(essidstring);
if((essidlen == 0) || (essidlen > ESSID_LEN_MAX))
	{
	fprintf(stderr, "ESSID length exception\n");
	return;
	}

pmklen = strlen(pmkstring);
if(pmklen != 64)
	{
	fprintf(stderr, "PMK length exception\n");
	return;
	}

if(getfield(pmkstring, 32, pmkopt) != 32)
	{
	fprintf(stderr, "PMK length exception\n");
	return;
	}

printf("ESSID............: %s\n", essidstring);
printf("PMK..............: ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkopt[p]);
printf("\n");
base64((unsigned char*)essidstring, essidlen, &baseline);
printf("PBKDF2-HMAC-SHA1.: sha1:4096:%s:", baseline);
free(baseline);
base64((unsigned char*)pmkopt, 32, &baseline);
printf("%s\n\nuse hashcat -m 12000 to recover the PSK\n", baseline);
free(baseline);
return;
}
/*===========================================================================*/
static void showstandardinfopmk(char *pskstring, char *essidstring, char *pmkstring)
{
static size_t p;
static size_t pmklen;
static size_t essidlen;
static size_t psklen;

essidlen = strlen(essidstring);
if((essidlen == 0) || (essidlen > ESSID_LEN_MAX))
	{
	fprintf(stderr, "ESSID length exception\n");
	return;
	}

psklen = strlen(pskstring);
if((psklen == 63) || (psklen > 63))
	{
	fprintf(stderr, "PSK length exception\n");
	return;
	}

pmklen = strlen(pmkstring);
if(pmklen != 64)
	{
	fprintf(stderr, "PMK length exception\n");
	return;
	}

if(getfield(pmkstring, 32, pmkopt) != 32)
	{
	fprintf(stderr, "PMK length exception\n");
	return;
	}

if(dopbkdf2(psklen, pskstring, essidlen, (uint8_t*)essidstring) == false) 
	{
	fprintf(stderr, "PBKDF2 calculation error\n");
	return;
	}
printf("ESSID............: %s\n", essidstring);
printf("PSK..............: %s\n", pskstring);
printf("PMK (calculated).: ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkcalculated[p]);
printf("\n");
printf("PMK (from option): ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkopt[p]);
if(memcmp(&pmkcalculated, &pmkopt, PMK_LEN) == 0) printf(" (equal)\n");
else printf(" (not equal)\n");
return;
}
/*===========================================================================*/
static void showstandardinfo(char *pskstring, char *essidstring)
{
static size_t p;
static size_t essidlen;
static size_t psklen;

essidlen = strlen(essidstring);
if((essidlen == 0) || (essidlen > ESSID_LEN_MAX))
	{
	fprintf(stderr, "ESSID length exception\n");
	return;
	}

psklen = strlen(pskstring);
if((psklen == 63) || (psklen > 63))
	{
	fprintf(stderr, "PSK length exception\n");
	return;
	}

if(dopbkdf2(psklen, pskstring, essidlen, (uint8_t*)essidstring) == false) 
	{
	fprintf(stderr, "PBKDF2 calculation error\n");
	return;
	}
printf("ESSID: %s\n", essidstring);
printf("PSK..: %s\n", pskstring);
printf("PMK..: ");
for(p = 0; p < PMK_LEN; p++) printf("%02x", pmkcalculated[p]);
printf("\n");
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s  (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"\n"
	"short options:\n"
	"-i <hash line> : input hashcat hash line (-m 22000)\n"
	"-e <ESSID>     : input ESSID\n"
	"-p <PSK>       : input Pre Shared Key\n"
	"-m <PMK>       : input Plain Master KEY\n"
	"\n"
	"long options:\n"
	"--help         : show this help\n"
	"--version      : show version\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static char *hashlinestring;
static char *essidstring;
static char *pskstring;
static char *pmkstring;

static const char *short_options = "i:e:p:m:hv";
static const struct option long_options[] =
{
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
hashlinestring = NULL;
essidstring = NULL;
pskstring = NULL;
pmkstring = NULL;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_HASHLINE:
		hashlinestring = optarg;
		break;

		case HCX_ESSID:
		essidstring = optarg;
		break;

		case HCX_PSK:
		pskstring = optarg;
		break;

		case HCX_PMK:
		pmkstring = optarg;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
printf("\n");
if((essidstring != NULL) && (pskstring != NULL) && (pmkstring == NULL) && (hashlinestring == NULL))
	{
	showstandardinfo(pskstring, essidstring);
	}
else if((essidstring != NULL) && (pskstring != NULL) && (pmkstring != NULL) && (hashlinestring == NULL))
	{
	showstandardinfopmk(pskstring, essidstring, pmkstring);
	}

else if((essidstring != NULL) && (pskstring == NULL) && (pmkstring != NULL) && (hashlinestring == NULL))
	{
	showstandardinfobase64(essidstring, pmkstring);
	}

else if((essidstring == NULL) && (pskstring != NULL) && (pmkstring == NULL) && (hashlinestring != NULL))
	{
	showstandardinfohashlinepsk(hashlinestring, pskstring);
	}

else if((essidstring == NULL) && (pskstring == NULL) && (pmkstring != NULL) && (hashlinestring != NULL))
	{
	showstandardinfohashlinepmk(hashlinestring, pmkstring);
	}

else if((essidstring != NULL) && (pskstring != NULL) && (pmkstring == NULL) && (hashlinestring != NULL))
	{
	showstandardinfohashlineessidpsk(hashlinestring, essidstring, pskstring);
	}

printf("\n");
EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();
return EXIT_SUCCESS;
}
/*===========================================================================*/

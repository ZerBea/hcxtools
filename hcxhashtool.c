#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <arpa/inet.h>  
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#if defined (__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#include <sys/socket.h>
#include <inttypes.h>
#else
#include <stdio_ext.h>
#endif
#ifdef __linux__
#include <linux/limits.h>
#endif
#include "include/version.h"
#include "include/hcxhashtool.h"
#include "include/strings.c"
#include "include/fileops.c"
#include "include/ieee80211.h"
#include "include/byteops.c"

/*===========================================================================*/
/* global var */

static const char *usedoui;
static int ouicount;
static int ouilistcount;
static ouilist_t *ouilist;
static hashlist_t *hashlist;
static long int hashlistcount;
static long int readcount;
static long int readerrorcount;
static long int pmkideapolcount;
static long int pmkidcount;
static long int eapolcount;
static long int pmkidwrittencount;
static long int eapolwrittencount;
static long int essidwrittencount;
static long int hccapxwrittencount;
static long int hccapwrittencount;
static long int johnwrittencount;

static int hashtype;
static int essidlen;
static int essidlenmin;
static int essidlenmax;
static int filteressidlen;
static char *filteressidptr;
static int filteressidpartlen;
static char *filteressidpartptr;

static char *filtervendorptr;

static bool flagpsk;
static bool flagpmk;
static bool flagessidgroup;
static bool flagmacapgroup;
static bool flagmacclientgroup;
static bool flagouigroup;
static bool flagvendorout;

static bool flagfiltermacap;
static uint8_t filtermacap[6];

static bool flagfiltermacclient;
static uint8_t filtermacclient[6];

static bool flagfilterouiap;
static uint8_t filterouiap[3];

static bool flagfilterouiclient;
static uint8_t filterouiclient[3];

static bool flagfilterauthorized;
static bool flagfilternotauthorized;
static bool flagfilterrcchecked;
static bool flagfilterapless;

static int pskptrlen;
static char *pskptr;
static uint8_t pmkpbkdf2[32];
static uint8_t pmk[32];
/*===========================================================================*/
static void closelists()
{
if(hashlist != NULL) free(hashlist);
if(ouilist != NULL) free(ouilist);

return;
}
/*===========================================================================*/
static bool initlists()
{
ouicount = 0;
ouilistcount = OUILIST_MAX;
hashlistcount = HASHLIST_MAX;
readcount = 0;
readerrorcount = 0;
pmkideapolcount = 0;
pmkidcount = 0;
eapolcount = 0;
pmkidwrittencount = 0;
eapolwrittencount = 0;
essidwrittencount = 0;
hccapxwrittencount = 0;
hccapwrittencount = 0;

if((hashlist = (hashlist_t*)calloc(hashlistcount, HASHLIST_SIZE)) == NULL) return false;
if((ouilist = (ouilist_t*)calloc(ouilistcount, OUILIST_SIZE)) == NULL) return false;

return true;
}
/*===========================================================================*/
static char *getvendor(uint8_t *mac)
{
static ouilist_t * zeiger;
static char *unknown = "unknown";

for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++)
	{
	if(memcmp(zeiger->oui, mac, 3) == 0) return zeiger->vendor;
	if(memcmp(zeiger->oui, mac, 3) > 0) return unknown;
	}
return unknown;
}
/*===========================================================================*/
static void printstatus()
{
static char *vendor;


printf("\nOUI information file...: %s\n", usedoui);
if(ouicount > 0)		printf("OUI entires............: %d\n", ouicount);
if(readcount > 0)		printf("total lines read.......: %ld\n", readcount);
if(flagvendorout == true)
	{
	printf("\n");
	return;
	}
if(readerrorcount > 0)			printf("read errors............: %ld\n", readerrorcount);
if(pmkideapolcount > 0)			printf("valid hash lines.......: %ld\n", pmkideapolcount);
if(pmkidcount > 0)			printf("PMKID hash lines.......: %ld\n", pmkidcount);
if(eapolcount > 0)			printf("EAPOL hash lines.......: %ld\n", eapolcount);
if(essidlenmin != 0)			printf("filter by ESSID len min: %d\n", essidlenmin);
if(essidlenmax != 32)			printf("filter by ESSID len max: %d\n", essidlenmax);
if(filteressidptr != NULL)		printf("filter by ESSID........: %s\n", filteressidptr);
if(filteressidpartptr != NULL)		printf("filter by part of ESSID: %s\n", filteressidpartptr);
if(flagfiltermacap == true)
	{
	vendor = getvendor(filtermacap);
	printf("filter by MAC..........: %02x%02x%02x%02x%02x%02x (%s)\n", filtermacap[0], filtermacap[1], filtermacap[2], filtermacap[3], filtermacap[4], filtermacap[5], vendor);
	}
if(flagfiltermacclient == true)
	{
	vendor = getvendor(filtermacclient);
	printf("filter by MAC..........: %02x%02x%02x%02x%02x%02x (%s)\n", filtermacclient[0], filtermacclient[1], filtermacclient[2], filtermacclient[3], filtermacclient[4], filtermacclient[5], vendor);
	}

if(flagfilterouiap == true)
	{
	vendor = getvendor(filterouiap);
	printf("filter AP by OUI.......: %02x%02x%02x (%s)\n", filterouiap[0], filterouiap[1], filterouiap[2], vendor);
	}
if(filtervendorptr != NULL)		printf("filter AP by VENDOR....: %s\n", filtervendorptr);
if(flagfilterouiclient == true)
	{
	vendor = getvendor(filterouiclient);
	printf("filter CLIENT by OUI...: %02x%02x%02x (%s)\n", filterouiclient[0], filterouiclient[1], filterouiclient[2], vendor);
	}
if(flagfilterapless == true)		printf("filter by M2...........: requested from client (AP-LESS)\n");
if(flagfilterrcchecked == true)		printf("filter by replaycount..: checked\n");
if(flagfilterauthorized == true)	printf("filter by status.......: authorized\n");
if(flagfilternotauthorized == true)	printf("filter by status.......: not authorized\n");
if(pmkidwrittencount > 0)		printf("PMKID written..........: %ld\n", pmkidwrittencount);
if(eapolwrittencount > 0)		printf("EAPOL written..........: %ld\n", eapolwrittencount);
if(hccapxwrittencount > 0)		printf("EAPOL written to hccapx: %ld\n", hccapxwrittencount);
if(hccapwrittencount > 0)		printf("EAPOL written to hccap.: %ld\n", hccapwrittencount);
if(johnwrittencount > 0)		printf("EAPOL written to john..: %ld\n", johnwrittencount);
if(essidwrittencount > 0)		printf("ESSID (unique) written.: %ld\n", essidwrittencount);
printf("\n");
return;
}
/*===========================================================================*/
static int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
static CMAC_CTX *ctx;
static int ret = -1;
static size_t outlen, i;

ctx = CMAC_CTX_new();
if (ctx == NULL) return -1;
if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) goto fail;
for (i = 0; i < num_elem; i++)
	{
	if (!CMAC_Update(ctx, addr[i], len[i])) goto fail;
	}
if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16) goto fail;
ret = 0;
fail:
CMAC_CTX_free(ctx);
return ret;
}
/*===========================================================================*/
static int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
/*===========================================================================*/
static void testeapolpmk(hashlist_t *zeiger)
{
static int keyver;
static int p;
static wpakey_t *wpak;
static uint8_t *pkeptr;

static uint8_t pkedata[102];
static uint8_t pkedata_prf[2 + 98 + 2];
static uint8_t ptk[128];
static uint8_t mymic[16];

wpak = (wpakey_t*)&zeiger->eapol[EAPAUTH_SIZE];
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver == 1 || keyver == 2))
	{
	pkeptr = pkedata;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&ptk, 0, sizeof(ptk));
	memcpy(pkeptr, "Pairwise key expansion", 23);
	if(memcmp(zeiger->ap, zeiger->client, 6) < 0)
		{
		memcpy(pkeptr +23, zeiger->ap, 6);
		memcpy(pkeptr +29, zeiger->client, 6);
		}
	else
		{
		memcpy(pkeptr +23, zeiger->client, 6);
		memcpy(pkeptr +29, zeiger->ap, 6);
		}

	if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +35, zeiger->nonce, 32);
		memcpy (pkeptr +67, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +35, wpak->nonce, 32);
		memcpy (pkeptr +67, zeiger->nonce, 32);
		}
	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), &pmk, 32, pkedata, 100, ptk + p *20, NULL);
		}
	if(keyver == 1) HMAC(EVP_md5(), &ptk, 16, zeiger->eapol, zeiger->eapauthlen, mymic, NULL);
	if(keyver == 2) HMAC(EVP_sha1(), &ptk, 16, zeiger->eapol, zeiger->eapauthlen, mymic, NULL);
	if(memcmp(zeiger->hash, &mymic, 16) == 0)
		{
		fprintf(stdout, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*", 
			pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],
			pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],
			pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],
			pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);
		for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
		fprintf(stdout, "\n");
		}
	return;
	}
else if(keyver == 3)
	{
	pkeptr = pkedata;
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memcpy(pkeptr, "Pairwise key expansion", 22);
	if(memcmp(zeiger->ap, zeiger->client, 6) < 0)
		{
		memcpy(pkeptr +22, zeiger->ap, 6);
		memcpy(pkeptr +28, zeiger->client, 6);
		}
	else
		{
		memcpy(pkeptr +22, zeiger->client, 6);
		memcpy(pkeptr +28, zeiger->ap, 6);
		}
	if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +34, zeiger->nonce, 32);
		memcpy (pkeptr +66, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +34, wpak->nonce, 32);
		memcpy (pkeptr +66, zeiger->nonce, 32);
		}
	HMAC(EVP_sha256(), &pmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, zeiger->eapol, zeiger->eapauthlen, mymic);
	if(memcmp(zeiger->hash, &mymic, 16) == 0)
		{
		fprintf(stdout, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*", 
			pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],
			pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],
			pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],
			pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);
		for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
		fprintf(stdout, "\n");
		}
	}
return;
}
/*===========================================================================*/
static void testpmkidpmk(hashlist_t *zeiger)
{
static int p;
static const char *pmkname = "PMK Name";
static uint8_t salt[32];
static uint8_t pmkidcalc[32];

memcpy(&salt, pmkname, 8);
memcpy(&salt[8], zeiger->ap, 6);
memcpy(&salt[14], zeiger->client, 6);
HMAC(EVP_sha1(), &pmk, 32, salt, 20, pmkidcalc, NULL);
if(memcmp(&pmkidcalc, zeiger->hash, 16) == 0)
	{
	fprintf(stdout, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*", 
		pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],
		pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],
		pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],
		pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);
	for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
	fprintf(stdout, "\n");
	}
return;
}
/*===========================================================================*/
static void testhashfilepmk()
{
static hashlist_t *zeiger;

for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);
	else if (zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);
	}
return;
}
/*===========================================================================*/
static bool dopbkdf2(int psklen, char *psk, int essidlen, uint8_t *essid)
{
if(PKCS5_PBKDF2_HMAC_SHA1(psk, psklen, essid, essidlen, 4096, 32, pmkpbkdf2) == 0) return false;
return true;
}
/*===========================================================================*/
static void testeapolpbkdf2(hashlist_t *zeiger)
{
static int keyver;
static int p;
static wpakey_t *wpak;
static uint8_t *pkeptr;

static uint8_t pkedata[102];
static uint8_t pkedata_prf[2 + 98 + 2];
static uint8_t ptk[128];
static uint8_t mymic[16];

wpak = (wpakey_t*)&zeiger->eapol[EAPAUTH_SIZE];
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver == 1 || keyver == 2))
	{
	pkeptr = pkedata;
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&ptk, 0, sizeof(ptk));
	memcpy(pkeptr, "Pairwise key expansion", 23);
	if(memcmp(zeiger->ap, zeiger->client, 6) < 0)
		{
		memcpy(pkeptr +23, zeiger->ap, 6);
		memcpy(pkeptr +29, zeiger->client, 6);
		}
	else
		{
		memcpy(pkeptr +23, zeiger->client, 6);
		memcpy(pkeptr +29, zeiger->ap, 6);
		}

	if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +35, zeiger->nonce, 32);
		memcpy (pkeptr +67, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +35, wpak->nonce, 32);
		memcpy (pkeptr +67, zeiger->nonce, 32);
		}
	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), &pmkpbkdf2, 32, pkedata, 100, ptk + p *20, NULL);
		}
	if(keyver == 1) HMAC(EVP_md5(), &ptk, 16, zeiger->eapol, zeiger->eapauthlen, mymic, NULL);
	if(keyver == 2) HMAC(EVP_sha1(), &ptk, 16, zeiger->eapol, zeiger->eapauthlen, mymic, NULL);
	if(memcmp(zeiger->hash, &mymic, 16) == 0)
		{
		fprintf(stdout, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*", 
			pmkpbkdf2[0], pmkpbkdf2[1], pmkpbkdf2[2], pmkpbkdf2[3], pmkpbkdf2[4], pmkpbkdf2[5], pmkpbkdf2[6], pmkpbkdf2[7],
			pmkpbkdf2[8], pmkpbkdf2[9], pmkpbkdf2[10], pmkpbkdf2[11], pmkpbkdf2[12], pmkpbkdf2[13], pmkpbkdf2[14], pmkpbkdf2[15],
			pmkpbkdf2[16], pmkpbkdf2[17], pmkpbkdf2[18], pmkpbkdf2[19], pmkpbkdf2[20], pmkpbkdf2[21], pmkpbkdf2[22], pmkpbkdf2[23],
			pmkpbkdf2[24], pmkpbkdf2[25], pmkpbkdf2[26], pmkpbkdf2[27], pmkpbkdf2[28], pmkpbkdf2[29], pmkpbkdf2[30], pmkpbkdf2[31]);
		for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
		if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s\n", pskptr);
		else
			{
			fprintf(stdout, ":$HEX[");
			for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);
			fprintf(stdout, "]\n");
			}
		}
	return;
	}
else if(keyver == 3)
	{
	pkeptr = pkedata;
	memset(&pkedata_prf, 0, sizeof(pkedata_prf));
	memset(&ptk, 0, sizeof(ptk));
	memcpy(pkeptr, "Pairwise key expansion", 22);
	if(memcmp(zeiger->ap, zeiger->client, 6) < 0)
		{
		memcpy(pkeptr +22, zeiger->ap, 6);
		memcpy(pkeptr +28, zeiger->client, 6);
		}
	else
		{
		memcpy(pkeptr +22, zeiger->client, 6);
		memcpy(pkeptr +28, zeiger->ap, 6);
		}
	if(memcmp(zeiger->nonce, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +34, zeiger->nonce, 32);
		memcpy (pkeptr +66, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +34, wpak->nonce, 32);
		memcpy (pkeptr +66, zeiger->nonce, 32);
		}
	pkedata_prf[0] = 1;
	pkedata_prf[1] = 0;
	memcpy (pkedata_prf + 2, pkedata, 98);
	pkedata_prf[100] = 0x80;
	pkedata_prf[101] = 1;
	HMAC(EVP_sha256(), &pmkpbkdf2, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, zeiger->eapol, zeiger->eapauthlen, mymic);
	if(memcmp(zeiger->hash, &mymic, 16) == 0)
		{
		fprintf(stdout, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*", 
			pmkpbkdf2[0], pmkpbkdf2[1], pmkpbkdf2[2], pmkpbkdf2[3], pmkpbkdf2[4], pmkpbkdf2[5], pmkpbkdf2[6], pmkpbkdf2[7],
			pmkpbkdf2[8], pmkpbkdf2[9], pmkpbkdf2[10], pmkpbkdf2[11], pmkpbkdf2[12], pmkpbkdf2[13], pmkpbkdf2[14], pmkpbkdf2[15],
			pmkpbkdf2[16], pmkpbkdf2[17], pmkpbkdf2[18], pmkpbkdf2[19], pmkpbkdf2[20], pmkpbkdf2[21], pmkpbkdf2[22], pmkpbkdf2[23],
			pmkpbkdf2[24], pmkpbkdf2[25], pmkpbkdf2[26], pmkpbkdf2[27], pmkpbkdf2[28], pmkpbkdf2[29], pmkpbkdf2[30], pmkpbkdf2[31]);
		for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
		if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s\n", pskptr);
		else
			{
			fprintf(stdout, ":$HEX[");
			for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);
			fprintf(stdout, "]\n");
			}
		}
	}
return;
}
/*===========================================================================*/
static void testpmkidpbkdf2(hashlist_t *zeiger)
{
static int p;
static const char *pmkname = "PMK Name";
static uint8_t salt[32];
static uint8_t pmkidcalc[32];

memcpy(&salt, pmkname, 8);
memcpy(&salt[8], zeiger->ap, 6);
memcpy(&salt[14], zeiger->client, 6);
HMAC(EVP_sha1(), &pmkpbkdf2, 32, salt, 20, pmkidcalc, NULL);
if(memcmp(&pmkidcalc, zeiger->hash, 16) == 0)
	{
	fprintf(stdout, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*", 
		pmkpbkdf2[0], pmkpbkdf2[1], pmkpbkdf2[2], pmkpbkdf2[3], pmkpbkdf2[4], pmkpbkdf2[5], pmkpbkdf2[6], pmkpbkdf2[7],
		pmkpbkdf2[8], pmkpbkdf2[9], pmkpbkdf2[10], pmkpbkdf2[11], pmkpbkdf2[12], pmkpbkdf2[13], pmkpbkdf2[14], pmkpbkdf2[15],
		pmkpbkdf2[16], pmkpbkdf2[17], pmkpbkdf2[18], pmkpbkdf2[19], pmkpbkdf2[20], pmkpbkdf2[21], pmkpbkdf2[22], pmkpbkdf2[23],
		pmkpbkdf2[24], pmkpbkdf2[25], pmkpbkdf2[26], pmkpbkdf2[27], pmkpbkdf2[28], pmkpbkdf2[29], pmkpbkdf2[30], pmkpbkdf2[31]);
	for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
	if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s\n", pskptr);
	else
		{
		fprintf(stdout, ":$HEX[");
		for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);
		fprintf(stdout, "]\n");
		}
	}
return;
}
/*===========================================================================*/
static void testhashfilepsk()
{
static hashlist_t *zeiger, *zeigerold;

zeigerold = hashlist;
if(dopbkdf2(pskptrlen, pskptr, zeigerold->essidlen, zeigerold->essid) == true)
	{
	if(zeigerold->type == HCX_TYPE_PMKID) testpmkidpbkdf2(zeigerold);
	if(zeigerold->type == HCX_TYPE_EAPOL) testeapolpbkdf2(zeigerold);
	}
for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	if((zeigerold->essidlen == zeiger->essidlen) && (memcmp(zeigerold->essid, zeiger->essid, zeigerold->essidlen) == 0))
		{
		if(zeiger->type == HCX_TYPE_PMKID) testpmkidpbkdf2(zeiger);
		if(zeiger->type == HCX_TYPE_EAPOL) testeapolpbkdf2(zeiger);
		}
	else
		{
		if(dopbkdf2(pskptrlen, pskptr, zeiger->essidlen, zeiger->essid) == true)
			{
			if(zeiger->type == HCX_TYPE_PMKID) testpmkidpbkdf2(zeiger);
			if(zeiger->type == HCX_TYPE_EAPOL) testeapolpbkdf2(zeiger);
			}
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
static bool isoui(uint8_t *mac)
{
static ouilist_t *zeiger;

for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++)
	{
	if(memcmp(mac, zeiger->oui, 3) == 0) return true;
	}
return false;
}
/*===========================================================================*/
static bool ispartof(int plen, uint8_t *pbuff, int slen, uint8_t *sbuff)
{
static int p;
if(plen > slen) return false;

for(p = 0; p <= slen -plen; p++)
	{
	if(memcmp(&sbuff[p], pbuff, plen) == 0) return true;
	}
return false;
}
/*===========================================================================*/
static void hccap2base(unsigned char *in, unsigned char b, FILE *fh_john)
{
static const char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fprintf(fh_john, "%c", (itoa64[in[0] >> 2]));
fprintf(fh_john, "%c", (itoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)]));
if(b)
	{
	fprintf(fh_john, "%c", (itoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)]));
	fprintf(fh_john, "%c", (itoa64[in[2] & 0x3f]));
	}
else fprintf(fh_john, "%c", (itoa64[((in[1] & 0x0f) << 2)]));
return;
}
/*===========================================================================*/
static void writejohnrecord(FILE *fh_john, hashlist_t *zeiger)
{
struct hccap_s
{
  char essid[36];
  unsigned char ap[6];
  unsigned char client[6];
  unsigned char snonce[32];
  unsigned char anonce[32];
  unsigned char eapol[256];
  int eapol_size;
  int keyver;
  unsigned char keymic[16];
};
typedef struct hccap_s hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))

static wpakey_t *wpak;
static int i;
static unsigned char *hcpos;
static hccap_t hccap;

if(zeiger->type == HCX_TYPE_PMKID) return;
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;
if(filteressidptr != NULL)
	{
	if(zeiger->essidlen != filteressidlen) return;
	if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;
	}
if(filteressidpartptr != NULL)
	{
	if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;
	}
if(filtervendorptr != 0)
	{
	if(isoui(zeiger->ap) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;

wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
memset(&hccap, 0, sizeof(hccap_t));
memcpy(&hccap.essid, zeiger->essid, zeiger->essidlen);
memcpy(&hccap.ap, zeiger->ap, 6);
memcpy(&hccap.client, zeiger->client, 6);
memcpy(&hccap.anonce, zeiger->nonce, 32);
memcpy(&hccap.snonce, wpak->nonce, 32);
memcpy(&hccap.keymic, zeiger->hash, 16);
hccap.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
hccap.eapol_size = zeiger->eapauthlen;
memcpy(&hccap.eapol, zeiger->eapol, zeiger->eapauthlen);
#ifdef BIG_ENDIAN_HOST
hccap.eapol_size = byte_swap_16(hccap.eapol_size);
#endif

fprintf(fh_john, "%.*s:$WPAPSK$%.*s#", zeiger->essidlen, zeiger->essid, zeiger->essidlen, zeiger->essid);
hcpos = (unsigned char*)&hccap;
for (i = 36; i + 3 < (int)HCCAP_SIZE; i += 3) hccap2base(&hcpos[i], 1, fh_john);
hccap2base(&hcpos[i], 0, fh_john);
fprintf(fh_john, ":%02x-%02x-%02x-%02x-%02x-%02x:%02x-%02x-%02x-%02x-%02x-%02x:%02x%02x%02x%02x%02x%02x",
zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5],
zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5]);
if(hccap.keyver == 1) fprintf(fh_john, "::WPA");
else fprintf(fh_john, "::WPA2");
if((zeiger->mp &0x7) == 0) fprintf(fh_john, ":not verified");
else fprintf(fh_john, ":verified");
fprintf(fh_john, ":converted by hcxhastool\n");
johnwrittencount++;
return;
}
/*===========================================================================*/
static void writejohnfile(char *johnoutname)
{
static FILE *fh_john;
static hashlist_t *zeiger;
static struct stat statinfo;

if(johnoutname != NULL)
	{
	if((fh_john = fopen(johnoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", johnoutname, strerror(errno));
		return;
		}
	}
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writejohnrecord(fh_john, zeiger);
if(fh_john != NULL) fclose(fh_john);
if(johnoutname != NULL)
	{
	if(stat(johnoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(johnoutname);
		}
	}
return;
}
/*===========================================================================*/
static void writehccaprecord(FILE *fh_hccap, hashlist_t *zeiger)
{
struct hccap_s
{
  char essid[36];
  unsigned char ap[6];
  unsigned char client[6];
  unsigned char snonce[32];
  unsigned char anonce[32];
  unsigned char eapol[256];
  int eapol_size;
  int keyver;
  unsigned char keymic[16];
};
typedef struct hccap_s hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))

static wpakey_t *wpak;
static hccap_t hccap;

if(zeiger->type == HCX_TYPE_PMKID) return;
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;
if(filteressidptr != NULL)
	{
	if(zeiger->essidlen != filteressidlen) return;
	if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;
	}
if(filteressidpartptr != NULL)
	{
	if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;
	}
if(filtervendorptr != 0)
	{
	if(isoui(zeiger->ap) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;

wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
memset(&hccap, 0, sizeof(hccap_t));
memcpy(&hccap.essid, zeiger->essid, zeiger->essidlen);
memcpy(&hccap.ap, zeiger->ap, 6);
memcpy(&hccap.client, zeiger->client, 6);
memcpy(&hccap.anonce, zeiger->nonce, 32);
memcpy(&hccap.snonce, wpak->nonce, 32);
memcpy(&hccap.keymic, zeiger->hash, 16);
hccap.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
hccap.eapol_size = zeiger->eapauthlen;
memcpy(&hccap.eapol, zeiger->eapol, zeiger->eapauthlen);
#ifdef BIG_ENDIAN_HOST
hccap.eapol_size = byte_swap_16(hccap.eapol_size);
#endif
fwrite(&hccap, HCCAP_SIZE, 1, fh_hccap);
hccapwrittencount++;
return;
}
/*===========================================================================*/
static void writehccapfile(char *hccapoutname)
{
static FILE *fh_hccap;
static hashlist_t *zeiger;
static struct stat statinfo;

if(hccapoutname != NULL)
	{
	if((fh_hccap = fopen(hccapoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", hccapoutname, strerror(errno));
		return;
		}
	}
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writehccaprecord(fh_hccap, zeiger);
if(fh_hccap != NULL) fclose(fh_hccap);
if(hccapoutname != NULL)
	{
	if(stat(hccapoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(hccapoutname);
		}
	}
return;
}
/*===========================================================================*/
static void writehccapxrecord(FILE *fh_hccapx, hashlist_t *zeiger)
{
struct hccapx_s
{
 uint32_t	signature;
#define HCCAPX_SIGNATURE 0x58504348
 uint32_t	version;
#define HCCAPX_VERSION 4
 uint8_t	message_pair;
 uint8_t	essid_len;
 uint8_t	essid[32];
 uint8_t	keyver;
 uint8_t	keymic[16];
 uint8_t	ap[6];
 uint8_t	anonce[32];
 uint8_t	client[6];
 uint8_t	snonce[32];
 uint16_t	eapol_len;
 uint8_t	eapol[256];
} __attribute__((packed));
typedef struct hccapx_s hccapx_t;
#define	HCCAPX_SIZE (sizeof(hccapx_t))

static wpakey_t *wpak;
static hccapx_t hccapx;

if(zeiger->type == HCX_TYPE_PMKID) return;
if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;
if(filteressidptr != NULL)
	{
	if(zeiger->essidlen != filteressidlen) return;
	if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;
	}
if(filteressidpartptr != NULL)
	{
	if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;
	}
if(filtervendorptr != 0)
	{
	if(isoui(zeiger->ap) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;

wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
memset (&hccapx, 0, sizeof(hccapx_t));
hccapx.signature = HCCAPX_SIGNATURE;
hccapx.version = HCCAPX_VERSION;
hccapx.message_pair = zeiger->mp;
hccapx.essid_len = zeiger->essidlen;
memcpy(&hccapx.essid, zeiger->essid, zeiger->essidlen);
memcpy(&hccapx.ap, zeiger->ap, 6);
memcpy(&hccapx.client, zeiger->client, 6);
memcpy(&hccapx.anonce, zeiger->nonce, 32);
memcpy(&hccapx.snonce, wpak->nonce, 32);
hccapx.eapol_len = zeiger->eapauthlen;
memcpy(&hccapx.eapol, zeiger->eapol, zeiger->eapauthlen);
hccapx.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
memcpy(&hccapx.keymic, zeiger->hash, 16);
#ifdef BIG_ENDIAN_HOST
hccapx.signature = byte_swap_32(hccapx.signature);
hccapx.version = byte_swap_32(hccapx.version);
hccapx.eapol_len = byte_swap_16(hccapx.eapol_len);
#endif
fwrite (&hccapx, sizeof(hccapx_t), 1, fh_hccapx);
hccapxwrittencount++;
return;
}
/*===========================================================================*/
static void writehccapxfile(char *hccapxoutname)
{
static FILE *fh_hccapx;
static hashlist_t *zeiger;
static struct stat statinfo;

if(hccapxoutname != NULL)
	{
	if((fh_hccapx = fopen(hccapxoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", hccapxoutname, strerror(errno));
		return;
		}
	}
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writehccapxrecord(fh_hccapx, zeiger);
if(fh_hccapx != NULL) fclose(fh_hccapx);
if(hccapxoutname != NULL)
	{
	if(stat(hccapxoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(hccapxoutname);
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void processessid(char *essidoutname)
{
static long int pc;
static hashlist_t *zeiger, *zeigerold;
static FILE *fh_essid;
static struct stat statinfo;

if((fh_essid = fopen(essidoutname, "a")) == NULL)
	{
	printf("error opening file %s: %s\n", essidoutname, strerror(errno));
	return;
	}
zeigerold = NULL;
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_maclist_by_essid);
for(pc = 0; pc < pmkideapolcount; pc++)
	{
	zeiger = hashlist +pc;
	if(zeigerold != NULL)
		{
		if(memcmp(zeiger->essid, zeigerold->essid, ESSID_LEN_MAX) == 0) continue;
		}
	fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_essid);
	essidwrittencount++;
	zeigerold = zeiger;
	}
fclose(fh_essid);
if(stat(essidoutname, &statinfo) == 0)
	{
	if(statinfo.st_size == 0) remove(essidoutname);
	}
return;
}
/*===========================================================================*/
static void writepmkideapolhashline(FILE *fh_pmkideapol, hashlist_t *zeiger)
{
static int p;

if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;
if(filteressidptr != NULL)
	{
	if(zeiger->essidlen != filteressidlen) return;
	if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;
	}
if(filteressidpartptr != NULL)
	{
	if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;
	}
if(filtervendorptr != 0)
	{
	if(isoui(zeiger->ap) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x00)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;

if(zeiger->type == HCX_TYPE_PMKID)
	{
	fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
		zeiger->type,
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
		zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);
	for(p = 0; p < zeiger->essidlen; p++) fprintf(fh_pmkideapol, "%02x", zeiger->essid[p]);
	fprintf(fh_pmkideapol, "***\n");
	pmkidwrittencount++;
	return;
	}
if(zeiger->type == HCX_TYPE_EAPOL)
	{
	fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
		zeiger->type,
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
		zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);
	for(p = 0; p < zeiger->essidlen; p++) fprintf(fh_pmkideapol, "%02x", zeiger->essid[p]);
	fprintf(fh_pmkideapol, "*");
	fprintf(fh_pmkideapol, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*",
		zeiger->nonce[0], zeiger->nonce[1], zeiger->nonce[2], zeiger->nonce[3], zeiger->nonce[4], zeiger->nonce[5], zeiger->nonce[6], zeiger->nonce[7],
		zeiger->nonce[8], zeiger->nonce[9], zeiger->nonce[10], zeiger->nonce[11], zeiger->nonce[12], zeiger->nonce[13], zeiger->nonce[14], zeiger->nonce[15],
		zeiger->nonce[16], zeiger->nonce[17], zeiger->nonce[18], zeiger->nonce[19], zeiger->nonce[20], zeiger->nonce[21], zeiger->nonce[22], zeiger->nonce[23],
		zeiger->nonce[24], zeiger->nonce[25], zeiger->nonce[26], zeiger->nonce[27], zeiger->nonce[28], zeiger->nonce[29], zeiger->nonce[30], zeiger->nonce[31]);
	for(p = 0; p < zeiger->eapauthlen; p++) fprintf(fh_pmkideapol, "%02x", zeiger->eapol[p]);
	fprintf(fh_pmkideapol, "*%02x\n", zeiger->mp);
	eapolwrittencount++;
	}
return;
}
/*===========================================================================*/
static void writeeapolpmkidessidgroups()
{
static int cei;
static int ceo;
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;

static const char digit[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_maclist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	groupoutname[0] = 0;
	if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) continue;
	if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) continue;
	ceo = 0;
	for (cei = 0; cei < zeiger->essidlen; cei++)
		{
		groupoutname[ceo] = digit[(zeiger->essid[cei] & 0xff) >> 4];
		ceo++;
		groupoutname[ceo] = digit[zeiger->essid[cei] & 0x0f];
		ceo++;
		}
	groupoutname[ceo] = 0;
	strcat(&groupoutname[ceo], ".22000");
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", groupoutname, strerror(errno));
		return;
		}
	writepmkideapolhashline(fh_pmkideapol, zeiger);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	if(groupoutname[0] != 0)
		{
		if(stat(groupoutname, &statinfo) == 0)
			{
			if(statinfo.st_size == 0) remove(groupoutname);
			}
		}
	}
return;
}
/*===========================================================================*/
static void writeeapolpmkidouigroups()
{
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;

static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_maclist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x.22000", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2]);
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", groupoutname, strerror(errno));
		return;
		}
	writepmkideapolhashline(fh_pmkideapol, zeiger);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	if(groupoutname[0] != 0)
		{
		if(stat(groupoutname, &statinfo) == 0)
			{
			if(statinfo.st_size == 0) remove(groupoutname);
			}
		}
	}
return;
}
/*===========================================================================*/
static void writeeapolpmkidmacapgroups()
{
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;

static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_maclist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x.22000", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5]);
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", groupoutname, strerror(errno));
		return;
		}
	writepmkideapolhashline(fh_pmkideapol, zeiger);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	if(groupoutname[0] != 0)
		{
		if(stat(groupoutname, &statinfo) == 0)
			{
			if(statinfo.st_size == 0) remove(groupoutname);
			}
		}
	}
return;
}
/*===========================================================================*/
static void writeeapolpmkidmacclientgroups()
{
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;

static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_maclist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x.22000", zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", groupoutname, strerror(errno));
		return;
		}
	writepmkideapolhashline(fh_pmkideapol, zeiger);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	if(groupoutname[0] != 0)
		{
		if(stat(groupoutname, &statinfo) == 0)
			{
			if(statinfo.st_size == 0) remove(groupoutname);
			}
		}
	}
return;
}
/*===========================================================================*/
static void writeeapolpmkidfile(char *pmkideapoloutname)
{
static FILE *fh_pmkideapol;
static hashlist_t *zeiger;
static struct stat statinfo;

if(pmkideapoloutname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkideapoloutname, strerror(errno));
		return;
		}
	}
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writepmkideapolhashline(fh_pmkideapol, zeiger);
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
if(pmkideapoloutname != NULL)
	{
	if(stat(pmkideapoloutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapoloutname);
		}
	}
return;
}
/*===========================================================================*/
static void writepmkideapolhashlineinfo(FILE *fh_pmkideapol, hashlist_t *zeiger)
{
static eapauth_t *eapa;
static wpakey_t *wpak;
static uint8_t keyver;
static uint64_t rc;
static char *vendor;

if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
if(flagfiltermacap == true) if(memcmp(&filtermacap, zeiger->ap, 6) != 0) return;
if(flagfiltermacclient == true) if(memcmp(&filtermacclient, zeiger->client, 6) != 0) return;
if(flagfilterouiap == true) if(memcmp(&filterouiap, zeiger->ap, 3) != 0) return;
if(flagfilterouiclient == true) if(memcmp(&filterouiclient, zeiger->client, 3) != 0) return;
if(filteressidptr != NULL)
	{
	if(zeiger->essidlen != filteressidlen) return;
	if(memcmp(zeiger->essid, filteressidptr, zeiger->essidlen) != 0) return;
	}
if(filteressidpartptr != NULL)
	{
	if(ispartof(filteressidpartlen, (uint8_t*)filteressidpartptr, zeiger->essidlen, zeiger->essid) == false) return;
	}
if(filtervendorptr != 0)
	{
	if(isoui(zeiger->ap) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) != 0x00)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilternotauthorized == true) && ((zeiger->mp &0x07) != 0x01)) return;

fprintf(fh_pmkideapol, "SSID.......: %.*s\n", zeiger->essidlen, zeiger->essid);
vendor = getvendor(zeiger->ap);
fprintf(fh_pmkideapol, "MAC_AP.....: %02x%02x%02x%02x%02x%02x (%s)\n", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], vendor);
vendor = getvendor(zeiger->client);
fprintf(fh_pmkideapol, "MAC_CLIENT.: %02x%02x%02x%02x%02x%02x (%s)\n", zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5], vendor);
if(zeiger->type == HCX_TYPE_PMKID)
	{
	fprintf(fh_pmkideapol, "PMKID......: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15]);
	}
if(zeiger->type == HCX_TYPE_EAPOL)
	{
	eapa = (eapauth_t*)zeiger->eapol;
	wpak = (wpakey_t*)&zeiger->eapol[EAPAUTH_SIZE];
	if(eapa->version == 1) fprintf(fh_pmkideapol, "VERSION....: 802.1X-2001 (1)\n");
	if(eapa->version == 2) fprintf(fh_pmkideapol, "VERSION....: 802.1X-2004 (2)\n");
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver == 1) fprintf(fh_pmkideapol, "KEY VERSION: WPA1\n");
	if(keyver == 2) fprintf(fh_pmkideapol, "KEY VERSION: WPA2\n");
	if(keyver == 3) fprintf(fh_pmkideapol, "KEY VERSION: WPA2 key version 3\n");
	#ifndef BIG_ENDIAN_HOST
	rc = byte_swap_64(wpak->replaycount);
	#else
	rc = wpak->replaycount;
	#endif
	fprintf(fh_pmkideapol, "REPLAYCOUNT: %" PRIu64 "\n", rc);
	if((zeiger->mp & 0x80) == 0x00) fprintf(fh_pmkideapol, "RC INFO....: replycount checked\n");
	if((zeiger->mp & 0x80) == 0x80) fprintf(fh_pmkideapol, "RC INFO....: not replycount checked / nc required\n");
	if((zeiger->mp & 0x10) == 0x10) fprintf(fh_pmkideapol, "RC INFO....: AP-LESS attack / nc not reqired\n");
	if((zeiger->mp & 0xe0) == 0x20) fprintf(fh_pmkideapol, "RC INFO....: little endian router / nc LE required\n");
	if((zeiger->mp & 0xe0) == 0x40) fprintf(fh_pmkideapol, "RC INFO....: big endian router / nc BE required\n");
	if((zeiger->mp & 0x07) == 0x00) fprintf(fh_pmkideapol, "MP M1M2 E2.: not authorized\n");
	if((zeiger->mp & 0x07) == 0x01) fprintf(fh_pmkideapol, "MP M1M4 E4.: authorized\n");
	if((zeiger->mp & 0x07) == 0x02) fprintf(fh_pmkideapol, "MP M2M3 E2.: authorized\n");
	if((zeiger->mp & 0x07) == 0x03) fprintf(fh_pmkideapol, "MP M2M3 E3.: authorized\n");
	if((zeiger->mp & 0x07) == 0x04) fprintf(fh_pmkideapol, "MP M3M4 E3.: authorized\n");
	if((zeiger->mp & 0x07) == 0x05) fprintf(fh_pmkideapol, "MP M3M4 E4.: authorized\n");
	fprintf(fh_pmkideapol, "MIC........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15]);
	}
fprintf(fh_pmkideapol, "HASHLINE...: ");
writepmkideapolhashline(fh_pmkideapol, zeiger);
fprintf(fh_pmkideapol, "\n");
return;
}
/*===========================================================================*/
static void writeinfofile(char *infooutname)
{
static hashlist_t *zeiger;
static FILE *fh_info;

if(strcmp(infooutname, "stdout") != 0)
	{
	if((fh_info = fopen(infooutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", infooutname, strerror(errno));
		return;
		}
	for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writepmkideapolhashlineinfo(fh_info, zeiger);
	fclose(fh_info);
	}
else
	{
	for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++) writepmkideapolhashlineinfo(stdout, zeiger);
	}
return;
}
/*===========================================================================*/
static uint16_t getfield(char *lineptr, size_t bufflen, uint8_t *buff)
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
	if(! isxdigit(lineptr[p +0])) return 0;
	if(! isxdigit(lineptr[p +1])) return 0;
	if((lineptr[p +1] == '*') && (lineptr[p +1] == 0)) return 0;
	idx0 = ((uint8_t)lineptr[p +0] &0x1F) ^0x10;
	idx1 = ((uint8_t)lineptr[p +1] &0x1F) ^0x10;
	buff[p /2] = (uint8_t)(hashmap[idx0] <<4) | hashmap[idx1];
	p += 2;
	if((p /2) > PMKIDEAPOL_BUFFER_LEN) return 0;
	}
return p /2;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream)) return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool readpmkideapolfile(FILE *fh_pmkideapol)
{
static int len;
static int oflen;
static uint16_t essidlen;
static uint16_t noncelen;
static uint16_t eapauthlen;
static uint16_t mplen;
static hashlist_t *zeiger, *hashlistnew;

static const char wpa01[] = { "WPA*01*" };
static const char wpa02[] = { "WPA*02*" };

static char linein[PMKIDEAPOL_LINE_LEN +1];
static uint8_t buffer[PMKIDEAPOL_LINE_LEN +1];

zeiger = hashlist;
while(1)
	{
	if((len = fgetline(fh_pmkideapol, PMKIDEAPOL_LINE_LEN, linein)) == -1) break;
	readcount++;
	if(len < 68)
		{
		readerrorcount++;
		continue;
		}
	if((memcmp(&linein, &wpa01, 7) != 0) && (memcmp(&linein, &wpa02, 7) != 0))
		{
		readerrorcount++;
		continue;
		}
	if((linein[39] != '*') && (linein[52] != '*') && (linein[65] != '*'))
		{
		readerrorcount++;
		continue;
		}
	if(getfield(&linein[7], PMKIDEAPOL_LINE_LEN, buffer) != 16)
		{
		readerrorcount++;
		continue;
		}
	memcpy(zeiger->hash, &buffer, 16);

	if(getfield(&linein[40], PMKIDEAPOL_LINE_LEN, buffer) != 6)
		{
		readerrorcount++;
		continue;
		}
	memcpy(zeiger->ap, &buffer, 6);

	if(getfield(&linein[53], PMKIDEAPOL_LINE_LEN, buffer) != 6)
		{
		readerrorcount++;
		continue;
		}
	memcpy(zeiger->client, &buffer, 6);
	essidlen = getfield(&linein[66], PMKIDEAPOL_LINE_LEN, buffer);
	if(essidlen > 32)
		{
		readerrorcount++;
		continue;
		}
	memcpy(zeiger->essid, &buffer, essidlen);
	zeiger->essidlen = essidlen;
	if(memcmp(&linein, &wpa01, 7) == 0)
		{
		zeiger->type = HS_PMKID;
		pmkidcount++;
		}
	else if(memcmp(&linein, &wpa02, 7) == 0)
		{
		oflen = 66 +essidlen *2 +1;
		noncelen = getfield(&linein[oflen], PMKIDEAPOL_LINE_LEN, buffer);
		if(noncelen > 32)
			{
			readerrorcount++;
			continue;
			}
		memcpy(zeiger->nonce, &buffer, 32);
		oflen += 65;
		eapauthlen = getfield(&linein[oflen], PMKIDEAPOL_LINE_LEN, buffer);
		if(eapauthlen > EAPOL_AUTHLEN_MAX)
			{
			readerrorcount++;
			continue;
			}
		memcpy(zeiger->eapol, &buffer, eapauthlen);
		zeiger->eapauthlen = eapauthlen;
		oflen += eapauthlen *2 +1;
		mplen = getfield(&linein[oflen], PMKIDEAPOL_LINE_LEN, buffer);
		if(mplen > 1)
			{
			readerrorcount++;
			continue;
			}
		zeiger->mp = buffer[0];
		zeiger->type = HS_EAPOL;
		eapolcount++;
		}
	else
		{
		readerrorcount++;
		continue;
		}
	pmkideapolcount = pmkidcount +eapolcount;
	if(pmkideapolcount >= hashlistcount)
		{
		hashlistcount += HASHLIST_MAX;
		hashlistnew = realloc(hashlist, hashlistcount *HASHLIST_SIZE);
		if(hashlistnew == NULL)
			{
			printf("failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		hashlist = hashlistnew;
		}
	zeiger = hashlist +pmkideapolcount;
	}
return true;
}
/*===========================================================================*/
static void showvendorlist()
{
static ouilist_t *zeiger;
fprintf(stdout, "\n");
for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++) fprintf(stdout, "%02x%02x%02x %s\n", zeiger->oui[0], zeiger->oui[1], zeiger->oui[2], zeiger->vendor); 
return;
}
/*===========================================================================*/
static void readoui()
{
static int len;
static uid_t uid;
static struct passwd *pwd;
static struct stat statinfo;
static ouilist_t *zeiger, *ouilistnew;
static FILE *fh_oui;
static char *vendorptr;
static const char *ouinameuser = "/.hcxtools/oui.txt";
static const char *ouinamesystemwide = "/usr/share/ieee-data/oui.txt";
static const char *ouina = "N/A";

static char ouinameuserpath[PATH_MAX +1];
static char linein[OUI_LINE_LEN +1];

usedoui = ouina;
uid = getuid();
pwd = getpwuid(uid);
if(pwd == NULL) return;
strncpy(ouinameuserpath, pwd->pw_dir, PATH_MAX -1);
strncat(ouinameuserpath, ouinameuser, PATH_MAX -1);
if(stat(ouinameuserpath, &statinfo) == 0) usedoui = ouinameuserpath;
else if(stat(ouinameuser, &statinfo) == 0) usedoui = ouinamesystemwide;
else return;
if((fh_oui = fopen(usedoui, "r")) == NULL) return;
zeiger = ouilist;
while(1)
	{
	if((len = fgetline(fh_oui, OUI_LINE_LEN, linein)) == -1) break;
	if(len < 20) continue;
	linein[6] = 0;
	if(getfield(linein, OUI_LINE_LEN, zeiger->oui) != 3) continue;
	if(strstr(&linein[7], "(base 16)") == NULL) continue;
	if(filtervendorptr != NULL)
		{
		if(strstr(&linein[7], filtervendorptr) == NULL) continue;
		}
	vendorptr = strrchr(&linein[7], '\t');
	if(vendorptr == NULL) continue;
	if(vendorptr++ == 0) continue;
	strncpy(zeiger->vendor, vendorptr, VENDOR_LEN_MAX -1);
	ouicount++;
	if(ouicount >= ouilistcount)
		{
		ouilistcount += OUILIST_MAX;
		ouilistnew = realloc(ouilist, ouilistcount *OUILIST_SIZE);
		if(ouilistnew == NULL)
			{
			printf("failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		ouilist = ouilistnew;
		}
	zeiger = ouilist +ouicount;
	}
fclose(fh_oui);
qsort(ouilist, ouicount, OUILIST_SIZE, sort_ouilist_by_oui);
return;
}
/*===========================================================================*/
static void downloadoui()
{
static uid_t uid;
static struct passwd *pwd;
static CURLcode ret;
static CURL *hnd;
static FILE* fhoui;
static struct stat statinfo;
static const char *ouipath = "/.hcxtools";
static const char *ouiname = "/oui.txt";
static char ouinameuserpath[PATH_MAX];

uid = getuid();
pwd = getpwuid(uid);
if(pwd == NULL) return;
strncpy(ouinameuserpath, pwd->pw_dir, PATH_MAX -1);
strncat(ouinameuserpath, ouipath, PATH_MAX -1);
if(stat(ouinameuserpath, &statinfo) == -1)
	{
	if(mkdir(ouinameuserpath, 0755) == -1)
		{
		fprintf(stderr, "failed to create conf dir\n");
		return;
		}
	}
strncat(ouinameuserpath, ouiname, PATH_MAX -1);
printf("start downloading oui from http://standards-oui.ieee.org to: %s\n", ouinameuserpath);
if((fhoui = fopen(ouinameuserpath, "w")) == NULL)
	{
	fprintf(stderr, "error creating file %s", ouiname);
	return;
	}
hnd = curl_easy_init ();
curl_easy_setopt(hnd, CURLOPT_URL, "http://standards-oui.ieee.org/oui.txt");
curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 1L);
curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 5L);
curl_easy_setopt(hnd, CURLOPT_WRITEDATA, fhoui) ;
ret = curl_easy_perform(hnd);
curl_easy_cleanup(hnd);
fclose(fhoui);
if(ret != 0)
	{
	fprintf(stderr, "download not successful");
	return;
	}
printf("download finished\n");
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-i <file>   : input PMKID/EAPOL hash file\n"
	"-o <file>   : output PMKID/EAPOL hash file\n"
	"-E <file>   : output ESSID list (autohex enabled)\n"
	"-d          : download http://standards-oui.ieee.org/oui.txt\n"
	"            : and save to ~/.hcxtools/oui.txt\n"
	"            : internet connection required\n"
	"-h          : show this help\n"
	"-v          : show version\n"
	"\n"
	"--essid-group                : convert to ESSID groups in working directory\n"
	"                               full advantage of reuse of PBKDF2\n"
	"                               not on old hash formats\n"
	"--oui-group                  : convert to OUI groups in working directory\n"
	"                               not on old hash formats\n"
	"--mac-group-ap               : convert APs to MAC groups in working directory\n"
	"                               not on old hash formats\n"
	"--mac-group-client           : convert CLIENTs to MAC groups in working directory\n"
	"                               not on old hash formats\n"
	"--type                       : filter by hash type\n"
	"                             : default PMKID (1) and EAPOL (2)\n"
	"--essid-len                  : filter by ESSID length\n"
	"                             : default ESSID length: %d...%d\n"
	"--essid-min                  : filter by ESSID minimum length\n"
	"                             : default ESSID minimum length: %d\n"
	"--essid-max                  : filter by ESSID maximum length\n"
	"                             : default ESSID maximum length: %d\n"
	"--essid=<ESSID>              : filter by ESSID\n"
	"--essid-part=<part of ESSID> : filter by part of ESSID\n"
	"--mac-ap=<MAC>               : filter AP by MAC\n"
	"                             : format: 001122334455 (hex)\n"
	"--mac-client=<MAC>           : filter CLIENT by MAC\n"
	"                             : format: 001122334455 (hex)\n"
	"--oui-ap=<OUI>                     : filter AP by OUI\n"
	"                             : format: 001122 (hex)\n"
	"--oui-client=<OUI>           : filter CLIENT by OUI\n"
	"                             : format: 001122 (hex)\n"
	"--vendor=<VENDOR>            : filter by (part of) VENDOR name\n"
	"--authorized                 : filter EAPOL pairs by status authorized\n"
	"--notauthorized              : filter EAPOL pairs by status not authorized\n"
	"--rc                         : filter EAPOL pairs by replaycount status checked\n"
	"--apless                     : filter EAPOL pairs by status M2 requested from client\n"
	"--info=<file>                : output detailed information about content of hash file\n"
	"--info=stdout                : stdout output detailed information about content of hash file\n"
	"--vendorlist                 : stdout output VENDOR list sorted by OUI\n"
	"--psk=<PSK>                  : pre-shared key to test\n"
	"                             : due to PBKDF2 calculation this is a very slow process\n"
	"                             : no nonce error corrections\n"
	"--pmk=<PMK>                  : plain master key to test\n"
	"                             : no nonce error corrections\n"
	"--hccapx=<file>              : output to deprecated hccapx file\n"
	"--hccap=<file>               : output to ancient hccap file\n"
	"--john=<file>                : output to deprecated john file\n"
	"--help                       : show this help\n"
	"--version                    : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, ESSID_LEN_MIN, ESSID_LEN_MAX, ESSID_LEN_MIN, ESSID_LEN_MAX);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static int hashtypein;
static int essidlenin;
static FILE *fh_pmkideapol;
static char *pmkideapolinname;
static char *pmkideapoloutname;
static char *essidoutname;
static char *hccapxoutname;
static char *hccapoutname;
static char *johnoutname;
static char *infooutname;
static char *ouiinstring;
static char *macinstring;
static char *pmkinstring;

static const char *short_options = "i:o:E:dhv";
static const struct option long_options[] =
{
	{"type",			required_argument,	NULL,	HCX_HASH_TYPE},
	{"essid-group",			no_argument,		NULL,	HCX_ESSID_GROUP},
	{"essid-len",			required_argument,	NULL,	HCX_ESSID_LEN},
	{"essid-min",			required_argument,	NULL,	HCX_ESSID_MIN},
	{"essid-max",			required_argument,	NULL,	HCX_ESSID_MAX},
	{"essid",			required_argument,	NULL,	HCX_FILTER_ESSID},
	{"essid-part",			required_argument,	NULL,	HCX_FILTER_ESSID_PART},
	{"mac-ap",			required_argument,	NULL,	HCX_FILTER_MAC_AP},
	{"mac-client",			required_argument,	NULL,	HCX_FILTER_MAC_CLIENT},
	{"mac-group-ap",		no_argument,		NULL,	HCX_MAC_GROUP_AP},
	{"mac-group-client",		no_argument,		NULL,	HCX_MAC_GROUP_CLIENT},
	{"oui-group",			no_argument,		NULL,	HCX_OUI_GROUP},
	{"oui-ap",			required_argument,	NULL,	HCX_FILTER_OUI_AP},
	{"vendor",			required_argument,	NULL,	HCX_FILTER_VENDOR},
	{"oui-client",			required_argument,	NULL,	HCX_FILTER_OUI_CLIENT},
	{"rc",				no_argument,		NULL,	HCX_FILTER_RC},
	{"authorized",			no_argument,		NULL,	HCX_FILTER_M12},
	{"notauthorized",		no_argument,		NULL,	HCX_FILTER_M1234},
	{"apless",			no_argument,		NULL,	HCX_FILTER_APLESS},
	{"psk",				required_argument,	NULL,	HCX_PSK},
	{"pmk",				required_argument,	NULL,	HCX_PMK},
	{"vendorlist",			no_argument,		NULL,	HCX_VENDOR_OUT},
	{"info",			required_argument,	NULL,	HCX_INFO_OUT},
	{"hccapx",			required_argument,	NULL,	HCX_HCCAPX_OUT},
	{"hccap",			required_argument,	NULL,	HCX_HCCAP_OUT},
	{"john",			required_argument,	NULL,	HCX_JOHN_OUT},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
fh_pmkideapol = NULL;
pmkideapolinname = NULL;
pmkideapoloutname = NULL;
essidoutname = NULL;
infooutname = NULL;
hccapxoutname = NULL;
hccapoutname = NULL;
johnoutname = NULL;
ouiinstring = NULL;
macinstring = NULL;
pmkinstring = NULL;
filteressidptr = NULL;
filteressidpartptr = NULL;
filtervendorptr = NULL;
flagfiltermacap = false;
flagfiltermacclient = false;
flagfilterouiap = false;
flagfilterouiclient = false;
flagfilterauthorized = false;
flagfilternotauthorized = false;
flagfilterrcchecked = false;
flagfilterapless = false;
flagpsk = false;
flagpmk = false;
flagessidgroup = false;
flagmacapgroup = false;
flagmacclientgroup = false;
flagouigroup = false;
flagvendorout = false;
hashtypein = 0;
hashtype = HCX_TYPE_PMKID | HCX_TYPE_EAPOL;
essidlenin = ESSID_LEN_MAX;
essidlen = ESSID_LEN_MAX;
essidlenmin = ESSID_LEN_MIN;
essidlenmax = ESSID_LEN_MAX;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_PMKIDEAPOL_IN:
		pmkideapolinname = optarg;
		break;

		case HCX_PMKIDEAPOL_OUT:
		pmkideapoloutname = optarg;
		break;

		case HCX_ESSID_OUT:
		essidoutname = optarg;
		break;

		case HCX_VENDOR_OUT:
		flagvendorout = true;
		break;

		case HCX_INFO_OUT:
		infooutname = optarg;
		break;

		case HCX_ESSID_GROUP:
		flagessidgroup = true;
		break;

		case HCX_HASH_TYPE:
		hashtypein |= strtol(optarg, NULL, 10);
		if((hashtypein < HCX_TYPE_PMKID) || (hashtypein < HCX_TYPE_EAPOL))
			{
			fprintf(stderr, "only hash types 1 and 2 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_ESSID_LEN:
		essidlenin = strtol(optarg, NULL, 10);
		if((essidlenin < 0) || (essidlenin > ESSID_LEN_MAX))
			{
			fprintf(stderr, "only values 0...32 allowed\n");
			exit(EXIT_FAILURE);
			}
		essidlenmin = essidlenin;
		essidlenmax = essidlenin;
		break;

		case HCX_ESSID_MIN:
		essidlenin = strtol(optarg, NULL, 10);
		if((essidlenin < 0) || (essidlenin > ESSID_LEN_MAX))
			{
			fprintf(stderr, "only values 0...32 allowed\n");
			exit(EXIT_FAILURE);
			}
		essidlenmin = essidlenin;
		break;

		case HCX_ESSID_MAX:
		essidlenin = strtol(optarg, NULL, 10);
		if((essidlenin < 0) || (essidlenin > ESSID_LEN_MAX))
			{
			fprintf(stderr, "only values 0...32 allowed\n");
			exit(EXIT_FAILURE);
			}
		essidlenmax = essidlenin;
		break;

		case HCX_FILTER_ESSID:
		filteressidptr = optarg;
		filteressidlen = strlen(filteressidptr);
		if((filteressidlen  < 1) || (filteressidlen > ESSID_LEN_MAX))
			{
			fprintf(stderr, "only values 0...32 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_FILTER_ESSID_PART:
		filteressidpartptr = optarg;
		filteressidpartlen = strlen(filteressidpartptr);
		if((filteressidpartlen  < 1) || (filteressidpartlen > ESSID_LEN_MAX))
			{
			fprintf(stderr, "only values 0...32 allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_MAC_GROUP_AP:
		flagmacapgroup = true;
		break;

		case HCX_MAC_GROUP_CLIENT:
		flagmacclientgroup = true;
		break;

		case HCX_OUI_GROUP:
		flagouigroup = true;
		break;

		case HCX_FILTER_OUI_AP:
		ouiinstring = optarg;
		if(getfield(ouiinstring, 3, filterouiap) != 3)
			{
			fprintf(stderr, "wrong OUI format\n");
			exit(EXIT_FAILURE);
			}
		flagfilterouiap = true;
		break;

		case HCX_FILTER_MAC_AP:
		macinstring = optarg;
		if(getfield(macinstring, 6, filtermacap) != 6)
			{
			fprintf(stderr, "wrong MAC format\n");
			exit(EXIT_FAILURE);
			}
		flagfiltermacap = true;
		break;

		case HCX_FILTER_MAC_CLIENT:
		macinstring = optarg;
		if(getfield(macinstring, 6, filtermacclient) != 6)
			{
			fprintf(stderr, "wrong MAC format\n");
			exit(EXIT_FAILURE);
			}
		flagfiltermacclient = true;
		break;

		case HCX_FILTER_VENDOR:
		filtervendorptr = optarg;
		break;

		case HCX_FILTER_OUI_CLIENT:
		ouiinstring = optarg;
		if(getfield(ouiinstring, 3, filterouiclient) != 3)
			{
			fprintf(stderr, "wrong OUI format\n");
			exit(EXIT_FAILURE);
			}
		flagfilterouiclient = true;
		break;

		case HCX_FILTER_RC:
		flagfilterrcchecked = true;
		break;

		case HCX_FILTER_M12:
		flagfilterauthorized = true;
		break;

		case HCX_FILTER_M1234:
		flagfilternotauthorized = true;
		break;

		case HCX_FILTER_APLESS:
		flagfilterapless = true;
		break;

		case HCX_PSK:
		pskptr = optarg;
		pskptrlen = strlen(pskptr);
		if((pskptrlen < 0) || (pskptrlen > 63))
			{
			fprintf(stderr, "only 0...63 characters allowed\n");
			exit(EXIT_FAILURE);
			}
		flagpsk = true;
		break;

		case HCX_PMK:
		pmkinstring = optarg;
		if(getfield(pmkinstring, 32, pmk) != 32)
			{
			fprintf(stderr, "wrong PMK length \n");
			exit(EXIT_FAILURE);
			}
		flagpmk = true;
		break;

		case HCX_DOWNLOAD_OUI:
		downloadoui();
		break;

		case HCX_HCCAPX_OUT:
		hccapxoutname = optarg;
		break;

		case HCX_HCCAP_OUT:
		hccapxoutname = optarg;
		break;

		case HCX_JOHN_OUT:
		johnoutname = optarg;
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

if(essidlenmin > essidlenmax)
	{
	fprintf(stderr, "minimum ESSID length is > maximum ESSID length\n");
	exit(EXIT_FAILURE);
	}

if(argc < 2)
	{
	fprintf(stderr, "no option selected\n");
	return EXIT_SUCCESS;
	}

if(initlists() == false) exit(EXIT_FAILURE);

readoui();
if((ouicount > 0) && (flagvendorout == true))
	{
	showvendorlist();
	printstatus();
	closelists();
	return EXIT_SUCCESS;
	}

if(pmkideapolinname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapolinname, "r")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkideapolinname, strerror(errno));
		closelists();
		exit(EXIT_FAILURE);
		}
	}

if(fh_pmkideapol != NULL) readpmkideapolfile(fh_pmkideapol);
if(hashtypein > 0) hashtype = hashtypein;

if((pmkideapolcount > 0) && (essidoutname != NULL)) processessid(essidoutname);
if((pmkideapolcount > 0) && (pmkideapoloutname != NULL)) writeeapolpmkidfile(pmkideapoloutname);
if((pmkideapolcount > 0) && (infooutname != NULL)) writeinfofile(infooutname);
if((pmkideapolcount > 0) && (flagessidgroup == true)) writeeapolpmkidessidgroups();
if((pmkideapolcount > 0) && (flagmacapgroup == true)) writeeapolpmkidmacapgroups();
if((pmkideapolcount > 0) && (flagmacclientgroup == true)) writeeapolpmkidmacclientgroups();
if((pmkideapolcount > 0) && (flagouigroup == true)) writeeapolpmkidouigroups();
if((pmkideapolcount > 0) && (flagpsk == true)) testhashfilepsk();
if((pmkideapolcount > 0) && (flagpmk == true)) testhashfilepmk();
if((pmkideapolcount > 0) && (hccapxoutname != NULL)) writehccapxfile(hccapxoutname);
if((pmkideapolcount > 0) && (hccapoutname != NULL)) writehccapfile(hccapoutname);
if((pmkideapolcount > 0) && (johnoutname != NULL)) writejohnfile(johnoutname);

printstatus();
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
closelists();
return EXIT_SUCCESS;
}
/*===========================================================================*/

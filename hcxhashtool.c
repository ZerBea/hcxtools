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

#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/version.h"
#include "include/hcxhashtool.h"
#include "include/strings.c"
#include "include/fileops.c"
#include "include/ieee80211.h"

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
static bool flagvendorout;

static bool flagfilterouiap;
static uint8_t filterouiap[3];

static bool flagfilterouiclient;
static uint8_t filterouiclient[3];

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

if((hashlist = (hashlist_t*)calloc(hashlistcount, HASHLIST_SIZE)) == NULL) return false;
if((ouilist = (ouilist_t*)calloc(ouilistcount, OUILIST_SIZE)) == NULL) return false;

return true;
}
/*===========================================================================*/
static void printstatus()
{
printf("\nOUI information file...: %s\n", usedoui);
if(ouicount > 0)		printf("OUI entires............: %d\n", ouicount);
if(readcount > 0)		printf("total lines read.......: %ld\n", readcount);
if(flagvendorout == true)
	{
	printf("\n");
	return;
	}
if(readerrorcount > 0)		printf("read errors............: %ld\n", readerrorcount);
if(pmkideapolcount > 0)		printf("valid hash lines.......: %ld\n", pmkideapolcount);
if(pmkidcount > 0)		printf("PMKID hash lines.......: %ld\n", pmkidcount);
if(eapolcount > 0)		printf("EAPOL hash lines.......: %ld\n", eapolcount);
printf("filter by ESSID len min: %d\n", essidlenmin);
printf("filter by ESSID len max: %d\n", essidlenmax);
if(filteressidptr != NULL)	printf("filter by ESSID........: %s\n", filteressidptr);
if(filteressidpartptr != NULL)	printf("filter by part of ESSID: %s\n", filteressidpartptr);
if(flagfilterouiap == true)	printf("filter AP by OUI.......: %02x%02x%02x\n", filterouiap[0], filterouiap[1], filterouiap[2]);
if(filtervendorptr != NULL)	printf("filter AP by VENDOR....: %s\n", filtervendorptr);
if(flagfilterouiclient == true)	printf("filter CLIENT by OUI...: %02x%02x%02x\n", filterouiclient[0], filterouiclient[1], filterouiclient[2]);
if(pmkidwrittencount > 0)	printf("PMKID written..........: %ld\n", pmkidwrittencount);
if(eapolwrittencount > 0)	printf("EAPOL written..........: %ld\n", eapolwrittencount);
if(essidwrittencount > 0)	printf("ESSID (unique) written.: %ld\n", essidwrittencount);
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
		fprintf(stdout, "xxxx  \n");
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
		fprintf(stdout, ":%s\n", pskptr);
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
		fprintf(stdout, ":%s\n", pskptr);
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
	fprintf(stdout, ":%s\n" , pskptr);
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
static void processessid(char *essidoutname)
{
static long int pc;
static hashlist_t *zeiger, *zeigerold;
static FILE *fh_essid;
static struct stat statinfo;

if((fh_essid = fopen(essidoutname, "a+")) == NULL)
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
/*===========================================================================*/
static bool ispartof(int plen, uint8_t *pbuff, int slen, uint8_t *sbuff)
{
static int p;
if(plen > slen) return false;

for(p = 0; p <= slen -plen; p++)
	{
	if(memcmp(&sbuff[p], pbuff, plen) == 0) return true;
	}
printf("hallo\n");
return false;
}
/*===========================================================================*/
/*===========================================================================*/
static void writepmkideapolhashline(FILE *fh_pmkideapol, hashlist_t *zeiger)
{
static int p;

if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
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
static void writepmkideapolhashlineinfo(FILE *fh_pmkideapol, hashlist_t *zeiger)
{
static char *vendor;

if((zeiger->essidlen < essidlenmin) || (zeiger->essidlen > essidlenmax)) return;
if(((zeiger->type &hashtype) != HCX_TYPE_PMKID) && ((zeiger->type &hashtype) != HCX_TYPE_EAPOL)) return;
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





fprintf(fh_pmkideapol, "SSID......: %.*s\n", zeiger->essidlen, zeiger->essid);
vendor = getvendor(zeiger->ap);
fprintf(fh_pmkideapol, "MAC_AP....: %02x%02x%02x%02x%02x%02x (%s)\n", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], vendor);
vendor = getvendor(zeiger->client);
fprintf(fh_pmkideapol, "MAC_CLIENT: %02x%02x%02x%02x%02x%02x (%s)\n", zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5], vendor);
if(zeiger->type == HCX_TYPE_PMKID)
	{
	fprintf(fh_pmkideapol, "PMKID.....: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15]);
	}
if(zeiger->type == HCX_TYPE_EAPOL)
	{
	fprintf(fh_pmkideapol, "MIC.......: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15]);
	}
fprintf(fh_pmkideapol, "HASHLINE..: ");
writepmkideapolhashline(fh_pmkideapol, zeiger);
fprintf(fh_pmkideapol, "\n");
return;
}
/*===========================================================================*/
static void writeeapolpmkidgroups()
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
static void writeinfofile(char *infooutname)
{
static hashlist_t *zeiger;
static FILE *fh_info;

if(strcmp(infooutname, "stdout") != 0)
	{
	if((fh_info = fopen(infooutname, "a+")) == NULL)
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
static void writeeapolpmkidfile(char *pmkideapoloutname)
{
static FILE *fh_pmkideapol;
static hashlist_t *zeiger;
static struct stat statinfo;

if(pmkideapoloutname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapoloutname, "a+")) == NULL)
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
	"--type                      : filter by hash type\n"
	"                            : default PMKID (1) and EAPOL (2)\n"
	"--essid-group               : convert to ESSID groups\n"
	"                              full advantage of reuse of PBKDF2\n"
	"--essid-len                 : filter by ESSID length\n"
	"                            : default ESSID length: %d...%d\n"
	"--essid-min                 : filter by ESSID minimum length\n"
	"                            : default ESSID minimum length: %d\n"
	"--essid-max                 : filter by ESSID maximum length\n"
	"                            : default ESSID maximum length: %d\n"
	"--essid=<ESSID>             : filter by ESSID\n"
	"--essid_part=<part ofESSID> : filter by part of ESSID\n"
	"--oui-ap                    : filter AP by OUI\n"
	"                            : format: 001122 (hex)\n"
	"--oui-client                : filter CLIENT by OUI\n"
	"                            : format: 001122 (hex)\n"
	"--vendor=<VENDOR>           : filter by (part of) VENDOR name\n"
	"--info=<file>               : output detailed information about content of hash file\n"
	"--info=stdout               : stdout output detailed information about content of hash file\n"
	"--vendorlist                : stdout output VENDOR list sorted by OUI\n"
	"--psk=<PSK>                 : pre-shared key to test\n"
	"                            : due to PBKDF2 calculation this is a very slow process\n"
	"                            : no nonce error corrections\n"
	"--pmk=<PMK>                 : plain master key to test\n"
	"                            : no nonce error corrections\n"
	"--help                      : show this help\n"
	"--version                   : show version\n"
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
static char *infooutname;
static char *ouiinstring;
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
	{"oui-ap",			required_argument,	NULL,	HCX_FILTER_OUI_AP},
	{"vendor",			required_argument,	NULL,	HCX_FILTER_VENDOR},
	{"oui-client",			required_argument,	NULL,	HCX_FILTER_OUI_CLIENT},
	{"psk",				required_argument,	NULL,	HCX_PSK},
	{"pmk",				required_argument,	NULL,	HCX_PMK},
	{"vendorlist",			no_argument,		NULL,	HCX_VENDOR_OUT},
	{"info",			required_argument,	NULL,	HCX_INFO_OUT},
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
ouiinstring = NULL;
pmkinstring = NULL;
filteressidptr = NULL;
filteressidpartptr = NULL;
filtervendorptr = NULL;
flagfilterouiap = false;
flagfilterouiclient = false;
flagpsk = false;
flagpmk = false;
flagessidgroup = false;
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

		case HCX_FILTER_OUI_AP:
		ouiinstring = optarg;
		if(getfield(ouiinstring, 3, filterouiap) != 3)
			{
			fprintf(stderr, "wrong OUI format\n");
			exit(EXIT_FAILURE);
			}
		flagfilterouiap = true;
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
	if((fh_pmkideapol = fopen(pmkideapolinname, "a+")) == NULL)
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
if((pmkideapolcount > 0) && (flagessidgroup == true)) writeeapolpmkidgroups();
if((pmkideapolcount > 0) && (flagpsk == true)) testhashfilepsk();
if((pmkideapolcount > 0) && (flagpmk == true)) testhashfilepmk();

printstatus();
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
closelists();
return EXIT_SUCCESS;
}
/*===========================================================================*/

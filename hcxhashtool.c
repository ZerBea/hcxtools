#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <regex.h>

#if defined (__APPLE__) || defined(__OpenBSD__)
#include <sys/socket.h>
#endif

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <curl/curl.h>
#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "include/hcxhashtool.h"
#include "include/strings.c"
#include "include/fileops.c"
#include "include/ieee80211.c"
#include "include/byteops.c"

/*===========================================================================*/
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
/*---------------------------------------------------------------------------*/
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
/*===========================================================================*/
/* global var */
static const char *usedoui;
static int ouicount;
static int ouilistcount;
static ouilist_t *ouilist;
static hashlist_t *hashlist;
static long int pbkdf2count;
static long int pbkdf2readerrorcount;
static long int hashlistcount;
static long int readcount;
static long int readerrorcount;
static long int correctedcount;
static long int pmkideapolcount;
static long int pmkidcount;
static long int eapolcount;
static long int pmkidwrittencount;
static long int eapolwrittencount;
static long int essidwrittencount;
static long int essidrawwrittencount;
static long int hccapxwrittencount;
static long int hccapwrittencount;
static long int johnpmkidwrittencount;
static long int johneapolwrittencount;

static EVP_MAC *hmac;
static EVP_MAC *cmac;
static EVP_MAC_CTX *ctxhmac;
static EVP_MAC_CTX *ctxcmac;
static OSSL_PARAM paramsmd5[3];
static OSSL_PARAM paramssha1[3];
static OSSL_PARAM paramssha256[3];
static OSSL_PARAM paramsaes128[3];

static int hashtype;
static int essidlen;
static int essidlenmin;
static int essidlenmax;
static int filteressidlen;
static char *filteressidptr;
static regex_t essidregex;
static int filteressidpartlen;
static char *filteressidpartptr;
static char *filteressidregexptr;

static char *filtervendorptr;
static char *filtervendorapptr;
static char *filtervendorclientptr;

static bool flagpsk;
static bool flagpmk;
static bool flagessidgroup;
static bool flagmacapgroup;
static bool flagmacclientgroup;
static bool flagouigroup;
static bool flagvendorout;
static bool flaghccapsingleout;
static bool caseflag;
static bool statusflag;

static bool flagfiltermacap;
static uint8_t filtermacap[6];

static bool flagfiltermacclient;
static uint8_t filtermacclient[6];

static bool flagfilterouiap;
static uint8_t filterouiap[3];

static bool flagfilterouiclient;
static uint8_t filterouiclient[3];

static bool flagfilterauthorized;
static bool flagfilterchallenge;
static bool flagfilterrcchecked;
static bool flagfilterrcnotchecked;
static bool flagfilterapless;

static int pskptrlen;
static char *pskptr;
static uint8_t pmk[32];
/*===========================================================================*/
static void closelists(void)
{
if(hashlist != NULL) free(hashlist);
if(ouilist != NULL) free(ouilist);
if(filteressidregexptr != NULL) regfree(&essidregex);
if(ctxhmac != NULL)
	{
	EVP_MAC_CTX_free(ctxhmac);
	EVP_MAC_free(hmac);
	}
if(ctxcmac != NULL)
	{
	EVP_MAC_CTX_free(ctxcmac);
	EVP_MAC_free(cmac);
	}
EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();
return;
}
/*===========================================================================*/
static bool initlists(void)
{
ouicount = 0;
ouilistcount = OUILIST_MAX;
hashlistcount = HASHLIST_MAX;
readcount = 0;
correctedcount = 0;
readerrorcount = 0;
pmkideapolcount = 0;
readerrorcount = 0;
pmkidcount = 0;
eapolcount = 0;
pmkidwrittencount = 0;
eapolwrittencount = 0;
essidwrittencount = 0;
essidrawwrittencount = 0;
johnpmkidwrittencount = 0;
johneapolwrittencount = 0;
hccapxwrittencount = 0;
hccapwrittencount = 0;
if((hashlist = (hashlist_t*)calloc(hashlistcount, HASHLIST_SIZE)) == NULL) return false;
if((ouilist = (ouilist_t*)calloc(ouilistcount, OUILIST_SIZE)) == NULL) return false;

ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();

hmac = NULL;
ctxhmac = NULL;
cmac = NULL;
ctxcmac = NULL;

hmac = EVP_MAC_fetch(NULL, "hmac", NULL);
if(hmac == NULL) return false;
cmac = EVP_MAC_fetch(NULL, "cmac", NULL);
if(cmac == NULL) return false;

char md5[] = "md5";
paramsmd5[0] = OSSL_PARAM_construct_utf8_string("digest", md5, 0);
paramsmd5[1] = OSSL_PARAM_construct_end();

char sha1[] = "sha1";
paramssha1[0] = OSSL_PARAM_construct_utf8_string("digest", sha1, 0);
paramssha1[1] = OSSL_PARAM_construct_end();

char sha256[] = "sha256";
paramssha256[0] = OSSL_PARAM_construct_utf8_string("digest", sha256, 0);
paramssha256[1] = OSSL_PARAM_construct_end();

char aes[] = "aes-1280-cbc";
paramsaes128[0] = OSSL_PARAM_construct_utf8_string("cipher", aes, 0);
paramsaes128[1] = OSSL_PARAM_construct_end();

ctxhmac = EVP_MAC_CTX_new(hmac);
if(ctxhmac == NULL) return false;
ctxcmac = EVP_MAC_CTX_new(cmac);
if(ctxcmac == NULL) return false;
return true;
}
/*===========================================================================*/
static char *getvendor(uint8_t *mac)
{
static ouilist_t * zeiger;
static char unknown[] = "Unknown";

for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++)
	{
	if(memcmp(zeiger->oui, mac, 3) == 0) return zeiger->vendor;
	if(memcmp(zeiger->oui, mac, 3) > 0) return unknown;
	}
return unknown;
}
/*===========================================================================*/
static void printstatus(void)
{
static char *vendor;

fprintf(stdout, "\nOUI information file..........: %s\n", usedoui);
if(ouicount > 0)		fprintf(stdout, "OUI entries...................: %d\n", ouicount);
if(readcount > 0)		fprintf(stdout, "total lines read..............: %ld\n", readcount);
if(flagvendorout == true)
	{
	fprintf(stdout, "\n");
	return;
	}
if(pbkdf2count > 0)			fprintf(stdout, "PBKDF2 lines..................: %ld\n", pbkdf2count);
if(pbkdf2readerrorcount > 0)		fprintf(stdout, "PBKDF2 errors.................: %ld\n", pbkdf2readerrorcount);
if(readerrorcount > 0)			fprintf(stdout, "read/format errors.........  .: %ld\n", readerrorcount);
if(correctedcount > 0)			fprintf(stdout, "corrected read/format errors  : %ld\n", correctedcount);
if(pmkideapolcount > 0)			fprintf(stdout, "valid hash lines..............: %ld\n", pmkideapolcount);
if(pmkidcount > 0)			fprintf(stdout, "PMKID hash lines..............: %ld\n", pmkidcount);
if(eapolcount > 0)			fprintf(stdout, "EAPOL hash lines..............: %ld\n", eapolcount);
if(essidlenmin != 0)			fprintf(stdout, "filter by ESSID len min.......: %d\n", essidlenmin);
if(essidlenmax != 32)			fprintf(stdout, "filter by ESSID len max.......: %d\n", essidlenmax);
if(filteressidptr != NULL)		fprintf(stdout, "filter by ESSID...............: %s\n", filteressidptr);
if(filteressidpartptr != NULL)		fprintf(stdout, "filter by part of ESSID.......: %s\n", filteressidpartptr);
if(filteressidregexptr != NULL)		fprintf(stdout, "filter by ESSID RegEx.........: %s\n", filteressidregexptr);
if(flagfiltermacap == true)
	{
	vendor = getvendor(filtermacap);
	fprintf(stdout, "filter by MAC.................: %02x%02x%02x%02x%02x%02x (%s)\n", filtermacap[0], filtermacap[1], filtermacap[2], filtermacap[3], filtermacap[4], filtermacap[5], vendor);
	}
if(flagfiltermacclient == true)
	{
	vendor = getvendor(filtermacclient);
	fprintf(stdout, "filter by MAC.................: %02x%02x%02x%02x%02x%02x (%s)\n", filtermacclient[0], filtermacclient[1], filtermacclient[2], filtermacclient[3], filtermacclient[4], filtermacclient[5], vendor);
	}

if(flagfilterouiap == true)
	{
	vendor = getvendor(filterouiap);
	fprintf(stdout, "filter AP by OUI..............: %02x%02x%02x (%s)\n", filterouiap[0], filterouiap[1], filterouiap[2], vendor);
	}
if(filtervendorptr != NULL)		fprintf(stdout, "filter AP and CLIENT by VENDOR: %s\n", filtervendorptr);
if(filtervendorapptr != NULL)		fprintf(stdout, "filter AP by VENDOR...........: %s\n", filtervendorapptr);
if(filtervendorclientptr != NULL)	fprintf(stdout, "filter CLIENT by VENDOR.......: %s\n", filtervendorclientptr);
if(flagfilterouiclient == true)
	{
	vendor = getvendor(filterouiclient);
	fprintf(stdout, "filter CLIENT by OUI..........: %02x%02x%02x (%s)\n", filterouiclient[0], filterouiclient[1], filterouiclient[2], vendor);
	}
if(flagfilterapless == true)		fprintf(stdout, "filter by M2..................: requested from client (AP-LESS)\n");
if(flagfilterrcchecked == true)		fprintf(stdout, "filter by NC..................: nonce-error-corrections not necessary\n");
if(flagfilterrcnotchecked == true)	fprintf(stdout, "filter by NC..................: nonce-error-corrections necessary\n");
if(flagfilterauthorized == true)	fprintf(stdout, "filter by status..............: authorized (M1M4, M2M3 or M3M4)\n");
if(flagfilterchallenge == true)	fprintf(stdout, "filter by status..............: challenge (M1M2)\n");
if(pmkidwrittencount > 0)		fprintf(stdout, "PMKID written.................: %ld\n", pmkidwrittencount);
if(eapolwrittencount > 0)		fprintf(stdout, "EAPOL written.................: %ld\n", eapolwrittencount);
if(johnpmkidwrittencount > 0)		fprintf(stdout, "PMKID written to john.........: %ld\n", johnpmkidwrittencount);
if(johneapolwrittencount > 0)		fprintf(stdout, "EAPOL written to john.........: %ld\n", johneapolwrittencount);
if(hccapxwrittencount > 0)		fprintf(stdout, "EAPOL written to hccapx.......: %ld\n", hccapxwrittencount);
if(hccapwrittencount > 0)		fprintf(stdout, "EAPOL written to hccap........: %ld\n", hccapwrittencount);
if(essidwrittencount > 0)		fprintf(stdout, "ESSID (unique) written........: %ld\n", essidwrittencount);
if(essidrawwrittencount > 0)		fprintf(stdout, "ESSID written.................: %ld\n", essidrawwrittencount);
fprintf(stdout, "\n");
return;
}
/*===========================================================================*/
static void testeapolpmk(hashlist_t *zeiger)
{
static int keyver;
static int p;
static wpakey_t *wpak;
static uint8_t *pkeptr;

static uint8_t eapoltmp[1024];
static uint8_t pkedata[102];

wpak = (wpakey_t*)&zeiger->eapol[EAPAUTH_SIZE];
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;

if((keyver == 1) || (keyver == 2))
	{
	memset(&pkedata, 0, sizeof(pkedata));
	pkeptr = pkedata;
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
	if(!EVP_MAC_init(ctxhmac, pmk, 32, paramssha1)) return;
	if(!EVP_MAC_update(ctxhmac, pkedata, 100)) return;
	if(!EVP_MAC_final(ctxhmac, pkedata, NULL, 100)) return;
	fprintf(stdout, "\n");
	if(keyver == 2)
		{
		memset(eapoltmp, 0, 1024);
		memcpy(eapoltmp, zeiger->eapol, zeiger->eapauthlen);
		if(!EVP_MAC_init(ctxhmac, pkedata, 16, paramssha1)) return;
		if(!EVP_MAC_update(ctxhmac, eapoltmp, zeiger->eapauthlen)) return;
		if(!EVP_MAC_final(ctxhmac, eapoltmp, NULL, zeiger->eapauthlen)) return;
		}
	if(keyver == 1)
		{
		memset(eapoltmp, 0, 1024);
		memcpy(eapoltmp, zeiger->eapol, zeiger->eapauthlen);
		if(!EVP_MAC_init(ctxhmac, pkedata, 16, paramsmd5)) return;
		if(!EVP_MAC_update(ctxhmac, eapoltmp, zeiger->eapauthlen)) return;
		if(!EVP_MAC_final(ctxhmac, eapoltmp, NULL, zeiger->eapauthlen)) return;
		}
	}
else if(keyver == 3)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	pkedata[0] = 1;
	pkedata[1] = 0;
	pkeptr = pkedata +2;
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
	pkedata[100] = 0x80;
	pkedata[101] = 1;
	if(!EVP_MAC_init(ctxhmac, pmk, 32, paramssha256)) return;
	if(!EVP_MAC_update(ctxhmac, pkedata, 102)) return;
	if(!EVP_MAC_final(ctxhmac, pkedata, NULL, 102)) return;
	memset(eapoltmp, 0, 1024);
	memcpy(eapoltmp, zeiger->eapol, zeiger->eapauthlen);
	if(!EVP_MAC_init(ctxcmac, pkedata, 16, paramsaes128)) return;
	if(!EVP_MAC_update(ctxcmac, eapoltmp, zeiger->eapauthlen)) return;
	if(!EVP_MAC_final(ctxcmac, eapoltmp, NULL, zeiger->eapauthlen)) return;
	}
else return;
if(memcmp(eapoltmp, zeiger->hash, 16) == 0)
	{
	for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->client[p]);
	fprintf(stdout, ":");
	for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->ap[p]);
	if(zeiger->essidlen != 0)
		{
		if(ispotfilestring(zeiger->essidlen, (char*)zeiger->essid) == true) fprintf(stdout, ":%.*s", zeiger->essidlen, zeiger->essid);
		else
			{
			fprintf(stdout, ":$HEX[");
			for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
			fprintf(stdout, "]");
			}
		}
	else fprintf(stdout, ":");
	fprintf(stdout, ":%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
		pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],
		pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],
		pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],
		pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);
	if(pskptr != NULL)
		{
		if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s", pskptr);
		else
			{
			fprintf(stdout, ":$HEX[");
			for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);
			fprintf(stdout, "]");
			}
		}
	fprintf(stdout, "\n");
	}
return;
}
/*===========================================================================*/
static void testpmkidpmk(hashlist_t *zeiger)
{
static int p;
static const char *pmkname = "PMK Name";
static uint8_t message[20];

memcpy(message, pmkname, 8);
memcpy(&message[8], zeiger->ap, 6);
memcpy(&message[14], zeiger->client, 6);
if(!EVP_MAC_init(ctxhmac, pmk, 32, paramssha1)) return;
if(!EVP_MAC_update(ctxhmac, message, 20)) return;
if(!EVP_MAC_final(ctxhmac, message, NULL, 20)) return;
if(memcmp(message, zeiger->hash, 16) == 0)
	{
	for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->client[p]);
	fprintf(stdout, ":");
	for(p = 0; p < 6; p++) fprintf(stdout, "%02x", zeiger->ap[p]);
	if(zeiger->essidlen != 0)
		{
		if(ispotfilestring(zeiger->essidlen, (char*)zeiger->essid) == true) fprintf(stdout, ":%.*s", zeiger->essidlen, zeiger->essid);
		else
			{
			fprintf(stdout, ":$HEX[");
			for(p = 0; p < zeiger->essidlen; p++) fprintf(stdout, "%02x", zeiger->essid[p]);
			fprintf(stdout, "]");
			}
		}
	else fprintf(stdout, ":");
	fprintf(stdout, ":%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", 
		pmk[0], pmk[1], pmk[2], pmk[3], pmk[4], pmk[5], pmk[6], pmk[7],
		pmk[8], pmk[9], pmk[10], pmk[11], pmk[12], pmk[13], pmk[14], pmk[15],
		pmk[16], pmk[17], pmk[18], pmk[19], pmk[20], pmk[21], pmk[22], pmk[23],
		pmk[24], pmk[25], pmk[26], pmk[27], pmk[28], pmk[29], pmk[30], pmk[31]);
	if(pskptr != NULL)
		{
		if(ispotfilestring(pskptrlen, pskptr) == true) fprintf(stdout, ":%s", pskptr);
		else
			{
			fprintf(stdout, ":$HEX[");
			for(p = 0; p < pskptrlen; p++) fprintf(stdout, "%02x", pskptr[p]);
			fprintf(stdout, "]");
			}
		}
	fprintf(stdout, "\n");
	}
return;
}
/*===========================================================================*/
static void testhashfilepmk(void)
{
static hashlist_t *zeiger;

for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);
	else if (zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);
	}
return;
}
/*===========================================================================*/
static bool dopbkdf2(int psklen, char *psk, int essidlen, uint8_t *essid)
{
if(PKCS5_PBKDF2_HMAC_SHA1(psk, psklen, essid, essidlen, 4096, 32, pmk) == 0) return false;
return true;
}
/*===========================================================================*/
static void testhashfilepsk(void)
{
static hashlist_t *zeiger, *zeigerold;

zeigerold = hashlist;
if(dopbkdf2(pskptrlen, pskptr, zeigerold->essidlen, zeigerold->essid) == true)
	{
	if(zeigerold->type == HCX_TYPE_PMKID) testpmkidpmk(zeigerold);
	if(zeigerold->type == HCX_TYPE_EAPOL) testeapolpmk(zeigerold);
	}
for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	if((zeigerold->essidlen == zeiger->essidlen) && (memcmp(zeigerold->essid, zeiger->essid, zeigerold->essidlen) == 0))
		{
		if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);
		if(zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);
		}
	else
		{
		if(dopbkdf2(pskptrlen, pskptr, zeiger->essidlen, zeiger->essid) == true)
			{
			if(zeiger->type == HCX_TYPE_PMKID) testpmkidpmk(zeiger);
			if(zeiger->type == HCX_TYPE_EAPOL) testeapolpmk(zeiger);
			}
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
static bool isoui(uint8_t *macap, uint8_t *macclient)
{
static ouilist_t *zeiger;

for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++)
	{
	if(((zeiger->type &TYPE_AP) == TYPE_AP) && (memcmp(macap, zeiger->oui, 3) == 0)) return true;
	if(((zeiger->type &TYPE_CLIENT) == TYPE_CLIENT) && (memcmp(macclient, zeiger->oui, 3) == 0)) return true;
	}
return false;
}
/*===========================================================================*/
static bool ispartof(int plen, uint8_t *pbuff, int slen, uint8_t *sbuff)
{
static int p;
static uint8_t buffers[32];
static uint8_t bufferp[32];

if(plen > slen) return false;
if(caseflag == false)
	{
	for(p = 0; p <= slen -plen; p++)
		{
		if(memcmp(&sbuff[p], pbuff, plen) == 0) return true;
		}
	return false;
	}
else
	{
	memset(buffers, 0, 32);
	for(p = 0; p < slen; p++)
		{
		if(isupper(sbuff[p])) buffers[p] = tolower(sbuff[p]);
		else buffers[p] = sbuff[p];
		}
	memset(bufferp, 0, 32);
	for(p = 0; p < plen; p++)
		{
		if(isupper(pbuff[p])) bufferp[p] = tolower(pbuff[p]);
		else bufferp[p] = pbuff[p];
		}
	for(p = 0; p <= slen -plen; p++)
		{
		if(memcmp(&buffers[p], bufferp, plen) == 0) return true;
		}
	return false;
	}
return false;
}
/*===========================================================================*/
static void hccap2base(unsigned char *in, unsigned char b, FILE *fh_john)
{
static const char itoa64[65] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

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
static wpakey_t *wpak;
static int i;
static char essid[ESSID_LEN_MAX+1];
static unsigned char *hcpos;
static hccap_t hccap;

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
if(filteressidregexptr != NULL)
	{
	strncpy(essid, (char*)zeiger->essid, zeiger->essidlen);
	essid[zeiger->essidlen] = '\0';
	if(regexec(&essidregex, essid, 0, NULL, 0) == REG_NOMATCH) return;
	}
if((filtervendorptr != NULL) || (filtervendorapptr != NULL) || (filtervendorclientptr != NULL))
	{
	if(isoui(zeiger->ap, zeiger->client) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) == 0x80)) return;
if((flagfilterrcnotchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilterchallenge == true) && ((zeiger->mp &0x07) != 0x01)) return;

if(zeiger->type == HCX_TYPE_PMKID)
	{
	fprintf(fh_john, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
		zeiger->hash[0], zeiger->hash[1], zeiger->hash[2], zeiger->hash[3], zeiger->hash[4], zeiger->hash[5], zeiger->hash[6], zeiger->hash[7],
		zeiger->hash[8], zeiger->hash[9], zeiger->hash[10], zeiger->hash[11], zeiger->hash[12], zeiger->hash[13], zeiger->hash[14], zeiger->hash[15],
		zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5],
		zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);
	for(i = 0; i < zeiger->essidlen; i++) fprintf(fh_john, "%02x", zeiger->essid[i]);
	fprintf(fh_john, "\n");
	johnpmkidwrittencount++;
	return;
	}
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
fprintf(fh_john, ":converted by hcxhashtool\n");
johneapolwrittencount++;
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
		fprintf(stdout, "error opening file %s: %s\n", johnoutname, strerror(errno));
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
static char essid[ESSID_LEN_MAX+1];

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
if(filteressidregexptr != NULL)
	{
	strncpy(essid, (char *) zeiger->essid, zeiger->essidlen);
    essid[zeiger->essidlen] = '\0';
	if(regexec(&essidregex, essid, 0, NULL, 0) == REG_NOMATCH) return;
	}
if((filtervendorptr != NULL) || (filtervendorapptr != NULL) || (filtervendorclientptr != NULL))
	{
	if(isoui(zeiger->ap, zeiger->client) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) == 0x80)) return;
if((flagfilterrcnotchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilterchallenge == true) && ((zeiger->mp &0x07) != 0x01)) return;

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
static void writehccapsinglefile(void)
{
static int c;
static FILE *fh_hccap;
static hashlist_t *zeiger;
static struct stat statinfo;
static char groupoutname[PATH_MAX];

for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	c = 0;
	do
		{
		snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x-%04d.hccap", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5], c);
		c++;
		}
	while (stat(groupoutname, &statinfo) == 0); 
	if((fh_hccap = fopen(groupoutname, "a")) == NULL) continue;
	writehccaprecord(fh_hccap, zeiger);
	if(fh_hccap != NULL) fclose(fh_hccap);
	if(stat(groupoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(groupoutname);
		}
	}
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
		fprintf(stdout, "error opening file %s: %s\n", hccapoutname, strerror(errno));
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
static wpakey_t *wpak;
static hccapx_t hccapx;
static char essid[ESSID_LEN_MAX+1];

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
if(filteressidregexptr != NULL)
	{
	strncpy(essid, (char *) zeiger->essid, zeiger->essidlen);
    essid[zeiger->essidlen] = '\0';
	if(regexec(&essidregex, essid, 0, NULL, 0) == REG_NOMATCH) return;
	}
if((filtervendorptr != NULL) || (filtervendorapptr != NULL) || (filtervendorclientptr != NULL))
	{
	if(isoui(zeiger->ap, zeiger->client) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) == 0x80)) return;
if((flagfilterrcnotchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilterchallenge == true) && ((zeiger->mp &0x07) != 0x01)) return;

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
		fprintf(stdout, "error opening file %s: %s\n", hccapxoutname, strerror(errno));
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
static void processessidraw(char *essidrawoutname)
{
static long int pc;
static hashlist_t *zeiger;
static FILE *fh_essid;
static struct stat statinfo;

if((fh_essid = fopen(essidrawoutname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", essidrawoutname, strerror(errno));
	return;
	}
for(pc = 0; pc < pmkideapolcount; pc++)
	{
	zeiger = hashlist +pc;
	fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_essid);
	essidrawwrittencount++;
	}
fclose(fh_essid);
if(stat(essidrawoutname, &statinfo) == 0)
	{
	if(statinfo.st_size == 0) remove(essidrawoutname);
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

if(strcmp(essidoutname, "stdout") != 0)
	{
	if((fh_essid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", essidoutname, strerror(errno));
		return;
		}
	zeigerold = NULL;
	qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
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
	}
else
	{
	statusflag = false;
	zeigerold = NULL;
	qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
	for(pc = 0; pc < pmkideapolcount; pc++)
		{
		zeiger = hashlist +pc;
		if(zeigerold != NULL)
			{
			if(memcmp(zeiger->essid, zeigerold->essid, ESSID_LEN_MAX) == 0) continue;
			}
		fwriteessidstr(zeiger->essidlen, zeiger->essid, stdout);
		essidwrittencount++;
		zeigerold = zeiger;
		}
	}
return;
}
/*===========================================================================*/
static void writepmkideapolhashline(FILE *fh_pmkideapol, hashlist_t *zeiger)
{
static int p;
static char essid[ESSID_LEN_MAX+1];

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
if(filteressidregexptr != NULL)
	{
	strncpy(essid, (char *) zeiger->essid, zeiger->essidlen);
    essid[zeiger->essidlen] = '\0';
    //p = regexec(&essidregex, essid, 0, NULL, 0);
    //printf("%d\n", p);
	if(regexec(&essidregex, essid, 0, NULL, 0) == REG_NOMATCH) return;
	}
if((filtervendorptr != NULL) || (filtervendorapptr != NULL) || (filtervendorclientptr != NULL))
	{
	if(isoui(zeiger->ap, zeiger->client) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) == 0x80)) return;
if((flagfilterrcnotchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilterchallenge == true) && ((zeiger->mp &0x07) != 0x01)) return;
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
static void writeeapolpmkidessidgroups(void)
{
static int cei;
static int ceo;
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;
static const char digit[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
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
		fprintf(stdout, "error opening file %s: %s\n", groupoutname, strerror(errno));
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
static void writeeapolpmkidouigroups(void)
{
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;
static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x.22000", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2]);
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", groupoutname, strerror(errno));
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
static void writeeapolpmkidmacapgroups(void)
{
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;
static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x.22000", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], zeiger->ap[3], zeiger->ap[4], zeiger->ap[5]);
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", groupoutname, strerror(errno));
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
static void writeeapolpmkidmacclientgroups(void)
{
static hashlist_t *zeiger;
static FILE *fh_pmkideapol;
static struct stat statinfo;
static char groupoutname[PATH_MAX];

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
for(zeiger = hashlist; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	snprintf(groupoutname, PATH_MAX -1, "%02x%02x%02x%02x%02x%02x.22000", zeiger->client[0], zeiger->client[1], zeiger->client[2], zeiger->client[3], zeiger->client[4], zeiger->client[5]);
	if((fh_pmkideapol = fopen(groupoutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", groupoutname, strerror(errno));
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
static void writelceapolpmkidfile(char *pmkideapoloutname, long int lcmin, long int lcmax)
{
static long int lc;
static FILE *fh_pmkideapol;
static hashlist_t *zeiger;
static hashlist_t *zeiger2;
static hashlist_t *zeigerbegin;
static hashlist_t *zeigerend;
static struct stat statinfo;

if(lcmax == 0) lcmax = pmkideapolcount;
if(lcmin > lcmax) return;
if(pmkideapoloutname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", pmkideapoloutname, strerror(errno));
		return;
		}
	}
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essid);
zeigerbegin = hashlist;
lc = 0;
for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
	{
	if(memcmp(zeigerbegin->essid, zeiger->essid, ESSID_LEN_MAX) == 0)
		{
		zeigerend = zeiger;
		lc++;
		}
	else
		{
		if(((zeigerend -zeigerbegin) >= lcmin) && ((zeigerend -zeigerbegin) <= lcmax))
			{
			for(zeiger2 = zeigerbegin; zeiger2 <= zeigerend; zeiger2++) writepmkideapolhashline(fh_pmkideapol, zeiger2);
			}
		lc = 0;
		zeigerbegin = zeiger;
		}
	}
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
static void writeeapolpmkidfile(char *pmkideapoloutname)
{
static FILE *fh_pmkideapol;
static hashlist_t *zeiger;
static struct stat statinfo;

if(pmkideapoloutname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", pmkideapoloutname, strerror(errno));
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
static uint8_t keyinfo;
static uint64_t rc;
static char *vendor;
static char essid[ESSID_LEN_MAX+1];

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
if(filteressidregexptr != NULL)
	{
	strncpy(essid, (char *) zeiger->essid, zeiger->essidlen);
    essid[zeiger->essidlen] = '\0';
	if(regexec(&essidregex, essid, 0, NULL, 0) == REG_NOMATCH) return;
	}
if((filtervendorptr != NULL) || (filtervendorapptr != NULL) || (filtervendorclientptr != NULL))
	{
	if(isoui(zeiger->ap, zeiger->client) == false) return;
	}
if((flagfilterapless == true) && ((zeiger->mp &0x10) != 0x10)) return;
if((flagfilterrcchecked == true) && ((zeiger->mp &0x80) == 0x80)) return;
if((flagfilterrcnotchecked == true) && ((zeiger->mp &0x80) != 0x80)) return;
if((flagfilterauthorized == true) && ((zeiger->mp &0x07) == 0x00)) return;
if((flagfilterchallenge == true) && ((zeiger->mp &0x07) != 0x01)) return;

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
	if((zeiger->mp & 0x20) == 0x20) fprintf(fh_pmkideapol, "ROUTER TYPE: little endian (LE)\n");
	else if((zeiger->mp & 0x40) == 0x40) fprintf(fh_pmkideapol, "ROUTER TYPE: big endian (BE)\n");
	if((zeiger->mp & 0xf0) == 0x10) fprintf(fh_pmkideapol, "NC INFO....: NC deactivated\n");
	else if((zeiger->mp & 0x80) == 0x80) fprintf(fh_pmkideapol, "NC INFO....: hashcat default NC activated\n");
	else fprintf(fh_pmkideapol, "NC INFO....: NC not detected\n");
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	fprintf(fh_pmkideapol, "EAPOL MSG..: %d\n", keyinfo);
	if((zeiger->mp & 0x07) == 0x00) fprintf(fh_pmkideapol, "MP M1M2 E2.: challenge\n");
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
static void writevendorapinfofile(char *vendorinfooutname)
{
static char *vendor;
static hashlist_t *zeiger;
static FILE *fh_info;

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macap);
if(strcmp(vendorinfooutname, "stdout") != 0)
	{
	if((fh_info = fopen(vendorinfooutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", vendorinfooutname, strerror(errno));
		return;
		}
	vendor = getvendor(hashlist->ap);
	fprintf(fh_info, "%02x%02x%02x\t%s\t[ACCESS POINT]\n", hashlist->ap[0], hashlist->ap[1], hashlist->ap[2], vendor);
	for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
		{
		if(memcmp((zeiger -1)->ap, zeiger->ap, 3) != 0)
			{
			vendor = getvendor(zeiger->ap);
			fprintf(fh_info, "%02x%02x%02x\t%s\t[ACCESS POINT]\n", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], vendor);
			}
		}
	fclose(fh_info);
	}
else
	{
	vendor = getvendor(hashlist->ap);
	fprintf(stdout, "%02x%02x%02x\t%s\t[ACCESS POINT]\n", hashlist->ap[0], hashlist->ap[1], hashlist->ap[2], vendor);
	for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
		{
		if(memcmp((zeiger -1)->ap, zeiger->ap, 3) != 0)
			{
			vendor = getvendor(zeiger->ap);
			fprintf(stdout, "%02x%02x%02x\t%s\t[ACCESS POINT]\n", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], vendor);
			}
		}
	}
return;
}
/*===========================================================================*/
static void writevendorclientinfofile(char *vendorinfooutname)
{
static char *vendor;
static hashlist_t *zeiger;
static FILE *fh_info;

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macclient);
if(strcmp(vendorinfooutname, "stdout") != 0)
	{
	if((fh_info = fopen(vendorinfooutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", vendorinfooutname, strerror(errno));
		return;
		}
	vendor = getvendor(hashlist->client);
	fprintf(fh_info, "%02x%02x%02x\t%s\t[CLIENT]\n", hashlist->client[0], hashlist->client[1], hashlist->client[2], vendor);
	for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
		{
		if(memcmp((zeiger -1)->client, zeiger->client, 3) != 0)
			{
			vendor = getvendor(zeiger->client);
			fprintf(fh_info, "%02x%02x%02x\t%s\t[CLIENT]\n", zeiger->client[0], zeiger->client[1], zeiger->client[2], vendor);
			}
		}
	fclose(fh_info);
	}
else
	{
	vendor = getvendor(hashlist->ap);
	fprintf(stdout, "%02x%02x%02x\t%s\t[CLIENT]\n", hashlist->ap[0], hashlist->ap[1], hashlist->ap[2], vendor);
	for(zeiger = hashlist +1; zeiger < hashlist +pmkideapolcount; zeiger++)
		{
		if(memcmp((zeiger -1)->ap, zeiger->ap, 3) != 0)
			{
			vendor = getvendor(zeiger->ap);
			fprintf(stdout, "%02x%02x%02x\t%s\t[CLIENT]\n", zeiger->ap[0], zeiger->ap[1], zeiger->ap[2], vendor);
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
	if((fh_info = fopen(infooutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", infooutname, strerror(errno));
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
	if(!isxdigit((unsigned char)lineptr[p +0])) return 0;
	if(!isxdigit((unsigned char)lineptr[p +1])) return 0;
	if((lineptr[p +1] == '*') || (lineptr[p +1] == 0)) return 0;
	idx0 = ((uint8_t)lineptr[p +0] &0x1F) ^0x10;
	idx1 = ((uint8_t)lineptr[p +1] &0x1F) ^0x10;
	buff[p /2] = (uint8_t)(hashmap[idx0] <<4) | hashmap[idx1];
	p += 2;
	}
return p /2;
}
/*===========================================================================*/
static void removepmkideapol(char *macskipname)
{
static int len;
static int p1, p2;
static FILE *fh_maclistin;
static long int i, f, r;
static int maclistskipcount, maclistskipmax;
static maclist_t *maclistskip, *zeiger, *maclistskipnew;
static hashlist_t *zeigerhash;
static char linein[PMKIDEAPOL_BUFFER_LEN];

maclistskipmax = 1000;
if((maclistskip = (maclist_t*)calloc(maclistskipmax, MACLIST_SIZE)) == NULL) return;
if((fh_maclistin = fopen(macskipname, "r")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", macskipname, strerror(errno));
	return;
	}
zeiger = maclistskip;
maclistskipcount = 0;
while(1)
	{
	if((len = fgetline(fh_maclistin, PMKIDEAPOL_BUFFER_LEN, linein)) == -1) break;
	if(len < 12) continue;
	if(len > 17)
		{
		p2 = 0;
		for(p1 = 0; p1 < 17; p1++)
			{
			if(isxdigit((unsigned char)linein[p1]))
				{
				linein[p2] = linein[p1];
				p2++;
				}
			}
		linein[p2] = 0;
		len = p2;
		}
	linein[12] = 0;
	if(getfield(linein, 6, zeiger->mac) != 6) continue;
	maclistskipcount++;
	if(maclistskipcount >= maclistskipmax)
		{
		maclistskipmax += 1000;
		maclistskipnew = (maclist_t*)realloc(maclistskip, maclistskipmax *MACLIST_SIZE);
		if(maclistskipnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		maclistskip = maclistskipnew;
		}
	zeiger = maclistskip +maclistskipcount;
	}
if(fh_maclistin != NULL) fclose(fh_maclistin);
qsort(maclistskip, maclistskipcount, MACLIST_SIZE, sort_maclistin);

qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macap);
zeigerhash = hashlist;
zeiger = maclistskip;
f = 0;
r = 0;
for(i = 0; i < pmkideapolcount; i++)
	{
	f = 0;
	while(f < maclistskipcount)
		{
		if(memcmp((zeigerhash +i)->ap, (zeiger +f)->mac, 6) == 0)
			{
			(zeigerhash +i)->type = HS_REMOVED;
			r++;
			}
		if(memcmp((zeiger +f)->mac, (zeigerhash +i)->ap, 6) >= 0) break;
		f++;
		}
	}
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_type);
pmkidcount -= r;
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macclient);
zeigerhash = hashlist;
zeiger = maclistskip;
f = 0;
r = 0;
for(i = 0; i < pmkideapolcount; i++)
	{
	if(memcmp((zeigerhash +i)->client, (zeiger +f)->mac, 6) > 0)
	while(f < maclistskipcount)
		{
		if(memcmp((zeiger +f)->mac, (zeigerhash +i)->client, 6) >= 0) break;
		f++;
		}
	if(memcmp((zeigerhash +i)->client, (zeiger +f)->mac, 6) == 0)
		{
		(zeigerhash +i)->type = HS_REMOVED;
		r++;
		}
	}
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_type);
pmkidcount -= r;
if(maclistskip != NULL) free(maclistskip);
return;
}
/*===========================================================================*/
static void processmacfile(char *maclistinname, char *pmkideapoloutname)
{
static int len;
static int p1, p2;
static FILE *fh_maclistin;
static FILE *fh_pmkideapol;
static struct stat statinfo;
static int maclistincount, maclistinmax;
static maclist_t *maclistin, *zeiger, *maclistinnew;
static hashlist_t *zeigerhash;
static int i, o;

static char linein[PMKIDEAPOL_BUFFER_LEN];

maclistinmax = 1000;
if((maclistin = (maclist_t*)calloc(maclistinmax, MACLIST_SIZE)) == NULL) return;
if((fh_maclistin = fopen(maclistinname, "r")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", maclistinname, strerror(errno));
	return;
	}
zeiger = maclistin;
maclistincount = 0;
while(1)
	{
	if((len = fgetline(fh_maclistin, PMKIDEAPOL_BUFFER_LEN, linein)) == -1) break;
	if(len == 17)
		{
		p2 = 0;
		for(p1 = 0; p1 < 17; p1++)
			{
			if(isxdigit((unsigned char)linein[p1]))
				{
				linein[p2] = linein[p1];
				p2++;
				}
			}
		linein[p2] = 0;
		len = p2;
		}
	if(len != 12) continue;
	if(getfield(linein, 6, zeiger->mac) != 6) continue;
	maclistincount++;
	if(maclistincount >= maclistinmax)
		{
		maclistinmax += 1000;
		maclistinnew = (maclist_t*)realloc(maclistin, maclistinmax *MACLIST_SIZE);
		if(maclistinnew == NULL)
			{
			fprintf(stdout, "failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		maclistin = maclistinnew;
		}
	zeiger = maclistin +maclistincount;
	}
if(fh_maclistin != NULL) fclose(fh_maclistin);
qsort(maclistin, maclistincount, MACLIST_SIZE, sort_maclistin);
if(pmkideapoloutname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
		{
		fprintf(stdout, "error opening file %s: %s\n", pmkideapoloutname, strerror(errno));
		free(maclistin);
		return;
		}
	}
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macap);
zeiger = maclistin;
zeigerhash = hashlist;
o = 0;
for(i = 0; i < maclistincount; i++)
	{
	while(o < pmkideapolcount)
		{
		if(memcmp((zeigerhash +o)->ap, (zeiger +i)->mac, 6) > 0) break;
		if(memcmp((zeigerhash +o)->ap, (zeiger +i)->mac, 6) == 0) writepmkideapolhashline(fh_pmkideapol, zeigerhash +o);
		o++;
		}
	}
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_macclient);
zeiger = maclistin;
zeigerhash = hashlist;
o = 0;
for(i = 0; i < maclistincount; i++)
	{
	while(o < pmkideapolcount)
		{
		if(memcmp((zeigerhash +o)->client, (zeiger +i)->mac, 6) > 0) break;
		if(memcmp((zeigerhash +o)->client, (zeiger +i)->mac, 6) == 0) writepmkideapolhashline(fh_pmkideapol, zeigerhash +o);
		o++;
		}
	}
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
if(pmkideapoloutname != NULL)
	{
	if(stat(pmkideapoloutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapoloutname);
		}
	}
if(maclistin != NULL) free(maclistin);
return;
}
/*===========================================================================*/
static void processessidfile(char *essidlistinname, char *pmkideapoloutname)
{
static int len;
static int i, o;
static FILE *fh_essidlistin;
static FILE *fh_pmkideapol;
static struct stat statinfo;
static int essidlistincount, essidlistinmax;
static essidlist_t *essidlistin, *zeiger, *essidlistinnew;
static hashlist_t *zeigerhash;
static char hexpfx[] = { "$HEX[" };
static char linein[PMKIDEAPOL_BUFFER_LEN];

essidlistinmax = 1000;
if((essidlistin = (essidlist_t*)calloc(essidlistinmax, ESSIDLIST_SIZE)) == NULL) return;
if((fh_essidlistin = fopen(essidlistinname, "r")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", essidlistinname, strerror(errno));
	return;
	}
zeiger = essidlistin;
essidlistincount = 0;
while(1)
	{
	if((len = fgetline(fh_essidlistin, PMKIDEAPOL_BUFFER_LEN, linein)) == -1) break;
	if((len < 1) || (len > 70)) continue;
	memset(zeiger->essid, 0, 33);
	if((len >= 8) && ((len %2) == 0) && (linein[len -1] == ']') && (memcmp(linein, hexpfx, 5) == 0))
		{
		linein[len -1] = 0;
		zeiger->essidlen = getfield(&linein[5], 32, zeiger->essid);
		}
	else if(len <= 32)
		{
		zeiger->essidlen = len;
		memcpy(zeiger->essid, linein, len);
		}
	else continue;
	essidlistincount++;
	if(essidlistincount >= essidlistinmax)
		{
		essidlistinmax += 1000;
		essidlistinnew = (essidlist_t*)realloc(essidlistin, essidlistinmax *ESSIDLIST_SIZE);
		if(essidlistinnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		essidlistin = essidlistinnew;
		}
	zeiger = essidlistin +essidlistincount;
	}
if(fh_essidlistin != NULL) fclose(fh_essidlistin);
qsort(essidlistin, essidlistincount, ESSIDLIST_SIZE, sort_essidlistin);
qsort(hashlist, pmkideapolcount, HASHLIST_SIZE, sort_hashlist_by_essidlen);
if(pmkideapoloutname == NULL)
	{
	if(essidlistin != NULL) free(essidlistin);
	return;
	}
if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", pmkideapoloutname, strerror(errno));
	free(essidlistin);
	return;
	}
zeiger = essidlistin;
zeigerhash = hashlist;
o = 0;
for(i = 0; i < essidlistincount; i++)
	{
	while(o < pmkideapolcount)
		{
		if((zeigerhash +o)->essidlen < (zeiger +i)->essidlen)
			{
			o++;
			continue;
			}
		if((zeigerhash +o)->essidlen > (zeiger +i)->essidlen) break;
		if((memcmp((zeigerhash +o)->essid, (zeiger +i)->essid, (zeigerhash +o)->essidlen)) > 0) break;
		if((memcmp((zeigerhash +o)->essid, (zeiger +i)->essid, (zeigerhash +o)->essidlen)) == 0) writepmkideapolhashline(fh_pmkideapol, zeigerhash +o);
		o++;
		}
	}
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
if(pmkideapoloutname != NULL)
	{
	if(stat(pmkideapoloutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapoloutname);
		}
	}
if(essidlistin != NULL) free(essidlistin);
return;
}
/*===========================================================================*/
static void readpmkideapolfile(FILE *fh_pmkideapol)
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
		if(eapauthlen > EAPOL_AUTHLEN_MAX +4)
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
		hashlistnew = (hashlist_t*)realloc(hashlist, hashlistcount *HASHLIST_SIZE);
		if(hashlistnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		hashlist = hashlistnew;
		}
	zeiger = hashlist +pmkideapolcount;
	}
return;
}
/*===========================================================================*/
static int get_keyinfo(uint16_t kyif)
{
if(kyif & WPA_KEY_INFO_ACK)
	{
	if(kyif & WPA_KEY_INFO_INSTALL) return 3; /* handshake 3 */
	else return 1; /* handshake 1 */
	}
else
	{
	if(kyif & WPA_KEY_INFO_SECURE) return 4; /* handshake 4 */
	else return 2; /* handshake 2 */
	}
return 0;
}
/*===========================================================================*/
static void readhccapxfile(int fd_hccapxin, long int hccapxrecords)
{
static long int c;
static hccapx_t *hccapxptr;
static eapauth_t *eapa;
static wpakey_t *wpak;
static uint8_t keyver;
static uint16_t keylen;
static hashlist_t *zeiger, *hashlistnew;
static uint8_t hccapxblock[HCCAPX_SIZE];

hccapxptr = (hccapx_t*)hccapxblock;
zeiger = hashlist;
for(c = 0; c < hccapxrecords; c++)
	{
	readcount++;
	if(read(fd_hccapxin, hccapxblock, HCCAPX_SIZE) != HCCAPX_SIZE)
		{
		readerrorcount++;
		continue;
		}
	if(hccapxptr->signature != HCCAPX_SIGNATURE)
		{
		readerrorcount++;
		continue;
		}
	if((hccapxptr->version != 3) && (hccapxptr->version != 4))
		{
		readerrorcount++;
		continue;
		}
	if((hccapxptr->essid_len == 0) || (hccapxptr->essid_len > ESSID_LEN_MAX))
		{
		readerrorcount++;
		continue;
		}
	wpak = (wpakey_t*)&hccapxptr->eapol[EAPAUTH_SIZE];
	if((keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK) == 0)
		{
		readerrorcount++;
		continue;
		}
	if(keyver != hccapxptr->keyver)
		{
		readerrorcount++;
		if(keyver > 3) continue;
		if(keyver == 0) continue;
		correctedcount++;
		}
	eapa = (eapauth_t*)hccapxptr->eapol;
	keylen = ntohs(eapa->len) +EAPAUTH_SIZE;
	if(keylen != hccapxptr->eapol_len)
		{
		readerrorcount++;
		if(keylen > 255) continue;
		correctedcount++;
		}
	memcpy(zeiger->ap, hccapxptr->ap, 6);
	memcpy(zeiger->client, hccapxptr->client, 6);
	memcpy(zeiger->essid, hccapxptr->essid, hccapxptr->essid_len);
	zeiger->essidlen = hccapxptr->essid_len;
	memcpy(zeiger->hash, hccapxptr->keymic, 16);
	zeiger->eapauthlen = keylen;
	memcpy(zeiger->eapol, hccapxptr->eapol, hccapxptr->eapol_len);
	if(memcmp(hccapxptr->anonce, wpak->nonce, 32) != 0) memcpy(zeiger->nonce, hccapxptr->anonce, 32);
	else if(memcmp(hccapxptr->snonce, wpak->nonce, 32) != 0) memcpy(zeiger->nonce, hccapxptr->snonce, 32);
	else
		{
		readerrorcount++;
		continue;
		}
	zeiger->type = HS_EAPOL;
	zeiger->mp = hccapxptr->message_pair;
	eapolcount++;
	pmkideapolcount = pmkidcount +eapolcount;
	if(pmkideapolcount >= hashlistcount)
		{
		hashlistcount += HASHLIST_MAX;
		hashlistnew = (hashlist_t*)realloc(hashlist, hashlistcount *HASHLIST_SIZE);
		if(hashlistnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		hashlist = hashlistnew;
		}
	zeiger = hashlist +pmkideapolcount;
	}
return;
}
/*===========================================================================*/
static void readhccapfile(int fd_hccapin, long int hccaprecords)
{
static long int c;
uint8_t el;
static hccap_t *hccapptr;
static eapauth_t *eapa;
static wpakey_t *wpak;
static uint8_t keyver;
static uint16_t keylen;
static uint16_t keyinfo = 0;

static hashlist_t *zeiger, *hashlistnew;
static uint8_t hccapblock[HCCAP_SIZE];

hccapptr = (hccap_t*)hccapblock;
zeiger = hashlist;
for(c = 0; c < hccaprecords; c++)
	{
	readcount++;
	if(read(fd_hccapin, hccapblock, HCCAP_SIZE) != HCCAP_SIZE)
		{
		readerrorcount++;
		continue;
		}
	wpak = (wpakey_t*)&hccapptr->eapol[EAPAUTH_SIZE];
	if((keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK) == 0)
		{
		readerrorcount++;
		continue;
		}
	if(keyver != hccapptr->keyver)
		{
		readerrorcount++;
		if(keyver > 3) continue;
		if(keyver == 0) continue;
		correctedcount++;
		}
	eapa = (eapauth_t*)hccapptr->eapol;
	keylen = ntohs(eapa->len) +EAPAUTH_SIZE;
	if(keylen != hccapptr->eapol_size)
		{
		readerrorcount++;
		if(keylen > 255) continue;
		correctedcount++;
		continue;
		}
	memcpy(zeiger->ap, hccapptr->ap, 6);
	memcpy(zeiger->client, hccapptr->client, 6);
	el = 0;
	while(el < ESSID_LEN_MAX)
		{
		if(hccapptr->essid[el] == 0) break;
		el++;
		}
	memcpy(zeiger->essid, hccapptr->essid, el);
	zeiger->essidlen = el;
	memcpy(zeiger->hash, hccapptr->keymic, 16);
	zeiger->eapauthlen = keylen;
	memcpy(zeiger->eapol, hccapptr->eapol, hccapptr->eapol_size);
	if(memcmp(hccapptr->anonce, wpak->nonce, 32) != 0) memcpy(zeiger->nonce, hccapptr->anonce, 32);
	else if(memcmp(hccapptr->snonce, wpak->nonce, 32) != 0) memcpy(zeiger->nonce, hccapptr->snonce, 32);
	else
		{
		readerrorcount++;
		continue;
		}
	zeiger->type = HS_EAPOL;
	keyinfo = (get_keyinfo(ntohs(wpak->keyinfo)));
	if(keyinfo == 2) zeiger->mp = 0x80;
	else if(keyinfo == 4) zeiger->mp = 0x81;
	else if(keyinfo == 3) zeiger->mp = 0x03;
	else
		{
		readerrorcount++;
		continue;
		}
	eapolcount++;
	pmkideapolcount = pmkidcount +eapolcount;
	if(pmkideapolcount >= hashlistcount)
		{
		hashlistcount += HASHLIST_MAX;
		hashlistnew = (hashlist_t*)realloc(hashlist, hashlistcount *HASHLIST_SIZE);
		if(hashlistnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		hashlist = hashlistnew;
		}
	zeiger = hashlist +pmkideapolcount;
	}
return;
}
/*===========================================================================*/
static bool readbpkdf2file(char *pkdf2inname)
{
static int len;
static char *pskpos;
static FILE *fh_pbkdf2;
static char linein[PBKDF2_LINE_LEN +1];

if((fh_pbkdf2 = fopen(pkdf2inname, "r")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", pkdf2inname, strerror(errno));
	return false;
	}
pbkdf2count = 0;
pbkdf2readerrorcount = 0;
while(1)
	{
	if((len = fgetline(fh_pbkdf2, PBKDF2_LINE_LEN, linein)) == -1) break;
	if(len < 76)
		{
		pbkdf2readerrorcount++;
		continue;
		}
	if(linein[64] != '*')
		{
		pbkdf2readerrorcount++;
		continue;
		}
	pskpos = strchr(&linein[65], ':');
	if(pskpos == NULL)
		{
		pbkdf2readerrorcount++;
		continue;
		}
	pskpos[0] = 0;
	fprintf(stdout, "%s %s\n", &linein[65], pskpos +1);
	pbkdf2count++;
	}
fclose(fh_pbkdf2);
return true;
}
/*===========================================================================*/
static void showvendorlist(void)
{
static ouilist_t *zeiger;

fprintf(stdout, "\n");
for(zeiger = ouilist; zeiger < ouilist +ouicount; zeiger++) fprintf(stdout, "%02x%02x%02x %s\n", zeiger->oui[0], zeiger->oui[1], zeiger->oui[2], zeiger->vendor); 
return;
}
/*===========================================================================*/
static int isvendor(int len, char *linein)
{
static int c;
static int ret;

for(c = 7; c < len; c++)
	{
	if(islower((unsigned char)linein[c])) linein[c] = toupper((unsigned char)linein[c]);
	}
ret = 0;
if(filtervendorptr != NULL)
	{
	if(strstr(&linein[7], filtervendorptr) != NULL) ret |= TYPE_AP + TYPE_CLIENT;
	}
if(filtervendorapptr != NULL)
	{
	if(strstr(&linein[7], filtervendorapptr) != NULL) ret |= TYPE_AP;
	}
if(filtervendorclientptr != NULL)
	{
	if(strstr(&linein[7], filtervendorclientptr) != NULL) ret |= TYPE_CLIENT;
	}
return ret;
}
/*===========================================================================*/
static void readoui(void)
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
	zeiger->type = 0;
	if((filtervendorptr != NULL) || (filtervendorapptr != NULL) || (filtervendorclientptr != NULL))
		{
		zeiger->type = isvendor(len, linein);
		if(zeiger->type == 0) continue;
		}
	vendorptr = strrchr(&linein[7], '\t');
	if(vendorptr == NULL) continue;
	if(vendorptr++ == 0) continue;
	strncpy(zeiger->vendor, vendorptr, VENDOR_LEN_MAX -1);
	ouicount++;
	if(ouicount >= ouilistcount)
		{
		ouilistcount += OUILIST_MAX;
		ouilistnew = (ouilist_t*)realloc(ouilist, ouilistcount *OUILIST_SIZE);
		if(ouilistnew == NULL)
			{
			fprintf(stderr, "failed to allocate memory for internal list\n");
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
static void downloadoui(void)
{
static uid_t uid;
static size_t bread;
static struct passwd *pwd;
static CURLcode ret;
static CURL *hnd;
static FILE *fhoui;
static FILE *fhouitmp;
static struct stat statinfo;
static const char *ouipath = "/.hcxtools";
static const char *ouiname = "/oui.txt";
static char ouinameuserpath[PATH_MAX];
static char ouibuff[OUIBUFFER_MAX];

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
fprintf(stdout, "start downloading oui from https://standards-oui.ieee.org to: %s\n", ouinameuserpath);
if((fhouitmp = tmpfile()) == NULL)
	{
	fprintf(stderr, "\nfailed to create temporary download file\n");
	return;
	}
hnd = curl_easy_init ();
curl_easy_setopt(hnd, CURLOPT_URL, "https://standards-oui.ieee.org/oui/oui.txt");
curl_easy_setopt(hnd, CURLOPT_MAXREDIRS, 5L);
curl_easy_setopt(hnd, CURLOPT_WRITEDATA, fhouitmp) ;
curl_easy_setopt(hnd, CURLOPT_NOPROGRESS, 0L);
ret = curl_easy_perform(hnd);
curl_easy_cleanup(hnd);
if(ret != 0)
	{
	fprintf(stderr, "\ndownload not successful\n");
	return;
	}
rewind(fhouitmp);
if((fhoui = fopen(ouinameuserpath, "w")) == NULL)
	{
	fprintf(stderr, "\nfailed to create %s\n", ouiname);
	return;
	}
while (!feof(fhouitmp))
	{
	bread = fread(ouibuff, 1, sizeof(ouibuff), fhouitmp);
	if(bread > 0) fwrite(ouibuff, 1, bread, fhoui);
	}
fclose(fhoui);
fprintf(stdout, "\ndownload finished\n");
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-i <file>   : input PMKID/EAPOL hash file\n"
	"-o <file>   : output PMKID/EAPOL hash file\n"
	"-E <file>   : output ESSID list (autohex enabled)\n"
	"-E stdout   : output ESSID list to stdout (autohex enabled)\n"
	"-L <file>   : output ESSID list (unfiltered and unsorted)\n"
	"              useful in combination with hashcat -a9 option\n"
	"-d          : download https://standards-oui.ieee.org/oui.txt\n"
	"              and save to ~/.hcxtools/oui.txt\n"
	"              internet connection required\n"
//	"-p          : input PBKDF2 file (hashcat potfile 22000 format)\n" 
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
	"--type=<digit>               : filter by hash type\n"
	"                               bitmask:\n"
	"                                1 = PMKID\n"
	"                                2 = EAPOL\n"
	"                               default PMKID and EAPOL (1+2=3)\n"
	"--hcx-min=<digit>            : disregard hashes with occurrence lower than hcx-min/ESSID\n"
	"--hcx-max=<digit>            : disregard hashes with occurrence higher than hcx-max/ESSID\n"
	"--essid-len                  : filter by ESSID length\n"
	"                               default ESSID length: %d...%d\n"
	"--essid-min                  : filter by ESSID minimum length\n"
	"                               default ESSID minimum length: %d\n"
	"--essid-max                  : filter by ESSID maximum length\n"
	"                               default ESSID maximum length: %d\n"
	"--essid=<ESSID>              : filter by ESSID\n"
	"--essid-part=<part of ESSID> : filter by part of ESSID (case sensitive)\n"
	"--essid-partx=<part of ESSID>: filter by part of ESSID (case insensitive)\n"
	"                               locale and wide characters are ignored\n"
	"--essid-list=<file>          : filter by ESSID file\n"
	"--essid-regex=<regex>        : filter ESSID by regular expression\n"
	"--mac-ap=<MAC>               : filter AP by MAC\n"
	"                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\n"
	"--mac-client=<MAC>           : filter CLIENT by MAC\n"
	"                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\n"
	"--mac-list=<file>            : filter by MAC file\n"
	"                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\n"
	"--mac-skiplist=<file>        : exclude MAC from file\n"
	"                               format: 001122334455, 00:11:22:33:44:55, 00-11-22-33-44-55 (hex)\n"
	"--oui-ap=<OUI>               : filter AP by OUI\n"
	"                               format: 001122, 00:11:22, 00-11-22 (hex)\n"
	"--oui-client=<OUI>           : filter CLIENT by OUI\n"
	"                               format: 001122, 00:11:22, 00-11-22 (hex)\n"
	"--vendor=<VENDOR>            : filter AP or CLIENT by (part of) VENDOR name\n"
	"--vendor-ap=<VENDOR>         : filter AP by (part of) VENDOR name\n"
	"--vendor-client=<VENDOR>     : filter CLIENT by (part of) VENDOR name\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, ESSID_LEN_MIN, ESSID_LEN_MAX, ESSID_LEN_MIN, ESSID_LEN_MAX);

fprintf(stdout, "--authorized                 : filter EAPOL pairs by status authorized (M2M3, M3M4, M1M4)\n"
	"--challenge                  : filter EAPOL pairs by status CHALLENGE (M1M2, M1M2ROGUE)\n"
	"--rc                         : filter EAPOL pairs by replaycount status checked\n"
	"--rc-not                     : filter EAPOL pairs by replaycount status not checked\n"
	"--apless                     : filter EAPOL pairs by status M1M2ROGUE (M2 requested from CLIENT)\n"
	"--info=<file>                : output detailed information about content of hash file\n"
	"                               no filter options available\n"
	"--info=stdout                : stdout output detailed information about content of hash file\n"
	"                               no filter options available\n"
	"--info-vendor=<file>         : output detailed information about ACCESS POINT and CLIENT VENDORs\n"
	"                               no filter options available\n"
	"--info-vendor-ap=<file>      : output detailed information about ACCESS POINT VENDORs\n"
	"                               no filter options available\n"
	"--info-vendor-client=<file>  : output detailed information about CLIENT VENDORs\n"
	"                               no filter options available\n"
	"--info-vendor=stdout         : stdout output detailed information about ACCESS POINT and CLIENT VENDORs\n"
	"                               no filter options available\n"
	"--info-vendor-ap=stdout      : stdout output detailed information about ACCESS POINT VENDORs\n"
	"                               no filter options available\n"
	"--info-vendor-client=stdout  : stdout output detailed information about CLIENT VENDORs\n"
	"                               no filter options available\n"
	"--psk=<PSK>                  : pre-shared key to test\n"
	"                               due to PBKDF2 calculation this is a very slow process\n"
	"                               no nonce error corrections\n"
	"--pmk=<PMK>                  : plain master key to test\n"
	"                               no nonce error corrections\n"
	"--hccapx-in=<file>           : input deprecated hccapx file\n"
	"                                MESSSAGEPAIR is taken from the hccapx source\n"
	"--hccapx-out=<file>          : output to deprecated hccapx file\n"
	"--hccap-in=<file>            : input ancient hccap file\n"
	"--hccap-out=<file>           : output to ancient hccap file\n"
	"                                MESSSAGEPAIR is calculated from the EAPOL MESSAGE\n"
	"                                due to missing information, the worst case value is calculated\n"
	"--hccap-single               : output to ancient hccap single files (MAC + count)\n"
	"--john=<file>                : output to deprecated john file\n"
	"--vendorlist                 : stdout output complete OUI list sorted by OUI\n"
	"--help                       : show this help\n"
	"--version                    : show version\n"
	"\n"
	"Important notice:\n"
	"%s does not do NONCE ERROR CORRECTIONS\n"
	"in case of a packet loss, you get a wrong PTK\n",
	eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static int l;
static int lcmin;
static int lcmax;
static int p1, p2;
static int hashtypein;
static int essidlenin;
static FILE *fh_pmkideapol;
static int fd_hccapxin;
static int fd_hccapin;
static char *pbkdf2inname;
static char *pmkideapolinname;
static char *pmkideapoloutname;
static char *essidoutname;
static char *essidrawoutname;
static char *essidinname;
static char *macinname;
static char *macskipname;
static char *hccapxinname;
static char *hccapxoutname;
static char *hccapinname;
static char *hccapoutname;
static char *johnoutname;
static char *infooutname;
static char *infovendoroutname;
static char *infovendorapoutname;
static char *infovendorclientoutname;
static char *ouiinstring;
static char *macinstring;
static char *pmkinstring;
static struct stat statinfo;

static const char *short_options = "i:o:E:L:dp:hv";
static const struct option long_options[] =
{
	{"type",			required_argument,	NULL,	HCX_HASH_TYPE},
	{"hcx-min",			required_argument,	NULL,	HCX_HASH_MIN},
	{"hcx-max",			required_argument,	NULL,	HCX_HASH_MAX},
	{"essid-min",			required_argument,	NULL,	HCX_ESSID_MIN},
	{"essid-group",			no_argument,		NULL,	HCX_ESSID_GROUP},
	{"essid-len",			required_argument,	NULL,	HCX_ESSID_LEN},
	{"essid-min",			required_argument,	NULL,	HCX_ESSID_MIN},
	{"essid-max",			required_argument,	NULL,	HCX_ESSID_MAX},
	{"essid",			required_argument,	NULL,	HCX_FILTER_ESSID},
	{"essid-part",			required_argument,	NULL,	HCX_FILTER_ESSID_PART},
	{"essid-partx",			required_argument,	NULL,	HCX_FILTER_ESSID_PARTX},
	{"essid-list",			required_argument,	NULL,	HCX_FILTER_ESSID_LIST_IN},
	{"essid-regex",			required_argument,	NULL,	HCX_FILTER_ESSID_REGEX},
	{"mac-ap",			required_argument,	NULL,	HCX_FILTER_MAC_AP},
	{"mac-client",			required_argument,	NULL,	HCX_FILTER_MAC_CLIENT},
	{"mac-list",			required_argument,	NULL,	HCX_FILTER_MAC_LIST_IN},
	{"mac-skiplist",		required_argument,	NULL,	HCX_FILTER_MAC_LIST_SKIP},
	{"mac-group-ap",		no_argument,		NULL,	HCX_MAC_GROUP_AP},
	{"mac-group-client",		no_argument,		NULL,	HCX_MAC_GROUP_CLIENT},
	{"oui-group",			no_argument,		NULL,	HCX_OUI_GROUP},
	{"oui-ap",			required_argument,	NULL,	HCX_FILTER_OUI_AP},
	{"oui-client",			required_argument,	NULL,	HCX_FILTER_OUI_CLIENT},
	{"vendor",			required_argument,	NULL,	HCX_FILTER_VENDOR},
	{"vendor-ap",			required_argument,	NULL,	HCX_FILTER_VENDOR_AP},
	{"vendor-client",		required_argument,	NULL,	HCX_FILTER_VENDOR_CLIENT},
	{"rc",				no_argument,		NULL,	HCX_FILTER_RC},
	{"rc-not",			no_argument,		NULL,	HCX_FILTER_RC_NOT},
	{"authorized",			no_argument,		NULL,	HCX_FILTER_M12},
	{"challenge",			no_argument,		NULL,	HCX_FILTER_M1234},
	{"apless",			no_argument,		NULL,	HCX_FILTER_M1M2ROGUE},
	{"psk",				required_argument,	NULL,	HCX_PSK},
	{"pmk",				required_argument,	NULL,	HCX_PMK},
	{"info",			required_argument,	NULL,	HCX_INFO_OUT},
	{"info-vendor",			required_argument,	NULL,	HCX_INFO_VENDOR_OUT},
	{"info-vendor-ap",		required_argument,	NULL,	HCX_INFO_VENDOR_AP_OUT},
	{"info-vendor-client",		required_argument,	NULL,	HCX_INFO_VENDOR_CLIENT_OUT},
	{"hccapx-in",			required_argument,	NULL,	HCX_HCCAPX_IN},
	{"hccapx-out",			required_argument,	NULL,	HCX_HCCAPX_OUT},
	{"hccap-in",			required_argument,	NULL,	HCX_HCCAP_IN},
	{"hccap-out",			required_argument,	NULL,	HCX_HCCAP_OUT},
	{"hccap-single",		no_argument,		NULL,	HCX_HCCAP_SINGLE_OUT},
	{"john",			required_argument,	NULL,	HCX_JOHN_OUT},
	{"vendorlist",			no_argument,		NULL,	HCX_VENDOR_OUT},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
pbkdf2inname = NULL;
fh_pmkideapol = NULL;
pmkideapolinname = NULL;
pmkideapoloutname = NULL;
essidoutname = NULL;
essidrawoutname = NULL;
essidinname = NULL;
macinname = NULL;
macskipname = NULL;
infooutname = NULL;
infovendoroutname = NULL;
infovendorapoutname = NULL;
infovendorclientoutname = NULL;
hccapxinname = NULL;
hccapxoutname = NULL;
hccapinname = NULL;
hccapoutname = NULL;
johnoutname = NULL;
ouiinstring = NULL;
macinstring = NULL;
pmkinstring = NULL;
filteressidptr = NULL;
filteressidpartptr = NULL;
filteressidregexptr = NULL;
filtervendorptr = NULL;
filtervendorapptr = NULL;
filtervendorclientptr = NULL;
fd_hccapxin = 0;
fd_hccapin = 0;
flagfiltermacap = false;
flagfiltermacclient = false;
flagfilterouiap = false;
flagfilterouiclient = false;
flagfilterauthorized = false;
flagfilterchallenge = false;
flagfilterrcchecked = false;
flagfilterrcnotchecked = false;
flagfilterapless = false;
flagpsk = false;
flagpmk = false;
flagessidgroup = false;
flagmacapgroup = false;
flagmacclientgroup = false;
flagouigroup = false;
flagvendorout = false;
flaghccapsingleout = false;
caseflag = false;
hashtypein = 0;
hashtype = HCX_TYPE_PMKID | HCX_TYPE_EAPOL;
essidlenin = ESSID_LEN_MAX;
essidlen = ESSID_LEN_MAX;
essidlenmin = ESSID_LEN_MIN;
essidlenmax = ESSID_LEN_MAX;
lcmin = 0;
lcmax = 0;
statusflag = true;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_PMKIDEAPOL_IN:
		if((hccapxinname != NULL) || (hccapinname != NULL)) 
			{
			fprintf(stderr, "only one input hash format is allowed\n");
			exit(EXIT_FAILURE);
			}
		pmkideapolinname = optarg;
		break;

		case HCX_PMKIDEAPOL_OUT:
		pmkideapoloutname = optarg;
		break;

		case HCX_ESSID_OUT:
		essidoutname = optarg;
		break;

		case HCX_ESSID_RAW_OUT:
		essidrawoutname = optarg;
		break;

		case HCX_VENDOR_OUT:
		flagvendorout = true;
		break;

		case HCX_INFO_OUT:
		infooutname = optarg;
		break;

		case HCX_INFO_VENDOR_OUT:
		infovendoroutname = optarg;
		break;

		case HCX_INFO_VENDOR_AP_OUT:
		infovendorapoutname = optarg;
		break;

		case HCX_INFO_VENDOR_CLIENT_OUT:
		infovendorclientoutname = optarg;
		break;

		case HCX_ESSID_GROUP:
		flagessidgroup = true;
		break;

		case HCX_HASH_TYPE:
		hashtypein |= strtol(optarg, NULL, 10);
		if((hashtypein < HCX_TYPE_PMKID) || (hashtypein > (HCX_TYPE_PMKID + HCX_TYPE_EAPOL)))
			{
			fprintf(stderr, "only hash types 1 and 2 allowed (values 1, 2 or 3)\n");
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
		caseflag = false;
		break;

		case HCX_FILTER_ESSID_PARTX:
		filteressidpartptr = optarg;
		filteressidpartlen = strlen(filteressidpartptr);
		if((filteressidpartlen  < 1) || (filteressidpartlen > ESSID_LEN_MAX))
			{
			fprintf(stderr, "only values 0...32 allowed\n");
			exit(EXIT_FAILURE);
			}
		caseflag = true;
		break;

		case HCX_FILTER_ESSID_LIST_IN:
		essidinname = optarg;
		break;

		case HCX_FILTER_ESSID_REGEX:
		filteressidregexptr = optarg;
		p1 = regcomp(&essidregex, filteressidregexptr, REG_EXTENDED);
		if(p1)
			{
			fprintf(stderr, "Could not compile regex\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCX_HASH_MIN:
		lcmin = strtol(optarg, NULL, 10);
		break;

		case HCX_HASH_MAX:
		lcmax = strtol(optarg, NULL, 10);
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
		l= strlen(optarg);
		p2 = 0;
		for(p1 = 0; p1 < l; p1++)
			{
			if(isxdigit((unsigned char)optarg[p1]))
				{
				optarg[p2] = optarg[p1];
				p2++;
				}
			}
		optarg[6] = 0;
		ouiinstring = optarg;
		if(getfield(ouiinstring, 3, filterouiap) != 3)
			{
			fprintf(stderr, "wrong OUI format\n");
			exit(EXIT_FAILURE);
			}
		flagfilterouiap = true;
		break;

		case HCX_FILTER_MAC_AP:
		l= strlen(optarg);
		p2 = 0;
		for(p1 = 0; p1 < l; p1++)
			{
			if(isxdigit((unsigned char)optarg[p1]))
				{
				optarg[p2] = optarg[p1];
				p2++;
				}
			}
		optarg[12] = 0;
		macinstring = optarg;
		if(getfield(macinstring, 6, filtermacap) != 6)
			{
			fprintf(stderr, "wrong MAC format $\n");
			exit(EXIT_FAILURE);
			}
		flagfiltermacap = true;
		break;

		case HCX_FILTER_MAC_CLIENT:
		l= strlen(optarg);
		p2 = 0;
		for(p1 = 0; p1 < l; p1++)
			{
			if(isxdigit((unsigned char)optarg[p1]))
				{
				optarg[p2] = optarg[p1];
				p2++;
				}
			}
		optarg[12] = 0;
		macinstring = optarg;
		if(getfield(macinstring, 6, filtermacclient) != 6)
			{
			fprintf(stderr, "wrong MAC format\n");
			exit(EXIT_FAILURE);
			}
		flagfiltermacclient = true;
		break;

		case HCX_FILTER_MAC_LIST_IN:
		macinname = optarg;
		break;

		case HCX_FILTER_MAC_LIST_SKIP:
		macskipname = optarg;
		break;

		case HCX_FILTER_OUI_CLIENT:
		l= strlen(optarg);
		p2 = 0;
		for(p1 = 0; p1 < l; p1++)
			{
			if(isxdigit((unsigned char)optarg[p1]))
				{
				optarg[p2] = optarg[p1];
				p2++;
				}
			}
		optarg[6] = 0;
		ouiinstring = optarg;
		if(getfield(ouiinstring, 3, filterouiclient) != 3)
			{
			fprintf(stderr, "wrong OUI format\n");
			exit(EXIT_FAILURE);
			}
		flagfilterouiclient = true;
		break;

		case HCX_FILTER_VENDOR:
		filtervendorptr = optarg;
		l = strlen(filtervendorptr);
		if(l < 3)
			{
			fprintf(stderr, "at least three characters of the VENDOR name are mandatory\n");
			exit(EXIT_FAILURE);
			}
		for(p1 = 0; p1 < l; p1++)
			{
			if(islower((unsigned char)filtervendorptr[p1])) filtervendorptr[p1] = toupper((unsigned char)filtervendorptr[p1]);
			}
		break;

		case HCX_FILTER_VENDOR_AP:
		filtervendorapptr = optarg;
		l = strlen(filtervendorapptr);
		if(l < 3)
			{
			fprintf(stderr, "at least three characters of the VENDOR name are mandatory\n");
			exit(EXIT_FAILURE);
			}
		for(p1 = 0; p1 < l; p1++)
			{
			if(islower((unsigned char)filtervendorapptr[p1])) filtervendorapptr[p1] = toupper((unsigned char)filtervendorapptr[p1]);
			}
		break;

		case HCX_FILTER_VENDOR_CLIENT:
		filtervendorclientptr = optarg;
		l = strlen(filtervendorclientptr);
		if(l < 3)
			{
			fprintf(stderr, "at least three characters of the VENDOR name are mandatory\n");
			exit(EXIT_FAILURE);
			}
		for(p1 = 0; p1 < l; p1++)
			{
			if(islower((unsigned char)filtervendorclientptr[p1])) filtervendorclientptr[p1] = toupper((unsigned char)filtervendorclientptr[p1]);
			}
		break;

		case HCX_FILTER_RC:
		flagfilterrcchecked = true;
		break;

		case HCX_FILTER_RC_NOT:
		flagfilterrcnotchecked = true;
		break;

		case HCX_FILTER_M12:
		flagfilterauthorized = true;
		break;

		case HCX_FILTER_M1234:
		flagfilterchallenge = true;
		break;

		case HCX_FILTER_M1M2ROGUE:
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
			fprintf(stderr, "wrong PMK length\n");
			exit(EXIT_FAILURE);
			}
		flagpmk = true;
		break;

		case HCX_DOWNLOAD_OUI:
		downloadoui();
		break;

		case HCX_PBKDF2_IN:
//		pbkdf2inname = optarg;
		break;

		case HCX_HCCAPX_IN:
		if((pmkideapolinname != NULL) || (hccapinname != NULL))
			{
			fprintf(stderr, "only one input hash format is allowed\n");
			exit(EXIT_FAILURE);
			}
		hccapxinname = optarg;
		break;

		case HCX_HCCAP_IN:
		if((pmkideapolinname != NULL) || (hccapxinname != NULL))
			{
			fprintf(stderr, "only one input hash format is allowed\n");
			exit(EXIT_FAILURE);
			}
		hccapinname = optarg;
		break;


		case HCX_HCCAPX_OUT:
		hccapxoutname = optarg;
		break;

		case HCX_HCCAP_OUT:
		hccapoutname = optarg;
		break;

		case HCX_HCCAP_SINGLE_OUT:
		flaghccapsingleout = true;
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
if(pbkdf2inname != NULL) readbpkdf2file(pbkdf2inname);
if((infooutname != NULL) || (infovendoroutname != NULL) || (infovendorapoutname != NULL) || (infovendorclientoutname != NULL))
	{
	filtervendorptr = NULL;
	filtervendorapptr = NULL;
	filtervendorclientptr = NULL;
	}
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
		fprintf(stdout, "error opening file %s: %s\n", pmkideapolinname, strerror(errno));
		closelists();
		exit(EXIT_FAILURE);
		}
	readpmkideapolfile(fh_pmkideapol);
	}
if(hccapxinname != NULL)
	{
	if(stat(hccapxinname, &statinfo) != 0)
		{
		fprintf(stderr, "can't stat %s\n", hccapxinname);
		closelists();
		exit(EXIT_FAILURE);
		}
	if((statinfo.st_size %HCCAPX_SIZE) != 0)
		{
		fprintf(stderr, "file is corrupt\n");
		closelists();
		exit(EXIT_FAILURE);
		}
	if((fd_hccapxin = open(hccapxinname, O_RDONLY)) == -1)
		{
		fprintf(stdout, "error opening file %s: %s\n", hccapxinname, strerror(errno));
		closelists();
		exit(EXIT_FAILURE);
		}
	readhccapxfile(fd_hccapxin, statinfo.st_size / HCCAPX_SIZE);
	}

if(hccapinname != NULL)
	{
	if(stat(hccapinname, &statinfo) != 0)
		{
		fprintf(stderr, "can't stat %s\n", hccapinname);
		closelists();
		exit(EXIT_FAILURE);
		}
	if((statinfo.st_size %HCCAP_SIZE) != 0)
		{
		fprintf(stderr, "file is corrupt\n");
		closelists();
		exit(EXIT_FAILURE);
		}
	if((fd_hccapin = open(hccapinname, O_RDONLY)) == -1)
		{
		fprintf(stdout, "error opening file %s: %s\n", hccapinname, strerror(errno));
		closelists();
		exit(EXIT_FAILURE);
		}
	readhccapfile(fd_hccapin, statinfo.st_size / HCCAP_SIZE);
	}

if(pmkideapolcount == 0)
	{
	fprintf(stdout, "no hashes loaded\n");
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	closelists();
	return EXIT_SUCCESS;
	}

if(essidrawoutname != 0) processessidraw(essidrawoutname);

if(infooutname != NULL)
	{
	writeinfofile(infooutname);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	closelists();
	return EXIT_SUCCESS;
	}

if(infovendoroutname != NULL)
	{
	writevendorapinfofile(infovendoroutname);
	writevendorclientinfofile(infovendoroutname);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	closelists();
	return EXIT_SUCCESS;
	}
else if(infovendorapoutname != NULL)
	{
	writevendorapinfofile(infovendorapoutname);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	closelists();
	return EXIT_SUCCESS;
	}
else if(infovendorclientoutname != NULL)
	{
	writevendorclientinfofile(infovendorclientoutname);
	if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
	closelists();
	return EXIT_SUCCESS;
	}

if(macskipname != NULL) removepmkideapol(macskipname);

if(hashtypein > 0) hashtype = hashtypein;

if(essidoutname != NULL) processessid(essidoutname);
if((pmkideapoloutname != NULL) && (essidinname == NULL))
	{
	if((lcmin == 0) && (lcmax == 0)) writeeapolpmkidfile(pmkideapoloutname);
	else writelceapolpmkidfile(pmkideapoloutname, lcmin, lcmax);
	}
if(flagessidgroup == true) writeeapolpmkidessidgroups();
if(flagmacapgroup == true) writeeapolpmkidmacapgroups();
if(flagmacclientgroup == true) writeeapolpmkidmacclientgroups();
if(flagouigroup == true) writeeapolpmkidouigroups();
if(flagpsk == true) testhashfilepsk();
if(flagpmk == true) testhashfilepmk();
if(hccapxoutname != NULL) writehccapxfile(hccapxoutname);
if(hccapoutname != NULL) writehccapfile(hccapoutname);
if(flaghccapsingleout == true) writehccapsinglefile();
if(johnoutname != NULL) writejohnfile(johnoutname);
if((pmkideapoloutname != NULL) && (essidinname != NULL)) processessidfile(essidinname, pmkideapoloutname);
if(macinname != NULL) processmacfile(macinname, pmkideapoloutname);
if(statusflag == true) printstatus();
if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
if(fd_hccapxin != 0) close(fd_hccapxin);
closelists();
return EXIT_SUCCESS;
}
/*===========================================================================*/

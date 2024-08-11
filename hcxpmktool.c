#define _GNU_SOURCE
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

#include <openssl/core.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/types.h>

#include "include/hcxpmktool.h"
#include "include/ieee80211.h"
#include "include/strings.c"
#include "include/fileops.c"

/*===========================================================================*/
/* global variable */

static uint16_t status;
static int exitcode;

static EVP_MAC *hmac;
static EVP_MAC *cmac;
static EVP_MAC_CTX *ctxhmac;
static EVP_MAC_CTX *ctxcmac;
static OSSL_PARAM paramsmd5[3];
static OSSL_PARAM paramssha1[3];
static OSSL_PARAM paramssha256[3];
static OSSL_PARAM paramsaes128[3];
static uint8_t pmkcalculated[128];
static uint8_t pmkidcalculated[128];
static uint8_t ptkcalculated[256];
static uint8_t miccalculated[128];

static int psklen;
static char *pskstring;
static ssize_t essidlen;
static uint8_t essid[34];
static uint8_t macap[8];
static uint8_t macclient[8];
static uint8_t pmkid[18];
static uint8_t mic[18];
static uint8_t anonce[34];
static size_t eapollen;
static uint8_t eapol[1024];
static eapauth_t *eapptr;
static size_t eapauthlen;
static wpakey_t *wpak;
static int keyversion;
/*===========================================================================*/
static void showresult(void)
{
fprintf(stdout, "\n");
if((status & HAS_PMKID_LINE) == HAS_PMKID_LINE)
	{
	fprintf(stdout, "HASH FORMAT.: PMKID (WPA*01)\n");
	}
if((status & HAS_EAPOL_LINE) == HAS_EAPOL_LINE)
	{
	fprintf(stdout, "HASH FORMAT.: EAPOL (WPA*02)\n");
	}
if((status & HAS_ESSID) == HAS_ESSID)
	{
	fprintf(stdout, "ESSID.......: %s\n", essid);
	}
if((status & HAS_MACAP) == HAS_MACAP)
	{
	fprintf(stdout, "MAC_AP......: %02x%02x%02x%02x%02x%02x\n",
	macap[0], macap[1], macap[2], macap[3], macap[4], macap[5]);
	}
if((status & HAS_MACCLIENT) == HAS_MACCLIENT)
	{
	fprintf(stdout, "MAC_CLIENT..: %02x%02x%02x%02x%02x%02x\n",
	macclient[0], macclient[1], macclient[2], macclient[3], macclient[4], macclient[5]);
	}
if((status & HAS_PSK) == HAS_PSK)
	{
	fprintf(stdout, "PSK.........: %s\n", pskstring);
	}
if((status & HAS_PMK_CALC) == HAS_PMK_CALC)
	{
	fprintf(stdout, "PMK.........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (calculated)\n",
	pmkcalculated[0], pmkcalculated[1], pmkcalculated[2], pmkcalculated[3], pmkcalculated[4], pmkcalculated[5], pmkcalculated[6], pmkcalculated[7], pmkcalculated[8], pmkcalculated[9], pmkcalculated[10], pmkcalculated[11], pmkcalculated[12], pmkcalculated[13], pmkcalculated[14], pmkcalculated[15],
	pmkcalculated[16], pmkcalculated[17], pmkcalculated[18], pmkcalculated[19], pmkcalculated[20], pmkcalculated[21], pmkcalculated[22], pmkcalculated[23], pmkcalculated[24], pmkcalculated[25], pmkcalculated[26], pmkcalculated[27], pmkcalculated[28], pmkcalculated[29], pmkcalculated[30], pmkcalculated[31]);
	}
if((status & HAS_PMK) == HAS_PMK)
	{
	fprintf(stdout, "PMK.........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	pmkcalculated[0], pmkcalculated[1], pmkcalculated[2], pmkcalculated[3], pmkcalculated[4], pmkcalculated[5], pmkcalculated[6], pmkcalculated[7], pmkcalculated[8], pmkcalculated[9], pmkcalculated[10], pmkcalculated[11], pmkcalculated[12], pmkcalculated[13], pmkcalculated[14], pmkcalculated[15],
	pmkcalculated[16], pmkcalculated[17], pmkcalculated[18], pmkcalculated[19], pmkcalculated[20], pmkcalculated[21], pmkcalculated[22], pmkcalculated[23], pmkcalculated[24], pmkcalculated[25], pmkcalculated[26], pmkcalculated[27], pmkcalculated[28], pmkcalculated[29], pmkcalculated[30], pmkcalculated[31]);
	}
if((status & HAS_PMKID) == HAS_PMKID)
	{
	fprintf(stdout, "PMKID.......: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	pmkid[0], pmkid[1], pmkid[2], pmkid[3], pmkid[4], pmkid[5], pmkid[6], pmkid[7], pmkid[8], pmkid[9], pmkid[10], pmkid[11], pmkid[12], pmkid[13], pmkid[14], pmkid[15]);
	if(((status & HAS_PMKID_CALC) == HAS_PMKID_CALC) || ((status & HAS_PMK) == HAS_PMK))
		{
		if(memcmp(pmkid, pmkidcalculated, 16) == 0)
			{
			exitcode = EXIT_SUCCESS_CONFIRMED;
			fprintf(stdout, " (confirmed)\n");
			}
		else fprintf(stdout, " (not confirmed)\n");
		}
	else fprintf(stdout, " (not confirmed)\n");
	}
if((status & HAS_MIC) == HAS_MIC)
	{
	if(keyversion == 2) fprintf(stdout, "KEY VERSION.: WPA2\n");
	else if(keyversion == 1) fprintf(stdout, "KEY VERSION.: WPA1\n");
	else if(keyversion == 3) fprintf(stdout, "KEY VERSION.: WPA2 KEY VERSION 3\n");
	fprintf(stdout, "NONCE 1.....: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	anonce[0], anonce[1], anonce[2], anonce[3], anonce[4], anonce[5], anonce[6], anonce[7], anonce[8], anonce[9], anonce[10], anonce[11], anonce[12], anonce[13], anonce[14], anonce[15],
	anonce[16], anonce[17], anonce[18], anonce[19], anonce[20], anonce[21], anonce[22], anonce[23], anonce[24], anonce[25], anonce[26], anonce[27], anonce[28], anonce[29], anonce[30], anonce[31]);
	fprintf(stdout, "NONCE 2.....: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
	wpak->nonce[0], wpak->nonce[1], wpak->nonce[2], wpak->nonce[3], wpak->nonce[4], wpak->nonce[5], wpak->nonce[6], wpak->nonce[7], wpak->nonce[8], wpak->nonce[9], wpak->nonce[10], wpak->nonce[11], wpak->nonce[12], wpak->nonce[13], wpak->nonce[14], wpak->nonce[15],
	wpak->nonce[16], wpak->nonce[17], wpak->nonce[18], wpak->nonce[19], wpak->nonce[20], wpak->nonce[21], wpak->nonce[22], wpak->nonce[23], wpak->nonce[24], wpak->nonce[25], wpak->nonce[26], wpak->nonce[27], wpak->nonce[28], wpak->nonce[29], wpak->nonce[30], wpak->nonce[31]);
	if((status & HAS_PTK_CALC) == HAS_PTK_CALC)
		{
		fprintf(stdout, "PTK.........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (calculated)\n",
		ptkcalculated[0], ptkcalculated[1], ptkcalculated[2], ptkcalculated[3], ptkcalculated[4], ptkcalculated[5], ptkcalculated[6], ptkcalculated[7], ptkcalculated[8], ptkcalculated[9], ptkcalculated[10], ptkcalculated[11], ptkcalculated[12], ptkcalculated[13], ptkcalculated[14], ptkcalculated[15],
		ptkcalculated[16], ptkcalculated[17], ptkcalculated[18], ptkcalculated[19], ptkcalculated[20], ptkcalculated[21], ptkcalculated[22], ptkcalculated[23], ptkcalculated[24], ptkcalculated[25], ptkcalculated[26], ptkcalculated[27], ptkcalculated[28], ptkcalculated[29], ptkcalculated[30], ptkcalculated[31]);

		fprintf(stdout, "KCK.........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (calculated)\n",
		ptkcalculated[0], ptkcalculated[1], ptkcalculated[2], ptkcalculated[3], ptkcalculated[4], ptkcalculated[5], ptkcalculated[6], ptkcalculated[7], ptkcalculated[8], ptkcalculated[9], ptkcalculated[10], ptkcalculated[11], ptkcalculated[12], ptkcalculated[13], ptkcalculated[14], ptkcalculated[15]);

		fprintf(stdout, "KEK.........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (calculated)\n",
		ptkcalculated[16], ptkcalculated[17], ptkcalculated[18], ptkcalculated[19], ptkcalculated[20], ptkcalculated[21], ptkcalculated[22], ptkcalculated[23], ptkcalculated[24], ptkcalculated[25], ptkcalculated[26], ptkcalculated[27], ptkcalculated[28], ptkcalculated[29], ptkcalculated[30], ptkcalculated[31]);
		}
	fprintf(stdout, "MIC.........: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	mic[0], mic[1], mic[2], mic[3], mic[4], mic[5], mic[6], mic[7], mic[8], mic[9], mic[10], mic[11], mic[12], mic[13], mic[14], mic[15]);
	if(memcmp(mic, miccalculated, 16) == 0)
		{
		fprintf(stdout, " (confirmed)\n");
		if(status & HAS_PMKID_CALC)
			{
			fprintf(stdout, "PMKID.......: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x (calculated)\n",
			pmkidcalculated[0], pmkidcalculated[1], pmkidcalculated[2], pmkidcalculated[3], pmkidcalculated[4], pmkidcalculated[5], pmkidcalculated[6], pmkidcalculated[7], pmkidcalculated[8], pmkidcalculated[9], pmkidcalculated[10], pmkidcalculated[11], pmkidcalculated[12], pmkidcalculated[13], pmkidcalculated[14], pmkidcalculated[15]);
			}
		exitcode = EXIT_SUCCESS_CONFIRMED;
		}
	else fprintf(stdout, " (not confirmed)\n");
	}
fprintf(stdout, "\n");
return;
}
/*===========================================================================*/
static bool genmicwpa2kv3(void)
{
static uint8_t eapoltmp[1024];

memset(eapoltmp, 0, 1024);
memcpy(eapoltmp, eapol, eapollen);
if(!EVP_MAC_init(ctxcmac, ptkcalculated, 16, paramsaes128)) return false;
if(!EVP_MAC_update(ctxcmac, eapoltmp, eapollen)) return false;
if(!EVP_MAC_final(ctxcmac, eapoltmp, NULL, eapollen)) return false;
memcpy(miccalculated, eapoltmp, 16);
return true;
}
/*===========================================================================*/
static bool genmicwpa1(void)
{
static uint8_t eapoltmp[1024];

memset(eapoltmp, 0, 1024);
memcpy(eapoltmp, eapol, eapollen);
if(!EVP_MAC_init(ctxhmac, ptkcalculated, 16, paramsmd5)) return false;
if(!EVP_MAC_update(ctxhmac, eapoltmp, eapollen)) return false;
if(!EVP_MAC_final(ctxhmac, eapoltmp, NULL, eapollen)) return false;
memcpy(miccalculated, eapoltmp, 16);
return true;
}
/*===========================================================================*/
static bool genmicwpa2(void)
{
static uint8_t eapoltmp[1024];

memset(eapoltmp, 0, 1024);
memcpy(eapoltmp, eapol, eapollen);
if(!EVP_MAC_init(ctxhmac, ptkcalculated, 16, paramssha1)) return false;
if(!EVP_MAC_update(ctxhmac, eapoltmp, eapollen)) return false;
if(!EVP_MAC_final(ctxhmac, eapoltmp, NULL, eapollen)) return false;
memcpy(miccalculated, eapoltmp, 16);
return true;
}
/*===========================================================================*/
static bool genptkwpa2kv3(void)
{
static uint8_t *pkeptr;

memset(&ptkcalculated, 0, 128);
pkeptr = ptkcalculated;
pkeptr[0] = 1;
pkeptr[1] = 0;
pkeptr += 2;
memcpy(pkeptr, "Pairwise key expansion", 22);
if(memcmp(macap, macclient, 6) < 0)
	{
	memcpy(pkeptr +22, macap, 6);
	memcpy(pkeptr +28, macclient, 6);
	}
else
	{
	memcpy(pkeptr +22, macclient, 6);
	memcpy(pkeptr +28, macap, 6);
	}
if(memcmp(anonce, wpak->nonce, 32) < 0)
	{
	memcpy (pkeptr +34, anonce, 32);
	memcpy (pkeptr +66, wpak->nonce, 32);
	}
else
	{
	memcpy (pkeptr +34, wpak->nonce, 32);
	memcpy (pkeptr +66, anonce, 32);
	}

ptkcalculated[100] = 0x80;
ptkcalculated[101] = 1;
if(!EVP_MAC_init(ctxhmac, pmkcalculated, 32, paramssha256)) return false;
if(!EVP_MAC_update(ctxhmac, ptkcalculated, 102)) return false;
if(!EVP_MAC_final(ctxhmac, ptkcalculated, NULL, 128)) return false;
return true;
}
/*===========================================================================*/
static bool genptkwpa12(void)
{
static uint8_t *pkeptr;

pkeptr = ptkcalculated;
memcpy(pkeptr, "Pairwise key expansion", 23);
if(memcmp(macap, macclient, 6) < 0)
	{
	memcpy(pkeptr +23, macap, 6);
	memcpy(pkeptr +29, macclient, 6);
	}
else
	{
	memcpy(pkeptr +23, macclient, 6);
	memcpy(pkeptr +29, macap, 6);
	}
if(memcmp(anonce,  wpak->nonce, 32) < 0)
	{
	memcpy (pkeptr +35, anonce, 32);
	memcpy (pkeptr +67, wpak->nonce, 32);
	}
else
	{
	memcpy (pkeptr +35, wpak->nonce, 32);
	memcpy (pkeptr +67, anonce, 32);
	}
if(!EVP_MAC_init(ctxhmac, pmkcalculated, 32, paramssha1)) return false;
if(!EVP_MAC_update(ctxhmac, ptkcalculated, 100)) return false;
if(!EVP_MAC_final(ctxhmac, ptkcalculated, NULL, 128)) return false;
return true;
}
/*===========================================================================*/
static bool genpmkid(void)
{
static const char *pmkname = "PMK Name";

memcpy(pmkidcalculated, pmkname, 8);
memcpy(pmkidcalculated +8, macap, 6);
memcpy(pmkidcalculated +14, macclient, 6);
if(!EVP_MAC_init(ctxhmac, pmkcalculated, 32, paramssha1)) return false;
if(!EVP_MAC_update(ctxhmac, pmkidcalculated, 20)) return false;
if(!EVP_MAC_final(ctxhmac, pmkidcalculated, NULL, 20)) return false;
status |= HAS_PMKID_CALC;
return true;
}
/*===========================================================================*/
static bool genpmk(char *psk)
{
memset(pmkcalculated, 0, 32);
if(PKCS5_PBKDF2_HMAC_SHA1(psk, psklen, essid, essidlen, 4096, 32, pmkcalculated) == 0) return false;
status |= HAS_PMK_CALC;
return true;
}
/*===========================================================================*/
static bool parsehashlinestring(char *hashlinestring)
{
static size_t hlen;
static size_t plen;
static ssize_t flen;

static const char *wpa1 = "WPA*01*";
static const char *wpa2 = "WPA*02*";

hlen = strlen(hashlinestring);
if(hlen < 71) return false;
plen = 7;
if(memcmp(wpa1, hashlinestring, 7) == 0)
	{
	flen = hex2bin(&hashlinestring[plen], pmkid, 16);
	if(flen != 16) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = hex2bin(&hashlinestring[plen], macap, 6);
	if(flen != 6) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = hex2bin(&hashlinestring[plen], macclient, 6);
	if(flen != 6) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	essidlen = hex2bin(&hashlinestring[plen], essid, 34);
	if((essidlen <= 0) || (essidlen > 32)) return false;
	plen += essidlen *2;
	if(hashlinestring[plen++] != '*') return false;
	status |= HAS_PMKID_LINE;
	status |= HAS_PMKID;
	status |= HAS_ESSID;
	status |= HAS_MACAP;
	status |= HAS_MACCLIENT;
	return true;
	}
if(memcmp(wpa2, hashlinestring, 7) == 0)
	{
	flen = hex2bin(&hashlinestring[plen], mic, 16);
	if(flen != 16) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = hex2bin(&hashlinestring[plen], macap, 6);
	if(flen != 6) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = hex2bin(&hashlinestring[plen], macclient, 6);
	if(flen != 6) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = getfieldlen(&hashlinestring[plen], 34);
	if((flen %2) != 0) return false;
	flen /= 2;
	if((flen <= 0) || (flen > 32)) return false;
	essidlen = hex2bin(&hashlinestring[plen], essid, flen);
	if((essidlen <= 0) || (essidlen > 32)) return false;
	plen += essidlen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = hex2bin(&hashlinestring[plen], anonce, 32);
	if(flen == -1) return false;
	plen += flen *2;
	if(hashlinestring[plen++] != '*') return false;
	flen = getfieldlen(&hashlinestring[plen], 1024);
	if((flen %2) != 0) return false;
	flen /= 2;
	if((flen <= 0) || (flen > 1024)) return false;
	eapollen = hex2bin(&hashlinestring[plen], eapol, flen);
	eapptr = (eapauth_t*)eapol;
	eapauthlen = ntohs(eapptr->len);
	if(eapollen < eapauthlen +4) return false;
	plen += eapollen *2;
	if(hashlinestring[plen++] != '*') return false;
	wpak = (wpakey_t*)(eapol +EAPAUTH_SIZE);
	keyversion = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	status |= HAS_EAPOL_LINE;
	status |= HAS_MIC;
	status |= HAS_ESSID;
	status |= HAS_MACAP;
	status |= HAS_MACCLIENT;
	return true;
	}
return false;
}
/*===========================================================================*/
static bool evpdeinitwpa(void)
{
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
return true;
}
/*===========================================================================*/
static bool evpinitwpa(void)
{
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

char aes[] = "aes-128-cbc";
paramsaes128[0] = OSSL_PARAM_construct_utf8_string("cipher", aes, 0);
paramsaes128[1] = OSSL_PARAM_construct_end();

ctxhmac = EVP_MAC_CTX_new(hmac);
if(ctxhmac == NULL) return false;
ctxcmac = EVP_MAC_CTX_new(cmac);
if(ctxcmac == NULL) return false;
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"\n"
	"short options:\n"
	"-l <hash line> : input hashcat hash line (-m 22000)\n"
	"-e <ESSID>     : input Network Name (ESSID)\n"
	"-p <PSK>       : input Pre Shared Key (PSK) or Plain Master Key (PMK)\n"
	"-p -           : read Pre Shared Key (PSK) from stdin\n"
	"               : small lists only\n"
	"\n"
	"long options:\n"
	"--help         : show this help\n"
	"--version      : show version\n\n"
	"exit codes:\n"
	"0 = PSK/PMK confirmed\n"
	"1 = ERROR occurred\n"
	"2 = PSK/PMK unconfirmed\n"
	"\n"
	"Important notice:\n"
	"%s does not do NONCE ERROR CORRECTIONS\n"
	"in case of a packet loss, you get a wrong PTK\n"
	"\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
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
static char *hashlinestring;
static char pskbuffer[128];

static const char *short_options = "l:e:p:m:a:c:hv";
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
exitcode = EXIT_SUCCESS_UNCONFIRMED;
status = 0;
essidlen = 0;
hashlinestring = NULL;
pskstring = NULL;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_HASHLINE:
		hashlinestring = optarg;
		break;

		case HCX_PSK:
		pskstring = optarg;
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
if(argc < 2)
	{
	fprintf(stderr, "no option selected\nrun %s --help to get more information\n", (basename(argv[0])));
	exit(EXIT_FAILURE);
	}
if(evpinitwpa() == false)
	{
	fprintf(stderr, "\nEVP API error\n");
	return EXIT_FAILURE;
	}
if(hashlinestring != NULL)
	{
	if(parsehashlinestring(hashlinestring) == false)
		{
		fprintf(stdout, "hash line error\n");
		return EXIT_FAILURE;
		}
	}
if(pskstring != NULL)
	{
	psklen = strlen(pskstring);
	if((psklen >= 8) &&(psklen < 63)) 
		{
		status |= HAS_PSK;
		if((status & HAS_ESSID) == HAS_ESSID)
			{
			if(genpmk(pskstring) == false)
				{
				fprintf(stderr, "\nPMK error\n");
				return EXIT_FAILURE;
				}
			}
		}
	else if(psklen == 64) 
		{
		if(hex2bin(pskstring, pmkcalculated, 32) != 32)
			{
			fprintf(stderr, "\nPMK error\n");
			return EXIT_FAILURE;
			}
		status |= HAS_PMK;
		}
	else if(strncmp(pskstring, "-", 1) == 0)
		{
		if((status & HAS_ESSID) == HAS_ESSID)
			{
			if((status & HAS_PMKID) == HAS_PMKID)
				{
				while(1)
					{
					if((psklen = fgetline(stdin, 128, pskbuffer)) == -1) break;
					if((psklen < 8) || (psklen > 63)) continue;
						{
						if(genpmk(pskbuffer) == false)
							{
							fprintf(stderr, "\nPMK error\n");
							exit(EXIT_FAILURE);
							}
						if(genpmkid() == false)
							{
							fprintf(stderr, "\nPMK error\n");
							exit(EXIT_FAILURE);
							}
						if(memcmp(pmkid, pmkidcalculated, 16) == 0)
							{
							pskstring = pskbuffer;
							status |= HAS_PSK;
							showresult();
							exit(EXIT_SUCCESS_CONFIRMED);
							}
						}
					}
				if(evpdeinitwpa() == false)
					{
					fprintf(stdout, "EVP API error\n");
					exit(EXIT_FAILURE);
					}
				exit(EXIT_SUCCESS);
				}
			if((status & HAS_MIC) == HAS_MIC)
				{
				if(keyversion == 2)
					{
					while(1)
						{
						if((psklen = fgetline(stdin, 128, pskbuffer)) == -1) break;
						if((psklen < 8) || (psklen > 63)) continue;
						if(genpmk(pskbuffer) == false) exit(EXIT_FAILURE);
						if(genptkwpa12() == false) exit(EXIT_FAILURE);
						if(genmicwpa2() == false) exit(EXIT_FAILURE);
						if(memcmp(mic, miccalculated, 16) == 0)
							{
							if(genpmkid() == false) exit(EXIT_FAILURE);
							pskstring = pskbuffer;
							status |= HAS_PSK;
							status |= HAS_PTK_CALC;
							status |= HAS_PMKID_CALC;
							showresult();
							exit(EXIT_SUCCESS_CONFIRMED);
							}
						}
					if(evpdeinitwpa() == false) exit(EXIT_FAILURE);
					exit(EXIT_SUCCESS);
					}
				if(keyversion == 1)
					{
					while(1)
						{
						if((psklen = fgetline(stdin, 128, pskbuffer)) == -1) break;
						if((psklen < 8) || (psklen > 63)) continue;
						if(genpmk(pskbuffer) == false) exit(EXIT_FAILURE);
						if(genptkwpa12() == false) exit(EXIT_FAILURE);
						if(genmicwpa1() == false) exit(EXIT_FAILURE);
						if(memcmp(mic, miccalculated, 16) == 0)
							{
							if(genpmkid() == false) exit(EXIT_FAILURE);
							pskstring = pskbuffer;
							status |= HAS_PSK;
							status |= HAS_PTK_CALC;
							status |= HAS_PMKID_CALC;
							showresult();
							exit(EXIT_SUCCESS_CONFIRMED);
							}
						}
					if(evpdeinitwpa() == false) exit(EXIT_FAILURE);
					exit(EXIT_SUCCESS);
					}
				if(keyversion == 3)
					{
					while(1)
						{
						if((psklen = fgetline(stdin, 128, pskbuffer)) == -1) break;
						if((psklen < 8) || (psklen > 63)) continue;
						if(genpmk(pskbuffer) == false) exit(EXIT_FAILURE);
						if(genptkwpa2kv3() == false) exit(EXIT_FAILURE);
						if(genmicwpa2kv3() == false) exit(EXIT_FAILURE);
						if(memcmp(mic, miccalculated, 16) == 0)
							{
							if(genpmkid() == false) exit(EXIT_FAILURE);
							pskstring = pskbuffer;
							status |= HAS_PSK;
							status |= HAS_PTK_CALC;
							status |= HAS_PMKID_CALC;
							showresult();
							exit(EXIT_SUCCESS_CONFIRMED);
							}
						}
					if(evpdeinitwpa() == false) exit(EXIT_FAILURE);
					exit(EXIT_SUCCESS);
					}
				if(evpdeinitwpa() == false) exit(EXIT_FAILURE);
				exit(EXIT_SUCCESS);
				}
			}
		}
	}

if((((status & HAS_PMK_CALC) == HAS_PMK_CALC) || ((status & HAS_PMK) == HAS_PMK)) && ((status & HAS_PMKID) == HAS_PMKID))
	{
	if(genpmkid() == false)
		{
		fprintf(stderr, "\nPMKID error\n");
		return EXIT_FAILURE;
		}
	}

if((status & HAS_EAPOL_LINE) == HAS_EAPOL_LINE)
	{
	if((keyversion == 0) || (keyversion > 3))
		{
		fprintf(stderr, "\nkey version error\n");
		return EXIT_FAILURE;
		}
	if(((status & HAS_PMK_CALC) == HAS_PMK_CALC) || ((status & HAS_PMK) == HAS_PMK))
		{
		if(keyversion < 3)
			{
			if(genptkwpa12() == false) return false;
			if(keyversion == 2)
				{
				if(genmicwpa2() == false) return false;
				if(genpmkid() == false) return false;
				status |= HAS_PTK_CALC;
				status |= HAS_PMKID_CALC;
				}
			if(keyversion == 1)
				{
				if(genmicwpa1() == false) return false;
				if(genpmkid() == false) return false;
				status |= HAS_PTK_CALC;
				status |= HAS_PMKID_CALC;
				}
			}
		else
			{
			if(genptkwpa2kv3() == false) return false;
			if(genmicwpa2kv3() == false) return false;
			if(genpmkid() == false) return false;
			status |= HAS_PTK_CALC;
			status |= HAS_PMKID_CALC;
			}
		}
	}

showresult();

if(evpdeinitwpa() == false)
	{
	fprintf(stdout, "EVP API error\n");
	exit(EXIT_FAILURE);
	}
exit(exitcode);
}
/*===========================================================================*/

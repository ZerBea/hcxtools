#define _GNU_SOURCE
#include <fcntl.h>
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
#include <pthread.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>

#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/version.h"
#include "include/hcxpmkidtool.h"
#include "include/strings.c"

/*===========================================================================*/
/* global var */
int cores;
int workitems;
FILE *fh_file;
intpsk_t *wordlist;
int essidlen;
int pskoutlen;
bool pskfoundflag;
bool pmkfoundflag;

char separator = ':';
uint8_t macsta[6];
uint8_t macap[6];
uint8_t essid[32];
uint8_t pmkid[16];
uint8_t pmkout[32];
uint8_t pskout[64];

/*===========================================================================*/
bool globalclose()
{

if(wordlist != NULL)
	{
	free(wordlist);
	}
return true;
}
/*===========================================================================*/
bool globalinit()
{
pskfoundflag = false;
pmkfoundflag = false;

if((cores = sysconf(_SC_NPROCESSORS_ONLN)) == -1)
	{
	printf("failed to get CPU information\n");
	return false;
	}
if(cores < 1)
	{
	printf("no cores available\n");
	return false;
	}
if(cores > 256)
	{
	cores = 256;
	}

workitems = cores *PSKCOUNT;

wordlist = malloc(workitems *INTPSK_SIZE);
if(wordlist == NULL)
	{
	printf("failed to allocate workload memory\n");
	return false;
	}
return true;
}
/*===========================================================================*/
bool isasciisepstring(int len, uint8_t *buffer)
{
uint8_t p;
for(p = 0; p < len; p++)
	{
	if((buffer[p] < 0x20) || (buffer[p] > 0x7e) || (buffer[p] == separator))
		{
		return false;
		}
	}
return true;
}
/*===========================================================================*/
size_t chop(char *buffer, size_t len)
{
char *ptr;

ptr = buffer +len -1;
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
size_t len;
char *buffptr;

if(feof(inputstream))
	return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL)
	return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
void *calculatethread(void *args)
{
int c;
argument_t *arg = (argument_t *)args;
intpsk_t *zeiger;

char *pmkname = "PMK Name";

uint8_t pmk[32];
uint8_t salt[32];
uint8_t mypmkid[32];

zeiger = arg->pos;
arg->found = false;
for(c = 0; c < arg->sc; c++)
	{
	if(PKCS5_PBKDF2_HMAC_SHA1(zeiger->psk, zeiger->len, essid, essidlen, 4096, 32, pmk) == 0)
		{
		return NULL;
		}
	memcpy(&salt, pmkname, 8);
	memcpy(&salt[8], &macap, 6);
	memcpy(&salt[14], &macsta, 6);
	HMAC(EVP_sha1(), &pmk, 32, salt, 20, mypmkid, NULL);
	if(memcmp(&mypmkid, &pmkid, 16) == 0)
		{
		arg->found = true;
		memcpy(arg->pmk, &pmk, 32);
		arg->psklen =  zeiger->len;
		memset(arg->psk, 0, 64);
		memcpy(arg->psk, zeiger->psk, zeiger->len);
		return NULL;
		}
	zeiger++;
	}
return NULL;
}
/*===========================================================================*/
int readitems()
{
int pskcount;
intpsk_t *zeiger;
int plen;

char hm[] = { "$HEX[" };

char pskinline[PSKLEN *2 +5];

pskcount = 0;
zeiger = wordlist;
while(pskcount < workitems)
	{
	if((plen = fgetline(fh_file, PSKLEN *2 +5, pskinline)) == -1)
		{
		break;
		}
	if(plen < 8)
		{
		continue;
		}
	if((memcmp(pskinline, &hm, 5) == 0) && (pskinline[plen -1] == ']'))
		{
		zeiger->len = (plen -6);
		if((zeiger->len %2) != 0)
			{
			continue;
			}
		zeiger->len = zeiger->len /2;
		if(zeiger->len > 64)
			{
			continue;
			}
		if(hex2bin(&pskinline[5], (uint8_t*)zeiger->psk, zeiger->len) == false)
			{
			continue;
			}
		zeiger++;
		pskcount++;
		continue;
		}
	if(plen < 64)
		{
		zeiger->len = plen;
		memset(zeiger->psk, 0, PSKLEN);
		memcpy(zeiger->psk, &pskinline, plen);
		}
	zeiger++;
	pskcount++;
	}
return pskcount;
}
/*===========================================================================*/
void processwordlist(char *wordlistname)
{
int ret;
int c;
int pskcount;

pthread_t thread[256];
argument_t args[256];

if((fh_file = fopen(wordlistname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open file %s\n", wordlistname);
	return;
	}

pskcount = workitems;
while(1)
	{
	if(pskfoundflag == true)
		{
		fclose(fh_file);
		return;
		}
	pskcount = readitems();
	if(pskcount == 0)
		{
		fclose(fh_file);
		return;
		}
	if(pskcount == workitems)
		{
		for(c = 0; c < cores; c++)
			{
			args[c].pos = wordlist +(c *PSKCOUNT);
			args[c].sc = PSKCOUNT;
			ret = pthread_create(&thread[c], NULL, &calculatethread, &args[c]);
			if(ret != 0)
				{
				fclose(fh_file);
				printf("failed to create thread\n");
				return;
				}
			}
		for(c = 0; c < cores; c++)
			{
			pthread_join(thread[c], NULL);
			if(args[c].found == true)
				{
				pskfoundflag = true;
				memcpy(&pmkout, args[c].pmk, 32);
				pskoutlen = args[c].psklen;
				memset(&pskout, 0, 64);
				memcpy(&pskout, args[c].psk, args[c].psklen);
				}
			}
		}
	if(pskcount < workitems)
		{
		break;
		}
	}
for(c = 0; c < cores; c++)
	{
	args[c].pos = wordlist +(c *((pskcount/cores) + (pskcount%cores)));
	args[c].sc = (pskcount/cores) + (pskcount%cores);
	ret = pthread_create(&thread[c], NULL, &calculatethread, &args[c]);
	if(ret != 0)
		{
		fclose(fh_file);
		printf("failed to create thread\n");
		return;
		}
	}
for(c = 0; c < cores; c++)
	{
	pthread_join(thread[c], NULL);
	if(args[c].found == true)
		{
		pskfoundflag = true;
		memcpy(&pmkout, args[c].pmk, 32);
		pskoutlen = args[c].psklen;
		memset(&pskout, 0, 64);
		memcpy(&pskout, args[c].psk, args[c].psklen);
		}
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
void processpmkname(char *pmkname)
{
int plen;

char *pmkn = "PMK Name";

uint8_t pmk[32];
uint8_t salt[32];
uint8_t mypmkid[32];

plen = strlen(pmkname);
if(plen != 64)
	{
	return;
	}
if(hex2bin(pmkname, pmk, 32) == false)
	{
	return;
	}

memcpy(&salt, pmkn, 8);
memcpy(&salt[8], &macap, 6);
memcpy(&salt[14], &macsta, 6);
HMAC(EVP_sha1(), &pmk, 32, salt, 20, mypmkid, NULL);

if(memcmp(&mypmkid, &pmkid, 16) == 0)
	{
	pmkfoundflag = true;
	memcpy(&pmkout, &pmk, 32);
	}
return;
}
/*===========================================================================*/
void processwordname(char *wordname)
{
int plen;
int len;

char *pmkname = "PMK Name";
char hm[] = { "$HEX[" };

char psk[PSKLEN];
uint8_t pmk[32];
uint8_t salt[32];
uint8_t mypmkid[32];

plen = strlen(wordname);
if(plen < 8)
	{
	return;
	}
if((memcmp(wordname, &hm, 5) == 0) && (wordname[plen -1] == ']'))
	{
	len = (plen -6);
	if((len %2) != 0)
		{
		return;
		}
	len = len /2;
	if(len > 64)
		{
		return;
		}
	if(hex2bin(&wordname[5], (uint8_t*)psk, len) == false)
		{
		return;
		}
	}
else if(plen < 64)
	{
	len = plen;
	memset(&psk, 0, PSKLEN);
	memcpy(&psk, wordname, len);
	}
else
	{
	return;
	}

if(PKCS5_PBKDF2_HMAC_SHA1(psk, len, essid, essidlen, 4096, 32, pmk) == 0)
	{
	return;
	}
memcpy(&salt, pmkname, 8);
memcpy(&salt[8], &macap, 6);
memcpy(&salt[14], &macsta, 6);
HMAC(EVP_sha1(), &pmk, 32, salt, 20, mypmkid, NULL);
if(memcmp(&mypmkid, &pmkid, 16) == 0)
	{
	pskfoundflag = true;
	memcpy(&pmkout, &pmk, 32);
	pskoutlen = len;
	memset(&pskout, 0, 64);
	memcpy(&pskout, psk, len);
	}
return;
}
/*===========================================================================*/
bool processpmkid(char *pmkidline)
{
int pmkidlen;

pmkidlen = strlen(pmkidline);
if((pmkidlen < 61) || ((pmkidlen > 59 +(ESSID_LEN_MAX *2))))
	{
	return false;
	}
if((pmkidline[32] == ':') && (pmkidline[45] == ':') && (pmkidline[58] == ':'))
	{
	separator = ':';
	}
else if((pmkidline[32] == '*') && (pmkidline[45] == '*') && (pmkidline[58] == '*'))
	{
	separator = '*';
	}
else
	{
	return false;
	}
if(hex2bin(&pmkidline[0], pmkid, 16) == false)
	{
	return false;
	}
if(hex2bin(&pmkidline[33], macap, 6) == false)
	{
	return false;
	}
if(hex2bin(&pmkidline[46], macsta, 6) == false)
	{
	return false;
	}
essidlen = pmkidlen -59;
if((essidlen == 0) || (essidlen > 64) || ((essidlen %2) != 0))
	{
	return false;
	}
essidlen = essidlen /2;
if(hex2bin(&pmkidline[59], essid, essidlen) ==false)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-p <pmkid>  : input PMKID\n"
	"              PMKID:MAC_AP:MAC_STA:ESSID(XDIGIT)\n"
	"              PMKID*MAC_AP*MAC_STA*ESSID(XDIGIT)\n"
	"-w <file>   : input wordlist (8...63 characters)\n"
	"              output: PMK:ESSID (XDIGIT):password\n"
	"-W <word>   : input single word (8...63 characters)\n"
	"              output: PMK:ESSID (XDIGIT):password\n"
	"-K <pmk>    : input single PMK\n"
	"              format:\n"
	"              output: PMK:ESSID (XDIGIT)\n"
	"-h          : show this help\n"
	"-v          : show version\n"
	"\n"
	"--help      : show this help\n"
	"--version   : show version\n"
	"\n"
	"hcxpmkidtool designed to verify an existing PSK or and existing PMK.\n"
	"It is not designed to run big wordlists!\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int index;
int c;

char *wordlistname = NULL;
char *wordname = NULL;
char *pmkidname = NULL;
char *pmkname = NULL;

const char *short_options = "w:W:K:p:hv";
const struct option long_options[] =
{
	{"version",			no_argument,		NULL,	HCXD_VERSION},
	{"help",			no_argument,		NULL,	HCXD_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCXD_WORD_IN:
		wordname = optarg;
		if((strlen(wordname) < 8) || (strlen(wordname) > 63))
			{
			fprintf(stderr, "only 8...63 characters allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_WORDLIST_IN:
		wordlistname = optarg;
		break;

		case HCXD_PMK_IN:
		pmkname = optarg;
		if(strlen(pmkname) != 64)
			{
			fprintf(stderr, "only 64 (XDIGIT) characters allowed\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_PMKID_IN:
		pmkidname = optarg;
		break;

		case HCXD_HELP:
		usage(basename(argv[0]));
		break;

		case HCXD_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

if(argc < 2)
	{
	fprintf(stderr, "no option selected\n");
	exit(EXIT_FAILURE);
	}

if(globalinit() == false)
	{
	fprintf(stderr, "initialization failed\n");
	exit(EXIT_FAILURE);
	}

if(processpmkid(pmkidname) == false)
	{
	fprintf(stderr, "wrong pmkidformat\n");
	exit(EXIT_FAILURE);
	}

if((wordname != NULL) && (pskfoundflag == false))
	{
	processwordname(wordname);
	}

if((wordlistname != NULL) && (pskfoundflag == false))
	{
	processwordlist(wordlistname);
	}

if((pmkname != NULL) && (pmkfoundflag == false))
	{
	processpmkname(pmkname);
	}

if(globalclose() == false)
	{
	fprintf(stderr, "deinitialization failed\n");
	exit(EXIT_FAILURE);
	}

if(pskfoundflag == true)
	{
	printf("verified:");
	for(c = 0; c < 32; c++)
		{
		printf("%02x", pmkout[c]);
		}
	printf("%c", separator);
	for(c = 0; c < essidlen; c++)
		{
		printf("%02x", essid[c]);
		}
	printf("%c", separator);
	if(isasciisepstring(pskoutlen, pskout) == true)
		{
		printf("%s\n", pskout);
		}
	else
		{
		printf("$HEX[");
		for(c = 0; c < pskoutlen; c++)
			{
			printf("%02x", pskout[c]);
			}
		printf("]/n");
		}
	return EXIT_SUCCESS;
	}

if(pmkfoundflag == true)
	{
	printf("verified:");
	for(c = 0; c < 32; c++)
		{
		printf("%02x", pmkout[c]);
		}
	printf("%c", separator);
	for(c = 0; c < essidlen; c++)
		{
		printf("%02x", essid[c]);
		}
	printf("\n");
	return EXIT_SUCCESS;
	}
return EXHAUSTED;
}
/*===========================================================================*/

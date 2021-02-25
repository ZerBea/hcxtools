#define _GNU_SOURCE
#include <libgen.h>
#include <ctype.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <stdbool.h>

#include "include/hcxeiutool.h"

/*===========================================================================*/
/* global variable */

static FILE *fh_digitlist;
static FILE *fh_xdigitlist;
static FILE *fh_charlist;
static FILE *fh_cslist;
/*===========================================================================*/
static void separatewords(int len, char *line)
{
static int c, cl, cs, cw, cd, cx;
static char word[LINE_MAX][WORD_MAX];

cs = 0;
cw = 0;
cd = 0;
cx = 0;
cl = CSWORD;
memset(word, 0, sizeof(word));
for(c = 0; c < len; c++)
	{
	if((line[c] >= '0') && (line[c] <= '9'))
		{
		word[DIGITWORD][cd] = line[c];
		cd++;
		}
	if(isxdigit(line[c]))
		{
		word[XDIGITWORD][cx] = line[c];
		cx++;
		}
	if(((line[c] >= 'A') && (line[c] <= 'Z')) || ((line[c] >= 'a') && (line[c] <= 'z')))
		{
		word[CHARWORD][cw] = line[c];
		word[cl][cs] = line[c];
		cw++;
		cs++;
		}
	else
		{
		cl++;
		cs = 0;
		}
	}
if(memcmp(word[DIGITWORD], word[XDIGITWORD], WORD_MAX) == 0) word[XDIGITWORD][0] = 0;
if(memcmp(word[CSWORD], word[XDIGITWORD], WORD_MAX) == 0) word[XDIGITWORD][0] = 0;
if(memcmp(word[CSWORD], word[CHARWORD], WORD_MAX) == 0) word[CHARWORD][0] = 0;

if(fh_digitlist != NULL)
	{
	if(strnlen(word[DIGITWORD], WORD_MAX) > 3) fprintf(fh_digitlist, "%s\n", word[DIGITWORD]);
	}
if(fh_xdigitlist != NULL)
	{
	if(strnlen(word[XDIGITWORD], WORD_MAX) > 3) fprintf(fh_xdigitlist, "%s\n", word[XDIGITWORD]);
	}
if(fh_charlist != NULL)
	{
	if(strnlen(word[CHARWORD], WORD_MAX) > 3) fprintf(fh_charlist, "%s\n", word[CHARWORD]);
	}
if(fh_cslist != NULL)
	{
	for(c = CSWORD; c < LINE_MAX; c++)
		{
		if(strnlen(word[c], WORD_MAX) > 3) fprintf(fh_cslist, "%s\n", word[c]);
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
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
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
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
static void processwordlist(FILE *fh_in)
{
static int len;

static char hexid[] = "$HEX[";
static char linein[LINEIN_MAX];

while((len = fgetline(fh_in, LINEIN_MAX, linein)) != -1)
	{
	if(memcmp(&linein, &hexid, 5) == 0) continue;
	if(len < 64) separatewords(len, linein);
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
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
	"-i <file> : input wordlist\n"
	"-d <file> : output digit wordlist\n"
	"-x <file> : output xdigit wordlist\n"
	"-c <file> : output character wordlist (A-Za-z - other characters removed)\n"
	"-s <file> : output character wordlist (A-Za-z - other characters replaced by 0x0d)\n"
	"            recommended option for processing with rules\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--help           : show this help\n"
	"--version        : show version\n"
	"\n"
	"example:\n"
	"$ hcxdumptool -i <interface> -o dump.pcapng --enable_status=31\n"
	"$ hcxpcapngtool -o hash.22000 -E elist dump.pcapng\n"
	"$ hcxeiutool -i elist -d digitlist -x xdigitlist -c charlist -s sclist\n"
	"$ cat elist digitlist xdigitlist charlist sclist > wordlisttmp\n"
	"$ hashcat --stdout -r <rule> charlist >> wordlisttmp\n"
	"$ hashcat --stdout -r <rule> sclist >> wordlisttmp\n"
	"$ cat wordlisttmp | sort | uniq > wordlist\n"
	"$ hashcat -m 22000 hash.22000 wordlist\n" 
	"\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
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
static FILE *fh_wordlistin = NULL;
static char *wordlistinname = NULL;
static char *digitname = NULL;
static char *xdigitname = NULL;
static char *charname = NULL;
static char *csname = NULL;

static const char *short_options = "i:d:x:c:s:hv";
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

fh_digitlist = NULL;
fh_xdigitlist = NULL;
fh_charlist = NULL;
fh_cslist = NULL;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_INPUT_WORDLIST:
		wordlistinname = optarg;
		break;

		case HCX_OUTPUT_DIGITLIST:
		digitname = optarg;
		break;

		case HCX_OUTPUT_XDIGITLIST:
		xdigitname = optarg;
		break;

		case HCX_OUTPUT_CHARLIST:
		charname = optarg;
		break;

		case HCX_OUTPUT_CSLIST:
		csname = optarg;
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
	fprintf(stderr, "no option selected\n");
	return EXIT_SUCCESS;
	}

if(wordlistinname == NULL)
	{
	fprintf(stderr, "no input wordlist selected\n");
	return EXIT_SUCCESS;
	}

if((fh_wordlistin = fopen(wordlistinname, "r")) == NULL)
	{
	printf("error opening file %s: %s\n", wordlistinname, strerror(errno));
	exit(EXIT_FAILURE);
	}

if(digitname != NULL)
	{
	if((fh_digitlist = fopen(digitname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", digitname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(xdigitname != NULL)
	{
	if((fh_xdigitlist = fopen(xdigitname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", xdigitname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(charname != NULL)
	{
	if((fh_charlist = fopen(charname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", charname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(csname != NULL)
	{
	if((fh_cslist = fopen(csname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", csname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

processwordlist(fh_wordlistin);

if(fh_cslist != NULL) fclose(fh_cslist);
if(fh_charlist != NULL) fclose(fh_charlist);
if(fh_xdigitlist != NULL) fclose(fh_xdigitlist);
if(fh_digitlist != NULL) fclose(fh_digitlist);
fclose(fh_wordlistin);

return EXIT_SUCCESS;
}
/*===========================================================================*/

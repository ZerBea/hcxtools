#define _GNU_SOURCE
#include <ctype.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <sys/types.h>
#include <stdbool.h>

#include "include/version.h"
#include "include/hcxwltool.h"

/*===========================================================================*/
/* global variable */

static bool wantstraight;
static bool wantdigit;
static bool wantxdigit;
static bool wantlower;
static bool wantupper;
static bool wantcapital;
static int sweeplen;
/*===========================================================================*/
static void printstraightlower(FILE *fh_out, int len, char *linein)
{
static int p,px;

static char lineout[LINEIN_MAX] = {};

px = 0;
for(p = 0; p < len; p++)
	{
	if(isupper(linein[p]))
		{
		lineout[p] = tolower(linein[p]);
		}
	else
		{
		lineout[p] = linein[p];
		}
	if(isxdigit(lineout[p]))
		{
		px++;
		}
	}
lineout[p] = 0;

if(p != px)
	{
	fprintf(fh_out, "%s\n", lineout);
	}
return;
}
/*===========================================================================*/
static void printstraightupper(FILE *fh_out, int len, char *linein)
{
static int p, px;

static char lineout[LINEIN_MAX] = {};

px = 0;
for(p = 0; p < len; p++)
	{
	if(islower(linein[p]))
		{
		lineout[p] = toupper(linein[p]);
		}
	else
		{
		lineout[p] = linein[p];
		}
	if(isxdigit(lineout[p]))
		{
		px++;
		}
	}
lineout[p] = 0;

if(p != px)
	{
	fprintf(fh_out, "%s\n", lineout);
	}
return;
}
/*===========================================================================*/
static void printstraightcapital(FILE *fh_out, int len, char *linein)
{
static int p,px;

static char lineout[LINEIN_MAX] = {};

px = 0;
for(p = 0; p < len; p++)
	{
	if(isupper(linein[p]))
		{
		lineout[p] = tolower(linein[p]);
		}
	else
		{
		lineout[p] = linein[p];
		}
	if(isxdigit(lineout[p]))
		{
		px++;
		}
	}
lineout[p] = 0;

if((p != px) && ((lineout[0] >= 'a') && (lineout[0] <= 'z')))
	{
	lineout[0] = toupper(linein[0]);
	fprintf(fh_out, "%s\n", lineout);
	}
return;
}
/*===========================================================================*/
static void printstraightstraight(FILE *fh_out, char *linein)
{

fprintf(fh_out, "%s\n", linein);

return;
}
/*===========================================================================*/
static void printstraigthsweep(FILE *fh_out, int slen, int len, char *linein)
{
static int l;
static char lineout[LINEIN_MAX] = {};

if(len >= slen)
	{
	for(l = 0; l <= len -slen; l++)
		{
		memcpy(&lineout, &linein[l], slen);
		lineout[slen] = 0;
		if(wantlower == true)
			{
			printstraightlower(fh_out, slen, lineout);
			}
		if(wantupper == true)
			{
			printstraightupper(fh_out, slen, lineout);
			}
		if(wantcapital == true)
			{
			printstraightcapital(fh_out, slen, lineout);
			}
		if((wantlower == false) && (wantupper == false) && (wantcapital == false))
			{
			printstraightstraight(fh_out, lineout);
			}
		}
	}
return;
}
/*===========================================================================*/
static void handlestraight(FILE *fh_out, int len, char *linein)
{
if(sweeplen == 0)
	{
	if(wantlower == true)
		{
		printstraightlower(fh_out, len, linein);
		}
	if(wantupper == true)
		{
		printstraightupper(fh_out, len, linein);
		}
	if(wantcapital == true)
		{
		printstraightcapital(fh_out, len, linein);
		}
	if((wantlower == false) && (wantupper == false) && (wantcapital == false))
		{
		printstraightstraight(fh_out, linein);
		}
	}
else
	{
	printstraigthsweep(fh_out, sweeplen, len,linein);
	}
return;
}
/*===========================================================================*/
static void printxdigitlower(FILE *fh_out, int len, char *linein)
{
static int p, pd;

static char lineout[LINEIN_MAX] = {};

pd = 0;
for(p = 0; p < len; p++)
	{
	if(isupper(linein[p]))
		{
		lineout[p] = tolower(linein[p]);
		}
	else
		{
		lineout[p] = linein[p];
		}
	if(isdigit(lineout[p]))
		{
		pd++;
		}
	}
lineout[p] = 0;

if(p != pd)
	{
	fprintf(fh_out, "%s\n", lineout);
	}
return;
}
/*===========================================================================*/
static void printxdigitupper(FILE *fh_out, int len, char *linein)
{
static int p, pd;

static char lineout[LINEIN_MAX] = {};

pd = 0;
for(p = 0; p < len; p++)
	{
	if(islower(linein[p]))
		{
		lineout[p] = toupper(linein[p]);
		}
	else
		{
		lineout[p] = linein[p];
		}
	if(isdigit(lineout[p]))
		{
		pd++;
		}
	}
lineout[p] = 0;

if(p != pd)
	{
	fprintf(fh_out, "%s\n", lineout);
	}
return;
}
/*===========================================================================*/
static void printxdigitstraight(FILE *fh_out, int len, char *linein)
{
static int p, pd;

pd = 0;
for(p = 0; p < len; p++)
	{
	if(isdigit(linein[p]))
		{
		pd++;
		}
	}

if(p != pd)
	{
	fprintf(fh_out, "%s\n", linein);
	}
return;
}
/*===========================================================================*/
static void printxdigitsweep(FILE *fh_out, int slen, int len, char *linein)
{
static int l;
static char lineout[LINEIN_MAX] = {};

if(len >= slen)
	{
	for(l = 0; l <= len -slen; l++)
		{
		memcpy(&lineout, &linein[l], slen);
		lineout[slen] = 0;
		if(wantlower == true)
			{
			printxdigitlower(fh_out, slen, lineout);
			}
		if(wantupper == true)
			{
			printxdigitupper(fh_out, slen, lineout);
			}
		if((wantlower == false) && (wantupper == false))
			{
			printxdigitstraight(fh_out, slen, lineout);
			}
		}
	}
return;
}
/*===========================================================================*/
static void handlexdigit(FILE *fh_out, int len, char *linein)
{
static int i, o;
static char lineout[LINEIN_MAX] = {};

o = 0;
for(i = 0; i < len; i++)
	{
	if(isxdigit(linein[i]))
		{
		lineout[o] = linein[i];
		o++;
		}
	}
lineout[o] = 0;
if((o < 8) || (o > 63))
	{
	return;
	}

if(sweeplen == 0)
	{
	if(wantlower == true)
		{
		printxdigitlower(fh_out, o, lineout);
		}
	if(wantupper == true)
		{
		printxdigitupper(fh_out, o, lineout);
		}
	if((wantlower == false) && (wantupper == false))
		{
		printxdigitstraight(fh_out, o, lineout);
		}

	}
else
	{
	printxdigitsweep(fh_out, sweeplen, o,lineout);
	}
return;
}
/*===========================================================================*/
static void printdigitsweep(FILE *fh_out, int slen, int len, char *linein)
{
static int l;
static char lineout[LINEIN_MAX] = {};

if(len >= slen)
	{
	for(l = 0; l <= len -slen; l++)
		{
		memcpy(&lineout, &linein[l], slen);
		lineout[slen] = 0;
		fprintf(fh_out, "%s\n", lineout);
		}
	}
return;
}
/*===========================================================================*/
static void handledigit(FILE *fh_out, int len, char *linein)
{
static int i, o;
static char lineout[LINEIN_MAX] = {};

o = 0;
for(i = 0; i < len; i++)
	{
	if(isdigit(linein[i]))
		{
		lineout[o] = linein[i];
		o++;
		}
	}
lineout[o] = 0;
if((o < 8) || (o > 63))
	{
	return;
	}

if(sweeplen == 0)
	{
	fprintf(fh_out, "%s\n", lineout);
	}
else
	{
	printdigitsweep(fh_out, sweeplen, o, lineout);
	}
return;
}
/*===========================================================================*/
static int handleignore(int len, char *linein)
{

static char *wlan = "WLAN-";
static char *skyroam = "#Skyroam_";
static char *huitube3 = "3HuiTube_";
static char *pocket3 = "3Pocket_";
static char *mobilewifi3 = "3MobileWiFi-";
static char *tube3 = "3Tube_";
static char *web3 = "3Web";
static char *webcube = "WebCube";
static char *neo3 = "3neo_";

static char *wifi4g = "4G Wi-Fi 3Danmark-";

if(len == 11)
	{
	if(memcmp(wlan, linein, 5) == 0)
		{
		return 0;
		}
	if(memcmp(webcube, linein, 7) == 0)
		{
		return 0;
		}
	}
if(len == 12)
	{
	if(memcmp(skyroam, linein, 9) == 0)
		{
		return 0;
		}
	if(memcmp(web3, linein, 4) == 0)
		{
		return 0;
		}
	if(memcmp(webcube, linein, 7) == 0)
		{
		return 0;
		}
	}
if(len == 13)
	{
	if(memcmp(skyroam, linein, 9) == 0)
		{
		return 0;
		}
	if(memcmp(webcube, linein, 7) == 0)
		{
		return 0;
		}
	}
if(len == 14)
	{
	if(memcmp(skyroam, linein, 9) == 0)
		{
		return 0;
		}
	if(memcmp(web3, linein, 4) == 0)
		{
		return 0;
		}
	if(memcmp(webcube, linein, 7) == 0)
		{
		return 0;
		}
	}
if(len == 15)
	{
	if(memcmp(webcube, linein, 7) == 0)
		{
		return 0;
		}
	}
if(len == 16)
	{
	if(memcmp(pocket3, linein, 8) == 0)
		{
		return 0;
		}
	if(memcmp(mobilewifi3, linein, 11) == 0)
		{
		return 0;
		}
	if(memcmp(neo3, linein, 5) == 0)
		{
		return 0;
		}
	}
if(len == 17)
	{
	if(memcmp(tube3, linein, 6) == 0)
		{
		return 0;
		}
	}
if(len == 18)
	{
	if(memcmp(huitube3, linein, 9) == 0)
		{
		return 0;
		}
	if(memcmp(wifi4g, linein, 18) == 0)
		{
		return 0;
		}
	}
if(len == 20)
	{
	if(memcmp(huitube3, linein, 9) == 0)
		{
		return 0;
		}
	}
if(len == 22)
	{
	if(memcmp(wifi4g, linein, 18) == 0)
		{
		return 0;
		}
	}

return len;
}
/*===========================================================================*/
static int handlehex(int len, char *line)
{
static char *token = "$HEX[";

if(len >= 6)
	{
	if((memcmp(line, token, 5) == 0) && (line[len -1] == ']'))
		{
		return 0;
		}
	}
return len;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
static char *ptr;

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
static int fgetline(FILE *fh_in, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(fh_in))
	return -1;
buffptr = fgets (buffer, size, fh_in);
if(buffptr == NULL)
	return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static void processwordlist(char *wordlistinname, FILE *fh_out)
{
static int len;
static FILE *fh_in;

static char linein[LINEIN_MAX];

if((fh_in = fopen(wordlistinname, "r")) == NULL)
	{
	fprintf(stderr, "opening wordlist failed %s\n", wordlistinname);
	return;
	}

while(1)
	{
	if((len = fgetline(fh_in, LINEIN_MAX, linein)) == -1)
		{
		break;
		}
	if((len < 8) || (len > 70))
		{
		continue;
		}
	if(handlehex(len, linein) == 0)
		{
		continue;
		}
	if(wantstraight == true)
		{
		if(handleignore(len, linein) != 0)
			{
			handlestraight(fh_out, len, linein);
			}
		}
	if(wantdigit == true)
		{
		handledigit(fh_out, len, linein);
		}
	if(wantxdigit == true)
		{
		handlexdigit(fh_out, len, linein);
		}
	}
fclose(fh_in);
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
	"-i        : input wordlist\n"
	"-o <file> : output wordlist to file\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--straight       : output format untouched\n"
	"--digit          : output format only digits\n"
	"--xdigit         : output format only xdigits\n"
	"--lower          : output format only lower\n"
	"--upper          : output format only upper\n"
	"--capital        : output format only capital\n"
	"--length=<digit> : password length (8...32)\n"
	"--help           : show this help\n"
	"--version        : show version\n"
	"\n"
	"examples:\n"
	"hcxwltool -i wordlist --straight | sort | uniq |  | sort | uniq | hashcat -m 2500 hashfile.hccapx\n"
	"hcxwltool -i wordlist --digit --length=10 | sort | uniq |  | sort | uniq | hashcat -m 2500 hashfile.hccapx\n"
	"hcxwltool -i wordlist --digit | sort | uniq | hashcat -m 16800 hashfile.16800\n"
	"hcxwltool -i wordlist --xdigit | sort | uniq | john --stdin --format=wpapsk-opencl hashfile.16800\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
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
static FILE *fh_out;

static char *wordlistinname = NULL;
static char *wordlistoutname = NULL;

static const char *short_options = "i:o:hv";
static const struct option long_options[] =
{
	{"straight",			no_argument,		NULL,	HCX_STRAIGHT},
	{"digit",			no_argument,		NULL,	HCX_DIGIT},
	{"xdigit",			no_argument,		NULL,	HCX_XDIGIT},
	{"lower",			no_argument,		NULL,	HCX_LOWER},
	{"upper",			no_argument,		NULL,	HCX_UPPER},
	{"capital",			no_argument,		NULL,	HCX_CAPITAL},
	{"length",			required_argument,	NULL,	HCX_SWEEP_LEN},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

wantstraight = false;
wantdigit = false;
wantxdigit = false;
wantlower = false;
wantupper = false;
wantcapital = false;
sweeplen = 0;

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_INPUT_WORDLIST:
		wordlistinname = optarg;
		break;

		case HCX_OUTPUT_WORDLIST:
		wordlistoutname = optarg;
		break;

		case HCX_STRAIGHT:
		wantstraight = true;
		break;

		case HCX_DIGIT:
		wantdigit = true;
		break;

		case HCX_XDIGIT:
		wantxdigit = true;
		break;

		case HCX_LOWER:
		wantlower = true;
		break;

		case HCX_UPPER:
		wantupper = true;
		break;

		case HCX_CAPITAL:
		wantcapital = true;
		break;

		case HCX_SWEEP_LEN:
		sweeplen = strtol(optarg, NULL, 10);
		if((sweeplen < 8) || (sweeplen > 32))
			{
			fprintf(stderr, "only 8...32 alowed\n");
			exit(EXIT_FAILURE);
			}
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

if(wordlistoutname != 0)
	{
	if((fh_out = fopen(wordlistoutname, "w")) == NULL)
		{
		perror("failed to open output file");
		exit(EXIT_FAILURE);
		}
	}
else
	{
	fh_out = stdout;
	}

if(wordlistinname != NULL)
	{
	processwordlist(wordlistinname, fh_out);
	}

if(wordlistoutname != 0)
	{
	fclose(fh_out);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

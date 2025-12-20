#define _GNU_SOURCE
#include <ctype.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <pthread.h>

#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

/*===========================================================================*/
#define INPUTLINEMAX	1024
#define PSKMAX		134
#define MICMAX		32
/*===========================================================================*/
typedef struct
{
 char		mic[MICMAX + 2];
 char		psk[PSKMAX + 2];
} miclist_t;
#define MICLIST_SIZE (sizeof(miclist_t))

static int sort_miclist(const void *a, const void *b)
{
int cmp;
const miclist_t *ia = (const miclist_t *)a;
const miclist_t *ib = (const miclist_t *)b;

cmp = memcmp(ia->mic, ib->mic, MICMAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
return 0;
}
/*---------------------------------------------------------------------------*/
typedef struct
{
 long int	hchptr;
 char		mic[MICMAX + 2];
} hashlist_t;
#define HASHLIST_SIZE (sizeof(hashlist_t))

static int sort_hashlist(const void *a, const void *b)
{
int cmp;
const hashlist_t *ia = (const hashlist_t *)a;
const hashlist_t *ib = (const hashlist_t *)b;

cmp = memcmp(ia->mic, ib->mic, MICMAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
return 0;
}
/*===========================================================================*/
static int hcocount;
static int hchcount;
static int hchcount2;
static miclist_t *miclist;
static hashlist_t *hashlist;
/*===========================================================================*/
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer + len - 1;
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
/*===========================================================================*/
static void makehmlists(FILE *hch)
{
static int i1;
static int i2;
static int len;

static char linein[INPUTLINEMAX];

hchcount2 = 0;
for(i1 = 0; i1 < hcocount; i1++)
	{
	for(i2 = hchcount2; i2 < hchcount; i2++)
		{
		if(memcmp((miclist + i1)->mic, (hashlist + i2)->mic, MICMAX) > 0)
			{
			continue;
			}
		else if(memcmp((miclist + i1)->mic, (hashlist + i2)->mic, MICMAX) < 0)
			{
			hchcount2 = i2;
			break;
			}
		else
			{
			fseek(hch, (hashlist + i2)->hchptr, SEEK_SET);
			if((len = fgetline(hch, INPUTLINEMAX, linein)) == -1) break;
			hchcount2 = i2 + 1;
			fprintf(stdout, "%s:%s\n", linein, (miclist + i1)->psk);
			break;
			}
		}
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n"
		"usage:  %s hashcat.22000(outfile) hashcat.22000(hashfile) > hashmob.22000(HEX:PLAIN file)\n"
		"output: HEX:PLAIN (22000) piped to stdout and accepted by https://hashmob.net/submit\n"
		, eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int len;
static int i;
static int it;
static int ic;
static char *pskptr = NULL;
static FILE *hco = NULL;
static FILE *hch = NULL;
static const char wpa[] = { "WPA*" };
static const char wpa01[] = { "WPA*01*" };
static const char wpa02[] = { "WPA*02*" };

static char linein[INPUTLINEMAX];

setbuf(stdout, NULL);
if (argc != 3)
	{
	version(basename(argv[0]));
	}

if((hco = fopen(argv[1], "rb")) == NULL)
	{
	fprintf(stderr, "failed to open hashcat out file %s\n", argv[1]);
	goto exit1;
	}
i = 0;
while(1)
	{
	if((len = fgetline(hco, INPUTLINEMAX, linein)) == -1) break;
	i++;
	}
fseek(hco, 0L, SEEK_SET);
if(i == 0) goto exit1;
if((miclist = (miclist_t*)calloc(i + 1, MICLIST_SIZE)) == NULL) goto exit1;
i = 0;
while(1)
	{
	if((len = fgetline(hco, INPUTLINEMAX, linein)) == -1) break;
	if(len < 70) continue;
	if(linein[32] != ':') continue;
	if(linein[45] != ':') continue;
	if(linein[58] != ':') continue;
	memcpy((miclist + i)->mic, linein, MICMAX);
	pskptr = strrchr(linein, ':');
	if(pskptr == NULL) continue;
	if(pskptr[1] == 0) continue;
	strncpy((miclist + i)->psk, &pskptr[1], PSKMAX);
	i++;
	}
hcocount = i;
qsort(miclist, i, MICLIST_SIZE, sort_miclist);
if((hch = fopen(argv[2], "rb")) == NULL)
	{
	fprintf(stderr, "failed to open hashcat hash file %s\n", argv[2]);
	goto exit1;
	}
i = 0;
while(1)
	{
	if((len = fgetline(hch, INPUTLINEMAX, linein)) == -1) break;
	i++;
	}
fseek(hch, 0L, SEEK_SET);
if(i == 0) goto exit1;
if((hashlist = (hashlist_t*)calloc(i + 1, HASHLIST_SIZE)) == NULL) goto exit1;
i = 0;
while(1)
	{
	(hashlist + i)->hchptr = ftell(hch);
	if((len = fgetline(hch, INPUTLINEMAX, linein)) == -1) break;
	if(len < 70) continue;
	if(linein[3] != '*') continue;
	if(linein[6] != '*') continue;
	if(linein[39] != '*') continue;
	if(linein[52] != '*') continue;
	if(linein[65] != '*') continue;
	if(linein[len -3] != '*') continue;
	if(strstr(&linein[3], wpa) != NULL) continue;
	if((memcmp(linein, wpa01, 7) != 0) && (memcmp(linein, wpa02, 7) != 0)) continue;
	ic = 0;
	for(it = 0; it < len; it++)
		{
		if(linein[ic]	== '*') ic ++;
		}
	if(ic > 8) continue;
	memcpy((hashlist + i)->mic, &linein[7], MICMAX);
	i++;
	}
hchcount = i;
qsort(hashlist, i, HASHLIST_SIZE, sort_hashlist);
makehmlists(hch);
exit1:
if(hashlist != NULL) free(hashlist);
if(miclist != NULL) free(miclist);
if(hch != NULL) fclose(hch);
if(hco != NULL) fclose(hco);
return EXIT_SUCCESS;
}

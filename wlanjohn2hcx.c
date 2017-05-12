#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <pcap.h>
#include <sys/stat.h>
#include <stdio_ext.h>
#include "common.h"

#define LINEBUFFER 1024

struct hccap
{
  char essid[36];
  unsigned char mac1[6];	/* bssid */
  unsigned char mac2[6];	/* client */
  unsigned char nonce1[32];	/* snonce client */
  unsigned char nonce2[32];	/* anonce bssid */
  unsigned char eapol[256];
  int eapol_size;
  int keyver;
  unsigned char keymic[16];
};
typedef struct hccap hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))

/*===========================================================================*/
/* globale Variablen */

char *hcxoutname = NULL;
/*===========================================================================*/
size_t chop(char *buffer,  size_t len)
{
char *ptr = buffer +len -1;

while (len) {
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}

while (len) {
	if (*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
int fgetline(FILE *inputstream, size_t size, char *buffer)
{
if (feof(inputstream)) return -1;
		char *buffptr = fgets (buffer, size, inputstream);

	if (buffptr == NULL) return -1;

	size_t len = strlen(buffptr);
	len = chop(buffptr, len);

return len;
}
/*===========================================================================*/
int processjohn(char *johninname)
{
int len;
int johnlen;
FILE* fhjohn;

char *wpapsk = "$WPAPSK$";
char *johndata;
char linein[LINEBUFFER];


if ((fhjohn = fopen(johninname, "r")) == NULL)
	{
	fprintf(stderr, "unable to open john file %s\n", johninname);
	exit (EXIT_FAILURE);
	}

while((len = fgetline(fhjohn, LINEBUFFER, linein)) != -1)
	{
	if(len == 0)
		continue;

	if(strstr(linein, wpapsk) == NULL)
		continue;

	johndata = strrchr(linein, '#');
	if(johndata == NULL)
		continue;

	johndata++;
	johnlen = 0;
	while(johndata < linein + len)
		{
//		if (atoi64[ARCH_INDEX(*hash++)] == 0x7f)
//			continue;
		johnlen++;
	}
	if (johnlen != 475)
		continue;


	
	fprintf(stdout, "%s\n", johndata);
	}
fclose(fhjohn);
return TRUE;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.john] [input.john] ...\n"
	"\n"
	"options:\n"
	"-o <file> : output hccapx file\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int index;
int auswahl;

char *eigenname = NULL;
char *eigenpfadname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "o:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'o':
		hcxoutname = optarg;
		break;

		default:
		usage(eigenname);
		break;
		}
	}

for (index = optind; index < argc; index++)
	{
	if(processjohn(argv[index]) == FALSE)
		{
		fprintf(stderr, "error processing records from %s\n", (argv[index]));
		exit(EXIT_FAILURE);
		}
	}


return EXIT_SUCCESS;
}

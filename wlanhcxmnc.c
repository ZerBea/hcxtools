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

/*===========================================================================*/
/* globale Variablen */

hcx_t *hcxdata = NULL;
/*===========================================================================*/
int writecorrhccapx(long int hcxrecords, int corrbyte, char *hcxoutname)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
eap_t *eap;
long int c;
int cb;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
		{
		if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", hcxoutname);
			return FALSE;
			}
		eap = (eap_t*)zeigerhcx->eapol;

		if(memcmp(zeigerhcx->nonce_ap, eap->nonce, 32) != 0)
			{
			for(cb = 0; cb <= 0x0ff; cb++)
				{
				zeigerhcx->nonce_ap[corrbyte] = cb;
				fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
				}
			}
		else
			{
			for(cb = 0; cb <= 0x0ff; cb++)
				{
				zeigerhcx->nonce_sta[corrbyte] = cb;
				fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
				}
			}
		fclose(fhhcx);
		}
	c++;
	}
return TRUE;
}
/*===========================================================================*/
int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return FALSE;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return FALSE;
	}

if((statinfo.st_size % HCX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return FALSE;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxinname);
	return FALSE;
	}

hcxdata = malloc(statinfo.st_size);
if(hcxdata == NULL)	
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		return FALSE;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
if(hcxsize != statinfo.st_size)	
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return FALSE;
	}
fclose(fhhcx);

printf("%ld records readed from %s\n", hcxsize / HCX_SIZE, hcxinname);
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-c <byte  : byte to correct (0 -> 31)\n"
	"-o <file> : input hccapx file\n"
	"-h           : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
long int hcxorgrecords = 0;
int corrbyte = -1;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *hcxoutname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:c:o:h")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'c':
		corrbyte = atol(optarg);
		if((corrbyte < 0) || (corrbyte > 31))
			{
			fprintf(stderr, "error wrong value (only 0 > 31 allowed)\n");
			exit(EXIT_FAILURE);
			}
		corrbyte = atol(optarg);
		break;

		case 'o':
		hcxoutname = optarg;
		break;

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

printf("%d\n", corrbyte);
hcxorgrecords = readhccapx(hcxinname);
if(hcxorgrecords == 0)
	return EXIT_SUCCESS;

if((corrbyte >= 0) && (corrbyte <= 31))
	writecorrhccapx(hcxorgrecords, corrbyte, hcxoutname);

if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

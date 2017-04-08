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
int writesearchessidhccapx(int hcxrecords, char *essidname)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
int essid_len;

char essidoutname[PATH_MAX +1];

essid_len = strlen(essidname);
snprintf(essidoutname, PATH_MAX, "%s.hccapx", essidname);
c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(essidname, zeigerhcx->essid, essid_len) == 0)
		{
		if((fhhcx = fopen(essidoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", essidoutname);
			return FALSE;
			}
		fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
		fclose(fhhcx);
		}
	c++;
	}
return TRUE;
}
/*===========================================================================*/
int writeessidhccapx(int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
int cei, ceo;

const char digit[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

char hcxoutname[PATH_MAX +1];


c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	ceo = 0;
	for (cei = 0; cei < zeigerhcx->essid_len; cei++)
		{
		hcxoutname[ceo] = digit[(zeigerhcx->essid[cei] & 0xff) >> 4];
		ceo++;
		hcxoutname[ceo] = digit[zeigerhcx->essid[cei] & 0x0f];
		ceo++;
		}
	hcxoutname[ceo] = 0;
	strcat(&hcxoutname[ceo], ".hccapx");
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", hcxoutname);
		return FALSE;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	c++;
	}
return TRUE;
}
/*===========================================================================*/
void mac2hxoutname(char ssid[13], unsigned char *p)
{
sprintf(ssid, "%02x%02x%02x%02x%02x%02x.hccapx",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
int writemachccapx(int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;

char hcxoutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	mac2hxoutname(hcxoutname, zeigerhcx->mac_ap.addr);
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening file %s", hcxoutname);
		return FALSE;
		}
	fwrite(zeigerhcx, HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	c++;
	}
return TRUE;
}
/*===========================================================================*/
int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
int hcxsize = 0;

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
	"-i <file>  : input hccapx file\n"
	"-a         : output file by mac_ap\n"
	"-e         : output file by essid\n"
	"-E <essid> : output file by single essid name\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int mode = 0;
int hcxorgrecords = 0;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *essidname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:E:aehv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'a':
		mode = 'a';
		break;

		case 'e':
		mode = 'e';
		break;

		case 'E':
		essidname = optarg;
		break;

		default:
		usage(eigenname);
		break;
		}
	}

hcxorgrecords = readhccapx(hcxinname);
if(hcxorgrecords == 0)
	return EXIT_SUCCESS;

if(mode == 'a')
	writemachccapx(hcxorgrecords);

else if(mode == 'e')
	writeessidhccapx(hcxorgrecords);

else if(essidname != NULL)
	writesearchessidhccapx(hcxorgrecords, essidname);

if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

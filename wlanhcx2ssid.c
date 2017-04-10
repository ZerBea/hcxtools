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
int writesearchmacstahccapx(long int hcxrecords, unsigned long long int mac_sta)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
adr_t mac;

char macoutname[PATH_MAX +1];

snprintf(macoutname, PATH_MAX, "%012llx.hccapx", mac_sta);

mac.addr[5] = mac_sta & 0xff;
mac.addr[4] = (mac_sta >> 8) & 0xff;
mac.addr[3] = (mac_sta >> 16) & 0xff;
mac.addr[2] = (mac_sta >> 24) & 0xff;
mac.addr[1] = (mac_sta >> 32) & 0xff;
mac.addr[0] = (mac_sta >> 40) & 0xff;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_sta.addr, 6) == 0)
		{
		if((fhhcx = fopen(macoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", macoutname);
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
int writesearchmacaphccapx(long int hcxrecords, unsigned long long int mac_ap)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;
adr_t mac;

char macoutname[PATH_MAX +1];

snprintf(macoutname, PATH_MAX, "%012llx.hccapx", mac_ap);

mac.addr[5] = mac_ap & 0xff;
mac.addr[4] = (mac_ap >> 8) & 0xff;
mac.addr[3] = (mac_ap >> 16) & 0xff;
mac.addr[2] = (mac_ap >> 24) & 0xff;
mac.addr[1] = (mac_ap >> 32) & 0xff;
mac.addr[0] = (mac_ap >> 40) & 0xff;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	if(memcmp(&mac.addr, zeigerhcx->mac_ap.addr, 6) == 0)
		{
		if((fhhcx = fopen(macoutname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening file %s", macoutname);
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
int writesearchessidhccapx(long int hcxrecords, char *essidname)
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
int writeessidhccapx(long int hcxrecords)
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
int writemacstahccapx(long int hcxrecords)
{
hcx_t *zeigerhcx;
FILE *fhhcx;
long int c;

char hcxoutname[PATH_MAX +1];

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	mac2hxoutname(hcxoutname, zeigerhcx->mac_sta.addr);
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
int writemacaphccapx(long int hcxrecords)
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
	"-i <file>    : input hccapx file\n"
	"-a           : output file by mac_ap's\n"
	"-s           : output file by mac_sta's\n"
	"-e           : output file by essid's\n"
	"-E <essid>   : output file by single essid name\n"
	"-A <mac_ap>  : output file by single mac_ap\n"
	"-S <mac_sta> : output file by single mac_sta\n"

	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int mode = 0;
long int hcxorgrecords = 0;
unsigned long long int mac_ap = 0;
unsigned long long int mac_sta = 0;
char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *essidname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:A:S:E:asehv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'a':
		mode = 'a';
		break;

		case 's':
		mode = 's';
		break;

		case 'e':
		mode = 'e';
		break;

		case 'E':
		essidname = optarg;
		break;

		case 'A':
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "error wrong mac size %s (need 112233aabbcc)\n", optarg);
			exit(EXIT_FAILURE);
			}
		mac_ap = strtoul(optarg, NULL, 16);
		mode = 'A';
		break;

		case 'S':
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "error wrong mac size %s (need 112233aabbcc)\n", optarg);
			exit(EXIT_FAILURE);
			}
		mac_sta = strtoul(optarg, NULL, 16);
		mode = 'S';
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
	writemacaphccapx(hcxorgrecords);

else if(mode == 's')
	writemacstahccapx(hcxorgrecords);

else if(mode == 'e')
	writeessidhccapx(hcxorgrecords);


else if(mode == 'A')
	writesearchmacaphccapx(hcxorgrecords, mac_ap);

else if(mode == 'S')
	writesearchmacstahccapx(hcxorgrecords, mac_sta);

else if(essidname != NULL)
	writesearchessidhccapx(hcxorgrecords, essidname);

if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <time.h>

#include "fileops.h"
/*===========================================================================*/
int getmagicnumber(int fd)
{
int res;
magicnr_t mnr;

res = read(fd, &mnr, 4);
if(res != 4) return 0;
return mnr.magic_number;
}
/*===========================================================================*/
void fwritetimestamphigh(uint32_t tshigh, FILE *fhd)
{
time_t pkttime;
struct tm *pkttm;

char tmbuf[64];

if(tshigh != 0)
	{
	pkttime = tshigh;
	pkttm = localtime(&pkttime);
	strftime(tmbuf, sizeof tmbuf, "%d%m%Y", pkttm);
	fprintf(fhd, "%s:", tmbuf);
	}
else fprintf(fhd, "00000000:");
return;
}
/*===========================================================================*/
void fwriteaddr1(uint8_t *macw, FILE *fhd)
{
int p;

for(p = 0; p< 6; p++) fprintf(fhd, "%02x", macw[p]);
fprintf(fhd, ":");
return;
}
/*===========================================================================*/
void fwriteaddr1addr2(uint8_t *mac1, uint8_t *mac2, FILE *fhd)
{
fwriteaddr1(mac1, fhd);
fwriteaddr1(mac2, fhd);
return;
}
/*===========================================================================*/
void fwriteessidstrnoret(uint8_t len, unsigned char *essidstr, FILE *fhd)
{
int p;

if(isasciistring(len, essidstr) != false) fprintf(fhd, "%.*s\n", len, essidstr);
else
	{
	fprintf(fhd, "$HEX[");
	for(p = 0; p < len; p++) fprintf(fhd, "%02x", essidstr[p]);
	fprintf(fhd, "]:");
	}
return;
}
/*===========================================================================*/
void fwriteessidstr(uint8_t len, unsigned char *essidstr, FILE *fhd)
{
int p;

if((len == 0) || (len > ESSID_LEN_MAX)) return;
if(essidstr[0] == 0) return;
if(isasciistring(len, essidstr) != false) fprintf(fhd, "%.*s\n", len, essidstr);
else
	{
	fprintf(fhd, "$HEX[");
	for(p = 0; p < len; p++) fprintf(fhd, "%02x", essidstr[p]);
	fprintf(fhd, "]\n");
	}
return;
}
/*===========================================================================*/
void fwritedeviceinfostr(uint8_t len, unsigned char *deviceinfostr, FILE *fhd)
{
int p;

fprintf(fhd, "\t");
if(deviceinfostr[0] == 0) return;
if(isasciistring(len, deviceinfostr) != false) fprintf(fhd, "%.*s", len, deviceinfostr);
else
	{
	fprintf(fhd, "$HEX[");
	for(p = 0; p < len; p++) fprintf(fhd, "%02x", deviceinfostr[p]);
	fprintf(fhd, "]");
	}
return;
}
/*===========================================================================*/
void fwritestring(uint8_t len, unsigned char *essidstr, FILE *fhd)
{
int p;

if(isasciistring(len, essidstr) != false) fprintf(fhd, "%.*s\n", len, essidstr);
else
	{
	fprintf(fhd, "$HEX[");
	for(p = 0; p < len; p++) fprintf(fhd, "%02x", essidstr[p]);
	fprintf(fhd, "]\n");
	}
return;
}
/*===========================================================================*/
void fwritehexbuffraw(uint8_t bufflen, uint8_t *buff, FILE *fhd)
{
int p;

for(p = 0; p < bufflen; p++) fprintf(fhd, "%02x", buff[p]);
return;
}
/*===========================================================================*/
void fwritehexbuff(uint8_t bufflen, uint8_t *buff, FILE *fhd)
{
int p;

for(p = 0; p < bufflen; p++) fprintf(fhd, "%02x", buff[p]);
fprintf(fhd, "\n");
return;
}
/*===========================================================================*/
void removeemptyfile(char *filenametoremove)
{
struct stat statinfo;

if(filenametoremove == NULL) return;
if(stat(filenametoremove, &statinfo) != 0) return;
if(statinfo.st_size == 0)
	{
	remove(filenametoremove);
	return;
	}
return;
}
/*===========================================================================*/
static size_t chop(char *buffer,  size_t len)
{
static char *ptr;

ptr = buffer +len -1;
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

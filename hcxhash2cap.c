#define _GNU_SOURCE
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
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#if defined (__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/hcxhash2cap.h"
#include "include/hashcatops.h"
#include "include/pcap.c"
#include "include/ieee80211.c"
#include "include/strings.c"
#include "include/version.h"

/*===========================================================================*/
/* global var */

struct timeval tv;
static uint64_t timestamp;

static int mybeaconsequence;
static int myaponlinetime;
static uint8_t myapchannel;
static unsigned long long int pmkcapwritten;
/*===========================================================================*/
static void writecappmkidwpa2(int fd_cap, uint8_t *macap, uint8_t *macsta, uint8_t *pmkid)
{
static int c;
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static const uint8_t pmkiddata[] =
{
0x88, 0x02, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x03, 0x00, 0x75, 0x02,
0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xed, 0x57, 0x5c, 0x4b, 0xca, 0xa7, 0x7a, 0xf1, 0x9e, 0x32, 0x94, 0x32, 0x63, 0x91, 0xad, 0x7d,
0x9c, 0xbc, 0x6a, 0xb4, 0xad, 0x04, 0xf1, 0x23, 0x80, 0xb4, 0x44, 0xbe, 0xb5, 0x8d, 0x2a, 0xdd,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x16,
0xdd, 0x14, 0x00, 0x0f, 0xac, 0x04,
0x7e, 0xf1, 0x33, 0x3c, 0xb6, 0xf9, 0x03, 0x73, 0xfc, 0x2a, 0xc7, 0x59, 0x37, 0xfd, 0x24, 0x3a
};
#define PMKIDDATA_SIZE sizeof(pmkiddata)

static uint8_t packetout[0xff];

memset(&packetout, 0, 0xff);
pcaph = (pcaprec_hdr_t*)packetout;
pcaph->ts_sec = timestamp /1000000;
pcaph->ts_usec = timestamp %1000000;
pcaph->incl_len = PMKIDDATA_SIZE;
pcaph->orig_len = pcaph->incl_len;
timestamp++;

memcpy(&packetout[PCAPREC_SIZE], &pmkiddata, PMKIDDATA_SIZE);
mach = (mac_t*)(packetout +PCAPREC_SIZE);
memcpy(mach->addr1, macsta, 6);
memcpy(mach->addr2, macap, 6);
memcpy(mach->addr3, macap, 6);

for(c = 0; c < 32; c++)
	{
	packetout[PCAPREC_SIZE +0x33 +c] = rand() %0xff;
	}
memcpy(&packetout[PCAPREC_SIZE +0x8b], pmkid, 16);

if(write(fd_cap, packetout, PCAPREC_SIZE +PMKIDDATA_SIZE) < 0)
	{
	perror("\nfailed to write beacon packet");
	}
return;
}
/*===========================================================================*/
static void writecapbeaconwpa2(int fd_cap, uint8_t *macap, uint8_t essidlen, uint8_t *essid)
{
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static capap_t *capap;

static const uint8_t beacondata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x06,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x0c, 0x00
};
#define BEACONDATA_SIZE sizeof(beacondata)

static uint8_t packetout[0xff];

memset(&packetout, 0, 0xff);
pcaph = (pcaprec_hdr_t*)packetout;
pcaph->ts_sec = timestamp /1000000;
pcaph->ts_usec = timestamp %1000000;
pcaph->incl_len = MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essidlen +BEACONDATA_SIZE;
pcaph->orig_len = pcaph->incl_len;
timestamp++;

mach = (mac_t*)(packetout +PCAPREC_SIZE);
mach->type = IEEE80211_FTYPE_MGMT;
mach->subtype = IEEE80211_STYPE_BEACON;
memcpy(mach->addr1, &mac_broadcast, 6);
memcpy(mach->addr2, macap, 6);
memcpy(mach->addr3, macap, 6);
mach->sequence = mybeaconsequence++ << 4;
if(mybeaconsequence >= 4096)
	{
	mybeaconsequence = 0;
	}

capap = (capap_t*)(packetout +PCAPREC_SIZE +MAC_SIZE_NORM);
capap->timestamp = myaponlinetime++;
capap->beaconintervall = 0x64;
capap->capabilities = 0x431;

packetout[PCAPREC_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = essidlen;
memcpy(&packetout[PCAPREC_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2], essid, essidlen);
memcpy(&packetout[PCAPREC_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essidlen], &beacondata, BEACONDATA_SIZE);
packetout[PCAPREC_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essidlen +0x0c] = myapchannel;
if(write(fd_cap, packetout, PCAPREC_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +essidlen +BEACONDATA_SIZE) < 0)
	{
	perror("\nfailed to write beacon packet");
	}
return;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
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
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

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
static inline void processpmkidfile(char *pmkidname, int fd_cap)
{
static int len;
static int aktread = 1;
static int essidlen;
static int fd_singlecap;
static FILE *fh_file;

static char linein[PMKID_LINE_LEN];
static uint8_t macap[6];
static uint8_t macsta[6];
static uint8_t pmkid[16];
static uint8_t essid[ESSID_LEN_MAX];

static char singlecapname[PATH_MAX +2];

if((fh_file = fopen(pmkidname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", pmkidname);
	return;
	}

while(1)
	{
	if((len = fgetline(fh_file, PMKID_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if((len < 61) || ((len > 59 +(ESSID_LEN_MAX *2))))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((linein[32] != '*') && (linein[45] != '*') && (linein[58] != '*'))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	essidlen = len -59;
	if((essidlen %2) != 0)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((essidlen < 2) ||  (essidlen > 64))
		{
		fprintf(stderr, "reading ESSID %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if(hex2bin(&linein[0], pmkid, 16) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		continue;
		}

	if(hex2bin(&linein[33], macap, 6) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		continue;
		}

	if(hex2bin(&linein[46], macsta, 6) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		continue;
		}

	if(hex2bin(&linein[59], essid, essidlen/2) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		continue;
		}
	if(fd_cap == 0)
		{
		snprintf(singlecapname, 18, "%02x%02x%02x%02x%02x%02x.cap", macsta[0], macsta[1], macsta[2], macsta[3], macsta[4], macsta[5]);
		fd_singlecap = hcxopencapdump(singlecapname);
		if(fd_singlecap == -1)
			{
			fprintf(stderr, "could not create cap file\n");
			exit(EXIT_FAILURE);
			}
		writecapbeaconwpa2(fd_singlecap, macap, essidlen /2, essid);
		writecappmkidwpa2(fd_singlecap, macap, macsta, pmkid);
		pmkcapwritten++;
		close(fd_singlecap);
		}
	else
		{
		writecapbeaconwpa2(fd_cap, macap, essidlen /2, essid);
		writecappmkidwpa2(fd_cap, macap, macsta, pmkid);
		pmkcapwritten++;
		}
	aktread++;
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
static inline void processhccapxfile(char *hccapxname, int fd_cap)
{
static struct stat statinfo;
static hccapx_t *hcxptr;
static int fd_singlecap;
static FILE *fhhcx;

static uint8_t hcxdata[HCCAPX_SIZE];
static char singlecapname[PATH_MAX +2];

if(stat(hccapxname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hccapxname);
	return;
	}

if((statinfo.st_size %HCCAPX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return;
	}

if((fhhcx = fopen(hccapxname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapxname);
	return;
	}

hcxptr = (hccapx_t*)hcxdata;
while(fread(&hcxdata, HCCAPX_SIZE, 1, fhhcx) == 1)
	{
	if(hcxptr->signature != HCCAPX_SIGNATURE)
		{
		continue;
		}
	if((hcxptr->version != 3) && (hcxptr->version != 4))
		{
		continue;
		}
	if((hcxptr->essid_len == 0) || (hcxptr->essid_len > ESSID_LEN_MAX))
		{
		continue;
		}
	if(fd_cap == 0)
		{
		snprintf(singlecapname, 18, "%02x%02x%02x%02x%02x%02x.cap", hcxptr->mac_sta[0], hcxptr->mac_sta[1], hcxptr->mac_sta[2], hcxptr->mac_sta[3], hcxptr->mac_sta[4], hcxptr->mac_sta[5]);
		fd_singlecap = hcxopencapdump(singlecapname);
		if(fd_singlecap == -1)
			{
			fprintf(stderr, "could not create cap file\n");
			exit(EXIT_FAILURE);
			}
		writecapbeaconwpa2(fd_singlecap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);

		close(fd_singlecap);
		}
	else
		{
		writecapbeaconwpa2(fd_cap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);

		}
	}
fclose(fhhcx);
return;
}
/*===========================================================================*/
static void removeemptycap(char *filenametoremove)
{
struct stat statinfo;

if(filenametoremove == NULL)
	{
	return;
	}
if(stat(filenametoremove, &statinfo) != 0)
	{
	return;
	}
if(statinfo.st_size == 24)
	{
	remove(filenametoremove);
	return;
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-c <file> : output cap file\n"
	"            if no cap file is selected, output will be written to single cap files\n"
	"            format: mac_sta.cap (mac_sta.cap_x)\n"
	"\n"
	"--pmkid=<file>  : input PMKID hash file\n"
	"--help          : show this help\n"
	"--version       : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
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
static int fd_cap = 0;
static char *hccapxname = NULL;
static char *pmkidname = NULL;
static char *capname = NULL;

static const char *short_options = "c:hv";
static const struct option long_options[] =
{
	{"pmkid",			required_argument,	NULL,	HCXP_PMKID},
	{"version",			no_argument,		NULL,	HCXP_VERSION},
	{"help",			no_argument,		NULL,	HCXP_HELP},
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
		case HCXP_HCCAPX:
		hccapxname = optarg;
		break;

		case HCXP_PMKID:
		pmkidname = optarg;
		break;

		case HCXP_CAP:
		capname = optarg;
		break;

		case HCXP_HELP:
		usage(basename(argv[0]));
		break;

		case HCXP_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

srand(time(NULL));
gettimeofday(&tv, NULL);
timestamp = (tv.tv_sec * 1000000) + tv.tv_usec;
mybeaconsequence = rand() %4096;
myaponlinetime = rand();
myapchannel = (rand() %12) +1;
pmkcapwritten = 0;

if(capname != NULL)
	{
	fd_cap = hcxopencapdump(capname);
	if(fd_cap == -1)
		{
		fprintf(stderr, "could not create cap file\n");
		exit(EXIT_FAILURE);
		}
	}

if(pmkidname != NULL)
	{
	processpmkidfile(pmkidname, fd_cap);
	}

if(hccapxname != NULL)
	{
	fprintf(stdout, "not implemented, yet\n");
//	processhccapxfile(hccapxname, fd_cap);
	}

if(fd_cap != 0)
	{
	close(fd_cap);
	removeemptycap(capname);
	}

if(pmkcapwritten > 0)
	{
	fprintf(stdout, "PMKIDs written to capfile(s): %llu\n", pmkcapwritten);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

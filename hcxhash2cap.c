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
#include <netinet/in.h>
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
#include "include/byteops.c"
#include "include/version.h"

#define ARCH_INDEX(x)	((unsigned int)(unsigned char)(x))

/*===========================================================================*/
/* global var */

struct timeval tv;
static uint64_t timestamp;

static int mybeaconsequence;
static int myaponlinetime;
static uint8_t myapchannel;
static unsigned long long int pmkcapwritten;
static unsigned long long int pmkcapskipped;
static unsigned long long int hccapxcapwritten;
static unsigned long long int hccapxcapskipped;
static unsigned long long int hccapcapwritten;
static unsigned long long int hccapcapskipped;
static unsigned long long int johnwritten;
static unsigned long long int johnskipped;

/*===========================================================================*/
static void globalinit()
{

srand(time(NULL));
gettimeofday(&tv, NULL);
timestamp = ((uint64_t)tv.tv_sec * 1000000) + tv.tv_usec;
mybeaconsequence = rand() %4096;
myaponlinetime = rand();
myapchannel = (rand() %12) +1;
pmkcapwritten = 0;
pmkcapskipped = 0;
hccapxcapwritten = 0;
hccapxcapskipped = 0;
hccapcapwritten = 0;
hccapcapskipped = 0;
johnwritten = 0;
johnskipped = 0;
}
/*===========================================================================*/
static void writecapm1wpa1(int fd_cap, uint8_t *macsta, uint8_t *macap, uint8_t *anonce, uint8_t keyversion, uint16_t keylen, uint64_t rc)
{
static int c;
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static wpakey_t *wpak;

static const uint8_t m1wpa1data[] =
{
0x88, 0x02, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x03, 0x00, 0x5f, 0xfe,
0x00, 0x89, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xed, 0x57, 0x5c, 0x4b, 0xca, 0xa7, 0x7a, 0xf1, 0x9e, 0x32, 0x94, 0x32, 0x63, 0x91, 0xad, 0x7d,
0x9c, 0xbc, 0x6a, 0xb4, 0xad, 0x04, 0xf1, 0x23, 0x80, 0xb4, 0x44, 0xbe, 0xb5, 0x8d, 0x2a, 0xdd,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00,
};
#define M1WPA1DATA_SIZE sizeof(m1wpa1data)

static uint8_t packetout[0xff];

memset(&packetout, 0, 0xff);
pcaph = (pcaprec_hdr_t*)packetout;
pcaph->ts_sec = timestamp /1000000;
pcaph->ts_usec = timestamp %1000000;
pcaph->incl_len = M1WPA1DATA_SIZE;
pcaph->orig_len = pcaph->incl_len;
timestamp++;

memcpy(&packetout[PCAPREC_SIZE], &m1wpa1data, M1WPA1DATA_SIZE);
mach = (mac_t*)(packetout +PCAPREC_SIZE);
memcpy(mach->addr1, macsta, 6);
memcpy(mach->addr2, macap, 6);
memcpy(mach->addr3, macap, 6);

packetout[PCAPREC_SIZE +0x22] = keyversion;

wpak = (wpakey_t*)(packetout +PCAPREC_SIZE +0x26);
#ifdef BIG_ENDIAN_HOST
rc = byte_swap_64(rc);
#endif
wpak->keylen = keylen;
wpak->replaycount = rc;

for(c = 0; c < 32; c++)
	{
	packetout[PCAPREC_SIZE +0x33 +c] = anonce[c];
	}

if(write(fd_cap, packetout, PCAPREC_SIZE +M1WPA1DATA_SIZE) < 0)
	{
	perror("\nfailed to write beacon packet");
	}
return;
}
/*===========================================================================*/
static void writecapm1wpa2(int fd_cap, uint8_t *macsta, uint8_t *macap, uint8_t *anonce, uint8_t keyversion, uint16_t keylen, uint64_t rc)
{
static int c;
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static wpakey_t *wpak;

static const uint8_t m1wpa2data[] =
{
0x88, 0x02, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x03, 0x00, 0x5f, 0x02,
0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xed, 0x57, 0x5c, 0x4b, 0xca, 0xa7, 0x7a, 0xf1, 0x9e, 0x32, 0x94, 0x32, 0x63, 0x91, 0xad, 0x7d,
0x9c, 0xbc, 0x6a, 0xb4, 0xad, 0x04, 0xf1, 0x23, 0x80, 0xb4, 0x44, 0xbe, 0xb5, 0x8d, 0x2a, 0xdd,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00,
};
#define M1WPA2DATA_SIZE sizeof(m1wpa2data)

static uint8_t packetout[0xff];

memset(&packetout, 0, 0xff);
pcaph = (pcaprec_hdr_t*)packetout;
pcaph->ts_sec = timestamp /1000000;
pcaph->ts_usec = timestamp %1000000;
pcaph->incl_len = M1WPA2DATA_SIZE;
pcaph->orig_len = pcaph->incl_len;
timestamp++;

memcpy(&packetout[PCAPREC_SIZE], &m1wpa2data, M1WPA2DATA_SIZE);
mach = (mac_t*)(packetout +PCAPREC_SIZE);
memcpy(mach->addr1, macsta, 6);
memcpy(mach->addr2, macap, 6);
memcpy(mach->addr3, macap, 6);

packetout[PCAPREC_SIZE +0x22] = keyversion;

wpak = (wpakey_t*)(packetout +PCAPREC_SIZE +0x26);
#ifdef BIG_ENDIAN_HOST
rc = byte_swap_64(rc);
#endif
wpak->keylen = keylen;
wpak->replaycount = rc;

for(c = 0; c < 32; c++)
	{
	packetout[PCAPREC_SIZE +0x33 +c] = anonce[c];
	}

if(write(fd_cap, packetout, PCAPREC_SIZE +M1WPA2DATA_SIZE) < 0)
	{
	perror("\nfailed to write beacon packet");
	}
return;
}
/*===========================================================================*/
static void writecapm1wpa2keyver3(int fd_cap, uint8_t *macsta, uint8_t *macap, uint8_t *anonce, uint8_t keyversion, uint16_t keylen, uint64_t rc)
{
static int c;
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static wpakey_t *wpak;

static const uint8_t m1wpa2keyver3data[] =
{
0x88, 0x02, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x03, 0x00, 0x5f, 0x02,
0x00, 0x8b, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xed, 0x57, 0x5c, 0x4b, 0xca, 0xa7, 0x7a, 0xf1, 0x9e, 0x32, 0x94, 0x32, 0x63, 0x91, 0xad, 0x7d,
0x9c, 0xbc, 0x6a, 0xb4, 0xad, 0x04, 0xf1, 0x23, 0x80, 0xb4, 0x44, 0xbe, 0xb5, 0x8d, 0x2a, 0xdd,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00,
};
#define M1WPA2KEYVER3DATA_SIZE sizeof(m1wpa2keyver3data)

static uint8_t packetout[0xff];

memset(&packetout, 0, 0xff);
pcaph = (pcaprec_hdr_t*)packetout;
pcaph->ts_sec = timestamp /1000000;
pcaph->ts_usec = timestamp %1000000;
pcaph->incl_len = M1WPA2KEYVER3DATA_SIZE;
pcaph->orig_len = pcaph->incl_len;
timestamp++;

memcpy(&packetout[PCAPREC_SIZE], &m1wpa2keyver3data, M1WPA2KEYVER3DATA_SIZE);
mach = (mac_t*)(packetout +PCAPREC_SIZE);
memcpy(mach->addr1, macsta, 6);
memcpy(mach->addr2, macap, 6);
memcpy(mach->addr3, macap, 6);

packetout[PCAPREC_SIZE +0x22] = keyversion;

wpak = (wpakey_t*)(packetout +PCAPREC_SIZE +0x26);
#ifdef BIG_ENDIAN_HOST
rc = byte_swap_64(rc);
#endif
wpak->keylen = keylen;
wpak->replaycount = rc;

for(c = 0; c < 32; c++)
	{
	packetout[PCAPREC_SIZE +0x33 +c] = anonce[c];
	}

if(write(fd_cap, packetout, PCAPREC_SIZE +M1WPA2KEYVER3DATA_SIZE) < 0)
	{
	perror("\nfailed to write beacon packet");
	}
return;
}
/*===========================================================================*/
static void writecappmkidwpa2(int fd_cap, uint8_t *macsta, uint8_t *macap, uint8_t *pmkid)
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
static void writecapm2(int fd_cap, uint8_t *macsta, uint8_t *macap, uint8_t eapollen, uint8_t *eapol, uint8_t *mic)
{
static pcaprec_hdr_t *pcaph;
static mac_t *mach;

static const uint8_t m2data[] =
{
0x88, 0x01, 0x3a, 0x01,
0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
0x00, 0x00, 0x06, 0x00,
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
};
#define M2DATA_SIZE sizeof(m2data)

static uint8_t packetout[0xff];

memset(&packetout, 0, 0xff);
pcaph = (pcaprec_hdr_t*)packetout;
pcaph->ts_sec = timestamp /1000000;
pcaph->ts_usec = timestamp %1000000;
pcaph->incl_len = M2DATA_SIZE +eapollen;
pcaph->orig_len = pcaph->incl_len;
timestamp++;


memcpy(&packetout[PCAPREC_SIZE], &m2data, M2DATA_SIZE);
mach = (mac_t*)(packetout +PCAPREC_SIZE);
memcpy(mach->addr1, macap, 6);
memcpy(mach->addr2, macsta, 6);
memcpy(mach->addr3, macap, 6);
memcpy(&packetout[PCAPREC_SIZE +M2DATA_SIZE], eapol, eapollen);
memcpy(&packetout[PCAPREC_SIZE +M2DATA_SIZE +0x51], mic, 16);

if(write(fd_cap, packetout, PCAPREC_SIZE +M2DATA_SIZE +eapollen) < 0)
	{
	perror("\nfailed to write beacon packet");
	}
return;
}
/*===========================================================================*/
static void writecapbeaconwpa1(int fd_cap, uint8_t *macap, uint8_t essidlen, uint8_t *essid)
{
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static capap_t *capap;

static const uint8_t beacondata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x06,
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x04, 0x01, 0x00, 0x00, 0x50,
0xf2, 0x04, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02
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
static void writecapbeaconwpa2keyver3(int fd_cap, uint8_t *macap, uint8_t essidlen, uint8_t *essid)
{
static pcaprec_hdr_t *pcaph;
static mac_t *mach;
static capap_t *capap;

static const uint8_t beacondata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x06,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x06, 0xcc, 0x00
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
static int fgetline(FILE *inputstream, size_t size, char *buffer)
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
static void processpmkidfile(char *pmkidname, int fd_cap)
{
static int len;
static int aktread = 1;
static int essidlen;
static int fd_singlecap;
static FILE *fhpmkid;

static char linein[PMKID_LINE_LEN];
static uint8_t macap[6];
static uint8_t macsta[6];
static uint8_t pmkid[16];
static uint8_t essid[ESSID_LEN_MAX];

static char singlecapname[PATH_MAX +2];

if((fhpmkid = fopen(pmkidname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", pmkidname);
	return;
	}

while(1)
	{
	if((len = fgetline(fhpmkid, PMKID_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if((len < 61) || ((len > 59 +(ESSID_LEN_MAX *2))))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		pmkcapskipped++;
		continue;
		}
	if(((linein[32] != '*') && (linein[45] != '*') && (linein[58] != '*')) && ((linein[32] != ':') && (linein[45] != ':') && (linein[58] != ':')))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		pmkcapskipped++;
		continue;
		}
	essidlen = len -59;
	if((essidlen %2) != 0)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		pmkcapskipped++;
		continue;
		}
	if((essidlen < 2) ||  (essidlen > 64))
		{
		fprintf(stderr, "reading ESSID %d failed: %s\n", aktread, linein);
		aktread++;
		pmkcapskipped++;
		continue;
		}
	if(hex2bin(&linein[0], pmkid, 16) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		pmkcapskipped++;
		continue;
		}

	if(hex2bin(&linein[33], macap, 6) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		pmkcapskipped++;
		continue;
		}

	if(hex2bin(&linein[46], macsta, 6) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		pmkcapskipped++;
		continue;
		}

	if(hex2bin(&linein[59], essid, essidlen/2) != true)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		pmkcapskipped++;
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
		writecappmkidwpa2(fd_singlecap, macsta, macap, pmkid);
		pmkcapwritten++;
		close(fd_singlecap);
		}
	else
		{
		writecapbeaconwpa2(fd_cap, macap, essidlen /2, essid);
		writecappmkidwpa2(fd_cap, macsta, macap, pmkid);
		pmkcapwritten++;
		}
	aktread++;
	}
fclose(fhpmkid);
return;
}
/*===========================================================================*/
static void processhccapxfile(char *hccapxname, int fd_cap)
{
static struct stat statinfo;
static hccapx_t *hcxptr;
static int fd_singlecap;
static FILE *fhhcx;

static eapauth_t *eapa;
static wpakey_t *wpak;
static uint16_t keyinfo;
static uint8_t keyver;
static uint64_t rc;

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
		hccapxcapskipped++;
		continue;
		}
	if((hcxptr->version != 3) && (hcxptr->version != 4))
		{
		hccapxcapskipped++;
		continue;
		}
	if((hcxptr->essid_len == 0) || (hcxptr->essid_len > ESSID_LEN_MAX))
		{
		hccapxcapskipped++;
		continue;
		}
	eapa = (eapauth_t*)hcxptr->eapol;
	if(eapa->type != EAPOL_KEY)
		{
		hccapxcapskipped++;
		continue;
		}
	if(hcxptr->eapol_len != ntohs(eapa->len) +4)
		{
		hccapxcapskipped++;
		continue;
		}

	wpak = (wpakey_t*)(hcxptr->eapol +EAPAUTH_SIZE);
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver != hcxptr->keyver)
		{
		hccapxcapskipped++;
		continue;
		}
	if(keyver > 3)
		{
		hccapxcapskipped++;
		continue;
		}
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	if(keyinfo == 3)
		{
		hccapxcapskipped++;
		continue;
		}
	rc = wpak->replaycount;
	#ifdef BIG_ENDIAN_HOST
	rc = byte_swap_64(rc);
	#endif
	if(keyinfo == 4)
		{
		rc--;
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
		if(keyver == 1)
			{
			writecapbeaconwpa1(fd_singlecap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);
			if(memcmp(wpak->nonce, hcxptr->nonce_ap, 32) != 0)
				{
				writecapm1wpa1(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_ap, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa1(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_sta, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->eapol_len, hcxptr->eapol, hcxptr->keymic);
			hccapxcapwritten++;
			}
		else if(keyver == 2)
			{
			writecapbeaconwpa2(fd_singlecap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);
			if(memcmp(wpak->nonce, hcxptr->nonce_ap, 32) != 0)
				{
				writecapm1wpa2(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_ap, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_sta, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->eapol_len, hcxptr->eapol, hcxptr->keymic);
			hccapxcapwritten++;
			}
		else if(keyver == 3)
			{
			writecapbeaconwpa2keyver3(fd_singlecap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);
			if(memcmp(wpak->nonce, hcxptr->nonce_ap, 32) != 0)
				{
				writecapm1wpa2keyver3(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_ap, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2keyver3(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_sta, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->eapol_len, hcxptr->eapol, hcxptr->keymic);
			hccapxcapwritten++;
			}
		close(fd_singlecap);
		}
	else
		{
		if(keyver == 1)
			{
			writecapbeaconwpa1(fd_cap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);
			if(memcmp(wpak->nonce, hcxptr->nonce_ap, 32) != 0)
				{
				writecapm1wpa1(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_ap, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa1(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_sta, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->eapol_len, hcxptr->eapol, hcxptr->keymic);
			hccapxcapwritten++;
			}
		else if(keyver == 2)
			{
			writecapbeaconwpa2(fd_cap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);
			if(memcmp(wpak->nonce, hcxptr->nonce_ap, 32) != 0)
				{
				writecapm1wpa2(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_ap, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_sta, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->eapol_len, hcxptr->eapol, hcxptr->keymic);
			hccapxcapwritten++;
			}
		else if(keyver == 3)
			{
			writecapbeaconwpa2keyver3(fd_cap, hcxptr->mac_ap, hcxptr->essid_len, hcxptr->essid);
			if(memcmp(wpak->nonce, hcxptr->nonce_ap, 32) != 0)
				{
				writecapm1wpa2keyver3(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_ap, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2keyver3(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->nonce_sta, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcxptr->mac_sta, hcxptr->mac_ap, hcxptr->eapol_len, hcxptr->eapol, hcxptr->keymic);
			hccapxcapwritten++;
			}
		}
	}
fclose(fhhcx);
return;
}
/*===========================================================================*/
static void processhccapfile(char *hccapname, int fd_cap)
{
static struct stat statinfo;
static hccap_t *hcptr;
static int fd_singlecap;
static FILE *fhhc;
static uint8_t essidlen;
static int c;
static eapauth_t *eapa;
static wpakey_t *wpak;
static uint16_t keyinfo;
static uint8_t keyver;
static uint64_t rc;

static uint8_t hcdata[HCCAP_SIZE];
static char singlecapname[PATH_MAX +2];

if(stat(hccapname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hccapname);
	return;
	}

if((statinfo.st_size %HCCAP_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return;
	}

if((fhhc = fopen(hccapname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapname);
	return;
	}

hcptr = (hccap_t*)hcdata;
while(fread(&hcdata, HCCAP_SIZE, 1, fhhc) == 1)
	{
	essidlen = 0;
	for(c = 0; c < ESSID_LEN_MAX; c++)
		{
		if(hcptr->essid[c] == 0)
			{
			break;
			}
		essidlen++;
		}

	if((essidlen == 0) || (essidlen > ESSID_LEN_MAX))
		{
		hccapcapskipped++;
		continue;
		}

	eapa = (eapauth_t*)hcptr->eapol;
	if(eapa->type != EAPOL_KEY)
		{
		hccapcapskipped++;
		continue;
		}
	if(hcptr->eapol_size != ntohs(eapa->len) +4)
		{
		hccapcapskipped++;
		continue;
		}

	wpak = (wpakey_t*)(hcptr->eapol +EAPAUTH_SIZE);
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver != hcptr->keyver)
		{
		hccapcapskipped++;
		continue;
		}
	if(keyver > 3)
		{
		hccapcapskipped++;
		continue;
		}
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	if(keyinfo == 3)
		{
		hccapcapskipped++;
		continue;
		}
	rc = wpak->replaycount;
	#ifdef BIG_ENDIAN_HOST
	rc = byte_swap_64(rc);
	#endif
	if(keyinfo == 4)
		{
		rc--;
		}
	if(fd_cap == 0)
		{
		snprintf(singlecapname, 18, "%02x%02x%02x%02x%02x%02x.cap", hcptr->mac2[0], hcptr->mac2[1], hcptr->mac2[2], hcptr->mac2[3], hcptr->mac2[4], hcptr->mac2[5]);
		fd_singlecap = hcxopencapdump(singlecapname);
		if(fd_singlecap == -1)
			{
			fprintf(stderr, "could not create cap file\n");
			exit(EXIT_FAILURE);
			}
		if(keyver == 1)
			{
			writecapbeaconwpa1(fd_singlecap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa1(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa1(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 2)
			{
			writecapbeaconwpa2(fd_singlecap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 3)
			{
			writecapbeaconwpa2keyver3(fd_singlecap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2keyver3(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2keyver3(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		close(fd_singlecap);
		}
	else
		{
		if(keyver == 1)
			{
			writecapbeaconwpa1(fd_cap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa1(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa1(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}

			writecapm2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 2)
			{
			writecapbeaconwpa2(fd_cap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 3)
			{
			writecapbeaconwpa2keyver3(fd_cap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2keyver3(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2keyver3(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		}
	}
fclose(fhhc);
return;
}
/*===========================================================================*/
static void processjohnfile(char *johnname, int fd_cap)
{
static int len;
static int i;
static FILE *fhjohn;
static int essidlen;
static int hashlen;
static char *ptressid;
static char *ptreapol;
static char *ptreapol2;
static uint8_t *johnptr;
static const char *pos;
static hccap_t *hcptr;
static int fd_singlecap;
static eapauth_t *eapa;
static wpakey_t *wpak;
static uint16_t keyinfo;
static uint8_t keyver;
static uint64_t rc;


static const char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static char singlecapname[PATH_MAX +2];
static char linein[JOHN_LINE_LEN];
static uint8_t hcdata[HCCAP_SIZE];
static unsigned char atoi64[0x100];

if((fhjohn = fopen(johnname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", johnname);
	return;
	}

memset(atoi64, 0x7F, sizeof(atoi64));
for(pos = itoa64; pos <= &itoa64[63]; pos++)
	{
	atoi64[ARCH_INDEX(*pos)] = pos - itoa64;
	}

hcptr = (hccap_t*)hcdata;
while(1)
	{
	if((len = fgetline(fhjohn, JOHN_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if(len < 534)
		{
		johnskipped++;
		continue;
		}
	ptressid =strstr(linein, ":$WPAPSK$");
	if(ptressid == NULL)
		{
		johnskipped++;
		continue;
		}
	ptressid += 9;
	ptreapol =strrchr(linein, '#');
	if(ptreapol == NULL)
		{
		johnskipped++;
		continue;
		}
	ptreapol++;
	essidlen = ptreapol -ptressid -1;
	if((essidlen == 0) || (essidlen > ESSID_LEN_MAX))
		{
		johnskipped++;
		continue;
		}
	ptreapol2 = strchr(ptreapol, ':');
	if(ptreapol2 == NULL)
		{
		johnskipped++;
		continue;
		}
	hashlen = ptreapol2 - ptreapol;
	if(hashlen != 475)
		{
		johnskipped++;
		continue;
		}
	memset(&hcdata, 0, HCCAP_SIZE);
	memcpy(&hcdata, ptressid, essidlen);
	johnptr = hcdata +36;
	for (i = 0; i < 118; i++)
		{
		johnptr[0] = (atoi64[ARCH_INDEX(ptreapol[0])] << 2) | (atoi64[ARCH_INDEX(ptreapol[1])] >> 4);
		johnptr[1] = (atoi64[ARCH_INDEX(ptreapol[1])] << 4) | (atoi64[ARCH_INDEX(ptreapol[2])] >> 2);
		johnptr[2] = (atoi64[ARCH_INDEX(ptreapol[2])] << 6) | (atoi64[ARCH_INDEX(ptreapol[3])]);
		johnptr += 3;
		ptreapol += 4;
		}
	johnptr[0] = (atoi64[ARCH_INDEX(ptreapol[0])] << 2) | (atoi64[ARCH_INDEX(ptreapol[1])] >> 4);
	johnptr[1] = (atoi64[ARCH_INDEX(ptreapol[1])] << 4) | (atoi64[ARCH_INDEX(ptreapol[2])] >> 2);

	eapa = (eapauth_t*)hcptr->eapol;
	if(eapa->type != EAPOL_KEY)
		{
		johnskipped++;
		continue;
		}
	if(hcptr->eapol_size != ntohs(eapa->len) +4)
		{
		johnskipped++;
		continue;
		}

	wpak = (wpakey_t*)(hcptr->eapol +EAPAUTH_SIZE);
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver != hcptr->keyver)
		{
		johnskipped++;
		continue;
		}
	if(keyver > 3)
		{
		johnskipped++;
		continue;
		}
	keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
	if(keyinfo == 3)
		{
		johnskipped++;
		continue;
		}
	rc = wpak->replaycount;
	#ifdef BIG_ENDIAN_HOST
	rc = byte_swap_64(rc);
	#endif
	if(keyinfo == 4)
		{
		rc--;
		}
	if(fd_cap == 0)
		{
		snprintf(singlecapname, 18, "%02x%02x%02x%02x%02x%02x.cap", hcptr->mac2[0], hcptr->mac2[1], hcptr->mac2[2], hcptr->mac2[3], hcptr->mac2[4], hcptr->mac2[5]);
		fd_singlecap = hcxopencapdump(singlecapname);
		if(fd_singlecap == -1)
			{
			fprintf(stderr, "could not create cap file\n");
			exit(EXIT_FAILURE);
			}
		if(keyver == 1)
			{
			writecapbeaconwpa1(fd_singlecap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa1(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa1(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 2)
			{
			writecapbeaconwpa2(fd_singlecap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 3)
			{
			writecapbeaconwpa2keyver3(fd_singlecap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2keyver3(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2keyver3(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_singlecap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		close(fd_singlecap);
		}
	else
		{
		if(keyver == 1)
			{
			writecapbeaconwpa1(fd_cap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa1(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa1(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 2)
			{
			writecapbeaconwpa2(fd_cap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		else if(keyver == 3)
			{
			writecapbeaconwpa2keyver3(fd_cap, hcptr->mac1, essidlen, (uint8_t*)hcptr->essid);
			if(memcmp(wpak->nonce, hcptr->nonce1, 32) != 0)
				{
				writecapm1wpa2keyver3(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce1, eapa->version, wpak->keylen, rc);
				}
			else
				{
				writecapm1wpa2keyver3(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->nonce2, eapa->version, wpak->keylen, rc);
				}
			writecapm2(fd_cap, hcptr->mac2, hcptr->mac1, hcptr->eapol_size, hcptr->eapol, hcptr->keymic);
			hccapcapwritten++;
			}
		}
	}
fclose(fhjohn);
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
	"-c <file> : output cap file\n"
	"            if no cap file is selected, output will be written to single cap files\n"
	"            format: mac_sta.cap (mac_sta.cap_x)\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--pmkid=<file>  : input PMKID hash file\n"
	"--hccapx=<file> : input hashcat hccapx file\n"
	"--hccap=<file>  : input hashcat hccap file\n"
	"--john=<file>   : input John the Ripper WPAPSK hash file\n"
	"--help          : show this help\n"
	"--version       : show version\n"
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
static int fd_cap = 0;
static char *pmkidname = NULL;
static char *hccapxname = NULL;
static char *hccapname = NULL;
static char *johnname = NULL;
static char *capname = NULL;

static const char *short_options = "c:hv";
static const struct option long_options[] =
{
	{"pmkid",			required_argument,	NULL,	HCXP_PMKID},
	{"hccapx",			required_argument,	NULL,	HCXP_HCCAPX},
	{"hccap",			required_argument,	NULL,	HCXP_HCCAP},
	{"john",			required_argument,	NULL,	HCXP_JOHN},
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
		case HCXP_PMKID:
		pmkidname = optarg;
		break;

		case HCXP_HCCAPX:
		hccapxname = optarg;
		break;

		case HCXP_HCCAP:
		hccapname = optarg;
		break;

		case HCXP_JOHN:
		johnname = optarg;
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

if(argc < 2)
	{
	fprintf(stderr, "no option selected\n");
	return EXIT_SUCCESS;
	}

globalinit();

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
	processhccapxfile(hccapxname, fd_cap);
	}

if(hccapname != NULL)
	{
	processhccapfile(hccapname, fd_cap);
	}

if(johnname != NULL)
	{
	processjohnfile(johnname, fd_cap);
	}


if(fd_cap != 0)
	{
	close(fd_cap);
	removeemptycap(capname);
	}

if(pmkcapwritten > 0)
	{
	fprintf(stdout, "PMKIDs written to capfile(s): %llu (%llu skipped)\n", pmkcapwritten, pmkcapskipped);
	}
if(hccapxcapwritten > 0)
	{
	fprintf(stdout, "EAPOLs written to capfile(s): %llu (%llu skipped)\n", hccapxcapwritten, hccapxcapskipped);
	}
if(hccapcapwritten > 0)
	{
	fprintf(stdout, "EAPOLs written to capfile(s): %llu (%llu skipped)\n", hccapcapwritten, hccapcapskipped);
	}
if(johnwritten > 0)
	{
	fprintf(stdout, "EAPOLs written to capfile(s): %llu (%llu skipped)\n", johnwritten, johnskipped);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

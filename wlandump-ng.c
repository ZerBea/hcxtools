#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include <time.h>
#include <pcap.h>
#include <linux/wireless.h>
#include <netinet/in.h>

#include "common.h"

#ifdef DOGPIOSUPPORT
#include <wiringPi.h>
#endif

/*===========================================================================*/
/* Definitionen */

#define TT_SIGUSR1 (SIGUSR1)
#define TT_SIGUSR2 (SIGUSR2)
#define TIME_INTERVAL_1S 5
#define TIME_INTERVAL_1NS 0

#define TIME_INTERVAL_2S 5
#define TIME_INTERVAL_2NS 0

#define APLISTESIZEMAX 1024
#define APHDLISTESIZEMAX 1024
#define SENDPACKETSIZEMAX 0x1ff

#define BEACONCOUNT 10
#define ESTABLISHEDHANDSHAKESMAX 1


#define WPA_M1  0b00000001
#define WPA_M2  0b00000010
#define WPA_M3  0b00000100
#define WPA_M4  0b00001000

void set_timer(timer_t timerid, int seconds, long int nanoseconds);

struct aplist
{
 long int	tv_sec;
 adr_t		addr_ap;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct aplist apl_t;
#define	APL_SIZE (sizeof(apl_t))


struct aphdlist
{
 long int	tv_sec;
 adr_t		addr_ap;
 adr_t		addr_sta;
 int		hdc;
};
typedef struct aphdlist aphdl_t;
#define	APHDL_SIZE (sizeof(aphdl_t))


struct handshake
{
 long int	tv_sec1;
 adr_t		addr_ap1;
 adr_t		addr_sta1;
 uint8_t	m1;
 unsigned long long int rc1;
 long int	tv_sec2;
 adr_t		addr_ap2;
 adr_t		addr_sta2;
 uint8_t	m2;
 unsigned long long int rc2;
 long int	tv_sec3;
 adr_t		addr_ap3;
 adr_t		addr_sta3;
 uint8_t	m3;
 unsigned long long int rc3;
 long int	tv_sec4;
 adr_t		addr_ap4;
 adr_t		addr_sta4;
 uint8_t	m4;
 unsigned long long int rc4;
 uint8_t	af;
};
typedef struct handshake hds_t;
#define	HDS_SIZE (sizeof(hds_t))
 
/*===========================================================================*/
/* globale variablen */

pcap_t *pcapin = NULL;
pcap_dumper_t *pcapout = NULL;
uint8_t chptr = 0;
uint8_t chlistende = 13;
uint16_t mysequencenr = 1;
int staytime = TIME_INTERVAL_2S;

int maxerrorcount;
int internalpcaperrors;
unsigned long long int myoui;
unsigned long long int mynic;
unsigned long long int mymac;

timer_t timer1;
timer_t timer2;

uint8_t nullmac[6];
uint8_t broadcastmac[6];
uint8_t myaddr[6];

int establishedhandshakes = ESTABLISHEDHANDSHAKESMAX;

apl_t *accesspointliste = NULL;
aphdl_t *accesspointhdliste = NULL;
char *interfacename = NULL;

bool wantstatusflag = false;
bool deauthflag = false;
bool disassocflag = false;
bool sendundirectedprflag = false;
bool beaconingflag = false;
bool respondflag = false;
bool wepdataflag = false;


adr_t	lastbeaconap;
uint8_t lastbeaconessid_len = 0;
uint8_t lastbeaconessid[32];

/*===========================================================================*/
/* Konstante */

const uint8_t txvendor1[] =
{
0x00, 0x00, 0x6c, 0x20, 0x5b, 0x2a
};

const int myvendor[] =
{
0x000101, 0x00054f, 0x000578, 0x000b18, 0x000bf4, 0x000c53, 0x000d58,
0x000da7, 0x000dc2, 0x000df2, 0x000e17, 0x000e22, 0x000e2a, 0x000eef, 0x000f09,
0x0016b4, 0x001761, 0x001825, 0x002067, 0x00221c, 0x0022f1, 0x00234a, 0x00238c,
0x0023f7, 0x002419, 0x0024fb, 0x00259d, 0x0025df, 0x00269f, 0x005047, 0x005079,
0x0050c7, 0x0084ed, 0x0086a0, 0x00a054, 0x00a085, 0x00bb3a, 0x00cb00, 0x0418b6,
0x0c8112, 0x100000, 0x10ae60, 0x10b713, 0x1100aa, 0x111111, 0x140708, 0x146e0a,
0x18421d, 0x1cf4ca, 0x205b2a, 0x20d160, 0x24336c, 0x24bf74, 0x28ef01, 0x3cb87a,
0x487604, 0x48f317, 0x50e14a, 0x544e45, 0x580943, 0x586ed6, 0x5c6b4f, 0x609620,
0x68e166, 0x706f81, 0x78f944, 0x7ce4aa, 0x8c8401, 0x8ce748, 0x906f18, 0x980ee4,
0x9c93e4, 0xa468bc, 0xa4a6a9, 0xacde48, 0xb025aa, 0xb0ece1, 0xb0febd, 0xb4e1eb,
0xc02250, 0xc8aacc, 0xd85dfb, 0xdc7014, 0xe00db9, 0xe0cb1d, 0xe80410, 0xf04f7c,
0xf0a225, 0xfcc233
};
#define MYVENDOR_SIZE sizeof(myvendor)


const uint8_t hdradiotap[] =
{
 0x00, 0x00, // <-- radiotap version
 0x0c, 0x00, // <- radiotap header length
 0x04, 0x80, 0x00, 0x00, // <-- bitmap
 0x02, // <-- rate
 0x00, // <-- padding for natural alignment
 0x18, 0x00, // <-- TX flags
};
#define HDRRT_SIZE sizeof(hdradiotap)


uint8_t authenticationframe[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATION_SIZE sizeof(authenticationframe)


/*undirected proberequest*/
uint8_t undirectedpr[] =
{
0x00, 0x00,
0x01, 0x08, 0x02, 0x04, 0x0b, 0x0c, 0x12, 0x16, 0x18, 0x24,
0x03, 0x01, 0x07,
0x2d, 0x1a, 0x62, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c
};
#define UNDIRECTEDPR_SIZE sizeof(undirectedpr)


/* Fritzbox 3272 Beacon */
uint8_t beaconfb3272[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
0x03, 0x01, 0x0b, //channel
0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
0x07, 0x06, 0x44, 0x45, 0x20, 0x01, 0x0d, 0x14,
0x2a, 0x01, 0x00,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01, 0x20
};
#define FB3272BEACON_SIZE sizeof(beaconfb3272)


/* Fritzbox 3272 Proberesponse*/
uint8_t proberesponsefb3272[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
0x03, 0x01, 0x0b,
0x07, 0x06, 0x44, 0x45, 0x20, 0x01, 0x0d, 0x14,
0x2a, 0x01, 0x00,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xef, 0x11, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x6f, 0x00, 0x50, 0xf2, 0x04, 0x10, 0x4a, 0x00, 0x01, 0x10, 0x10, 0x44, 0x00, 0x01, 0x02, 0x10, 0x3b, 0x00, 0x01, 0x03, 0x10, 0x47, 0x00, 0x10, 0xe1, 0x88, 0x94,
0x6e, 0x88, 0x55, 0xf6, 0xb5, 0xef, 0xef, 0x34, 0x81, 0xc4, 0xcb, 0xb5, 0x30, 0x10, 0x21, 0x00, 0x03, 0x41, 0x56, 0x4d, 0x10, 0x23, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78,
0x10, 0x24, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x42, 0x00, 0x04, 0x30, 0x30, 0x30, 0x30, 0x10, 0x54, 0x00, 0x08, 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01,
0x10, 0x11, 0x00, 0x04, 0x46, 0x42, 0x6f, 0x78, 0x10, 0x08, 0x00, 0x02, 0x23, 0x88, 0x10, 0x3c, 0x00, 0x01, 0x01, 0x10, 0x49, 0x00, 0x06, 0x00, 0x37, 0x2a, 0x00, 0x01,
0x20
};
#define FB3272PROBERESPONSE_SIZE sizeof(proberesponsefb3272)


const uint8_t associationresponse[] =
{
0x01, 0x08, 0x82, 0x84, 0x8b, 0x0c, 0x12, 0x96, 0x18, 0x24,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0x2d, 0x1a, 0xaf, 0x01, 0x1b, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x04, 0x06, 0xe6, 0x47, 0x0d, 0x00,
0x3d, 0x16, 0x0b, 0x0f, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x4a, 0x0e, 0x14, 0x00, 0x0a, 0x00, 0x2c, 0x01, 0xc8, 0x00, 0x14, 0x00, 0x05, 0x00, 0x19, 0x00,
0x7f, 0x08, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x00, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00
};
#define ASSOCRESP_SIZE sizeof(associationresponse)


const uint8_t anonce[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7,
0x00, 0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79,
0x09, 0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd,
0xb9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00
};
#define ANONCE_SIZE sizeof(anonce)


const uint8_t requestidentity[] =
{
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x02, 0x00, 0x00, 0x05, 0x01, 0xb8, 0x00, 0x05, 0x01
};
#define REQUESTIDENTITY_SIZE sizeof(requestidentity)

/*===========================================================================*/
bool initgloballists()
{
struct timeval starttimeval;

gettimeofday (&starttimeval, NULL);

memset(&nullmac, 0, 6);
memset(&broadcastmac, 0xff, 6);

mynic = rand() & 0xffff;
myoui = myvendor[rand() % ((MYVENDOR_SIZE / sizeof(int))-1)];
mymac = (myoui << 24) | mynic;
memset(&myaddr, 0, 6);
myaddr[5] = mynic & 0xff;
myaddr[4] = (mynic >> 8) & 0xff;
myaddr[3] = (mynic >> 16) & 0xff;
myaddr[2] = myoui & 0xff;
myaddr[1] = (myoui >> 8) & 0xff;
myaddr[0] = (myoui >> 16) & 0xff;

if((accesspointliste = calloc((APLISTESIZEMAX +1), APL_SIZE)) == NULL)
	return false;

if((accesspointhdliste = calloc((APHDLISTESIZEMAX +1), APHDL_SIZE)) == NULL)
	return false;

return true;
}
/*===========================================================================*/
void printmacdir(uint8_t *mac1, uint8_t *mac2, uint8_t tods, uint8_t fromds, uint8_t eapcode, char *infostring)
{
int m;
time_t t = time(NULL);
struct tm *tm = localtime(&t);
char timestring[64];

strftime(timestring, sizeof(timestring), "%H:%M:%S", tm);
printf("%s % 3d ", timestring, channellist[chptr]);


if((tods == 0) && (fromds == 1))
	{
	for (m = 0; m < 6; m++)
		printf("%02x", mac2[m]);
	printf(" --> ");
	for (m = 0; m < 6; m++)
		printf("%02x", mac1[m]);
	}
else if((tods == 1) && (fromds == 0))
	{
	for (m = 0; m < 6; m++)
		printf("%02x", mac1[m]);
	printf(" <-- ");
	for (m = 0; m < 6; m++)
		printf("%02x", mac2[m]);
	}
else
	return;

if(eapcode == EAP_CODE_REQ)
	printf(" identity request: %s          \n", infostring);
else if(eapcode == EAP_CODE_RESP)
	printf(" identity response: %s          \n", infostring);
else
	printf(" unknown: %s          \n", infostring);
return;
}
/*===========================================================================*/
void printmac(uint8_t *mac1, uint8_t *mac2, uint8_t tods, uint8_t fromds, char *infostring)
{
int m;
time_t t = time(NULL);
struct tm *tm = localtime(&t);
char timestring[64];

strftime(timestring, sizeof(timestring), "%H:%M:%S", tm);
printf("%s % 3d ", timestring, channellist[chptr]);

if((tods == 0) && (fromds == 1))
	{
	for (m = 0; m < 6; m++)
		printf("%02x", mac2[m]);
	printf(" <-> ");
	for (m = 0; m < 6; m++)
		printf("%02x", mac1[m]);
	}
else if((tods == 1) && (fromds == 0))
	{
	for (m = 0; m < 6; m++)
		printf("%02x", mac1[m]);
	printf(" <-> ");
	for (m = 0; m < 6; m++)
		printf("%02x", mac2[m]);
	}
else
	return;
printf(" %s          \n", infostring);
return;
}
/*===========================================================================*/
void printidentity(uint8_t *mac1, uint8_t *mac2, uint8_t tods, uint8_t fromds, uint8_t eapcode, eapext_t *eapext)
{
eapri_t *eapidentity;
int idlen;
char idstring[258];

eapidentity = (eapri_t*)(eapext);
if(eapidentity->eaptype != EAP_TYPE_ID)
	return;
idlen = htons(eapidentity->eaplen) -5;
if((idlen > 0) && (idlen <= 256))
	{
	memset(&idstring, 0, 258);
	memcpy(idstring, eapidentity->identity, idlen);
	printmacdir(mac1, mac2, tods, fromds, eapcode, idstring);
	}
return;
}

/*===========================================================================*/
/*===========================================================================*/
int getwpskey(eapext_t *eapext)
{
wps_t *wpsd;
vtag_t *vtag;

wpsd = (wps_t*)(eapext->data);
if((memcmp(wpsd->vid, WPS_VENDOR, sizeof(wpsd->vid)) != 0) || (be32toh(wpsd->type) != WPS_SIMPLECONF))
	return 0;

printf("%ld\n", EAPEXT_SIZE);

int vtagl = be16toh(eapext->eaplen);
vtag = (vtag_t*)(wpsd->tags);
while( 0 < vtagl)
	{
	vtag = (vtag_t*)((uint8_t*)vtag + be16toh(vtag->len) + VTAG_SIZE);
	vtagl -= be16toh(vtag->len) + VTAG_SIZE;
	if(memcmp(&vtag->id, WPS_MSG_TYPE, 2) == 0)
		return vtag->data[0];
	}
return 0;
}
/*===========================================================================*/
void handlewps(uint8_t *mac1, uint8_t *mac2, uint8_t tods, uint8_t fromds, eapext_t *eapext)
{
int wpskey; 
int m;
time_t t = time(NULL);
struct tm *tm = localtime(&t);
char timestring[64];

wpskey = getwpskey(eapext);
if((wpskey < WPS_MSG_M1 ) || (wpskey > WPS_MSG_DONE))
	return;

strftime(timestring, sizeof(timestring), "%H:%M:%S", tm);
printf("%s % 3d ", timestring, channellist[chptr]);

if((tods == 0) && (fromds == 1))
	{
	for (m = 0; m < 6; m++)
		printf("%02x", mac2[m]);
	printf(" --> ");
	for (m = 0; m < 6; m++)
		printf("%02x", mac1[m]);
	}
else if((tods == 1) && (fromds == 0))
	{
	for (m = 0; m < 6; m++)
		printf("%02x", mac1[m]);
	printf(" <-- ");
	for (m = 0; m < 6; m++)
		printf("%02x", mac2[m]);
	}
else
	return;

if(wpskey == WPS_MSG_M1)
	printf(" WPS-M1 message          \n");
if(wpskey == WPS_MSG_M2)
	printf(" WPS-M2 message          \n");
if(wpskey == WPS_MSG_M2D)
	printf(" WPS-M2D message          \n");
if(wpskey == WPS_MSG_M3)
	printf(" WPS-M3 message          \n");
if(wpskey == WPS_MSG_M4)
	printf(" WPS-M4 message          \n");
if(wpskey == WPS_MSG_M5)
	printf(" WPS-M5 message          \n");
if(wpskey == WPS_MSG_M6)
	printf(" WPS-M6 message          \n");
if(wpskey == WPS_MSG_M7)	
	printf(" WPS-M7 message          \n");
if(wpskey == WPS_MSG_M8)
	printf(" WPS-M8 message          \n");
if(wpskey == WPS_MSG_ACK)
	printf(" WPS-ACK                 \n");
if(wpskey == WPS_MSG_NACK)
	printf(" WPS-NACK                \n");
if(wpskey == WPS_MSG_DONE)
	printf(" WPS-DONE                \n");
return;
}
/*===========================================================================*/
void nextmac()
{
mynic++;
myaddr[5] = mynic & 0xff;
myaddr[4] = (mynic >> 8) & 0xff;
myaddr[3] = (mynic >> 16) & 0xff;
return;
}
/*===========================================================================*/
unsigned long long int getreplaycount(eap_t *eap)
{
unsigned long long int replaycount = 0;

replaycount = be64toh(eap->replaycount);
return replaycount;
}
/*===========================================================================*/
uint8_t geteapkey(eap_t *eap)
{
uint16_t keyinfo;

keyinfo = (((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8));
if (keyinfo & WPA_KEY_INFO_ACK)
	{
	if(keyinfo & WPA_KEY_INFO_INSTALL)
		{
		/* handshake 3 */
		return WPA_M3;
		}
	else
		{
		/* handshake 1 */
		return WPA_M1;
		}
	}
else
	{
	if(keyinfo & WPA_KEY_INFO_SECURE)
		{
		/* handshake 4 */
		return WPA_M4;
		}
	else
		{
		/* handshake 2 */
		return WPA_M2;
		}
	}
}
/*===========================================================================*/
void sendundirectedpr()
{
int pcapstatus;
mac_t grundframe;
uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_MGMT;
grundframe.subtype = MAC_ST_PROBE_REQ;
grundframe.duration = 0x0000;
memcpy(grundframe.addr1.addr, &broadcastmac, 6);
memcpy(grundframe.addr2.addr, &txvendor1, 6);
memcpy(grundframe.addr3.addr, &broadcastmac, 6);
grundframe.sequence = htole16(mysequencenr++ << 4);
memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket + HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket + HDRRT_SIZE +MAC_SIZE_NORM, undirectedpr, UNDIRECTEDPR_SIZE);
sendpacket[HDRRT_SIZE +MAC_SIZE_NORM +14] = channellist[chptr];

pcapstatus = pcap_inject(pcapin, &sendpacket, HDRRT_SIZE + MAC_SIZE_NORM +UNDIRECTEDPR_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending deauthentication %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}

mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
return ;
}
/*===========================================================================*/
void sendbeacon(uint8_t *macaddr2, uint8_t essid_len, uint8_t *essid)
{
struct timeval tv1;
int pcapstatus;
mac_t grundframe;
beacon_t beacontsframe;
essid_t essidframe;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_MGMT;
grundframe.subtype = MAC_ST_BEACON;
grundframe.duration = 0;
memcpy(grundframe.addr1.addr, &broadcastmac, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
grundframe.sequence = htole16(mysequencenr++ << 4);

gettimeofday( &tv1,  NULL );
beacontsframe.beacon_timestamp = htole64(tv1.tv_sec*1000000UL + tv1.tv_usec);
beacontsframe.beacon_interval = 0x0064;
beacontsframe.beacon_capabilities = 0x431;

essidframe.info_essid = 0;
essidframe.info_essid_len = essid_len;

memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM, &beacontsframe, BEACONINFO_SIZE);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE, &essidframe, ESSIDINFO_SIZE);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE, essid, essid_len);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len, beaconfb3272, FB3272BEACON_SIZE);

sendpacket[HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +12] = channellist[chptr];

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +FB3272BEACON_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif

	fprintf(stderr, "error while sending beacon %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}
mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
return;
}
/*===========================================================================*/
void sendproberesponse(uint8_t *macaddr1, uint8_t *macaddr2, uint8_t essid_len, uint8_t **essid)
{
struct timeval tv1;
int pcapstatus;
mac_t grundframe;
beacon_t beacontsframe;
essid_t essidframe;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_MGMT;
grundframe.subtype = MAC_ST_PROBE_RESP;
grundframe.duration = 0x013a;
memcpy(grundframe.addr1.addr, macaddr1, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
grundframe.sequence = htole16(mysequencenr++ << 4);

gettimeofday( &tv1,  NULL );
beacontsframe.beacon_timestamp = htole64(tv1.tv_sec*1000000UL + tv1.tv_usec);
beacontsframe.beacon_interval = 0x0064;
beacontsframe.beacon_capabilities = 0x431;

essidframe.info_essid = 0;
essidframe.info_essid_len = essid_len;

memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM, &beacontsframe, BEACONINFO_SIZE);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE, &essidframe, ESSIDINFO_SIZE);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE, essid, essid_len);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len, proberesponsefb3272, FB3272PROBERESPONSE_SIZE);

sendpacket[HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +12] = channellist[chptr];

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +FB3272PROBERESPONSE_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending probe response %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}
mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
return;
}
/*===========================================================================*/
void sendassociationresponse(uint8_t dart, uint8_t *macaddr1, uint8_t *macaddr2)
{
int pcapstatus;
mac_t grundframe;
assocres_t associationframe;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_MGMT;
grundframe.subtype = dart;
grundframe.duration = 0x013a;
memcpy(grundframe.addr1.addr, macaddr1, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
grundframe.sequence = htole16(mysequencenr++ << 4);

associationframe.ap_capabilities = 0x0431;
associationframe.ap_status = 0;
associationframe.ap_associd = 1;

memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM, &associationframe, ASSOCIATIONRESF_SIZE);

memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESF_SIZE, &associationresponse, ASSOCRESP_SIZE);

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +ASSOCIATIONRESF_SIZE +ASSOCRESP_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending associationresponce %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}
mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
return;
}
/*===========================================================================*/
void sendacknowledgement(uint8_t *macaddr1)
{
mac_t grundframe;
int pcapstatus;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_CTRL;
grundframe.subtype = MAC_ST_ACK;
grundframe.duration = 0;
memcpy(grundframe.addr1.addr, macaddr1, 6);

memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_ACK);

pcapstatus = pcap_inject(pcapin, &sendpacket, HDRRT_SIZE +MAC_SIZE_ACK);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending acknowledgement %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}
return;
}
/*===========================================================================*/
void sendrequestidentity(uint8_t *macaddr1, uint8_t *macaddr2)
{
int pcapstatus;
mac_t grundframe;
qos_t qosframe;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
memset(&qosframe, 0, QOS_SIZE);
grundframe.type = MAC_TYPE_DATA;
grundframe.subtype = MAC_ST_QOSDATA;
grundframe.from_ds = 1;
grundframe.duration = 0x3a01;
memcpy(grundframe.addr1.addr, macaddr1, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
qosframe.control = 0;
qosframe.flags = 0;
memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM, &qosframe, QOS_SIZE);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +QOS_SIZE, &requestidentity, REQUESTIDENTITY_SIZE);

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +QOS_SIZE +REQUESTIDENTITY_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending request identity %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	return;
	}
return;
}
/*===========================================================================*/
void sendkey1(uint8_t *macaddr1, uint8_t *macaddr2)
{
int pcapstatus;
mac_t grundframe;
qos_t qosframe;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
memset(&qosframe, 0, QOS_SIZE);
grundframe.type = MAC_TYPE_DATA;
grundframe.subtype = MAC_ST_QOSDATA;
grundframe.from_ds = 1;
grundframe.duration = 0x3a01;
memcpy(grundframe.addr1.addr, macaddr1, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
qosframe.control = 0;
qosframe.flags = 0;
memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM, &qosframe, QOS_SIZE);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM +QOS_SIZE, &anonce, ANONCE_SIZE);

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +QOS_SIZE +ANONCE_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending key 1 %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	return;
	}
return;
}
/*===========================================================================*/
void sendauthentication(uint8_t *macaddr1, uint8_t *macaddr2)
{
mac_t grundframe;
int pcapstatus;

uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_MGMT;
grundframe.subtype = MAC_ST_AUTH;
grundframe.duration = 0x013a;
memcpy(grundframe.addr1.addr, macaddr1, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
grundframe.sequence = htole16(mysequencenr++ << 4);

memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket +HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
memcpy(sendpacket +HDRRT_SIZE +MAC_SIZE_NORM, &authenticationframe, AUTHENTICATION_SIZE);

pcapstatus = pcap_inject(pcapin, &sendpacket, HDRRT_SIZE +MAC_SIZE_NORM +AUTHENTICATION_SIZE);

if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending authentication %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}
mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
return;
}
/*===========================================================================*/
void send_deauthentication(uint8_t dart, uint8_t reason, uint8_t *macaddr1, uint8_t *macaddr2)
{
int pcapstatus;
mac_t grundframe;
uint8_t sendpacket[SENDPACKETSIZEMAX];

memset(&grundframe, 0, MAC_SIZE_NORM);
grundframe.type = MAC_TYPE_MGMT;
grundframe.subtype = dart;
grundframe.duration = 0x013a;
memcpy(grundframe.addr1.addr, macaddr1, 6);
memcpy(grundframe.addr2.addr, macaddr2, 6);
memcpy(grundframe.addr3.addr, macaddr2, 6);
grundframe.sequence = htole16(mysequencenr++ << 4);
memcpy(sendpacket, hdradiotap, HDRRT_SIZE);
memcpy(sendpacket + HDRRT_SIZE, &grundframe, MAC_SIZE_NORM);
sendpacket[HDRRT_SIZE +MAC_SIZE_NORM] = reason;
sendpacket[HDRRT_SIZE +MAC_SIZE_NORM +1] = 0;
pcapstatus = pcap_inject(pcapin, &sendpacket, HDRRT_SIZE + MAC_SIZE_NORM +2);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending deauthentication %s \n", pcap_geterr(pcapin));
	internalpcaperrors++;
	}

mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
return ;
}
/*===========================================================================*/
int sort_by_time(const void *a, const void *b)
{
apl_t *ia = (apl_t *)a;
apl_t *ib = (apl_t *)b;

return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
bool checkaphds(uint8_t *mac_ap)
{
aphdl_t *zeiger;
int c;

zeiger = accesspointhdliste;
for(c = 0; c < APHDLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (zeiger->hdc == establishedhandshakes))
		return true;
	if(memcmp(&nullmac, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
return false;
}
/*===========================================================================*/
bool checkapstahds(uint8_t *mac_ap,  uint8_t *mac_sta)
{
aphdl_t *zeiger;
int c;

zeiger = accesspointhdliste;
for(c = 0; c < APHDLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (memcmp(mac_sta, zeiger->addr_sta.addr, 6) == 0) && (zeiger->hdc == establishedhandshakes))
		return true;
	if(memcmp(&nullmac, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
return false;
}
/*===========================================================================*/
void addaphds(time_t tvsec, uint8_t *mac_ap,  uint8_t *mac_sta)
{
aphdl_t *zeiger;
int c;

zeiger = accesspointhdliste;
for(c = 0; c < APHDLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (memcmp(mac_sta, zeiger->addr_sta.addr, 6) == 0))
		{
		zeiger->tv_sec = tvsec;
		if(zeiger->hdc == establishedhandshakes)
			return;
		zeiger->hdc += 1;
		return;
		}
	if(memcmp(&nullmac, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
memcpy(zeiger->addr_sta.addr, mac_sta, 6);
zeiger->hdc = 1;
qsort(accesspointhdliste, APHDLISTESIZEMAX +1, APHDL_SIZE, sort_by_time);
return;
}
/*===========================================================================*/
bool handleaps(time_t tvsec, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
apl_t *zeiger;
int c;

zeiger = accesspointliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		zeiger->tv_sec = tvsec;
		return true;
		}
	if(memcmp(&nullmac, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essid_len;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essidname, essid_len);
qsort(accesspointliste, APLISTESIZEMAX +1, APL_SIZE, sort_by_time);
return false;
}
/*===========================================================================*/
bool handleapsrnd(time_t tvsec, uint8_t *mac_sta, uint8_t essid_len, uint8_t **essidname)
{
apl_t *zeiger;
int c;

zeiger = accesspointliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if((zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		zeiger->tv_sec = tvsec;
		if(respondflag == true)
			sendproberesponse(mac_sta, zeiger->addr_ap.addr, essid_len, essidname);
		lastbeaconessid_len = essid_len;
		memcpy(lastbeaconessid, essidname, essid_len);
		memcpy(lastbeaconap.addr, zeiger->addr_ap.addr, 6);
		return true;
		}
	if(memcmp(&nullmac, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
nextmac();
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_ap.addr, &myaddr, 6);
if(respondflag == true)
	sendproberesponse(mac_sta, zeiger->addr_ap.addr, essid_len, essidname);
zeiger->essid_len = essid_len;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essidname, essid_len);
lastbeaconessid_len = essid_len;
memcpy(lastbeaconessid, essidname, essid_len);
memcpy(lastbeaconap.addr, zeiger->addr_ap.addr, 6);
qsort(accesspointliste, APLISTESIZEMAX +1, APL_SIZE, sort_by_time);
return false;
}
/*===========================================================================*/
/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	pcap_dump_flush(pcapout);
	pcap_dump_close(pcapout);
	pcap_close(pcapin);
	printf("\nterminated...\e[?25h\n");
	exit (EXIT_SUCCESS);
	}
return;
}
/*===========================================================================*/
timer_t create_timer(int signo)
{
timer_t timerid;
struct sigevent se;
se.sigev_notify=SIGEV_SIGNAL;
se.sigev_signo = signo;
if(timer_create(CLOCK_REALTIME, &se, &timerid) == -1)
	{
	perror("failed to create timer");
	exit(EXIT_FAILURE);
	}
return timerid;
}
/*===========================================================================*/
void set_timer(timer_t timerid, int seconds, long int nanoseconds)
{
struct itimerspec timervals;
timervals.it_value.tv_sec = seconds;
timervals.it_value.tv_nsec = nanoseconds;
timervals.it_interval.tv_sec = seconds;
timervals.it_interval.tv_nsec = nanoseconds;

if(timer_settime(timerid, 0, &timervals, NULL) == -1)
	{
	perror("failed to start timer");
	exit(EXIT_FAILURE);
	}
return;
}
/*===========================================================================*/
void install_sighandler(int signo, void(*handler)(int))
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
void signal_handler(int signo)
{
if(signo == TT_SIGUSR1)
	{
#ifdef DOGPIOSUPPORT
	digitalWrite(0, HIGH);
	delay (25);
	digitalWrite(0, LOW);
	delay (25);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		pcap_dump_flush(pcapout);
		pcap_dump_close(pcapout);
		pcap_close(pcapin);
		system("poweroff");
		}
#endif
	return;
	}

if(signo == TT_SIGUSR2)
	{
	pcap_breakloop(pcapin);
	return;
	}
return;
}
/*===========================================================================*/
void setchannel()
{
struct iwreq wrq;

int sock = 0;
int result = 0;
memset(&wrq, 0, sizeof(struct iwreq));
strncpy(wrq.ifr_name, interfacename , IFNAMSIZ);
if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
        fprintf(stderr, "socket open for ioctl() on '%s' failed with '%d'\n", interfacename, sock);
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	programmende(SIGINT);
	return;
	}

wrq.u.freq.m = channellist[chptr];
wrq.u.freq.e = 0;
wrq.u.freq.flags = IW_FREQ_FIXED;
if(ioctl(sock, SIOCSIWFREQ, &wrq) < 0)
	{
	usleep(100);
	if((result = ioctl(sock, SIOCSIWFREQ, &wrq)) < 0)
		{
		fprintf(stderr, "ioctl(SIOCSIWFREQ) on '%s' failed with '%d'\n", interfacename, result);
		fprintf(stderr, "unable to set channel %d on '%s'\n", channellist[chptr], interfacename);
#ifdef DOGPIOSUPPORT
		system("reboot");
#endif
		programmende(SIGINT);
		}
	}
close(sock);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
void pcaploop(int has_rth)
{
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
struct pcap_pkthdr *pkh;
rth_t *rth = NULL;
mac_t *macf = NULL;
essid_t *essidf;
eapext_t *eapext = NULL;
uint8_t	*payload = NULL;
uint8_t field = 0;
authf_t *authenticationreq = NULL;
int pcapstatus = 1;
int macl = 0;
int fcsl = 0;
eap_t *eap = NULL;
uint8_t mkey;
unsigned long long int replaycount;
mpdu_frame_t *enc = NULL;
ipv4_frame_t *ipv4h = NULL;
ipv6_frame_t *ipv6h = NULL;
int beaconcount = 0;
unsigned long long int receivepacketcount = 0;
adr_t lastap;
hds_t akthds;

memset(&akthds, 0, HDS_SIZE);
if(wantstatusflag == true)
	printf("\e[?25lstart capturing on channel %d using mac_ap %06llx%06llx (stop with ctrl+c)...\n", channellist[chptr], myoui, mynic);
while(1)
	{
	pcapstatus = pcap_next_ex(pcapin, &pkh, &packet);
	if(pcapstatus == 0)
		continue;

	if(pcapstatus == -1)
		{
		fprintf(stderr, "pcap read error: %s \n", pcap_geterr(pcapin));
		internalpcaperrors++;
		if((maxerrorcount > 0) && (internalpcaperrors >= maxerrorcount))
			system("reboot");
		continue;
		}

	if(pcapstatus == -2)
		{
		chptr++;
		if(chptr >= chlistende)
			chptr = 0;
		setchannel();
		if(sendundirectedprflag == true)
			sendundirectedpr();

		if(wantstatusflag == true)
			printf("channel: % 3d, received packets: %llu, pcaperrors: %d               \r", channellist[chptr], receivepacketcount, internalpcaperrors);
		continue;
		}

	if(pkh->caplen != pkh->len)
		continue;

	/* check radiotap-header */
	h80211 = packet;
	if(has_rth == true)
		{
		if(RTH_SIZE > pkh->len)
			continue;
		rth = (rth_t*)packet;
		fcsl = 0;
		field = 12;
		if((rth->it_present & 0x01) == 0x01)
			field += 8;
		if((rth->it_present & 0x80000000) == 0x80000000)
			field += 4;
		if((rth->it_present & 0x02) == 0x02)
			{
			if((packet[field] & 0x10) == 0x10)
				fcsl = 4;
			}
		pkh->caplen -= rth->it_len +fcsl;
		pkh->len -=  rth->it_len +fcsl;
		h80211 = packet + rth->it_len;
		}

	macf = (mac_t*)(h80211);
	if((macf->to_ds == 1) && (macf->from_ds == 1))
		macl = MAC_SIZE_LONG;
	else
		macl = MAC_SIZE_NORM;

	if(MAC_SIZE_NORM > pkh->len)
		continue;

	if (macf->type == MAC_TYPE_CTRL)
		{
		if (macf->subtype == MAC_ST_RTS)
			macl = MAC_SIZE_RTS;
		else
			{
			if (macf->subtype == MAC_ST_ACK)
				macl = MAC_SIZE_ACK;
			}
		}
	 else
		{
		if (macf->type == MAC_TYPE_DATA)
			if (macf->subtype & MAC_ST_QOSDATA)
				macl += QOS_SIZE;
		}

	receivepacketcount++;

	if(beaconingflag == true)
		{
		beaconcount++;
		if(beaconcount == BEACONCOUNT)
			{
			if(lastbeaconessid_len != 0)
				sendbeacon(lastbeaconap.addr, lastbeaconessid_len, lastbeaconessid);
			beaconcount = 0;
			}
		}

	payload = ((uint8_t*)macf)+macl;

	/* check management frames */
	if(macf->type == MAC_TYPE_MGMT)
		{
		if(macf->subtype == MAC_ST_BEACON)
			{
			if(memcmp(macf->addr2.addr, &myaddr, 3) == 0)
				continue;
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->essid[0] == 0)
				continue;
			if(handleaps(pkh->ts.tv_sec, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if(deauthflag == false)
				continue;
			if(memcmp(&lastap.addr, macf->addr2.addr, 6) == 0)
				continue;
			memcpy(lastap.addr, macf->addr2.addr, 6);
			if(checkaphds(macf->addr2.addr) == false)
				send_deauthentication(MAC_ST_DEAUTH, WLAN_REASON_PREV_AUTH_NOT_VALID, macf->addr1.addr, macf->addr2.addr);
			continue;
			}

		else if(macf->subtype == MAC_ST_PROBE_RESP)
			{
			if(memcmp(macf->addr2.addr, &myaddr, 3) == 0)
				continue;
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->essid[0] == 0)
				continue;
			if(handleaps(pkh->ts.tv_sec, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			continue;
			}

		else if(macf->subtype == MAC_ST_PROBE_REQ)
			{
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->essid[0] == 0)
				continue;
			if(memcmp(&broadcastmac, macf->addr1.addr, 6) != 0)
				{
				if(handleaps(pkh->ts.tv_sec, macf->addr1.addr, essidf->info_essid_len, essidf->essid) == false)
					pcap_dump((u_char *) pcapout, pkh, h80211);
				if(respondflag == true)
					sendproberesponse(macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
				lastbeaconessid_len = essidf->info_essid_len;
				memcpy(lastbeaconessid, essidf->essid, essidf->info_essid_len);
				memcpy(lastbeaconap.addr, macf->addr1.addr, 6);
				}
			else
				{
				if(handleapsrnd(pkh->ts.tv_sec, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
					pcap_dump((u_char *) pcapout, pkh, h80211);
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_ASSOC_REQ)
			{
			if((macl +ASSOCIATIONREQF_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +ASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->essid[0] == 0)
				continue;
			pcap_dump((u_char *) pcapout, pkh, h80211);
			if(respondflag == true)
				{
				sendacknowledgement(macf->addr2.addr);
				sendassociationresponse(MAC_ST_ASSOC_RESP, macf->addr2.addr, macf->addr1.addr);
				sendkey1(macf->addr2.addr, macf->addr1.addr);
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_REASSOC_REQ)
			{
			if((macl +REASSOCIATIONREQF_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +REASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->essid[0] == 0)
				continue;
			pcap_dump((u_char *) pcapout, pkh, h80211);
			if(respondflag == true)
				{
				sendacknowledgement(macf->addr2.addr);
				sendassociationresponse(MAC_ST_REASSOC_RESP, macf->addr2.addr, macf->addr1.addr);
				sendkey1(macf->addr2.addr, macf->addr1.addr);
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_AUTH)
			{
			authenticationreq = (authf_t*)(payload);
			if(authenticationreq->authentication_seq == 1)
				{
				if(respondflag == true)
					{
					sendacknowledgement(macf->addr2.addr);
					sendauthentication(macf->addr2.addr, macf->addr1.addr);
					}
				}
			continue;
			}
		continue;
		}

	if((macf->type != MAC_TYPE_DATA) || (macl +LLC_SIZE > pkh->len))
		continue;

	if((((llc_t*)payload)->dsap != LLC_SNAP) || (((llc_t*)payload)->ssap != LLC_SNAP))
		{
		if(macf->protected == 1)
			{
			enc = (mpdu_frame_t*)(payload);
			if((wepdataflag == true) && (((enc->keyid >> 5) &1) == 0))
				pcap_dump((u_char *) pcapout, pkh, h80211);
			continue;
			}
		continue;
		}
	/* check handshake frames */
	if((ntohs(((llc_t*)payload)->type) == LLC_TYPE_AUTH))
		{
		eap = (eap_t*)(payload + LLC_SIZE);
		if(eap->type == 3)
			{
			pcap_dump((u_char *) pcapout, pkh, h80211);
			pcap_dump_flush(pcapout);
			mkey = geteapkey(eap);
			replaycount = getreplaycount(eap);
			if((mkey == WPA_M1) && (replaycount == MYREPLAYCOUNT))
				continue;
			else if((mkey == WPA_M2) && (replaycount == MYREPLAYCOUNT))
				{
				if(wantstatusflag == true)
					{
					if(macf->retry == 1)
						printmac(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, "M1M2 handshake (forced-retransmission)");
					else	
						printmac(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, "M1M2 handshake (forced)");
					}
				akthds.af |= WPA_M1;
				}
			else if((mkey == WPA_M1) && (replaycount != MYREPLAYCOUNT))
				{
				memset(&akthds, 0, HDS_SIZE);
				akthds.tv_sec1 = pkh->ts.tv_sec;
				memcpy(&akthds.addr_ap1, macf->addr2.addr, 6);
				memcpy(&akthds.addr_sta1, macf->addr1.addr, 6);
				akthds.m1 = mkey;
				akthds.rc1 = replaycount;
				}
			else if((mkey == WPA_M2) && (replaycount != MYREPLAYCOUNT))
				{
				akthds.tv_sec2 = pkh->ts.tv_sec;
				memcpy(&akthds.addr_ap2, macf->addr1.addr, 6);
				memcpy(&akthds.addr_sta2, macf->addr2.addr, 6);
				akthds.m2 = mkey;
				akthds.rc2 = replaycount;
				if((akthds.tv_sec2 == akthds.tv_sec1) && (akthds.m1 == WPA_M1) && (akthds.rc2 == akthds.rc1) && (memcmp(&akthds.addr_ap1, &akthds.addr_ap2, 6) == 0) && (memcmp(&akthds.addr_sta1, &akthds.addr_sta2, 6) == 0))
					{
					if(wantstatusflag == true)
						printmac(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, "M1M2 handshake (not verified)");
					akthds.af |= WPA_M2;
					}
				else
					{
					memset(&akthds, 0, HDS_SIZE);
					}
				}
			else if(mkey == WPA_M3)
				{
				akthds.tv_sec3 = pkh->ts.tv_sec;
				memcpy(&akthds.addr_ap3, macf->addr2.addr, 6);
				memcpy(&akthds.addr_sta3, macf->addr1.addr, 6);
				akthds.m3 = mkey;
				akthds.rc3 = replaycount;
				if((akthds.tv_sec3 == akthds.tv_sec2) && (akthds.m2 == WPA_M2) && (akthds.rc3 == (akthds.rc2 +1)) && (memcmp(&akthds.addr_ap2, &akthds.addr_ap3, 6) == 0) && (memcmp(&akthds.addr_sta2, &akthds.addr_sta3, 6) == 0))
					{
					if(wantstatusflag == true)
						printmac(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, "M2M3 handshake (verified)");
					akthds.af |= WPA_M3;
					}
				else
					{
					memset(&akthds, 0, HDS_SIZE);
					}
				}
			else if(mkey == WPA_M4)
				{
				if((pkh->ts.tv_sec == akthds.tv_sec3) && (akthds.m3 == WPA_M3) && (replaycount == akthds.rc3) && (memcmp(&akthds.addr_ap3, macf->addr1.addr, 6) == 0) && (memcmp(&akthds.addr_sta3, macf->addr2.addr, 6) == 0))
					{
					if(wantstatusflag == true)
						printmac(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, "M3M4 handshake (established)");
					akthds.af |= WPA_M4;
					}
				if((akthds.af &6) == 6)
					addaphds(pkh->ts.tv_sec, macf->addr1.addr, macf->addr2.addr);
				if(checkapstahds(macf->addr1.addr, macf->addr2.addr) == false)
					{
					if(disassocflag == true)
						send_deauthentication(MAC_ST_DISASSOC, WLAN_REASON_DISASSOC_AP_BUSY, macf->addr2.addr, macf->addr1.addr);
					akthds.af |= WPA_M4;
					}
				memset(&akthds, 0, HDS_SIZE);
				}
			continue;
			}
		else if(eap->type == 0)
			{
			eapext = (eapext_t*)(payload + LLC_SIZE);

			if(eapext->eaptype == EAP_TYPE_ID)
				{
				if(wantstatusflag == true)
					printidentity(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, eapext->eapcode, eapext);
				}
			else if(eapext->eaptype == EAP_TYPE_EXPAND)
				handlewps(macf->addr1.addr, macf->addr2.addr, macf->to_ds, macf->from_ds, eapext);
			pcap_dump((u_char *) pcapout, pkh, h80211);
			pcap_dump_flush(pcapout);
			continue;
			}
		else if(eap->type == 1)
			{
//			pcap_dump((u_char *) pcapout, pkh, h80211);
			if(eap->len == 0)
				{
				if(respondflag == true)
					{
					sendacknowledgement(macf->addr2.addr);
					sendrequestidentity(macf->addr2.addr, macf->addr1.addr);
					}
				}
			continue;
			}
		}
	else if((ntohs(((llc_t*)payload)->type) == LLC_TYPE_IPV4))
		{
		if(pkh->len < (macl +LLC_SIZE +IPV4_SIZE_MIN +GRE_MIN_SIZE +PPP_SIZE +PPPCHAPHDR_MIN_CHAL_SIZE))
			continue;
		ipv4h = (ipv4_frame_t*)(payload +LLC_SIZE);
		if((ipv4h->ver_hlen & 0xf0) != 0x40)
			continue;
		if(ipv4h->nextprotocol == NEXTHDR_NONE)
			continue;
		if(ipv4h->nextprotocol == NEXTHDR_GRE)
			{
			pcap_dump((u_char *) pcapout, pkh, h80211);
			pcap_dump_flush(pcapout);
			continue;
			}
		}
	else if((ntohs(((llc_t*)payload)->type) == LLC_TYPE_IPV6))
		{
		if(pkh->len < (macl +LLC_SIZE +IPV6_SIZE +GRE_MIN_SIZE +PPP_SIZE +PPPCHAPHDR_MIN_CHAL_SIZE))
			continue;
		ipv6h = (ipv6_frame_t*)(payload +LLC_SIZE);
		if((ntohl(ipv6h->ver_class) & 0xf) != 6)
			continue;
		if(ipv6h->nextprotocol == NEXTHDR_NONE)
			continue;
		if(ipv6h->nextprotocol == NEXTHDR_GRE)
			{
			pcap_dump((u_char *) pcapout, pkh, h80211);
			pcap_dump_flush(pcapout);
			continue;
			}
		}
	}
}
/*===========================================================================*/
void installbpf(pcap_t *pcapin, char *externalbpfname)
{
struct stat statinfo;
struct bpf_program filter;
FILE *fhbpf;
int bpfsize = 0;

char *extfilterstring = NULL;

char pcaperrorstring[PCAP_ERRBUF_SIZE];


if(externalbpfname != NULL)
	{
	if(stat(externalbpfname, &statinfo) != 0)
		{
		fprintf(stderr, "can't stat BPF %s\n", externalbpfname);
		exit(EXIT_FAILURE);
		}
	if((fhbpf = fopen(externalbpfname, "r")) == NULL)
		{
		fprintf(stderr, "error opening BPF %s\n", externalbpfname);
		exit(EXIT_FAILURE);
		}
	extfilterstring = malloc(statinfo.st_size +1);
	if(extfilterstring == NULL)
		{
		fprintf(stderr, "out of memory to store BPF\n");
		fclose(fhbpf);
		exit(EXIT_FAILURE);
		}
	extfilterstring[statinfo.st_size] = 0;
	bpfsize = fread(extfilterstring, 1, statinfo.st_size, fhbpf);
	fclose(fhbpf);
	if(bpfsize != statinfo.st_size)
		{
		fprintf(stderr, "error reading BPF %s\n", externalbpfname);
		free(extfilterstring);
		exit(EXIT_FAILURE);
		}
	filterstring = extfilterstring;
	}

if(pcap_compile(pcapin, &filter, filterstring, 1, 0) < 0)
	{
	fprintf(stderr, "error compiling BPF %s \n", pcap_geterr(pcapin));
	exit(EXIT_FAILURE);
	}

if(pcap_setfilter(pcapin, &filter) < 0)
	{
	sprintf(pcaperrorstring, "error installing BPF ");
	pcap_perror(pcapin, pcaperrorstring);
	exit(EXIT_FAILURE);
	}

pcap_freecode(&filter);

if(extfilterstring != NULL)
	free(extfilterstring);

return;
}
/*===========================================================================*/
bool startcapturing(char *pcapoutname, char *externalbpfname)
{
struct stat statinfo;
pcap_t *pcapdh = NULL;
int datalink = 0;
int c = 0;
int has_rth = false;

char newpcapoutname[PATH_MAX +2];
char pcaperrorstring[PCAP_ERRBUF_SIZE];

if(pcapoutname == NULL)
	{
	fprintf(stderr, "no output file selected\n");
	exit(EXIT_FAILURE);
	}

pcapin = pcap_open_live(interfacename, 65535, 1, 5, pcaperrorstring);
if(pcapin == NULL)
	{
	fprintf(stderr, "error opening device %s: %s\n", interfacename, pcaperrorstring);
	exit(EXIT_FAILURE);
	}

datalink = pcap_datalink(pcapin);
	if (datalink == DLT_IEEE802_11_RADIO)
		has_rth = true;

installbpf(pcapin, externalbpfname);

strcpy(newpcapoutname, pcapoutname);
while(stat(newpcapoutname, &statinfo) == 0)
	{
	snprintf(newpcapoutname, PATH_MAX, "%s-%d.cap", pcapoutname, c);
	c++;
	}
pcapdh = pcap_open_dead(DLT_IEEE802_11, 65535);
if ((pcapout = pcap_dump_open(pcapdh, newpcapoutname)) == NULL)
	{
	fprintf(stderr, "error creating dump file %s\n", newpcapoutname);
	exit(EXIT_FAILURE);
	}

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

setchannel();

signal(SIGINT, programmende);

timer1 = create_timer(TT_SIGUSR1);
timer2 = create_timer(TT_SIGUSR2);

install_sighandler(TT_SIGUSR1, signal_handler);
install_sighandler(TT_SIGUSR2, signal_handler);

set_timer(timer1, TIME_INTERVAL_1S, TIME_INTERVAL_1NS);
set_timer(timer2, staytime, TIME_INTERVAL_2NS);

pcaploop(has_rth);
return true;
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
	"usage: %s <options>\n"
	"(ctrl+c terminates program)\n"
	"options:\n"
	"-i <interface> : WLAN interface\n"
	"-o <file>      : output cap file\n"
	"-c <channel>   : set start channel for hopping (1-13)\n"
	"               : 2.4GHz (1-13) \n"
	"               : default start channel = 1\n"
	"-C <channel>   : set start channel for hopping (1-165)\n"
	"               : 2.4GHz (1-14) \n"
	"               : 5 GHz (36, 40, 44, 48, 52, 56, 60, 64)\n"
	"               : 5 GHz (100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140)\n"
	"               : 5 GHz (149, 153, 157, 161, 165)\n"
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"               : for fixed channel operation use high value (86400 for a day)\n"
	"               : default = 5 seconds\n"
	"-T <maxerrors> : enable auto reboot after <xx> maximal pcap errors (default: disabled)\n"
	"-F <file>      : input file containing entries for Berkeley Packet Filter (BPF)\n"
	"-R             : enable to respond to all requests\n"
	"-D             : enable deauthentications\n"
	"-d             : enable disassociations\n"
	"-E <digit>     : stop deauthentications and disassociations if xx complete handshakes received\n"
	"               : default = 1 complete handshake (M1-M4)\n"
	"-U             : send one undirected proberequest to broadcast after channel change\n"
	"-B             : enable beaconig on last proberequest\n"
	"-L             : enable capture of wep encrypted data packets\n"
	"-s             : enable status messages\n"
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
pcap_if_t *alldevs, *d;
int auswahl;
uint8_t channel = 1;
char *eigenpfadname, *eigenname;
char *pcapoutname = NULL;
char *externalbpfname = NULL;

char pcaperrorstring[PCAP_ERRBUF_SIZE];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

maxerrorcount = 0;
internalpcaperrors = 0;
setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "i:o:c:C:t:T:F:E:RDdUBLshv")) != -1)
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
		pcapoutname = optarg;
		break;

		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 0)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to 1\n");
			staytime = TIME_INTERVAL_2S;
			}
		break;

		case 'T':
		maxerrorcount = strtol(optarg, NULL, 10);
		break;

		case 'c':
		channel = strtol(optarg, NULL, 10);
		for(chptr = 0; chptr < 13; chptr++)
			{
			if(channel == channellist[chptr])
				break;
			}
		if(chptr >= 13)
			{
			fprintf(stderr, "wrong channel, only 1-13 allowed\nsetting channel to default (1)\n");
			chptr = 0;
			}
		chlistende = 13;
		break;

		case 'C':
		channel = strtol(optarg, NULL, 10);
		for(chptr = 0; chptr < CHANNELLIST_SIZE; chptr++)
			{
			if(channel == channellist[chptr])
				break;
			}
		if(chptr >= CHANNELLIST_SIZE)
			{
			fprintf(stderr, "channel not allowed\nsetting channel to default (1)\n");
			chptr = 0;
			}
		chlistende = CHANNELLIST_SIZE;
		break;

		case 'F':
		externalbpfname = optarg;
		break;

		case 'E':
		establishedhandshakes = strtol(optarg, NULL, 10);
		break;

		case 'R':
		respondflag = true;
		break;

		case 'D':
		deauthflag = true;
		break;

		case 'd':
		disassocflag = true;
		break;

		case 'U':
		sendundirectedprflag = true;
		break;

		case 'B':
		beaconingflag = true;
		break;

		case 'L':
		wepdataflag = true;
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

if( getuid() != 0 )
	{
	fprintf(stderr, "this program requires root privileges\n" );
	exit(EXIT_FAILURE);
	}

if(interfacename == NULL)
	{
	fprintf(stdout,"\nno device selected - suitable devices:\n--------------------------------------\n");

	if(pcap_findalldevs(&alldevs, pcaperrorstring) == -1)
		{
		fprintf(stderr,"error in pcap_findalldevs: %s\n", pcaperrorstring);
		exit (EXIT_FAILURE);
		}

	for(d=alldevs; d; d=d->next)
		{
		fprintf(stdout, "%s", d->name);
		if(d->description)
			printf(" (%s)\n", d->description);

		else
		fprintf(stdout," (no description available)\n");
		}

	pcap_freealldevs(alldevs);
	exit (EXIT_FAILURE);
	}

if(initgloballists() != true)
	{
	fprintf(stderr, "could not allocate memory for tables\n" );
	exit (EXIT_FAILURE);
	}

if(startcapturing(pcapoutname, externalbpfname) == false)
	{
	fprintf(stderr, "could not init device\n" );
	exit (EXIT_FAILURE);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

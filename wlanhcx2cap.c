#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <pcap.h>
#include <sys/stat.h>
#include <stdio_ext.h>
#include <curl/curl.h>
#include "common.h"


#define MAXPCAPOUT     50
#define HANDSHAKELEVEL 50
#define HANDSHAKEART1	1
#define HANDSHAKEART2	2
#define HANDSHAKEART3	3
#define HANDSHAKEART4	4

/*===========================================================================*/
/* globale Variablen */

/*===========================================================================*/
void printhex(const uint8_t *buffer, int size)
{
int c, d;
d = 0;
for (c = 0; c < size; c++)
	{
	fprintf(stdout, "%02x", buffer[c]);
	d++;
	if((d == 32) && (size > 32))
		{
		fprintf(stdout,"\n                 ");
		d = 0;
		}
	}
fprintf(stdout," ");
return;
}
/*===========================================================================*/
unsigned long long int getreplaycount(uint8_t *eapdata)
{
eap_t *eap;
unsigned long long int replaycount = 0;

eap = (eap_t*)(uint8_t*)(eapdata);
replaycount = be64toh(eap->replaycount);
return replaycount;
}
/*===========================================================================*/
uint8_t geteapkey(uint8_t *eapdata)
{
eap_t *eap;
uint16_t keyinfo;
int eapkey = 0;

eap = (eap_t*)(uint8_t*)(eapdata);
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
void pcapwritepaket(pcap_dumper_t *pcapdump, hcx_t *zeigersend)
{
struct pcap_pkthdr pkhdump;
struct timeval tv1;
int pp;
int tc;
int essidlen;
unsigned long long int replaycount;
uint8_t keynr;
u_int64_t timestamp;

uint8_t beaconwpa[] = {
0x01, 0x04, 0x82, 0x84, 0x8b, 0x96,
0x03, 0x01, 0x0b,
0x05, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x2a, 0x01, 0x04,
0x32, 0x08, 0x0c, 0x12, 0x18, 0x24, 0x30, 0x48, 0x60, 0x6c,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x00,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x80, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00 };

uint8_t beaconwpa2[] = {
0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
0x03, 0x01, 0x06,
0x05, 0x04, 0x00, 0x01, 0x00, 0x0a,
0x2a, 0x01, 0x00,
0x30, 0x14, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x04, 0x01, 0x00, 0x00, 0x0f, 0xac, 0x02, 0x00, 0x00,
0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x00, 0x00, 0x50, 0xf2, 0x02,
0x32, 0x04, 0x30, 0x48, 0x60, 0x6c,
0xdd, 0x18, 0x00, 0x50, 0xf2, 0x02, 0x01, 0x01, 0x04, 0x00, 0x03, 0xa4, 0x00, 0x00, 0x27, 0xa4, 0x00, 0x00, 0x42, 0x43, 0x5e, 0x00, 0x62, 0x32, 0x2f, 0x00,
0x2d, 0x1a, 0xce, 0x13, 0x1b, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x3d, 0x16, 0x06, 0x07, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0xdd, 0x09, 0x00, 0x03, 0x7f, 0x01, 0x01, 0x00, 0x00, 0xff, 0x7f,
0xdd, 0x0c, 0x00, 0x04, 0x0e, 0x01, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };

const uint8_t anonce[] = {
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e,
0x01, 0x03, 0x00, 0x5f, 0x02, 0x00, 0x8a, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

const uint8_t snonce[] = {
0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e };

uint8_t mypacket[0xfff];

/* beacon */
pp = 0;
gettimeofday( &tv1,  NULL );
pkhdump.ts.tv_sec = tv1.tv_sec;
pkhdump.ts.tv_usec = tv1.tv_usec;
memset(&mypacket[pp] , 0 , 0xfff);
mypacket[pp + 0x00] = 0x80;
mypacket[pp + 0x02] = 0x3a;
mypacket[pp + 0x03] = 0x01;
mypacket[pp + 0x04] = 0xff;
mypacket[pp + 0x05] = 0xff;
mypacket[pp + 0x06] = 0xff;
mypacket[pp + 0x07] = 0xff;
mypacket[pp + 0x08] = 0xff;
mypacket[pp + 0x09] = 0xff;
memcpy(&mypacket[0x0a], zeigersend->mac_ap.addr, 6);
memcpy(&mypacket[0x10], zeigersend->mac_ap.addr, 6);
mypacket[pp + 0x16] = 0;
mypacket[pp + 0x17] = 0;
pp += 0x18;
timestamp=tv1.tv_sec*1000000UL + tv1.tv_usec;
for(tc = 0; tc < 8; tc++)
	{
	mypacket[pp] = (timestamp >> (tc * 8)) & 0xFF;
	pp ++;
	}
mypacket[pp + 0x00] = 0x3a;
mypacket[pp + 0x01] = 0x01;
mypacket[pp + 0x02] = 0x31;
mypacket[pp + 0x03] = 0x04;
pp += 4;
mypacket[pp + 0x00] = 0x00;
pp++;
essidlen = 0;
while(zeigersend->essid[essidlen] != 0)
	essidlen++;
mypacket[pp + 0x00] = essidlen;
pp++;
memcpy(&mypacket[pp], zeigersend->essid, essidlen);
pp += essidlen;
if(zeigersend->eapol[0x04] == 0xfe)
	{
	memcpy(&mypacket[pp], &beaconwpa, sizeof(beaconwpa));
	pp += sizeof(beaconwpa);
	}
else
	{
	memcpy(&mypacket[pp], &beaconwpa2, sizeof(beaconwpa2));
	pp += sizeof(beaconwpa2);
	}
pkhdump.caplen = pp;
pkhdump.len = pp;
pcap_dump((u_char *) pcapdump, &pkhdump, mypacket);

/* anonce */
pp = 0;
gettimeofday( &tv1,  NULL );
pkhdump.ts.tv_sec = tv1.tv_sec;
pkhdump.ts.tv_usec = tv1.tv_usec;
memset(&mypacket[pp] , 0 , 0xfff);
mypacket[pp + 0x00] = 0x88;
mypacket[pp + 0x01] = 0x02;
mypacket[pp + 0x02] = 0x3a;
mypacket[pp + 0x03] = 0x01;
memcpy(&mypacket[0x04], zeigersend->mac_sta.addr, 6);
memcpy(&mypacket[0x0a], zeigersend->mac_ap.addr, 6);
memcpy(&mypacket[0x10], zeigersend->mac_ap.addr, 6);
pp += 0x1a;
memcpy(&mypacket[pp], anonce, 32);
mypacket[pp + 0x08] = zeigersend->eapol[0x00];
mypacket[pp + 0x0c] = zeigersend->eapol[0x04];
mypacket[pp + 0x0e] = zeigersend->eapol[0x06] | 0x80;

keynr = geteapkey(zeigersend->eapol);
if(keynr == 4)
	{
	replaycount = getreplaycount(zeigersend->eapol) -1;
	mypacket[pp + 0x11] = (int)((replaycount >> 56) & 0xFF) ;
	mypacket[pp + 0x12] = (int)((replaycount >> 48) & 0xFF) ;
	mypacket[pp + 0x13] = (int)((replaycount >> 40) & 0xFF) ;
	mypacket[pp + 0x14] = (int)((replaycount >> 32) & 0xFF) ;
	mypacket[pp + 0x15] = (int)((replaycount >> 24) & 0xFF) ;
	mypacket[pp + 0x16] = (int)((replaycount >> 16) & 0xFF) ;
	mypacket[pp + 0x17] = (int)((replaycount >> 8) & 0XFF);
	mypacket[pp + 0x18] = (int)((replaycount & 0XFF));
	}
else
	memcpy(&mypacket[pp + 0x11], &zeigersend->eapol[0x09], 8);

if(memcmp(&zeigersend->eapol[0x11], zeigersend->nonce_sta, 32) == 0)
	memcpy(&mypacket[pp + 0x19], zeigersend->nonce_ap, 32);
else
	memcpy(&mypacket[pp + 0x19], zeigersend->nonce_sta, 32);
pkhdump.caplen = 0x85;
pkhdump.len = 0x85;
pcap_dump((u_char *) pcapdump, &pkhdump, mypacket);

/* snonce */
pp = 0;
gettimeofday( &tv1,  NULL );
pkhdump.ts.tv_sec = tv1.tv_sec;
pkhdump.ts.tv_usec = tv1.tv_usec;
memset(&mypacket[pp] , 0 , 0xfff);
mypacket[pp + 0x00] = 0x88;
mypacket[pp + 0x01] = 0x01;
mypacket[pp + 0x02] = 0x3a;
mypacket[pp + 0x03] = 0x01;
memcpy(&mypacket[0x04], zeigersend->mac_ap.addr, 6);
memcpy(&mypacket[0x0a], zeigersend->mac_sta.addr, 6);
memcpy(&mypacket[0x10], zeigersend->mac_ap.addr, 6);
pp += 0x1a;
memcpy(&mypacket[pp], snonce, 32);
memcpy(&mypacket[0x22], zeigersend->eapol, zeigersend->eapol_len);
memcpy(&mypacket[0x73], zeigersend->keymic, 16);
pkhdump.caplen = zeigersend->eapol_len + 0x26;
pkhdump.len = zeigersend->eapol_len + 0x26;
pcap_dump((u_char *) pcapdump, &pkhdump, mypacket);
pcap_dump_flush(pcapdump);
return;
}
/*===========================================================================*/
bool mac12checkdouble(hcx_t *zeiger, long int akthccapset, long int hccapsets)
{
hcx_t *zeigertest = zeiger;
int p;
for(p = akthccapset +1; p < hccapsets; p++)
	{
	zeigertest++;
	if((memcmp(zeigertest->mac_ap.addr, zeiger->mac_ap.addr, 6) == 0) && (memcmp(zeigertest->mac_sta.addr, zeiger->mac_sta.addr, 6) == 0) && (zeigertest->message_pair == zeiger->message_pair))
		return true;

	return false;
	}
return false;
}
/*===========================================================================*/
void mac2macstring(char ssid[13], unsigned char *p)
{
sprintf(ssid, "%02x%02x%02x%02x%02x%02x",p[0],p[1],p[2],p[3],p[4],p[5]);
return;
}
/*===========================================================================*/
void writecap(char *capoutname, long int hccapsets, hcx_t *hccapxdata)
{
int p;
int pcapcount = 0;
uint8_t keynr = 0;
hcx_t *zeiger;

pcap_dumper_t *pcapdump;
pcap_t *pcapdh;

char macstr_ap[PATH_MAX +1];
char macstr_sta[PATH_MAX +1];
char pcapoutstr[PATH_MAX +2];

zeiger = hccapxdata;
for(p = 0; p < hccapsets; p++)
	{
	if((zeiger->message_pair & 0x80) == 0x80)
		{
		zeiger++;
		continue;
		}

	keynr = geteapkey(zeiger->eapol);
	if((keynr != 3) && (zeiger->eapol_len >= 91) && (zeiger->eapol_len <= sizeof(zeiger->eapol)))
		{
		mac2macstring(macstr_ap, zeiger->mac_ap.addr);
		mac2macstring(macstr_sta, zeiger->mac_sta.addr);
		if(memcmp(&mynonce, zeiger->nonce_ap, 32) == 0)
			sprintf(pcapoutstr, "%s-%s-%s-wf.cap", capoutname, macstr_ap, macstr_sta);

		else
			sprintf(pcapoutstr, "%s-%s-%s-%d.cap", capoutname, macstr_ap, macstr_sta, zeiger->message_pair);

		pcapdh = pcap_open_dead(DLT_IEEE802_11, 65535);
		if((pcapdump = pcap_dump_open(pcapdh, pcapoutstr)) != NULL)
			{
			pcapwritepaket(pcapdump, zeiger);
			pcapcount++;
			pcap_dump_close(pcapdump);
			}
		else
			{
			fprintf(stderr, "error opening dump file %s\n", pcapoutstr);
			}
		}
	zeiger++;
	}

printf("%d pcap(s) written\n", pcapcount);
return;
}
/*===========================================================================*/
bool hccapx2cap(char *hccapxinname, char *capoutname)
{
struct stat statinfo;
hcx_t *hccapxdata;
FILE *fhhccapx;
long int hccapxsize;
long int hccapsets;


if(hccapxinname == NULL)
	return false;

if(stat(hccapxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hccapxinname);
	return false;
	}

if(statinfo.st_size % sizeof(hcx_t) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return false;
	}

if((fhhccapx = fopen(hccapxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapxinname);
	return false;
	}

hccapxdata = malloc(statinfo.st_size);
if(hccapxdata == NULL)	
		{
		fprintf(stderr, "--> out of memory to store hccapx file\n");
		return false;
		}

hccapxsize = fread(hccapxdata, 1, statinfo.st_size, fhhccapx);
if(hccapxsize != statinfo.st_size)	
	{
	fprintf(stderr, "error reading hccapx file %s", hccapxinname);
	return false;
	}
fclose(fhhccapx);
hccapsets = hccapxsize / sizeof(hcx_t);
printf("%ld records read from %s\n", hccapxsize / sizeof(hcx_t), hccapxinname);

writecap(capoutname, hccapsets, hccapxdata);

return true;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file>   : input hccapx file\n"
	"-o <prefix> : output prefix cap file (mac_ap - mac_sta - messagepair or wf.cap is added to the prefix)\n"
	"            : prefix - mac_ap - mac_sta - messagepair or wf (wlandumpforced handshake).cap\n"
	"            : example: pfx-xxxxxxxxxxxx-xxxxxxxxxxxx-xx\n"
	"-h          : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hccapxinname = NULL;
char *capoutname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:m:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hccapxinname = optarg;
		break;

		case 'o':
		capoutname = optarg;
		break;

		case 'h':
		usage(eigenname);
		break;

		case 'v':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

if(capoutname != NULL)
	hccapx2cap(hccapxinname, capoutname);
else
	printf("no prefix for out file selected\n");

return EXIT_SUCCESS;
}

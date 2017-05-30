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


#define MAXPCAPOUT 20
#define HANDSHAKELEVEL 50
#define HANDSHAKEART1	1
#define HANDSHAKEART2	2
#define HANDSHAKEART3	3
#define HANDSHAKEART4	4
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
void pcapwritepaket(pcap_dumper_t *pcapdump, hcx_t *zeigersend)
{
struct pcap_pkthdr pkhdump;
struct timeval tv1;
int pp;
int tc;
int essidlen;
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

if((zeigersend->message_pair & 0x80) == 0x80)
	return;

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
int mac12checkdouble(hcx_t *zeiger, long int akthccapset, long int hccapsets)
{
hcx_t *zeigertest = zeiger;
int p;
for(p = akthccapset +1; p < hccapsets; p++)
	{
	zeigertest++;
	if((memcmp(zeigertest->mac_ap.addr, zeiger->mac_ap.addr, 6) == 0) && (memcmp(zeigertest->mac_sta.addr, zeiger->mac_sta.addr, 6) == 0))
		return TRUE;

	return FALSE;
	}
return FALSE;
}
/*===========================================================================*/
int sort_by_mac12(const void *a, const void *b) 
{ 
hcx_t *ia = (hcx_t *)a;
hcx_t *ib = (hcx_t *)b;

if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta.addr, ib->mac_sta.addr, 6) < 0)
	return -1;
else return 0;	
}
/*===========================================================================*/
void writecap(char *capoutname, long int hccapsets, hcx_t *hccapxdata)
{
int p;
int pcapcount = 0;
int keyinformation;
hcx_t *zeiger;
struct stat statinfo;

pcap_dumper_t *pcapdump[MAXPCAPOUT +1];
pcap_t *pcapdh;

int lasthostcount = 1;
int maxhostcount = 0;
uint8_t lasthost[6];
char pcapoutstr[PATH_MAX +2];

qsort(hccapxdata, hccapsets, sizeof(hcx_t), sort_by_mac12);
zeiger = hccapxdata;
for(p = 0; p < hccapsets; p++)
	{
	keyinformation = (zeiger->eapol[5] << 8) + zeiger->eapol[6];
	if((! (keyinformation & WPA_KEY_INFO_ACK)) && (! (keyinformation & WPA_KEY_INFO_SECURE)))
		{
		if((mac12checkdouble(zeiger, p, hccapsets) == FALSE))
			{
			if(memcmp(lasthost, zeiger->mac_ap.addr, 6) == 0)
				lasthostcount++;
			else lasthostcount = 1;
			memcpy(lasthost, zeiger->mac_ap.addr, 6);
			if(lasthostcount > maxhostcount)
				maxhostcount = lasthostcount;
			pcapcount++;
			}
		}
	zeiger++;
	}

if(maxhostcount > MAXPCAPOUT)
	maxhostcount = MAXPCAPOUT;
	
for(p = 1; p <= MAXPCAPOUT; p++)
	{
	sprintf(pcapoutstr,"%s-%02d.cap", capoutname, p);
	pcapdh = pcap_open_dead(DLT_IEEE802_11, 65535);
	if((pcapdump[p] = pcap_dump_open(pcapdh, pcapoutstr)) == NULL)
		{
		fprintf(stderr, "error opening dump file %s\n", pcapoutstr);
		exit(EXIT_FAILURE);
		}
	}

zeiger = hccapxdata;
for(p = 0; p < hccapsets; p++)
	{
	if((zeiger->eapol[0x06] == 0x0a) || (zeiger->eapol[0x06] == 0x09))
		{
		if((mac12checkdouble(zeiger, p, hccapsets) == FALSE))
			{
			if(memcmp(lasthost, zeiger->mac_ap.addr, 6) == 0)
				lasthostcount++;
			else lasthostcount = 1;
			if(lasthostcount <= MAXPCAPOUT)
				pcapwritepaket(pcapdump[lasthostcount], zeiger);

			memcpy(lasthost, zeiger->mac_ap.addr, 6);
			pcapcount++;
			}
		}
	zeiger++;
	}

for(p = 1; p <= MAXPCAPOUT; p++)
	pcap_dump_close(pcapdump[p]);


for(p = 1; p <= MAXPCAPOUT; p++)
	{
	sprintf(pcapoutstr,"%s-%02d.cap", capoutname, p);
	stat(pcapoutstr, &statinfo);
	if((statinfo.st_size) == 24)
		remove(pcapoutstr);
	}

printf("%d pcap(s) written\n", pcapcount);
return;
}
/*===========================================================================*/
int hccapx2cap(char *hccapxinname, char *capoutname)
{
struct stat statinfo;
hcx_t *hccapxdata;
FILE *fhhccapx;
long int hccapxsize;
long int hccapsets;


if(hccapxinname == NULL)
	return FALSE;

if(stat(hccapxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hccapxinname);
	return FALSE;
	}

if(statinfo.st_size % sizeof(hcx_t) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return FALSE;
	}

if((fhhccapx = fopen(hccapxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapxinname);
	return FALSE;
	}

hccapxdata = malloc(statinfo.st_size);
if(hccapxdata == NULL)	
		{
		fprintf(stderr, "--> out of memory to store hccapx file\n");
		return FALSE;
		}

hccapxsize = fread(hccapxdata, 1, statinfo.st_size, fhhccapx);
if(hccapxsize != statinfo.st_size)	
	{
	fprintf(stderr, "error reading hccapx file %s", hccapxinname);
	return FALSE;
	}
fclose(fhhccapx);
hccapsets = hccapxsize / sizeof(hcx_t);
printf("%ld records read from %s\n", hccapxsize / sizeof(hcx_t), hccapxinname);


if(capoutname != NULL)
	writecap(capoutname, hccapsets, hccapxdata);

return TRUE;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-o <file> : output cap file\n"
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
while ((auswahl = getopt(argc, argv, "i:o:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hccapxinname = optarg;
		break;

		case 'o':
		capoutname = optarg;
		break;

		default:
		usage(eigenname);
		break;
		}
	}

hccapx2cap(hccapxinname, capoutname);


return EXIT_SUCCESS;
}

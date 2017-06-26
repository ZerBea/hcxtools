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
#include <curl/curl.h>
#include "common.h"

struct ppi_packet_header
{
 uint8_t  pph_version;
 uint8_t  pph_flags;
 uint16_t pph_len;
 uint32_t pph_dlt;
} __attribute__((packed));
typedef struct ppi_packet_header ppi_packet_header_t;

struct hc5500
{
 adr_t    mac_ap1;
 adr_t    mac_sta1;
 adr_t    mac_ap2;
 adr_t    mac_sta2;
 uint8_t  p1;
 uint8_t  p2;
 uint8_t  leapid1;
 uint8_t  leapid2;
 char     username[258];
 uint8_t  peerchallenge[8];
 uint8_t  peerresponse[24];
} __attribute__((packed));
typedef struct hc5500 hc5500_t;


struct hc4800
{
 adr_t    mac_ap1;
 adr_t    mac_sta1;
 adr_t    mac_ap2;
 adr_t    mac_sta2;
 uint8_t  id1;
 uint8_t  id2;
 uint8_t  p1;
 uint8_t  p2;

 uint8_t  challenge[16];
 uint8_t  response[16];
} __attribute__((packed));
typedef struct hc4800 hc4800_t;



/*===========================================================================*/
/* globale Variablen */

const uint8_t nullnonce[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define	NULLNONCE_SIZE (sizeof(nullnonce))

netdb_t *netdbdata = NULL;
netdb_t *newnetdbdata = NULL;
long int netdbrecords = 0;

eapdb_t *eapdbdata = NULL;
eapdb_t *neweapdbdata = NULL;

long int eapdbrecords = 0;

pcap_dumper_t *pcapout = NULL;
pcap_dumper_t *pcapextout = NULL;
pcap_dumper_t *pcapipv46out = NULL;

uint8_t netexact = FALSE;
uint8_t replaycountcheck = FALSE;
uint8_t wcflag = FALSE;
uint8_t wldflag = FALSE;
uint8_t ancflag = FALSE;
uint8_t anecflag = FALSE;

int rctimecount = 0;

hc4800_t hcmd5;
hc5500_t hcleap;

char *hcxoutname = NULL;
char *hc4800outname = NULL;
char *hc5500outname = NULL;
char *wdfhcxoutname = NULL;
char *nonwdfhcxoutname = NULL;
char *usernameoutname = NULL;

hcx_t oldhcxrecord;

/*===========================================================================*/
void initgloballists()
{
memset(&hcmd5, 0, sizeof(hc4800_t));
memset(&hcleap, 0, sizeof(hc5500_t));

return;
}
/*===========================================================================*/
void addeapmd5(uint8_t *mac_1, uint8_t *mac_2, eapext_t *eapext)
{
eapmd5_t *eapmd5 = NULL;
FILE *fhhash = NULL;
uint8_t changeflag = FALSE;
int c;

eapmd5 = (eapmd5_t*)(eapext);
if((eapmd5->eapcode == EAP_CODE_REQ) && (eapmd5->eapvaluesize == 16)) 
	{
	memcpy(&hcmd5.mac_ap1, mac_2, 6);
	memcpy(&hcmd5.mac_sta1, mac_1, 6);
	hcmd5.id1 = eapmd5->eapid;
	memcpy(&hcmd5.challenge, eapmd5->md5data, 16);
	hcmd5.p1 = TRUE;
	changeflag = TRUE;
	}

if((eapmd5->eapcode == EAP_CODE_RESP) && (eapmd5->eapvaluesize == 16)) 
	{
	hcmd5.id2 = eapmd5->eapid;
	memcpy(&hcmd5.mac_ap2, mac_1, 6);
	memcpy(&hcmd5.mac_sta2, mac_2, 6);
	memcpy(&hcmd5.response, eapmd5->md5data, 16);
	hcmd5.p2 = TRUE;
	changeflag = TRUE;
	}

if((changeflag == TRUE) && (hcmd5.id1 == hcmd5.id2) && (hcmd5.p1 == TRUE) && (hcmd5.p2 == TRUE) && (memcmp(&hcmd5.mac_ap1, &hcmd5.mac_ap2, 6) == 0) && (memcmp(&hcmd5.mac_sta1, &hcmd5.mac_sta2, 6) == 0))
	{
	if(hc4800outname != NULL)
		{
		if((fhhash = fopen(hc4800outname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening iSCSI CHAP authentication, MD5(CHAP) file %s\n", hc4800outname);
			exit(EXIT_FAILURE);
			}
		for(c = 0; c < 16; c++)
			fprintf(fhhash, "%02x", hcmd5.response[c]);
		fprintf(fhhash, ":");
		for(c = 0; c < 16; c++)
			fprintf(fhhash, "%02x", hcmd5.challenge[c]);
		fprintf(fhhash, ":");
		fprintf(fhhash, "%02x\n", hcmd5.id2);
		fclose(fhhash);
		}
	}
return;
}
/*===========================================================================*/
void addleap(uint8_t *mac_1, uint8_t *mac_2, eapext_t *eapext)
{
FILE *fhhash = NULL;
FILE *fhuser = NULL;
eapleap_t *eapleap = NULL;
int eaplen;
int c;
uint8_t changeflag = FALSE;
char *ptr = NULL;

eapleap = (eapleap_t*)(eapext);
if(eapleap->leapversion != 1)
	return;

eaplen = htobe16(eapleap->eaplen);
if((eapleap->eapcode == EAP_CODE_REQ) && (eapleap->leapcount == 8))
	{
	memcpy(&hcleap.mac_ap1, mac_2, 6);
	memcpy(&hcleap.mac_sta1, mac_1, 6);
	hcleap.leapid1 = eapleap->eapid;
	memset(&hcleap.username, 0, 258);
	memcpy(&hcleap.peerchallenge, eapleap->leapdata, eapleap->leapcount);
	memcpy(&hcleap.username, eapleap->leapdata +8, (eaplen -eapleap->leapcount -8));
	hcleap.p1 = TRUE;
	changeflag = TRUE;
	if(usernameoutname != NULL)
		{
		if((fhuser = fopen(usernameoutname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening username/identity file %s\n", usernameoutname);
			exit(EXIT_FAILURE);
			}
		fprintf(fhuser, "%s\n", hcleap.username);
		fclose(fhuser);
		}
	}

if((eapleap->eapcode == EAP_CODE_RESP) && (eapleap->leapcount == 24))
	{
	memcpy(&hcleap.mac_ap2, mac_1, 6);
	memcpy(&hcleap.mac_sta2, mac_2, 6);
	memcpy(&hcleap.peerresponse, eapleap->leapdata, eapleap->leapcount);
	hcleap.leapid2 = eapleap->eapid;
	hcleap.p2 = TRUE;
	changeflag = TRUE;
	}

if((changeflag == TRUE) && (hcleap.p1 == TRUE) && (hcleap.p2 == TRUE) && (memcmp(&hcleap.mac_ap1, &hcleap.mac_ap2, 6) == 0) && (memcmp(&hcleap.mac_sta1, &hcleap.mac_sta2, 6) == 0))
	{
	if(hc5500outname != NULL)
		{
		if((fhhash = fopen(hc5500outname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening netNTLMv1 file %s\n", hc5500outname);
			exit(EXIT_FAILURE);
			}

		ptr = strchr(hcleap.username, '\\');
		if(ptr == NULL)
			fprintf(fhhash, "%s::::", hcleap.username);
		else
			fprintf(fhhash, "%s::::", ++ptr);

		for(c = 0; c < 24; c++)
			fprintf(fhhash, "%02x", hcleap.peerresponse[c]);
		fprintf(fhhash, ":");
		for(c = 0; c < 8; c++)
			fprintf(fhhash, "%02x", hcleap.peerchallenge[c]);
		fprintf(fhhash, "\n");
		fclose(fhhash);
		}
	}
return;
}
/*===========================================================================*/
void addresponseidentity(eapext_t *eapext)
{
eapri_t *eapidentity = NULL;
FILE *fhuser = NULL;
int idlen;
char idstring[258];

eapidentity = (eapri_t*)(eapext);
if(eapidentity->eaptype != EAP_TYPE_ID)
	return;
idlen = htobe16(eapidentity->eaplen) -5;
if((idlen > 0) && (idlen <= 256))
	{
	memset(idstring, 0, 258);
	memcpy(&idstring, eapidentity->identity, idlen);
	if(usernameoutname != NULL)
		{
		if((fhuser = fopen(usernameoutname, "a")) == NULL)
			{
			fprintf(stderr, "error opening username/identity file %s\n", usernameoutname);
			exit(EXIT_FAILURE);
			}
		fprintf(fhuser, "%s\n", idstring);
		fclose(fhuser);
		}
	}
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
int checkmynonce(uint8_t *eapdata)
{
eap_t *eap;

eap = (eap_t*)(uint8_t*)(eapdata);
if(memcmp(eap->nonce, &mynonce, 32) == 0)
	return TRUE;
return FALSE;
}
/*===========================================================================*/
void writehcx(uint8_t essid_len, uint8_t *essid, eapdb_t *zeiger1, eapdb_t *zeiger2, uint8_t message_pair)
{
hcx_t hcxrecord;
eap_t *eap1;
eap_t *eap2;
FILE *fhhcx = NULL;
unsigned long long int r;
int wldflagint = FALSE;

eap1 = (eap_t*)(zeiger1->eapol);
eap2 = (eap_t*)(zeiger2->eapol);
memset(&hcxrecord, 0, HCX_SIZE);
hcxrecord.signature = HCCAPX_SIGNATURE;
hcxrecord.version = HCCAPX_VERSION;
hcxrecord.message_pair = message_pair;
hcxrecord.essid_len = essid_len;
memcpy(hcxrecord.essid, essid, essid_len);
hcxrecord.keyver = ((((eap1->keyinfo & 0xff) << 8) | (eap1->keyinfo >> 8)) & WPA_KEY_INFO_TYPE_MASK);
memcpy(hcxrecord.mac_ap.addr, zeiger1->mac_ap.addr, 6);
memcpy(hcxrecord.nonce_ap, eap1->nonce, 32);
memcpy(hcxrecord.mac_sta.addr, zeiger2->mac_sta.addr, 6);
memcpy(hcxrecord.nonce_sta, eap2->nonce, 32);
hcxrecord.eapol_len = zeiger2->eapol_len;
memcpy(hcxrecord.eapol,zeiger2->eapol, zeiger2->eapol_len +4);
memcpy(hcxrecord.keymic, eap2->keymic, 16);
memset(&hcxrecord.eapol[0x51], 0, 16);

if(oldhcxrecord.message_pair == hcxrecord.message_pair)
 if(memcmp(oldhcxrecord.mac_ap.addr, hcxrecord.mac_ap.addr, 6) == 0)
  if(memcmp(oldhcxrecord.mac_sta.addr, hcxrecord.mac_sta.addr, 6) == 0)
   if(memcmp(oldhcxrecord.keymic, hcxrecord.keymic, 16) == 0)
    if(memcmp(oldhcxrecord.essid, hcxrecord.essid, 32) == 0)
     if(memcmp(oldhcxrecord.nonce_ap, hcxrecord.nonce_ap, 32) == 0)
      if(memcmp(oldhcxrecord.nonce_sta, hcxrecord.nonce_sta, 32) == 0)
	return;

if((memcmp(oldhcxrecord.nonce_ap, hcxrecord.nonce_ap, 28) == 0) && (memcmp(oldhcxrecord.nonce_ap, hcxrecord.nonce_ap, 32) != 0))
		anecflag = TRUE;

memcpy(&oldhcxrecord, &hcxrecord, HCX_SIZE);

if(hcxoutname != NULL)
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", hcxoutname);
		exit(EXIT_FAILURE);
		}
	fwrite(&hcxrecord, 1 * HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	}

r = getreplaycount(zeiger2->eapol);
if((r == MYREPLAYCOUNT) && (memcmp(&mynonce, eap1->nonce, 32) == 0))
	{
	wldflagint = TRUE;
	wldflag = TRUE;
	}

if((wdfhcxoutname != NULL) && (wldflagint == TRUE))
	{
	if((fhhcx = fopen(wdfhcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", wdfhcxoutname);
		exit(EXIT_FAILURE);
		}
	fwrite(&hcxrecord, 1 * HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	}

if((nonwdfhcxoutname != NULL) && (wldflagint == FALSE))
	{
	if((fhhcx = fopen(nonwdfhcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", nonwdfhcxoutname);
		exit(EXIT_FAILURE);
		}
	fwrite(&hcxrecord, 1 * HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	}
return;	
}
/*===========================================================================*/
void lookforessidexact(eapdb_t *zeiger1, eapdb_t *zeiger2, uint8_t message_pair)
{
netdb_t *zeigernewnet;
long int c;

c = netdbrecords;
zeigernewnet = newnetdbdata;
while(c >= 0)
	{
	if((memcmp(zeigernewnet->mac_ap.addr, zeiger1->mac_ap.addr, 6) == 0) && (memcmp(zeigernewnet->mac_sta.addr, zeiger1->mac_sta.addr, 6) == 0))
		{
		if((zeigernewnet->essid_len <= 32) && (zeigernewnet->essid_len != 0) && (zeigernewnet->essid[0] != 0))
			writehcx(zeigernewnet->essid_len, zeigernewnet->essid, zeiger1, zeiger2, message_pair);
		return;
		}
	zeigernewnet--;
	c--;
	}
return;
}
/*===========================================================================*/
void lookforessid(eapdb_t *zeiger1, eapdb_t *zeiger2, uint8_t message_pair)
{
netdb_t *zeigernewnet;
long int c;

c = netdbrecords;
zeigernewnet = newnetdbdata;
while(c >= 0)
	{
	if(memcmp(zeigernewnet->mac_ap.addr, zeiger1->mac_ap.addr, 6) == 0)
		{
		if((zeigernewnet->essid_len <= 32) && (zeigernewnet->essid_len != 0) && (zeigernewnet->essid[0] != 0))
			writehcx(zeigernewnet->essid_len, zeigernewnet->essid, zeiger1, zeiger2, message_pair);
		return;
		}
	zeigernewnet--;
	c--;
	}
return;
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
void lookfor14(long int cakt, eapdb_t *zeigerakt, unsigned long long int replaycakt)
{
eapdb_t *zeiger;
unsigned long long int r;
long int c;
int rctime = 2;
uint8_t m = 0;

zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		break;

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 1) && (r == (replaycakt -1)))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M14E4);
			if(netexact == TRUE)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M14E4);
			return;
			}
		}
	zeiger--;
	c--;
	}

if(replaycountcheck == TRUE)
	return;

rctime = 10;
zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		return;

	if((zeigerakt->tv_sec - zeiger->tv_sec) > rctimecount)
		rctimecount = (zeigerakt->tv_sec - zeiger->tv_sec);

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 1) && (r != MYREPLAYCOUNT) && (checkmynonce(zeiger->eapol) == FALSE))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M14E4NR);
			if(netexact == TRUE)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M14E4NR);
			ancflag = TRUE;
			return;
			}
		}
	zeiger--;
	c--;
	}
return;
}
/*===========================================================================*/
void lookfor34(long int cakt, eapdb_t *zeigerakt, unsigned long long int replaycakt)
{
eapdb_t *zeiger;
unsigned long long int r;
long int c;
int rctime = 2;
uint8_t m = 0;

zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		break;

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 3) && (r == (replaycakt)))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M34E4);
			if(netexact == TRUE)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M34E4);
			return;
			}
		}
	zeiger--;
	c--;
	}

if(replaycountcheck == TRUE)
	return;

rctime = 10;
zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		return;

	if((zeigerakt->tv_sec - zeiger->tv_sec) > rctimecount)
		rctimecount = (zeigerakt->tv_sec - zeiger->tv_sec);

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if(m == 3)
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M34E4NR);
			if(netexact == TRUE)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M34E4NR);
			return;
			}
		}
	zeiger--;
	c--;
	}
return;
}
/*===========================================================================*/
void lookfor23(long int cakt, eapdb_t *zeigerakt, unsigned long long int replaycakt)
{
eapdb_t *zeiger;
unsigned long long int r;
long int c;
int rctime = 2;
uint8_t m = 0;

zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		break;

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 2) && (r == (replaycakt -1)))
			{
			lookforessid(zeigerakt, zeiger, MESSAGE_PAIR_M32E2);
			if(netexact == TRUE)
				lookforessidexact(zeigerakt, zeiger, MESSAGE_PAIR_M32E2);
			return;
			}
		}
	zeiger--;
	c--;
	}

if(replaycountcheck == TRUE)
	return;

rctime = 10;
zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		return;

	if((zeigerakt->tv_sec - zeiger->tv_sec) > rctimecount)
		rctimecount = (zeigerakt->tv_sec - zeiger->tv_sec);

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 2) && (r != MYREPLAYCOUNT))
			{
			lookforessid(zeigerakt, zeiger, MESSAGE_PAIR_M32E2NR);
			if(netexact == TRUE)
				lookforessidexact(zeigerakt, zeiger, MESSAGE_PAIR_M32E2NR);
			return;
			}
		}
	zeiger--;
	c--;
	}
return;
}
/*===========================================================================*/
void lookfor12(long int cakt, eapdb_t *zeigerakt, unsigned long long int replaycakt)
{
eapdb_t *zeiger;
unsigned long long int r;
long int c;
int rctime = 2;
uint8_t m = 0;

if (replaycakt == MYREPLAYCOUNT)
	{
	rctime = 120;
	}

zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		break;

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 1) && (r == replaycakt))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M12E2);
			if(netexact == TRUE)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M12E2);
			return;
			}
		}
	zeiger--;
	c--;
	}


if(replaycountcheck == TRUE)
	return;
	
rctime = 10;
zeiger = zeigerakt;
c = cakt;
while(c >= 0)
	{
	if(((zeigerakt->tv_sec - zeiger->tv_sec) < 0) || ((zeigerakt->tv_sec - zeiger->tv_sec) > rctime))
		return;

	if((zeigerakt->tv_sec - zeiger->tv_sec) > rctimecount)
		rctimecount = (zeigerakt->tv_sec - zeiger->tv_sec);

	if((memcmp(zeiger->mac_ap.addr, zeigerakt->mac_ap.addr, 6) == 0) && (memcmp(zeiger->mac_sta.addr, zeigerakt->mac_sta.addr, 6) == 0))
		{
		m = geteapkey(zeiger->eapol);
		r = getreplaycount(zeiger->eapol);
		if((m == 1) && (r != MYREPLAYCOUNT) && (checkmynonce(zeiger->eapol) == FALSE))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M12E2NR);
			if(netexact == TRUE)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M12E2NR);
			ancflag = TRUE;
			return;
			}
		}
	zeiger--;
	c--;
	}
return;
}
/*===========================================================================*/
int addeapol(time_t tvsec, time_t tvusec, uint8_t *mac_sta, uint8_t *mac_ap, eap_t *eap)
{
unsigned long long int replaycount;
uint8_t m = 0;

if(memcmp(mac_ap, mac_sta, 6) == 0)
	return FALSE;
if(memcmp(eap->nonce, &nullnonce, NULLNONCE_SIZE) == 0)
	return FALSE;
memset(neweapdbdata, 0, EAPDB_SIZE);
neweapdbdata->tv_sec = tvsec;
neweapdbdata->tv_usec = tvusec;
memcpy(neweapdbdata->mac_ap.addr, mac_ap, 6);
memcpy(neweapdbdata->mac_sta.addr, mac_sta, 6);
neweapdbdata->eapol_len = htobe16(eap->len) +4;
if(neweapdbdata->eapol_len > 256)
	return FALSE;
memcpy(neweapdbdata->eapol, eap, neweapdbdata->eapol_len);
m = geteapkey(neweapdbdata->eapol);
replaycount = getreplaycount(neweapdbdata->eapol);
if(m == 2)
	{
	lookfor12(eapdbrecords, neweapdbdata, replaycount);
	}

if(m == 3)
	{
	lookfor23(eapdbrecords, neweapdbdata, replaycount);
	}

if(m == 4)
	{
	lookfor34(eapdbrecords, neweapdbdata, replaycount);
	lookfor14(eapdbrecords, neweapdbdata, replaycount);
	}
neweapdbdata++;
eapdbrecords++;
return TRUE;
}
/*===========================================================================*/
int addnet(time_t tvsec, time_t tvusec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essid)
{
if(memcmp(mac_ap, mac_sta, 6) == 0)
	return FALSE;
memset(newnetdbdata, 0, NETDB_SIZE);
newnetdbdata->tv_sec = tvsec;
newnetdbdata->tv_usec = tvusec;
memcpy(newnetdbdata->mac_ap.addr, mac_ap, 6);
memcpy(newnetdbdata->mac_sta.addr, mac_sta, 6);
newnetdbdata->essid_len = essid_len;
memcpy(newnetdbdata->essid, essid, essid_len);
newnetdbdata++;
netdbrecords++;
return TRUE;
}
/*===========================================================================*/
int checkessid(uint8_t essid_len, uint8_t *essid)
{
uint8_t p;

if(essid_len == 0)
	return FALSE;

if(essid_len > 32)
	return FALSE;

for(p = 0; p < essid_len; p++)
	if((essid[p] < 0x20) || (essid[p] > 0x7e))
		return FALSE;
return TRUE;
}
/*===========================================================================*/
int processcap(char *pcapinname, char *essidoutname, char *essidunicodeoutname)
{
struct stat statinfo;
struct bpf_program filter;
struct pcap_pkthdr *pkh;
pcap_t *pcapin = NULL;
rth_t *rth = NULL;
ppi_packet_header_t *ppih = NULL;
mac_t *macf = NULL;
eap_t *eap = NULL;
eapext_t *eapext = NULL;
essid_t *essidf = NULL;
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
uint8_t	*payload = NULL;
netdb_t *zeigernet;
FILE *fhessid = NULL;
int macl = 0;
int fcsl = 0;
uint8_t field = 0;
int datalink = 0;
int pcapstatus;
int packetcount = 0;
wcflag = FALSE;
wldflag = FALSE;
ancflag = FALSE;
anecflag = FALSE;
int c;
int llctype;

uint8_t eap3flag = FALSE;
uint8_t eap4flag = FALSE;
uint8_t eap5flag = FALSE;
uint8_t eap6flag = FALSE;
uint8_t eap9flag = FALSE;
uint8_t eap10flag = FALSE;
uint8_t eap11flag = FALSE;
uint8_t eap12flag = FALSE;
uint8_t eap13flag = FALSE;
uint8_t eap14flag = FALSE;
uint8_t eap15flag = FALSE;
uint8_t eap16flag = FALSE;
uint8_t eap17flag = FALSE;
uint8_t eap18flag = FALSE;
uint8_t eap19flag = FALSE;
uint8_t eap21flag = FALSE;
uint8_t eap22flag = FALSE;
uint8_t eap23flag = FALSE;
uint8_t eap24flag = FALSE;
uint8_t eap25flag = FALSE;
uint8_t eap26flag = FALSE;
uint8_t eap27flag = FALSE;
uint8_t eap28flag = FALSE;
uint8_t eap29flag = FALSE;
uint8_t eap30flag = FALSE;
uint8_t eap31flag = FALSE;
uint8_t eap32flag = FALSE;
uint8_t eap33flag = FALSE;
uint8_t eap34flag = FALSE;
uint8_t eap35flag = FALSE;
uint8_t eap36flag = FALSE;
uint8_t eap37flag = FALSE;
uint8_t eap38flag = FALSE;
uint8_t eap39flag = FALSE;
uint8_t eap40flag = FALSE;
uint8_t eap41flag = FALSE;
uint8_t eap42flag = FALSE;
uint8_t eap43flag = FALSE;
uint8_t eap44flag = FALSE;
uint8_t eap45flag = FALSE;
uint8_t eap46flag = FALSE;
uint8_t eap47flag = FALSE;
uint8_t eap48flag = FALSE;
uint8_t eap49flag = FALSE;
uint8_t eap50flag = FALSE;
uint8_t eap51flag = FALSE;
uint8_t eap52flag = FALSE;
uint8_t eap53flag = FALSE;
uint8_t eap54flag = FALSE;
uint8_t eap55flag = FALSE;
uint8_t eap254flag = FALSE;
uint8_t eap255flag = FALSE;

uint8_t ipv4flag = FALSE;
uint8_t ipv6flag = FALSE;
uint8_t preautflag = FALSE;
uint8_t frrrflag = FALSE;


char pcaperrorstring[PCAP_ERRBUF_SIZE];

if (!(pcapin = pcap_open_offline(pcapinname, pcaperrorstring)))
	{
	fprintf(stderr, "error opening %s %s\n", pcaperrorstring, pcapinname);
	return FALSE;
	}

datalink = pcap_datalink(pcapin);
if((datalink != DLT_IEEE802_11) && (datalink != DLT_IEEE802_11_RADIO) && (datalink != DLT_PPI))
	{
	fprintf (stderr, "unsupported datalinktyp %d\n", datalink);
	return FALSE;
	}

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

if(stat(pcapinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat cap file %s\n", pcapinname);
	return FALSE;
	}

netdbdata = malloc(statinfo.st_size +NETDB_SIZE);
if(netdbdata == NULL)	
		{
		fprintf(stderr, "out of memory process nets\n");
		exit(EXIT_FAILURE);
		}
newnetdbdata = netdbdata;
netdbrecords = 0;

eapdbdata = malloc(statinfo.st_size *2 +EAPDB_SIZE);
if(eapdbdata == NULL)	
		{
		fprintf(stderr, "out of memory process eaps\n");
		exit(EXIT_FAILURE);
		}
neweapdbdata = eapdbdata;
eapdbrecords = 0;


printf("start reading from %s\n", pcapinname);

while((pcapstatus = pcap_next_ex(pcapin, &pkh, &packet)) != -2)
	{
	if(pcapstatus == 0)
		{
		fprintf(stderr, "pcapstatus %d\n", pcapstatus);
		continue;
		}

	if(pcapstatus == -1)
		{
		fprintf(stderr, "pcap read error: %s \n", pcap_geterr(pcapin));
		continue;
		}

	if(pkh->caplen != pkh->len)
		continue;

	packetcount++;
	if((pkh->ts.tv_sec == 0) && (pkh->ts.tv_sec == 0))
		wcflag = TRUE;

	/* check 802.11-header */
	if(datalink == DLT_IEEE802_11)
		h80211 = packet;

	/* check radiotap-header */
	else if(datalink == DLT_IEEE802_11_RADIO)
		{
		rth = (rth_t*)packet;
		fcsl = 0;
		field = 8;
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

	/* check ppi-header */
	else if(datalink == DLT_PPI)
		{
		ppih = (ppi_packet_header_t*)packet;
		if(ppih->pph_dlt != DLT_IEEE802_11)
			continue;
		fcsl = 0;
		if((packet[0x14] & 1) == 1)
			fcsl = 4;
		pkh->caplen -= ppih->pph_len +fcsl;
		pkh->len -=  ppih->pph_len +fcsl;
		h80211 = packet + ppih->pph_len;
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
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);

			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;

			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid);
			}
		else if(macf->subtype == MAC_ST_PROBE_RESP)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid);
			}

		/* check proberequest frames */
		else if(macf->subtype == MAC_ST_PROBE_REQ)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);

			essidf = (essid_t*)(payload);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
			}

		/* check associationrequest - reassociationrequest frames */
		else if(macf->subtype == MAC_ST_ASSOC_REQ)
			{
			essidf = (essid_t*)(payload +ASSOCIATIONREQF_SIZE);
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
			}

		else if(macf->subtype == MAC_ST_REASSOC_REQ)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			essidf = (essid_t*)(payload +REASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
			}
		continue;
		}

	/* check handshake frames */
	if((macf->type == MAC_TYPE_DATA) && (LLC_SIZE <= pkh->len) && (be16toh(((llc_t*)payload)->type) == LLC_TYPE_AUTH) && (pkh->len > 26))
		{
		eap = (eap_t*)(payload + LLC_SIZE);
		if(eap->type == 3)
			{
			if(macf->from_ds == 1) /* sta - ap */
				addeapol(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr1.addr, macf->addr2.addr, eap);

			if(macf->to_ds == 1) /* ap - sta */
				addeapol(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, eap);
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			continue;
			}

		if(eap->type == 0)
			{
			eapext = (eapext_t*)(payload + LLC_SIZE);
			if((htobe16(eapext->len) < 8))
				continue;

			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);

			if(pcapextout != NULL)
				pcap_dump((u_char *) pcapextout, pkh, h80211);


			if(eapext->eapcode == EAP_CODE_RESP)
				addresponseidentity(eapext);

			if(eapext->eaptype == EAP_TYPE_NAK)
				eap3flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_MD5)
				{
				addeapmd5(macf->addr1.addr, macf->addr2.addr, eapext);
				eap4flag = TRUE;
				}

			if(eapext->eaptype == EAP_TYPE_OTP)
				eap5flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_GTC)
				eap6flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_RSA)
				eap9flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_DSS)
				eap10flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_KEA)
				eap11flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_KEA_VALIDATE)
				eap12flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_TLS)
				eap13flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_AXENT)
				eap14flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_RSA_SSID)
				eap15flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_RSA_ARCOT)
				eap16flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_LEAP)
				{
				if((macf->from_ds == 1) && (macf->to_ds == 0) && (eapext->eapcode == EAP_CODE_REQ))
					{
					addleap( macf->addr1.addr, macf->addr2.addr, eapext);
					eap17flag = TRUE;
					}

				else if((macf->from_ds == 0) && (macf->to_ds == 1) && (eapext->eapcode == EAP_CODE_RESP))
					{
					addleap( macf->addr1.addr, macf->addr2.addr, eapext);
					eap17flag = TRUE;
					}
				}

			if(eapext->eaptype == EAP_TYPE_SIM)
				eap18flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_SRP_SHA1)
				eap19flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_TTLS)
				eap21flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_RAS)
				eap22flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_AKA)
				eap23flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_3COMEAP)
				eap24flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_PEAP)
				eap25flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_MSEAP)
				eap26flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_MAKE)
				eap27flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_CRYPTOCARD)
				eap28flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_MSCHAPV2)
				eap29flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_DYNAMICID)
				eap30flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_ROB)
				eap31flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_POTP)
				eap32flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_MSTLV)
				eap33flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_SENTRI)
				eap34flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_AW)
				eap35flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_CSBA)
				eap36flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_AIRFORT)
				eap40flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_HTTPD)
				eap38flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_SS)
				eap39flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_DC)
				eap40flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_SPEKE)
				eap41flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_MOBAC)
				eap42flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_FAST)
				eap43flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_ZLXEAP)
				eap44flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_LINK)
				eap45flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_PAX)
				eap46flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_PSK)
				eap47flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_SAKE)
				eap48flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_IKEV2)
				eap49flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_AKA1)
				eap50flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_GPSK)
				eap51flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_PWD)
				eap52flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_EKE1)
				eap53flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_PTEAP)
				eap54flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_TEAP)
				eap55flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_EXPAND)
				eap254flag = TRUE;

			if(eapext->eaptype == EAP_TYPE_EXPERIMENTAL)
				eap255flag = TRUE;

			continue;
			}

		if(eap->type == 1)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);

			if(pcapextout != NULL)
				pcap_dump((u_char *) pcapextout, pkh, h80211);

			continue;
			}
		}

	if((macf->type == MAC_TYPE_DATA) && (LLC_SIZE <= pkh->len)&& (pkh->len >= IP_SIZE_MIN))
		{
		llctype = be16toh(((llc_t*)payload)->type);
		if(llctype == LLC_TYPE_IPV4)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if(pcapipv46out != NULL)
				pcap_dump((u_char *) pcapipv46out, pkh, h80211);
			ipv4flag = TRUE;
			}

		if(llctype == LLC_TYPE_IPV6)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if(pcapipv46out != NULL)
				pcap_dump((u_char *) pcapipv46out, pkh, h80211);
			ipv6flag = TRUE;
			}

		if(llctype == LLC_TYPE_PREAUT)
			preautflag = TRUE;

		if(llctype == LLC_TYPE_FRRR)
			frrrflag = TRUE;

		}

	}

if(essidoutname != NULL)
	{
	if((fhessid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidoutname);
		exit(EXIT_FAILURE);
		}

	zeigernet = netdbdata;
	for(c = 0; c < netdbrecords; c++)
		{
		if(checkessid(zeigernet->essid_len, zeigernet->essid) == TRUE)
			fprintf(fhessid, "%s\n", zeigernet->essid);
		zeigernet++;
		}

	fclose(fhessid);
	}


if(essidunicodeoutname != NULL)
	{
	if((fhessid = fopen(essidunicodeoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidunicodeoutname);
		exit(EXIT_FAILURE);
		}

	zeigernet = netdbdata;
	for(c = 0; c < netdbrecords; c++)
		{
		fprintf(fhessid, "%s\n", zeigernet->essid);
		zeigernet++;
		}

	fclose(fhessid);
	}

free(eapdbdata);
free(netdbdata);
pcap_close(pcapin);
printf("%d packets processed (total: %ld network management packets, %ld wpa packets)\n", packetcount, netdbrecords, eapdbrecords);

if(anecflag == TRUE)
	printf("\x1B[32mhashcat --nonce-error-corrections is working on that file\x1B[0m\n");


if(wldflag == TRUE)
	{
	printf("\x1B[32mfound wlandump forced handshakes inside\x1B[0m\n");
	if(wdfhcxoutname != NULL)
		printf("\x1B[33myou can use hashcat --nonce-error-corrections=0 on %s\x1B[0m\n", wdfhcxoutname);
	}

if(ancflag == TRUE)
	{
	if(hcxoutname != NULL)
		{
		if((rctimecount > 2) && (rctimecount <= 4))
			printf("\x1B[33myou should use hashcat --nonce-error-corrections=16 on %s\x1B[0m\n", hcxoutname);
		if((rctimecount > 4) && (rctimecount <= 8))
			printf("\x1B[33myou should use hashcat --nonce-error-corrections=32 on %s\x1B[0m\n", hcxoutname);
		if(rctimecount > 8)
			printf("\x1B[33myou should use hashcat --nonce-error-corrections=64 on %s\x1B[0m\n", hcxoutname);
		}

	if(nonwdfhcxoutname != NULL)
		{
		if((rctimecount > 2) && (rctimecount <= 4))
			printf("\x1B[33myou should use hashcat --nonce-error-corrections=16 on %s\x1B[0m\n", hcxoutname);
		if((rctimecount > 4) && (rctimecount <= 8))
			printf("\x1B[33myou should use hashcat --nonce-error-corrections=32 on %s\x1B[0m\n", hcxoutname);
		if(rctimecount > 8)
			printf("\x1B[33myou should use hashcat --nonce-error-corrections=64 on %s\x1B[0m\n", hcxoutname);
		}
	}

if(eap3flag == TRUE)
	printf("\x1B[36mfound Legacy Nak\x1B[0m\n");

if(eap4flag == TRUE)
	printf("\x1B[36mfound MD5-Challenge (hashcat -m 4800)\x1B[0m\n");

if(eap5flag == TRUE)
	printf("\x1B[36mfound One-Time Password (OTP)\x1B[0m\n");

if(eap6flag == TRUE)
	printf("\x1B[36mfound Generic Token Card (GTC)\x1B[0m\n");

if(eap9flag == TRUE)
	printf("\x1B[36mfound RSA Public Key Authentication\x1B[0m\n");

if(eap10flag == TRUE)
	printf("\x1B[36mfound DSS Unilateral\x1B[0m\n");

if(eap11flag == TRUE)
	printf("\x1B[36mfound KEA\x1B[0m\n");

if(eap12flag == TRUE)
	printf("\x1B[36mfound KEA-VALIDATE\x1B[0m\n");

if(eap13flag == TRUE)
	printf("\x1B[36mfound EAP-TLS Authentication\x1B[0m\n");

if(eap14flag == TRUE)
	printf("\x1B[36mfound Defender Token (AXENT)\x1B[0m\n");

if(eap15flag == TRUE)
	printf("\x1B[36mfound RSA Security SecurID EAP\x1B[0m\n");

if(eap16flag == TRUE)
	printf("\x1B[36mfound Arcot Systems EAP\x1B[0m\n");

if(eap17flag == TRUE)
	printf("\x1B[36mfound EAP-Cisco Wireless Authentication (hashcat -m 5500)\x1B[0m\n");

if(eap18flag == TRUE)
	printf("\x1B[36mfound EAP-SIM (GSM Subscriber Modules) Authentication\x1B[0m\n");

if(eap19flag == TRUE)
	printf("\x1B[36mfound SRP-SHA1 Authentication\x1B[0m\n");

if(eap21flag == TRUE)
	printf("\x1B[36mfound EAP-TTLS Authentication\x1B[0m\n");

if(eap22flag == TRUE)
	printf("\x1B[36mfound Remote Access Service\x1B[0m\n");

if(eap23flag == TRUE)
	printf("\x1B[36mfound EAP-AKA Authentication\x1B[0m\n");

if(eap24flag == TRUE)
	printf("\x1B[36mfound EAP-3Com Wireless Authentication\x1B[0m\n");

if(eap25flag == TRUE)
	printf("\x1B[36mfound PEAP Authentication\x1B[0m\n");

if(eap26flag == TRUE)
	printf("\x1B[36mfound MS-EAP Authentication\x1B[0m\n");

if(eap27flag == TRUE)
	printf("\x1B[36mfound Mutual Authentication w/Key Exchange (MAKE)\x1B[0m\n");

if(eap28flag == TRUE)
	printf("\x1B[36mfound CRYPTOCard\x1B[0m\n");

if(eap29flag == TRUE)
	printf("\x1B[36mfound EAP-MSCHAP-V2 Authentication\x1B[0m\n");

if(eap30flag == TRUE)
	printf("\x1B[36mfound DynamicID\x1B[0m\n");

if(eap31flag == TRUE)
	printf("\x1B[36mfound Rob EAP\x1B[0m\n");

if(eap32flag == TRUE)
	printf("\x1B[36mfound Protected One-Time Password\x1B[0m\n");

if(eap33flag == TRUE)
	printf("\x1B[36mfound MS-Authentication-TLV\x1B[0m\n");

if(eap34flag == TRUE)
	printf("\x1B[36mfound SentriNET\x1B[0m\n");

if(eap35flag == TRUE)
	printf("\x1B[36mfound EAP-Actiontec Wireless Authentication\x1B[0m\n");

if(eap36flag == TRUE)
	printf("\x1B[36mfound Cogent Systems Biometrics Authentication EAP\x1B[0m\n");

if(eap37flag == TRUE)
	printf("\x1B[36mfound AirFortress EAP\x1B[0m\n");

if(eap38flag == TRUE)
	printf("\x1B[36mfound EAP-HTTP Digest\x1B[0m\n");

if(eap39flag == TRUE)
	printf("\x1B[36mfound SecureSuite EAP\x1B[0m\n");

if(eap40flag == TRUE)
	printf("\x1B[36mfound DeviceConnect EAP\x1B[0m\n");

if(eap41flag == TRUE)
	printf("\x1B[36mfound EAP-SPEKE Authentication\x1B[0m\n");

if(eap42flag == TRUE)
	printf("\x1B[36mfound EAP-MOBAC Authentication\x1B[0m\n");

if(eap43flag == TRUE)
	printf("\x1B[36mfound FAST Authentication\x1B[0m\n");

if(eap44flag == TRUE)
	printf("\x1B[36mfound ZoneLabs EAP (ZLXEAP)\x1B[0m\n");

if(eap45flag == TRUE)
	printf("\x1B[36mfound EAP-Link Authetication\x1B[0m\n");

if(eap46flag == TRUE)
	printf("\x1B[36mfound EAP-PAX Authetication\x1B[0m\n");

if(eap47flag == TRUE)
	printf("\x1B[36mfound EAP-PSK Authetication\x1B[0m\n");

if(eap48flag == TRUE)
	printf("\x1B[36mfound EAP-SAKE Authetication\x1B[0m\n");

if(eap49flag == TRUE)
	printf("\x1B[36mfound EAP-IKEv2 Authetication\x1B[0m\n");

if(eap50flag == TRUE)
	printf("\x1B[36mfound EAP-AKA Authetication\x1B[0m\n");

if(eap51flag == TRUE)
	printf("\x1B[36mfound EAP-GPSK Authetication\x1B[0m\n");

if(eap52flag == TRUE)
	printf("\x1B[36mfound EAP-pwd Authetication\x1B[0m\n");

if(eap53flag == TRUE)
	printf("\x1B[36mfound EAP-EKE Version 1 Authetication\x1B[0m\n");

if(eap54flag == TRUE)
	printf("\x1B[36mfound EAP Method Type for PT-EAP Authetication\x1B[0m\n");

if(eap55flag == TRUE)
	printf("\x1B[36mfound TEAP Authetication\x1B[0m\n");

if(eap254flag == TRUE)
	printf("\x1B[36mfound WPS Authentication\x1B[0m\n");

if(eap255flag == TRUE)
	printf("\x1B[36mfound Experimental Authentication\x1B[0m\n");


if(ipv4flag == TRUE)
	printf("\x1B[35mfound IPv4 packets\x1B[0m\n");

if(ipv6flag == TRUE)
	printf("\x1B[35mfound IPv6 packets\x1B[0m\n");

if(preautflag == TRUE)
	printf("\x1B[35mPre-Authentication detected\x1B[0m\n");

if(frrrflag == TRUE)
	printf("\x1B[35mfound Fast Roaming Remote Request\x1B[0m\n");


if(wcflag == TRUE)
	printf("\x1B[31mwarning: use of wpaclean detected\x1B[0m\n");

return TRUE;	
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.cap] [input.cap] ...\n"
	"       %s <options> *.cap\n"
	"       %s <options> *.*\n"
	"\n"
	"options:\n"
	"-o <file> : output hccapx file (wpa/wpa2: use hashcat -m 2500)\n"
	"-w <file> : output only wlandump forced to hccapx file\n"
	"-W <file> : output only not wlandump forced to hccapx file\n"
	"-p <file> : output merged pcap file\n"
	"-P <file> : output extended eapol packets pcap file (analysis purpose)\n"
	"-l <file> : output IPv4/IPv6 packets pcap file (analysis purpose)\n"
	"-m <file> : output extended eapol file (iSCSI CHAP authentication, MD5(CHAP): use hashcat -m 4800)\n"
	"-n <file> : output extended eapol file (NetNTLMv1: use hashcat -m 5500)\n"
	"-e <file> : output wordlist to use as hashcat input wordlist\n"
	"-E <file> : output wordlist to use as hashcat input wordlist (unicode)\n"
	"-u <file> : output usernames/identities file\n"
	"-x        : look for net exact (ap == ap) && (sta == sta)\n"
	"-r        : enable replaycountcheck (default: disabled)\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
pcap_t *pcapdh = NULL;
pcap_t *pcapextdh = NULL;
pcap_t *pcapipv46dh = NULL;

int auswahl;
int index;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *pcapoutname = NULL;
char *pcapextoutname = NULL;
char *pcapipv46outname = NULL;
char *essidoutname = NULL;
char *essidunicodeoutname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "o:m:n:p:P:l:e:E:w:W:u:xrhv")) != -1)
	{
	switch (auswahl)
		{
		case 'o':
		hcxoutname = optarg;
		break;

		case 'n':
		hc5500outname = optarg;
		break;

		case 'm':
		hc4800outname = optarg;
		break;

		case 'w':
		wdfhcxoutname = optarg;
		break;

		case 'W':
		nonwdfhcxoutname = optarg;
		break;

		case 'p':
		pcapoutname = optarg;
		break;

		case 'P':
		pcapextoutname = optarg;
		break;

		case 'l':
		pcapipv46outname = optarg;
		break;

		case 'e':
		essidoutname = optarg;
		break;

		case 'E':
		essidunicodeoutname = optarg;
		break;

		case 'u':
		usernameoutname = optarg;
		break;


		case 'x':
		netexact = TRUE;
		break;

		case 'r':
		replaycountcheck = TRUE;
		break;

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

initgloballists();

if(pcapoutname != NULL)
	{
	pcapdh = pcap_open_dead(DLT_IEEE802_11, 65535);
	if ((pcapout = pcap_dump_open(pcapdh, pcapoutname)) == NULL)
		fprintf(stderr, "\x1B[31merror creating dump file %s\x1B[0m\n", pcapoutname);
	}

if(pcapextoutname != NULL)
	{
	pcapextdh = pcap_open_dead(DLT_IEEE802_11, 65535);
	if ((pcapextout = pcap_dump_open(pcapextdh, pcapextoutname)) == NULL)
		fprintf(stderr, "\x1B[31merror creating dump file %s\x1B[0m\n", pcapextoutname);
	}

if(pcapipv46outname != NULL)
	{
	pcapipv46dh = pcap_open_dead(DLT_IEEE802_11, 65535);
	if ((pcapipv46out = pcap_dump_open(pcapipv46dh, pcapipv46outname)) == NULL)
		fprintf(stderr, "\x1B[31merror creating dump file %s\x1B[0m\n", pcapipv46outname);
	}

memset(&oldhcxrecord, 0, HCX_SIZE);
for (index = optind; index < argc; index++)
	{
	if(pcapoutname != NULL)
		if(strcmp(argv[index], pcapoutname) == 0)
			{
			fprintf(stderr, "\x1B[31mfile skipped (inputname = outputname) %s\x1B[0m\n", (argv[index]));
			continue;	
			}

	if(pcapextoutname != NULL)
		if(strcmp(argv[index], pcapextoutname) == 0)
			{
			fprintf(stderr, "\x1B[31mfile skipped (inputname = outputname) %s\x1B[0m\n", (argv[index]));
			continue;	
			}
	if(processcap(argv[index], essidoutname, essidunicodeoutname) == FALSE)
		fprintf(stderr, "\x1B[31merror processing records from %s\x1B[0m\n", (argv[index]));

	}

if(pcapipv46out != NULL)
	pcap_dump_close(pcapipv46out);

if(pcapextout != NULL)
	pcap_dump_close(pcapextout);

if(pcapout != NULL)
	pcap_dump_close(pcapout);
return EXIT_SUCCESS;
}

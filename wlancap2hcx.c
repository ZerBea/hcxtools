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
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/evp.h>
#include "common.c"
#include "com_md5_64.c"
#include "com_aes.c"
#include "com_formats.c"
#include "com_wpa.c"

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
long int hcxwritecount = 0;
long int hcxwritewldcount = 0;
long int weakpasscount = 0;
pcap_dumper_t *pcapout = NULL;
pcap_dumper_t *pcapextout = NULL;
pcap_dumper_t *pcapipv46out = NULL;
pcap_dumper_t *pcapwepout = NULL;

uint8_t netexact = false;
uint8_t replaycountcheck = false;
uint8_t idcheck = false;
uint8_t wcflag = false;
uint8_t ancflag = false;
uint8_t anecflag = false;
uint8_t showinfo1 = false;
uint8_t showinfo2 = false;
uint8_t weakpassflag = false;

int rctimecount = 0;

hc4800_t hcmd5;
hc5500_t hcleap;
hc5500chap_t hcleapchap;

long int wpakv1c = 0;
long int wpakv2c = 0;
long int wpakv3c = 0;
long int wpakv4c = 0;

char *hcxoutname = NULL;
char *hc4800outname = NULL;
char *hc5500outname = NULL;
char *wdfhcxoutname = NULL;
char *nonwdfhcxoutname = NULL;
char *showinfo2outname = NULL;
char *usernameoutname = NULL;

hcx_t oldhcxrecord;

/*===========================================================================*/
void initgloballists()
{
memset(&hcmd5, 0, sizeof(hc4800_t));
memset(&hcleap, 0, sizeof(hc5500_t));
memset(&hcleapchap, 0, sizeof(hc5500chap_t));

return;
}
/*===========================================================================*/
bool addpppchap(uint8_t *mac_1, uint8_t *mac_2, uint8_t *payload)
{
int c;
gre_frame_t *greh = NULL;
int grehsize = 0;
ppp_frame_t *ppph = NULL;
pppchap_frame_t *pppchaph = NULL;
FILE *fhuser = NULL;
FILE *fhhash = NULL;

SHA_CTX ctxsha1;
char *ptr = NULL;

unsigned char digestsha1[SHA_DIGEST_LENGTH];
greh = (gre_frame_t*)(payload);

if(be16toh(greh->type) != GREPROTO_PPP)
	return false;

grehsize = GRE_MIN_SIZE;
if((greh->flags & GRE_FLAG_SYNSET) == GRE_FLAG_SYNSET)
	grehsize += 4;
if((greh->flags & GRE_FLAG_ACKSET) == GRE_FLAG_ACKSET)
	grehsize += 4;

ppph = (ppp_frame_t*)(payload +grehsize);
if(be16toh(ppph->proto) != PPPPROTO_CHAP)
	return false;


pppchaph = (pppchap_frame_t*)(payload +grehsize +PPP_SIZE);
if(be16toh(pppchaph->length) < 20)
	return false;

if((pppchaph->code == PPPCHAP_CHALLENGE) && (pppchaph->u.challenge.datalen == 16))
	{
	memcpy(&hcleapchap.mac_ap1, mac_2, 6);
	memcpy(&hcleapchap.mac_sta1, mac_1, 6);
	hcleapchap.id1 = pppchaph->identifier;
	memcpy(&hcleapchap.serverchallenge, pppchaph->u.challenge.serverchallenge, 16);
	memset(&hcleapchap.usernames, 0, 258);
	memcpy(&hcleapchap.usernames, &pppchaph->u.challenge.names, (be16toh(pppchaph->length) -21));
	hcleapchap.p1 = true;
	if(usernameoutname != NULL)
		{
		if((fhuser = fopen(usernameoutname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening username/identity file %s\n", usernameoutname);
			exit(EXIT_FAILURE);
			}
		fprintf(fhuser, "%s\n", hcleapchap.usernames);
		fclose(fhuser);
		}
	}
if(pppchaph->code == PPPCHAP_RESPONSE)
	{
	memcpy(&hcleapchap.mac_ap2, mac_1, 6);
	memcpy(&hcleapchap.mac_sta2, mac_2, 6);
	hcleapchap.id2 = pppchaph->identifier;
	memcpy(&hcleapchap.clientchallenge, pppchaph->u.response.clientchallenge, 16);
	memcpy(&hcleapchap.authresponse, pppchaph->u.response.authresponse, 24);
	memset(&hcleapchap.usernamec, 0, 258);
	memcpy(&hcleapchap.usernamec, &pppchaph->u.response.namec, (be16toh(pppchaph->length) -54));
	hcleapchap.p2 = true;
	if(usernameoutname != NULL)
		{
		if((fhuser = fopen(usernameoutname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening username/identity file %s\n", usernameoutname);
			exit(EXIT_FAILURE);
			}
		fprintf(fhuser, "%s\n", hcleapchap.usernamec);
		fclose(fhuser);
		}
	}

SHA1_Init(&ctxsha1);
SHA1_Update(&ctxsha1, &hcleapchap.clientchallenge, 16);
SHA1_Update(&ctxsha1, &hcleapchap.serverchallenge, 16);
ptr = strchr(hcleapchap.usernamec, '\\');
if(ptr == NULL)
	SHA1_Update(&ctxsha1, hcleapchap.usernamec, strlen(hcleapchap.usernamec));
else
	{
	ptr++;
	SHA1_Update(&ctxsha1, ptr, strlen(ptr));
	}
SHA1_Final(digestsha1, &ctxsha1);
memcpy(&hcleapchap.authchallenge,  &digestsha1, 8);

if((idcheck == true) & (hcleapchap.id1 != hcleapchap.id2))
	return false;


if((hcleapchap.p1 == true) && (hcleapchap.p2 == true) && (memcmp(&hcleapchap.mac_ap1, &hcleapchap.mac_ap2, 6) == 0) && (memcmp(&hcleapchap.mac_sta1, &hcleapchap.mac_sta2, 6) == 0))
	{
	if(hc5500outname != NULL)
		{
		if((fhhash = fopen(hc5500outname, "a+")) == NULL)
			{
			fprintf(stderr, "error opening netNTLMv1 file %s\n", hc5500outname);
			exit(EXIT_FAILURE);
			}

		if(ptr == NULL)
			fprintf(fhhash, "%s::::", hcleapchap.usernamec);
		else
			fprintf(fhhash, "%s::::", ++ptr);

		for(c = 0; c < 24; c++)
			fprintf(fhhash, "%02x", hcleapchap.authresponse[c]);
		fprintf(fhhash, ":");
		for(c = 0; c < 8; c++)
			fprintf(fhhash, "%02x", hcleapchap.authchallenge[c]);
		fprintf(fhhash, "\n");
		fclose(fhhash);
		}
	return true;
	}
return false;
}
/*===========================================================================*/
bool addeapmd5(uint8_t *mac_1, uint8_t *mac_2, eapext_t *eapext)
{
eapmd5_t *eapmd5 = NULL;
FILE *fhhash = NULL;
uint8_t changeflag = false;
int c;

eapmd5 = (eapmd5_t*)(eapext);
if((eapmd5->eapcode == EAP_CODE_REQ) && (eapmd5->eapvaluesize == 16)) 
	{
	memcpy(&hcmd5.mac_ap1, mac_2, 6);
	memcpy(&hcmd5.mac_sta1, mac_1, 6);
	hcmd5.id1 = eapmd5->eapid;
	memcpy(&hcmd5.challenge, eapmd5->md5data, 16);
	hcmd5.p1 = true;
	changeflag = true;
	}

if((eapmd5->eapcode == EAP_CODE_RESP) && (eapmd5->eapvaluesize == 16)) 
	{
	hcmd5.id2 = eapmd5->eapid;
	memcpy(&hcmd5.mac_ap2, mac_1, 6);
	memcpy(&hcmd5.mac_sta2, mac_2, 6);
	memcpy(&hcmd5.response, eapmd5->md5data, 16);
	hcmd5.p2 = true;
	changeflag = true;
	}

if((idcheck == true) & (hcmd5.id1 != hcmd5.id2))
	return false;

if((changeflag == true) && (hcmd5.id1 == hcmd5.id2) && (hcmd5.p1 == true) && (hcmd5.p2 == true) && (memcmp(&hcmd5.mac_ap1, &hcmd5.mac_ap2, 6) == 0) && (memcmp(&hcmd5.mac_sta1, &hcmd5.mac_sta2, 6) == 0))
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
	return true;
	}
return false;
}
/*===========================================================================*/
bool addleap(uint8_t *mac_1, uint8_t *mac_2, eapext_t *eapext)
{
FILE *fhhash = NULL;
FILE *fhuser = NULL;
eapleap_t *eapleap = NULL;
int eaplen;
int c;
uint8_t changeflag = false;
char *ptr = NULL;

eapleap = (eapleap_t*)(eapext);
if(eapleap->leapversion != 1)
	return false;

eaplen = htobe16(eapleap->eaplen);
if((eaplen <= 8) || (eaplen > 258 +16))
	return false;

if((eapleap->eapcode == EAP_CODE_REQ) && (eapleap->leapcount == 8))
	{
	memcpy(&hcleap.mac_ap1, mac_2, 6);
	memcpy(&hcleap.mac_sta1, mac_1, 6);
	hcleap.leapid1 = eapleap->eapid;
	memset(&hcleap.username, 0, 258);
	memcpy(&hcleap.peerchallenge, eapleap->leapdata, eapleap->leapcount);
	memcpy(&hcleap.username, eapleap->leapdata +8, (eaplen -eapleap->leapcount -8));
	hcleap.p1 = true;
	changeflag = true;
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
	hcleap.p2 = true;
	changeflag = true;
	}

if((idcheck == true) & (hcleap.leapid1 != hcleap.leapid2))
	return false;

if((changeflag == true) && (hcleap.p1 == true) && (hcleap.p2 == true) && (memcmp(&hcleap.mac_ap1, &hcleap.mac_ap2, 6) == 0) && (memcmp(&hcleap.mac_sta1, &hcleap.mac_sta2, 6) == 0))
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
	return true;
	}
return false;
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
bool checkmynonce(uint8_t *eapdata)
{
eap_t *eap;

eap = (eap_t*)(uint8_t*)(eapdata);
if(memcmp(eap->nonce, &mynonce, 32) == 0)
	return true;
return false;
}
/*===========================================================================*/
void showinfo(hcx_t *hcxrecord)
{
char outstr[256] = {0};
FILE *fhshowinfo2 = NULL;

if(showinfo1 == true)
	{
	if(showhashrecord(hcxrecord, NULL, 0, outstr) == true)
		printf("%s\n", outstr);
	}

if(showinfo2 == true)
	{
	if(showinfo2outname != NULL)
		{
		if((fhshowinfo2 = fopen(showinfo2outname, "ab")) == NULL)
			{
			fprintf(stderr, "error opening hccapx file %s\n", showinfo2outname);
			exit(EXIT_FAILURE);
			}
		}

	if(showhashrecord(hcxrecord, NULL, 0, outstr) == true)
		fprintf(fhshowinfo2, "%s\n", outstr);

	fclose(fhshowinfo2);
	}
}
/*===========================================================================*/
void writehcx(uint8_t essid_len, uint8_t *essid, eapdb_t *zeiger1, eapdb_t *zeiger2, uint8_t message_pair)
{
hcx_t hcxrecord;
eap_t *eap1;
eap_t *eap2;
FILE *fhhcx = NULL;

unsigned long long int r;
bool wldflagint = false;

uint8_t pmk[32];

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
		anecflag = true;

memcpy(&oldhcxrecord, &hcxrecord, HCX_SIZE);
hcxwritecount++;

if(hcxrecord.keyver == 1)
	wpakv1c++;
if(hcxrecord.keyver == 2)
	wpakv2c++;
if(hcxrecord.keyver == 3)
	wpakv3c++;
if((hcxrecord.keyver &4) == 4)
	wpakv4c++;

memset(&pmk, 0,32);
if((weakpassflag == true) && (wpatesthash(&hcxrecord, pmk) == true))
	{
	weakpasscount++;
	return;
	}
else if(wpatesthash(&hcxrecord, pmk) == true)
	weakpasscount++;

r = getreplaycount(zeiger2->eapol);
if((r == MYREPLAYCOUNT) && (memcmp(&mynonce, eap1->nonce, 32) == 0))
	{
	hcxwritewldcount++;
	wldflagint = true;
	}

if((hcxoutname != NULL) && ((hcxrecord.keyver == 1) || (hcxrecord.keyver == 2) || (hcxrecord.keyver == 3)))
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", hcxoutname);
		exit(EXIT_FAILURE);
		}
	fwrite(&hcxrecord, 1 * HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	showinfo(&hcxrecord);
	}

if((wdfhcxoutname != NULL) && (wldflagint == true) && ((hcxrecord.keyver == 1) || (hcxrecord.keyver == 2) || (hcxrecord.keyver == 3)))
	{
	if((fhhcx = fopen(wdfhcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", wdfhcxoutname);
		exit(EXIT_FAILURE);
		}
	fwrite(&hcxrecord, 1 * HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	showinfo(&hcxrecord);
	}

if((nonwdfhcxoutname != NULL) && (wldflagint == false) && ((hcxrecord.keyver == 1) || (hcxrecord.keyver == 2) || (hcxrecord.keyver == 3)))
	{
	if((fhhcx = fopen(nonwdfhcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", nonwdfhcxoutname);
		exit(EXIT_FAILURE);
		}
	fwrite(&hcxrecord, 1 * HCX_SIZE, 1, fhhcx);
	fclose(fhhcx);
	showinfo(&hcxrecord);
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
			if(netexact == true)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M14E4);
			return;
			}
		}
	zeiger--;
	c--;
	}

if(replaycountcheck == true)
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
		if((m == 1) && (r != MYREPLAYCOUNT) && (checkmynonce(zeiger->eapol) == false))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M14E4NR);
			if(netexact == true)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M14E4NR);
			ancflag = true;
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
			if(netexact == true)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M34E4);

			return;
			}
		}
	zeiger--;
	c--;
	}

if(replaycountcheck == true)
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
			if(netexact == true)
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
			if(netexact == true)
				lookforessidexact(zeigerakt, zeiger, MESSAGE_PAIR_M32E2);
			return;
			}
		}
	zeiger--;
	c--;
	}

if(replaycountcheck == true)
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
			if(netexact == true)
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
			if(netexact == true)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M12E2);
			return;
			}
		}
	zeiger--;
	c--;
	}


if(replaycountcheck == true)
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
		if((m == 1) && (r != MYREPLAYCOUNT) && (checkmynonce(zeiger->eapol) == false))
			{
			lookforessid(zeiger, zeigerakt, MESSAGE_PAIR_M12E2NR);
			if(netexact == true)
				lookforessidexact(zeiger, zeigerakt, MESSAGE_PAIR_M12E2NR);
			ancflag = true;
			return;
			}
		}
	zeiger--;
	c--;
	}
return;
}
/*===========================================================================*/
bool addeapol(time_t tvsec, time_t tvusec, uint8_t *mac_sta, uint8_t *mac_ap, eap_t *eap)
{
unsigned long long int replaycount;
uint8_t m = 0;

if(memcmp(mac_ap, mac_sta, 6) == 0)
	return false;
if(memcmp(eap->nonce, &nullnonce, NULLNONCE_SIZE) == 0)
	return false;
memset(neweapdbdata, 0, EAPDB_SIZE);
neweapdbdata->tv_sec = tvsec;
neweapdbdata->tv_usec = tvusec;
memcpy(neweapdbdata->mac_ap.addr, mac_ap, 6);
memcpy(neweapdbdata->mac_sta.addr, mac_sta, 6);
neweapdbdata->eapol_len = htobe16(eap->len) +4;

if((neweapdbdata->eapol_len < 91) || (neweapdbdata->eapol_len > 256 -4))
	return false;

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

return true;
}
/*===========================================================================*/
bool addnet(time_t tvsec, time_t tvusec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essid)
{
if(memcmp(mac_ap, mac_sta, 6) == 0)
	return false;

memset(newnetdbdata, 0, NETDB_SIZE);
newnetdbdata->tv_sec = tvsec;
newnetdbdata->tv_usec = tvusec;
memcpy(newnetdbdata->mac_ap.addr, mac_ap, 6);
memcpy(newnetdbdata->mac_sta.addr, mac_sta, 6);
newnetdbdata->essid_len = essid_len;
memcpy(newnetdbdata->essid, essid, essid_len);
if(newnetdbdata->essid[0] == 0)
	return false;
newnetdbdata++;
netdbrecords++;
return true;
}
/*===========================================================================*/
int checkessid(uint8_t essid_len, uint8_t *essid)
{
uint8_t p;

if(essid_len == 0)
	return false;

if(essid_len > 32)
	return false;

for(p = 0; p < essid_len; p++)
	if((essid[p] < 0x20) || (essid[p] > 0x7e))
		return false;
return true;
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
bool processcap(char *pcapinname, char *essidoutname, char *essidunicodeoutname, char *pmkoutname, char *externalbpfname)
{
struct stat statinfo;
struct pcap_pkthdr *pkh;
pcap_t *pcapin = NULL;
ether_header_t *eth = NULL;
loopb_header_t *loopbh = NULL;

rth_t *rth = NULL;
ppi_packet_header_t *ppih = NULL;
mac_t *macf = NULL;
eap_t *eap = NULL;
eapext_t *eapext = NULL;
essid_t *essidf = NULL;
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
uint8_t	*payload = NULL;
mpdu_frame_t* enc = NULL;
int encsystem = 0;
netdb_t *zeigernet;
FILE *fhessid = NULL;
FILE *fhpmk = NULL;
int macl = 0;
int fcsl = 0;
uint8_t field = 0;
int datalink = 0;
int pcapstatus;
long int packetcount = 0;
long int wlanpacketcount = 0;
long int ethpacketcount = 0;
long int loopbpacketcount = 0;

ipv4_frame_t *ipv4h = NULL;
ipv6_frame_t *ipv6h = NULL;
uint8_t ipv4hlen = 0;
uint8_t pppchapflag = false;

udp_frame_t *udph = NULL;
int udpports = 0;
int udpportd = 0;
int c, c1;
int llctype;


uint8_t meshflag = false;

uint8_t eap3flag = false;
uint8_t eap4flag = false;
uint8_t eap5flag = false;
uint8_t eap6flag = false;
uint8_t eap9flag = false;
uint8_t eap10flag = false;
uint8_t eap11flag = false;
uint8_t eap12flag = false;
uint8_t eap13flag = false;
uint8_t eap14flag = false;
uint8_t eap15flag = false;
uint8_t eap16flag = false;
uint8_t eap17flag = false;
uint8_t eap18flag = false;
uint8_t eap19flag = false;
uint8_t eap21flag = false;
uint8_t eap22flag = false;
uint8_t eap23flag = false;
uint8_t eap24flag = false;
uint8_t eap25flag = false;
uint8_t eap26flag = false;
uint8_t eap27flag = false;
uint8_t eap28flag = false;
uint8_t eap29flag = false;
uint8_t eap30flag = false;
uint8_t eap31flag = false;
uint8_t eap32flag = false;
uint8_t eap33flag = false;
uint8_t eap34flag = false;
uint8_t eap35flag = false;
uint8_t eap36flag = false;
uint8_t eap37flag = false;
uint8_t eap38flag = false;
uint8_t eap39flag = false;
uint8_t eap40flag = false;
uint8_t eap41flag = false;
uint8_t eap42flag = false;
uint8_t eap43flag = false;
uint8_t eap44flag = false;
uint8_t eap45flag = false;
uint8_t eap46flag = false;
uint8_t eap47flag = false;
uint8_t eap48flag = false;
uint8_t eap49flag = false;
uint8_t eap50flag = false;
uint8_t eap51flag = false;
uint8_t eap52flag = false;
uint8_t eap53flag = false;
uint8_t eap54flag = false;
uint8_t eap55flag = false;
uint8_t eap254flag = false;
uint8_t eap255flag = false;

uint8_t ipv4flag = false;
uint8_t ipv6flag = false;
uint8_t tcpflag = false;
uint8_t udpflag = false;
uint8_t radiusflag = false;

uint8_t preautflag = false;
uint8_t frrrflag = false;

uint8_t wepdataflag = false;
uint8_t wpadataflag = false;

char pcaperrorstring[PCAP_ERRBUF_SIZE];

wcflag = false;
ancflag = false;
anecflag = false;
hcxwritecount = 0;
hcxwritewldcount = 0;
weakpasscount = 0;
wpakv1c = 0;
wpakv2c = 0;
wpakv3c = 0;
wpakv4c = 0;


if(!(pcapin = pcap_open_offline(pcapinname, pcaperrorstring)))
	{
	fprintf(stderr, "error opening %s %s\n", pcaperrorstring, pcapinname);
	return false;
	}

datalink = pcap_datalink(pcapin);
if((datalink != DLT_IEEE802_11) && (datalink != DLT_IEEE802_11_RADIO) && (datalink != DLT_PPI) && (datalink != DLT_EN10MB) && (datalink != DLT_NULL))
	{
	fprintf (stderr, "unsupported datalinktyp %d\n", datalink);
	return false;
	}

if((datalink == DLT_IEEE802_11) || (datalink == DLT_IEEE802_11_RADIO) || (datalink == DLT_PPI) || (datalink == DLT_EN10MB))
	{
	installbpf(pcapin, externalbpfname);
	}

if(stat(pcapinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat cap file %s\n", pcapinname);
	return false;
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
	if((pkh->ts.tv_sec == 0) && (pkh->ts.tv_usec == 0))
		wcflag = true;


	/* check Loopback-header */
	if(datalink == DLT_NULL)
		{
		if(LOOPB_SIZE > pkh->len)
			continue;
		loopbpacketcount++;
		loopbh = (loopb_header_t*)packet;
		if(be32toh(loopbh->family) != 2)
			continue;
		if(LOOPB_SIZE +IPV4_SIZE_MIN > pkh->len)
			continue;

		ipv4h = (ipv4_frame_t*)(packet +LOOPB_SIZE);
		ipv4h = (ipv4_frame_t*)(packet +LOOPB_SIZE);
		if((ipv4h->ver_hlen & 0xf0) == 0x40)
			{
			ipv4hlen = (ipv4h->ver_hlen & 0x0f) * 4;
			ipv4flag = true;
			if(ipv4h->nextprotocol == NEXTHDR_NONE)
				continue;

			if(ipv4h->nextprotocol == NEXTHDR_GRE)
				{
				if(addpppchap(eth->addr1.addr, eth->addr2.addr, (uint8_t*)packet +LOOPB_SIZE +ipv4hlen) == true)
					pppchapflag = true;
				continue;
				}

			if(ipv4h->nextprotocol == NEXTHDR_TCP)
				{
				tcpflag = true;
				continue;
				}

			if(ipv4h->nextprotocol == NEXTHDR_UDP)
				{
				udpflag = true;
				udph = (udp_frame_t*)(packet +LOOPB_SIZE +ipv4hlen);
				udpports = htobe16(udph->port_source);
				udpportd = htobe16(udph->port_destination);
				if((udpports == 1812) || (udpportd == 1812))
					radiusflag = true;
				continue;
				}
			continue;
			}

		ipv6h = (ipv6_frame_t*)(packet +LOOPB_SIZE);
		if((ipv6h->ver_class & 0xf0) == 0x60)
			{
			ipv6flag = true;
			if(ipv6h->nextprotocol == NEXTHDR_NONE)
				continue;

			if(ipv6h->nextprotocol == NEXTHDR_GRE)
				{
				if(addpppchap(eth->addr1.addr, eth->addr2.addr, (uint8_t*)packet +ETHER_SIZE +IPV6_SIZE) == true)
					pppchapflag = true;
				continue;
				}
			if(ipv6h->nextprotocol == NEXTHDR_TCP)
				{
				tcpflag = true;
				continue;
				}

			if(ipv6h->nextprotocol == NEXTHDR_UDP)
				{
				udpflag = true;
				udph = (udp_frame_t*)(packet +LOOPB_SIZE +IPV6_SIZE);
				udpports = htobe16(udph->port_source);
				udpportd = htobe16(udph->port_destination);
				if((udpports == 1812) || (udpportd == 1812))
					radiusflag = true;
				continue;
				}
			continue;
			}

		continue;
		}

	/* check Ethernet-header */
	if(datalink == DLT_EN10MB)
		{
		if(ETHER_SIZE > pkh->len)
			continue;
		ethpacketcount++;
		eth = (ether_header_t*)packet;
		if(ETHER_SIZE +LLC_SIZE > pkh->len)
			continue;
		llctype = be16toh(eth->ether_type);
		if(llctype == LLC_TYPE_IPV4)
			{
			ipv4flag = true;
			ipv4h = (ipv4_frame_t*)(packet +ETHER_SIZE);
			if((ipv4h->ver_hlen & 0xf0) != 0x40)
				continue;
			ipv4hlen = (ipv4h->ver_hlen & 0x0f) * 4;
			if(ipv4h->nextprotocol == NEXTHDR_NONE)
				continue;
			if(ipv4h->nextprotocol == NEXTHDR_GRE)
				{
				if(addpppchap(eth->addr1.addr, eth->addr2.addr, (uint8_t*)packet +ETHER_SIZE +ipv4hlen) == true)
					pppchapflag = true;
				continue;
				}
			if(ipv4h->nextprotocol == NEXTHDR_TCP)
				{
				tcpflag = true;
				continue;
				}
			if(ipv4h->nextprotocol == NEXTHDR_UDP)
				{
				udpflag = true;
				udph = (udp_frame_t*)(packet +ETHER_SIZE +ipv4hlen);
				udpports = htobe16(udph->port_source);
				udpportd = htobe16(udph->port_destination);
				if((udpports == 1812) || (udpportd == 1812))
					radiusflag = true;

				continue;
				}
			}

		else if(llctype == LLC_TYPE_IPV6)
			{
			ipv6flag = true;
			ipv6h = (ipv6_frame_t*)(packet +ETHER_SIZE);
			if((be32toh(ipv6h->ver_class) & 0xf) != 6)
				continue;
			if(ipv6h->nextprotocol == NEXTHDR_NONE)
				continue;
			if(ipv6h->nextprotocol == NEXTHDR_GRE)
				{
				if(addpppchap(eth->addr1.addr, eth->addr2.addr, (uint8_t*)packet +ETHER_SIZE +IPV6_SIZE) == true)
					pppchapflag = true;
				continue;
				}
			if(ipv6h->nextprotocol == NEXTHDR_TCP)
				{
				tcpflag = true;
				continue;
				}
			if(ipv6h->nextprotocol == NEXTHDR_UDP)
				{
				udpflag = true;
				udph = (udp_frame_t*)(packet +ETHER_SIZE +IPV6_SIZE);
				udpports = htobe16(udph->port_source);
				udpportd = htobe16(udph->port_destination);
				if((udpports == 1812) || (udpportd == 1812))
					radiusflag = true;
				continue;
				}
			}
		continue;
		}

	wlanpacketcount++;

	/* check 802.11-header */
	if(datalink == DLT_IEEE802_11)
		h80211 = packet;

	/* check radiotap-header */
	else if(datalink == DLT_IEEE802_11_RADIO)
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

	/* check ppi-header */
	else if(datalink == DLT_PPI)
		{
		if(PPIH_SIZE > pkh->len)
			continue;
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

	if(MAC_SIZE_NORM > pkh->len)
		continue;
	macf = (mac_t*)(h80211);
	if((macf->to_ds == 1) && (macf->from_ds == 1))
		{
		macl = MAC_SIZE_LONG;
		meshflag = true;
		}
	else
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
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid);
			}
		else if(macf->subtype == MAC_ST_PROBE_RESP)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid);
			}

		/* check proberequest frames */
		else if(macf->subtype == MAC_ST_PROBE_REQ)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if((macl +BEACONINFO_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
			}

		/* check associationrequest - reassociationrequest frames */
		else if(macf->subtype == MAC_ST_ASSOC_REQ)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if((macl +ASSOCIATIONREQF_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +ASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
			}

		else if(macf->subtype == MAC_ST_REASSOC_REQ)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
			if((macl +REASSOCIATIONREQF_SIZE) > pkh->len)
				continue;
			essidf = (essid_t*)(payload +REASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			addnet(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid);
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
			encsystem = (enc->keyid >> 5) &1;
			if(encsystem == 0)
				wepdataflag = true;
			if(encsystem == 1)
				wpadataflag = true;
			if((encsystem == 0) && (pcapwepout != NULL))
				pcap_dump((u_char *) pcapwepout, pkh, h80211);
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
			if(macf->from_ds == 1) /* sta - ap */
				addeapol(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr1.addr, macf->addr2.addr, eap);

			else if(macf->to_ds == 1) /* ap - sta */
				addeapol(pkh->ts.tv_sec, pkh->ts.tv_usec, macf->addr2.addr, macf->addr1.addr, eap);

			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);
		
			continue;
			}

		else if(eap->type == 0)
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
				eap3flag = true;

			if(eapext->eaptype == EAP_TYPE_MD5)
				{
				if(addeapmd5(macf->addr1.addr, macf->addr2.addr, eapext) == true)
					eap4flag = true;
				}

			if(eapext->eaptype == EAP_TYPE_OTP)
				eap5flag = true;

			if(eapext->eaptype == EAP_TYPE_GTC)
				eap6flag = true;

			if(eapext->eaptype == EAP_TYPE_RSA)
				eap9flag = true;

			if(eapext->eaptype == EAP_TYPE_DSS)
				eap10flag = true;

			if(eapext->eaptype == EAP_TYPE_KEA)
				eap11flag = true;

			if(eapext->eaptype == EAP_TYPE_KEA_VALIDATE)
				eap12flag = true;

			if(eapext->eaptype == EAP_TYPE_TLS)
				eap13flag = true;

			if(eapext->eaptype == EAP_TYPE_AXENT)
				eap14flag = true;

			if(eapext->eaptype == EAP_TYPE_RSA_SSID)
				eap15flag = true;

			if(eapext->eaptype == EAP_TYPE_RSA_ARCOT)
				eap16flag = true;

			if(eapext->eaptype == EAP_TYPE_LEAP)
				{
				if((macf->from_ds == 1) && (macf->to_ds == 0) && (eapext->eapcode == EAP_CODE_REQ))
					{
					if(addleap(macf->addr1.addr, macf->addr2.addr, eapext) == true)
						eap17flag = true;
					}

				else if((macf->from_ds == 0) && (macf->to_ds == 1) && (eapext->eapcode == EAP_CODE_RESP))
					{
					if(addleap(macf->addr1.addr, macf->addr2.addr, eapext) == true)
						eap17flag = true;
					}
				}

			if(eapext->eaptype == EAP_TYPE_SIM)
				eap18flag = true;

			if(eapext->eaptype == EAP_TYPE_SRP_SHA1)
				eap19flag = true;

			if(eapext->eaptype == EAP_TYPE_TTLS)
				eap21flag = true;

			if(eapext->eaptype == EAP_TYPE_RAS)
				eap22flag = true;

			if(eapext->eaptype == EAP_TYPE_AKA)
				eap23flag = true;

			if(eapext->eaptype == EAP_TYPE_3COMEAP)
				eap24flag = true;

			if(eapext->eaptype == EAP_TYPE_PEAP)
				eap25flag = true;

			if(eapext->eaptype == EAP_TYPE_MSEAP)
				eap26flag = true;

			if(eapext->eaptype == EAP_TYPE_MAKE)
				eap27flag = true;

			if(eapext->eaptype == EAP_TYPE_CRYPTOCARD)
				eap28flag = true;

			if(eapext->eaptype == EAP_TYPE_MSCHAPV2)
				eap29flag = true;

			if(eapext->eaptype == EAP_TYPE_DYNAMICID)
				eap30flag = true;

			if(eapext->eaptype == EAP_TYPE_ROB)
				eap31flag = true;

			if(eapext->eaptype == EAP_TYPE_POTP)
				eap32flag = true;

			if(eapext->eaptype == EAP_TYPE_MSTLV)
				eap33flag = true;

			if(eapext->eaptype == EAP_TYPE_SENTRI)
				eap34flag = true;

			if(eapext->eaptype == EAP_TYPE_AW)
				eap35flag = true;

			if(eapext->eaptype == EAP_TYPE_CSBA)
				eap36flag = true;

			if(eapext->eaptype == EAP_TYPE_AIRFORT)
				eap40flag = true;

			if(eapext->eaptype == EAP_TYPE_HTTPD)
				eap38flag = true;

			if(eapext->eaptype == EAP_TYPE_SS)
				eap39flag = true;

			if(eapext->eaptype == EAP_TYPE_DC)
				eap40flag = true;

			if(eapext->eaptype == EAP_TYPE_SPEKE)
				eap41flag = true;

			if(eapext->eaptype == EAP_TYPE_MOBAC)
				eap42flag = true;

			if(eapext->eaptype == EAP_TYPE_FAST)
				eap43flag = true;

			if(eapext->eaptype == EAP_TYPE_ZLXEAP)
				eap44flag = true;

			if(eapext->eaptype == EAP_TYPE_LINK)
				eap45flag = true;

			if(eapext->eaptype == EAP_TYPE_PAX)
				eap46flag = true;

			if(eapext->eaptype == EAP_TYPE_PSK)
				eap47flag = true;

			if(eapext->eaptype == EAP_TYPE_SAKE)
				eap48flag = true;

			if(eapext->eaptype == EAP_TYPE_IKEV2)
				eap49flag = true;

			if(eapext->eaptype == EAP_TYPE_AKA1)
				eap50flag = true;

			if(eapext->eaptype == EAP_TYPE_GPSK)
				eap51flag = true;

			if(eapext->eaptype == EAP_TYPE_PWD)
				eap52flag = true;

			if(eapext->eaptype == EAP_TYPE_EKE1)
				eap53flag = true;

			if(eapext->eaptype == EAP_TYPE_PTEAP)
				eap54flag = true;

			if(eapext->eaptype == EAP_TYPE_TEAP)
				eap55flag = true;

			if(eapext->eaptype == EAP_TYPE_EXPAND)
				eap254flag = true;

			if(eapext->eaptype == EAP_TYPE_EXPERIMENTAL)
				eap255flag = true;

			continue;
			}

		else if(eap->type == 1)
			{
			if(pcapout != NULL)
				pcap_dump((u_char *) pcapout, pkh, h80211);

			if(pcapextout != NULL)
				pcap_dump((u_char *) pcapextout, pkh, h80211);

			continue;
			}
		}

	else if((be16toh(((llc_t*)payload)->type) == LLC_TYPE_IPV4))
		{
		ipv4flag = true;
		if(pcapipv46out != NULL)
			pcap_dump((u_char *) pcapipv46out, pkh, h80211);

		if(pkh->len < (macl +LLC_SIZE +IPV4_SIZE_MIN +GRE_MIN_SIZE +PPP_SIZE +PPPCHAPHDR_MIN_CHAL_SIZE))
			continue;

		ipv4h = (ipv4_frame_t*)(payload +LLC_SIZE);
		ipv4hlen = (ipv4h->ver_hlen & 0x0f) * 4;
		if((ipv4h->ver_hlen & 0xf0) != 0x40)
			continue;

		if(ipv4h->nextprotocol == NEXTHDR_NONE)
			continue;

		if(ipv4h->nextprotocol == NEXTHDR_GRE)
			{
			if(addpppchap(macf->addr1.addr, macf->addr2.addr, payload + LLC_SIZE +ipv4hlen) == true)
				{
				if(pcapout != NULL)
					pcap_dump((u_char *) pcapout, pkh, h80211);
				pppchapflag = true;
				}
			continue;
			}

		if(ipv4h->nextprotocol == NEXTHDR_TCP)
			{
			tcpflag = true;
			}

		if(ipv4h->nextprotocol == NEXTHDR_UDP)
			{
			udpflag = true;
			udph = (udp_frame_t*)(payload + LLC_SIZE +ipv4hlen);
			udpports = htobe16(udph->port_source);
			udpportd = htobe16(udph->port_destination);
			if((udpports == 1812) || (udpportd == 1812))
				radiusflag = true;
			}
		continue;
		}

	else if((be16toh(((llc_t*)payload)->type) == LLC_TYPE_IPV6))
		{
		ipv6flag = true;
		if(pcapipv46out != NULL)
			pcap_dump((u_char *) pcapipv46out, pkh, h80211);

		ipv6h = (ipv6_frame_t*)(payload +LLC_SIZE);
		if((be32toh(ipv6h->ver_class) & 0xf) != 6)
			continue;

		if(ipv6h->nextprotocol == NEXTHDR_NONE)
			continue;

		if(ipv6h->nextprotocol == NEXTHDR_GRE)
			{
			if(addpppchap(macf->addr1.addr, macf->addr2.addr, payload + LLC_SIZE +IPV6_SIZE) == true)
				{
				if(pcapout != NULL)
					pcap_dump((u_char *) pcapout, pkh, h80211);
				pppchapflag = true;
				}
			continue;
			}

		if(ipv6h->nextprotocol == NEXTHDR_TCP)
			{
			tcpflag = true;
			continue;
			}

		if(ipv6h->nextprotocol == NEXTHDR_UDP)
			{
			udpflag = true;
			udph = (udp_frame_t*)(payload + LLC_SIZE +IPV6_SIZE);
			udpports = htobe16(udph->port_source);
			udpportd = htobe16(udph->port_destination);
			if((udpports == 1812) || (udpportd == 1812))
				radiusflag = true;
			continue;
			}

		continue;
		}

	else if((be16toh(((llc_t*)payload)->type) == LLC_TYPE_PREAUT))
		{
		preautflag = true;
		continue;
		}

	else if((be16toh(((llc_t*)payload)->type) == LLC_TYPE_FRRR))
		frrrflag = true;
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
		if(checkessid(zeigernet->essid_len, zeigernet->essid) == true)
			fprintf(fhessid, "%s\n", zeigernet->essid);

		else
			{
			fprintf(fhessid, "$HEX[");
			for(c1 = 0; c1 < zeigernet->essid_len; c1++)
				fprintf(fhessid, "%02x", zeigernet->essid[c1]);
			fprintf(fhessid, "]\n");
			}
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

if(pmkoutname != NULL)
	{
	if((fhpmk = fopen(pmkoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", pmkoutname);
		exit(EXIT_FAILURE);
		}

	zeigernet = netdbdata;
	for(c = 0; c < netdbrecords; c++)
		{
		if(zeigernet->essid_len == 32)
			{
			for(c1 = 0; c1 < 32; c1++)
				fprintf(fhpmk, "%02x", zeigernet->essid[c1]);
			fprintf(fhpmk, "\n");
			}

		zeigernet++;
		}

	fclose(fhpmk);
	}

free(eapdbdata);
free(netdbdata);
pcap_close(pcapin);
printf("%ld packets processed (%ld wlan, %ld lan, %ld loopback)\n", packetcount, wlanpacketcount, ethpacketcount, loopbpacketcount);

if(hcxwritecount == 1)
	printf("\x1B[32mtotal %ld usefull wpa handshake\x1B[0m\n", hcxwritecount);
else if(hcxwritecount > 1)
	printf("\x1B[32mtotal %ld usefull wpa handshakes\x1B[0m\n", hcxwritecount);

if(weakpasscount == 1)
	printf("\x1B[32mfound %ld handshake with zeroed plainmasterkeys (hashcat -m 2501 with a zeroed plainmasterkey)\x1B[0m\n", weakpasscount);
else if(weakpasscount > 1)
	printf("\x1B[32mfound %ld handshakes with zeroed plainmasterkeys (hashcat -m 2501 with a zeroed plainmasterkey)\x1B[0m\n", weakpasscount);

if(wpakv1c > 0)
	printf("\x1B[32mfound %ld WPA1 RC4 Cipher, HMAC-MD5\x1B[0m\n", wpakv1c);

if(wpakv2c > 0)
	printf("\x1B[32mfound %ld WPA2 AES Cipher, HMAC-SHA1\x1B[0m\n", wpakv2c);

if(wpakv3c > 0)
	printf("\x1B[32mfound %ld WPA2 AES Cipher, AES-128-CMAC\x1B[0m\n", wpakv3c);

if(wpakv4c > 0)
	printf("\x1B[32mfound %ld Groupkeys\x1B[0m\n", wpakv4c);

if(hcxwritewldcount == 1)
	{
	printf("\x1B[32mfound %ld valid WPA handshake (by wlandump-ng/wlanresponse)\x1B[0m\n", hcxwritewldcount);
	if(wdfhcxoutname != NULL)
		printf("\x1B[32myou can use hashcat --nonce-error-corrections=0 on %s\x1B[0m\n", wdfhcxoutname);
	}
else if(hcxwritewldcount > 1)
	{
	printf("\x1B[32mfound %ld valid WPA handshakes (by wlandump-ng/wlanresponse)\x1B[0m\n", hcxwritewldcount);
	if(wdfhcxoutname != NULL)
		printf("\x1B[32myou can use hashcat --nonce-error-corrections=0 on %s\x1B[0m\n", wdfhcxoutname);
	}

if((anecflag == true) && (wdfhcxoutname == NULL))
	printf("\x1B[32mhashcat --nonce-error-corrections is working on that file\x1B[0m\n");

if((ancflag == true) && (hcxoutname != NULL))
	{
	if((rctimecount > 2) && (rctimecount <= 4))
		printf("\x1B[32myou should use hashcat --nonce-error-corrections=16 (or greater) on %s\x1B[0m\n", hcxoutname);
	if((rctimecount > 4) && (rctimecount <= 8))
		printf("\x1B[32myou should use hashcat --nonce-error-corrections=32 (or greater) on %s\x1B[0m\n", hcxoutname);
	if(rctimecount > 8)
		printf("\x1B[32myou should use hashcat --nonce-error-corrections=64 (or greater) on %s\x1B[0m\n", hcxoutname);
	}

if((ancflag == true) && (nonwdfhcxoutname != NULL))
	{
	if((rctimecount > 2) && (rctimecount <= 4))
		printf("\x1B[32myou should use hashcat --nonce-error-corrections=16 (or greater) on %s\x1B[0m\n", nonwdfhcxoutname);
	if((rctimecount > 4) && (rctimecount <= 8))
		printf("\x1B[32myou should use hashcat --nonce-error-corrections=32 (or greater) on %s\x1B[0m\n", nonwdfhcxoutname);
	if(rctimecount > 8)
		printf("\x1B[32myou should use hashcat --nonce-error-corrections=64 (or greater) on %s\x1B[0m\n", nonwdfhcxoutname);
	}


if(eap3flag == true)
	printf("\x1B[36mfound Legacy Nak\x1B[0m\n");

if(eap4flag == true)
	printf("\x1B[36mfound MD5-Challenge (hashcat -m 4800)\x1B[0m\n");

if(eap5flag == true)
	printf("\x1B[36mfound One-Time Password (OTP)\x1B[0m\n");

if(eap6flag == true)
	printf("\x1B[36mfound Generic Token Card (GTC)\x1B[0m\n");

if(eap9flag == true)
	printf("\x1B[36mfound RSA Public Key Authentication\x1B[0m\n");

if(eap10flag == true)
	printf("\x1B[36mfound DSS Unilateral\x1B[0m\n");

if(eap11flag == true)
	printf("\x1B[36mfound KEA\x1B[0m\n");

if(eap12flag == true)
	printf("\x1B[36mfound KEA-VALIDATE\x1B[0m\n");

if(eap13flag == true)
	printf("\x1B[36mfound EAP-TLS Authentication\x1B[0m\n");

if(eap14flag == true)
	printf("\x1B[36mfound Defender Token (AXENT)\x1B[0m\n");

if(eap15flag == true)
	printf("\x1B[36mfound RSA Security SecurID EAP\x1B[0m\n");

if(eap16flag == true)
	printf("\x1B[36mfound Arcot Systems EAP\x1B[0m\n");

if(eap17flag == true)
	printf("\x1B[36mfound EAP-Cisco Wireless Authentication (hashcat -m 5500)\x1B[0m\n");

if(eap18flag == true)
	printf("\x1B[36mfound EAP-SIM (GSM Subscriber Modules) Authentication\x1B[0m\n");

if(eap19flag == true)
	printf("\x1B[36mfound SRP-SHA1 Authentication\x1B[0m\n");

if(eap21flag == true)
	printf("\x1B[36mfound EAP-TTLS Authentication\x1B[0m\n");

if(eap22flag == true)
	printf("\x1B[36mfound Remote Access Service\x1B[0m\n");

if(eap23flag == true)
	printf("\x1B[36mfound EAP-AKA Authentication\x1B[0m\n");

if(eap24flag == true)
	printf("\x1B[36mfound EAP-3Com Wireless Authentication\x1B[0m\n");

if(eap25flag == true)
	printf("\x1B[36mfound PEAP Authentication\x1B[0m\n");

if(eap26flag == true)
	printf("\x1B[36mfound MS-EAP Authentication\x1B[0m\n");

if(eap27flag == true)
	printf("\x1B[36mfound Mutual Authentication w/Key Exchange (MAKE)\x1B[0m\n");

if(eap28flag == true)
	printf("\x1B[36mfound CRYPTOCard\x1B[0m\n");

if(eap29flag == true)
	printf("\x1B[36mfound EAP-MSCHAP-V2 Authentication\x1B[0m\n");

if(eap30flag == true)
	printf("\x1B[36mfound DynamicID\x1B[0m\n");

if(eap31flag == true)
	printf("\x1B[36mfound Rob EAP\x1B[0m\n");

if(eap32flag == true)
	printf("\x1B[36mfound Protected One-Time Password\x1B[0m\n");

if(eap33flag == true)
	printf("\x1B[36mfound MS-Authentication-TLV\x1B[0m\n");

if(eap34flag == true)
	printf("\x1B[36mfound SentriNET\x1B[0m\n");

if(eap35flag == true)
	printf("\x1B[36mfound EAP-Actiontec Wireless Authentication\x1B[0m\n");

if(eap36flag == true)
	printf("\x1B[36mfound Cogent Systems Biometrics Authentication EAP\x1B[0m\n");

if(eap37flag == true)
	printf("\x1B[36mfound AirFortress EAP\x1B[0m\n");

if(eap38flag == true)
	printf("\x1B[36mfound EAP-HTTP Digest\x1B[0m\n");

if(eap39flag == true)
	printf("\x1B[36mfound SecureSuite EAP\x1B[0m\n");

if(eap40flag == true)
	printf("\x1B[36mfound DeviceConnect EAP\x1B[0m\n");

if(eap41flag == true)
	printf("\x1B[36mfound EAP-SPEKE Authentication\x1B[0m\n");

if(eap42flag == true)
	printf("\x1B[36mfound EAP-MOBAC Authentication\x1B[0m\n");

if(eap43flag == true)
	printf("\x1B[36mfound FAST Authentication\x1B[0m\n");

if(eap44flag == true)
	printf("\x1B[36mfound ZoneLabs EAP (ZLXEAP)\x1B[0m\n");

if(eap45flag == true)
	printf("\x1B[36mfound EAP-Link Authetication\x1B[0m\n");

if(eap46flag == true)
	printf("\x1B[36mfound EAP-PAX Authetication\x1B[0m\n");

if(eap47flag == true)
	printf("\x1B[36mfound EAP-PSK Authetication\x1B[0m\n");

if(eap48flag == true)
	printf("\x1B[36mfound EAP-SAKE Authetication\x1B[0m\n");

if(eap49flag == true)
	printf("\x1B[36mfound EAP-IKEv2 Authetication\x1B[0m\n");

if(eap50flag == true)
	printf("\x1B[36mfound EAP-AKA Authetication\x1B[0m\n");

if(eap51flag == true)
	printf("\x1B[36mfound EAP-GPSK Authetication\x1B[0m\n");

if(eap52flag == true)
	printf("\x1B[36mfound EAP-pwd Authetication\x1B[0m\n");

if(eap53flag == true)
	printf("\x1B[36mfound EAP-EKE Version 1 Authetication\x1B[0m\n");

if(eap54flag == true)
	printf("\x1B[36mfound EAP Method Type for PT-EAP Authetication\x1B[0m\n");

if(eap55flag == true)
	printf("\x1B[36mfound TEAP Authetication\x1B[0m\n");

if(eap254flag == true)
	printf("\x1B[36mfound WPS Authentication\x1B[0m\n");

if(eap255flag == true)
	printf("\x1B[36mfound Experimental Authentication\x1B[0m\n");

if(radiusflag == true)
	printf("\x1B[35mfound RADIUS Authentication\x1B[0m\n");

if(preautflag == true)
	printf("\x1B[35mPre-Authentication detected\x1B[0m\n");

if(frrrflag == true)
	printf("\x1B[35mfound Fast Roaming Remote Request\x1B[0m\n");


if(ipv4flag == true)
	printf("\x1B[35mfound IPv4 packets\x1B[0m\n");

if(ipv6flag == true)
	printf("\x1B[35mfound IPv6 packets\x1B[0m\n");

if(tcpflag == true)
	printf("\x1B[35mfound TCP packets\x1B[0m\n");

if(udpflag == true)
	printf("\x1B[35mfound UDP packets\x1B[0m\n");

if(pppchapflag == true)
	printf("\x1B[35mfound PPP CHAP Authentication packets (hashcat -m 5500)\x1B[0m\n");

if(wpadataflag == true)
	printf("\x1B[35mfound WPA encrypted data packets\x1B[0m\n");

if(wepdataflag == true)
	printf("\x1B[35mfound WEP encrypted data packets\x1B[0m\n");

if(meshflag == true)
	printf("\x1B[35mfound WDS or Mesh packets\x1B[0m\n");

if(wcflag == true)
	printf("\x1B[31mwarning: use of wpaclean detected\x1B[0m\n");

return true;	
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
	"-o <file> : output hccapx file (WPA/WPA2/WPA2 AES-128-CMAC: use hashcat -m 2500 or -m 2501)\n"
	"-w <file> : output only wlandump forced to hccapx file\n"
	"-W <file> : output only not wlandump forced to hccapx file\n"
	"-p <file> : output merged pcap file (upload this file to http://wpa-sec.stanev.org)\n"
	"-P <file> : output extended eapol packets pcap file (analysis purpose)\n"
	"-l <file> : output IPv4/IPv6 packets pcap file (analysis purpose)\n"
	"-L <file> : output wep encrypted data packets pcap file (for use with a wep cracker)\n"
	"-m <file> : output extended eapol file (iSCSI CHAP authentication, MD5(CHAP): use hashcat -m 4800)\n"
	"-n <file> : output extended eapol file (PPP-CHAP and NetNTLMv1 authentication: use hashcat -m 5500)\n"
	"-e <file> : output wordlist (autohex enabled) to use as hashcat input wordlist (hashcat -m 2500)\n"
	"-E <file> : output wordlist (autohex disabled) to use as hashcat input wordlist (hashcat -m 2500)\n"
	"-f <file> : output possible wpa/wpa2 pmk list (hashcat -m 2501)\n"
	"-u <file> : output usernames/identities file (hashcat -m 2500)\n"
	"-s        : show info for identified hccapx handshake\n"
	"-S <file> : output info for identified hccapx handshake to file\n"
	"-x        : look for net exact (ap == ap) && (sta == sta)\n"
	"-r        : enable replaycountcheck\n"
	"          : default: disabled - you will get more wpa handshakes, but some of them are uncrackable\n"
	"-i        : enable id check (default: disabled)\n"
	"          : default: disabled - you will get more authentications, but some of them are uncrackable\n"
	"-F <file> : input file containing entries for Berkeley Packet Filter (BPF)\n"
	"          : syntax: https://biot.com/capstats/bpf.html\n"
	"-Z        : ignore zeroed plainmasterkeys\n"
	"-h        : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
pcap_t *pcapdh = NULL;
pcap_t *pcapextdh = NULL;
pcap_t *pcapipv46dh = NULL;
pcap_t *pcapwepdh = NULL;

int auswahl;
int index;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *pcapoutname = NULL;
char *pcapextoutname = NULL;
char *pcapipv46outname = NULL;
char *pcapwepoutname = NULL;
char *essidoutname = NULL;
char *essidunicodeoutname = NULL;
char *pmkoutname = NULL;
char *externalbpfname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

if (argc == 1)
	{
	usage(eigenname);
	exit(EXIT_FAILURE);
	}

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "o:m:n:p:P:l:L:e:E:f:w:W:u:S:F:xrisZhv")) != -1)
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

		case 'L':
		pcapwepoutname = optarg;
		break;

		case 'e':
		essidoutname = optarg;
		break;

		case 'E':
		essidunicodeoutname = optarg;
		break;

		case 'f':
		pmkoutname = optarg;
		break;

		case 'u':
		usernameoutname = optarg;
		break;

		case 'x':
		netexact = true;
		break;

		case 'r':
		replaycountcheck = true;
		break;

		case 'i':
		idcheck = true;
		break;

		case 's':
		showinfo1 = true;
		break;

		case 'S':
		showinfo2outname = optarg;
		showinfo2 = true;
		break;

		case 'F':
		externalbpfname = optarg;
		break;

		case 'Z':
		weakpassflag = true;
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

if(pcapwepoutname != NULL)
	{
	pcapwepdh = pcap_open_dead(DLT_IEEE802_11, 65535);
	if ((pcapwepout = pcap_dump_open(pcapwepdh, pcapwepoutname)) == NULL)
		fprintf(stderr, "\x1B[31merror creating dump file %s\x1B[0m\n", pcapwepoutname);
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
	if(processcap(argv[index], essidoutname, essidunicodeoutname, pmkoutname, externalbpfname) == false)
		fprintf(stderr, "\x1B[31merror processing records from %s\x1B[0m\n", (argv[index]));

	}


if(pcapwepout != NULL)
	pcap_dump_close(pcapwepout);

if(pcapipv46out != NULL)
	pcap_dump_close(pcapipv46out);

if(pcapextout != NULL)
	pcap_dump_close(pcapextout);

if(pcapout != NULL)
	pcap_dump_close(pcapout);
return EXIT_SUCCESS;
}

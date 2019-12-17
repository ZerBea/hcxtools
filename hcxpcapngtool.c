#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#if defined (__APPLE__) || defined(__OpenBSD__)
#define PATH_MAX 255
#include <libgen.h>
#include <sys/socket.h>
#else
#include <stdio_ext.h>
#endif
#ifdef __linux__
#include <linux/limits.h>
#endif

#include "include/version.h"
#include "include/hcxpcapngtool.h"
#include "include/ieee80211.c"
#include "include/strings.c"
#include "include/byteops.c"
#include "include/fileops.c"
#include "include/hashops.c"
#include "include/pcap.c"
#include "include/gzops.c"

/*===========================================================================*/
/* global var */

static maclist_t *aplist, *aplistptr;
static messagelist_t *messagelist;
static handshakelist_t *handshakelist, *handshakelistptr;
static pmkidlist_t *pmkidlist, *pmkidlistptr;

static char *jtrbasename;
static FILE *fh_pmkideapolhc;
static FILE *fh_pmkideapoljtr;

static int maclistmax;
static int messagelistmax;
static int handshakelistmax;
static int pmkidlistmax;
static int fd_pcap;

static int endianess;
static uint16_t versionmajor;
static uint16_t versionminor;
static uint16_t dltlinktype;

static long int rawpacketcount;
static long int pcapreaderrors;
static long int skippedpacketcount;
static long int fcsframecount;
static long int beaconcount;
static long int proberesponsecount;
static long int proberequestcount;
static long int proberequestdirectedcount;
static long int authopensystemcount;
static long int authseacount;
static long int authsharedkeycount;
static long int authfbtcount;
static long int authfilscount;
static long int authfilspfs;
static long int authfilspkcount;
static long int authnetworkeapcount;
static long int authunknowncount;
static long int associationrequestcount;
static long int reassociationrequestcount;
static long int pmkidcount;
static long int pmkiduselesscount;
static long int pmkidwrittenhcount;
static long int pmkidwrittenjcount;
static long int eapolmsgcount;
static long int eapolmpcount;
static long int eapolm1count;
static long int eapolm2count;
static long int eapolm3count;
static long int eapolm4count;
static long int eapolwrittenhcount;
static long int eapolaplesscount;
static long int eapolwrittenjcount;

static uint64_t timestampstart;
static uint32_t eapoltimeoutvalue;
static uint64_t ncvalue;
static int essidsvalue;

static bool ignoreieflag;

static uint8_t myaktap[6];
static uint8_t myaktclient[6];
static uint8_t myaktanonce[32];
static uint8_t myaktsnonce[32];
static uint64_t myaktreplaycount;

static char pcapnghwinfo[OPTIONLEN_MAX];
static char pcapngosinfo[OPTIONLEN_MAX];
static char pcapngapplinfo[OPTIONLEN_MAX];
static char pcapngoptioninfo[OPTIONLEN_MAX];
static char pcapngweakcandidate[OPTIONLEN_MAX];
static uint8_t pcapngdeviceinfo[6];

/*===========================================================================*/
static inline void debugprint(int len, uint8_t *ptr)
{
static int p;

fprintf(stdout, "\nRAW: "); 

for(p = 0; p < len; p++)
	{
	fprintf(stdout, "%02x", ptr[p]);
	}
fprintf(stdout, "\n");
return;
}
/*===========================================================================*/
static void closelists()
{

if(aplist != NULL) free(aplist);
if(messagelist != NULL) free(messagelist);
if(handshakelist != NULL) free(handshakelist);
if(pmkidlist != NULL) free(pmkidlist);

return;
}
/*===========================================================================*/
static bool initlists()
{
static char nastring[] = { "N/A" };

maclistmax = MACLIST_MAX;
if((aplist = (maclist_t*)calloc((maclistmax +1), MACLIST_SIZE)) == NULL) return false;
aplistptr = aplist;
messagelistmax = ncvalue;
if((messagelist = (messagelist_t*)calloc((MESSAGELIST_MAX +1), MESSAGELIST_SIZE)) == NULL) return false;

handshakelistmax = HANDSHAKELIST_MAX;
if((handshakelist = (handshakelist_t*)calloc((handshakelistmax +1), HANDSHAKELIST_SIZE)) == NULL) return false;
handshakelistptr = handshakelist;

pmkidlistmax = PMKIDLIST_MAX;
if((pmkidlist = (pmkidlist_t*)calloc((pmkidlistmax +1),PMKIDLIST_SIZE)) == NULL) return false;
pmkidlistptr = pmkidlist;

memset(&pcapnghwinfo, 0, OPTIONLEN_MAX);
memset(&pcapngosinfo, 0, OPTIONLEN_MAX);
memset(&pcapngapplinfo, 0, OPTIONLEN_MAX);
memset(&pcapngoptioninfo, 0, OPTIONLEN_MAX);
memset(&pcapngweakcandidate, 0 ,OPTIONLEN_MAX);
memset(&pcapngdeviceinfo, 0 ,6);
memset(&myaktap, 0 ,6);
memset(&myaktclient, 0 ,6);

memcpy(&pcapnghwinfo, nastring, 3);
memcpy(&pcapngosinfo, nastring, 3);
memcpy(&pcapngapplinfo, nastring, 3);
memcpy(&pcapngoptioninfo, nastring, 3);
memcpy(&pcapngweakcandidate, nastring, 3);

endianess = 0;
rawpacketcount = 0;
pcapreaderrors = 0;
skippedpacketcount = 0;
fcsframecount = 0;
beaconcount = 0;
proberesponsecount = 0;
proberequestcount = 0;
proberequestdirectedcount = 0;
authopensystemcount = 0;
authseacount = 0;
authsharedkeycount = 0;
authfbtcount = 0;
authfilscount = 0;
authfilspfs = 0;
authfilspkcount = 0;
authnetworkeapcount = 0;
authunknowncount = 0;
associationrequestcount = 0;
reassociationrequestcount = 0;
pmkidcount = 0;
pmkiduselesscount = 0;
pmkidwrittenhcount = 0;
pmkidwrittenjcount = 0;
eapolmsgcount = 0;
eapolmpcount = 0;
eapolm1count = 0;
eapolm2count = 0;
eapolm3count = 0;
eapolm4count = 0;
eapolwrittenhcount = 0;
eapolaplesscount = 0;
eapolwrittenjcount = 0;

return true;
}
/*===========================================================================*/
static void printcontentinfo()
{
if(endianess == 0)			printf("endianess.............................: little endian\n");
else					printf("endianess.............................: big endian\n");
if(rawpacketcount > 0)			printf("packets inside........................: %ld\n", rawpacketcount);
if(pcapreaderrors > 0)			printf("read errors...........................: %ld\n", pcapreaderrors);
if(skippedpacketcount > 0)		printf("skipped packets.......................: %ld\n", skippedpacketcount);
if(fcsframecount > 0)			printf("frames with correct FCS...............: %ld\n", fcsframecount);
if(beaconcount > 0)			printf("BEACON................................: %ld\n", beaconcount);
if(proberequestcount > 0)		printf("PROBEREQUEST..........................: %ld\n", proberequestcount);
if(proberequestdirectedcount > 0)	printf("PROBEREQUEST (directed)...............: %ld\n", proberequestdirectedcount);
if(proberesponsecount > 0)		printf("PROBERESONSE..........................: %ld\n", proberesponsecount);
if(authopensystemcount > 0)		printf("AUTHENTICATION (OPEN SYSTEM)..........: %ld\n", authopensystemcount);
if(authseacount > 0)			printf("AUTHENTICATION (SAE)..................: %ld\n", authseacount);
if(authsharedkeycount > 0)		printf("AUTHENTICATION (SHARED KEY)...........: %ld\n", authsharedkeycount);
if(authfbtcount > 0)			printf("AUTHENTICATION (FBT)..................: %ld\n", authfbtcount);
if(authfilscount > 0)			printf("AUTHENTICATION (FILS).................: %ld\n", authfilscount);
if(authfilspfs > 0)			printf("AUTHENTICATION (FILS PFS).............: %ld\n", authfilspfs);
if(authfilspkcount > 0)			printf("AUTHENTICATION (FILS PK...............: %ld\n", authfilspkcount);
if(authnetworkeapcount > 0)		printf("AUTHENTICATION (NETWORK EAP)..........: %ld\n", authnetworkeapcount);
if(authunknowncount > 0)		printf("AUTHENTICATION (unknown)..............: %ld\n", authunknowncount);
if(associationrequestcount > 0)		printf("ASSOCIATIONREQUEST....................: %ld\n", associationrequestcount);
if(reassociationrequestcount > 0)	printf("REASSOCIATIONREQUEST..................: %ld\n", reassociationrequestcount);
if(pmkidcount > 0)			printf("PMKID.................................: %ld\n", pmkidcount);
if(pmkiduselesscount > 0)		printf("PMKID (useless).......................: %ld\n", pmkiduselesscount);
if(pmkidwrittenhcount > 0)		printf("PMKID written to hashcat..............: %ld\n", pmkidwrittenhcount);
if(pmkidwrittenjcount > 0)		printf("PMKID written to JtR..................: %ld\n", pmkidwrittenjcount);
if(eapolmsgcount > 0)			printf("EAPOL messages (total)................: %ld\n", eapolmsgcount);
if(eapolm1count > 0)			printf("EAPOL M1 messages.....................: %ld\n", eapolm1count);
if(eapolm2count > 0)			printf("EAPOL M2 messages.....................: %ld\n", eapolm2count);
if(eapolm3count > 0)			printf("EAPOL M3 messages.....................: %ld\n", eapolm3count);
if(eapolm4count > 0)			printf("EAPOL M4 messages.....................: %ld\n", eapolm4count);
if(eapolmpcount > 0)			printf("EAPOL message pairs...................: %ld\n", eapolmpcount);
if(eapolaplesscount > 0)		printf("EAPOL message pairs (AP-LESS).........: %ld\n", eapolaplesscount);
if(eapolwrittenhcount > 0)		printf("EAPOL message pairs written to hashcat: %ld\n", eapolwrittenhcount);
if(eapolwrittenjcount > 0)		printf("EAPOL message pairs written to JtR....: %ld\n", eapolwrittenjcount);

return;
}
/*===========================================================================*/
static handshakelist_t *gethandshake(maclist_t *zeigermac, handshakelist_t *zeigerhsakt)
{
static int p;
static handshakelist_t *zeigerhs;
static wpakey_t *wpak;

for(zeigerhs = zeigerhsakt; zeigerhs < handshakelistptr; zeigerhs++)
	{
	if(memcmp(zeigermac->addr, zeigerhs->ap, 6) == 0)
		{
		if((zeigerhs->status & ST_APLESS) == ST_APLESS) eapolaplesscount++;
		if((ncvalue > 0) && (zeigerhs->status & ST_APLESS) != ST_APLESS) zeigerhs->status |= ST_NC;
		wpak = (wpakey_t*)(zeigerhs->eapol +EAPAUTH_SIZE);
		if(fh_pmkideapolhc != 0)
			{
			//WPA:TYPE:PMKID-ODER-MIC:MACAP:MACSTA:ESSID_HEX:ANONCE:EAPOL:ZUSATZINFO
			fprintf(fh_pmkideapolhc, "WPA:%02d:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:",
				HCX_TYPE_EAPOL,
				wpak->keymic[0], wpak->keymic[1], wpak->keymic[2], wpak->keymic[3], wpak->keymic[4], wpak->keymic[5] ,wpak->keymic[6], wpak->keymic[7],
				wpak->keymic[8], wpak->keymic[9], wpak->keymic[10], wpak->keymic[11], wpak->keymic[12], wpak->keymic[13] ,wpak->keymic[14], wpak->keymic[15],
				zeigerhs->ap[0], zeigerhs->ap[1], zeigerhs->ap[2], zeigerhs->ap[3], zeigerhs->ap[4], zeigerhs->ap[5],
				zeigerhs->client[0], zeigerhs->client[1], zeigerhs->client[2], zeigerhs->client[3], zeigerhs->client[4], zeigerhs->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkideapolhc, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkideapolhc, ":");
			fprintf(fh_pmkideapolhc, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:",
			zeigerhs->anonce[0], zeigerhs->anonce[1], zeigerhs->anonce[2], zeigerhs->anonce[3], zeigerhs->anonce[4], zeigerhs->anonce[5], zeigerhs->anonce[6], zeigerhs->anonce[7],
			zeigerhs->anonce[8], zeigerhs->anonce[9], zeigerhs->anonce[10], zeigerhs->anonce[11], zeigerhs->anonce[12], zeigerhs->anonce[13], zeigerhs->anonce[14], zeigerhs->anonce[15],
			zeigerhs->anonce[16], zeigerhs->anonce[17], zeigerhs->anonce[18], zeigerhs->anonce[19], zeigerhs->anonce[20], zeigerhs->anonce[21], zeigerhs->anonce[22], zeigerhs->anonce[23],
			zeigerhs->anonce[24], zeigerhs->anonce[25], zeigerhs->anonce[26], zeigerhs->anonce[27], zeigerhs->anonce[28], zeigerhs->anonce[29], zeigerhs->anonce[30], zeigerhs->anonce[31]);
			memset(wpak->keymic, 0, 16);
			for(p = 0; p < zeigerhs->eapauthlen; p++) fprintf(fh_pmkideapolhc, "%02x", zeigerhs->eapol[p]);
			fprintf(fh_pmkideapolhc, ":%02x\n", zeigerhs->status);
			eapolwrittenhcount++;
			}
/*
		if(fh_pmkideapoljtr != 0)
			{
			fprintf(fh_pmkideapoljtr, "%.*s:$WPAPSK$%.*s#", zeigermac->essidlen, zeigermac->essid, zeigermac->essidlen, zeigermac->essid);
			if((zeigerhs->status &0x7) == 0) fprintf(fh_pmkideapoljtr, ":not verified");
			else  fprintf(fh_pmkideapoljtr, ":verified");
			fprintf(fh_pmkideapoljtr, ":%s\n", basename(jtrbasename));
			eapolwrittenjcount++;
			}
*/
		}
	if(memcmp(zeigerhs->ap, zeigermac->addr, 6) > 0)
		{
		zeigerhsakt = zeigerhs;
		return zeigerhsakt;
		}
	}
return zeigerhsakt;
}
/*===========================================================================*/
static pmkidlist_t *getpmkid(maclist_t *zeigermac, pmkidlist_t *zeigerpmkidakt)
{
static int p;
static pmkidlist_t *zeigerpmkid;

for(zeigerpmkid = zeigerpmkidakt; zeigerpmkid < pmkidlistptr; zeigerpmkid++)
	{
	if(memcmp(zeigermac->addr, zeigerpmkid->ap, 6) == 0)
		{
		if(fh_pmkideapolhc != 0)
			{
			//WPA:TYPE:PMKID-ODER-MIC:MACAP:MACSTA:ESSID_HEX:ANONCE:EAPOL:ZUSATZINFO
			fprintf(fh_pmkideapolhc, "WPA:%02d:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:",
				HCX_TYPE_PMKID,
				zeigerpmkid->pmkid[0], zeigerpmkid->pmkid[1], zeigerpmkid->pmkid[2], zeigerpmkid->pmkid[3], zeigerpmkid->pmkid[4], zeigerpmkid->pmkid[5], zeigerpmkid->pmkid[6], zeigerpmkid->pmkid[7],
				zeigerpmkid->pmkid[8], zeigerpmkid->pmkid[9], zeigerpmkid->pmkid[10], zeigerpmkid->pmkid[11], zeigerpmkid->pmkid[12], zeigerpmkid->pmkid[13], zeigerpmkid->pmkid[14], zeigerpmkid->pmkid[15],
				zeigerpmkid->ap[0], zeigerpmkid->ap[1], zeigerpmkid->ap[2], zeigerpmkid->ap[3], zeigerpmkid->ap[4], zeigerpmkid->ap[5],
				zeigerpmkid->client[0], zeigerpmkid->client[1], zeigerpmkid->client[2], zeigerpmkid->client[3], zeigerpmkid->client[4], zeigerpmkid->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkideapolhc, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkideapolhc, ":::\n");
			pmkidwrittenhcount++;
			}
		if(fh_pmkideapoljtr != 0)
			{
			fprintf(fh_pmkideapoljtr, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
				zeigerpmkid->pmkid[0], zeigerpmkid->pmkid[1], zeigerpmkid->pmkid[2], zeigerpmkid->pmkid[3], zeigerpmkid->pmkid[4], zeigerpmkid->pmkid[5], zeigerpmkid->pmkid[6], zeigerpmkid->pmkid[7],
				zeigerpmkid->pmkid[8], zeigerpmkid->pmkid[9], zeigerpmkid->pmkid[10], zeigerpmkid->pmkid[11], zeigerpmkid->pmkid[12], zeigerpmkid->pmkid[13], zeigerpmkid->pmkid[14], zeigerpmkid->pmkid[15],
				zeigerpmkid->ap[0], zeigerpmkid->ap[1], zeigerpmkid->ap[2], zeigerpmkid->ap[3], zeigerpmkid->ap[4], zeigerpmkid->ap[5],
				zeigerpmkid->client[0], zeigerpmkid->client[1], zeigerpmkid->client[2], zeigerpmkid->client[3], zeigerpmkid->client[4], zeigerpmkid->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkideapoljtr, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkideapoljtr, "\n");
			pmkidwrittenjcount++;
			}
		}
	if(memcmp(zeigerpmkid->ap, zeigermac->addr, 6) > 0)
		{
		zeigerpmkidakt = zeigerpmkid;
		return zeigerpmkidakt;
		}
	}
return zeigerpmkidakt;
}
/*===========================================================================*/
static void outputwpalists()
{
static maclist_t *zeigermac, *zeigermacold;
static handshakelist_t *zeigerhsakt;
static pmkidlist_t *zeigerpmkidakt;

qsort(aplist, aplistptr -aplist, MACLIST_SIZE, sort_maclist_by_mac_count);
qsort(pmkidlist, pmkidlistptr -pmkidlist, PMKIDLIST_SIZE, sort_pmkidlist_by_mac);
qsort(handshakelist, handshakelistptr -handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_timegap);

zeigerhsakt = handshakelist;
zeigerpmkidakt = pmkidlist;
for(zeigermac = aplist; zeigermac < aplistptr; zeigermac++)
	{
	if(zeigermac->type != AP) continue;
	zeigermacold = zeigermac -essidsvalue;
	if(zeigermacold >= aplist)
		{
		if(memcmp(zeigermacold->addr, zeigermac->addr, 6) == 0) continue;
		}
	if(ignoreieflag == true)
		{
		getpmkid(zeigermac, zeigerpmkidakt);
		gethandshake(zeigermac, zeigerhsakt);
		}
	else if((zeigermac->akm == AK_PSK) || (zeigermac->akm == AK_PSKSHA256))
		{
		getpmkid(zeigermac, zeigerpmkidakt);
		gethandshake(zeigermac, zeigerhsakt);
		}
	}
return;
}
/*===========================================================================*/
static void cleanuphandshake()
{
static handshakelist_t *zeiger;
static handshakelist_t *zeigernext;

if(handshakelistptr == handshakelist) return;
qsort(handshakelist, handshakelistptr -handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_mac);
for(zeiger = handshakelist; zeiger < handshakelistptr -1; zeiger++)
	{
	if(zeiger->timestampgap == 0) continue;
	for(zeigernext = zeiger +1; zeigernext < handshakelistptr; zeigernext++)
		{
		if(memcmp(zeiger->ap, zeigernext->ap, 6) != 0) break;
		if(memcmp(zeiger->client, zeigernext->client, 6) != 0) break;
		if(zeiger->timestampgap > zeigernext->timestampgap) zeiger->timestampgap =zeigernext->timestampgap;
		if(zeiger->rcgap > zeigernext->rcgap) zeiger->rcgap = zeigernext->rcgap;
		zeiger->messageap |= zeigernext->messageap;
		zeiger->messageclient |= zeigernext->messageclient;
		memset(zeigernext, 0xff, HANDSHAKELIST_SIZE);
		}
	}
return;
}
/*===========================================================================*/
static void cleanuppmkid()
{
static pmkidlist_t *zeiger;
static pmkidlist_t *zeigernext;

if(pmkidlistptr == pmkidlist) return;
qsort(pmkidlist, pmkidlistptr -pmkidlist, PMKIDLIST_SIZE, sort_pmkidlist_by_mac);
for(zeiger = pmkidlist; zeiger < pmkidlistptr -1; zeiger++)
	{
	for(zeigernext = zeiger +1; zeigernext < pmkidlistptr; zeigernext++)
		{
		if(memcmp(zeiger->ap, zeigernext->ap, 6) != 0) break;
		if(memcmp(zeiger->client, zeigernext->client, 6) != 0) break;
		if(memcmp(zeiger->pmkid, zeigernext->pmkid, 16) != 0) break;
		memset(zeigernext, 0xff, PMKIDLIST_SIZE);
		}
	}
return;
}
/*===========================================================================*/
static void cleanupmac()
{
static maclist_t *zeiger;
static maclist_t *zeigernext;

if(aplistptr == aplist) return;
qsort(aplist, aplistptr -aplist, MACLIST_SIZE, sort_maclist_by_mac);
for(zeiger = aplist; zeiger < aplistptr -1; zeiger++)
	{
	if(zeiger->timestamp == 0) continue;
	for(zeigernext = zeiger +1; zeigernext < aplistptr; zeigernext++)
		{
		if(memcmp(zeiger->addr, zeigernext->addr, 6) != 0) break;
		if(zeiger->essidlen != zeigernext->essidlen) break;
		if(memcmp(zeiger->essid, zeigernext->essid, zeigernext->essidlen) != 0) break;
		zeiger->timestamp = zeigernext->timestamp;
		zeiger->type |= zeigernext->type;
		zeiger->status |= zeigernext->status;
		zeiger->count += 1;
		memset(zeigernext, 0xff, MACLIST_SIZE);
		}
	}
qsort(aplist, aplistptr -aplist, MACLIST_SIZE, sort_maclist_by_mac);
return;
}
/*===========================================================================*/
static bool cleanbackhandshake()
{
static int c;
static handshakelist_t *zeiger;

zeiger = handshakelistptr;
for(c = 0; c < 20; c ++)
	{
	zeiger--;
	if(zeiger < handshakelist) return false;
	if(memcmp(zeiger->ap, handshakelistptr->ap, 6) != 0) continue;
	if(memcmp(zeiger->client, handshakelistptr->client, 6) != 0) continue;
	if(memcmp(zeiger->anonce, handshakelistptr->anonce, 32) != 0) continue;
	if(zeiger->eapauthlen != handshakelistptr->eapauthlen) continue;
	if(memcmp(zeiger->eapol, handshakelistptr->eapol, handshakelistptr->eapauthlen) != 0) continue;
	if(zeiger->timestampgap > handshakelistptr->timestampgap) zeiger->timestampgap = handshakelistptr->timestampgap;
	if(zeiger->rcgap > handshakelistptr->rcgap) zeiger->rcgap = handshakelistptr->rcgap;
	zeiger->messageap |= handshakelistptr->messageap;
	zeiger->messageclient |= handshakelistptr->messageclient;
	return true;
	}
return false;
}
/*===========================================================================*/
static void addhandshake(uint64_t eaptimegap, uint64_t rcgap, messagelist_t *msgclient, messagelist_t *msgap, uint8_t mpfield)
{
static handshakelist_t *handshakelistnew;

eapolmpcount++;
if(handshakelistptr >= handshakelist +handshakelistmax)
	{
	handshakelistnew = realloc(handshakelist, (handshakelistmax +HANDSHAKELIST_MAX) *HANDSHAKELIST_SIZE);
	if(handshakelistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	handshakelist = handshakelistnew;
	handshakelistptr = handshakelistnew +maclistmax;
	handshakelistmax += HANDSHAKELIST_MAX;
	}
memset(handshakelistptr, 0, HANDSHAKELIST_SIZE);
handshakelistptr->timestampgap = eaptimegap;
handshakelistptr->status = mpfield | msgap->status | msgclient->status;
handshakelistptr->rcgap = rcgap;
handshakelistptr->messageap = msgap->message;
handshakelistptr->messageclient = msgclient->message;
memcpy(handshakelistptr->ap, msgap->ap, 6);
memcpy(handshakelistptr->client, msgclient->client, 6);
memcpy(handshakelistptr->anonce, msgap->nonce, 32);
memcpy(handshakelistptr->pmkid, msgap->pmkid, 32);
handshakelistptr->eapauthlen = msgclient->eapauthlen;
memcpy(handshakelistptr->eapol, msgclient->eapol, msgclient->eapauthlen);
if(cleanbackhandshake() == false) handshakelistptr++;
return;
}
/*===========================================================================*/
static bool cleanbackpmkid()
{
static int c;
static pmkidlist_t *zeiger;

zeiger = pmkidlistptr;
for(c = 0; c < 20; c ++)
	{
	zeiger--;
	if(zeiger < pmkidlist) return false;
	if(memcmp(zeiger->ap, pmkidlistptr->ap, 6) != 0) continue;
	if(memcmp(zeiger->client, pmkidlistptr->client, 6) != 0) continue;
	if(memcmp(zeiger->pmkid, pmkidlistptr->pmkid, 16) != 0) continue;
	return true;
	}
return false;
}
/*===========================================================================*/
static void addpmkid(uint8_t *macclient, uint8_t *macap, uint8_t *pmkid)
{
static pmkidlist_t *pmkidlistnew;

pmkidcount++;
if(pmkidlistptr >= pmkidlist +pmkidlistmax)
	{
	pmkidlistnew = realloc(pmkidlist, (pmkidlistmax +PMKIDLIST_MAX) *PMKIDLIST_SIZE);
	if(pmkidlistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	pmkidlist = pmkidlistnew;
	pmkidlistptr = pmkidlistnew +maclistmax;
	pmkidlistmax += PMKIDLIST_MAX;
	}
memset(pmkidlistptr, 0, PMKIDLIST_SIZE);
memcpy(pmkidlistptr->ap, macap, 6);
memcpy(pmkidlistptr->client, macclient, 6);
memcpy(pmkidlistptr->pmkid, pmkid, 16);
if(cleanbackpmkid() == false) pmkidlistptr++;
return;
}
/*===========================================================================*/
static void process80211eapol_m4(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t eapauthlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static uint64_t eaptimegap;
static uint64_t rc;
static uint64_t rcgap;
static uint8_t mpfield;

eapolm4count++;
eapolmsgcount++;
if(eapauthlen > 255) return;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > eapauthlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
if(memcmp(wpak->nonce, &zeroed32, 32) == 0) return;
zeiger = messagelist +MESSAGELIST_MAX;
memset(zeiger, 0, MESSAGELIST_SIZE);
zeiger->timestamp = eaptimestamp;
zeiger->eapolmsgcount = eapolmsgcount;
memcpy(zeiger->client, macfm, 6);
memcpy(zeiger->ap, macto, 6);
zeiger->message = HS_M4;
rc = be64toh(wpak->replaycount);
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
zeiger->eapauthlen = eapauthlen;
memcpy(zeiger->eapol, eapauthptr, eapauthlen);
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
	{
	if(zeiger->message == HS_M3)
		{
		if(zeiger->rc > rc) rcgap = zeiger->rc -rc;
		else rcgap = rc -zeiger->rc;
		if(rcgap > ncvalue) continue;
		if(memcmp(zeiger->client, macfm, 6) != 0) continue;
		if(memcmp(zeiger->ap, macto, 6) != 0) continue;
		if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
		else eaptimegap = zeiger->timestamp -eaptimestamp;
		mpfield = ST_M34E4;
		if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, mpfield);
		}
	if((zeiger->message &HS_M1) != HS_M1) continue;
	rc -= 1;
	if(zeiger->rc > rc) rcgap = zeiger->rc -rc;
	else rcgap = rc -zeiger->rc;
	if(rcgap > ncvalue) continue;
	if(memcmp(zeiger->client, macfm, 6) != 0) continue;
	if(memcmp(zeiger->ap, macto, 6) != 0) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M14E4;
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m3(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t eapauthlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static messagelist_t *zeigerakt;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static uint64_t eaptimegap;
static uint64_t rc;
static uint64_t rcgap;
static uint8_t mpfield;

eapolm3count++;
eapolmsgcount++;
zeigerakt = messagelist +MESSAGELIST_MAX;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > eapauthlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
memset(zeigerakt, 0, MESSAGELIST_SIZE);
zeigerakt->timestamp = eaptimestamp;
zeigerakt->eapolmsgcount = eapolmsgcount;
memcpy(zeigerakt->client, macto, 6);
memcpy(zeigerakt->ap, macfm, 6);
zeigerakt->message = HS_M3;
rc = be64toh(wpak->replaycount);
zeigerakt->rc = rc;
memcpy(zeigerakt->nonce, wpak->nonce, 32);
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->ap, macfm, 6) != 0) continue;
	if(memcmp(zeiger->client, macto, 6) != 0) continue;
	if((memcmp(zeiger->nonce, wpak->nonce, 28) == 0) && (memcmp(&zeiger->nonce[29], &wpak->nonce[29], 4) != 0))
		{
		zeiger->status |= ST_NC;
		zeigerakt->status |= ST_NC;
		}
	if((zeiger->message) != HS_M2) continue;
	rc -= 1;
	if(zeiger->rc > rc) rcgap = zeiger->rc -rc;
	else rcgap = rc -zeiger->rc;
	if(rcgap > ncvalue) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M32E2;
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, zeiger, messagelist +MESSAGELIST_MAX, mpfield);
	}
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX +1; zeiger++)
	{
	if(((zeiger->message &HS_M1) != HS_M1) && ((zeiger->message &HS_M3) != HS_M3)) continue;
	if(memcmp(zeiger->ap, macfm, 6) != 0) continue;
	if((memcmp(zeiger->nonce, wpak->nonce, 28) == 0) && (memcmp(&zeiger->nonce[28], &wpak->nonce[28], 4) != 0))
		{
		zeiger->status |= ST_NC;
		if(zeiger->nonce[31] != wpak->nonce[31]) zeiger->status |= ST_LE;
		else if(zeiger->nonce[28] != wpak->nonce[28]) zeiger->status |= ST_BE;
		}
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m2(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t eapauthlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static uint64_t eaptimegap;
static uint64_t rc;
static uint64_t rcgap;
static uint8_t mpfield;

eapolm2count++;
eapolmsgcount++;
if(eapauthlen > 256) return;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > eapauthlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
if(memcmp(wpak->nonce, &zeroed32, 32) == 0) return;
zeiger = messagelist +MESSAGELIST_MAX;
memset(zeiger, 0, MESSAGELIST_SIZE);
zeiger->timestamp = eaptimestamp;
zeiger->eapolmsgcount = eapolmsgcount;
memcpy(zeiger->client, macfm, 6);
memcpy(zeiger->ap, macto, 6);
zeiger->message = HS_M2;
rc = be64toh(wpak->replaycount);
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
zeiger->eapauthlen = eapauthlen;
memcpy(zeiger->eapol, eapauthptr, eapauthlen);
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
	{
	if((zeiger->message &HS_M1) != HS_M1) continue;
	if(zeiger->rc > rc) rcgap = zeiger->rc -rc;
	else rcgap = rc -zeiger->rc;
	if(rcgap > ncvalue) continue;
	if(memcmp(zeiger->client, macfm, 6) != 0) continue;
	if(memcmp(zeiger->ap, macto, 6) != 0) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M12E2;
	if(myaktreplaycount > 0)
		{
		if((rc == myaktreplaycount) && (memcmp(&myaktanonce, zeiger->nonce, 32) == 0))
			{
			eaptimegap = 0;
			mpfield |= ST_APLESS;
			}
		}
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m1(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t eapauthlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static pmkid_t *pmkid;
static uint64_t rc;

eapolm1count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > eapauthlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
zeiger = messagelist +MESSAGELIST_MAX;
memset(zeiger, 0, MESSAGELIST_SIZE);
zeiger->timestamp = eaptimestamp;
zeiger->eapolmsgcount = eapolmsgcount;
memcpy(zeiger->client, macto, 6);
memcpy(zeiger->ap, macfm, 6);
zeiger->message = HS_M1;
rc = be64toh(wpak->replaycount);
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
if(authlen >= (int)(WPAKEY_SIZE +PMKID_SIZE))
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if((pmkid->len == 0x14) && (pmkid->type == 0x04) && (memcmp(pmkid->pmkid, &zeroed32, 16) != 0))
		{
		zeiger->message |= HS_PMKID;
		memcpy(zeiger->pmkid, pmkid->pmkid, 16);
		addpmkid(macto, macfm, pmkid->pmkid);
		}
	else
		{
		pmkiduselesscount++;
		}
	}
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX +1; zeiger++)
	{
	if(((zeiger->message &HS_M1) != HS_M1) && ((zeiger->message &HS_M3) != HS_M3)) continue;
	if(memcmp(zeiger->ap, macfm, 6) != 0) continue;
	if((memcmp(zeiger->nonce, wpak->nonce, 28) == 0) && (memcmp(&zeiger->nonce[28], &wpak->nonce[28], 4) != 0))
		{
		zeiger->status |= ST_NC;
		if(zeiger->nonce[31] != wpak->nonce[31]) zeiger->status |= ST_LE;
		else if(zeiger->nonce[28] != wpak->nonce[28]) zeiger->status |= ST_BE;
		}
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t eapauthlen, uint8_t *eapauthptr)
{
static eapauth_t *eapauth;
static uint32_t authlen;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint16_t keyinfo;

eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > eapauthlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
if(keyinfo == 1) process80211eapol_m1(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
else if(keyinfo == 2)
	{
	if(authlen != 0x5f) process80211eapol_m2(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
	else process80211eapol_m4(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
	}
else if(keyinfo == 3) process80211eapol_m3(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
else if(keyinfo == 4) process80211eapol_m4(eaptimestamp, macto, macfm, eapauthlen, eapauthptr);
return;
}
/*===========================================================================*/
static void process80211eap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eaplen, uint8_t *eapptr)
{
static uint8_t *eapauthptr;
static eapauth_t *eapauth;

eapauthptr = eapptr;
eapauth = (eapauth_t*)eapauthptr;
if(eaplen < (int)EAPAUTH_SIZE) return; 
if(eapauth->type == EAPOL_KEY)
	{
	process80211eapol(eaptimestamp, macto, macfm, eaplen, eapauthptr);
	}
//else if(eapauth->type == EAP_PACKET) process80211exteap(authlen);
//else if(eapauth->type == EAPOL_ASF) process80211exteap_asf();
//else if(eapauth->type == EAPOL_MKA) process80211exteap_mka();
else if(eapauth->type == EAPOL_START)
	{
	}
else if(eapauth->type == EAPOL_LOGOFF)
	{
	}
return;
}
/*===========================================================================*/
static bool cleanbackmac()
{
static int c;
static maclist_t *zeiger;
zeiger = aplistptr;
for(c = 0; c < 20; c ++)
	{
	zeiger--;
	if(zeiger < aplist) return false;
	if(zeiger->type != aplistptr->type) continue;
	if(zeiger->essidlen != aplistptr->essidlen) continue;
	if(memcmp(zeiger->addr, aplistptr->addr, 6) != 0) continue;
	if(memcmp(zeiger->essid, aplistptr->essid, aplistptr->essidlen) != 0) continue;
	zeiger->timestamp = aplistptr->timestamp;
	zeiger->count += 1;
	zeiger->status |= aplistptr->status;
	zeiger->type |= aplistptr->type;
	if(aplistptr->groupcipher != 0) zeiger->groupcipher = aplistptr->groupcipher;
	if(aplistptr->cipher != 0) zeiger->cipher = aplistptr->cipher;
	if(aplistptr->akm != 0) zeiger->akm = aplistptr->akm;
	return true;
	}
return false;
}
/*===========================================================================*/
static inline bool getaptags(int infolen, uint8_t *infoptr, tags_t *zeiger)
{
static int c;
static ietag_t *tagptr;
static rsnie_t *rsnptr;
static wpaie_t *wpaptr;
static suite_t *suiteptr;
static suitecount_t *suitecountptr;
static int suitelen;
static rsnpmkidlist_t *rsnpmkidlistptr;

memset(zeiger, 0, TAGS_SIZE);
while(0 < infolen)
	{
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len > (infolen -IETAG_SIZE))
		{
		if(ignoreieflag == true) return true;
		else return false;
		}
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) && (tagptr->len <= ESSID_LEN_MAX))
			{
			if(tagptr->data[0] != 0)
				{
				memcpy(zeiger->essid, &tagptr->data[0], tagptr->len);
				zeiger->essidlen = tagptr->len;
				}
			}
		}
	else if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) zeiger->channel = tagptr->data[0];
		}
	else if(tagptr->id == TAG_RSN)
		{
		if(tagptr->len >= RSN_LEN_MIN)
			{
			rsnptr = (rsnie_t*)infoptr;
			if(rsnptr->version == 1)
				{
				zeiger->kdversion |= WPA2;
				suiteptr = (suite_t*)(infoptr + RSNIE_SIZE); 
				if(memcmp(suiteptr->oui, &suiteoui, 3) == 0)
					{
					zeiger->groupcipher = suiteptr->type;
					suitelen = RSNIE_SIZE +SUITE_SIZE;
					suitecountptr = (suitecount_t*)(infoptr +suitelen);
					suitelen += SUITECOUNT_SIZE;
					for(c = 0; c < suitecountptr->count; c++)
						{
						suiteptr = (suite_t*)(infoptr +suitelen);
						suitelen += SUITE_SIZE;
						if(suitelen > rsnptr->len +(int)IETAG_SIZE) break;
						if((suiteptr->type == CS_CCMP) || (suiteptr->type == CS_TKIP)) zeiger->cipher = suiteptr->type;
						}
					if(suitelen < rsnptr->len)
						{
						suitecountptr = (suitecount_t*)(infoptr +suitelen);
						suitelen += SUITECOUNT_SIZE;
						for(c = 0; c < suitecountptr->count; c++)
							{
							suiteptr = (suite_t*)(infoptr +suitelen);
							suitelen += SUITE_SIZE;
							if(suitelen > rsnptr->len +(int)IETAG_SIZE) break;
							if(memcmp(suiteptr->oui, &suiteoui, 3) == 0)
								{
								if((suiteptr->type == AK_PSK) || (suiteptr->type == AK_PSKSHA256))
									{
									zeiger->akm = suiteptr->type;
									break;
									}
								}
							}
						}
					if(suitelen < rsnptr->len) 
						{
						suitelen += RSNCAPABILITIES_SIZE;
						rsnpmkidlistptr = (rsnpmkidlist_t*)(infoptr +suitelen);
						if(rsnpmkidlistptr->count == 0) break;
						suitelen += RSNPMKIDLIST_SIZE;
						if(suitelen +16 > rsnptr->len +4 +(int)IETAG_SIZE) break;
						memcpy(zeiger->pmkid, &infoptr[suitelen], 16);
						}
					}
				}
			}
		}
	else if(tagptr->id == TAG_VENDOR)
		{
		if(tagptr->len >= WPA_LEN_MIN)
			{
			wpaptr = (wpaie_t*)infoptr;
			if(memcmp(wpaptr->oui, &mscorp, 3) == 0)
				{
				if(wpaptr->ouitype == 1)
					{
					if(wpaptr->type == VT_WPA_IE)
						{
						zeiger->kdversion |= WPA1;
						suiteptr = (suite_t*)(infoptr + WPAIE_SIZE); 
						if(memcmp(suiteptr->oui, &mscorp, 3) == 0)
							{
							zeiger->groupcipher = suiteptr->type;
							suitelen = WPAIE_SIZE +SUITE_SIZE;
							suitecountptr = (suitecount_t*)(infoptr +suitelen);
							suitelen += SUITECOUNT_SIZE;
							for(c = 0; c < suitecountptr->count; c++)
								{
								suiteptr = (suite_t*)(infoptr +suitelen);
								suitelen += SUITE_SIZE;
								if(suitelen > wpaptr->len +(int)IETAG_SIZE) break;
								if((suiteptr->type == CS_CCMP) || (suiteptr->type == CS_TKIP)) zeiger->cipher = suiteptr->type;
								}
							if(suitelen < wpaptr->len)
								{
								suitecountptr = (suitecount_t*)(infoptr +suitelen);
								suitelen += SUITECOUNT_SIZE;
								for(c = 0; c < suitecountptr->count; c++)
									{
									suiteptr = (suite_t*)(infoptr +suitelen);
									suitelen += SUITE_SIZE;
									if(suitelen > wpaptr->len +(int)IETAG_SIZE) break;
									if(memcmp(suiteptr->oui, &mscorp, 3) == 0)
										{
										if((suiteptr->type == AK_PSK) || (suiteptr->type == AK_PSKSHA256))
											{
											zeiger->akm = suiteptr->type;
											break;
											}
										}
									}
								}
							}
						}
					}
				}
			}
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	if(infolen == 4) return true;
	}
if(infolen != 0)
	{
	if(ignoreieflag == false) return false;
	}
return true;
}
/*===========================================================================*/
static void process80211reassociation_req(uint64_t reassociationrequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t reassociationrequestlen, uint8_t *reassociationrequestptr)
{
static int clientinfolen;
static uint8_t *clientinfoptr;
static maclist_t *aplistnew;

static tags_t tags;

reassociationrequestcount++;
clientinfoptr = reassociationrequestptr +CAPABILITIESREQSTA_SIZE;
clientinfolen = reassociationrequestlen -CAPABILITIESREQSTA_SIZE;
if(clientinfolen < (int)IETAG_SIZE) return;
if(getaptags(clientinfolen, clientinfoptr, &tags) == false) return;
if(memcmp(&tags.pmkid, &zeroed32, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = reassociationrequesttimestamp;
aplistptr->count = 1;
aplistptr->type = AP;
memcpy(aplistptr->addr, macap, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
aplistptr->groupcipher = tags.groupcipher;
aplistptr->cipher = tags.cipher;
aplistptr->akm = tags.akm;
if(cleanbackmac() == false) aplistptr++;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = reassociationrequesttimestamp;
aplistptr->count = 1;
aplistptr->status = ST_REASSOC_REQ;
aplistptr->type = CLIENT;
memcpy(aplistptr->addr, macclient, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
aplistptr->groupcipher = tags.groupcipher;
aplistptr->cipher = tags.cipher;
aplistptr->akm = tags.akm;
if(cleanbackmac() == false) aplistptr++;
return;
}
/*===========================================================================*/
static void process80211association_req(uint64_t associationrequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t associationrequestlen, uint8_t *associationrequestptr)
{
static int clientinfolen;
static uint8_t *clientinfoptr;
static maclist_t *aplistnew;
static tags_t tags;

associationrequestcount++;
clientinfoptr = associationrequestptr +CAPABILITIESSTA_SIZE;
clientinfolen = associationrequestlen -CAPABILITIESSTA_SIZE;
if(clientinfolen < (int)IETAG_SIZE) return;
if(getaptags(clientinfolen, clientinfoptr, &tags) == false) return;
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = associationrequesttimestamp;
aplistptr->count = 1;
aplistptr->status = ST_ASSOC_REQ;
aplistptr->type = AP;
memcpy(aplistptr->addr, macap, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
aplistptr->groupcipher = tags.groupcipher;
aplistptr->cipher = tags.cipher;
aplistptr->akm = tags.akm;
if(cleanbackmac() == false) aplistptr++;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = associationrequesttimestamp;
aplistptr->count = 1;
aplistptr->status = ST_ASSOC_REQ;
aplistptr->type = CLIENT;
memcpy(aplistptr->addr, macclient, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
aplistptr->groupcipher = tags.groupcipher;
aplistptr->cipher = tags.cipher;
aplistptr->akm = tags.akm;
if(cleanbackmac() == false) aplistptr++;
return;
}
/*===========================================================================*/
static inline void process80211authentication(uint32_t authenticationlen, uint8_t *authenticationptr)
{
static authf_t *auth;

auth = (authf_t*)authenticationptr;
if(authenticationlen < (int)AUTHENTICATIONFRAME_SIZE) return;
if(auth->algorithm == OPEN_SYSTEM)	authopensystemcount++;
else if(auth->algorithm == SAE)	authseacount++;
else if(auth->algorithm == SHARED_KEY) authsharedkeycount++;
else if(auth->algorithm == FBT)	authfbtcount++;
else if(auth->algorithm == FILS) authfilscount++;
else if(auth->algorithm == FILSPFS) authfilspfs++;
else if(auth->algorithm == FILSPK) authfilspkcount++;
else if(auth->algorithm == NETWORKEAP) authnetworkeapcount++;
else authunknowncount++;
return;
}
/*===========================================================================*/
static void process80211probe_req_direct(uint64_t proberequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t proberequestlen, uint8_t *proberequestptr)
{
static maclist_t *aplistnew;
static tags_t tags;

proberequestdirectedcount++;
if(proberequestlen < (int)IETAG_SIZE) return;
if(getaptags(proberequestlen, proberequestptr, &tags) == false) return;
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = proberequesttimestamp;
aplistptr->count = 1;
aplistptr->status = ST_PROBE_REQ;
aplistptr->type = AP;
memcpy(aplistptr->addr, macap, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
if(cleanbackmac() == false) aplistptr++;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = proberequesttimestamp;
aplistptr->count = 1;
aplistptr->status = ST_PROBE_REQ;
aplistptr->type = CLIENT;
memcpy(aplistptr->addr, macclient, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
if(cleanbackmac() == false) aplistptr++;
return;
}
/*===========================================================================*/
static void process80211probe_req(uint64_t proberequesttimestamp, uint8_t *macclient, uint32_t proberequestlen, uint8_t *proberequestptr)
{
static maclist_t *aplistnew;
static tags_t tags;

proberequestcount++;
if(proberequestlen < (int)IETAG_SIZE) return;
if(getaptags(proberequestlen, proberequestptr, &tags) == false) return;
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = proberequesttimestamp;
aplistptr->count = 1;
aplistptr->status = ST_PROBE_REQ;
aplistptr->type = CLIENT;
memcpy(aplistptr->addr, macclient, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
if(cleanbackmac() == false) aplistptr++;
return;
}
/*===========================================================================*/
static void process80211probe_resp(uint64_t proberesponsetimestamp, uint8_t *macap, uint32_t proberesponselen, uint8_t *proberesponseptr)
{
static int apinfolen;
static maclist_t *aplistnew;
static uint8_t *apinfoptr;
static tags_t tags;

proberesponsecount++;
apinfoptr = proberesponseptr +CAPABILITIESAP_SIZE;
apinfolen = proberesponselen -CAPABILITIESAP_SIZE;
if(proberesponselen < (int)IETAG_SIZE) return;
if(getaptags(apinfolen, apinfoptr, &tags) == false) return;
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = proberesponsetimestamp;
aplistptr->count = 1;
aplistptr->status = ST_PROBE_RESP;
aplistptr->type = AP;
memcpy(aplistptr->addr, macap, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
aplistptr->groupcipher = tags.groupcipher;
aplistptr->cipher = tags.cipher;
aplistptr->akm = tags.akm;
if(cleanbackmac() == false) aplistptr++;
return;
}
/*===========================================================================*/
static void process80211beacon(uint64_t beacontimestamp, uint8_t *macap, uint32_t beaconlen, uint8_t *beaconptr)
{
static int apinfolen;
static uint8_t *apinfoptr;
static maclist_t *aplistnew;
static tags_t tags;

beaconcount++;
apinfoptr = beaconptr +CAPABILITIESAP_SIZE;
apinfolen = beaconlen -CAPABILITIESAP_SIZE;
if(beaconlen < (int)IETAG_SIZE) return;
if(getaptags(apinfolen, apinfoptr, &tags) == false) return;
if(tags.essidlen == 0) return;
if(tags.essid[0] == 0) return;
if(aplistptr >= aplist +maclistmax)
	{
	aplistnew = realloc(aplist, (maclistmax +MACLIST_MAX) *MACLIST_SIZE);
	if(aplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	aplist = aplistnew;
	aplistptr = aplistnew +maclistmax;
	maclistmax += MACLIST_MAX;
	}
memset(aplistptr, 0, MACLIST_SIZE);
aplistptr->timestamp = beacontimestamp;
aplistptr->count = 1;
aplistptr->status = ST_BEACON;
aplistptr->type = AP;
memcpy(aplistptr->addr, macap, 6);
aplistptr->essidlen = tags.essidlen;
memcpy(aplistptr->essid, tags.essid, tags.essidlen);
aplistptr->groupcipher = tags.groupcipher;
aplistptr->cipher = tags.cipher;
aplistptr->akm = tags.akm;
if(cleanbackmac() == false) aplistptr++;
aplistptr++;
return;
}
/*===========================================================================*/
static void process80211packet(uint64_t packetimestamp, uint32_t packetlen, uint8_t *packetptr)
{

//static uint32_t wdsoffset = 0;
static mac_t *macfrx;
static uint32_t payloadlen;
static uint8_t *payloadptr;
static uint8_t *llcptr;
static llc_t *llc;
//static uint8_t *mpduptr;
//static mpdu_t *mpdu;

if(packetlen < (int)MAC_SIZE_NORM) return;
macfrx = (mac_t*)packetptr;
if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
	{
	payloadptr = packetptr +MAC_SIZE_LONG;
	payloadlen = packetlen -MAC_SIZE_LONG;
	}
else
	{
	payloadptr = packetptr +MAC_SIZE_NORM;
	payloadlen = packetlen -MAC_SIZE_NORM;
	}
if(macfrx->type == IEEE80211_FTYPE_MGMT)
	{
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211probe_resp(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH) process80211authentication(payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(&mac_broadcast, macfrx->addr1, 6) == 0) process80211probe_req(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
		else process80211probe_req_direct(packetimestamp, macfrx->addr1, macfrx->addr2, payloadlen, payloadptr);
		}
	}
else if(macfrx->type == IEEE80211_FTYPE_DATA)
	{
	if((macfrx->subtype &IEEE80211_STYPE_QOS_DATA) == IEEE80211_STYPE_QOS_DATA)
		{
		payloadptr += QOS_SIZE;
		payloadlen -= QOS_SIZE;
		}
	if(payloadlen < (int)LLC_SIZE) return;
	llcptr = payloadptr;
	llc = (llc_t*)llcptr;
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211eap(packetimestamp, macfrx->addr1, macfrx->addr2, payloadlen -LLC_SIZE, payloadptr +LLC_SIZE);
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
//		process80211ipv4();
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
//		process80211ipv6();
		}
	else if(macfrx->protected ==1)
		{
/*
		mpduptr = payloadptr;
		mpdu = (mpdu_t*)mpduptr;
		if(((mpdu->keyid >> 5) &1) == 1) process80211data_wpa();
		else if(((mpdu->keyid >> 5) &1) == 0) process80211data_wep();
*/
		}
	}
return;
}
/*===========================================================================*/
static void processlinktype(uint64_t captimestamp, int linktype, uint32_t caplen, uint8_t *capptr)
{
static uint16_t rthlen;
static rth_t *rth;
static uint32_t packetlen;
static uint8_t *packetptr;
static ppi_t *ppi;
static prism_t *prism;
static avs_t *avs;
static fcs_t *fcs;
static uint32_t crc;

if(captimestamp == 0)
	{
	captimestamp = timestampstart;
	timestampstart += (eapoltimeoutvalue -2);
	}
if(linktype == DLT_IEEE802_11_RADIO)
	{
	if(caplen < (uint32_t)RTH_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read radiotap header\n");
		return;
		}
	rth = (rth_t*)capptr;
	rthlen = le16toh(rth->it_len);
	if(rthlen > caplen)
		{
		pcapreaderrors++;
		printf("failed to read radiotap header\n");
		return;
		}
	packetlen = caplen -rthlen;
	packetptr = capptr +rthlen;
	}
else if(linktype == DLT_IEEE802_11)
	{
	packetptr = capptr;
	packetlen = caplen;
	}
else if(linktype == DLT_PPI)
	{
	if(caplen < (uint32_t)PPI_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read ppi header\n");
		return;
		}
	ppi = (ppi_t*)capptr;
	#ifdef BIG_ENDIAN_HOST
	ppi->pph_len	= byte_swap_16(ppi->pph_len);
	#endif
	if(ppi->pph_len > caplen)
		{
		pcapreaderrors++;
		printf("failed to read ppi header\n");
		return;
		}
	packetlen = caplen -ppi->pph_len;
	packetptr = capptr +ppi->pph_len;
	}
else if(linktype == DLT_PRISM_HEADER)
	{
	if(caplen < (uint32_t)PRISM_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read prism header\n");
		return;
		}
	prism = (prism_t*)capptr;
	#ifdef BIG_ENDIAN_HOST
	prism->msgcode		= byte_swap_32(prism->msgcode);
	prism->msglen		= byte_swap_32(prism->msglen);
	prism->frmlen.data	= byte_swap_32(prism->frmlen.data);
	#endif
	if(prism->msglen > caplen)
		{
		if(prism->frmlen.data > caplen)
			{
			pcapreaderrors++;
			printf("failed to read prism header\n");
			return;
			}
		prism->msglen = caplen -prism->frmlen.data;
		}
	packetlen = caplen -prism->msglen;
	packetptr = capptr +prism->msglen;
	}
else if(linktype == DLT_IEEE802_11_RADIO_AVS)
	{
	if(caplen < (uint32_t)AVS_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read avs header\n");
		return;
		}
	avs = (avs_t*)capptr;
	#ifdef BIG_ENDIAN_HOST
	avs->len		= byte_swap_32(avs->len);
	#endif
	if(avs->len > caplen)
		{
		pcapreaderrors++;
		printf("failed to read avs header\n");
		return;
		}
	packetlen = caplen -avs->len;
	packetptr = capptr +avs->len;
	}
else
	{
	printf("unsupported network type %d\n", linktype);
	return;
	}

if(packetlen < 4)
	{
	pcapreaderrors++;
	printf("failed to read packet\n");
	return;
	}
fcs = (fcs_t*)(packetptr +packetlen -4);
crc = fcscrc32check(packetptr, packetlen -4);
#ifdef BIG_ENDIAN_HOST
crc	= byte_swap_32(crc);
#endif
if(endianess == 1)
	{
	crc	= byte_swap_32(crc);
	}
if(crc == fcs->fcs)
	{
	fcsframecount++;
	packetlen -= 4;
	}

process80211packet(captimestamp, packetlen, packetptr);

return;
}
/*===========================================================================*/
void processcap(int fd, char *pcaporgname, char *pcapinname)
{
static unsigned int res;
static off_t resseek;
static pcap_hdr_t pcapfhdr;
static pcaprec_hdr_t pcaprhdr;
static uint64_t timestampcap;
static uint8_t packet[MAXPACPSNAPLEN];

printf("reading from %s...\n", basename(pcapinname));
memset(&packet, 0, MAXPACPSNAPLEN);
res = read(fd, &pcapfhdr, PCAPHDR_SIZE);
if(res != PCAPHDR_SIZE)
	{
	pcapreaderrors++;
	printf("failed to read pcap header\n");
	return;
	}

#ifdef BIG_ENDIAN_HOST
pcapfhdr.magic_number	= byte_swap_32(pcapfhdr.magic_number);
pcapfhdr.version_major	= byte_swap_16(pcapfhdr.version_major);
pcapfhdr.version_minor	= byte_swap_16(pcapfhdr.version_minor);
pcapfhdr.thiszone	= byte_swap_32(pcapfhdr.thiszone);
pcapfhdr.sigfigs	= byte_swap_32(pcapfhdr.sigfigs);
pcapfhdr.snaplen	= byte_swap_32(pcapfhdr.snaplen);
pcapfhdr.network	= byte_swap_32(pcapfhdr.network);
#endif

if(pcapfhdr.magic_number == PCAPMAGICNUMBERBE)
	{
	pcapfhdr.magic_number	= byte_swap_32(pcapfhdr.magic_number);
	pcapfhdr.version_major	= byte_swap_16(pcapfhdr.version_major);
	pcapfhdr.version_minor	= byte_swap_16(pcapfhdr.version_minor);
	pcapfhdr.thiszone	= byte_swap_32(pcapfhdr.thiszone);
	pcapfhdr.sigfigs	= byte_swap_32(pcapfhdr.sigfigs);
	pcapfhdr.snaplen	= byte_swap_32(pcapfhdr.snaplen);
	pcapfhdr.network	= byte_swap_32(pcapfhdr.network);
	endianess = 1;
	}

versionmajor = pcapfhdr.version_major;
versionminor = pcapfhdr.version_minor;
dltlinktype  = pcapfhdr.network;

if(pcapfhdr.version_major != PCAP_MAJOR_VER)
	{
	pcapreaderrors++;
	printf("unsupported pcap version\n");
	return;
	}
if(pcapfhdr.version_minor != PCAP_MINOR_VER)
	{
	pcapreaderrors++;
	printf("unsupported pcap version\n");
	return;
	}
if(pcapfhdr.snaplen > MAXPACPSNAPLEN)
	{
	pcapreaderrors++;
	printf("detected oversized snaplen (%d)\n", pcapfhdr.snaplen);
	}

while(1)
	{
	res = read(fd, &pcaprhdr, PCAPREC_SIZE);
	if(res == 0) break;
	if(res != PCAPREC_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read pcap packet header for packet %ld\n", rawpacketcount);
		break;
		}

	#ifdef BIG_ENDIAN_HOST
	pcaprhdr.ts_sec		= byte_swap_32(pcaprhdr.ts_sec);
	pcaprhdr.ts_usec	= byte_swap_32(pcaprhdr.ts_usec);
	pcaprhdr.incl_len	= byte_swap_32(pcaprhdr.incl_len);
	pcaprhdr.orig_len	= byte_swap_32(pcaprhdr.orig_len);
	#endif
	if(endianess == 1)
		{
		pcaprhdr.ts_sec		= byte_swap_32(pcaprhdr.ts_sec);
		pcaprhdr.ts_usec	= byte_swap_32(pcaprhdr.ts_usec);
		pcaprhdr.incl_len	= byte_swap_32(pcaprhdr.incl_len);
		pcaprhdr.orig_len	= byte_swap_32(pcaprhdr.orig_len);
		}
	if(pcaprhdr.incl_len > pcapfhdr.snaplen)
		{
		pcapreaderrors++;
		}
	if(pcaprhdr.incl_len < MAXPACPSNAPLEN)
		{
		rawpacketcount++;
		res = read(fd, &packet, pcaprhdr.incl_len);
		if(res != pcaprhdr.incl_len)
			{
			pcapreaderrors++;
			printf("failed to read packet %ld\n", rawpacketcount);
			break;
			}
		}
	else
		{
		skippedpacketcount++;
		resseek = lseek(fd, pcaprhdr.incl_len, SEEK_CUR);
		if(resseek < 0)
			{
			pcapreaderrors++;
			printf("failed to set file pointer\n");
			break;
			}
		continue;
		}

	if(pcaprhdr.incl_len > 0)
		{
		timestampcap = ((uint64_t)pcaprhdr.ts_sec *1000000) + pcaprhdr.ts_usec;
		processlinktype(timestampcap, pcapfhdr.network, pcaprhdr.incl_len, packet);
		}
	}

printf("\nsummary capture file\n"
	"--------------------\n"
	"file name.............................: %s\n"
	"version (pcap/cap)....................: %d.%d (very basic format without any additional information)\n"  
	, basename(pcaporgname), versionmajor, versionminor
	);
if(dltlinktype == DLT_IEEE802_11_RADIO)		printf("link layer header type................: DLT_IEEE802_11_RADIO (%d)\n", dltlinktype);
if(dltlinktype == DLT_IEEE802_11)		printf("link layer header type................: DLT_IEEE802_11 (%d)\n", dltlinktype);
if(dltlinktype == DLT_PPI)			printf("link layer header type................: DLT_PPI (%d)\n", dltlinktype);
if(dltlinktype == DLT_PRISM_HEADER)		printf("link layer header type................: DLT_PRISM_HEADER (%d)\n", dltlinktype);
if(dltlinktype == DLT_IEEE802_11_RADIO_AVS)	printf("link layer header type................: DLT_IEEE802_11_RADIO_AVS (%d)\n", dltlinktype);

cleanupmac();
cleanuphandshake();
cleanuppmkid();
outputwpalists();
printcontentinfo();

return;
}
/*===========================================================================*/
void pcapngoptionwalk(uint32_t blocktype, uint8_t *optr, int restlen)
{
static option_header_t *option;
static int padding;

while(0 < restlen)
	{
	option = (option_header_t*)optr;
	#ifdef BIG_ENDIAN_HOST
	option->option_code = byte_swap_16(option->option_code);
	option->option_length = byte_swap_16(option->option_length);
	#endif
	if(endianess == 1)
		{
		option->option_code = byte_swap_16(option->option_code);
		option->option_length = byte_swap_16(option->option_length);
		}
	padding = 0;
	if((option->option_length  %4)) padding = 4 -(option->option_length %4);
	if(option->option_code == SHB_EOC) return;
	if(option->option_code == SHB_HARDWARE)
		{
		if(option->option_length < OPTIONLEN_MAX)
			{
			memset(&pcapnghwinfo, 0, OPTIONLEN_MAX);
			memcpy(&pcapnghwinfo, option->data, option->option_length);
			}
		}
	else if(option->option_code == SHB_OS)
		{
		if(option->option_length < OPTIONLEN_MAX)
			{
			memset(&pcapngosinfo, 0, OPTIONLEN_MAX);
			memcpy(&pcapngosinfo, option->data, option->option_length);
			}
		}
	else if(option->option_code == SHB_USER_APPL)
		{
		if(option->option_length < OPTIONLEN_MAX)
			{
			memset(&pcapngapplinfo, 0, OPTIONLEN_MAX);
			memcpy(&pcapngapplinfo, option->data, option->option_length);
			}
		}
	else if(option->option_code == IF_MACADDR)
		{
		if(option->option_length == 6)
			{
			memset(&pcapngdeviceinfo, 0, 6);
			memcpy(&pcapngdeviceinfo, option->data, 6);
			}
		}
	else if(option->option_code == SHB_CUSTOM_OPT)
		{
		if(option->option_length > 40)
			{
			if((memcmp(&option->data[0], &hcxmagic, 4) == 0) && (memcmp(&option->data[4], &hcxmagic, 32) == 0)) pcapngoptionwalk(blocktype, optr +OH_SIZE +36, option->option_length -36);
			else if((memcmp(&option->data[1], &hcxmagic, 4) == 0) && (memcmp(&option->data[5], &hcxmagic, 32) == 0)) pcapngoptionwalk(blocktype, optr +OH_SIZE +1 +36, option->option_length -36);
			}
		}
	else if(option->option_code == OPTIONCODE_MACORIG)
		{
		if(option->option_length == 6)
			{
			memset(&pcapngdeviceinfo, 0, 6);
			memcpy(&pcapngdeviceinfo, option->data, 6);
			}
		}
	else if(option->option_code == OPTIONCODE_MACAP)
		{
		if(option->option_length == 6) memcpy(&myaktap, &option->data, 6);
		}
	else if(option->option_code == OPTIONCODE_RC)
		{
		if(option->option_length == 8)
			{
			myaktreplaycount = option->data[0x07] & 0xff;
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x06] & 0xff);
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x05] & 0xff);
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x04] & 0xff);
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x03] & 0xff);
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x02] & 0xff);
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x01] & 0xff);
			myaktreplaycount = (myaktreplaycount << 8) + (option->data[0x00] & 0xff);
			#ifdef BIG_ENDIAN_HOST
			myaktreplaycount = byte_swap_64(myaktreplaycount);
			#endif
			if(endianess == 1)
				{
				myaktreplaycount = byte_swap_64(myaktreplaycount);
				}
			}
		}
	else if(option->option_code == OPTIONCODE_ANONCE)
		{
		if(option->option_length == 32) memcpy(&myaktanonce, &option->data, 32);
		}
	else if(option->option_code == OPTIONCODE_MACCLIENT)
		{
		if(option->option_length == 6) memcpy(&myaktclient, &option->data, 6);
		}
	else if(option->option_code == OPTIONCODE_SNONCE)
		{
		if(option->option_length == 32) memcpy(&myaktsnonce, &option->data, 32);
		}
	else if(option->option_code == OPTIONCODE_WEAKCANDIDATE)
		{
		if(option->option_length < 64) memcpy(&pcapngweakcandidate, &option->data, option->option_length);
		}
	optr += option->option_length +padding +OH_SIZE;
	restlen -= option->option_length +padding +OH_SIZE;
	}
return;
}
/*===========================================================================*/
void processpcapng(int fd, char *pcaporgname, char *pcapinname)
{
static unsigned int res;
static off_t fdsize;
static off_t aktseek;
static off_t resseek;

static uint32_t snaplen;
static uint32_t blocktype;
static uint32_t blocklen;
static uint32_t blockmagic;
static uint64_t timestamppcapng;
static int padding;

block_header_t *pcapngbh;
section_header_block_t *pcapngshb;
interface_description_block_t *pcapngidb;
packet_block_t *pcapngpb;
enhanced_packet_block_t *pcapngepb;
custom_block_t *pcapngcb;

uint8_t pcpngblock[2 *MAXPACPSNAPLEN];
uint8_t packet[MAXPACPSNAPLEN];

printf("reading from %s...\n", basename(pcapinname));
fdsize = lseek(fd, 0, SEEK_END);
if(fdsize < 0)
	{
	pcapreaderrors++;
	printf("failed to get file size\n");
	return;
	}

aktseek = lseek(fd, 0L, SEEK_SET);
if(aktseek < 0)
	{
	pcapreaderrors++;
	printf("failed to set file pointer\n");
	return;
	}

snaplen = 0;
memset(&packet, 0, MAXPACPSNAPLEN);
while(1)
	{
	aktseek = lseek(fd, 0, SEEK_CUR);
	if(aktseek < 0)
		{
		pcapreaderrors++;
		printf("failed to set file pointer\n");
		break;
		}
	res = read(fd, &pcpngblock, BH_SIZE);
	if(res == 0)
		{
		break;
		}
	if(res != BH_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read block header\n");
		break;
		}
	pcapngbh = (block_header_t*)pcpngblock;
	blocktype = pcapngbh->block_type;
	blocklen =  pcapngbh->total_length;
	blockmagic = pcapngbh->byte_order_magic;
	#ifdef BIG_ENDIAN_HOST
	blocktype  = byte_swap_32(blocktype);
	blocklen = byte_swap_32(blocklen);
	blockmagic = byte_swap_32(blockmagic);
	#endif
	if(blocktype == PCAPNGBLOCKTYPE)
		{
		if(blockmagic == PCAPNGMAGICNUMBERBE)
			{
			endianess = 1;
			}
		}
	if(endianess == 1)
		{
		blocktype  = byte_swap_32(blocktype);
		blocklen = byte_swap_32(blocklen);
		}
	if((blocklen > (2 *MAXPACPSNAPLEN)) || ((blocklen %4) != 0))
		{
		pcapreaderrors++;
		printf("failed to read pcapng block header \n");
		break;
		}
	resseek = lseek(fd, aktseek, SEEK_SET);
	if(resseek < 0)
		{
		pcapreaderrors++;
		printf("failed to set file pointer\n");
		break;
		}
	res = read(fd, &pcpngblock, blocklen);
	if((res < BH_SIZE) || (res != blocklen))
		{
		pcapreaderrors++;
		printf("failed to read pcapng block header\n");
		break;
		}
	if(memcmp(&pcpngblock[4], &pcpngblock[ blocklen -4], 4) != 0)
		{
		pcapreaderrors++;
		printf("failed to read pcapng block header \n");
		break;
		}
	if(blocktype == PCAPNGBLOCKTYPE)
		{
		pcapngshb = (section_header_block_t*)pcpngblock;
		#ifdef BIG_ENDIAN_HOST
		pcapngshb->major_version	= byte_swap_16(pcapngshb->major_version);
		pcapngshb->minor_version	= byte_swap_16(pcapngshb->minor_version);
		pcapngshb->section_length	= byte_swap_64(pcapngshb->section_length);
		#endif
		if(endianess == 1)
			{
			pcapngshb->major_version	= byte_swap_16(pcapngshb->major_version);
			pcapngshb->minor_version	= byte_swap_16(pcapngshb->minor_version);
			pcapngshb->section_length	= byte_swap_64(pcapngshb->section_length);
			}
		versionmajor = pcapngshb->major_version;
		versionminor = pcapngshb->minor_version;
		if(pcapngshb->major_version != PCAPNG_MAJOR_VER)
			{
			pcapreaderrors++;
			printf("unsupported pcapng version\n");
			break;
			}
		if(pcapngshb->minor_version != PCAPNG_MINOR_VER)
			{
			pcapreaderrors++;
			printf("unsupported pcapng version\n");
			break;
			}
		pcapngoptionwalk(blocktype, pcapngshb->data, blocklen -SHB_SIZE);
		}
	else if(blocktype == IDBID)
		{
		pcapngidb = (interface_description_block_t*)pcpngblock;
		#ifdef BIG_ENDIAN_HOST
		pcapngidb->linktype	= byte_swap_16(pcapngidb->linktype);
		pcapngidb->snaplen	= byte_swap_32(pcapngidb->snaplen);
		#endif
		if(endianess == 1)
			{
			pcapngidb->linktype	= byte_swap_16(pcapngidb->linktype);
			pcapngidb->snaplen	= byte_swap_32(pcapngidb->snaplen);
			}
		dltlinktype = pcapngidb->linktype;
		snaplen = pcapngidb->snaplen;
		if(snaplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("detected oversized snaplen (%d)\n", snaplen);
			}
		pcapngoptionwalk(blocktype, pcapngidb->data, blocklen -IDB_SIZE);
		}
	else if(blocktype == PBID)
		{
		pcapngpb = (packet_block_t*)pcpngblock;
		#ifdef BIG_ENDIAN_HOST
		pcapngpb->caplen		= byte_swap_32(pcapngpb->caplen);
		#endif
		if(endianess == 1)
			{
			pcapngpb->caplen	= byte_swap_32(pcapngpb->caplen);
			}
		timestamppcapng = 0;
		if(pcapngpb->caplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("caplen > MAXSNAPLEN (%d > %d)\n", pcapngpb->caplen, MAXPACPSNAPLEN);
			continue;
			}
		if(pcapngpb->caplen > blocklen)
			{
			pcapreaderrors++;
			printf("caplen > blocklen (%d > %d)\n", pcapngpb->caplen, blocklen);
			continue;
			}
		rawpacketcount++;
		processlinktype(timestamppcapng, dltlinktype, pcapngpb->caplen, pcapngpb->data);
		}
	else if(blocktype == SPBID)
		{
		continue;
		}
	else if(blocktype == NRBID)
		{
		continue;
		}
	else if(blocktype == ISBID)
		{
		continue;
		}
	else if(blocktype == EPBID)
		{
		pcapngepb = (enhanced_packet_block_t*)pcpngblock;
		#ifdef BIG_ENDIAN_HOST
		pcapngepb->interface_id		= byte_swap_32(pcapngepb->interface_id);
		pcapngepb->timestamp_high	= byte_swap_32(pcapngepb->timestamp_high);
		pcapngepb->timestamp_low	= byte_swap_32(pcapngepb->timestamp_low);
		pcapngepb->caplen		= byte_swap_32(pcapngepb->caplen);
		pcapngepb->len			= byte_swap_32(pcapngepb->len);
		#endif
		if(endianess == 1)
			{
			pcapngepb->interface_id		= byte_swap_32(pcapngepb->interface_id);
			pcapngepb->timestamp_high	= byte_swap_32(pcapngepb->timestamp_high);
			pcapngepb->timestamp_low	= byte_swap_32(pcapngepb->timestamp_low);
			pcapngepb->caplen		= byte_swap_32(pcapngepb->caplen);
			pcapngepb->len			= byte_swap_32(pcapngepb->len);
			}
		timestamppcapng = pcapngepb->timestamp_high;
		timestamppcapng = (timestamppcapng << 32) +pcapngepb->timestamp_low;
		if(pcapngepb->caplen != pcapngepb->len)
			{
			pcapreaderrors++;
			printf("caplen != len (%d != %d)\n", pcapngepb->caplen, pcapngepb->len);
			continue;
			}
		if(pcapngepb->caplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("caplen > MAXSNAPLEN (%d > %d)\n", pcapngepb->caplen, MAXPACPSNAPLEN);
			continue;
			}
		if(pcapngepb->caplen > blocklen)
			{
			pcapreaderrors++;
			printf("caplen > blocklen (%d > %d)\n", pcapngepb->caplen, blocklen);
			continue;
			}
		rawpacketcount++;
		processlinktype(timestamppcapng, dltlinktype, pcapngepb->caplen, pcapngepb->data);
		padding = 0;
		if((pcapngepb->caplen  %4))
			{
			padding = 4 -(pcapngepb->caplen %4);
			}
		pcapngoptionwalk(blocktype, pcapngepb->data +pcapngepb->caplen +padding, blocklen -EPB_SIZE -pcapngepb->caplen -padding);
		}
	else if(blocktype == CBID)
		{
		pcapngcb = (custom_block_t*)pcpngblock;
		if(blocklen < CB_SIZE)
			{
			skippedpacketcount++;
			continue;
			}
		if(memcmp(pcapngcb->pen, & hcxmagic, 4) != 0)
			{
			skippedpacketcount++;
			continue;
			}
		if(memcmp(pcapngcb->hcxm, & hcxmagic, 32) != 0)
			{
			skippedpacketcount++;
			continue;
			}
		pcapngoptionwalk(blocktype, pcapngcb->data, blocklen -CB_SIZE);
		}
	else
		{
		skippedpacketcount++;
		}
	}

printf("\nsummary capture file\n"
	"--------------------\n"
	"file name.............................: %s\n"
	"version (pcapng)......................: %d.%d\n"
	"operating system......................: %s\n"
	"application...........................: %s\n"
	"interface name........................: %s\n"
	"interface vendor......................: %02x%02x%02x\n"
	"weak candidate........................: %s\n"
	"MAC ACCESS POINT......................: %02x%02x%02x%02x%02x%02x (incremented on every new client)\n"
	"MAC CLIENT............................: %02x%02x%02x%02x%02x%02x\n"
	"REPLAYCOUNT...........................: %"  PRIu64  "\n"
	"ANONCE................................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE................................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	, basename(pcaporgname), versionmajor, versionminor,
	pcapngosinfo, pcapngapplinfo, pcapnghwinfo, pcapngdeviceinfo[0], pcapngdeviceinfo[1], pcapngdeviceinfo[2], pcapngweakcandidate,
	myaktap[0], myaktap[1], myaktap[2], myaktap[3], myaktap[4], myaktap[5],
	myaktclient[0], myaktclient[1], myaktclient[2], myaktclient[3], myaktclient[4], myaktclient[5],
	myaktreplaycount,
	myaktanonce[0], myaktanonce[1], myaktanonce[2], myaktanonce[3], myaktanonce[4], myaktanonce[5], myaktanonce[6], myaktanonce[7],
	myaktanonce[8], myaktanonce[9], myaktanonce[10], myaktanonce[11], myaktanonce[12], myaktanonce[13], myaktanonce[14], myaktanonce[15],
	myaktanonce[16], myaktanonce[17], myaktanonce[18], myaktanonce[19], myaktanonce[20], myaktanonce[21], myaktanonce[22], myaktanonce[23],
	myaktanonce[24], myaktanonce[25], myaktanonce[26], myaktanonce[27], myaktanonce[28], myaktanonce[29], myaktanonce[30], myaktanonce[31],
	myaktsnonce[0], myaktsnonce[1], myaktsnonce[2], myaktsnonce[3], myaktsnonce[4], myaktsnonce[5], myaktsnonce[6], myaktsnonce[7],
	myaktsnonce[8], myaktsnonce[9], myaktsnonce[10], myaktsnonce[11], myaktsnonce[12], myaktsnonce[13], myaktsnonce[14], myaktsnonce[15],
	myaktsnonce[16], myaktsnonce[17], myaktsnonce[18], myaktsnonce[19], myaktsnonce[20], myaktsnonce[21], myaktsnonce[22], myaktsnonce[23],
	myaktsnonce[24], myaktsnonce[25], myaktsnonce[26], myaktsnonce[27], myaktsnonce[28], myaktsnonce[29], myaktsnonce[30], myaktsnonce[31]
	);
if(dltlinktype == DLT_IEEE802_11_RADIO)		printf("link layer header type................: DLT_IEEE802_11_RADIO (%d)\n", dltlinktype);
if(dltlinktype == DLT_IEEE802_11)		printf("link layer header type................: DLT_IEEE802_11 (%d)\n", dltlinktype);
if(dltlinktype == DLT_PPI)			printf("link layer header type................: DLT_PPI (%d)\n", dltlinktype);
if(dltlinktype == DLT_PRISM_HEADER)		printf("link layer header type................: DLT_PRISM_HEADER (%d)\n", dltlinktype);
if(dltlinktype == DLT_IEEE802_11_RADIO_AVS)	printf("link layer header type................: DLT_IEEE802_11_RADIO_AVS (%d)\n", dltlinktype);

cleanupmac();
cleanuppmkid();
cleanuphandshake();
outputwpalists();
printcontentinfo();

return;
}
/*===========================================================================*/
static bool processcapfile(char *pcapinname)
{
static int resseek;
static uint32_t magicnumber;
static char *pcapnameptr;
static char *pcaptempnameptr;

static char tmpoutname[PATH_MAX +1];

pcaptempnameptr = NULL;
pcapnameptr = pcapinname;
if(testgzipfile(pcapinname) == true)
	{
	memset(&tmpoutname, 0, PATH_MAX);
	snprintf(tmpoutname, PATH_MAX, "/tmp/%s.tmp", basename(pcapinname));
	if(decompressgz(pcapinname, tmpoutname) == false) return false;
	pcaptempnameptr = tmpoutname;
	pcapnameptr = tmpoutname;
	}
jtrbasename = pcapinname;
fd_pcap = open(pcapnameptr, O_RDONLY);
if(fd_pcap == -1)
	{
	perror("failed to open file");
	return false;
	}
magicnumber = getmagicnumber(fd_pcap);

resseek = lseek(fd_pcap, 0L, SEEK_SET);
if(resseek < 0)
	{
	pcapreaderrors++;
	printf("failed to set file pointer\n");
	return false;
	}

if(magicnumber == PCAPNGBLOCKTYPE)
	{
	if(initlists() == true)
		{
		processpcapng(fd_pcap, pcapinname, pcapnameptr);
		close(fd_pcap);
		closelists();
		}
	}

else if((magicnumber == PCAPMAGICNUMBER) || (magicnumber == PCAPMAGICNUMBERBE))
	{
	if(initlists() == true)
		{
		processcap(fd_pcap, pcapinname, pcapnameptr);
		close(fd_pcap);
		closelists();
		}
	}

if(pcaptempnameptr != NULL) remove(pcaptempnameptr);

return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"%s <options> input.pcapng\n"
	"%s <options> *.pcapng\n"
	"%s <options> *.pcap\n"
	"%s <options> *.cap\n"
	"%s <options> *.*\n"
	"\n"
	"options:\n"
	"-o <file> : output PMKID/EAPOL (hashcat -m 22000/22001)\n"
	"-j <file> : output PMKID/EAPOL (JtR wpapsk-opencl/wpapsk-pmk-opencl)\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--eapoltimeout=<digit>             : set EAPOL TIMEOUT (milliseconds)\n"
	"                                   : default: %d ms\n"
	"--nonce-error-corrections=<digit>  : set nonce error correction\n"
	"                                     warning: values > 0 can lead to uncrackable handshakes\n"
	"                                   : default: %d\n"
	"--ignore-ie                        : do not use CIPHER and AKM information\n"
	"                                     this will convert damaged frames,\n"
	"                                     but can lead to uncrackable hashes\n"
	"--max-essids=<digit>               : maximum allowed ESSIDs\n"
	"                                     default: %d ESSID\n"
	"                                     disregard ESSID changes and take ESSID with highest ranking\n"
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n"
	"bitmask for message pair field:\n"
	"0: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)\n"
	"1: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)\n"
	"2: MP info (https://hashcat.net/wiki/doku.php?id=hccapx)\n"
	"3: x (unused)\n"
	"4: ap-less attack (set to 1) - no nonce-error-corrections necessary\n"
	"5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary\n"
	"6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary\n"
	"7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary\n"
	"\n"
	"Do not edit, merge or convert pcapng files!. This will remove optional comment fields!\n"
	"Do not use %s in combination with third party cap/pcap/pcapng cleaning tools (except: tshark and/or Wireshark)!\n"
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcaptool will understand this.\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname, eigenname, eigenname, eigenname,
	EAPOLTIMEOUT /10000, NONCEERRORCORRECTION, ESSIDSMAX,
	eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usageerror(char *eigenname)
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
static char *pmkideapolhcoutname;
static char *pmkideapoljtroutname;
struct timeval tv;
static struct stat statinfo;

static const char *short_options = "o:j:hv";
static const struct option long_options[] =
{
	{"eapoltimeout",		required_argument,	NULL,	HCX_EAPOL_TIMEOUT},
	{"nonce-error-corrections",	required_argument,	NULL,	HCX_NC},
	{"ignore-ie",			no_argument,		NULL,	HCX_IE},
	{"max-essids",			required_argument,	NULL,	HCX_ESSIDS},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
ignoreieflag = false;
eapoltimeoutvalue = EAPOLTIMEOUT;
ncvalue = NONCEERRORCORRECTION;
essidsvalue = ESSIDSMAX;
pmkideapolhcoutname = NULL;
pmkideapoljtroutname = NULL;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_EAPOL_TIMEOUT:
		eapoltimeoutvalue = strtol(optarg, NULL, 10);
		if(eapoltimeoutvalue <= 0)
			{
			fprintf(stderr, "EAPOL TIMEOUT must be > 0\n");
			exit(EXIT_FAILURE);
			}
		eapoltimeoutvalue *= 10000;
		break;

		case HCX_NC:
		ncvalue = strtol(optarg, NULL, 10) *4;
		break;

		case HCX_IE:
		ignoreieflag = true;
		break;
		
		case HCX_ESSIDS:
		essidsvalue = strtol(optarg, NULL, 10);
		break;

		case HCX_PMKIDEAPOLHC_OUT:
		pmkideapolhcoutname = optarg;
		break;

		case HCX_PMKIDEAPOLJTR_OUT:
		pmkideapoljtroutname = optarg;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

gettimeofday(&tv, NULL);
timestampstart = ((uint64_t)tv.tv_sec *1000000) + tv.tv_usec;

if(argc < 2)
	{
	printf("no option selected\n");
	return EXIT_SUCCESS;
	}

if(optind == argc)
	{
	printf("no input file(s) selected\n");
	exit(EXIT_FAILURE);
	}

if(pmkideapolhcoutname != NULL)
	{
	if((fh_pmkideapolhc = fopen(pmkideapolhcoutname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkideapolhcoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(pmkideapoljtroutname != NULL)
	{
	if((fh_pmkideapoljtr = fopen(pmkideapoljtroutname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkideapoljtroutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

for(index = optind; index < argc; index++)
	{
	processcapfile(argv[index]);
	}

if(fh_pmkideapolhc != NULL) fclose(fh_pmkideapolhc);
if(fh_pmkideapoljtr != NULL) fclose(fh_pmkideapoljtr);

if(pmkideapolhcoutname != NULL)
	{
	if(stat(pmkideapolhcoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapolhcoutname);
		}
	}
if(pmkideapoljtroutname != NULL)
	{
	if(stat(pmkideapoljtroutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapoljtroutname);
		}
	}
return EXIT_SUCCESS;
}
/*===========================================================================*/

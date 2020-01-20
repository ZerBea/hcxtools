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
#include <libgen.h>
#include <sys/socket.h>
#include <inttypes.h>
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

struct hccap_s
{
  char essid[36];
  unsigned char ap[6];
  unsigned char client[6];
  unsigned char snonce[32];
  unsigned char anonce[32];
  unsigned char eapol[256];
  int eapol_size;
  int keyver;
  unsigned char keymic[16];
};
typedef struct hccap_s hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))
/*===========================================================================*/
struct hccapx_s
{
 uint32_t	signature;
#define HCCAPX_SIGNATURE 0x58504348
 uint32_t	version;
#define HCCAPX_VERSION 4
 uint8_t	message_pair;
 uint8_t	essid_len;
 uint8_t	essid[32];
 uint8_t	keyver;
 uint8_t	keymic[16];
 uint8_t	ap[6];
 uint8_t	anonce[32];
 uint8_t	client[6];
 uint8_t	snonce[32];
 uint16_t	eapol_len;
 uint8_t	eapol[256];
} __attribute__((packed));
typedef struct hccapx_s hccapx_t;
#define	HCCAPX_SIZE (sizeof(hccapx_t))
/*===========================================================================*/
/* global var */

static maclist_t *aplist, *aplistptr;
static messagelist_t *messagelist;
static handshakelist_t *handshakelist, *handshakelistptr;
static pmkidlist_t *pmkidlist, *pmkidlistptr;
static eapmd5msglist_t *eapmd5msglist;
static eapmd5hashlist_t *eapmd5hashlist, *eapmd5hashlistptr;
static eapleaphashlist_t *eapleaphashlist, *eapleaphashlistptr;
static eapleapmsglist_t *eapleapmsglist;

static char *jtrbasenamedeprecated;

static FILE *fh_pmkideapol;
static FILE *fh_eapmd5;
static FILE *fh_eapmd5john;
static FILE *fh_eapleap;
static FILE *fh_essid;
static FILE *fh_identity;
static FILE *fh_username;
static FILE *fh_nmea;
static FILE *fh_pmkideapoljtrdeprecated;
static FILE *fh_pmkiddeprecated;
static FILE *fh_hccapxdeprecated;
static FILE *fh_hccapdeprecated;

static int maclistmax;
static int handshakelistmax;
static int pmkidlistmax;
static int eapmd5hashlistmax;
static int eapleaphashlistmax;
static int fd_pcap;

static int endianess;
static uint16_t versionmajor;
static uint16_t versionminor;
static uint16_t dltlinktype;

static long int nmeacount;
static long int rawpacketcount;
static long int pcapreaderrors;
static long int skippedpacketcount;
static long int zeroedtimestampcount;
static long int fcsframecount;
static long int wdscount;
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
static long int ipv4count;
static long int ipv6count;
static long int wepenccount;
static long int wpaenccount;
static long int eapcount;
static long int eapsimcount;
static long int eapakacount;
static long int eappeapcount;
static long int eapmd5count;
static long int eapmd5hashcount;
static long int eapleapcount;
static long int eapleaphashcount;
static long int eapexpandedcount;
static long int eapidcount;
static long int eapcodereqcount;
static long int eapcoderespcount;
static long int zeroedpmkcount;
static long int pmkidcount;
static long int pmkidbestcount;
static long int pmkiduselesscount;
static long int pmkidwrittenhcount;
static long int pmkidwrittenjcountdeprecated;
static long int pmkidwrittencountdeprecated;
static long int eapolrc4count;
static long int eapolrsncount;
static long int eapolwpacount;
static long int eapolmsgcount;
static long int eapolmpcount;
static long int eapolmpbestcount;
static long int eapolm1count;
static long int eapolm2count;
static long int eapolm3count;
static long int eapolm4count;
static long int eapolwrittencount;
static long int eapolncwrittencount;
static long int eapolaplesscount;
static long int eapolwrittenjcountdeprecated;
static long int eapolwrittenhcpxcountdeprecated;
static long int eapolncwrittenhcpxcountdeprecated;
static long int eapolwrittenhcpcountdeprecated;
static long int eapolm12e2count;
static long int eapolm14e4count;
static long int eapolm32e2count;
static long int eapolm32e3count;
static long int eapolm34e3count;
static long int eapolm34e4count;
static long int eapmd5writtencount;
static long int eapmd5johnwrittencount;
static long int eapleapwrittencount;
static long int identitycount;
static long int usernamecount;

static uint64_t rcgapmax;

static long int essidcount;
static long int essiddupemax;

static uint64_t timestampstart;
static uint64_t timestampmin;
static uint64_t timestampmax;
static uint64_t eaptimegapmax;

static uint32_t eapoltimeoutvalue;
static uint64_t ncvalue;
static int essidsvalue;

static int nmealen;

static bool ignoreieflag;
static bool donotcleanflag;

static const uint8_t fakenonce1[] =
{
0x07, 0xbc, 0x92, 0xea, 0x2f, 0x5a, 0x1e, 0xe2, 0x54, 0xf6, 0xb1, 0xb7, 0xe0, 0xaa, 0xd3, 0x53,
0xf4, 0x5b, 0x0a, 0xac, 0xf9, 0xc9, 0x90, 0x2f, 0x90, 0xd8, 0x78, 0x80, 0xb7, 0x03, 0x0a, 0x20
};

static const uint8_t fakenonce2[] =
{
0x95, 0x30, 0xd1, 0xc7, 0xc3, 0x55, 0xb9, 0xab, 0xe6, 0x83, 0xd6, 0xf3, 0x7e, 0xcb, 0x78, 0x02,
0x75, 0x1f, 0x53, 0xcc, 0xb5, 0x81, 0xd1, 0x52, 0x3b, 0xb4, 0xba, 0xad, 0x23, 0xab, 0x01, 0x07
};

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

static char nmeasentence[OPTIONLEN_MAX];
static char gpwplold[OPTIONLEN_MAX];

//static unsigned char pmk[64];

/*===========================================================================*/
/*
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
*/
/*===========================================================================*/
static void closelists()
{
if(aplist != NULL) free(aplist);
if(messagelist != NULL) free(messagelist);
if(handshakelist != NULL) free(handshakelist);
if(pmkidlist != NULL) free(pmkidlist);
if(eapmd5msglist != NULL) free(eapmd5msglist);
if(eapmd5hashlist != NULL) free(eapmd5hashlist);
if(eapleapmsglist != NULL) free(eapleapmsglist);
if(eapleaphashlist != NULL) free(eapleaphashlist);
return;
}
/*===========================================================================*/
static bool initlists()
{
static const char nastring[] = { "N/A" };

maclistmax = MACLIST_MAX;
if((aplist = (maclist_t*)calloc((maclistmax +1), MACLIST_SIZE)) == NULL) return false;
aplistptr = aplist;

if((messagelist = (messagelist_t*)calloc((MESSAGELIST_MAX +1), MESSAGELIST_SIZE)) == NULL) return false;

handshakelistmax = HANDSHAKELIST_MAX;
if((handshakelist = (handshakelist_t*)calloc((handshakelistmax +1), HANDSHAKELIST_SIZE)) == NULL) return false;
handshakelistptr = handshakelist;

pmkidlistmax = PMKIDLIST_MAX;
if((pmkidlist = (pmkidlist_t*)calloc((pmkidlistmax +1),PMKIDLIST_SIZE)) == NULL) return false;
pmkidlistptr = pmkidlist;

if((eapmd5msglist = (eapmd5msglist_t*)calloc((EAPMD5MSGLIST_MAX +1), EAPMD5MSGLIST_SIZE)) == NULL) return false;

eapmd5hashlistmax = EAPMD5HASHLIST_MAX;
if((eapmd5hashlist = (eapmd5hashlist_t*)calloc((eapmd5hashlistmax +1), EAPMD5HASHLIST_SIZE)) == NULL) return false;
eapmd5hashlistptr = eapmd5hashlist;

if((eapleapmsglist = (eapleapmsglist_t*)calloc((EAPLEAPMSGLIST_MAX +1), EAPLEAPMSGLIST_SIZE)) == NULL) return false;

eapleaphashlistmax = EAPLEAPHASHLIST_MAX;
if((eapleaphashlist = (eapleaphashlist_t*)calloc((eapleaphashlistmax +1), EAPLEAPHASHLIST_SIZE)) == NULL) return false;
eapleaphashlistptr = eapleaphashlist;

memset(&pcapnghwinfo, 0, OPTIONLEN_MAX);
memset(&pcapngosinfo, 0, OPTIONLEN_MAX);
memset(&pcapngapplinfo, 0, OPTIONLEN_MAX);
memset(&pcapngoptioninfo, 0, OPTIONLEN_MAX);
memset(&pcapngweakcandidate, 0 ,OPTIONLEN_MAX);
memset(&pcapngdeviceinfo, 0 ,6);
memset(&myaktap, 0 ,6);
memset(&myaktclient, 0 ,6);
memset(&nmeasentence, 0, OPTIONLEN_MAX);
memset(&gpwplold, 0, OPTIONLEN_MAX);

memcpy(&pcapnghwinfo, nastring, 3);
memcpy(&pcapngosinfo, nastring, 3);
memcpy(&pcapngapplinfo, nastring, 3);
memcpy(&pcapngoptioninfo, nastring, 3);
memcpy(&pcapngweakcandidate, nastring, 3);

nmeacount = 0;
endianess = 0;
rawpacketcount = 0;
pcapreaderrors = 0;
skippedpacketcount = 0;
zeroedtimestampcount = 0;
fcsframecount = 0;
wdscount = 0;
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
ipv4count = 0;
ipv6count = 0;
wepenccount = 0;
wpaenccount = 0;
eapcount = 0;
eapsimcount = 0;
eapakacount = 0;
eappeapcount = 0;
eapmd5count = 0;
eapmd5hashcount = 0;
eapleapcount = 0;
eapleaphashcount = 0;
eapexpandedcount = 0;
eapidcount = 0;
eapcodereqcount = 0;
eapcoderespcount = 0;
zeroedpmkcount = 0;
pmkidcount = 0;
pmkidbestcount = 0;
pmkiduselesscount = 0;
pmkidwrittenhcount = 0;
eapolwrittenjcountdeprecated = 0;
pmkidwrittenjcountdeprecated = 0;
pmkidwrittencountdeprecated = 0;
eapolrc4count = 0;
eapolrsncount = 0;
eapolwpacount = 0;
eapolmsgcount = 0;
eapolmpbestcount = 0;
eapolmpcount = 0;
eapolm1count = 0;
eapolm2count = 0;
eapolm3count = 0;
eapolm4count = 0;
eapolwrittencount = 0;
eapolaplesscount = 0;
eapolwrittenjcountdeprecated = 0;
eapolwrittenhcpxcountdeprecated = 0;
eapolwrittenhcpcountdeprecated = 0;
eapolm12e2count = 0;
eapolm14e4count = 0;
eapolm32e2count = 0;
eapolm32e3count = 0;
eapolm34e3count = 0;
eapolm34e4count = 0;
eapmd5writtencount = 0;
eapmd5johnwrittencount = 0;
eapleapwrittencount = 0;
identitycount = 0;
usernamecount = 0;
essidcount = 0;
essiddupemax = 0;
rcgapmax = 0;
eaptimegapmax = 0;

timestampmin = 0;
timestampmax = 0;
timestampstart = 0;
return true;
}
/*===========================================================================*/
static void printcontentinfo()
{
if(nmeacount > 0)			printf("NMEA sentence..........................: %ld\n", nmeacount);
if(endianess == 0)			printf("endianess (capture system).............: little endian\n");
else					printf("endianess (capture system).............: big endian\n");
if(rawpacketcount > 0)			printf("packets inside.........................: %ld\n", rawpacketcount);
if(pcapreaderrors > 0)			printf("read errors............................: %ld\n", pcapreaderrors);
if(zeroedtimestampcount > 0)		printf("packets with zeroed timestamps.........: %ld (warning: this prevents EAPOL time calculation)\n", zeroedtimestampcount);
if(skippedpacketcount > 0)		printf("skipped packets........................: %ld\n", skippedpacketcount);
if(fcsframecount > 0)			printf("frames with correct FCS................: %ld\n", fcsframecount);
if(wdscount > 0)			printf("WIRELESS DISTRIBUTION SYSTEM...........: %ld\n", wdscount);
if(beaconcount > 0)			printf("BEACON.................................: %ld\n", beaconcount);
if(proberequestcount > 0)		printf("PROBEREQUEST...........................: %ld\n", proberequestcount);
if(proberequestdirectedcount > 0)	printf("PROBEREQUEST (directed)................: %ld\n", proberequestdirectedcount);
if(proberesponsecount > 0)		printf("PROBERESONSE...........................: %ld\n", proberesponsecount);
if(authopensystemcount > 0)		printf("AUTHENTICATION (OPEN SYSTEM)...........: %ld\n", authopensystemcount);
if(authseacount > 0)			printf("AUTHENTICATION (SAE)...................: %ld\n", authseacount);
if(authsharedkeycount > 0)		printf("AUTHENTICATION (SHARED KEY)............: %ld\n", authsharedkeycount);
if(authfbtcount > 0)			printf("AUTHENTICATION (FBT)...................: %ld\n", authfbtcount);
if(authfilscount > 0)			printf("AUTHENTICATION (FILS)..................: %ld\n", authfilscount);
if(authfilspfs > 0)			printf("AUTHENTICATION (FILS PFS)..............: %ld\n", authfilspfs);
if(authfilspkcount > 0)			printf("AUTHENTICATION (FILS PK................: %ld\n", authfilspkcount);
if(authnetworkeapcount > 0)		printf("AUTHENTICATION (NETWORK EAP)...........: %ld\n", authnetworkeapcount);
if(authunknowncount > 0)		printf("AUTHENTICATION (unknown)...............: %ld\n", authunknowncount);
if(associationrequestcount > 0)		printf("ASSOCIATIONREQUEST.....................: %ld\n", associationrequestcount);
if(reassociationrequestcount > 0)	printf("REASSOCIATIONREQUEST...................: %ld\n", reassociationrequestcount);
if(wpaenccount > 0)			printf("WPA encrypted..........................: %ld\n", wpaenccount);
if(wepenccount > 0)			printf("WEP encrypted..........................: %ld\n", wepenccount);
if(ipv4count > 0)			printf("IPv4...................................: %ld\n", ipv4count);
if(ipv6count > 0)			printf("IPv6...................................: %ld\n", ipv6count);
if(identitycount > 0)			printf("IDENTITIES.............................: %ld\n", identitycount);
if(usernamecount > 0)			printf("USERNAMES..............................: %ld\n", usernamecount);
if(eapcount > 0)			printf("EAP (total)............................: %ld\n", eapcount);
if(eapexpandedcount > 0)		printf("EAP-EXPANDED...........................: %ld\n", eapexpandedcount);
if(eapcodereqcount > 0)			printf("EAP CODE REQUEST.......................: %ld\n", eapcodereqcount);
if(eapcoderespcount > 0)		printf("EAP CODE RESPONSE......................: %ld\n", eapcoderespcount);
if(eapidcount > 0)			printf("EAP ID.................................: %ld\n", eapidcount);
if(eapsimcount > 0)			printf("EAP-SIM................................: %ld\n", eapsimcount);
if(eapakacount > 0)			printf("EAP-AKA................................: %ld\n", eapakacount);
if(eappeapcount > 0)			printf("EAP-PEAP...............................: %ld\n", eappeapcount);
if(eapmd5count > 0)			printf("EAP-MD5 messages.......................: %ld\n", eapmd5count);
if(eapmd5hashcount > 0)			printf("EAP-MD5 pairs..........................: %ld\n", eapmd5hashcount);
if(eapmd5writtencount > 0)		printf("EAP-MD5 pairs written..................: %ld\n", eapmd5writtencount);
if(eapmd5johnwrittencount > 0)		printf("EAP-MD5 pairs written to JtR...........: %ld\n", eapmd5johnwrittencount);
if(eapleapcount > 0)			printf("EAP-LEAP messages......................: %ld\n", eapleapcount);
if(eapleapwrittencount > 0)		printf("EAP-LEAP pairs written.................: %ld\n", eapleapwrittencount);
if(zeroedpmkcount > 0)			printf("PMK (zeroed)...........................: %ld\n", zeroedpmkcount);
if(eapolmsgcount > 0)			printf("EAPOL messages (total).................: %ld\n", eapolmsgcount);
if(eapolrc4count > 0)			printf("EAPOL RC4 messages.....................: %ld\n", eapolrc4count);
if(eapolrsncount > 0)			printf("EAPOL RSN messages.....................: %ld\n", eapolrsncount);
if(eapolwpacount > 0)			printf("EAPOL WPA messages.....................: %ld\n", eapolwpacount);
if(essidcount > 0)			printf("ESSID (total unique)...................: %ld\n", essidcount);
if(essiddupemax > 0)			printf("ESSID changes (mesured maximum)........: %ld (warning)\n", essiddupemax);
if(eaptimegapmax > 0)			printf("EAPOLTIME gap (measured maximum usec)..: %" PRId64 "\n", eaptimegapmax);
if(rcgapmax > 0)			printf("REPLAYCOUNT gap (measured maximum).....: %" PRIu64 "\n", rcgapmax);
if(eapolm1count > 0)			printf("EAPOL M1 messages......................: %ld\n", eapolm1count);
if(eapolm2count > 0)			printf("EAPOL M2 messages......................: %ld\n", eapolm2count);
if(eapolm3count > 0)			printf("EAPOL M3 messages......................: %ld\n", eapolm3count);
if(eapolm4count > 0)			printf("EAPOL M4 messages......................: %ld\n", eapolm4count);
if(eapolmpcount > 0)			printf("EAPOL pairs (total)....................: %ld\n", eapolmpcount);
if(eapolmpbestcount > 0)		printf("EAPOL pairs (best).....................: %ld\n", eapolmpbestcount);
if(eapolaplesscount > 0)		printf("EAPOL pairs (AP-LESS)..................: %ld\n", eapolaplesscount);
if(eapolwrittencount > 0)		printf("EAPOL pairs written to combi hash file.: %ld (RC checked)\n", eapolwrittencount);
if(eapolncwrittencount > 0)		printf("EAPOL pairs written to combi hash file.: %ld (RC not checked)\n", eapolncwrittencount);
if(eapolwrittenhcpxcountdeprecated > 0)	printf("EAPOL pairs written to hccapx..........: %ld (RC checked)\n", eapolwrittenhcpxcountdeprecated);
if(eapolncwrittenhcpxcountdeprecated > 0)	printf("EAPOL pairs written to hccapx..........: %ld (RC not checked)\n", eapolncwrittenhcpxcountdeprecated);
if(eapolwrittenhcpcountdeprecated > 0)	printf("EAPOL pairs written to hccap...........: %ld (RC checked)\n", eapolwrittenhcpcountdeprecated);
if(eapolwrittenjcountdeprecated > 0)	printf("EAPOL pairs written to old JtR format..: %ld (RC checked)\n", eapolwrittenjcountdeprecated);
if(eapolm12e2count > 0)			printf("EAPOL M12E2............................: %ld\n", eapolm12e2count);
if(eapolm14e4count > 0)			printf("EAPOL M14E4............................: %ld\n", eapolm14e4count);
if(eapolm32e2count > 0)			printf("EAPOL M32E2............................: %ld\n", eapolm32e2count);
if(eapolm32e3count > 0)			printf("EAPOL M32E3............................: %ld\n", eapolm32e3count);
if(eapolm34e3count > 0)			printf("EAPOL M34E3............................: %ld\n", eapolm34e3count);
if(eapolm34e4count > 0)			printf("EAPOL M34E4............................: %ld\n", eapolm34e4count);
if(pmkidcount > 0)			printf("PMKID (total)..........................: %ld\n", pmkidcount);
if(pmkidbestcount > 0)			printf("PMKID (best)...........................: %ld\n", pmkidbestcount);
if(pmkiduselesscount > 0)		printf("PMKID (useless)........................: %ld\n", pmkiduselesscount);
if(pmkidwrittenhcount > 0)		printf("PMKID written to combi hash file.......: %ld\n", pmkidwrittenhcount);
if(pmkidwrittenjcountdeprecated > 0)	printf("PMKID written to old JtR format........: %ld\n", pmkidwrittenjcountdeprecated);
if(pmkidwrittencountdeprecated > 0)	printf("PMKID written to old format (1680x)....: %ld\n", pmkidwrittencountdeprecated);
printf("\n");
return;
}
/*===========================================================================*/
static void printlinklayerinfo()
{
static struct timeval tvmin;
static struct timeval tvmax;
static char timestringmin[32];
static char timestringmax[32];

tvmin.tv_sec = timestampmin /1000000;
tvmin.tv_usec = timestampmin %1000000;
strftime(timestringmin, 32, "%d.%m.%Y %H:%M:%S", localtime(&tvmin.tv_sec));
tvmax.tv_sec = timestampmax /1000000;
tvmax.tv_usec = timestampmax %1000000;
strftime(timestringmax, 32, "%d.%m.%Y %H:%M:%S", localtime(&tvmax.tv_sec));
printf("timestamp minimum (GMT)................: %s\n", timestringmin);
printf("timestamp maximum (GMT)................: %s\n", timestringmax);
if(dltlinktype == DLT_IEEE802_11_RADIO)		printf("link layer header type.................: DLT_IEEE802_11_RADIO (%d)\n", dltlinktype);
if(dltlinktype == DLT_IEEE802_11)		printf("link layer header type.................: DLT_IEEE802_11 (%d)\n", dltlinktype);
if(dltlinktype == DLT_PPI)			printf("link layer header type.................: DLT_PPI (%d)\n", dltlinktype);
if(dltlinktype == DLT_PRISM_HEADER)		printf("link layer header type.................: DLT_PRISM_HEADER (%d)\n", dltlinktype);
if(dltlinktype == DLT_IEEE802_11_RADIO_AVS)	printf("link layer header type.................: DLT_IEEE802_11_RADIO_AVS (%d)\n", dltlinktype);
if(dltlinktype == DLT_EN10MB)			printf("link layer header type.................: DLT_EN10MB (%d)\n", dltlinktype);
return;
}
/*===========================================================================*/
static void outputwordlists()
{
static int wecl;
static maclist_t *zeigermac, *zeigermacold;

zeigermacold = NULL;
qsort(aplist, aplistptr -aplist, MACLIST_SIZE, sort_maclist_by_essidlen);
wecl = strlen(pcapngweakcandidate);
if((wecl > 0) && (wecl < 64) && (strcmp(pcapngweakcandidate, "N/A") != 0))
	{
	if(fh_essid != NULL) fprintf(fh_essid, "%s\n", pcapngweakcandidate); 
	}
for(zeigermac = aplist; zeigermac < aplistptr; zeigermac++)
	{
	if((zeigermacold != NULL) && (zeigermac->essidlen == zeigermacold->essidlen))
		{
		if(memcmp(zeigermac->essid, zeigermacold->essid, zeigermac->essidlen) == 0) continue;
		}
	if(zeigermac->essidlen > ESSID_LEN_MAX) continue;
	if(zeigermac->essidlen == 0) continue;
	if(fh_essid != NULL) fwriteessidstr(zeigermac->essidlen, zeigermac->essid, fh_essid);
	essidcount++;
	zeigermacold = zeigermac;
	}
return;
}
/*===========================================================================*/
static void writegpwpl(uint8_t *mac)
{
static int c;
static int cs;
static int gpwpllen;
static char *gpwplptr;
static char gpwpl[NMEA_MAX];

static const char gpgga[] = "$GPGGA";
static const char gprmc[] = "$GPRMC";

if(nmealen < 30) return;
if(memcmp(&gpgga, &nmeasentence, 6) == 0) snprintf(gpwpl, NMEA_MAX-1, "$GPWPL,%.*s,%02x%02x%02x%02x%02x%02x*", 26, &nmeasentence[17], mac[0] , mac[1], mac[2], mac[3], mac[4], mac[5]);
else if(memcmp(&gprmc, &nmeasentence, 6) == 0) snprintf(gpwpl, NMEA_MAX-1, "$GPWPL,%.*s,%02x%02x%02x%02x%02x%02x*", 26, &nmeasentence[19], mac[0] , mac[1], mac[2], mac[3], mac[4], mac[5]);
else return;

gpwplptr = gpwpl+1;
c = 0;
cs = 0;
while(gpwplptr[c] != '*')
	{
	cs ^= gpwplptr[c];
	gpwplptr++;
	}
snprintf(gpwplptr +1, NMEA_MAX -44, "%02x", cs);
gpwpllen = strlen(gpwpl);
if(memcmp(&gpwplold, &gpwpl, gpwpllen) != 0) fprintf(fh_nmea, "%s\n", gpwpl);
memcpy(&gpwplold, &gpwpl, gpwpllen);
return;
}
/*===========================================================================*/
static void processipv4(uint64_t timestamp, uint16_t ipv4len, uint8_t *ipv4ptr)
{

ipv4count++;


//dummy code to satisfy gcc untill full code is implemented
timestamp = timestamp;
ipv4len = ipv4len;
if(ipv4ptr == NULL) return;
return;
}
/*===========================================================================*/
static void processipv6(uint64_t timestamp, uint16_t ipv6len, uint8_t *ipv6ptr)
{

ipv6count++;


//dummy code to satisfy gcc untill full code is implemented
if(ipv6ptr == NULL) return;
timestamp = timestamp;
ipv6len = ipv6len;
return;
}
/*===========================================================================*/
static void outputeapleaphashlist()
{
static eapleaphashlist_t *zeiger, *zeigerold;

zeiger = eapleaphashlist;
zeigerold = eapleaphashlist;
if(memcmp(&zeroed32, zeiger->leaprequest, LEAPREQ_LEN_MAX) == 0) return;
qsort(eapleaphashlist, eapleaphashlistptr -eapleaphashlist, EAPLEAPHASHLIST_SIZE, sort_eapleaphashlist_by_id);
if(fh_eapleap != 0)
	{
	fprintf(fh_eapleap, "%.*s::::%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x\n",
		zeiger->leapusernamelen, zeiger->leapusername,
		zeiger->leapresponse[0], zeiger->leapresponse[1], zeiger->leapresponse[2], zeiger->leapresponse[3], zeiger->leapresponse[4], zeiger->leapresponse[5], zeiger->leapresponse[6], zeiger->leapresponse[7],
		zeiger->leapresponse[8], zeiger->leapresponse[9], zeiger->leapresponse[10], zeiger->leapresponse[11], zeiger->leapresponse[12], zeiger->leapresponse[13], zeiger->leapresponse[14], zeiger->leapresponse[15],
		zeiger->leapresponse[16], zeiger->leapresponse[17], zeiger->leapresponse[18], zeiger->leapresponse[19], zeiger->leapresponse[20], zeiger->leapresponse[21], zeiger->leapresponse[22], zeiger->leapresponse[23],
		zeiger->leaprequest[0], zeiger->leaprequest[1], zeiger->leaprequest[2], zeiger->leaprequest[3], zeiger->leaprequest[4], zeiger->leaprequest[5], zeiger->leaprequest[6], zeiger->leaprequest[7]);
	eapleapwrittencount++;
	}
for(zeiger = eapleaphashlist +1; zeiger < eapleaphashlistptr; zeiger++)
	{
	if((zeigerold->id == zeiger->id) && (zeigerold->leapusernamelen == zeiger->leapusernamelen) && (memcmp(zeigerold->leapusername, zeiger->leapusername, zeiger->leapusernamelen) == 0) && (memcmp(zeigerold->leaprequest, zeiger->leaprequest, LEAPREQ_LEN_MAX) == 0) && (memcmp(zeigerold->leapresponse, zeiger->leapresponse, LEAPRESP_LEN_MAX) == 0)) continue;
	if(fh_eapleap != 0)
		{
		fprintf(fh_eapleap, "%.*s::::%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x\n",
			zeiger->leapusernamelen, zeiger->leapusername,
			zeiger->leapresponse[0], zeiger->leapresponse[1], zeiger->leapresponse[2], zeiger->leapresponse[3], zeiger->leapresponse[4], zeiger->leapresponse[5], zeiger->leapresponse[6], zeiger->leapresponse[7],
			zeiger->leapresponse[8], zeiger->leapresponse[9], zeiger->leapresponse[10], zeiger->leapresponse[11], zeiger->leapresponse[12], zeiger->leapresponse[13], zeiger->leapresponse[14], zeiger->leapresponse[15],
			zeiger->leapresponse[16], zeiger->leapresponse[17], zeiger->leapresponse[18], zeiger->leapresponse[19], zeiger->leapresponse[20], zeiger->leapresponse[21], zeiger->leapresponse[22], zeiger->leapresponse[23],
			zeiger->leaprequest[0], zeiger->leaprequest[1], zeiger->leaprequest[2], zeiger->leaprequest[3], zeiger->leaprequest[4], zeiger->leaprequest[5], zeiger->leaprequest[6], zeiger->leaprequest[7]);
		eapleapwrittencount++;
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
static void addeapleaphash(uint8_t id, uint8_t leapusernamelen, uint8_t *leapusername, uint8_t *leaprequest, uint8_t *leapresponse)
{
static eapleaphashlist_t *eapleaphashlistnew; 

eapleaphashcount++;
if(eapleaphashlistptr >= eapleaphashlist +eapleaphashlistmax)
	{
	eapleaphashlistnew = realloc(eapleaphashlist, (eapleaphashlistmax +EAPLEAPHASHLIST_MAX) *EAPLEAPHASHLIST_SIZE);
	if(eapleaphashlistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	eapleaphashlist = eapleaphashlistnew;
	eapleaphashlistptr = eapleaphashlistnew +eapleaphashlistmax;
	eapleaphashlistmax += EAPLEAPHASHLIST_MAX;
	}
memset(eapleaphashlistptr, 0, EAPLEAPHASHLIST_SIZE);
eapleaphashlistptr->id = id;
memcpy(eapleaphashlistptr->leaprequest, leaprequest, LEAPREQ_LEN_MAX);
memcpy(eapleaphashlistptr->leapresponse, leapresponse, LEAPRESP_LEN_MAX);
eapleaphashlistptr->leapusernamelen = leapusernamelen;
memcpy(eapleaphashlistptr->leapusername, leapusername, leapusernamelen);
eapleaphashlistptr++;
return;
}
/*===========================================================================*/
static void processexteapleap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eapcode, uint32_t restlen, uint8_t *eapleapptr)
{
static eapleap_t *eapleap;
static uint32_t eapleaplen;
static eapleapmsglist_t *zeiger;
static uint32_t leapusernamelen;
static uint8_t *leapusernameptr;

eapleapcount++;
eapleap = (eapleap_t*)eapleapptr;
eapleaplen = ntohs(eapleap->eapleaplen);
if(eapleaplen > restlen) return;
if(eapleap->version != 1) return;
if(eapleap->reserved != 0) return;
if(eapcode == EAP_CODE_REQ)
	{
	zeiger = eapleapmsglist +EAPLEAPMSGLIST_MAX;
	if(eapleap->leaplen != LEAPREQ_LEN_MAX) return;
	if(eapleap->leaplen > eapleaplen -EAPLEAP_SIZE) return;
	if(eapleap->leaplen == eapleaplen -EAPLEAP_SIZE) return;
	if(memcmp(&zeroed32, eapleap->leapdata, LEAPREQ_LEN_MAX) == 0) return; 
	memset(zeiger, 0, EAPLEAPMSGLIST_SIZE);
	zeiger->timestamp = eaptimestamp;
	memcpy(zeiger->ap, macfm, 6);
	memcpy(zeiger->client, macto, 6);
	zeiger->type = EAP_CODE_REQ;
	zeiger->id = eapleap->id;
	memcpy(zeiger->leaprequest, eapleap->leapdata, LEAPREQ_LEN_MAX);
	leapusernamelen = eapleaplen -EAPLEAP_SIZE -LEAPREQ_LEN_MAX;
	if(leapusernamelen == 0) return;
	if(leapusernamelen > LEAPUSERNAME_LEN_MAX) return;
	if(EAPLEAP_SIZE +LEAPREQ_LEN_MAX +leapusernamelen > restlen) return;
	leapusernameptr = eapleapptr +EAPLEAP_SIZE +LEAPREQ_LEN_MAX;
	zeiger->leapusernamelen = leapusernamelen;
	memcpy(zeiger->leapusername, leapusernameptr, leapusernamelen);
	if(fh_username != 0)
		{
		fwritestring(leapusernamelen, leapusernameptr, fh_username);
		usernamecount++;
		}
	qsort(eapleapmsglist, EAPLEAPMSGLIST_MAX +1, EAPLEAPMSGLIST_SIZE, sort_eapleapmsglist_by_timestamp);
	}
else if(eapcode == EAP_CODE_RESP)
	{
	zeiger = eapleapmsglist +EAPLEAPMSGLIST_MAX;
	if(eapleap->leaplen != LEAPRESP_LEN_MAX) return;
	if(eapleap->leaplen > eapleaplen -EAPLEAP_SIZE) return;
	if(memcmp(&zeroed32, eapleap->leapdata, LEAPRESP_LEN_MAX) == 0) return; 
	memset(zeiger, 0, EAPLEAPMSGLIST_SIZE);
	zeiger->timestamp = eaptimestamp;
	memcpy(zeiger->ap, macto, 6);
	memcpy(zeiger->client, macfm, 6);
	zeiger->type = EAP_CODE_RESP;
	zeiger->id = eapleap->id;
	memcpy(zeiger->leapresponse, eapleap->leapdata, LEAPRESP_LEN_MAX);
	for(zeiger = eapleapmsglist; zeiger < eapleapmsglist +EAPLEAPMSGLIST_MAX; zeiger++)
		{
		if((zeiger->type) != EAP_CODE_REQ) continue;
		if((zeiger->id) != eapleap->id) continue;
		if(memcmp(zeiger->ap, macto, 6) != 0) continue;
		if(memcmp(zeiger->client, macfm, 6) != 0) continue;
		addeapleaphash(eapleap->id, zeiger->leapusernamelen, zeiger->leapusername, zeiger->leaprequest, eapleap->leapdata); 
		}
	qsort(eapleapmsglist, EAPLEAPMSGLIST_MAX +1, EAPLEAPMSGLIST_SIZE, sort_eapleapmsglist_by_timestamp);
	}
return;
}
/*===========================================================================*/
static void outputeapmd5hashlist()
{
static eapmd5hashlist_t *zeiger, *zeigerold;

zeiger = eapmd5hashlist;
zeigerold = eapmd5hashlist;
if(memcmp(&zeroed32, zeiger->md5request, EAPMD5_LEN_MAX) == 0) return;
qsort(eapmd5hashlist, eapmd5hashlistptr -eapmd5hashlist, EAPMD5HASHLIST_SIZE, sort_eapmd5hashlist_by_id);
if(fh_eapmd5 != 0)
	{
	fprintf(fh_eapmd5, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x\n",
			zeiger->md5response[0], zeiger->md5response[1], zeiger->md5response[2], zeiger->md5response[3], zeiger->md5response[4], zeiger->md5response[5], zeiger->md5response[6], zeiger->md5response[7],
			zeiger->md5response[8], zeiger->md5response[9], zeiger->md5response[10], zeiger->md5response[11], zeiger->md5response[12], zeiger->md5response[13], zeiger->md5response[14], zeiger->md5response[15],
			zeiger->md5request[0], zeiger->md5request[1], zeiger->md5request[2], zeiger->md5request[3], zeiger->md5request[4], zeiger->md5request[5], zeiger->md5request[6], zeiger->md5request[7],
			zeiger->md5request[8], zeiger->md5request[9], zeiger->md5request[10], zeiger->md5request[11], zeiger->md5request[12], zeiger->md5request[13], zeiger->md5request[14], zeiger->md5request[15],
			zeiger->id);
			eapmd5writtencount++;
	}
if(fh_eapmd5john != 0)
	{
	fprintf(fh_eapmd5john, "$chap$%x*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
			zeiger->id,
			zeiger->md5request[0], zeiger->md5request[1], zeiger->md5request[2], zeiger->md5request[3], zeiger->md5request[4], zeiger->md5request[5], zeiger->md5request[6], zeiger->md5request[7],
			zeiger->md5request[8], zeiger->md5request[9], zeiger->md5request[10], zeiger->md5request[11], zeiger->md5request[12], zeiger->md5request[13], zeiger->md5request[14], zeiger->md5request[15],
			zeiger->md5response[0], zeiger->md5response[1], zeiger->md5response[2], zeiger->md5response[3], zeiger->md5response[4], zeiger->md5response[5], zeiger->md5response[6], zeiger->md5response[7],
			zeiger->md5response[8], zeiger->md5response[9], zeiger->md5response[10], zeiger->md5response[11], zeiger->md5response[12], zeiger->md5response[13], zeiger->md5response[14], zeiger->md5response[15]);
			eapmd5johnwrittencount++;
	}
for(zeiger = eapmd5hashlist +1; zeiger < eapmd5hashlistptr; zeiger++)
	{
	if((zeigerold->id == zeiger->id) && (memcmp(zeigerold->md5request, zeiger->md5request, EAPMD5_LEN_MAX) == 0) && (memcmp(zeigerold->md5response, zeiger->md5response, EAPMD5_LEN_MAX) == 0)) continue;
	if(fh_eapmd5 != 0)
		{
		fprintf(fh_eapmd5, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x\n",
				zeiger->md5response[0], zeiger->md5response[1], zeiger->md5response[2], zeiger->md5response[3], zeiger->md5response[4], zeiger->md5response[5], zeiger->md5response[6], zeiger->md5response[7],
				zeiger->md5response[8], zeiger->md5response[9], zeiger->md5response[10], zeiger->md5response[11], zeiger->md5response[12], zeiger->md5response[13], zeiger->md5response[14], zeiger->md5response[15],
				zeiger->md5request[0], zeiger->md5request[1], zeiger->md5request[2], zeiger->md5request[3], zeiger->md5request[4], zeiger->md5request[5], zeiger->md5request[6], zeiger->md5request[7],
				zeiger->md5request[8], zeiger->md5request[9], zeiger->md5request[10], zeiger->md5request[11], zeiger->md5request[12], zeiger->md5request[13], zeiger->md5request[14], zeiger->md5request[15],
				zeiger->id);
		eapmd5writtencount++;
		}
	if(fh_eapmd5john != 0)
		{
		fprintf(fh_eapmd5john, "$chap$%x*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n",
				zeiger->id,
				zeiger->md5request[0], zeiger->md5request[1], zeiger->md5request[2], zeiger->md5request[3], zeiger->md5request[4], zeiger->md5request[5], zeiger->md5request[6], zeiger->md5request[7],
				zeiger->md5request[8], zeiger->md5request[9], zeiger->md5request[10], zeiger->md5request[11], zeiger->md5request[12], zeiger->md5request[13], zeiger->md5request[14], zeiger->md5request[15],
				zeiger->md5response[0], zeiger->md5response[1], zeiger->md5response[2], zeiger->md5response[3], zeiger->md5response[4], zeiger->md5response[5], zeiger->md5response[6], zeiger->md5response[7],
				zeiger->md5response[8], zeiger->md5response[9], zeiger->md5response[10], zeiger->md5response[11], zeiger->md5response[12], zeiger->md5response[13], zeiger->md5response[14], zeiger->md5response[15]);
				eapmd5johnwrittencount++;
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
static void addeapmd5hash(uint8_t id, uint8_t *challenge, uint8_t *response)
{
static eapmd5hashlist_t *eapmd5hashlistnew; 

eapmd5hashcount++;
if(eapmd5hashlistptr >= eapmd5hashlist +eapmd5hashlistmax)
	{
	eapmd5hashlistnew = realloc(eapmd5hashlist, (eapmd5hashlistmax +EAPMD5HASHLIST_MAX) *EAPMD5HASHLIST_SIZE);
	if(eapmd5hashlistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	eapmd5hashlist = eapmd5hashlistnew;
	eapmd5hashlistptr = eapmd5hashlistnew +eapmd5hashlistmax;
	eapmd5hashlistmax += EAPMD5HASHLIST_MAX;
	}
memset(eapmd5hashlistptr, 0, EAPMD5HASHLIST_SIZE);
eapmd5hashlistptr->id = id;
memcpy(eapmd5hashlistptr->md5request, challenge, EAPMD5_LEN_MAX);
memcpy(eapmd5hashlistptr->md5response, response, EAPMD5_LEN_MAX);
eapmd5hashlistptr++;
return;
}
/*===========================================================================*/
static void processexteapmd5(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eapcode, uint32_t restlen, uint8_t *eapmd5ptr)
{
static eapmd5_t *eapmd5;
static uint32_t eapmd5len;
static eapmd5msglist_t *zeiger;

eapmd5count++;
eapmd5 = (eapmd5_t*)eapmd5ptr;
eapmd5len = ntohs(eapmd5->eapmd5len);
if(eapmd5len != restlen) return;
if(eapmd5->md5len != EAPMD5_LEN_MAX) return;
if(memcmp(&zeroed32, eapmd5->md5data, EAPMD5_LEN_MAX) == 0) return; 
if(eapcode == EAP_CODE_REQ)
	{
	zeiger = eapmd5msglist +EAPMD5MSGLIST_MAX;
	memset(zeiger, 0, EAPMD5MSGLIST_SIZE );
	zeiger->timestamp = eaptimestamp;
	memcpy(zeiger->ap, macfm, 6);
	memcpy(zeiger->client, macto, 6);
	zeiger->type = EAP_CODE_REQ;
	zeiger->id = eapmd5->id;
	memcpy(zeiger->md5, eapmd5->md5data, EAPMD5_LEN_MAX);
	qsort(eapmd5msglist, EAPMD5MSGLIST_MAX +1, EAPMD5MSGLIST_SIZE, sort_eapmd5msglist_by_timestamp);
	}
else if(eapcode == EAP_CODE_RESP)
	{
	zeiger = eapmd5msglist +EAPMD5MSGLIST_MAX;
	memset(zeiger, 0, EAPMD5MSGLIST_SIZE );
	zeiger->timestamp = eaptimestamp;
	memcpy(zeiger->ap, macto, 6);
	memcpy(zeiger->client, macfm, 6);
	zeiger->type = EAP_CODE_RESP;
	zeiger->id = eapmd5->id;
	memcpy(zeiger->md5, eapmd5->md5data, EAPMD5_LEN_MAX);
	for(zeiger = eapmd5msglist; zeiger < eapmd5msglist +EAPMD5MSGLIST_MAX; zeiger++)
		{
		if((zeiger->type) != EAP_CODE_REQ) continue;
		if((zeiger->id) != eapmd5->id) continue;
		if(memcmp(zeiger->ap, macto, 6) != 0) continue;
		if(memcmp(zeiger->client, macfm, 6) != 0) continue;
		addeapmd5hash(eapmd5->id, zeiger->md5, eapmd5->md5data); 
		}
	qsort(eapmd5msglist, EAPMD5MSGLIST_MAX +1, EAPMD5MSGLIST_SIZE, sort_eapmd5msglist_by_timestamp);
	}
return;
}
/*===========================================================================*/
static void hccap2base(unsigned char *in, unsigned char b)
{
static const char itoa64[64] = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fprintf(fh_pmkideapoljtrdeprecated, "%c", (itoa64[in[0] >> 2]));
fprintf(fh_pmkideapoljtrdeprecated, "%c", (itoa64[((in[0] & 0x03) << 4) | (in[1] >> 4)]));
if(b)
	{
	fprintf(fh_pmkideapoljtrdeprecated, "%c", (itoa64[((in[1] & 0x0f) << 2) | (in[2] >> 6)]));
	fprintf(fh_pmkideapoljtrdeprecated, "%c", (itoa64[in[2] & 0x3f]));
	}
else fprintf(fh_pmkideapoljtrdeprecated, "%c", (itoa64[((in[1] & 0x0f) << 2)]));
return;
}
/*===========================================================================*/
static bool testzeroedpmkid(uint8_t *macsta, uint8_t *macap, uint8_t *pmkid)
{
static char *pmkname = "PMK Name";

static uint8_t salt[32];
static uint8_t testpmkid[32];

memcpy(&salt, pmkname, 8);
memcpy(&salt[8], macap, 6);
memcpy(&salt[14], macsta, 6);
HMAC(EVP_sha1(), zeroed32, 32, salt, 20, testpmkid, NULL);
if(memcmp(&testpmkid, pmkid, 16) == 0) return true;
return false;
}
/*===========================================================================*/
int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
static CMAC_CTX *ctx;
static int ret = -1;
static size_t outlen, i;

ctx = CMAC_CTX_new();
if(ctx == NULL) return -1;
if(!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL)) goto fail;
for(i = 0; i < num_elem; i++)
	{
	if(!CMAC_Update(ctx, addr[i], len[i])) goto fail;
	}
if(!CMAC_Final(ctx, mac, &outlen) || outlen != 16) goto fail;
ret = 0;
fail:
CMAC_CTX_free(ctx);
return ret;
}
/*===========================================================================*/
int omac1_aes_128(const uint8_t *key, const uint8_t *data, size_t data_len, uint8_t *mac)
{
return omac1_aes_128_vector(key, 1, &data, &data_len, mac);
}
/*===========================================================================*/
static bool testeapolzeropmk(uint8_t keyver, uint8_t *macsta, uint8_t *macap, uint8_t *nonceap, uint8_t eapollen, uint8_t *eapolmessage)
{
static int p;
static uint8_t *pkeptr;
static wpakey_t *wpakzero, *wpak;

static uint8_t pkedata[102];
static uint8_t pkedata_prf[2 + 98 + 2];
static uint8_t ptk[128];
static uint8_t eapoldata[0xff];
static uint8_t miczero[16];

memcpy(&eapoldata, eapolmessage, eapollen);
wpakzero = (wpakey_t*)(eapoldata +EAPAUTH_SIZE);
memset(wpakzero->keymic, 0, 16);
wpak = (wpakey_t*)(eapolmessage +EAPAUTH_SIZE);
memset(&pkedata, 0, sizeof(pkedata));
memset(&pkedata_prf, 0, sizeof(pkedata_prf));
memset(&ptk, 0, sizeof(ptk));
pkeptr = pkedata;
if((keyver == 1) || (keyver == 2))
	{
	memcpy(pkeptr, "Pairwise key expansion", 23);
	if(memcmp(macap, macsta, 6) < 0)
		{
		memcpy(pkeptr +23, macap, 6);
		memcpy(pkeptr +29, macsta, 6);
		}
	else
		{
		memcpy(pkeptr +23, macsta, 6);
		memcpy(pkeptr +29, macap, 6);
		}

	if(memcmp(nonceap, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +35, nonceap, 32);
		memcpy (pkeptr +67, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +35, wpak->nonce, 32);
		memcpy (pkeptr +67, nonceap, 32);
		}

	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), zeroed32, 32, pkedata, 100, ptk + p *20, NULL);
		}
	if(keyver == 1)
		{
		HMAC(EVP_md5(), &ptk, 16, eapoldata, eapollen, miczero, NULL);
		if(memcmp(&miczero, wpak->keymic, 16) == 0) return true;
		}
	else if(keyver == 2)
		{
		HMAC(EVP_sha1(), ptk, 16, eapoldata, eapollen, miczero, NULL);
		if(memcmp(&miczero, wpak->keymic, 16) == 0) return true;
		}
	}
else if(keyver == 3)
	{
	memcpy(pkeptr, "Pairwise key expansion", 22);
	if(memcmp(macap, macsta, 6) < 0)
		{
		memcpy(pkeptr +22, macap, 6);
		memcpy(pkeptr +28, macsta, 6);
		}
	else
		{
		memcpy(pkeptr +22, macsta, 6);
		memcpy(pkeptr +28, macap, 6);
		}
	if(memcmp(nonceap, wpak->nonce, 32) < 0)
		{
		memcpy (pkeptr +34, nonceap, 32);
		memcpy (pkeptr +66, wpak->nonce, 32);
		}
	else
		{
		memcpy (pkeptr +34, wpak->nonce, 32);
		memcpy (pkeptr +66, nonceap, 32);
		}
	pkedata_prf[0] = 1;
	pkedata_prf[1] = 0;
	memcpy (pkedata_prf + 2, pkedata, 98);
	pkedata_prf[100] = 0x80;
	pkedata_prf[101] = 1;
	HMAC(EVP_sha256(), zeroed32, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, eapoldata, eapollen, miczero);
	if(memcmp(&miczero, wpak->keymic, 16) == 0) return true;
	}
return false;
}
/*===========================================================================*/
/*
static bool dopbkdf2(uint8_t psklen, char *psk, uint8_t essidlen, uint8_t *essid)
{
if(PKCS5_PBKDF2_HMAC_SHA1(psk, psklen, essid, essidlen, 4096, 32, pmk) == 0) return false;
return true;
}
*/
/*===========================================================================*/
static handshakelist_t *gethandshake(maclist_t *zeigermac, handshakelist_t *zeigerhsakt)
{
static int p;
static handshakelist_t *zeigerhs, *zeigerhsold;
static wpakey_t *wpak, *wpaktemp;
static int i;
static unsigned char *hcpos;
static uint8_t keyvertemp;
static uint8_t eapoltemp[EAPOL_AUTHLEN_MAX];
static hccapx_t hccapx;
static hccap_t hccap;

zeigerhsold = NULL;
for(zeigerhs = zeigerhsakt; zeigerhs < handshakelistptr; zeigerhs++)
	{
	if(donotcleanflag == false)
		{
		if(zeigerhsold != NULL)
			{
			if((memcmp(zeigerhs->ap, zeigerhsold->ap, 6) == 0) && (memcmp(zeigerhs->client, zeigerhsold->client, 6) == 0)) continue;
			}
		}
	if(memcmp(zeigermac->addr, zeigerhs->ap, 6) == 0)
		{
		eapolmpbestcount++;
		if((zeigerhs->status &ST_APLESS) == ST_APLESS) eapolaplesscount++;
		if((zeigerhs->status &7) == ST_M12E2) eapolm12e2count++; 
		if((zeigerhs->status &7) == ST_M14E4) eapolm14e4count++; 
		if((zeigerhs->status &7) == ST_M32E2) eapolm32e2count++; 
		if((zeigerhs->status &7) == ST_M32E3) eapolm32e3count++; 
		if((zeigerhs->status &7) == ST_M34E3) eapolm34e3count++; 
		if((zeigerhs->status &7) == ST_M34E4) eapolm34e4count++; 
		wpak = (wpakey_t*)(zeigerhs->eapol +EAPAUTH_SIZE);
		keyvertemp = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
		memcpy(&eapoltemp, zeigerhs->eapol, zeigerhs->eapauthlen);
		wpaktemp = (wpakey_t*)(eapoltemp +EAPAUTH_SIZE);
		memset(wpaktemp->keymic, 0, 16);
		if(fh_pmkideapol != 0)
			{
			//WPA*TYPE*PMKID-ODER-MIC*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP
			fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
				HCX_TYPE_EAPOL,
				wpak->keymic[0], wpak->keymic[1], wpak->keymic[2], wpak->keymic[3], wpak->keymic[4], wpak->keymic[5], wpak->keymic[6], wpak->keymic[7],
				wpak->keymic[8], wpak->keymic[9], wpak->keymic[10], wpak->keymic[11], wpak->keymic[12], wpak->keymic[13], wpak->keymic[14], wpak->keymic[15],
				zeigerhs->ap[0], zeigerhs->ap[1], zeigerhs->ap[2], zeigerhs->ap[3], zeigerhs->ap[4], zeigerhs->ap[5],
				zeigerhs->client[0], zeigerhs->client[1], zeigerhs->client[2], zeigerhs->client[3], zeigerhs->client[4], zeigerhs->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkideapol, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkideapol, "*");
			fprintf(fh_pmkideapol, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*",
				zeigerhs->anonce[0], zeigerhs->anonce[1], zeigerhs->anonce[2], zeigerhs->anonce[3], zeigerhs->anonce[4], zeigerhs->anonce[5], zeigerhs->anonce[6], zeigerhs->anonce[7],
				zeigerhs->anonce[8], zeigerhs->anonce[9], zeigerhs->anonce[10], zeigerhs->anonce[11], zeigerhs->anonce[12], zeigerhs->anonce[13], zeigerhs->anonce[14], zeigerhs->anonce[15],
				zeigerhs->anonce[16], zeigerhs->anonce[17], zeigerhs->anonce[18], zeigerhs->anonce[19], zeigerhs->anonce[20], zeigerhs->anonce[21], zeigerhs->anonce[22], zeigerhs->anonce[23],
				zeigerhs->anonce[24], zeigerhs->anonce[25], zeigerhs->anonce[26], zeigerhs->anonce[27], zeigerhs->anonce[28], zeigerhs->anonce[29], zeigerhs->anonce[30], zeigerhs->anonce[31]);
			for(p = 0; p < zeigerhs->eapauthlen; p++) fprintf(fh_pmkideapol, "%02x", eapoltemp[p]);
			fprintf(fh_pmkideapol, "*%02x\n", zeigerhs->status);
			if(zeigerhs->rcgap == 0) eapolwrittencount++;
			else  eapolncwrittencount++;
			}
		if((fh_pmkideapoljtrdeprecated != 0) && (zeigerhs->rcgap == 0))
			{
			memset (&hccap, 0, sizeof(hccap_t));
			memcpy(&hccap.ap, zeigerhs->ap, 6);
			memcpy(&hccap.client, zeigerhs->client, 6);
			memcpy(&hccap.anonce, zeigerhs->anonce, 32);
			memcpy(&hccap.snonce, wpak->nonce, 32);
			memcpy(&hccap.keymic, &wpak->keymic, 16);
			hccap.keyver = keyvertemp;
			hccap.eapol_size = zeigerhs->eapauthlen;
			memcpy(&hccap.eapol, &eapoltemp, zeigerhs->eapauthlen);
			#ifdef BIG_ENDIAN_HOST
			hccap.eapol_size = byte_swap_16(hccap.eapol_size);
			#endif
			fprintf(fh_pmkideapoljtrdeprecated, "%.*s:$WPAPSK$%.*s#", zeigermac->essidlen, zeigermac->essid, zeigermac->essidlen, zeigermac->essid);
			hcpos = (unsigned char*)&hccap;
			for (i = 36; i + 3 < (int)HCCAP_SIZE; i += 3) hccap2base(&hcpos[i], 1);
			hccap2base(&hcpos[i], 0);
			fprintf(fh_pmkideapoljtrdeprecated, ":%02x-%02x-%02x-%02x-%02x-%02x:%02x-%02x-%02x-%02x-%02x-%02x:%02x%02x%02x%02x%02x%02x",
				zeigerhs->client[0], zeigerhs->client[1], zeigerhs->client[2], zeigerhs->client[3], zeigerhs->client[4], zeigerhs->client[5],
				zeigerhs->ap[0], zeigerhs->ap[1], zeigerhs->ap[2], zeigerhs->ap[3], zeigerhs->ap[4], zeigerhs->ap[5],
				zeigerhs->ap[0], zeigerhs->ap[1], zeigerhs->ap[2], zeigerhs->ap[3], zeigerhs->ap[4], zeigerhs->ap[5]);
			if(keyvertemp == 1) fprintf(fh_pmkideapoljtrdeprecated, "::WPA");
			else fprintf(fh_pmkideapoljtrdeprecated, "::WPA2");
			if((zeigerhs->status &0x7) == 0) fprintf(fh_pmkideapoljtrdeprecated, ":not verified");
			else fprintf(fh_pmkideapoljtrdeprecated, ":verified");
			fprintf(fh_pmkideapoljtrdeprecated, ":%s\n", basename(jtrbasenamedeprecated));
			eapolwrittenjcountdeprecated++;
			}
		if(fh_hccapxdeprecated != 0)
			{
			memset (&hccapx, 0, sizeof(hccapx_t));
			hccapx.signature = HCCAPX_SIGNATURE;
			hccapx.version = HCCAPX_VERSION;
			hccapx.message_pair = zeigerhs->status;
			hccapx.essid_len = zeigermac->essidlen;
			memcpy(&hccapx.essid, zeigermac->essid, zeigermac->essidlen);
			memcpy(&hccapx.ap, zeigerhs->ap, 6);
			memcpy(&hccapx.client, zeigerhs->client, 6);
			memcpy(&hccapx.anonce, zeigerhs->anonce, 32);
			memcpy(&hccapx.snonce, wpak->nonce, 32);
			hccapx.eapol_len = zeigerhs->eapauthlen;
			memcpy(&hccapx.eapol, &eapoltemp, zeigerhs->eapauthlen);
			hccapx.keyver = keyvertemp;
			memcpy(&hccapx.keymic, wpak->keymic, 16);
			#ifdef BIG_ENDIAN_HOST
			hccapx.signature = byte_swap_32(hccapx.signature);
			hccapx.version = byte_swap_32(hccapx.version);
			hccapx.eapol_len = byte_swap_16(hccapx.eapol_len);
			#endif
			fwrite (&hccapx, sizeof(hccapx_t), 1, fh_hccapxdeprecated);
			if(zeigerhs->rcgap == 0) eapolwrittenhcpxcountdeprecated++;
			else eapolncwrittenhcpxcountdeprecated++;
			}
		if((fh_hccapdeprecated != 0) && (zeigerhs->rcgap == 0))
			{
			memset(&hccap, 0, sizeof(hccap_t));
			memcpy(&hccap.essid, zeigermac->essid, zeigermac->essidlen);
			memcpy(&hccap.ap, zeigerhs->ap, 6);
			memcpy(&hccap.client, zeigerhs->client, 6);
			memcpy(&hccap.anonce, zeigerhs->anonce, 32);
			memcpy(&hccap.snonce, wpak->nonce, 32);
			memcpy(&hccap.keymic, wpak->keymic, 16);
			hccap.keyver = keyvertemp;
			hccap.eapol_size = zeigerhs->eapauthlen;
			memcpy(&hccap.eapol, &eapoltemp, zeigerhs->eapauthlen);
			#ifdef BIG_ENDIAN_HOST
			hccap.eapol_size = byte_swap_16(hccap.eapol_size);
			#endif
			fwrite(&hccap, HCCAP_SIZE, 1, fh_hccapdeprecated);
			eapolwrittenhcpcountdeprecated++;
			}
		}
	if(memcmp(zeigerhs->ap, zeigermac->addr, 6) > 0)
		{
		zeigerhsakt = zeigerhs;
		return zeigerhsakt;
		}
	zeigerhsold = zeigerhs;
	}
return zeigerhsakt;
}
/*===========================================================================*/
static pmkidlist_t *getpmkid(maclist_t *zeigermac, pmkidlist_t *zeigerpmkidakt)
{
static int p;
static pmkidlist_t *zeigerpmkid, *zeigerpmkidold;

zeigerpmkidold = NULL;
for(zeigerpmkid = zeigerpmkidakt; zeigerpmkid < pmkidlistptr; zeigerpmkid++)
	{
	if(donotcleanflag == false)
		{
		if(zeigerpmkidold != NULL)
			{
			if((memcmp(zeigerpmkid->ap, zeigerpmkidold->ap, 6) == 0) && (memcmp(zeigerpmkid->client, zeigerpmkidold->client, 6) == 0)) continue;
			}
		}
	if(memcmp(zeigermac->addr, zeigerpmkid->ap, 6) == 0)
		{
		pmkidbestcount++;
		if(fh_pmkideapol != 0)
			{
			//WPA*TYPE*PMKID-ODER-MIC*MACAP*MACSTA*ESSID_HEX*ANONCE*EAPOL*MP
			fprintf(fh_pmkideapol, "WPA*%02d*%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
				HCX_TYPE_PMKID,
				zeigerpmkid->pmkid[0], zeigerpmkid->pmkid[1], zeigerpmkid->pmkid[2], zeigerpmkid->pmkid[3], zeigerpmkid->pmkid[4], zeigerpmkid->pmkid[5], zeigerpmkid->pmkid[6], zeigerpmkid->pmkid[7],
				zeigerpmkid->pmkid[8], zeigerpmkid->pmkid[9], zeigerpmkid->pmkid[10], zeigerpmkid->pmkid[11], zeigerpmkid->pmkid[12], zeigerpmkid->pmkid[13], zeigerpmkid->pmkid[14], zeigerpmkid->pmkid[15],
				zeigerpmkid->ap[0], zeigerpmkid->ap[1], zeigerpmkid->ap[2], zeigerpmkid->ap[3], zeigerpmkid->ap[4], zeigerpmkid->ap[5],
				zeigerpmkid->client[0], zeigerpmkid->client[1], zeigerpmkid->client[2], zeigerpmkid->client[3], zeigerpmkid->client[4], zeigerpmkid->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkideapol, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkideapol, "***\n");
			pmkidwrittenhcount++;
			}
		if(fh_pmkideapoljtrdeprecated != 0)
			{
			fprintf(fh_pmkideapoljtrdeprecated, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
				zeigerpmkid->pmkid[0], zeigerpmkid->pmkid[1], zeigerpmkid->pmkid[2], zeigerpmkid->pmkid[3], zeigerpmkid->pmkid[4], zeigerpmkid->pmkid[5], zeigerpmkid->pmkid[6], zeigerpmkid->pmkid[7],
				zeigerpmkid->pmkid[8], zeigerpmkid->pmkid[9], zeigerpmkid->pmkid[10], zeigerpmkid->pmkid[11], zeigerpmkid->pmkid[12], zeigerpmkid->pmkid[13], zeigerpmkid->pmkid[14], zeigerpmkid->pmkid[15],
				zeigerpmkid->ap[0], zeigerpmkid->ap[1], zeigerpmkid->ap[2], zeigerpmkid->ap[3], zeigerpmkid->ap[4], zeigerpmkid->ap[5],
				zeigerpmkid->client[0], zeigerpmkid->client[1], zeigerpmkid->client[2], zeigerpmkid->client[3], zeigerpmkid->client[4], zeigerpmkid->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkideapoljtrdeprecated, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkideapoljtrdeprecated, "\n");
			pmkidwrittenjcountdeprecated++;
			}
		if(fh_pmkiddeprecated != 0)
			{
			fprintf(fh_pmkiddeprecated, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*%02x%02x%02x%02x%02x%02x*",
				zeigerpmkid->pmkid[0], zeigerpmkid->pmkid[1], zeigerpmkid->pmkid[2], zeigerpmkid->pmkid[3], zeigerpmkid->pmkid[4], zeigerpmkid->pmkid[5], zeigerpmkid->pmkid[6], zeigerpmkid->pmkid[7],
				zeigerpmkid->pmkid[8], zeigerpmkid->pmkid[9], zeigerpmkid->pmkid[10], zeigerpmkid->pmkid[11], zeigerpmkid->pmkid[12], zeigerpmkid->pmkid[13], zeigerpmkid->pmkid[14], zeigerpmkid->pmkid[15],
				zeigerpmkid->ap[0], zeigerpmkid->ap[1], zeigerpmkid->ap[2], zeigerpmkid->ap[3], zeigerpmkid->ap[4], zeigerpmkid->ap[5],
				zeigerpmkid->client[0], zeigerpmkid->client[1], zeigerpmkid->client[2], zeigerpmkid->client[3], zeigerpmkid->client[4], zeigerpmkid->client[5]);
			for(p = 0; p < zeigermac->essidlen; p++) fprintf(fh_pmkiddeprecated, "%02x", zeigermac->essid[p]);
			fprintf(fh_pmkiddeprecated, "\n");
			pmkidwrittencountdeprecated++;
			}
		}
	if(memcmp(zeigerpmkid->ap, zeigermac->addr, 6) > 0)
		{
		zeigerpmkidakt = zeigerpmkid;
		return zeigerpmkidakt;
		}
	zeigerpmkidold = zeigerpmkid;
	}
return zeigerpmkidakt;
}
/*===========================================================================*/
static void outputwpalists()
{
static maclist_t *zeigermac, *zeigermacold;
static handshakelist_t *zeigerhsakt;
static pmkidlist_t *zeigerpmkidakt;
static int essiddupecount;

qsort(aplist, aplistptr -aplist, MACLIST_SIZE, sort_maclist_by_mac_count);
qsort(pmkidlist, pmkidlistptr -pmkidlist, PMKIDLIST_SIZE, sort_pmkidlist_by_mac);
qsort(handshakelist, handshakelistptr -handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_timegap);
zeigerhsakt = handshakelist;
zeigerpmkidakt = pmkidlist;
zeigermacold = aplist;
if(zeigermacold->type == AP)
	{
	if(ignoreieflag == true)
		{
		getpmkid(zeigermacold, zeigerpmkidakt);
		gethandshake(zeigermacold, zeigerhsakt);
		}
	else if(((zeigermacold->akm &TAK_PSK) == TAK_PSK) || ((zeigermacold->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
		{
		getpmkid(zeigermacold, zeigerpmkidakt);
		gethandshake(zeigermacold, zeigerhsakt);
		}
	}
essiddupecount = 0;
for(zeigermac = aplist +1; zeigermac < aplistptr; zeigermac++)
	{
	if(zeigermac->type != AP)
		{
		essiddupecount = 0;
		continue;
		}
	if(zeigermacold->type == AP)
		{
		if(memcmp(zeigermacold->addr, zeigermac->addr, 6) == 0)
			{
			essiddupecount++;
			if(essiddupecount > essiddupemax) essiddupemax = essiddupecount;
			if(essiddupecount > essidsvalue) continue;
			}
		else essiddupecount = 0;
		}
	if(ignoreieflag == true)
		{
		getpmkid(zeigermac, zeigerpmkidakt);
		gethandshake(zeigermac, zeigerhsakt);
		}
	else if(((zeigermac->akm &TAK_PSK) == TAK_PSK) || ((zeigermac->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
		{
		getpmkid(zeigermac, zeigerpmkidakt);
		gethandshake(zeigermac, zeigerhsakt);
		}
	zeigermacold = zeigermac;
	}
return;
}
/*===========================================================================*/
static void cleanupmac()
{
static maclist_t *zeiger;
static maclist_t *zeigerold;

if(aplistptr == aplist) return;
qsort(aplist, aplistptr -aplist, MACLIST_SIZE, sort_maclist_by_mac);
zeigerold = aplist;
for(zeiger = aplist +1; zeiger < aplistptr; zeiger++)
	{
	if(memcmp(zeigerold->addr, zeiger->addr, 6) == 0)
		{
		if(zeigerold->essidlen == zeiger->essidlen)
			{
			if(memcmp(zeigerold->essid, zeiger->essid, zeigerold->essidlen) == 0)
				{
				zeigerold->timestamp = zeiger->timestamp;
				zeigerold->type |= zeiger->type;
				zeigerold->status |= zeiger->status;
				zeigerold->count += 1;
				zeigerold->groupcipher |= zeiger->groupcipher;
				zeigerold->cipher |= zeiger->cipher;
				zeigerold->akm |= zeiger->akm;
				zeiger->type = REMOVED;
				continue;
				}
			}
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
static bool cleanbackhandshake()
{
static int c;
static handshakelist_t *zeiger;

if(donotcleanflag == true) return false;
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
static void addhandshake(uint64_t eaptimegap, uint64_t rcgap, messagelist_t *msgclient, messagelist_t *msgap, uint8_t keyver, uint8_t mpfield)
{
static handshakelist_t *handshakelistnew;

eapolmpcount++;
if(testeapolzeropmk(keyver, msgclient->client, msgap->ap, msgap->nonce, msgclient->eapauthlen, msgclient->eapol) == false)
	{
	if(handshakelistptr >= handshakelist +handshakelistmax)
		{
		handshakelistnew = realloc(handshakelist, (handshakelistmax +HANDSHAKELIST_MAX) *HANDSHAKELIST_SIZE);
		if(handshakelistnew == NULL)
			{
			printf("failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		handshakelist = handshakelistnew;
		handshakelistptr = handshakelistnew +handshakelistmax;
		handshakelistmax += HANDSHAKELIST_MAX;
		}
	memset(handshakelistptr, 0, HANDSHAKELIST_SIZE);
	handshakelistptr->timestampgap = eaptimegap;
	handshakelistptr->status = mpfield;
	handshakelistptr->rcgap = rcgap;
	if(handshakelistptr->rcgap > 0) handshakelistptr->status |= ST_NC;
	handshakelistptr->messageap = msgap->message;
	handshakelistptr->messageclient = msgclient->message;
	memcpy(handshakelistptr->ap, msgap->ap, 6);
	memcpy(handshakelistptr->client, msgclient->client, 6);
	memcpy(handshakelistptr->anonce, msgap->nonce, 32);
	memcpy(handshakelistptr->pmkid, msgap->pmkid, 32);
	handshakelistptr->eapauthlen = msgclient->eapauthlen;
	memcpy(handshakelistptr->eapol, msgclient->eapol, msgclient->eapauthlen);
	if(cleanbackhandshake() == false) handshakelistptr++;
	}
else
	{
	zeroedpmkcount++;
	if(donotcleanflag == true)
		{
		if(handshakelistptr >= handshakelist +handshakelistmax)
			{
			handshakelistnew = realloc(handshakelist, (handshakelistmax +HANDSHAKELIST_MAX) *HANDSHAKELIST_SIZE);
			if(handshakelistnew == NULL)
				{
				printf("failed to allocate memory for internal list\n");
				exit(EXIT_FAILURE);
				}
			handshakelist = handshakelistnew;
			handshakelistptr = handshakelistnew +handshakelistmax;
			handshakelistmax += HANDSHAKELIST_MAX;
			}
		memset(handshakelistptr, 0, HANDSHAKELIST_SIZE);
		handshakelistptr->timestampgap = eaptimegap;
		handshakelistptr->status = mpfield;
		handshakelistptr->rcgap = rcgap;
		if(handshakelistptr->rcgap > 0) handshakelistptr->status |= ST_NC;
		handshakelistptr->messageap = msgap->message;
		handshakelistptr->messageclient = msgclient->message;
		memcpy(handshakelistptr->ap, msgap->ap, 6);
		memcpy(handshakelistptr->client, msgclient->client, 6);
		memcpy(handshakelistptr->anonce, msgap->nonce, 32);
		memcpy(handshakelistptr->pmkid, msgap->pmkid, 32);
		handshakelistptr->eapauthlen = msgclient->eapauthlen;
		memcpy(handshakelistptr->eapol, msgclient->eapol, msgclient->eapauthlen);
		if(cleanbackhandshake() == false) handshakelistptr++;
		}
	}
return;
}
/*===========================================================================*/
static bool cleanbackpmkid()
{
static int c;
static pmkidlist_t *zeiger;

if(donotcleanflag == true) return false;
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
if(testzeroedpmkid(macclient, macap, pmkid) == false)
	{
	if(pmkidlistptr >= pmkidlist +pmkidlistmax)
		{
		pmkidlistnew = realloc(pmkidlist, (pmkidlistmax +PMKIDLIST_MAX) *PMKIDLIST_SIZE);
		if(pmkidlistnew == NULL)
			{
			printf("failed to allocate memory for internal list\n");
			exit(EXIT_FAILURE);
			}
		pmkidlist = pmkidlistnew;
		pmkidlistptr = pmkidlistnew +pmkidlistmax;
		pmkidlistmax += PMKIDLIST_MAX;
		}
	memset(pmkidlistptr, 0, PMKIDLIST_SIZE);
	memcpy(pmkidlistptr->ap, macap, 6);
	memcpy(pmkidlistptr->client, macclient, 6);
	memcpy(pmkidlistptr->pmkid, pmkid, 16);
	if(cleanbackpmkid() == false) pmkidlistptr++;
	}
else
	{
	zeroedpmkcount++;
	if(donotcleanflag == true)
		{
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
		}
	}
return;
}
/*===========================================================================*/
static void process80211exteap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t restlen, uint8_t *eapptr)
{
static eapauth_t *eapauth;
static uint32_t authlen;
static exteap_t *exteap;
static uint32_t exteaplen;
static uint32_t idstrlen;

eapcount++;
if(restlen < (int)EAPAUTH_SIZE) return; 
eapauth = (eapauth_t*)eapptr;
authlen = ntohs(eapauth->len);
if(authlen > restlen) return;
exteap = (exteap_t*)(eapptr +EAPAUTH_SIZE);
exteaplen = ntohs(exteap->len);
if(exteaplen > authlen) return;
idstrlen = exteaplen -EXTEAP_SIZE;
if(exteap->type == EAP_TYPE_SIM) eapsimcount++;
else if(exteap->type == EAP_TYPE_AKA) eapakacount++;
else if(exteap->type == EAP_TYPE_PEAP) eappeapcount++;
else if(exteap->type == EAP_TYPE_EXPAND) eapexpandedcount++;
else if(exteap->type == EAP_TYPE_MD5) processexteapmd5(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr +EAPAUTH_SIZE);
else if(exteap->type == EAP_TYPE_LEAP) processexteapleap(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr +EAPAUTH_SIZE);

if(exteap->code == EAP_CODE_REQ)
	{
	eapcodereqcount++;
	if(exteap->type == EAP_TYPE_ID)
		{
		if(idstrlen > 1)
			{
			if(eapptr[EAPAUTH_SIZE +EXTEAP_SIZE] != 0)
				{
				identitycount++;
				if(fh_identity != NULL) fwritestring(idstrlen, &eapptr[EAPAUTH_SIZE +EXTEAP_SIZE], fh_identity);
				}
			else if(eapptr[EAPAUTH_SIZE +EXTEAP_SIZE +1] != 0)
				{
				identitycount++;
				if(fh_identity != NULL) fwritestring(idstrlen -1, &eapptr[EAPAUTH_SIZE +EXTEAP_SIZE +1], fh_identity);
				}
			}
		eapidcount++;
		}
	}
else if(exteap->code == EAP_CODE_RESP)
	{
	eapcoderespcount++;
	if(exteap->type == EAP_TYPE_ID)
		{
		if(idstrlen > 1)
			{
			if(eapptr[EAPAUTH_SIZE +EXTEAP_SIZE] != 0)
				{
				identitycount++;
				if(fh_identity != NULL) fwritestring(idstrlen, &eapptr[EAPAUTH_SIZE +EXTEAP_SIZE], fh_identity);
				}
			else if(eapptr[EAPAUTH_SIZE +EXTEAP_SIZE +1] != 0)
				{
				identitycount++;
				if(fh_identity != NULL) fwritestring(idstrlen -1, &eapptr[EAPAUTH_SIZE +EXTEAP_SIZE +1], fh_identity);
				}
			}
		eapidcount++;
		}
	}
return;
}
/*===========================================================================*/
static inline void gettagwps(int wpslen, uint8_t *ieptr, tags_t *zeiger)
{
wpslen -= VENDORIE_SIZE;
ieptr += VENDORIE_SIZE;

if(wpslen == 0) return;
zeiger->wpsinfo = 1;
return;
}
/*===========================================================================*/
static inline void gettagwpa(int wpalen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static wpaie_t *wpaptr;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;

wpaptr = (wpaie_t*)ieptr;
wpalen -= WPAIE_SIZE;
ieptr += WPAIE_SIZE;
if(wpaptr->type != VT_WPA_IE) return;
zeiger->kdversion |= KV_WPAIE;
gsuiteptr = (suite_t*)ieptr; 
if(memcmp(gsuiteptr->oui, &mscorp, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) zeiger->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) zeiger->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) zeiger->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) zeiger->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) zeiger->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) zeiger->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) zeiger->groupcipher = TCS_NOT_ALLOWED;
	}
wpalen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < csuitecountptr->count; c++)
	{
	csuiteptr = (suite_t*)ieptr; 
	if(memcmp(csuiteptr->oui, &mscorp, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) zeiger->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) zeiger->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) zeiger->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) zeiger->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) zeiger->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) zeiger->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) zeiger->cipher |= TCS_NOT_ALLOWED;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < asuitecountptr->count; c++)
	{
	asuiteptr = (suite_t*)ieptr; 
	if(memcmp(asuiteptr->oui, &mscorp, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) zeiger->akm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) zeiger->akm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) zeiger->akm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) zeiger->akm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) zeiger->akm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) zeiger->akm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) zeiger->akm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) zeiger->akm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) zeiger->akm |= TAK_FT_SAE;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen <= 0) return;
	}
return;
}
/*===========================================================================*/
static inline void gettagvendor(int vendorlen, uint8_t *ieptr, tags_t *zeiger)
{
static wpaie_t *wpaptr;

wpaptr = (wpaie_t*)ieptr;
if(memcmp(wpaptr->oui, &mscorp, 3) != 0) return;
if((wpaptr->ouitype == VT_WPA_IE) && (vendorlen >= WPAIE_LEN_MIN)) gettagwpa(vendorlen, ieptr, zeiger);
if((wpaptr->ouitype == VT_WPS_IE) && (vendorlen >= (int)WPSIE_SIZE)) gettagwps(vendorlen, ieptr, zeiger);
return;
}
/*===========================================================================*/
static inline void gettagrsn(int rsnlen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static rsnie_t *rsnptr;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static rsnpmkidlist_t *rsnpmkidlistptr; 

rsnptr = (rsnie_t*)ieptr;
if(rsnptr->version != 1) return;
zeiger->kdversion |= KV_RSNIE;
rsnlen -= RSNIE_SIZE;
ieptr += RSNIE_SIZE;
gsuiteptr = (suite_t*)ieptr; 
if(memcmp(gsuiteptr->oui, &suiteoui, 3) == 0)
	{
	if(gsuiteptr->type == CS_WEP40) zeiger->groupcipher |= TCS_WEP40;
	if(gsuiteptr->type == CS_TKIP) zeiger->groupcipher |= TCS_TKIP;
	if(gsuiteptr->type == CS_WRAP) zeiger->groupcipher |= TCS_WRAP;
	if(gsuiteptr->type == CS_CCMP) zeiger->groupcipher |= TCS_CCMP;
	if(gsuiteptr->type == CS_WEP104) zeiger->groupcipher |= TCS_WEP104;
	if(gsuiteptr->type == CS_BIP) zeiger->groupcipher |= TCS_BIP;
	if(gsuiteptr->type == CS_NOT_ALLOWED) zeiger->groupcipher |= TCS_NOT_ALLOWED;
	}
rsnlen -= SUITE_SIZE;
ieptr += SUITE_SIZE;
csuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < csuitecountptr->count; c++)
	{
	csuiteptr = (suite_t*)ieptr; 
	if(memcmp(csuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(csuiteptr->type == CS_WEP40) zeiger->cipher |= TCS_WEP40;
		if(csuiteptr->type == CS_TKIP) zeiger->cipher |= TCS_TKIP;
		if(csuiteptr->type == CS_WRAP) zeiger->cipher |= TCS_WRAP;
		if(csuiteptr->type == CS_CCMP) zeiger->cipher |= TCS_CCMP;
		if(csuiteptr->type == CS_WEP104) zeiger->cipher |= TCS_WEP104;
		if(csuiteptr->type == CS_BIP) zeiger->cipher |= TCS_BIP;
		if(csuiteptr->type == CS_NOT_ALLOWED) zeiger->cipher |= TCS_NOT_ALLOWED;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
asuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
for(c = 0; c < asuitecountptr->count; c++)
	{
	asuiteptr = (suite_t*)ieptr; 
	if(memcmp(asuiteptr->oui, &suiteoui, 3) == 0)
		{
		if(asuiteptr->type == AK_PMKSA) zeiger->akm |= TAK_PMKSA;
		if(asuiteptr->type == AK_PSK) zeiger->akm |= TAK_PSK;
		if(asuiteptr->type == AK_FT) zeiger->akm |= TAK_FT;
		if(asuiteptr->type == AK_FT_PSK) zeiger->akm |= TAK_FT_PSK;
		if(asuiteptr->type == AK_PMKSA256) zeiger->akm |= TAK_PMKSA256;
		if(asuiteptr->type == AK_PSKSHA256) zeiger->akm |= TAK_PSKSHA256;
		if(asuiteptr->type == AK_TDLS) zeiger->akm |= TAK_TDLS;
		if(asuiteptr->type == AK_SAE_SHA256) zeiger->akm |= TAK_SAE_SHA256;
		if(asuiteptr->type == AK_FT_SAE) zeiger->akm |= TAK_FT_SAE;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen <= 0) return;
	}
rsnlen -= RSNCAPABILITIES_SIZE;
ieptr += RSNCAPABILITIES_SIZE;
if(rsnlen <= 0) return;
rsnpmkidlistptr = (rsnpmkidlist_t*)ieptr; 
if(rsnpmkidlistptr->count == 0) return;
rsnlen -= RSNPMKIDLIST_SIZE;
ieptr += RSNPMKIDLIST_SIZE;
if(rsnlen < 16) return;
if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256)) memcpy(zeiger->pmkid, ieptr, 16);
return;
}
/*===========================================================================*/
static void gettags(int infolen, uint8_t *infoptr, tags_t *zeiger)
{
static ietag_t *tagptr;

memset(zeiger, 0, TAGS_SIZE);
while(0 < infolen)
	{
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len == 0) return;
	if(tagptr->len > infolen) return;
	if(tagptr->id == TAG_SSID)
		{
		if((tagptr->len > 0) &&  (tagptr->len <= ESSID_LEN_MAX))
			{
			memcpy(zeiger->essid, &tagptr->data[0], tagptr->len);
			zeiger->essidlen = tagptr->len;
			}
		}
	else if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) zeiger->channel = tagptr->data[0];
		}
	else if(tagptr->id == TAG_RSN)
		{
		if(tagptr->len >= RSNIE_LEN_MIN) gettagrsn(tagptr->len, tagptr->data, zeiger);
		}
	else if(tagptr->id == TAG_VENDOR)
		{
		if(tagptr->len >= VENDORIE_SIZE) gettagvendor(tagptr->len, tagptr->data, zeiger);
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
return;
}
/*===========================================================================*/
static void process80211eapol_m4(uint64_t eaptimestamp, uint8_t *macap, uint8_t *macclient, uint32_t restlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static uint64_t eaptimegap;
static uint8_t keyver;
static uint64_t rc;
static uint64_t rcgap;
static uint8_t mpfield;

eapolm4count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen +EAPAUTH_SIZE > restlen) return;
if(authlen +EAPAUTH_SIZE > EAPOL_AUTHLEN_MAX) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((ignoreieflag == false) && (keyver == 0)) return;
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if(memcmp(&zeroed32, wpak->nonce, 32) == 0) return;
zeiger = messagelist +MESSAGELIST_MAX;
memset(zeiger, 0, MESSAGELIST_SIZE);
zeiger->timestamp = eaptimestamp;
zeiger->eapolmsgcount = eapolmsgcount;
memcpy(zeiger->client, macclient, 6);
memcpy(zeiger->ap, macap, 6);
zeiger->message = HS_M4;
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
zeiger->eapauthlen = authlen +EAPAUTH_SIZE;
memcpy(zeiger->eapol, eapauthptr, zeiger->eapauthlen);
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
	{
	if(zeiger->message == HS_M3)
		{
		if(zeiger->rc >= rc) rcgap = zeiger->rc -rc;
		else rcgap = rc -zeiger->rc;
		if(rcgap > rcgapmax) rcgapmax = rcgap;
		if(rcgap > ncvalue) continue;
		if(memcmp(zeiger->client, macclient, 6) != 0) continue;
		if(memcmp(zeiger->ap, macap, 6) != 0) continue;
		if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
		else eaptimegap = zeiger->timestamp -eaptimestamp;
		mpfield = ST_M34E4;
		if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
		if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
		}
	if((zeiger->message &HS_M1) != HS_M1) continue;
	if(zeiger->rc >= rc -1) rcgap = zeiger->rc -rc +1;
	else rcgap = rc -zeiger->rc +1;
	if(rcgap > ncvalue) continue;
	if(memcmp(zeiger->client, macclient, 6) != 0) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M14E4;
	if(myaktreplaycount > 0)
		{
		if(zeiger->rc == myaktreplaycount) continue;
		}
	if(rcgap > rcgapmax) rcgapmax = rcgap;
	if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m3(uint64_t eaptimestamp, uint8_t *macclient, uint8_t *macap, uint32_t restlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static messagelist_t *zeigerakt;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static uint64_t eaptimegap;
static uint8_t keyver;
static uint64_t rc;
static uint64_t rcgap;
static uint8_t mpfield;

eapolm3count++;
eapolmsgcount++;
zeigerakt = messagelist +MESSAGELIST_MAX;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > restlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((ignoreieflag == false) && (keyver == 0)) return;
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17)) return; 
memset(zeigerakt, 0, MESSAGELIST_SIZE);
zeigerakt->timestamp = eaptimestamp;
zeigerakt->eapolmsgcount = eapolmsgcount;
memcpy(zeigerakt->client, macclient, 6);
memcpy(zeigerakt->ap, macap, 6);
zeigerakt->message = HS_M3;
zeigerakt->rc = rc;
memcpy(zeigerakt->nonce, wpak->nonce, 32);
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
	{
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
	if(memcmp(zeiger->client, macclient, 6) != 0) continue;
	if((memcmp(zeiger->nonce, wpak->nonce, 28) == 0) && (memcmp(&zeiger->nonce[29], &wpak->nonce[29], 4) != 0))
		{
		zeiger->status |= ST_NC;
		zeigerakt->status |= ST_NC;
		}
	if((zeiger->message) != HS_M2) continue;
	if(zeiger->rc >= rc -1) rcgap = zeiger->rc -rc +1;
	else rcgap = rc -zeiger->rc +1;
	if(rcgap > ncvalue) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M32E2;
	if(myaktreplaycount > 0)
		{
		if(zeiger->rc == myaktreplaycount) continue;
		}
	if(rcgap > rcgapmax) rcgapmax = rcgap;
	if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, zeiger, messagelist +MESSAGELIST_MAX, keyver, mpfield);
	}
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX +1; zeiger++)
	{
	if(((zeiger->message &HS_M1) != HS_M1) && ((zeiger->message &HS_M3) != HS_M3)) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
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
static void process80211eapol_m2(uint64_t eaptimestamp, uint8_t *macap, uint8_t *macclient, uint32_t restlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static uint64_t eaptimegap;
static uint8_t keyver;
static uint64_t rc;
static uint64_t rcgap;
static uint8_t mpfield;
static int infolen;
static tags_t tags;

eapolm2count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen +EAPAUTH_SIZE > restlen) return;
if(authlen +EAPAUTH_SIZE > EAPOL_AUTHLEN_MAX) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((ignoreieflag == false) && (keyver == 0)) return;
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if(memcmp(&zeroed32, wpak->nonce, 32) == 0) return;
zeiger = messagelist +MESSAGELIST_MAX;
memset(zeiger, 0, MESSAGELIST_SIZE);
zeiger->timestamp = eaptimestamp;
zeiger->eapolmsgcount = eapolmsgcount;
memcpy(zeiger->client, macclient, 6);
memcpy(zeiger->ap, macap, 6);
zeiger->message = HS_M2;
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
zeiger->eapauthlen = authlen +EAPAUTH_SIZE;
memcpy(zeiger->eapol, eapauthptr, zeiger->eapauthlen);
infolen = ntohs(wpak->wpadatalen);
if(infolen >= RSNIE_LEN_MIN)
	{
	gettags(infolen, wpakptr +WPAKEY_SIZE, &tags);
	if(((tags.akm &TAK_PSK) != TAK_PSK) && ((tags.akm &TAK_PSKSHA256) != TAK_PSKSHA256))
		{
		if(ignoreieflag == false) return;
		}
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0)
		{
		zeiger->message |= HS_PMKID;
		memcpy(zeiger->pmkid, tags.pmkid, 16);
		addpmkid(macclient, macap, tags.pmkid);
		}
	}
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
	{
	if((zeiger->message &HS_M1) != HS_M1) continue;
	if(zeiger->rc >= rc) rcgap = zeiger->rc -rc;
	else rcgap = rc -zeiger->rc;
	if(rcgap > ncvalue) continue;
	if(memcmp(zeiger->client, macclient, 6) != 0) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
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
		if(rcgap != 0) continue;
		}
	if(rcgap > rcgapmax) rcgapmax = rcgap;
	if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m1(uint64_t eaptimestamp, uint8_t *macclient, uint8_t *macap, uint32_t restlen, uint8_t *eapauthptr)
{
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static pmkid_t *pmkid;
static uint8_t keyver;
static uint64_t rc;

eapolm1count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > restlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((ignoreieflag == false) && (keyver == 0)) return;
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17)) return; 
zeiger = messagelist +MESSAGELIST_MAX;
memset(zeiger, 0, MESSAGELIST_SIZE);
zeiger->timestamp = eaptimestamp;
zeiger->eapolmsgcount = eapolmsgcount;
memcpy(zeiger->client, macclient, 6);
memcpy(zeiger->ap, macap, 6);
zeiger->message = HS_M1;
zeiger->rc = rc;
memcpy(zeiger->nonce, wpak->nonce, 32);
if(authlen >= (int)(WPAKEY_SIZE +PMKID_SIZE))
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if((pmkid->len == 0x14) && (pmkid->type == 0x04))
		{
		zeiger->message |= HS_PMKID;
		if(memcmp(&zeroed32, pmkid->pmkid, 16) != 0)
			{
			memcpy(zeiger->pmkid, pmkid->pmkid, 16);
			addpmkid(macclient, macap, pmkid->pmkid);
			}
		}
	else pmkiduselesscount++;
	}
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX +1; zeiger++)
	{
	if(((zeiger->message &HS_M1) != HS_M1) && ((zeiger->message &HS_M3) != HS_M3)) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
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
static void process80211rc4key()
{

eapolrc4count++;

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
if(wpak->keydescriptor == EAP_KDT_RC4)
	{
	process80211rc4key();
	return;
	}
else if(wpak->keydescriptor == EAP_KDT_WPA) eapolwpacount++;
else if(wpak->keydescriptor == EAP_KDT_RSN) eapolrsncount++;
else return;
if(ntohs(wpak->keylen) > 256) return;
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
static void process80211eap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint32_t restlen, uint8_t *eapptr)
{
static eapauth_t *eapauth;

eapauth = (eapauth_t*)eapptr;
if(restlen < (int)EAPAUTH_SIZE) return; 
if(eapauth->type == EAPOL_KEY)
	{
	process80211eapol(eaptimestamp, macto, macfm, restlen, eapptr);
	}
else if(eapauth->type == EAP_PACKET) process80211exteap(eaptimestamp, macto, macfm, restlen, eapptr);
//else if(eapauth->type == EAPOL_ASF) process80211exteap_asf();
//else if(eapauth->type == EAPOL_MKA) process80211exteap_mka();
else if(eapauth->type == EAPOL_START)
	{
	}
else if(eapauth->type == EAPOL_START)
	{
	}
else if(eapauth->type == EAPOL_LOGOFF)
	{
	}
if(fh_nmea != NULL) writegpwpl(macfm);
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
	zeiger->groupcipher |= aplistptr->groupcipher;
	zeiger->cipher |= aplistptr->cipher;
	zeiger->akm |= aplistptr->akm;
	return true;
	}
return false;
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
gettags(clientinfolen, clientinfoptr, &tags);
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
if(fh_nmea != NULL) writegpwpl(macclient);
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
if(ignoreieflag == true)
	{
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
	}
else if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
	{
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
	}
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
if(fh_nmea != NULL) writegpwpl(macclient);
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
gettags(clientinfolen, clientinfoptr, &tags);
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
if(ignoreieflag == true)
	{
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
	}
else if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
	{
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
	}
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
if(fh_nmea != NULL) writegpwpl(macclient);
return;
}
/*===========================================================================*/
static inline void process80211authentication(uint8_t *macfm, uint32_t authenticationlen, uint8_t *authenticationptr)
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
if(fh_nmea != NULL) writegpwpl(macfm);
return;
}
/*===========================================================================*/
static void process80211probe_req_direct(uint64_t proberequesttimestamp, uint8_t *macclient, uint8_t *macap, uint32_t proberequestlen, uint8_t *proberequestptr)
{
static maclist_t *aplistnew;
static tags_t tags;

proberequestdirectedcount++;
if(proberequestlen < (int)IETAG_SIZE) return;
gettags(proberequestlen, proberequestptr, &tags);
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
gettags(proberequestlen, proberequestptr, &tags);
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
gettags(apinfolen, apinfoptr, &tags);
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
if(fh_nmea != NULL) writegpwpl(macap);
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
gettags(apinfolen, apinfoptr, &tags);
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
if(fh_nmea != NULL) writegpwpl(macap);
return;
}
/*===========================================================================*/
static void process80211packet(uint64_t packetimestamp, uint32_t packetlen, uint8_t *packetptr)
{
static mac_t *macfrx;
static uint32_t payloadlen;
static uint8_t *payloadptr;
static uint8_t *llcptr;
static llc_t *llc;
static uint8_t *mpduptr;
static mpdu_t *mpdu;

if(packetlen < (int)MAC_SIZE_NORM) return;
macfrx = (mac_t*)packetptr;
if((macfrx->from_ds == 1) && (macfrx->to_ds == 1))
	{
	payloadptr = packetptr +MAC_SIZE_LONG;
	payloadlen = packetlen -MAC_SIZE_LONG;
	wdscount++;
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
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH) process80211authentication(macfrx->addr2, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(&mac_broadcast, macfrx->addr1, 6) == 0) process80211probe_req(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
		else process80211probe_req_direct(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
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
		processipv4(packetimestamp, payloadlen -LLC_SIZE, payloadptr +LLC_SIZE);
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv6(packetimestamp, payloadlen -LLC_SIZE, payloadptr +LLC_SIZE);
		}
	else if(macfrx->prot ==1)
		{
		mpduptr = payloadptr;
		mpdu = (mpdu_t*)mpduptr;
		if(((mpdu->keyid >> 5) &1) == 1) wpaenccount++;
		else if(((mpdu->keyid >> 5) &1) == 0) wepenccount++;
		}
	}
return;
}
/*===========================================================================*/
void processethernetpacket(uint64_t timestamp, uint32_t caplen, uint8_t *packetptr)
{
static eth2_t *eth2;

if(caplen < (int)LLC_SIZE) return;
eth2 = (eth2_t*)packetptr;
if(ntohs(eth2->ether_type) == LLC_TYPE_IPV4)
	{
	processipv4(timestamp, caplen, packetptr);
	}
else if(ntohs(eth2->ether_type) == LLC_TYPE_IPV6)
	{
	processipv6(timestamp, caplen, packetptr);
	}
/*
if(ntohs(eth2->ether_type) == LLC_TYPE_AUTH)
	{
	process80211networkauthentication(tv_sec, tv_usec, caplen, eth2->addr1, eth2->addr2, packet_ptr);
	}
*/
return;
}
/*===========================================================================*/
static void processlinktype(uint64_t captimestamp, int linktype, uint32_t caplen, uint8_t *capptr)
{
static rth_t *rth;
static uint32_t packetlen;
static uint8_t *packetptr;
static ppi_t *ppi;
static prism_t *prism;
static avs_t *avs;
static fcs_t *fcs;
static uint32_t crc;

if(timestampmin == 0) timestampmin = captimestamp;
if(timestampmin > captimestamp) timestampmin = captimestamp;
if(timestampmax < captimestamp) timestampmax = captimestamp;
if(captimestamp == 0)
	{
	captimestamp = timestampstart;
	timestampstart += (eapoltimeoutvalue -2);
	zeroedtimestampcount++;
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
	#ifdef BIG_ENDIAN_HOST
	rth->it_len = byte_swap_16(rth->it_len);
	rth->it_present = byte_swap_32(rth->it_present);
	#endif
	if(rth->it_len > caplen)
		{
		pcapreaderrors++;
		printf("failed to read radiotap header\n");
		return;
		}
	packetlen = caplen -rth->it_len;
	packetptr = capptr +rth->it_len;
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
	ppi->pph_len = byte_swap_16(ppi->pph_len);
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
	prism->msgcode = byte_swap_32(prism->msgcode);
	prism->msglen = byte_swap_32(prism->msglen);
	prism->frmlen.data = byte_swap_32(prism->frmlen.data);
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
	avs->len = byte_swap_32(avs->len);
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
else if(linktype == DLT_EN10MB)
	{
	if(caplen < (uint32_t)ETH2_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read ethernet header\n");
		return;
		}
	packetlen = caplen -ETH2_SIZE;
	packetptr = capptr +ETH2_SIZE;
	processethernetpacket(captimestamp, packetlen, packetptr);
	return;
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
crc = byte_swap_32(crc);
#endif
if(endianess == 1) crc = byte_swap_32(crc);
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
	"file name..............................: %s\n"
	"version (pcap/cap).....................: %d.%d (very basic format without any additional information)\n"  
	, basename(pcaporgname), versionmajor, versionminor
	);

printlinklayerinfo();
cleanupmac();
outputwpalists();
outputeapmd5hashlist();
outputeapleaphashlist();
outputwordlists();
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
	else if(option->option_code == OPTIONCODE_NMEA)
		{
		if(option->option_length >= 66)
			{
			nmealen = option->option_length;
			memset(&nmeasentence, 0, NMEA_MAX);
			memcpy(&nmeasentence, &option->data, option->option_length);
			if(fh_nmea != NULL) fprintf(fh_nmea, "%s\n", nmeasentence);
			nmeacount++;
			}
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
static block_header_t *pcapngbh;
static section_header_block_t *pcapngshb;
static interface_description_block_t *pcapngidb;
static packet_block_t *pcapngpb;
static enhanced_packet_block_t *pcapngepb;
static custom_block_t *pcapngcb;

static uint8_t pcpngblock[2 *MAXPACPSNAPLEN];
static uint8_t packet[MAXPACPSNAPLEN];

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
		if(memcmp(pcapngcb->pen, &hcxmagic, 4) != 0)
			{
			skippedpacketcount++;
			continue;
			}
		if(memcmp(pcapngcb->hcxm, &hcxmagic, 32) != 0)
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
	"file name..............................: %s\n"
	"version (pcapng).......................: %d.%d\n"
	"operating system.......................: %s\n"
	"application............................: %s\n"
	"interface name.........................: %s\n"
	"interface vendor.......................: %02x%02x%02x\n"
	"weak candidate.........................: %s\n"
	"MAC ACCESS POINT.......................: %02x%02x%02x%02x%02x%02x (incremented on every new client)\n"
	"MAC CLIENT.............................: %02x%02x%02x%02x%02x%02x\n"
	"REPLAYCOUNT............................: %"  PRIu64  "\n"
	"ANONCE.................................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE.................................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
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

printlinklayerinfo();
cleanupmac();
outputwpalists();
outputwordlists();
outputeapmd5hashlist();
outputeapleaphashlist();
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
jtrbasenamedeprecated = pcapinname;
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
	"short options:\n"
	"-o <file> : output PMKID/EAPOL hash file\n"
	"            hashcat -m 22000/22001 and JtR wpapsk-opencl/wpapsk-pmk-opencl\n"
	"-E <file> : output wordlist (autohex enabled on non ASCII characters) to use as input wordlist for cracker\n"
	"-I <file> : output unsorted identity list to use as input wordlist for cracker\n"
	"-U <file> : output unsorted username list to use as input wordlist for cracker\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"long options:\n"
	"--all                              : convert all possible hashes instead of only the best one\n"
	"                                     that can lead to much overhead hashes\n"
	"                                     use hcxhashtool to filter hashes\n"
	"--eapoltimeout=<digit>             : set EAPOL TIMEOUT (milliseconds)\n"
	"                                   : default: %d ms\n"
	"--nonce-error-corrections=<digit>  : set nonce error correction\n"
	"                                     warning: values > 0 can lead to uncrackable handshakes\n"
	"                                   : default: %d\n"
	"--ignore-ie                        : do not use CIPHER and AKM information\n"
	"                                     this will convert all frames regadless of\n"
	"                                     CIPHER and/OR AKM information,\n"
	"                                     and can lead to uncrackable hashes\n"
	"--max-essids=<digit>               : maximum allowed ESSIDs\n"
	"                                     default: %d ESSID\n"
	"                                     disregard ESSID changes and take ESSID with highest ranking\n"
	"--eapmd5=<file>                    : output EAP MD5 CHALLENGE (hashcat -m 4800)\n"
	"--eapmd5-john=<file>               : output EAP MD5 CHALLENGE (john chap)\n"
	"--eapleap=<file>                   : output EAP LEAP CHALLENGE (hashcat -m 5500, john netntlm)\n"
	"--nmea=<file>                      : output GPS data in NMEA format\n"
	"                                     format: NMEA 0183 $GPGGA, $GPRMC, $GPWPL\n"
	"                                     to convert it to gpx, use GPSBabel:\n"
	"                                     gpsbabel -i nmea -f hcxdumptool.nmea -o gpx -F file.gpx\n"
	"                                     to display the track, open file.gpx with viking\n"
	"--pmkid=<file>                     : output deprecated PMKID file (delimter *)\n"
	"--hccapx=<file>                    : output deprecated hccapx v4 file\n"
	"--hccap=<file>                     : output deprecated hccap file (delimter *)\n"
	"--john=<file>                      : output deprecated PMKID/EAPOL (JtR wpapsk-opencl/wpapsk-pmk-opencl)\n"
	"--prefix=<file>                    : convert everything to lists using this prefix (overrides single options):\n"
	"                                      -o <file.22000>      : output PMKID/EAPOL hash file\n"
	"                                      -E <file.essid>      : output wordlist (autohex enabled on non ASCII characters) to use as input wordlist for cracker\n"
	"                                      -I <file.identitiy>  : output unsorted identity list to use as input wordlist for cracker\n"
	"                                      -U <file.username>   : output unsorted username list to use as input wordlist for cracker\n"
	"                                     --eapmd5=<file.4800>  : output EAP MD5 CHALLENGE (hashcat -m 4800)\n"
	"                                     --eapleap=<file.5500> : output EAP LEAP CHALLENGE (hashcat -m 5500, john netntlm)\n"
	"                                     --nmea=<file.nmea>    : output GPS data in NMEA format\n"
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
	"Do not edit, merge or convert pcapng files! This will remove optional comment fields!\n"
	"Do not use %s in combination with third party cap/pcap/pcapng cleaning tools (except: tshark and/or Wireshark)!\n"
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcapngtool will understand this.\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname, eigenname, eigenname, eigenname,
	EAPOLTIMEOUT /1000, NONCEERRORCORRECTION, ESSIDSMAX,
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
static char *pmkideapoloutname;
static char *eapmd5outname;
static char *eapmd5johnoutname;
static char *eapleapoutname;
static char *essidoutname;
static char *identityoutname;
static char *usernameoutname;
static char *nmeaoutname;
static char *pmkideapoljtroutnamedeprecated;
static char *pmkidoutnamedeprecated;
static char *hccapxoutnamedeprecated;
static char *hccapoutnamedeprecated;

static const char *prefixoutname;
static const char *pmkideapolsuffix = ".22000";
static const char *eapmd5suffix = ".4800";
static const char *eapleapsuffix = ".5500";
static const char *essidsuffix = ".essid";
static const char *identitysuffix = ".identity";
static const char *usernamesuffix = ".username";
static const char *nmeasuffix = ".nmea";

static char pmkideapolprefix[PATH_MAX];
static char eapmd5prefix[PATH_MAX];
static char eapleapprefix[PATH_MAX];
static char essidprefix[PATH_MAX];
static char identityprefix[PATH_MAX];
static char usernameprefix[PATH_MAX];
static char nmeaprefix[PATH_MAX];

struct timeval tv;
static struct stat statinfo;

static const char *short_options = "o:E:I:U:hv";
static const struct option long_options[] =
{
	{"all",				no_argument,		NULL,	HCX_CONVERT_ALL},
	{"eapoltimeout",		required_argument,	NULL,	HCX_EAPOL_TIMEOUT},
	{"nonce-error-corrections",	required_argument,	NULL,	HCX_NC},
	{"ignore-ie",			no_argument,		NULL,	HCX_IE},
	{"max-essids",			required_argument,	NULL,	HCX_ESSIDS},
	{"nmea",			required_argument,	NULL,	HCX_NMEA_OUT},
	{"pmkid",			required_argument,	NULL,	HCX_PMKID_OUT_DEPRECATED},
	{"eapmd5",			required_argument,	NULL,	HCX_EAPMD5_OUT},
	{"eapmd5-john",			required_argument,	NULL,	HCX_EAPMD5_JOHN_OUT},
	{"eapleap",			required_argument,	NULL,	HCX_EAPLEAP_OUT},
	{"hccapx",			required_argument,	NULL,	HCX_HCCAPX_OUT_DEPRECATED},
	{"hccap",			required_argument,	NULL,	HCX_HCCAP_OUT_DEPRECATED},
	{"john",			required_argument,	NULL,	HCX_PMKIDEAPOLJTR_OUT_DEPRECATED},
	{"prefix",			required_argument,	NULL,	HCX_PREFIX_OUT},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
ignoreieflag = false;
donotcleanflag = false;
eapoltimeoutvalue = EAPOLTIMEOUT;
ncvalue = NONCEERRORCORRECTION;
essidsvalue = ESSIDSMAX;

pmkideapoloutname = NULL;
eapmd5outname = NULL;
eapmd5johnoutname = NULL;
essidoutname = NULL;
identityoutname = NULL;
usernameoutname = NULL;
nmeaoutname = NULL;
prefixoutname = NULL;
pmkideapoljtroutnamedeprecated = NULL;
pmkidoutnamedeprecated = NULL;
hccapxoutnamedeprecated = NULL;
hccapoutnamedeprecated = NULL;

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
		eapoltimeoutvalue *= 1000;
		break;

		case HCX_NC:
		ncvalue = strtol(optarg, NULL, 10);
		break;

		case HCX_IE:
		ignoreieflag = true;
		break;

		case HCX_CONVERT_ALL:
		donotcleanflag = true;
		break;

		case HCX_ESSIDS:
		essidsvalue = strtol(optarg, NULL, 10);
		break;

		case HCX_PMKIDEAPOL_OUT:
		pmkideapoloutname = optarg;
		break;

		case HCX_EAPMD5_OUT:
		eapmd5outname = optarg;
		break;

		case HCX_EAPMD5_JOHN_OUT:
		eapmd5johnoutname = optarg;
		break;

		case HCX_EAPLEAP_OUT:
		eapleapoutname = optarg;
		break;

		case HCX_ESSID_OUT:
		essidoutname = optarg;
		break;

		case HCX_IDENTITY_OUT:
		identityoutname = optarg;
		break;

		case HCX_USERNAME_OUT:
		usernameoutname = optarg;
		break;

		case HCX_NMEA_OUT:
		nmeaoutname = optarg;
		break;

		case HCX_PMKIDEAPOLJTR_OUT_DEPRECATED:
		pmkideapoljtroutnamedeprecated = optarg;
		break;

		case HCX_PMKID_OUT_DEPRECATED:
		pmkidoutnamedeprecated = optarg;
		break;

		case HCX_HCCAPX_OUT_DEPRECATED:
		hccapxoutnamedeprecated = optarg;
		break;

		case HCX_HCCAP_OUT_DEPRECATED:
		hccapoutnamedeprecated = optarg;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_PREFIX_OUT:
		prefixoutname = optarg;
		if(strlen(prefixoutname) > PREFIX_BUFFER_MAX)
			{
			fprintf(stderr, "prefix must be < %d\n", PATH_MAX -12);
			exit(EXIT_FAILURE);
			}
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

if(prefixoutname != NULL)
	{
	strncpy(pmkideapolprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(pmkideapolprefix, pmkideapolsuffix, PREFIX_BUFFER_MAX);
	pmkideapoloutname = pmkideapolprefix;

	strncpy(essidprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(essidprefix, essidsuffix, PREFIX_BUFFER_MAX);
	essidoutname = essidprefix;

	strncpy(identityprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(identityprefix, identitysuffix, PREFIX_BUFFER_MAX);
	identityoutname = identityprefix;

	strncpy(usernameprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(usernameprefix, usernamesuffix, PREFIX_BUFFER_MAX);
	usernameoutname = usernameprefix;

	strncpy(eapmd5prefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(eapmd5prefix, eapmd5suffix, PREFIX_BUFFER_MAX);
	eapmd5outname = eapmd5prefix;

	strncpy(eapleapprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(eapleapprefix, eapleapsuffix, PREFIX_BUFFER_MAX);
	eapleapoutname = eapleapprefix;

	strncpy(nmeaprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(nmeaprefix, nmeasuffix, PREFIX_BUFFER_MAX);
	nmeaoutname = nmeaprefix;

	}

if(pmkideapoloutname != NULL)
	{
	if((fh_pmkideapol = fopen(pmkideapoloutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkideapoloutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(eapmd5outname != NULL)
	{
	if((fh_eapmd5 = fopen(eapmd5outname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", eapmd5outname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(eapmd5johnoutname != NULL)
	{
	if((fh_eapmd5john = fopen(eapmd5johnoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", eapmd5johnoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(eapleapoutname != NULL)
	{
	if((fh_eapleap = fopen(eapleapoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", eapleapoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(essidoutname != NULL)
	{
	if((fh_essid = fopen(essidoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", essidoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(identityoutname != NULL)
	{
	if((fh_identity = fopen(identityoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", identityoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(usernameoutname != NULL)
	{
	if((fh_username = fopen(usernameoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", usernameoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(nmeaoutname != NULL)
	{
	if((fh_nmea = fopen(nmeaoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", nmeaoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(pmkideapoljtroutnamedeprecated != NULL)
	{
	if((fh_pmkideapoljtrdeprecated = fopen(pmkideapoljtroutnamedeprecated, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkideapoljtroutnamedeprecated, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(pmkidoutnamedeprecated != NULL)
	{
	if((fh_pmkiddeprecated = fopen(pmkidoutnamedeprecated, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", pmkidoutnamedeprecated, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(hccapxoutnamedeprecated != NULL)
	{
	if((fh_hccapxdeprecated = fopen(hccapxoutnamedeprecated, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", hccapxoutnamedeprecated, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(hccapoutnamedeprecated != NULL)
	{
	if((fh_hccapdeprecated = fopen(hccapoutnamedeprecated, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", hccapoutnamedeprecated, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

for(index = optind; index < argc; index++)
	{
	processcapfile(argv[index]);
	}

if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
if(fh_eapmd5 != NULL) fclose(fh_eapmd5);
if(fh_eapmd5john != NULL) fclose(fh_eapmd5john);
if(fh_eapleap != NULL) fclose(fh_eapleap);
if(fh_essid != NULL) fclose(fh_essid);
if(fh_identity != NULL) fclose(fh_identity);
if(fh_username != NULL) fclose(fh_username);
if(fh_nmea != NULL) fclose(fh_nmea);
if(fh_pmkideapoljtrdeprecated != NULL) fclose(fh_pmkideapoljtrdeprecated);
if(fh_pmkiddeprecated != NULL) fclose(fh_pmkiddeprecated);
if(fh_hccapxdeprecated != NULL) fclose(fh_hccapxdeprecated);
if(fh_hccapdeprecated != NULL) fclose(fh_hccapdeprecated);

if(pmkideapoloutname != NULL)
	{
	if(stat(pmkideapoloutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapoloutname);
		}
	}
if(eapmd5outname != NULL)
	{
	if(stat(eapmd5outname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(eapmd5outname);
		}
	}
if(eapmd5johnoutname != NULL)
	{
	if(stat(eapmd5johnoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(eapmd5johnoutname);
		}
	}
if(eapleapoutname != NULL)
	{
	if(stat(eapleapoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(eapleapoutname);
		}
	}
if(essidoutname != NULL)
	{
	if(stat(essidoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(essidoutname);
		}
	}
if(identityoutname != NULL)
	{
	if(stat(identityoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(identityoutname);
		}
	}
if(usernameoutname != NULL)
	{
	if(stat(usernameoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(usernameoutname);
		}
	}
if(nmeaoutname != NULL)
	{
	if(stat(nmeaoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(nmeaoutname);
		}
	}

if(pmkideapoljtroutnamedeprecated != NULL)
	{
	if(stat(pmkideapoljtroutnamedeprecated, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkideapoljtroutnamedeprecated);
		}
	}
if(pmkidoutnamedeprecated != NULL)
	{
	if(stat(pmkidoutnamedeprecated, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(pmkidoutnamedeprecated);
		}
	}
if(hccapxoutnamedeprecated != NULL)
	{
	if(stat(hccapxoutnamedeprecated, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(hccapxoutnamedeprecated);
		}
	}
if(hccapoutnamedeprecated != NULL)
	{
	if(stat(hccapoutnamedeprecated, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(hccapoutnamedeprecated);
		}
	}
return EXIT_SUCCESS;
}
/*===========================================================================*/

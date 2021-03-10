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
#include <limits.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#if defined (__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#include <sys/socket.h>
#else
#include <stdio_ext.h>
#endif
#ifdef __linux__
#include <linux/limits.h>
#endif

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

#include "include/hcxpcapngtool.h"
#include "include/ieee80211.c"
#include "include/strings.c"
#include "include/byteops.c"
#include "include/fileops.c"
#include "include/hashops.c"
#include "include/pcap.c"
#include "include/gzops.c"
/*===========================================================================*/
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
static eapmschapv2hashlist_t *eapmschapv2hashlist, *eapmschapv2hashlistptr;
static eapmschapv2msglist_t *eapmschapv2msglist;
static tacacsplist_t *tacacsplist, *tacacsplistptr;

static char *jtrbasenamedeprecated;

static FILE *fh_pmkideapol;
static FILE *fh_eapmd5;
static FILE *fh_eapmd5john;
static FILE *fh_eapleap;
static FILE *fh_tacacsp;
static FILE *fh_essid;
static FILE *fh_essidproberequest;
static FILE *fh_identity;
static FILE *fh_username;
static FILE *fh_nmea;
static FILE *fh_csv;
static FILE *fh_raw_out;
static FILE *fh_log;
static FILE *fh_pmkideapoljtrdeprecated;
static FILE *fh_pmkiddeprecated;
static FILE *fh_hccapxdeprecated;
static FILE *fh_hccapdeprecated;

static int maclistmax;
static int handshakelistmax;
static int pmkidlistmax;
static int eapmd5hashlistmax;
static int eapleaphashlistmax;
static int eapmschapv2hashlistmax;
static int tacacsplistmax;
static int fd_pcap;

static int gzipstat;
static int pcapngstat;
static int capstat;
static int pcapngstat;

static int endianess;
static uint16_t versionmajor;
static uint16_t versionminor;

static int opensslversionmajor;
static int opensslversionminor;

static uint32_t iface;
static uint32_t dltlinktype[MAX_INTERFACE_ID +1];
static uint32_t timeresolval[MAX_INTERFACE_ID +1];

static long int radiotaperrorcount;

static long int nmeacount;
static long int nmeaerrorcount;
static long int rawpacketcount;
static long int pcapreaderrors;
static long int skippedpacketcount;
static long int zeroedtimestampcount;
static long int fcsframecount;
static long int wdscount;
static long int actioncount;
static long int awdlcount;
static long int beaconcount;
static long int beaconhcxcount;
static long int beaconerrorcount;
static long int pagcount;
static long int proberesponsecount;
static long int proberequestcount;
static long int proberequestdirectedcount;
static long int mgtreservedcount;
static long int deauthenticationcount;
static long int disassociationcount;
static long int authenticationcount;
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
static long int associationrequestpskcount;
static long int associationrequestpsk256count;
static long int associationrequestsae256count;
static long int associationrequestsae384bcount;
static long int associationrequestowecount;
static long int reassociationrequestcount;
static long int reassociationrequestpskcount;
static long int reassociationrequestpsk256count;
static long int reassociationrequestsae256count;
static long int reassociationrequestsae384bcount;
static long int reassociationrequestowecount;
static long int ipv4count;
static long int icmp4count;
static long int ipv6count;
static long int icmp6count;
static long int tcpcount;
static long int udpcount;
static long int grecount;
static long int protochapcount;
static long int protochapreqcount;
static long int protochaprespcount;
static long int protochapsuccesscount;
static long int protopapcount;
static long int tacacspcount;
static long int tacacspwrittencount;
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
static long int eapmschapv2count;
static long int eapmschapv2hashcount;
static long int eaptlscount;
static long int eapexpandedcount;
static long int eapidcount;
static long int eapcodereqcount;
static long int eapcoderespcount;
static long int zeroedpmkidpskcount;
static long int zeroedpmkidpmkcount;
static long int zeroedeapolpskcount;
static long int zeroedeapolpmkcount;
static long int zeroedeapolpskcount;
static long int pmkidcount;
static long int pmkidbestcount;
static long int pmkidroguecount;
static long int pmkiduselesscount;
static long int pmkidwrittenhcount;
static long int pmkidwrittenjcountdeprecated;
static long int pmkidwrittencountdeprecated;
static long int eapolrc4count;
static long int eapolrsncount;
static long int eapolwpacount;
static long int eapolmsgcount;
static long int eapolnccount;
static long int eapolmsgerrorcount;
static long int eapolmsgtimestamperrorcount;
static long int eapolmpcount;
static long int eapolmpbestcount;
static long int eapolm1count;
static long int eapolm1kdv0count;
static long int eapolm1ancount;
static long int eapolm1errorcount;
static long int eapolm2count;
static long int eapolm2kdv0count;
static long int eapolm2errorcount;
static long int eapolm3count;
static long int eapolm3kdv0count;
static long int eapolm3errorcount;
static long int eapolm4count;
static long int eapolm4kdv0count;
static long int eapolm4errorcount;
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
static long int eapmschapv2writtencount;
static long int identitycount;
static long int usernamecount;

static uint64_t rcgapmax;

static long int taglenerrorcount;
static long int essidcount;
static long int essiderrorcount;
static long int sequenceerrorcount;
static long int essiddupemax;

static long int malformedcount;

static uint64_t timestampstart;
static uint64_t timestampmin;
static uint64_t timestampmax;
static uint64_t eaptimegapmax;
static uint64_t captimestampold;

static uint64_t eapoltimeoutvalue;
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

static char rssi;
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
static uint8_t pcapngtimeresolution;
static char nmeasentence[OPTIONLEN_MAX];
static char gpwplold[OPTIONLEN_MAX];

static char zeroedpsk[8];
static uint8_t zeroedpmk[32];
static uint8_t calculatedpmk[32];
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
if(eapmschapv2msglist != NULL) free(eapmschapv2msglist);
if(eapmschapv2hashlist != NULL) free(eapmschapv2hashlist);
if(tacacsplist != NULL) free(tacacsplist);

EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();
return;
}
/*===========================================================================*/
static bool initlists()
{
static unsigned long opensslversion;
static const char nastring[] = { "N/A" };

ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
opensslversion = OpenSSL_version_num();
opensslversionmajor = (opensslversion & 0x10000000L) >> 28;
opensslversionminor = (opensslversion & 0x01100000L) >> 20;

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

if((eapmschapv2msglist = (eapmschapv2msglist_t*)calloc((EAPMSCHAPV2MSGLIST_MAX +1), EAPMSCHAPV2MSGLIST_SIZE)) == NULL) return false;

eapmschapv2hashlistmax = EAPMSCHAPV2HASHLIST_MAX;
if((eapmschapv2hashlist = (eapmschapv2hashlist_t*)calloc((eapmschapv2hashlistmax +1), EAPMSCHAPV2HASHLIST_SIZE)) == NULL) return false;
eapmschapv2hashlistptr = eapmschapv2hashlist;

tacacsplistmax = TACACSPLIST_MAX;
if((tacacsplist = (tacacsplist_t*)calloc((TACACSPLIST_MAX +1), TACACSPLIST_SIZE)) == NULL) return false;
tacacsplistptr = tacacsplist;

memset(&pcapnghwinfo, 0, OPTIONLEN_MAX);
memset(&pcapngosinfo, 0, OPTIONLEN_MAX);
memset(&pcapngapplinfo, 0, OPTIONLEN_MAX);
memset(&pcapngoptioninfo, 0, OPTIONLEN_MAX);
memset(&pcapngweakcandidate, 0 ,OPTIONLEN_MAX);
memset(&pcapngdeviceinfo, 0 ,6);
pcapngtimeresolution = TSRESOL_USEC;
memset(&myaktap, 0 ,6);
memset(&myaktclient, 0 ,6);
memset(&nmeasentence, 0, OPTIONLEN_MAX);
memset(&gpwplold, 0, OPTIONLEN_MAX);

memcpy(&pcapnghwinfo, nastring, 3);
memcpy(&pcapngosinfo, nastring, 3);
memcpy(&pcapngapplinfo, nastring, 3);
memcpy(&pcapngoptioninfo, nastring, 3);
memcpy(&pcapngweakcandidate, nastring, 3);

radiotaperrorcount = 0;
nmeacount = 0;
nmeaerrorcount = 0;
endianess = 0;
rawpacketcount = 0;
pcapreaderrors = 0;
skippedpacketcount = 0;
zeroedtimestampcount = 0;
fcsframecount = 0;
wdscount = 0;
actioncount = 0;
awdlcount = 0;
beaconcount = 0;
beaconhcxcount = 0;
beaconerrorcount = 0;
pagcount = 0;
proberesponsecount = 0;
proberequestcount = 0;
proberequestdirectedcount = 0;
mgtreservedcount = 0;
deauthenticationcount = 0;
disassociationcount = 0;
authenticationcount = 0;
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
associationrequestpskcount = 0;
associationrequestpsk256count = 0;
associationrequestsae256count = 0;
associationrequestsae384bcount = 0;
associationrequestowecount = 0;
reassociationrequestcount = 0;
reassociationrequestpskcount = 0;
reassociationrequestpsk256count = 0;
reassociationrequestsae256count = 0;
reassociationrequestsae384bcount = 0;
reassociationrequestowecount = 0;
ipv4count = 0;
icmp4count = 0;
ipv6count = 0;
icmp6count = 0;
tcpcount = 0;
udpcount = 0;
grecount = 0;
protochapcount = 0;
protochapreqcount = 0;
protochaprespcount = 0;
protochapsuccesscount = 0;
protopapcount = 0;
tacacspcount = 0;
tacacspwrittencount = 0;
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
eapmschapv2count = 0;
eapmschapv2hashcount = 0;
eaptlscount = 0;
eapexpandedcount = 0;
eapidcount = 0;
eapcodereqcount = 0;
eapcoderespcount = 0;
zeroedpmkidpskcount = 0;
zeroedpmkidpmkcount = 0;
zeroedeapolpskcount = 0;
zeroedeapolpmkcount = 0;
pmkidcount = 0;
pmkidbestcount = 0;
pmkidroguecount = 0;
pmkiduselesscount = 0;
pmkidwrittenhcount = 0;
eapolwrittenjcountdeprecated = 0;
pmkidwrittenjcountdeprecated = 0;
pmkidwrittencountdeprecated = 0;
eapolrc4count = 0;
eapolrsncount = 0;
eapolwpacount = 0;
eapolmsgcount = 0;
eapolnccount = 0;
eapolmsgerrorcount = 0;
eapolmsgtimestamperrorcount = 0;
eapolmpbestcount = 0;
eapolmpcount = 0;
eapolm1count = 0;
eapolm1kdv0count = 0;
eapolm1ancount = 0;
eapolm1errorcount = 0;
eapolm2count = 0;
eapolm2kdv0count = 0;
eapolm2errorcount = 0;
eapolm3count = 0;
eapolm3kdv0count = 0;
eapolm3errorcount = 0;
eapolm4count = 0;
eapolm4kdv0count = 0;
eapolm4errorcount = 0;
eapolwrittencount = 0;
eapolncwrittencount = 0;
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
eapmschapv2writtencount = 0;
identitycount = 0;
usernamecount = 0;
taglenerrorcount = 0;
essidcount = 0;
essiderrorcount = 0;
sequenceerrorcount = 0;
essiddupemax = 0;
rcgapmax = 0;
eaptimegapmax = 0;
malformedcount = 0;
timestampmin = 0;
timestampmax = 0;
timestampstart = 0;
captimestampold = 0;

memset(&zeroedpsk, 0, 8);
memset(&zeroedpmk, 0, 32);
return true;
}
/*===========================================================================*/
static void printcontentinfo()
{
if(nmeacount > 0)			printf("NMEA sentence............................: %ld\n", nmeacount);
if(nmeaerrorcount > 0)			printf("NMEA sentence checksum errors............: %ld\n", nmeaerrorcount);
if(endianess == 0)			printf("endianess (capture system)...............: little endian\n");
else					printf("endianess (capture system)...............: big endian\n");
if(rawpacketcount > 0)			printf("packets inside...........................: %ld\n", rawpacketcount);
if(skippedpacketcount > 0)		printf("skipped packets..........................: %ld\n", skippedpacketcount);
if(fcsframecount > 0)			printf("frames with correct FCS..................: %ld\n", fcsframecount);
if(wdscount > 0)			printf("WIRELESS DISTRIBUTION SYSTEM.............: %ld\n", wdscount);
if(beaconcount > 0)			printf("BEACON (total)...........................: %ld\n", beaconcount);
if(pagcount > 0)			printf("BEACON (pwnagotchi)......................: %ld\n", pagcount);
if(beaconhcxcount > 0)			printf("BEACON (hcxhash2cap).....................: %ld\n", beaconhcxcount);
if(actioncount > 0)			printf("ACTION (total)...........................: %ld\n", actioncount);
if(awdlcount > 0)			printf("AWDL (Apple Wireless Direct Link)........: %ld\n", awdlcount);
if(proberequestcount > 0)		printf("PROBEREQUEST.............................: %ld\n", proberequestcount);
if(proberequestdirectedcount > 0)	printf("PROBEREQUEST (directed)..................: %ld\n", proberequestdirectedcount);
if(proberesponsecount > 0)		printf("PROBERESPONSE............................: %ld\n", proberesponsecount);
if(deauthenticationcount > 0)		printf("DEAUTHENTICATION (total).................: %ld\n", deauthenticationcount);
if(disassociationcount > 0)		printf("DISASSOCIATION (total)...................: %ld\n", disassociationcount);
if(authenticationcount > 0)		printf("AUTHENTICATION (total)...................: %ld\n", authenticationcount);
if(authopensystemcount > 0)		printf("AUTHENTICATION (OPEN SYSTEM).............: %ld\n", authopensystemcount);
if(authseacount > 0)			printf("AUTHENTICATION (SAE).....................: %ld\n", authseacount);
if(authsharedkeycount > 0)		printf("AUTHENTICATION (SHARED KEY)..............: %ld\n", authsharedkeycount);
if(authfbtcount > 0)			printf("AUTHENTICATION (FBT).....................: %ld\n", authfbtcount);
if(authfilscount > 0)			printf("AUTHENTICATION (FILS)....................: %ld\n", authfilscount);
if(authfilspfs > 0)			printf("AUTHENTICATION (FILS PFS)................: %ld\n", authfilspfs);
if(authfilspkcount > 0)			printf("AUTHENTICATION (FILS PK..................: %ld\n", authfilspkcount);
if(authnetworkeapcount > 0)		printf("AUTHENTICATION (NETWORK EAP).............: %ld\n", authnetworkeapcount);
if(authunknowncount > 0)		printf("AUTHENTICATION (unknown).................: %ld\n", authunknowncount);
if(associationrequestcount > 0)		printf("ASSOCIATIONREQUEST (total)...............: %ld\n", associationrequestcount);
if(associationrequestpskcount > 0)	printf("ASSOCIATIONREQUEST (PSK).................: %ld\n", associationrequestpskcount);
if(associationrequestpsk256count > 0)	printf("ASSOCIATIONREQUEST (PSK SHA256)..........: %ld\n", associationrequestpsk256count);
if(associationrequestsae256count > 0)	printf("ASSOCIATIONREQUEST (SAE SHA256)..........: %ld\n", associationrequestsae256count);
if(associationrequestsae384bcount > 0)	printf("ASSOCIATIONREQUEST (SAE SHA384 SUITE B)..: %ld\n", associationrequestsae384bcount);
if(associationrequestowecount > 0)	printf("ASSOCIATIONREQUEST (OWE).................: %ld\n", associationrequestowecount);
if(reassociationrequestcount > 0)	printf("REASSOCIATIONREQUEST (total).............: %ld\n", reassociationrequestcount);
if(reassociationrequestpskcount > 0)	printf("REASSOCIATIONREQUEST (PSK)...............: %ld\n", reassociationrequestpskcount);
if(reassociationrequestpsk256count > 0)	printf("REASSOCIATIONREQUEST (PSK SHA256)........: %ld\n", reassociationrequestpsk256count);
if(reassociationrequestsae256count > 0)	printf("REASSOCIATIONREQUEST (SAE SHA256)........: %ld\n", reassociationrequestsae256count);
if(reassociationrequestsae384bcount > 0)printf("REASSOCIATIONREQUEST (SAE SHA384 SUITE B): %ld\n", reassociationrequestsae384bcount);
if(reassociationrequestowecount > 0)	printf("REASSOCIATIONREQUEST (OWE)...............: %ld\n", reassociationrequestowecount);
if(mgtreservedcount > 0)		printf("RESERVED MANAGEMENT frame................: %ld\n", mgtreservedcount);
if(wpaenccount > 0)			printf("WPA encrypted............................: %ld\n", wpaenccount);
if(wepenccount > 0)			printf("WEP encrypted............................: %ld\n", wepenccount);
if(ipv4count > 0)			printf("IPv4 (total).............................: %ld\n", ipv4count);
if(icmp4count > 0)			printf("ICMPv4...................................: %ld\n", icmp4count);
if(ipv6count > 0)			printf("IPv6 (total).............................: %ld\n", ipv6count);
if(icmp6count > 0)			printf("ICMPv6...................................: %ld\n", icmp6count);
if(tcpcount > 0)			printf("TCP (total)..............................: %ld\n", tcpcount);
if(udpcount > 0)			printf("UDP (total)..............................: %ld\n", udpcount);
if(grecount > 0)			printf("GRE (total)..............................: %ld\n", grecount);
if(protochapcount > 0)			printf("PPP-CHAP (total).........................: %ld\n", protochapcount);
if(protochapreqcount > 0)		printf("PPP-CHAP request.........................: %ld\n", protochapreqcount);
if(protochaprespcount > 0)		printf("PPP-CHAP response........................: %ld\n", protochaprespcount);
if(protochapsuccesscount > 0)		printf("PPP-CHAP success.........................: %ld\n", protochapsuccesscount);
if(protopapcount > 0)			printf("PPP-PAP..................................: %ld\n", protopapcount);
if(tacacspcount > 0)			printf("TACACS+..................................: %ld\n", tacacspcount);
if(tacacspwrittencount > 0)		printf("TACACS+ written..........................: %ld\n", tacacspwrittencount);
if(identitycount > 0)			printf("IDENTITIES...............................: %ld\n", identitycount);
if(usernamecount > 0)			printf("USERNAMES................................: %ld\n", usernamecount);
if(eapcount > 0)			printf("EAP (total)..............................: %ld\n", eapcount);
if(eapexpandedcount > 0)		printf("EAP-EXPANDED.............................: %ld\n", eapexpandedcount);
if(eapcodereqcount > 0)			printf("EAP CODE request.........................: %ld\n", eapcodereqcount);
if(eapcoderespcount > 0)		printf("EAP CODE response........................: %ld\n", eapcoderespcount);
if(eapidcount > 0)			printf("EAP ID...................................: %ld\n", eapidcount);
if(eapsimcount > 0)			printf("EAP-SIM..................................: %ld\n", eapsimcount);
if(eapakacount > 0)			printf("EAP-AKA..................................: %ld\n", eapakacount);
if(eappeapcount > 0)			printf("EAP-PEAP.................................: %ld\n", eappeapcount);
if(eapmd5count > 0)			printf("EAP-MD5 messages.........................: %ld\n", eapmd5count);
if(eapmd5hashcount > 0)			printf("EAP-MD5 pairs............................: %ld\n", eapmd5hashcount);
if(eapmd5writtencount > 0)		printf("EAP-MD5 pairs written....................: %ld\n", eapmd5writtencount);
if(eapmd5johnwrittencount > 0)		printf("EAP-MD5 pairs written to JtR.............: %ld\n", eapmd5johnwrittencount);
if(eapleapcount > 0)			printf("EAP-LEAP messages........................: %ld\n", eapleapcount);
if(eapleapwrittencount > 0)		printf("EAP-LEAP pairs written...................: %ld\n", eapleapwrittencount);
if(eapmschapv2count > 0)		printf("EAP-MSCHAPV2 messages....................: %ld\n", eapmschapv2count);
if(eapmschapv2writtencount > 0)		printf("EAP-MSCHAPV2 pairs written...............: %ld\n", eapmschapv2writtencount);
if(eaptlscount > 0)			printf("EAP-TLS messages.........................: %ld\n", eaptlscount);
if(eapolmsgcount > 0)			printf("EAPOL messages (total)...................: %ld\n", eapolmsgcount);
if(eapolrc4count > 0)			printf("EAPOL RC4 messages.......................: %ld\n", eapolrc4count);
if(eapolrsncount > 0)			printf("EAPOL RSN messages.......................: %ld\n", eapolrsncount);
if(eapolwpacount > 0)			printf("EAPOL WPA messages.......................: %ld\n", eapolwpacount);
if(essidcount > 0)			printf("ESSID (total unique).....................: %ld\n", essidcount);
if(essiddupemax > 0)
	{
	if((essidsvalue > 1) || (donotcleanflag == true)) printf("ESSID changes (detected maximum).........: %ld\n", essiddupemax);
	else printf("ESSID changes (detected maximum).........: %ld (information: option --max-essids=<digit> and --all recommended)\n", essiddupemax);
	}
if(eaptimegapmax > 0) printf("EAPOLTIME gap (measured maximum usec)....: %" PRId64 "\n", eaptimegapmax);
if((eapolnccount > 0) && (eapolmpcount > 0))
	{
	printf ("EAPOL ANONCE error corrections (NC)......: working\n");
	if(rcgapmax > 0) printf("REPLAYCOUNT gap (suggested NC)...........: %" PRIu64 "\n", rcgapmax);
	if(rcgapmax == 0) printf("REPLAYCOUNT gap (recommended NC).........: 8\n");
	}
if(eapolnccount == 0)
	{
	printf("EAPOL ANONCE error corrections (NC)......: not detected\n");
	if(rcgapmax > 0) printf("REPLAYCOUNT gap (measured maximum).......: %" PRIu64 "\n", rcgapmax);
	}
if(eapolm1count > 0)			printf("EAPOL M1 messages (total)................: %ld\n", eapolm1count);
if(eapolm1kdv0count > 0)		printf("EAPOL M1 messages (KDV:0 AKM defined)....: %ld\n", eapolm1kdv0count);
if(eapolm2count > 0)			printf("EAPOL M2 messages (total)................: %ld\n", eapolm2count);
if(eapolm2kdv0count > 0)		printf("EAPOL M2 messages (KDV:0 AKM defined)....: %ld\n", eapolm2kdv0count);
if(eapolm3count > 0)			printf("EAPOL M3 messages (total)................: %ld\n", eapolm3count);
if(eapolm3kdv0count > 0)		printf("EAPOL M3 messages (KDV:0 AKM defined)....: %ld\n", eapolm3kdv0count);
if(eapolm4count > 0)			printf("EAPOL M4 messages (total)................: %ld\n", eapolm4count);
if(eapolm4kdv0count > 0)		printf("EAPOL M4 messages (KDV:0 AKM defined)....: %ld\n", eapolm4kdv0count);
if(eapolmpcount > 0)			printf("EAPOL pairs (total)......................: %ld\n", eapolmpcount);
if(zeroedeapolpskcount > 0)		printf("EAPOL (from zeroed PSK)..................: %ld\n", zeroedeapolpskcount);
if(zeroedeapolpmkcount > 0)		printf("EAPOL (from zeroed PMK)..................: %ld\n", zeroedeapolpmkcount);
if(eapolmpbestcount > 0)		printf("EAPOL pairs (best).......................: %ld\n", eapolmpbestcount);
if(eapolaplesscount > 0)		printf("EAPOL ROGUE pairs........................: %ld\n", eapolaplesscount);
if(eapolwrittencount > 0)		printf("EAPOL pairs written to combi hash file...: %ld (RC checked)\n", eapolwrittencount);
if(eapolncwrittencount > 0)		printf("EAPOL pairs written to combi hash file...: %ld (RC not checked)\n", eapolncwrittencount);
if(eapolwrittenhcpxcountdeprecated > 0)	printf("EAPOL pairs written to old format hccapx.: %ld (RC checked)\n", eapolwrittenhcpxcountdeprecated);
if(eapolncwrittenhcpxcountdeprecated > 0)	printf("EAPOL pairs written to old format hccapx.: %ld (RC not checked)\n", eapolncwrittenhcpxcountdeprecated);
if(eapolwrittenhcpcountdeprecated > 0)	printf("EAPOL pairs written to old format hccap..: %ld (RC checked)\n", eapolwrittenhcpcountdeprecated);
if(eapolwrittenjcountdeprecated > 0)	printf("EAPOL pairs written to old format JtR....: %ld (RC checked)\n", eapolwrittenjcountdeprecated);
if(eapolm12e2count > 0)			printf("EAPOL M12E2 (challenge)..................: %ld\n", eapolm12e2count);
if(eapolm14e4count > 0)			printf("EAPOL M14E4 (authorized).................: %ld\n", eapolm14e4count);
if(eapolm32e2count > 0)			printf("EAPOL M32E2 (authorized).................: %ld\n", eapolm32e2count);
if(eapolm32e3count > 0)			printf("EAPOL M32E3 (authorized).................: %ld\n", eapolm32e3count);
if(eapolm34e3count > 0)			printf("EAPOL M34E3 (authorized).................: %ld\n", eapolm34e3count);
if(eapolm34e4count > 0)			printf("EAPOL M34E4 (authorized).................: %ld\n", eapolm34e4count);
if(pmkiduselesscount > 0)		printf("PMKID (useless)..........................: %ld\n", pmkiduselesscount);
if(pmkidcount > 0)			printf("PMKID (total)............................: %ld\n", pmkidcount);
if(zeroedpmkidpskcount > 0)		printf("PMKID (from zeroed PSK)..................: %ld\n", zeroedpmkidpskcount);
if(zeroedpmkidpmkcount > 0)		printf("PMKID (from zeroed PMK)..................: %ld\n", zeroedpmkidpmkcount);
if(pmkidbestcount > 0)			printf("PMKID (best).............................: %ld\n", pmkidbestcount);
if(pmkidroguecount > 0)			printf("PMKID ROGUE..............................: %ld\n", pmkidroguecount);
if(pmkidwrittenhcount > 0)		printf("PMKID written to combi hash file.........: %ld\n", pmkidwrittenhcount);
if(pmkidwrittenjcountdeprecated > 0)	printf("PMKID written to old format JtR..........: %ld\n", pmkidwrittenjcountdeprecated);
if(pmkidwrittencountdeprecated > 0)	printf("PMKID written to old format (1680x)......: %ld\n", pmkidwrittencountdeprecated);
if(pcapreaderrors > 0)			printf("packet read error........................: %ld\n", pcapreaderrors);
if(radiotaperrorcount > 0)		printf("packet with damaged radiotap header......: %ld\n", radiotaperrorcount);
if(zeroedtimestampcount > 0)		printf("packets with zeroed timestamps...........: %ld\n", zeroedtimestampcount);
if(eapolmsgtimestamperrorcount > 0)	printf("EAPOL frames with wrong timestamp........: %ld\n", eapolmsgtimestamperrorcount);
malformedcount = beaconerrorcount +taglenerrorcount +essiderrorcount +eapolmsgerrorcount;
if(malformedcount > 0)			printf("malformed packets (total)................: %ld\n", malformedcount);
if(beaconerrorcount > 0)		printf("BROADCAST MAC error (malformed packets)..: %ld\n", beaconerrorcount);
if(taglenerrorcount > 0)		printf("IE TAG length error (malformed packets)..: %ld\n", taglenerrorcount);
if(essiderrorcount > 0)			printf("ESSID error (malformed packets)..........: %ld\n", essiderrorcount);
eapolmsgerrorcount = eapolmsgerrorcount +eapolm1errorcount +eapolm2errorcount +eapolm3errorcount +eapolm4errorcount;
if(eapolmsgerrorcount > 0)		printf("EAPOL messages (malformed packets).......: %ld\n", eapolmsgerrorcount);

if((eapolwrittencount +eapolncwrittencount +eapolwrittenhcpxcountdeprecated +eapolncwrittenhcpxcountdeprecated +eapolwrittenhcpcountdeprecated 
	+eapolwrittenjcountdeprecated +pmkidwrittenhcount +pmkidwrittenjcountdeprecated +pmkidwrittencountdeprecated
	+eapmd5writtencount +eapmd5johnwrittencount +eapleapwrittencount +eapmschapv2writtencount +tacacspwrittencount) == 0)
	{
	printf( "\nInformation: no hashes written to hash files\n");
	}
if(sequenceerrorcount > 0)
	{
	printf("\nWarning: out of sequence timestamps!\n"
		"This dump file contains frames with out of sequence timestamps.\n"
		"That is a bug of the capturing tool.\n");
	}
if(zeroedtimestampcount > 0)
	{
	printf("\nWarning: missing timestamps!\n"
		"This dump file contains frames with zeroed timestamps.\n"
		"It prevent calculation of EAPOL TIMEOUT values.\n"
		"That is a bug of the capturing/cleaning tool.\n");
	}
if(eapolmsgtimestamperrorcount > 0)
	{
	printf("\nWarning: wrong timestamps!\n"
		"This dump file contains frames with wrong timestamps.\n"
		"It prevent calculation of EAPOL TIMEOUT values.\n"
		"That is a bug of the capturing tool.\n");
	}
if((deauthenticationcount +disassociationcount) > 100)
	{
	printf("\nWarning: too many deauthentication/disassociation frames detected!\n"
		"That can cause that an ACCESS POINT change channel, reset EAPOL TIMER,\n"
		"renew ANONCE and set PMKID to zero.\n"
		"This could prevent to calculate a valid EAPOL MESSAGE PAIR\n"
		"or to get a valid PMKID.\n");
	}
if(proberequestcount == 0)
	{
	printf("\nWarning: missing frames!\n"
		"This dump file does not contain undirected proberequest frames.\n"
		"An undirected proberequest may contain information about the PSK.\n"
		"It always happens if the capture file was cleaned or\n"
		"it could happen if filter options are used during capturing.\n"
		"That makes it hard to recover the PSK.\n");
	}
if((authenticationcount +associationrequestcount +reassociationrequestcount) == 0)
	{
	printf("\nWarning: missing frames!\n"
		"This dump file does not contain important frames like\n"
		"authentication, association or reassociation.\n"
		"It always happens if the capture file was cleaned or\n"
		"it could happen if filter options are used during capturing.\n"
		"That makes it hard to recover the PSK.\n");
	}
if(eapolm1ancount <= 1)
	{
	printf("\nWarning: missing frames!\n"
		"This dump file does not contain enough EAPOL M1 frames.\n"
		"It always happens if the capture file was cleaned or\n"
		"it could happen if filter options are used during capturing.\n"
		"That makes it impossible to calculate nonce-error-correction values.\n");
	}
if(malformedcount > 5)
	{
	printf( "\nWarning: malformed packets detected!\n"   
		"In monitor mode the adapter does not check to see if the cyclic redundancy check (CRC)\n"
		"values are correct for packets captured. The device is able to detect the Physical Layer\n"
		"Convergence Procedure (PLCP) preamble and is able to synchronize to it, but if there is\n"
		"a bit error in the payload it can lead to unexpected results.\n"
		"Please analyze the dump file with tshark or Wireshark.\n");
	}
printf("\n");
return;
}
/*===========================================================================*/
static void printlinklayerinfo()
{
static uint32_t c;
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
printf("timestamp minimum (GMT)..................: %s\n", timestringmin);
printf("timestamp maximum (GMT)..................: %s\n", timestringmax);
printf("used capture interfaces..................: %d\n", iface);
for(c = 0; c < iface; c++)
	{
	if(c > 0)
		{
		if(dltlinktype[c] == dltlinktype[c -1]) continue;
		}
	if(dltlinktype[c] == DLT_IEEE802_11_RADIO)	printf("link layer header type...................: DLT_IEEE802_11_RADIO (%d)\n", dltlinktype[c]);
	if(dltlinktype[c] == DLT_IEEE802_11)		printf("link layer header type...................: DLT_IEEE802_11 (%d)\n", dltlinktype[c]);
	if(dltlinktype[c] == DLT_PPI)			printf("link layer header type...................: DLT_PPI (%d)\n", dltlinktype[c]);
	if(dltlinktype[c] == DLT_PRISM_HEADER)		printf("link layer header type...................: DLT_PRISM_HEADER (%d)\n", dltlinktype[c]);
	if(dltlinktype[c] == DLT_IEEE802_11_RADIO_AVS)	printf("link layer header type...................: DLT_IEEE802_11_RADIO_AVS (%d)\n", dltlinktype[c]);
	if(dltlinktype[c] == DLT_EN10MB)		printf("link layer header type...................: DLT_EN10MB (%d)\n", dltlinktype[c]);
	if(dltlinktype[c] == DLT_NULL)			printf("link layer header type...................: DLT_NULL (BSD LO) (%d)\n", dltlinktype[c]);
	}
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
	if(fh_essid != NULL) fwriteessidstr(zeigermac->essidlen, zeigermac->essid, fh_essid);
	if((fh_essidproberequest != NULL) && (zeigermac->status == ST_PROBE_REQ)) fwriteessidstr(zeigermac->essidlen, zeigermac->essid, fh_essidproberequest);
	essidcount++;
	zeigermacold = zeigermac;
	}
return;
}
/*===========================================================================*/
static void writecsv(uint64_t timestamp, uint8_t *mac, tags_t *tags)
{
static int c;
static int p;
static struct timeval tvo;
static float latitude;
static char ew;
static float longitude;
static char ns;
static const char gpgga[] = "$GPGGA";
static const char gprmc[] = "$GPRMC";

static char timestring[24];

if(tags->essidlen == 0) return;
if(tags->essid[0] == 0) return;
tvo.tv_sec = timestamp /1000000;
tvo.tv_usec = 0;
strftime(timestring, 24, "%Y-%m-%d\t%H:%M:%S", gmtime(&tvo.tv_sec));
fprintf(fh_csv, "%s\t%02x:%02x:%02x:%02x:%02x:%02x\t%.*s", timestring, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], tags->essidlen, tags->essid);
fprintf(fh_csv, "\t");
if(tags->kdversion == 0) fprintf(fh_csv, "OPEN");
if((tags->kdversion & KV_WPAIE) == KV_WPAIE) fprintf(fh_csv, "[WPA1]");
if((tags->kdversion & KV_RSNIE) == KV_RSNIE) fprintf(fh_csv, "[WPA2]");
fprintf(fh_csv, "\t");
if((tags->cipher & TCS_TKIP) == TCS_TKIP) fprintf(fh_csv, "[TKIP]");
if((tags->cipher & TCS_CCMP) == TCS_CCMP) fprintf(fh_csv, "[CCMP]");
if((tags->cipher & TCS_WEP40) == TCS_WEP40) fprintf(fh_csv, "[WEP40]");
if((tags->cipher & TCS_WEP104) == TCS_WEP104) fprintf(fh_csv, "[WEP104]");
if((tags->cipher & TCS_WRAP) == TCS_WRAP) fprintf(fh_csv, "[WRAP]");
if((tags->cipher & TCS_BIP) == TCS_BIP) fprintf(fh_csv, "[BIP]");
if((tags->cipher & TCS_NOT_ALLOWED) == TCS_NOT_ALLOWED) fprintf(fh_csv, "[NOT_ALLOWED]");
fprintf(fh_csv, "\t");
if((tags->akm & TAK_PSK) == TAK_PSK) fprintf(fh_csv, "[PSK]");
if((tags->akm & TAK_PSKSHA256) == TAK_PSKSHA256) fprintf(fh_csv, "[PSK_SHA256]");
if((tags->akm & TAK_PMKSA) == TAK_PMKSA) fprintf(fh_csv, "[PMKSA]");
if((tags->akm & TAK_PMKSA256) == TAK_PMKSA256) fprintf(fh_csv, "[PMKSA_SHA256]");
if((tags->akm & TAK_FT) == TAK_FT) fprintf(fh_csv, "[FT]");
if((tags->akm & TAK_FT_PSK) == TAK_FT_PSK) fprintf(fh_csv, "[FT_PSK]");
if((tags->akm & TAK_FT_SAE) == TAK_FT_SAE) fprintf(fh_csv, "[FT_SAE]");
if((tags->akm & TAK_TDLS) == TAK_TDLS) fprintf(fh_csv, "[TDLS]");
if((tags->akm & TAK_SAE_SHA256) == TAK_SAE_SHA256) fprintf(fh_csv, "[SAE_SHA256]");
if((tags->akm & TAK_SAE_SHA256B) == TAK_SAE_SHA256B) fprintf(fh_csv, "[SAE_SHA256B]");
if((tags->akm & TAK_SAE_SHA384B) == TAK_SAE_SHA384B) fprintf(fh_csv, "[SAE_SHA384B]");
if((tags->akm & TAK_AP_PKA) == TAK_AP_PKA) fprintf(fh_csv, "[AP_PKA]");
if((tags->akm & TAK_OWE) == TAK_OWE) fprintf(fh_csv, "[OWE]");
fprintf(fh_csv, "\t");
if((tags->country[0] >= 'A') && (tags->country[0] <= 'Z') && (tags->country[1] >= 'A') && (tags->country[1] <= 'Z')) fprintf(fh_csv,"%c%c", tags->country[0], tags->country[1]);
fprintf(fh_csv, "\t");
if(tags->channel != 0) fprintf(fh_csv,"%d", tags->channel);
fprintf(fh_csv, "\t");
if(rssi != 0) fprintf(fh_csv, "%d", rssi);
if(nmealen < 48)
	{
	fprintf(fh_csv, "\n");
	return;
	}
p = 7;
c = 0;
latitude = 0;
longitude = 0;
ew = 0;
ns = 0;
if(memcmp(&gprmc, nmeasentence, 6) == 0)
	{
	while((nmeasentence[p] != 0) && (c < 2))
		{
		if(nmeasentence[p] == ',') c++;
		p++;
		}
	sscanf(&nmeasentence[p],"%f,%c,%f,%c", &latitude, &ew, &longitude, &ns);
	if((latitude == 0) || (longitude == 0) || (ew == 0) || (ns == 0))
		{
		fprintf(fh_csv, "\n");
		return;
		}
	fprintf(fh_csv, "\t%f\t%c\t%f\t%c\n", latitude, ew, longitude, ns);
	return;
	}
if(memcmp(&gpgga, nmeasentence, 6) == 0)
	{
	while((nmeasentence[p] != 0) && (c < 1))
		{
		if(nmeasentence[p] == ',') c++;
		p++;
		}
	sscanf(&nmeasentence[p],"%f,%c,%f,%c", &latitude, &ew, &longitude, &ns);
	if((latitude == 0) || (longitude == 0) || (ew == 0) || (ns == 0))
		{
		fprintf(fh_csv, "\n");
		return;
		}
	fprintf(fh_csv, "\t%f\t%c\t%f\t%c\n", latitude, ew, longitude, ns);
	return;
	}
return;
}
/*===========================================================================*/
static void writegpwpl(uint8_t *mac)
{
static int c;
static int cs;
static int cc, ca, ce;
static int gpwpllen;
static char *gpwplptr;
static const char gpgga[] = "$GPGGA";
static const char gprmc[] = "$GPRMC";
static char gpwpl[NMEA_MAX];

if(nmealen < 48) return;
gpwpl[0] = 0;
c = 0;
cc = 0;
ca = 0;
ce = 0;
if(memcmp(&gprmc, nmeasentence, 6) == 0)
	{
	while(nmeasentence[c] != 0)
		{
		if(nmeasentence[c] == ',')
			{
			cc++;
			if(cc == 3) ca = c +1;
			if(cc == 7)
				{
				ce = c;
				break;
				}
			}
		c++;
		}
	if(ce > ca) snprintf(gpwpl, NMEA_MAX-1, "$GPWPL,%.*s,%02x%02x%02x%02x%02x%02x*", ce-ca, &nmeasentence[ca], mac[0] , mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
else if(memcmp(&gpgga, nmeasentence, 6) == 0)
	{
	while(nmeasentence[c] != 0)
		{
		if(nmeasentence[c] == ',')
			{
			cc++;
			if(cc == 2) ca = c +1;
			if(cc == 6)
				{
				ce = c;
				break;
				}
			}
		c++;
		}
	if(ce > ca) snprintf(gpwpl, NMEA_MAX-1, "$GPWPL,%.*s,%02x%02x%02x%02x%02x%02x*", ce-ca, &nmeasentence[ca], mac[0] , mac[1], mac[2], mac[3], mac[4], mac[5]);
	}
else return;
if(gpwpl[0] == 0) return;
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
static void outputtacacsplist()
{
static uint32_t c;
static tacacsplist_t *zeiger, *zeigerold;

if(tacacsplist == tacacsplistptr) return;
zeiger = tacacsplist;
zeigerold = tacacsplist;
if(fh_tacacsp != NULL)
	{
	fprintf(fh_tacacsp, "$tacacs-plus$0$%08x$", zeiger->sessionid);
	for(c = 0; c < zeiger->len; c++) fprintf(fh_tacacsp, "%02x", zeiger->data[c]);
	fprintf(fh_tacacsp, "$%02x%02x\n", zeiger->version, zeiger->sequencenr);
	tacacspwrittencount++;
	}
for(zeiger = tacacsplist +1; zeiger < tacacsplistptr; zeiger++)
	{
	if((zeigerold->sessionid == zeiger->sessionid) && (zeigerold->sequencenr == zeiger->sequencenr)  && (zeigerold->len == zeiger->len) && (memcmp(zeigerold->data, zeiger->data, zeiger->len) == 0)) continue;
	if(fh_tacacsp != NULL)
		{
		fprintf(fh_tacacsp, "$tacacs-plus$0$%08x$", zeiger->sessionid);
		for(c = 0; c < zeiger->len; c++) fprintf(fh_tacacsp, "%02x", zeiger->data[c]);
		fprintf(fh_tacacsp, "$%02x%02x\n", zeiger->version, zeiger->sequencenr);
		tacacspwrittencount++;
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
void processtacacsppacket(uint32_t restlen, uint8_t *tacacspptr)
{
static uint32_t authlen;
static tacacsp_t *tacacsp;
static tacacsplist_t *tacacsplistnew; 

if(restlen < (uint32_t)TACACSP_SIZE) return;
tacacsp = (tacacsp_t*)tacacspptr;
if(tacacsp->type != TACACS_AUTHENTICATION) return;
authlen = ntohl(tacacsp->len);
if((authlen > restlen -TACACSP_SIZE) || (authlen > TACACSPMAX_LEN)) return;
if(tacacsplistptr >= tacacsplist +tacacsplistmax)
	{
	tacacsplistnew = realloc(tacacsplist, (tacacsplistmax +TACACSPLIST_MAX) *TACACSPLIST_SIZE);
	if(tacacsplistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	tacacsplist = tacacsplistnew;
	tacacsplistptr = tacacsplistnew +tacacsplistmax;
	tacacsplistmax += TACACSPLIST_MAX;
	}
memset(tacacsplistptr, 0, TACACSPLIST_SIZE);
tacacsplistptr->version = tacacsp->version;
tacacsplistptr->sequencenr = tacacsp->sequencenr;
tacacsplistptr->sessionid = ntohl(tacacsp->sessionid);
tacacsplistptr->len = authlen;
memcpy(tacacsplistptr->data, tacacsp->data, authlen);
tacacsplistptr++;
tacacspcount++;
return;
}
/*===========================================================================*/
static void processprotochappacket(uint32_t restlen, uint8_t *chapptr)
{
static chap_t *chap;

if(restlen < (uint32_t)CHAP_SIZE) return;
chap = (chap_t*)chapptr;
if(chap->code == CHAP_CODE_REQ) protochapreqcount++;
else if(chap->code == CHAP_CODE_RESP) protochaprespcount++;
else if(chap->code == CHAP_CODE_SUCCESS) protochapsuccesscount++;
protochapcount++;
return;
}
/*===========================================================================*/
static void processprotopapppacket()
{

protopapcount++;
return;
}
/*===========================================================================*/
static void processptppacket(uint32_t restlen, uint8_t *ptpptr)
{
static  ptp_t *ptp;

if(restlen < (uint32_t)PTP_SIZE) return;
ptp = (ptp_t*)ptpptr;
if(ntohs(ptp->type) == PROTO_CHAP) processprotochappacket(restlen -PTP_SIZE, ptpptr +PTP_SIZE);
else if(ntohs(ptp->type) == PROTO_PAP) processprotopapppacket();
return;
}
/*===========================================================================*/
static void processgrepacket(uint32_t restlen, uint8_t *greptr)
{
static gre_t *gre;
static uint32_t ofco;

if(restlen < (uint32_t)GRE_SIZE) return;
gre = (gre_t*)greptr;
if((ntohs(gre->flags) & GRE_MASK_VERSION) != 0x1) return; /* only GRE v1 supported */
ofco = 0;
if((ntohs(gre->flags) & GRE_FLAG_SNSET) == GRE_FLAG_SNSET) ofco += 4;
if((ntohs(gre->flags) & GRE_FLAG_ACKSET) == GRE_FLAG_ACKSET) ofco +=4;
if(ntohs(gre->type) == GREPROTO_PPP) processptppacket(restlen -GRE_SIZE -ofco, greptr +GRE_SIZE +ofco);
grecount++;
return;
}
/*===========================================================================*/
static void processudppacket(uint64_t timestamp, uint32_t restlen, uint8_t *udpptr)
{
static udp_t *udp;
static uint16_t udplen; 

if(restlen < UDP_SIZE) return;
udp = (udp_t*)udpptr;
udplen = ntohs(udp->len);
if(restlen < udplen) return;
udpcount++;
//dummy code to satisfy gcc untill full code is implemented
timestamp = timestamp;
return;
}
/*===========================================================================*/
static void processtcppacket(uint64_t timestamp, uint32_t restlen, uint8_t *tcpptr)
{
static uint32_t tcplen; 
static tcp_t *tcp;
static tacacsp_t *tacacsp;

if(restlen < TCP_SIZE_MIN) return;
tcp = (tcp_t*)tcpptr;
tcplen = byte_swap_8(tcp->len) *4;
if(restlen < tcplen) return;
if(restlen >= (uint32_t)TCP_SIZE_MIN +(uint32_t)TACACSP_SIZE)
	{
	tacacsp = (tacacsp_t*)(tcpptr +tcplen);
	if(tacacsp->version == TACACSP_VERSION) processtacacsppacket(restlen -tcplen, tcpptr +tcplen);
	}
tcpcount++;
//dummy code to satisfy gcc untill full code is implemented
timestamp = timestamp;
return;
}
/*===========================================================================*/
static void processicmp4()
{
icmp4count++;
return;
}
/*===========================================================================*/
static void processipv4(uint64_t timestamp, uint32_t restlen, uint8_t *ipv4ptr)
{
static ipv4_t *ipv4;
static uint32_t ipv4len;

if(restlen < IPV4_SIZE_MIN) return;
ipv4 = (ipv4_t*)ipv4ptr;
if((ipv4->ver_hlen & 0xf0) != 0x40) return;
ipv4len = (ipv4->ver_hlen & 0x0f) *4;
if(restlen < ipv4len) return;
if(ipv4->nextprotocol == NEXTHDR_TCP) processtcppacket(timestamp, ntohs(ipv4->len) -ipv4len, ipv4ptr +ipv4len);
else if(ipv4->nextprotocol == NEXTHDR_UDP) processudppacket(timestamp, ntohs(ipv4->len) -ipv4len, ipv4ptr +ipv4len);
else if(ipv4->nextprotocol == NEXTHDR_ICMP4) processicmp4();
else if(ipv4->nextprotocol == NEXTHDR_GRE) processgrepacket(ntohs(ipv4->len) -ipv4len, ipv4ptr +ipv4len);
ipv4count++;
return;
}
/*===========================================================================*/
static void processicmp6()
{
icmp6count++;
return;
}
/*===========================================================================*/
static void processipv6(uint64_t timestamp, uint16_t restlen, uint8_t *ipv6ptr)
{
static ipv6_t *ipv6;

if(restlen < IPV6_SIZE) return;
ipv6 = (ipv6_t*)ipv6ptr;
if((ntohl(ipv6->ver_class) & 0xf0000000) != 0x60000000) return;
if(restlen < ntohs(ipv6->len)) return;
if(ipv6->nextprotocol == NEXTHDR_TCP) processtcppacket(timestamp, restlen, ipv6ptr +IPV6_SIZE);
else if(ipv6->nextprotocol == NEXTHDR_UDP) processudppacket(timestamp, restlen, ipv6ptr +IPV6_SIZE);
else if(ipv6->nextprotocol == NEXTHDR_ICMP6) processicmp6();
else if(ipv6->nextprotocol == NEXTHDR_GRE) processgrepacket(restlen, ipv6ptr +IPV6_SIZE);
ipv6count++;
return;
}
/*===========================================================================*/
static inline bool mschapv2_challenge_hash(uint8_t *peer_challenge, uint8_t *auth_challenge, uint8_t *username, size_t usernamelen, uint8_t *challenge)
{
static unsigned int shalen;
static EVP_MD_CTX* mdctx;
static uint8_t shahash[EVP_MAX_MD_SIZE];

shalen = 40;
mdctx = EVP_MD_CTX_create();
if(mdctx == NULL) return false;
if(EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
shalen = MSCHAPV2_CHALLENGE_LEN_MAX;
if(EVP_DigestUpdate(mdctx, peer_challenge, MSCHAPV2_CHALLENGE_PEER_LEN_MAX) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestUpdate(mdctx, auth_challenge, MSCHAPV2_CHALLENGE_PEER_LEN_MAX) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestUpdate(mdctx, username, usernamelen) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestFinal_ex(mdctx, shahash, &shalen) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
EVP_MD_CTX_free(mdctx);
memcpy(challenge, shahash, MSCHAPV2_CHALLENGE_LEN_MAX);
return true;
}
/*===========================================================================*/
static inline size_t mschapv2_username_clean(uint8_t *username, size_t usernamelen, uint8_t *usernameclean)
{
static char *ptr;

ptr = memchr(username, '\\', usernamelen);
if(ptr == NULL)
	{
	memcpy(usernameclean, username, usernamelen);
	return usernamelen;
	}
memcpy(usernameclean, ptr +1, username +usernamelen -(uint8_t*)ptr -1);
return (username +usernamelen -(uint8_t*)ptr -1);
}
/*===========================================================================*/
static void outputeapmschapv2hashlist()
{
static eapmschapv2hashlist_t *zeiger, *zeigerold;
static uint8_t challenge[MSCHAPV2_CHALLENGE_LEN_MAX];
static uint8_t usernameclean[MSCHAPV2USERNAME_LEN_MAX];
static size_t usernamecleanlen;

zeiger = eapmschapv2hashlist;
zeigerold = NULL;
qsort(eapmschapv2hashlist, eapmschapv2hashlistptr -eapmschapv2hashlist, EAPMSCHAPV2HASHLIST_SIZE, sort_eapmschapv2hashlist_by_id);
for(zeiger = eapmschapv2hashlist; zeiger < eapmschapv2hashlistptr; zeiger++)
	{
	if((zeigerold != NULL) && (zeigerold->id == zeiger->id) && (zeigerold->mschapv2usernamelen == zeiger->mschapv2usernamelen) && (memcmp(zeigerold->mschapv2username, zeiger->mschapv2username, zeiger->mschapv2usernamelen) == 0) && (memcmp(zeigerold->mschapv2request, zeiger->mschapv2request, MSCHAPV2REQ_LEN_MAX) == 0) && (memcmp(zeigerold->mschapv2response, zeiger->mschapv2response, MSCHAPV2RESP_LEN_MAX) == 0)) continue;
	if(fh_eapleap != NULL)
		{
		usernamecleanlen = mschapv2_username_clean(zeiger->mschapv2username, zeiger->mschapv2usernamelen, usernameclean);
		if(mschapv2_challenge_hash(zeiger->mschapv2response, zeiger->mschapv2request, usernameclean, usernamecleanlen, challenge) == false) continue;
		fprintf(fh_eapleap, "%.*s::::%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x%02x%02x\n",
			(int)zeiger->mschapv2usernamelen, zeiger->mschapv2username,
			zeiger->mschapv2response[24], zeiger->mschapv2response[25], zeiger->mschapv2response[26], zeiger->mschapv2response[27], zeiger->mschapv2response[28], zeiger->mschapv2response[29], zeiger->mschapv2response[30], zeiger->mschapv2response[31],
			zeiger->mschapv2response[32], zeiger->mschapv2response[33], zeiger->mschapv2response[34], zeiger->mschapv2response[35], zeiger->mschapv2response[36], zeiger->mschapv2response[37], zeiger->mschapv2response[38], zeiger->mschapv2response[39],
			zeiger->mschapv2response[40], zeiger->mschapv2response[41], zeiger->mschapv2response[42], zeiger->mschapv2response[43], zeiger->mschapv2response[44], zeiger->mschapv2response[45], zeiger->mschapv2response[46], zeiger->mschapv2response[47],
			challenge[0], challenge[1], challenge[2], challenge[3], challenge[4], challenge[5], challenge[6], challenge[7]);
		eapmschapv2writtencount++;
		}
	zeigerold = zeiger;
	}
return;
}
/*===========================================================================*/
static void addeapmschapv2hash(uint8_t id, uint8_t mschapv2usernamelen, uint8_t *mschapv2username, uint8_t *mschapv2request, uint8_t *mschapv2response)
{
static eapmschapv2hashlist_t *eapmschapv2hashlistnew; 

eapmschapv2hashcount++;
if(eapmschapv2hashlistptr >= eapmschapv2hashlist +eapmschapv2hashlistmax)
	{
	eapmschapv2hashlistnew = realloc(eapmschapv2hashlist, (eapmschapv2hashlistmax +EAPMSCHAPV2HASHLIST_MAX) *EAPMSCHAPV2HASHLIST_SIZE);
	if(eapmschapv2hashlistnew == NULL)
		{
		printf("failed to allocate memory for internal list\n");
		exit(EXIT_FAILURE);
		}
	eapmschapv2hashlist = eapmschapv2hashlistnew;
	eapmschapv2hashlistptr = eapmschapv2hashlistnew +eapmschapv2hashlistmax;
	eapmschapv2hashlistmax += EAPMSCHAPV2HASHLIST_MAX;
	}
memset(eapmschapv2hashlistptr, 0, EAPMSCHAPV2HASHLIST_SIZE);
eapmschapv2hashlistptr->id = id;
memcpy(eapmschapv2hashlistptr->mschapv2request, mschapv2request, MSCHAPV2REQ_LEN_MAX);
memcpy(eapmschapv2hashlistptr->mschapv2response, mschapv2response, MSCHAPV2RESP_LEN_MAX);
eapmschapv2hashlistptr->mschapv2usernamelen = mschapv2usernamelen;
memcpy(eapmschapv2hashlistptr->mschapv2username, mschapv2username, mschapv2usernamelen);
eapmschapv2hashlistptr++;
return;
}
/*===========================================================================*/
static void processexteapmschapv2(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t eapcode, uint32_t restlen, uint8_t *eapmschapv2ptr)
{
static eapmschapv2_t *eapmschapv2;
static uint16_t eaplen;
static uint16_t mschapv2len;
static eapmschapv2msglist_t *zeiger;
static uint32_t mschapv2usernamelen;
static uint8_t *mschapv2usernameptr;

eapmschapv2count++;
eapmschapv2 = (eapmschapv2_t*)eapmschapv2ptr;
eaplen = ntohs(eapmschapv2->eaplen);
mschapv2len = ntohs(eapmschapv2->mschapv2len);
if(eaplen > restlen) return;
if((eapcode == EAP_CODE_REQ) && (eapmschapv2->opcode == EAP_MSCHAPV2_OPCODE_REQ))
	{
	zeiger = eapmschapv2msglist +EAPMSCHAPV2MSGLIST_MAX;
	if(eapmschapv2->mschapv2valuesize != MSCHAPV2REQ_LEN_MAX) return;
	memset(zeiger, 0, EAPMSCHAPV2MSGLIST_SIZE);
	zeiger->timestamp = eaptimestamp;
	memcpy(zeiger->ap, macfm, 6);
	memcpy(zeiger->client, macto, 6);
	zeiger->type = EAP_CODE_REQ;
	zeiger->id = eapmschapv2->id;
	memcpy(zeiger->mschapv2request, eapmschapv2->mschapv2data, eapmschapv2->mschapv2valuesize);
	mschapv2usernamelen = eaplen -EAPMSCHAPV2_SIZE -eapmschapv2->mschapv2valuesize;
	if(mschapv2usernamelen > MSCHAPV2USERNAME_LEN_MAX) return;
	if(EAPMSCHAPV2_SIZE +MSCHAPV2REQ_LEN_MAX +mschapv2usernamelen > restlen) return;
	mschapv2usernameptr = eapmschapv2ptr +EAPMSCHAPV2_SIZE +eapmschapv2->mschapv2valuesize;
	if((fh_identity != 0) && (mschapv2usernamelen > 0))
		{
		fwritestring(mschapv2usernamelen, mschapv2usernameptr, fh_identity);
		identitycount++;
		}
	qsort(eapmschapv2msglist, EAPMSCHAPV2MSGLIST_MAX +1, EAPMSCHAPV2MSGLIST_SIZE, sort_eapmschapv2msglist_by_timestamp);
	}
else if((eapcode == EAP_CODE_RESP) && (eapmschapv2->opcode == EAP_MSCHAPV2_OPCODE_RESP))
	{
	zeiger = eapmschapv2msglist +EAPMSCHAPV2MSGLIST_MAX;
	if(mschapv2len != eaplen -EXTEAP_SIZE) return;
	if(memcmp(&zeroed32, eapmschapv2->mschapv2data +MSCHAPV2_CHALLENGE_PEER_LEN_MAX +MSCHAPV2_RESERVED_LEN_MAX, MSCHAPV2_NTRESPONSE_LEN_MAX) == 0) return;
	if(eapmschapv2->mschapv2valuesize != MSCHAPV2RESP_LEN_MAX) return;
	memset(zeiger, 0, EAPMSCHAPV2MSGLIST_SIZE);
	zeiger->timestamp = eaptimestamp;
	memcpy(zeiger->ap, macto, 6);
	memcpy(zeiger->client, macfm, 6);
	zeiger->type = EAP_CODE_RESP;
	zeiger->id = eapmschapv2->id;
	memcpy(zeiger->mschapv2response, eapmschapv2->mschapv2data, eapmschapv2->mschapv2valuesize);
	mschapv2usernamelen = restlen -EAPMSCHAPV2_SIZE -eapmschapv2->mschapv2valuesize;
	if(mschapv2usernamelen == 0) return;
	if(mschapv2usernamelen > MSCHAPV2USERNAME_LEN_MAX) return;
	if(EAPMSCHAPV2_SIZE +MSCHAPV2REQ_LEN_MAX +mschapv2usernamelen > restlen) return;
	mschapv2usernameptr = eapmschapv2ptr +EAPMSCHAPV2_SIZE +eapmschapv2->mschapv2valuesize;
	zeiger->mschapv2usernamelen = mschapv2usernamelen;
	memcpy(zeiger->mschapv2username, mschapv2usernameptr, mschapv2usernamelen);
	if(fh_username != 0)
		{
		fwritestring(mschapv2usernamelen, mschapv2usernameptr, fh_username);
		usernamecount++;
		}
	for(zeiger = eapmschapv2msglist; zeiger < eapmschapv2msglist +EAPMSCHAPV2MSGLIST_MAX; zeiger++)
		{
		if((zeiger->type) != EAP_CODE_REQ) continue;
		if((zeiger->id) != eapmschapv2->id) continue;
		if(memcmp(zeiger->ap, macto, 6) != 0) continue;
		if(memcmp(zeiger->client, macfm, 6) != 0) continue;
		zeiger->mschapv2usernamelen = mschapv2usernamelen;
		memcpy(zeiger->mschapv2username, mschapv2usernameptr, mschapv2usernamelen);
		addeapmschapv2hash(eapmschapv2->id, zeiger->mschapv2usernamelen, zeiger->mschapv2username, zeiger->mschapv2request, eapmschapv2->mschapv2data); 
		}
	qsort(eapmschapv2msglist, EAPMSCHAPV2MSGLIST_MAX +1, EAPMSCHAPV2MSGLIST_SIZE, sort_eapmschapv2msglist_by_timestamp);
	}
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
if(fh_eapleap != NULL)
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
	if(fh_eapleap != NULL)
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
static bool testpmkid(uint8_t *testpmk, uint8_t *macsta, uint8_t *macap, uint8_t *pmkid)
{
static size_t testpmkidlen;
static EVP_MD_CTX *mdctx;
static EVP_PKEY *pkey;
static char *pmkname = "PMK Name";

static uint8_t message[32];
static uint8_t testpmkid[EVP_MAX_MD_SIZE];

memcpy(&message, pmkname, 8);
memcpy(&message[8], macap, 6);
memcpy(&message[14], macsta, 6);
testpmkidlen = 16;
mdctx = EVP_MD_CTX_new();
if(mdctx == 0) return false;
pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testpmk, 32);
if(pkey == NULL)
	{
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestSignInit(mdctx, NULL,  EVP_sha1(), NULL, pkey) != 1)
	{
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestSignUpdate(mdctx, message, 20) != 1)
	{
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return false;
	}
if(EVP_DigestSignFinal(mdctx, testpmkid, &testpmkidlen) <= 0)
	{
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	return false;
	}
EVP_PKEY_free(pkey);
EVP_MD_CTX_free(mdctx);
if(memcmp(&testpmkid, pmkid, 16) == 0) return true;
return false;
}
/*===========================================================================*/
static bool testeapolpmk(uint8_t *testpmk, uint8_t keyver, uint8_t *macsta, uint8_t *macap, uint8_t *nonceap, uint8_t eapollen, uint8_t *eapolmessage)
{
static uint8_t *pkeptr;
static wpakey_t *wpakzero, *wpak;

static size_t testptklen;
static size_t testmiclen;
static EVP_MD_CTX *mdctx;
static EVP_PKEY *pkey;

static uint8_t pkedata[102];
static uint8_t testptk[EVP_MAX_MD_SIZE];
static uint8_t eapoldata[0xff];
static uint8_t testmic[EVP_MAX_MD_SIZE];

memcpy(&eapoldata, eapolmessage, eapollen);
wpakzero = (wpakey_t*)(eapoldata +EAPAUTH_SIZE);
memset(wpakzero->keymic, 0, 16);
wpak = (wpakey_t*)(eapolmessage +EAPAUTH_SIZE);
if(keyver == 2)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&testptk, 0, sizeof(testptk));
	memset(&testmic, 0, sizeof(testptk));
	pkeptr = pkedata;
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
	testptklen = 32;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testpmk, 32);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, pkedata, 100) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(mdctx);
	testmiclen = 16;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testptk, 16);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, eapoldata, eapollen) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testmic, &testmiclen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	if(memcmp(&testmic, wpak->keymic, 16) == 0) return true;
	}
else if(keyver == 1)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&testptk, 0, sizeof(testptk));
	memset(&testmic, 0, sizeof(testptk));
	pkeptr = pkedata;
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
	testptklen = 32;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testpmk, 32);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, pkedata, 100) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(mdctx);
	testmiclen = 16;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testptk, 16);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL,  EVP_md5(), NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, eapoldata, eapollen) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testmic, &testmiclen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	if(memcmp(&testmic, wpak->keymic, 16) == 0) return true;
	}
else if(keyver == 3)
	{
	memset(&pkedata, 0, sizeof(pkedata));
	memset(&testptk, 0, sizeof(testptk));
	memset(&testmic, 0, sizeof(testptk));
	pkedata[0] = 1;
	pkedata[1] = 0;
	pkeptr = pkedata +2;
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
	pkedata[100] = 0x80;
	pkedata[101] = 1;
	testptklen = 32;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, testpmk, 32);
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, pkedata, 102) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testptk, &testptklen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_reset(mdctx);
	testmiclen = 16;
	mdctx = EVP_MD_CTX_new();
	if(mdctx == 0) return false;
	pkey = EVP_PKEY_new_CMAC_key(NULL, testptk, 16, EVP_aes_128_cbc());
	if(pkey == NULL)
		{
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignInit(mdctx, NULL, NULL, NULL, pkey) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignUpdate(mdctx, eapoldata, eapollen) != 1)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	if(EVP_DigestSignFinal(mdctx, testmic, &testmiclen) <= 0)
		{
		EVP_PKEY_free(pkey);
		EVP_MD_CTX_free(mdctx);
		return false;
		}
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_free(mdctx);
	if(memcmp(&testmic, wpak->keymic, 16) == 0) return true;
	}
return false;
}
/*===========================================================================*/
static bool testzeroedpsk(uint8_t essidlen, uint8_t *essid)
{
if(PKCS5_PBKDF2_HMAC_SHA1(zeroedpsk, 8, essid, essidlen, 4096, 32, calculatedpmk) == 0) return false;
return true;
}
/*===========================================================================*/
static void getnc(handshakelist_t *zeigerhsakt)
{
static handshakelist_t *zeigerhs, *zeigerhsold;

zeigerhsold = zeigerhsakt;
for(zeigerhs = zeigerhsakt; zeigerhs < handshakelistptr; zeigerhs++)
	{
	if(memcmp(zeigerhs->ap, zeigerhsold->ap, 6) != 0) return;
		{
		zeigerhsakt->status |= zeigerhs->status &0xe0;
		zeigerhsold->status |= zeigerhs->status &0xe0;
		}
	zeigerhsold = zeigerhs;
	}
return;
}
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
			if((memcmp(zeigerhs->ap, zeigerhsold->ap, 6) == 0) && (memcmp(zeigerhs->client, zeigerhsold->client, 6) == 0))
				{
				if((zeigerhs->status &ST_APLESS) != ST_APLESS) getnc(zeigerhs);
				continue;
				}
			}
		}
	if(memcmp(zeigermac->addr, zeigerhs->ap, 6) == 0)
		{
		eapolmpbestcount++;
		if((zeigerhs->status &ST_APLESS) != ST_APLESS) getnc(zeigerhs);
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
		if(donotcleanflag == false)
			{
			if(testzeroedpsk(zeigermac->essidlen, zeigermac->essid) == true)
				{
				if(testeapolpmk(calculatedpmk, keyvertemp, zeigerhs->client, zeigerhs->ap, zeigerhs->anonce, zeigerhs->eapauthlen, zeigerhs->eapol) == true)
					{
					zeroedeapolpskcount++;
					eapolmpbestcount--;
					continue;
					}
				}
			}
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
		if(donotcleanflag == false)
			{
			if(testzeroedpsk(zeigermac->essidlen, zeigermac->essid) == true)
				{
				if(testpmkid(calculatedpmk, zeigerpmkid->client, zeigerpmkid->ap, zeigerpmkid->pmkid) == true)
					{
					zeroedpmkidpskcount++;
					continue;
					}
				}
			}
		if(memcmp(&myaktclient, zeigerpmkid->client, 6) == 0) pmkidroguecount++;
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
if(ncvalue == 0) qsort(handshakelist, handshakelistptr -handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_timegap);
else  qsort(handshakelist, handshakelistptr -handshakelist, HANDSHAKELIST_SIZE, sort_handshakelist_by_rcgap);
zeigerhsakt = handshakelist;
zeigerpmkidakt = pmkidlist;
zeigermacold = aplist;
if(zeigermacold->type == AP)
	{
	if(zeigermacold->essidlen != 0)
		{
		if(ignoreieflag == true)
			{
			zeigerpmkidakt = getpmkid(zeigermacold, zeigerpmkidakt);
			zeigerhsakt = gethandshake(zeigermacold, zeigerhsakt);
			}
		else
			{
			if(((zeigermacold->akm &TAK_PSK) == TAK_PSK) || ((zeigermacold->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
				{
				zeigerpmkidakt = getpmkid(zeigermacold, zeigerpmkidakt);
				zeigerhsakt = gethandshake(zeigermacold, zeigerhsakt);
				}
			}
		}
	}
essiddupecount = 0;
for(zeigermac = aplist +1; zeigermac < aplistptr; zeigermac++)
	{
	if(zeigermac->essidlen == 0) continue;
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
			if(essiddupecount >= essiddupemax) essiddupemax = essiddupecount;
			if(essiddupecount >= essidsvalue) continue;
			}
		else essiddupecount = 0;
		}
	if(ignoreieflag == true)
		{
		zeigerpmkidakt = getpmkid(zeigermac, zeigerpmkidakt);
		zeigerhsakt = gethandshake(zeigermac, zeigerhsakt);
		}
	else
		{
		if(((zeigermac->akm &TAK_PSK) == TAK_PSK) || ((zeigermac->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
			{
			zeigerpmkidakt = getpmkid(zeigermac, zeigerpmkidakt);
			zeigerhsakt = gethandshake(zeigermac, zeigerhsakt);
			}
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
	if(zeiger->rcgap > handshakelistptr->rcgap) zeiger->rcgap = (zeiger->rcgap &0xe0) | handshakelistptr->rcgap;
	if(zeiger->status < handshakelistptr->status) zeiger->status = handshakelistptr->status;
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
static messagelist_t *zeiger;

eapolmpcount++;
if((mpfield &ST_APLESS) != ST_APLESS)
	{
	for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX; zeiger++)
		{
		if((zeiger->status &ST_APLESS) != ST_APLESS)
			{
			if(memcmp(msgap->ap, zeiger->ap, 6) == 0) mpfield |= zeiger->status & 0xe0;
			}
		}
	}
if(msgap->timestamp == msgclient->timestamp) eapolmsgtimestamperrorcount++;
if(testeapolpmk(zeroedpmk, keyver, msgclient->client, msgap->ap, msgap->nonce, msgclient->eapauthlen, msgclient->eapol) == false)
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
	zeroedeapolpmkcount++;
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
if(testpmkid(zeroedpmk, macclient, macap, pmkid) == false)
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
	zeroedpmkidpmkcount++;
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
else if(exteap->type == EAP_TYPE_TLS) eaptlscount++;
else if(exteap->type == EAP_TYPE_EXPAND) eapexpandedcount++;
else if(exteap->type == EAP_TYPE_MD5) processexteapmd5(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr +EAPAUTH_SIZE);
else if(exteap->type == EAP_TYPE_LEAP) processexteapleap(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr +EAPAUTH_SIZE);
else if(exteap->type == EAP_TYPE_MSEAP) processexteapmschapv2(eaptimestamp, macto, macfm, exteap->code, exteaplen, eapptr +EAPAUTH_SIZE);

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
static bool gettagwps(int wpslen, uint8_t *ieptr, tags_t *zeiger)
{
wpslen -= VENDORIE_SIZE;
ieptr += VENDORIE_SIZE;
if(wpslen < (int)WPSIE_SIZE) return true;
zeiger->wpsinfo = 1;
return true;
}
/*===========================================================================*/
static bool gettagwpa(int wpalen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static wpaie_t *wpaptr;
static int wpatype;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static int csuitecount;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static int asuitecount;

wpaptr = (wpaie_t*)ieptr;
wpalen -= WPAIE_SIZE;
ieptr += WPAIE_SIZE;
#ifndef BIG_ENDIAN_HOST
wpatype = wpaptr->type;
#else
wpatype = byte_swap_16(wpaptr->type);
#endif
if(wpatype != VT_WPA_IE) return false;
zeiger->kdversion |= KV_WPAIE;
gsuiteptr = (suite_t*)ieptr; 
if(memcmp(gsuiteptr->oui, &ouimscorp, 3) == 0)
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
#ifndef BIG_ENDIAN_HOST
csuitecount = csuitecountptr->count;
#else
csuitecount = byte_swap_16(csuitecountptr->count);
#endif
if(csuitecount *4 > wpalen)
	{
	taglenerrorcount++;
	return false;
	}
for(c = 0; c < csuitecount; c++)
	{
	csuiteptr = (suite_t*)ieptr; 
	if(memcmp(csuiteptr->oui, &ouimscorp, 3) == 0)
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
	if(wpalen == 0) return true;
	if(wpalen < 0) return false;
	}
asuitecountptr = (suitecount_t*)ieptr;
wpalen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
#ifndef BIG_ENDIAN_HOST
asuitecount = asuitecountptr->count;
#else
asuitecount = byte_swap_16(asuitecountptr->count);
#endif
if(asuitecount *4 > wpalen)
	{
	taglenerrorcount++;
	return false;
	}
for(c = 0; c < asuitecount; c++)
	{
	asuiteptr = (suite_t*)ieptr; 
	if(memcmp(asuiteptr->oui, &ouimscorp, 3) == 0)
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
		if(asuiteptr->type == AK_SAE_SHA384B) zeiger->akm |= TAK_SAE_SHA384B;
		if(asuiteptr->type == AK_OWE) zeiger->akm |= TAK_OWE;
		}
	wpalen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(wpalen == 0) return true;
	if(wpalen < 0) return false;
	}
return true;
}
/*===========================================================================*/
static bool gettagvendor(int vendorlen, uint8_t *ieptr, tags_t *zeiger)
{
static wpaie_t *wpaptr;

static const uint8_t hcxoui[] =
{
0xff, 0xff, 0xff, 0x00, 0xd9, 0x20, 0x21, 0x9b, 0x9b, 0x6a, 0xc9, 0x59, 0x49, 0x42, 0xe6, 0x55,
0x6a, 0x06, 0xa3, 0x23, 0x94, 0x2d, 0x94
};

wpaptr = (wpaie_t*)ieptr;
if(memcmp(wpaptr->oui, &ouimscorp, 3) == 0)
	{
	if((wpaptr->ouitype == VT_WPA_IE) && (vendorlen >= WPAIE_LEN_MIN))
		{
		if(gettagwpa(vendorlen, ieptr, zeiger) == false) return false;
		return true;
		}
	if((wpaptr->ouitype == VT_WPS_IE) && (vendorlen >= (int)WPSIE_SIZE))
		{
		if(gettagwps(vendorlen, ieptr, zeiger) == false) return false;
		return true;
		}
	return true;
	}
if(vendorlen == 0x17)
	{
	if(memcmp(&hcxoui, ieptr, 0x17) == 0) beaconhcxcount++;
	}
return true;
}
/*===========================================================================*/
static bool gettagrsn(int rsnlen, uint8_t *ieptr, tags_t *zeiger)
{
static int c;
static rsnie_t *rsnptr;
static int rsnver;
static suite_t *gsuiteptr;
static suitecount_t *csuitecountptr;
static suite_t *csuiteptr;
static int csuitecount;
static suitecount_t *asuitecountptr;
static suite_t *asuiteptr;
static int asuitecount;
static rsnpmkidlist_t *rsnpmkidlistptr; 
static int rsnpmkidcount;

static const uint8_t foxtrott[4] = { 0xff, 0xff, 0xff, 0xff };

rsnptr = (rsnie_t*)ieptr;
#ifndef BIG_ENDIAN_HOST
rsnver = rsnptr->version;
#else
rsnver = byte_swap_16(rsnptr->version);
#endif
if(rsnver != 1) return true;
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
#ifndef BIG_ENDIAN_HOST
csuitecount = csuitecountptr->count;
#else
csuitecount = byte_swap_16(csuitecountptr->count);
#endif
if(csuitecount *4 > rsnlen)
	{
	taglenerrorcount++;
	return false;
	}
for(c = 0; c < csuitecount; c++)
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
	if(rsnlen < 0) return false;
	if(rsnlen == 0) return true;
	}
asuitecountptr = (suitecount_t*)ieptr;
rsnlen -= SUITECOUNT_SIZE;
ieptr += SUITECOUNT_SIZE;
#ifndef BIG_ENDIAN_HOST
asuitecount = asuitecountptr->count;
#else
asuitecount = byte_swap_16(asuitecountptr->count);
#endif
if(asuitecount *4 > rsnlen)
	{
	taglenerrorcount++;
	return false;
	}
for(c = 0; c < asuitecount; c++)
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
		if(asuiteptr->type == AK_SAE_SHA384B) zeiger->akm |= TAK_SAE_SHA384B;
		if(asuiteptr->type == AK_OWE) zeiger->akm |= TAK_OWE;
		}
	rsnlen -= SUITE_SIZE;
	ieptr += SUITE_SIZE;
	if(rsnlen < 0) return false;
	if(rsnlen == 0) return true;
	}
rsnlen -= RSNCAPABILITIES_SIZE;
ieptr += RSNCAPABILITIES_SIZE;
if(rsnlen <= 0) return true;
rsnpmkidlistptr = (rsnpmkidlist_t*)ieptr; 
#ifndef BIG_ENDIAN_HOST
rsnpmkidcount = rsnpmkidlistptr->count;
#else
rsnpmkidcount = byte_swap_16(rsnpmkidlistptr->count);
#endif
if(rsnpmkidcount == 0) return true;
rsnlen -= RSNPMKIDLIST_SIZE;
ieptr += RSNPMKIDLIST_SIZE;
if(rsnlen < 16) return true;
if(((zeiger->akm &TAK_PSK) == TAK_PSK) || ((zeiger->akm &TAK_PSKSHA256) == TAK_PSKSHA256))
	{
	if(memcmp(&zeroed32, ieptr, 16) == 0) return true;
	for(c = 0; c < 12; c++)
		{
		if(memcmp(&zeroed32, &ieptr[c], 4) == 0) return false;
		if(memcmp(&foxtrott, &ieptr[c], 4) == 0) return false;
		}
	memcpy(zeiger->pmkid, ieptr, 16);
	}
return true;
}
/*===========================================================================*/
static bool isessidvalid(int essidlen, uint8_t *essid)
{
static int c;
static const uint8_t foxtrott[4] = { 0xff, 0xff, 0xff, 0xff };

if(essidlen > ESSID_LEN_MAX) return false;
if(essidlen == 0) return true;
if(memcmp(&zeroed32, essid, essidlen) == 0) return true;
if(essid[essidlen -1] == 0)
	{
	essiderrorcount++;
	return false;
	}
for(c = 0; c< essidlen -4; c++)
	{
	if(memcmp(&zeroed32, &essid[c], 4) == 0)
		{
		essiderrorcount++;
		return false;
		}
	if(memcmp(&foxtrott, &essid[c], 4) == 0)
		{
		essiderrorcount++;
		return false;
		}
	}
return true;
}
/*===========================================================================*/
static bool gettags(int infolen, uint8_t *infoptr, tags_t *zeiger)
{
static ietag_t *tagptr;

memset(zeiger, 0, TAGS_SIZE);
while(0 < infolen)
	{
	if(infolen == 4) return true;
	tagptr = (ietag_t*)infoptr;
	if(tagptr->len == 0)
		{
		infoptr += tagptr->len +IETAG_SIZE;
		infolen -= tagptr->len +IETAG_SIZE;
		continue;
		}
	if(tagptr->len > infolen) return false;
	if(tagptr->id == TAG_SSID)
		{
		if(tagptr->len > ESSID_LEN_MAX)
			{
			taglenerrorcount++;
			return false;
			}
		if(isessidvalid(tagptr->len, &tagptr->data[0]) == false) return false;
			{
			memcpy(zeiger->essid, &tagptr->data[0], tagptr->len);
			zeiger->essidlen = tagptr->len;
			}
		}
	else if(tagptr->id == TAG_CHAN)
		{
		if(tagptr->len == 1) zeiger->channel = tagptr->data[0];
		}
	else if(tagptr->id == TAG_COUNTRY)
		{
		if(tagptr->len > 2)
			{
			zeiger->country[0] = tagptr->data[0];
			zeiger->country[1] = tagptr->data[1];
			}
		}
	else if(tagptr->id == TAG_RSN)
		{
		if(tagptr->len >= RSNIE_LEN_MIN)
			{
			if(gettagrsn(tagptr->len, tagptr->data, zeiger) == false) return false;
			}
		}
	else if(tagptr->id == TAG_VENDOR)
		{
		if(tagptr->len >= VENDORIE_SIZE)
			{
			if(gettagvendor(tagptr->len, tagptr->data, zeiger) == false) return false;
			}
		}
	infoptr += tagptr->len +IETAG_SIZE;
	infolen -= tagptr->len +IETAG_SIZE;
	}
if((infolen != 0) && (infolen != 4)) return false;
return true;
}
/*===========================================================================*/
static void process80211eapol_m4(uint64_t eaptimestamp, uint8_t *macap, uint8_t *macclient, uint32_t restlen, uint8_t *eapauthptr)
{
static int c;
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

static const uint8_t foxtrott[4] = { 0xff, 0xff, 0xff, 0xff };
eapolm4count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen +EAPAUTH_SIZE > restlen) return;
if(authlen +EAPAUTH_SIZE > EAPOL_AUTHLEN_MAX) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver == 0) || (keyver > 3))
	{
	eapolm4kdv0count++;
	return;
	}
if(ntohs(wpak->wpadatalen) > (restlen -EAPAUTH_SIZE -WPAKEY_SIZE))
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M4 wpa data len > eap authentication len: %ld\n", rawpacketcount);
	eapolm4errorcount++;
	return;
	}
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if(memcmp(&zeroed32, wpak->keymic, 16) == 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M4 key mic zeroed: %ld\n", rawpacketcount);
	eapolm4errorcount++;
	return;
	}
for(c = 0; c < 12; c++)
	{
	if(memcmp(&zeroed32, &wpak->keymic[c], 4) == 0)
		{
		if(fh_log != NULL) fprintf(fh_log, "EAPOL M4 key mic possible plcp bit error: %ld\n", rawpacketcount);
		eapolm4errorcount++;
		return;
		}
	if(memcmp(&foxtrott, &wpak->keymic[c], 4) == 0)
		{
		if(fh_log != NULL) fprintf(fh_log, "EAPOL M4 key mic possible plcp bit error: %ld\n", rawpacketcount);
		eapolm4errorcount++;
		return;
		}
	}
if(memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M4 key id != 0: %ld\n", rawpacketcount);
	eapolm4errorcount++;
	return;
	}
if(memcmp(&zeroed32, wpak->nonce, 32) == 0) return;
if((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17)) return; 
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
	if((zeiger->message &HS_M3) == HS_M3)
		{
		if(memcmp(zeiger->client, macclient, 6) != 0) continue;
		if(memcmp(zeiger->ap, macap, 6) != 0) continue;
		if(zeiger->rc >= rc) rcgap = zeiger->rc -rc;
		else rcgap = rc -zeiger->rc;
		if(rcgap > rcgapmax) rcgapmax = rcgap;
		if(rcgap > ncvalue) continue;
		if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
		else eaptimegap = zeiger->timestamp -eaptimestamp;
		mpfield = ST_M34E4;
		if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
		if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
		}
	if((zeiger->message &HS_M1) != HS_M1) continue;
	if(memcmp(zeiger->client, macclient, 6) != 0) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
	if(zeiger->rc >= rc -1) rcgap = zeiger->rc -rc +1;
	else rcgap = rc +1 -zeiger->rc;
	if(zeiger->rc != myaktreplaycount)
		{
		if(rcgap > rcgapmax) rcgapmax = rcgap;
		}
	if(rcgap > ncvalue) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M14E4;
	if(myaktreplaycount > 0)
		{
		if(zeiger->rc == myaktreplaycount) continue;
		}
	if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m3(uint64_t eaptimestamp, uint8_t *macclient, uint8_t *macap, uint32_t restlen, uint8_t *eapauthptr)
{
static int c;
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

static const uint8_t foxtrott[4] = { 0xff, 0xff, 0xff, 0xff };

eapolm3count++;
eapolmsgcount++;
zeigerakt = messagelist +MESSAGELIST_MAX;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > restlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver == 0) || (keyver > 3))
	{
	eapolm3kdv0count++;
	return;
	}
if(ntohs(wpak->wpadatalen) > (restlen -EAPAUTH_SIZE -WPAKEY_SIZE))
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M3 wpa data len > eap authentication len: %ld\n", rawpacketcount);
	eapolm3errorcount++;
	return;
	}
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if(memcmp(&zeroed32, wpak->keymic, 16) == 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M3 key mic zeroed: %ld\n", rawpacketcount);
	eapolm3errorcount++;
	return;
	}
for(c = 0; c < 12; c++)
	{
	if(memcmp(&zeroed32, &wpak->keymic[c], 4) == 0)
		{
		if(fh_log != NULL) fprintf(fh_log, "EAPOL M3 key mic possible plcp bit error: %ld\n", rawpacketcount);
		eapolm3errorcount++;
		return;
		}
	if(memcmp(&foxtrott, &wpak->keymic[c], 4) == 0)
		{
		if(fh_log != NULL) fprintf(fh_log, "EAPOL M3 key mic possible plcp bit error: %ld\n", rawpacketcount);
		eapolm3errorcount++;
		return;
		}
	}
if(memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M3 key id != 0: %ld\n", rawpacketcount);
	eapolm3errorcount++;
	return;
	}
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
	if(((zeiger->message &HS_M1) == HS_M1) || ((zeiger->message &HS_M3) == HS_M3))
		{
		if((memcmp(zeiger->nonce, wpak->nonce, 28) == 0) && (memcmp(&zeiger->nonce[29], &wpak->nonce[29], 4) != 0))
			{
			zeiger->status |= ST_NC;
			zeigerakt->status |= ST_NC;
			if(zeiger->nonce[31] != wpak->nonce[31]) zeiger->status |= ST_LE;
			else if(zeiger->nonce[28] != wpak->nonce[28]) zeiger->status |= ST_BE;
			eapolnccount++;
			}
		}
	if((zeiger->message &HS_M2) == HS_M2)
		{
		if(memcmp(zeiger->ap, macap, 6) != 0) continue;
		if(memcmp(zeiger->client, macclient, 6) != 0) continue;
		if(zeiger->rc >= rc -1) rcgap = zeiger->rc -rc +1;
		else rcgap = rc +1 -zeiger->rc;
		if(zeiger->rc != myaktreplaycount)
			{
			if(rcgap > rcgapmax) rcgapmax = rcgap;
			}
		if(rcgap > ncvalue) continue;
		if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
		else eaptimegap = zeiger->timestamp -eaptimestamp;
		mpfield = ST_M32E2;
		if(myaktreplaycount > 0)
			{
			if(zeiger->rc == myaktreplaycount) continue;
			}
		if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
		if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, zeiger, messagelist +MESSAGELIST_MAX, keyver, mpfield);
		}
	if((zeiger->message &HS_M4) != HS_M4) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
	if(memcmp(zeiger->client, macclient, 6) != 0) continue;
	if(zeiger->rc >= rc) rcgap = zeiger->rc -rc;
	else rcgap = rc -zeiger->rc;
	if(rcgap > rcgapmax) rcgapmax = rcgap;
	if(rcgap > ncvalue) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M34E4;
	if(myaktreplaycount > 0)
		{
		if(zeiger->rc == myaktreplaycount) continue;
		}
	if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, zeiger, messagelist +MESSAGELIST_MAX, keyver, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m2(uint64_t eaptimestamp, uint8_t *macap, uint8_t *macclient, uint32_t restlen, uint8_t *eapauthptr)
{
static int c;
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

static const uint8_t foxtrott[4] = { 0xff, 0xff, 0xff, 0xff };

eapolm2count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen +EAPAUTH_SIZE > restlen) return;
if(authlen +EAPAUTH_SIZE > EAPOL_AUTHLEN_MAX) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver == 0) || (keyver > 3))
	{
	eapolm2kdv0count++;
	return;
	}
if(ntohs(wpak->wpadatalen) > (restlen -EAPAUTH_SIZE -WPAKEY_SIZE))
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 wpa data len > eap authentication len: %ld\n", rawpacketcount);
	eapolm2errorcount++;
	return;
	}
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if(memcmp(&zeroed32, wpak->nonce, 32) == 0) return;
if(memcmp(&zeroed32, wpak->keymic, 16) == 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 key mic zeroed: %ld\n", rawpacketcount);
	eapolm2errorcount++;
	return;
	}
for(c = 0; c < 12; c++)
	{
	if(memcmp(&zeroed32, &wpak->keymic[c], 4) == 0)
		{
		if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 key mic possible plcp bit error: %ld\n", rawpacketcount);
		eapolm2errorcount++;
		return;
		}
	if(memcmp(&foxtrott, &wpak->keymic[c], 4) == 0)
		{
		if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 key mic possible plcp bit error: %ld\n", rawpacketcount);
		eapolm2errorcount++;
		return;
		}
	}
if(memcmp(&zeroed32, wpak->keyiv, 16) != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 key iv != 0: %ld\n", rawpacketcount);
	eapolm2errorcount++;
	return;
	}
if(wpak->keyrsc != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 key rsc != 0: %ld\n", rawpacketcount);
	eapolm2errorcount++;
	return;
	}
if(memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M2 key id != 0: %ld\n", rawpacketcount);
	eapolm2errorcount++;
	return;
	}
if((memcmp(&fakenonce1, wpak->nonce, 32) == 0) && (rc == 17)) return; 
if((memcmp(&fakenonce2, wpak->nonce, 32) == 0) && (rc == 17)) return; 
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
	if(gettags(infolen, wpakptr +WPAKEY_SIZE, &tags) == false) return;
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
	if((zeiger->message &HS_M1) == HS_M1)
		{
		if(memcmp(zeiger->client, macclient, 6) != 0) continue;
		if(memcmp(zeiger->ap, macap, 6) != 0) continue;
		if(zeiger->rc >= rc) rcgap = zeiger->rc -rc;
		else rcgap = rc -zeiger->rc;
		if((rc != myaktreplaycount) && (zeiger->rc != myaktreplaycount))
			{
			if(rcgap > rcgapmax) rcgapmax = rcgap;
			}
		if(rcgap > ncvalue) continue;
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
		if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
		if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
		}
	if((zeiger->message &HS_M3) != HS_M3) continue;
	if(memcmp(zeiger->client, macclient, 6) != 0) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
	if(zeiger->rc >= rc +1) rcgap = zeiger->rc -rc -1;
	else rcgap = rc +1 -zeiger->rc;
	if(rc != myaktreplaycount)
		{
		if(rcgap > rcgapmax) rcgapmax = rcgap;
		}
	if(rcgap > ncvalue) continue;
	if(eaptimestamp > zeiger->timestamp) eaptimegap = eaptimestamp -zeiger->timestamp;
	else eaptimegap = zeiger->timestamp -eaptimestamp;
	mpfield = ST_M32E2;
	if(myaktreplaycount > 0)
		{
		if((rc == myaktreplaycount) && (memcmp(&myaktanonce, zeiger->nonce, 32) == 0))
			{
			eaptimegap = 0;
			mpfield |= ST_APLESS;
			}
		if(rcgap != 0) continue;
		}
	if(eaptimegap > eaptimegapmax) eaptimegapmax = eaptimegap; 
	if(eaptimegap <= eapoltimeoutvalue) addhandshake(eaptimegap, rcgap, messagelist +MESSAGELIST_MAX, zeiger, keyver, mpfield);
	}
qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
return;
}
/*===========================================================================*/
static void process80211eapol_m1(uint64_t eaptimestamp, uint8_t *macclient, uint8_t *macap, uint8_t *macsrc, uint32_t restlen, uint8_t *eapauthptr)
{
static int c;
static messagelist_t *zeiger;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static eapauth_t *eapauth;
static uint32_t authlen;
static pmkid_t *pmkid;
static uint8_t keyver;
static uint64_t rc;

static const uint8_t foxtrott[4] = { 0xff, 0xff, 0xff, 0xff };

eapolm1count++;
eapolmsgcount++;
eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > restlen) return;
wpakptr = eapauthptr +EAPAUTH_SIZE;
wpak = (wpakey_t*)wpakptr;
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver == 0) || (keyver > 3))
	{
	eapolm1kdv0count++;
	return;
	}
if(ntohs(wpak->wpadatalen) > (restlen -EAPAUTH_SIZE -WPAKEY_SIZE))
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M1 wpa data len > eap authentication len: %ld\n", rawpacketcount);
	eapolm1errorcount++;
	return;
	}
#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif
if(wpak->keyrsc != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M1 key rc != 0: %ld\n", rawpacketcount);
	eapolm1errorcount++;
	return;
	}
if(memcmp(&zeroed32, wpak->keyid, 8) != 0)
	{
	if(fh_log != NULL) fprintf(fh_log, "EAPOL M1 key id != 0: %ld\n", rawpacketcount);
	eapolm1errorcount++;
	return;
	}
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

if((zeiger->rc == myaktreplaycount) && (memcmp(&myaktanonce, zeiger->nonce, 32) == 0)) 
	{
	zeiger->status |= ST_APLESS;
	eapolm1ancount++;
	qsort(messagelist, MESSAGELIST_MAX +1, MESSAGELIST_SIZE, sort_messagelist_by_epcount);
	return;
	}
if(authlen >= (int)(WPAKEY_SIZE +PMKID_SIZE))
	{
	pmkid = (pmkid_t*)(wpakptr +WPAKEY_SIZE);
	if(pmkid->id != TAG_VENDOR) return;
	if((pmkid->len == 0x14) && (pmkid->type == 0x04))
		{
		zeiger->message |= HS_PMKID;
		if(memcmp(&zeroed32, pmkid->pmkid, 16) == 0)
			{
			pmkiduselesscount++;
			}
		else
			{
			for(c = 0; c < 12; c++)
				{
				if(memcmp(&zeroed32, &pmkid->pmkid[c], 4) == 0)
					{
					if(fh_log != NULL) fprintf(fh_log, "EAPOL M1 possible plcp bit error: %ld\n", rawpacketcount);
					eapolm1errorcount++;
					return;
					}
				if(memcmp(&foxtrott, &pmkid->pmkid[c], 4) == 0)
					{
					if(fh_log != NULL) fprintf(fh_log, "EAPOL M1 possible plcp bit error: %ld\n", rawpacketcount);
					eapolm1errorcount++;
					return;
					}
				}
			memcpy(zeiger->pmkid, pmkid->pmkid, 16);
			addpmkid(macclient, macsrc, pmkid->pmkid);
			}
		}
	else pmkiduselesscount++;
	}
for(zeiger = messagelist; zeiger < messagelist +MESSAGELIST_MAX +1; zeiger++)
	{
	if(((zeiger->message &HS_M1) != HS_M1) && ((zeiger->message &HS_M3) != HS_M3)) continue;
	if(memcmp(zeiger->ap, macap, 6) != 0) continue;
	eapolm1ancount++;
	if((memcmp(zeiger->nonce, wpak->nonce, 28) == 0) && (memcmp(&zeiger->nonce[28], &wpak->nonce[28], 4) != 0))
		{
		eapolnccount++;
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
static void process80211eapol(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t *macsrc, uint32_t eapauthlen, uint8_t *eapauthptr)
{
static eapauth_t *eapauth;
static uint32_t authlen;
static uint8_t *wpakptr;
static wpakey_t *wpak;
static uint16_t keyinfo;
static uint16_t keylen;

eapauth = (eapauth_t*)eapauthptr;
authlen = ntohs(eapauth->len);
if(authlen > eapauthlen)
	{
	eapolmsgerrorcount++;
	return;
	}
if(authlen < WPAKEY_SIZE)
	{
	eapolmsgerrorcount++;
	return;
	}
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
keylen = ntohs(wpak->keylen);
if((keylen != 0) && (keylen != 16) && (keylen != 32))
	{
	eapolmsgerrorcount++;
	return;
	}
if(keyinfo == 1) process80211eapol_m1(eaptimestamp, macto, macfm, macsrc, eapauthlen, eapauthptr);
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
static void process80211eap(uint64_t eaptimestamp, uint8_t *macto, uint8_t *macfm, uint8_t *macsrc, uint32_t restlen, uint8_t *eapptr)
{
static eapauth_t *eapauth;

eapauth = (eapauth_t*)eapptr;
if(restlen < (int)EAPAUTH_SIZE) return; 
if(eapauth->type == EAPOL_KEY)
	{
	process80211eapol(eaptimestamp, macto, macfm, macsrc, restlen, eapptr);
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
if(gettags(clientinfolen, clientinfoptr, &tags) == false) return;
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
if((tags.akm &TAK_PSK) == TAK_PSK) reassociationrequestpskcount++; 
else if((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256) reassociationrequestpsk256count++; 
else if((tags.akm &TAK_SAE_SHA256) == TAK_SAE_SHA256) reassociationrequestsae256count++; 
else if((tags.akm &TAK_SAE_SHA384B) == TAK_SAE_SHA384B) reassociationrequestsae384bcount++; 
else if((tags.akm &TAK_OWE) == TAK_OWE) reassociationrequestowecount++; 
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
if(gettags(clientinfolen, clientinfoptr, &tags) == false) return;
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
if(ignoreieflag == true)
	{
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
	}
else if(((tags.akm &TAK_PSK) == TAK_PSK) || ((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256))
	{
	if(memcmp(&zeroed32, tags.pmkid, 16) != 0) addpmkid(macclient, macap, tags.pmkid);
	}
if((tags.akm &TAK_PSK) == TAK_PSK) associationrequestpskcount++; 
else if((tags.akm &TAK_PSKSHA256) == TAK_PSKSHA256) associationrequestpsk256count++; 
else if((tags.akm &TAK_SAE_SHA256) == TAK_SAE_SHA256) associationrequestsae256count++; 
else if((tags.akm &TAK_SAE_SHA384B) == TAK_SAE_SHA384B) associationrequestsae384bcount++; 
else if((tags.akm &TAK_OWE) == TAK_OWE) associationrequestowecount++; 
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

authenticationcount++;
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
if(gettags(proberequestlen, proberequestptr, &tags) == false) return;
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
if(gettags(proberequestlen, proberequestptr, &tags) == false) return; 
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
if(gettags(apinfolen, apinfoptr, &tags) == false) return;
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
if(fh_csv != NULL) writecsv(proberesponsetimestamp, macap, &tags);
if(cleanbackmac() == false) aplistptr++;
if(fh_nmea != NULL) writegpwpl(macap);
return;
}
/*===========================================================================*/
static inline bool processpag(uint8_t *macap, int vendorlen, uint8_t *ieptr)
{
static int c, p;
static const uint8_t mac_pwag[6] =
{
0xde, 0xad, 0xbe, 0xef, 0xde, 0xad
};

if(ieptr[1] != 0xff) return false;
if(vendorlen <= 0x78) return false;
if(memcmp(&mac_pwag, macap, 6) != 0) return false;
for(p = 2; p < vendorlen -75 ; p++)
	{
	if(memcmp(&ieptr[p], "identity", 8) == 0)
		{
		for(c = 0; c < 64; c++)
			{
			if(!isxdigit(ieptr[p +11 +c])) return false;
			}
		pagcount++;
		return true;
		}
	}
return false;
}
/*===========================================================================*/
static void process80211beacon(uint64_t beacontimestamp, uint8_t *macbc, uint8_t *macap, uint32_t beaconlen, uint8_t *beaconptr)
{
static int apinfolen;
static uint8_t *apinfoptr;
static maclist_t *aplistnew;
static tags_t tags;

beaconcount++;
if(memcmp(&mac_broadcast, macbc, 6) != 0)
	{
	beaconerrorcount++;
	return;
	}
apinfoptr = beaconptr +CAPABILITIESAP_SIZE;
apinfolen = beaconlen -CAPABILITIESAP_SIZE;
if(apinfoptr[0] == TAG_PAG)
	{
	if(processpag(macap, apinfolen, apinfoptr) == true) return;
	}
if(beaconlen < (int)IETAG_SIZE) return;
if(gettags(apinfolen, apinfoptr, &tags) == false) return;
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
if(fh_csv != NULL) writecsv(beacontimestamp, macap, &tags);
if(cleanbackmac() == false) aplistptr++;
if(fh_nmea != NULL) writegpwpl(macap);
return;
}
/*===========================================================================*/
static void process80211actionvendor(uint32_t packetlen, uint8_t *packetptr)
{
static actvf_t *actvf;

if(packetlen < ACTIONVENDORFRAME_SIZE) return;
actvf = (actvf_t*)packetptr;
if(memcmp(actvf->vendor, &ouiapple, 3) == 0) awdlcount++;


return;
}
/*===========================================================================*/
static void process80211action(uint32_t packetlen, uint8_t *packetptr)
{
static actf_t *actf;

if(packetlen < ACTIONFRAME_SIZE) return;
actf = (actf_t*)packetptr;
actioncount++;
if(actf->categoriecode == CAT_VENDOR) process80211actionvendor(packetlen, packetptr);
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
	if(macfrx->subtype == IEEE80211_STYPE_BEACON) process80211beacon(packetimestamp, macfrx->addr1, macfrx->addr2, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_RESP) process80211probe_resp(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_AUTH) process80211authentication(macfrx->addr2, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_ASSOC_REQ) process80211association_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_REASSOC_REQ) process80211reassociation_req(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		if(memcmp(&mac_broadcast, macfrx->addr1, 6) == 0) process80211probe_req(packetimestamp, macfrx->addr2, payloadlen, payloadptr);
		else process80211probe_req_direct(packetimestamp, macfrx->addr2, macfrx->addr1, payloadlen, payloadptr);
		}
	else if(macfrx->subtype == IEEE80211_STYPE_ACTION) process80211action(payloadlen, payloadptr);
	else if(macfrx->subtype == IEEE80211_STYPE_DEAUTH) deauthenticationcount++;
	else if(macfrx->subtype == IEEE80211_STYPE_DISASSOC) disassociationcount++;
	else if(macfrx->subtype == IEEE80211_STYPE_MGTRESERVED) mgtreservedcount++;
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
		process80211eap(packetimestamp, macfrx->addr1, macfrx->addr2, macfrx->addr3, payloadlen -LLC_SIZE, payloadptr +LLC_SIZE);
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

if(caplen < LLC_SIZE) return;
eth2 = (eth2_t*)packetptr;
if(ntohs(eth2->ether_type) == LLC_TYPE_IPV4)
	{
	processipv4(timestamp, caplen -ETH2_SIZE, packetptr +ETH2_SIZE);
	}
else if(ntohs(eth2->ether_type) == LLC_TYPE_IPV6)
	{
	processipv6(timestamp, caplen -ETH2_SIZE, packetptr +ETH2_SIZE);
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
void processlobapacket(uint64_t timestamp, uint32_t caplen, uint8_t *packetptr)
{
static loba_t *loba;
if(caplen < LOBA_SIZE) return;
loba = (loba_t*)packetptr;
#ifdef BIG_ENDIAN_HOST
loba->family = byte_swap_32(loba->family);
#endif
if(loba->family == LOBA_IPV4) processipv4(timestamp, caplen -LOBA_SIZE, packetptr +LOBA_SIZE);
else if(loba->family == LOBA_IPV624) processipv6(timestamp, caplen -LOBA_SIZE, packetptr +LOBA_SIZE);
else if(loba->family == LOBA_IPV628) processipv6(timestamp, caplen -LOBA_SIZE, packetptr +LOBA_SIZE);
else if(loba->family == LOBA_IPV630) processipv6(timestamp, caplen -LOBA_SIZE, packetptr +LOBA_SIZE);
return;
}
/*===========================================================================*/
static void getradiotapfield(uint16_t rthlen, uint32_t caplen, uint8_t *capptr)
{
static int i;
static uint16_t pf;
static rth_t *rth;
static uint32_t *pp;

rth = (rth_t*)capptr;
pf = RTH_SIZE;
if((rth->it_present & IEEE80211_RADIOTAP_DBM_ANTSIGNAL) != IEEE80211_RADIOTAP_DBM_ANTSIGNAL) return;
if((rth->it_present & IEEE80211_RADIOTAP_EXT) == IEEE80211_RADIOTAP_EXT)
	{
	pp = (uint32_t*)capptr;
	for(i = 2; i < rthlen /4; i++)
		{
		#ifdef BIG_ENDIAN_HOST
		pp[i] = byte_swap_32(pp[i]);
		#endif
		pf += 4;
		if((pp[i] & IEEE80211_RADIOTAP_EXT) != IEEE80211_RADIOTAP_EXT) break;
		}
	}
if((pf %8) != 0) pf +=4;
if((rth->it_present & IEEE80211_RADIOTAP_TSFT) == IEEE80211_RADIOTAP_TSFT) pf += 8;
if((rth->it_present & IEEE80211_RADIOTAP_FLAGS) == IEEE80211_RADIOTAP_FLAGS) pf += 1;
if((rth->it_present & IEEE80211_RADIOTAP_RATE) == IEEE80211_RADIOTAP_RATE) pf += 1;
if((rth->it_present & IEEE80211_RADIOTAP_CHANNEL) == IEEE80211_RADIOTAP_CHANNEL) pf += 4;
if((rth->it_present & IEEE80211_RADIOTAP_FHSS) == IEEE80211_RADIOTAP_FHSS) pf += 2;
if(pf > caplen) return;
rssi = capptr[pf];
return;
}
/*===========================================================================*/
static void processlinktype(uint64_t captimestamp, uint32_t linktype, uint32_t caplen, uint8_t *capptr)
{
static uint8_t cs;
static uint32_t p;
static rth_t *rth;
static uint32_t packetlen;
static uint8_t *packetptr;
static ppi_t *ppi;
static prism_t *prism;
static avs_t *avs;
static fcs_t *fcs;
static uint32_t crc;

rssi = 0;
if(fh_raw_out != NULL)
	{
	cs = captimestamp &0xff;
	cs ^= (captimestamp >> 8) &0xff;
	cs ^= (captimestamp >> 16) &0xff;
	cs ^= (captimestamp >> 24) &0xff;
	cs ^= (captimestamp >> 32) &0xff;
	cs ^= (captimestamp >> 40) &0xff;
	cs ^= (captimestamp >> 48) &0xff;
	cs ^= (captimestamp >> 56) &0xff;
	cs ^= linktype &0xff;
	cs ^= (linktype >> 8) &0xff;
	cs ^= (linktype >> 16) &0xff;
	cs ^= (linktype >> 24) &0xff;
	#ifndef BIG_ENDIAN_HOST
	fprintf(fh_raw_out, "%016" PRIx64 "*%08x*", captimestamp, linktype);
	#else
	fprintf(fh_raw_out, "%016" PRIx64 "*%08x*", byte_swap_64(captimestamp), byte_swap_32(linktype));
	#endif
	for(p = 0; p < caplen; p++)
		{
		fprintf(fh_raw_out, "%02x", capptr[p]);
		cs ^= capptr[p];
		}
	fprintf(fh_raw_out, "*%02x\n", cs);
	}
if(captimestamp < captimestampold) sequenceerrorcount++;
captimestampold = captimestamp;
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
	if(caplen < RTH_SIZE)
		{
		pcapreaderrors++;
		radiotaperrorcount++;
		if(fh_log != NULL) fprintf(fh_log, "failed to read radiotap header: %ld\n", rawpacketcount);
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
		radiotaperrorcount++;
		if(fh_log != NULL) fprintf(fh_log, "failed to read radiotap header: %ld\n", rawpacketcount);
		return;
		}
	if(rth->it_version != 0)
		{
		pcapreaderrors++;
		radiotaperrorcount++;
		if(fh_log != NULL) fprintf(fh_log, "unsupported radiotap header version: %ld\n", rawpacketcount);
		return;
		}
	getradiotapfield(rth->it_len, caplen, capptr);
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
	if(caplen < PPI_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read ppi header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read ppi header: %ld\n", rawpacketcount);
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
		if(fh_log != NULL) fprintf(fh_log, "failed to read ppi header: %ld\n", rawpacketcount);
		return;
		}
	packetlen = caplen -ppi->pph_len;
	packetptr = capptr +ppi->pph_len;
	}
else if(linktype == DLT_PRISM_HEADER)
	{
	if(caplen < PRISM_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read prism header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read prism header: %ld\n", rawpacketcount);
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
			if(fh_log != NULL) fprintf(fh_log, "failed to read prism header: %ld\n", rawpacketcount);
			return;
			}
		prism->msglen = caplen -prism->frmlen.data;
		}
	packetlen = caplen -prism->msglen;
	packetptr = capptr +prism->msglen;
	}
else if(linktype == DLT_IEEE802_11_RADIO_AVS)
	{
	if(caplen < AVS_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read avs header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read avs header: %ld\n", rawpacketcount);
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
		if(fh_log != NULL) fprintf(fh_log, "failed to read avs header: %ld\n", rawpacketcount);
		return;
		}
	packetlen = caplen -avs->len;
	packetptr = capptr +avs->len;
	}
else if(linktype == DLT_EN10MB)
	{
	if(caplen < ETH2_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read ethernet header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read ethernet header: %ld\n", rawpacketcount);
		return;
		}
	processethernetpacket(captimestamp, caplen, capptr);
	return;
	}
else if(linktype == DLT_NULL)
	{
	if(caplen < LOBA_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read loopback header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read loopback header: %ld\n", rawpacketcount);
		return;
		}
	processlobapacket(captimestamp, caplen, capptr);
	return;
	}
else
	{
	printf("unsupported network type %d\n", linktype);
	if(fh_log != NULL) fprintf(fh_log, "unsupported network type %d: %ld\n", linktype, rawpacketcount);
	return;
	}

if(packetlen < 4)
	{
	pcapreaderrors++;
	printf("failed to read packet\n");
	if(fh_log != NULL) fprintf(fh_log, "failed to read packet (len < 4): %ld\n", rawpacketcount);
	return;
	}
fcs = (fcs_t*)(packetptr +packetlen -4);
crc = fcscrc32check(packetptr, packetlen -4);
#ifdef BIG_ENDIAN_HOST
crc = byte_swap_32(crc);
#endif
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
iface = 1;
res = read(fd, &pcapfhdr, PCAPHDR_SIZE);
if(res != PCAPHDR_SIZE)
	{
	pcapreaderrors++;
	printf("failed to read pcap header\n");
	if(fh_log != NULL) fprintf(fh_log, "failed to read pcap header: %s\n", basename(pcapinname));
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

dltlinktype[0] = pcapfhdr.network;
if(pcapfhdr.version_major != PCAP_MAJOR_VER)
	{
	pcapreaderrors++;
	printf("unsupported major pcap version\n");
	if(fh_log != NULL) fprintf(fh_log, "unsupported major pcap version: %d\n", pcapfhdr.version_major);
	return;
	}
if(pcapfhdr.version_minor != PCAP_MINOR_VER)
	{
	pcapreaderrors++;
	printf("unsupported minor pcap version\n");
	if(fh_log != NULL) fprintf(fh_log, "unsupported minor pcap version: %d\n", pcapfhdr.version_minor);
	return;
	}
if(pcapfhdr.snaplen > MAXPACPSNAPLEN)
	{
	pcapreaderrors++;
	printf("detected oversized snaplen (%d)\n", pcapfhdr.snaplen);
	if(fh_log != NULL) fprintf(fh_log, "detected oversized snaplen (%d): %d\n",  pcapfhdr.snaplen, pcapfhdr.version_minor);
	}

while(1)
	{
	res = read(fd, &pcaprhdr, PCAPREC_SIZE);
	if(res == 0) break;
	if(res != PCAPREC_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read pcap packet header for packet %ld\n", rawpacketcount);
		if(fh_log != NULL) fprintf(fh_log, "failed to read pcap packet header: %ld\n", rawpacketcount);
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
		if(fh_log != NULL) fprintf(fh_log, "inclusive length > snaplen: %ld\n", rawpacketcount);
		}
	if(pcaprhdr.incl_len < MAXPACPSNAPLEN)
		{
		rawpacketcount++;
		res = read(fd, &packet, pcaprhdr.incl_len);
		if(res != pcaprhdr.incl_len)
			{
			pcapreaderrors++;
			printf("failed to read packet %ld\n", rawpacketcount);
			if(fh_log != NULL) fprintf(fh_log, "packet error: %ld\n", rawpacketcount);
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
			if(fh_log != NULL) fprintf(fh_log, "failed to set file pointer: %s\n", basename(pcapinname));
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
	"file name................................: %s\n"
	"version (pcap/cap).......................: %d.%d (very basic format without any additional information)\n"  
	, basename(pcaporgname), versionmajor, versionminor
	);

printlinklayerinfo();
cleanupmac();
outputwpalists();
outputeapmd5hashlist();
outputeapleaphashlist();
outputeapmschapv2hashlist();
outputtacacsplist();
outputwordlists();
printcontentinfo();

return;
}
/*===========================================================================*/
int pcapngoptionwalk(uint32_t blocktype, uint8_t *optr, int restlen)
{
static int csn, csc, pn;
static int padding;
static option_header_t *option;

while(0 <= restlen)
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
	if(option->option_code == SHB_EOC) return 0;
	padding = 0;
	if(option->option_length > OPTIONLEN_MAX) return option->option_length;
	if((option->option_length  %4)) padding = 4 -(option->option_length %4);
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
	else if(option->option_code == IF_TSRESOL)
		{
		if(option->option_length == 1) pcapngtimeresolution = option->data[0];
		}
	else if(option->option_code == SHB_CUSTOM_OPT)
		{
		if(option->option_length > 40)
			{
			if((memcmp(&option->data[0], &hcxmagic, 4) == 0) && (memcmp(&option->data[4], &hcxmagic, 32) == 0)) restlen = pcapngoptionwalk(blocktype, optr +OH_SIZE +36, option->option_length -36);
			else if((memcmp(&option->data[1], &hcxmagic, 4) == 0) && (memcmp(&option->data[5], &hcxmagic, 32) == 0)) restlen = pcapngoptionwalk(blocktype, optr +OH_SIZE +1 +36, option->option_length -36);
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
			if(endianess == 1) myaktreplaycount = byte_swap_64(myaktreplaycount);
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
		if(fh_nmea != NULL)
			{
			if(option->option_length >= 48)
				{
				nmealen = option->option_length;
				memset(&nmeasentence, 0, OPTIONLEN_MAX);
				memcpy(&nmeasentence, &option->data, option->option_length);
				csc = 0;
				csn = 0;
				pn = 1;
				while((nmeasentence[pn] != 0) && (nmeasentence[pn] != '*'))
					{
					csn ^= nmeasentence[pn];
					pn++;
					}
				if(nmeasentence[pn] == '*')
					{
					csc = strtol(&nmeasentence[option->option_length -2], NULL, 16);
					if(csn == csc)
						{
						if(fh_nmea!= NULL) fprintf(fh_nmea, "%s\n", nmeasentence);
						nmeacount++;
						}
					else
						{
						nmealen = 0;
						nmeaerrorcount++;
						}
					}
				}
			}
		}
	optr += option->option_length +padding +OH_SIZE;
	restlen -= option->option_length +padding +OH_SIZE;
	}
return 0;
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

static int interfaceid[MAX_INTERFACE_ID];
static uint8_t pcpngblock[2 *MAXPACPSNAPLEN];
static uint8_t packet[MAXPACPSNAPLEN];

printf("reading from %s...\n", basename(pcapinname));
iface = 0;
nmealen = 0;
memset(&interfaceid, 0, sizeof(int) *MAX_INTERFACE_ID);
fdsize = lseek(fd, 0, SEEK_END);
if(fdsize < 0)
	{
	pcapreaderrors++;
	printf("failed to get file size\n");
	if(fh_log != NULL) fprintf(fh_log, "failed to get file size: %s\n", basename(pcapinname));
	return;
	}

aktseek = lseek(fd, 0L, SEEK_SET);
if(aktseek < 0)
	{
	pcapreaderrors++;
	printf("failed to set file pointer\n");
	if(fh_log != NULL) fprintf(fh_log, "failed to set file pointer: %s\n", basename(pcapinname));
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
		if(fh_log != NULL) fprintf(fh_log, "failed to set file pointer: %s\n", basename(pcapinname));
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
		if(fh_log != NULL) fprintf(fh_log, "failed to read block header: %s\n", basename(pcapinname));
		break;
		}
	pcapngbh = (block_header_t*)pcpngblock;
	blocktype = pcapngbh->block_type;
	blocklen =  pcapngbh->total_length;
	blockmagic = pcapngbh->byte_order_magic;
	#ifdef BIG_ENDIAN_HOST
	blocktype = byte_swap_32(blocktype);
	blocklen = byte_swap_32(blocklen);
	blockmagic = byte_swap_32(blockmagic);
	#endif
	if(blocktype == PCAPNGBLOCKTYPE)
		{
		if(blockmagic == PCAPNGMAGICNUMBERBE) endianess = 1;
		}
	if(endianess == 1)
		{
		blocktype = byte_swap_32(blocktype);
		blocklen = byte_swap_32(blocklen);
		}
	if((blocklen > (2 *MAXPACPSNAPLEN)) || ((blocklen %4) != 0))
		{
		pcapreaderrors++;
		printf("failed to read pcapng block header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read pcapng block header: %ld\n", rawpacketcount);
		break;
		}
	resseek = lseek(fd, aktseek, SEEK_SET);
	if(resseek < 0)
		{
		pcapreaderrors++;
		printf("failed to set file pointer\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to set file pointer: %s\n", basename(pcapinname));
		break;
		}
	res = read(fd, &pcpngblock, blocklen);
	if((res < BH_SIZE) || (res != blocklen))
		{
		pcapreaderrors++;
		printf("failed to read pcapng block header\n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read pcapng block header: %ld\n", rawpacketcount);
		break;
		}
	if(memcmp(&pcpngblock[4], &pcpngblock[ blocklen -4], 4) != 0)
		{
		pcapreaderrors++;
		printf("failed to read pcapng block header \n");
		if(fh_log != NULL) fprintf(fh_log, "failed to read pcapng block header: %ld\n", rawpacketcount);
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
			printf("unsupported major pcapng version\n");
			if(fh_log != NULL) fprintf(fh_log, "unsupported major pcapng version: %d\n", pcapngshb->major_version);
			break;
			}
		if(pcapngshb->minor_version != PCAPNG_MINOR_VER)
			{
			pcapreaderrors++;
			printf("unsupported minor pcapng version\n");
			if(fh_log != NULL) fprintf(fh_log, "unsupported minor pcapng version: %d\n", pcapngshb->minor_version);
			break;
			}
		if(pcapngoptionwalk(blocktype, pcapngshb->data, blocklen -SHB_SIZE) != 0) pcapreaderrors++;
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
		snaplen = pcapngidb->snaplen;
		if(pcapngoptionwalk(blocktype, pcapngidb->data, blocklen -IDB_SIZE) != 0) pcapreaderrors++;
		if(snaplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("detected oversized snaplen (%d)\n", snaplen);
			if(fh_log != NULL) fprintf(fh_log, "detected oversized snaplen: %ld\n", rawpacketcount);
			}
		if(iface >= MAX_INTERFACE_ID)
			{
			pcapreaderrors++;
			printf("maximum of supported interfaces reached: %d\n", iface);
			if(fh_log != NULL) fprintf(fh_log, "maximum of supported interfaces reached: %d\n", iface);
			continue;
			}
		dltlinktype[iface] = pcapngidb->linktype;
		timeresolval[iface] = pcapngtimeresolution;
		iface++;
		}
	else if(blocktype == PBID)
		{
		pcapngpb = (packet_block_t*)pcpngblock;
		#ifdef BIG_ENDIAN_HOST
		pcapngpb->caplen = byte_swap_32(pcapngpb->caplen);
		#endif
		if(endianess == 1) pcapngpb->caplen	= byte_swap_32(pcapngpb->caplen);
		timestamppcapng = 0;
		if(pcapngpb->caplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("caplen > MAXSNAPLEN (%d > %d)\n", pcapngpb->caplen, MAXPACPSNAPLEN);
			if(fh_log != NULL) fprintf(fh_log, "caplen > MAXSNAPLEN: %ld\n", rawpacketcount);
			continue;
			}
		if(pcapngpb->caplen > blocklen)
			{
			pcapreaderrors++;
			printf("caplen > blocklen (%d > %d)\n", pcapngpb->caplen, blocklen);
			if(fh_log != NULL) fprintf(fh_log, "caplen > blocklen: %ld\n", rawpacketcount);
			continue;
			}
		rawpacketcount++;
		processlinktype(timestamppcapng, dltlinktype[0], pcapngpb->caplen, pcapngpb->data);
		}
	else if(blocktype == SPBID) continue;
	else if(blocktype == NRBID) continue;
	else if(blocktype == ISBID) continue;
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
		if(pcapngepb->interface_id >= iface)
			{
			pcapreaderrors++;
			printf("maximum of supported interfaces reached: %d\n", iface);
			if(fh_log != NULL) printf("maximum of supported interfaces reached: %d\n", iface);
			continue;
			}
		timestamppcapng = pcapngepb->timestamp_high;
		timestamppcapng = (timestamppcapng << 32) +pcapngepb->timestamp_low;

		if(timeresolval[pcapngepb->interface_id] == TSRESOL_NSEC)
			{
			timestamppcapng = pcapngepb->timestamp_high / 1000;
			timestamppcapng = (timestamppcapng << 32) +pcapngepb->timestamp_low;
			}
		if(pcapngepb->caplen != pcapngepb->len)
			{
			pcapreaderrors++;
			printf("caplen != len (%d != %d)\n", pcapngepb->caplen, pcapngepb->len);
			if(fh_log != NULL) fprintf(fh_log, "caplen != len: %ld\n", rawpacketcount);
			continue;
			}
		if(pcapngepb->caplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("caplen > MAXSNAPLEN (%d > %d)\n", pcapngepb->caplen, MAXPACPSNAPLEN);
			if(fh_log != NULL) fprintf(fh_log, "caplen > MAXSNAPLEN: %ld\n", rawpacketcount);
			continue;
			}
		if(pcapngepb->caplen > blocklen)
			{
			pcapreaderrors++;
			printf("caplen > blocklen (%d > %d)\n", pcapngepb->caplen, blocklen);
			if(fh_log != NULL) fprintf(fh_log, "caplen > blocklen: %ld\n", rawpacketcount);
			continue;
			}
		rawpacketcount++;
		processlinktype(timestamppcapng, dltlinktype[pcapngepb->interface_id], pcapngepb->caplen, pcapngepb->data);
		padding = 0;
		if((pcapngepb->caplen %4)) padding = 4 -(pcapngepb->caplen %4);
		if(pcapngoptionwalk(blocktype, pcapngepb->data +pcapngepb->caplen +padding, blocklen -EPB_SIZE -pcapngepb->caplen -padding) != 0) pcapreaderrors++;
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
		if(pcapngoptionwalk(blocktype, pcapngcb->data, blocklen -CB_SIZE) != 0) pcapreaderrors++;
		}
	else
		{
		skippedpacketcount++;
		}
	}

printf("\nsummary capture file\n"
	"--------------------\n"
	"file name................................: %s\n"
	"version (pcapng).........................: %d.%d\n"
	"operating system.........................: %s\n"
	"application..............................: %s\n"
	"interface name...........................: %s\n"
	"interface vendor.........................: %02x%02x%02x\n"
	"openSSL version..........................: %d.%d\n"
	"weak candidate...........................: %s\n"
	"MAC ACCESS POINT.........................: %02x%02x%02x%02x%02x%02x (incremented on every new client)\n"
	"MAC CLIENT...............................: %02x%02x%02x%02x%02x%02x\n"
	"REPLAYCOUNT..............................: %"  PRIu64  "\n"
	"ANONCE...................................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	"SNONCE...................................: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x\n"
	, basename(pcaporgname), versionmajor, versionminor,
	pcapngosinfo, pcapngapplinfo, pcapnghwinfo, pcapngdeviceinfo[0], pcapngdeviceinfo[1], pcapngdeviceinfo[2],
	opensslversionmajor, opensslversionminor,
	pcapngweakcandidate,
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
outputeapmschapv2hashlist();
outputtacacsplist();
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
	gzipstat++;
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
	if(fh_log != NULL) fprintf(fh_log, "failed to set file pointer: %s\n", pcapinname);
	return false;
	}

if(magicnumber == PCAPNGBLOCKTYPE)
	{
	if(initlists() == true)
		{
		processpcapng(fd_pcap, pcapinname, pcapnameptr);
		pcapngstat++;
		close(fd_pcap);
		closelists();
		}
	}

else if((magicnumber == PCAPMAGICNUMBER) || (magicnumber == PCAPMAGICNUMBERBE))
	{
	if(magicnumber == PCAPMAGICNUMBERBE) endianess = 1;
	if(initlists() == true)
		{
		processcap(fd_pcap, pcapinname, pcapnameptr);
		capstat++;
		close(fd_pcap);
		closelists();
		}
	}

if(pcaptempnameptr != NULL) remove(pcaptempnameptr);

return true;
}
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream)) return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool processrawfile(char *rawinname)
{
static int len;
static int pos;
static long int linecount;
static FILE *fh_raw_in;
static uint64_t timestampraw;
static uint16_t linktyperaw;
static uint8_t cs, ct;
static uint32_t caplenraw;
uint8_t idx0;
uint8_t idx1;
static char *csptr;
static char *stopptr = NULL;

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

static char linein[RAW_LEN_MAX];
static uint8_t packet[MAXPACPSNAPLEN];

if(initlists() == false) return false;
if((fh_raw_in = fopen(rawinname, "r")) == NULL)
	{
	fprintf(stderr, "failed to open raw file %s\n", rawinname);
	return false;
	}
linecount = 0;
while(1)
	{
	if((len = fgetline(fh_raw_in, RAW_LEN_MAX, linein)) == -1) break;
	linecount++;
	if(len < 30) continue;
	if((linein[16] != '*') && (linein[25] != '*'))
		{
		printf("delimiter error line: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "delimiter error line: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	csptr = strchr(linein +26, '*');
	if(csptr == NULL)
		{
		printf("delimiter error line: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "delimiter error line: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	if(((csptr -linein) %2) != 0)
		{
		printf("delimiter error line: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "delimiter error line: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	if((len -(csptr -linein)) < 3)
		{
		printf("delimiter error line: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "delimiter error line: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	timestampraw = strtoull(linein, &stopptr, 16);
	if((stopptr == NULL) || ((stopptr -linein) != 16))
		{
		printf("timestamp error line: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "timestamp error line: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	#ifdef BIG_ENDIAN_HOST
	timestampraw = byte_swap_64(timestampraw);
	#endif
	linktyperaw = strtoul(&linein[17], &stopptr, 16);
	if((stopptr == NULL) || ((stopptr -linein) != 25))
		{
		printf("linktype error line: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "linktype error line: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	#ifdef BIG_ENDIAN_HOST
	linktyperaw = byte_swap_16(linktyperaw);
	#endif
	cs = timestampraw &0xff;
	cs ^= (timestampraw >> 8) &0xff;
	cs ^= (timestampraw >> 16) &0xff;
	cs ^= (timestampraw >> 24) &0xff;
	cs ^= (timestampraw >> 32) &0xff;
	cs ^= (timestampraw >> 40) &0xff;
	cs ^= (timestampraw >> 48) &0xff;
	cs ^= (timestampraw >> 56) &0xff;
	cs ^= linktyperaw &0xff;
	cs ^= (linktyperaw >> 8) &0xff;
	cs ^= (linktyperaw >> 16) &0xff;
	cs ^= (linktyperaw >> 24) &0xff;
	caplenraw = 0;
	for (pos = 0; ((pos < MAXPACPSNAPLEN) && (pos < RAW_LEN_MAX)); pos += 2)
		{
		if(linein[26 +pos] == 0)
			{
			printf("frame error line: %ld\n", linecount);
			if(fh_log != NULL) fprintf(fh_log, "frame error line: %ld\n", linecount);
			pcapreaderrors++;
			continue;
			}
		if(linein[26 +pos] == '*') break;
		idx0 = ((uint8_t)linein[26 +pos +0] & 0x1F) ^ 0x10;
		idx1 = ((uint8_t)linein[26 +pos +1] & 0x1F) ^ 0x10;
		packet[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
		cs ^= packet[pos/2];
		caplenraw++;
		};
	if((len -pos -26) < 3)
		{
		printf("line length error: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "line length error: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	ct = strtoul(&linein[26 +pos +1], &stopptr, 16);
	if((stopptr == NULL) || ((stopptr -linein) != len))
		{
		printf("line length error: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "line length error: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	if(ct != cs)
		{
		printf("checksum error: %ld\n", linecount);
		if(fh_log != NULL) fprintf(fh_log, "checksum error: %ld\n", linecount);
		pcapreaderrors++;
		continue;
		}
	processlinktype(timestampraw, linktyperaw, caplenraw, packet);
	rawpacketcount++;
	}

printf("\nsummary raw file\n"
	"----------------\n"
	"file name................................: %s\n"
	"lines read...............................: %ld\n"
	, basename(rawinname),linecount);

printlinklayerinfo();
cleanupmac();
outputwpalists();
outputwordlists();
outputeapmd5hashlist();
outputeapleaphashlist();
outputeapmschapv2hashlist();
printcontentinfo();

fclose(fh_raw_in);
return true ;
}
/*===========================================================================*/
static bool testfilename(char *filename1, char *filename2)
{
if(filename1 == NULL) return false;
if(filename2 == NULL) return false;
if(strcmp(filename1, filename2) != 0) return false;
printf("same file names for different file types is not allowed: %s - %s\n", filename1, filename2);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"convert pcapng, pcap and cap files to hash formats that hashcat and JtR use\n"
	"usage:\n"
	"%s <options>\n"
	"%s <options> input.pcapng\n"
	"%s <options> *.pcapng\n"
	"%s <options> *.pcap\n"
	"%s <options> *.cap\n"
	"%s <options> *.*\n"
	"\n"
	"short options:\n"
	"-o <file> : output WPA-PBKDF2-PMKID+EAPOL (hashcat -m 22000)hash file\n"
	"            get full advantage of reuse of PBKDF2 on PMKID and EAPOL\n"
	"-E <file> : output wordlist (autohex enabled on non ASCII characters) to use as input wordlist for cracker\n"
	"            retrieved from every frame that contain an ESSID\n"
	"-R <file> : output wordlist (autohex enabled on non ASCII characters) to use as input wordlist for cracker\n"
	"            retrieved from PROBEREQUEST frames only\n"
	"-I <file> : output unsorted identity list to use as input wordlist for cracker\n"
	"-U <file> : output unsorted username list to use as input wordlist for cracker\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"long options:\n"
	"--all                              : convert all possible hashes instead of only the best one\n"
	"                                     that can lead to much overhead hashes\n"
	"                                     use hcxhashtool to filter hashes\n"
	"                                     need hashcat --nonce-error-corrections >= 8\n"
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
	"--eapleap=<file>                   : output EAP LEAP and MSCHAPV2 CHALLENGE (hashcat -m 5500, john netntlm)\n"
	"--tacacs-plus=<file>               : output TACACS PLUS (hashcat -m 16100, john tacacs-plus)\n"
	"--nmea=<file>                      : output GPS data in NMEA format\n"
	"                                     format: NMEA 0183 $GPGGA, $GPRMC, $GPWPL\n"
	"                                     to convert it to gpx, use GPSBabel:\n"
	"                                     gpsbabel -i nmea -f hcxdumptool.nmea -o gpx,gpxver=1.1 -F hcxdumptool.gpx\n"
	"                                     to display the track, open file.gpx with viking\n"
	"--csv=<file>                       : output ACCESS POINT information in CSV format\n"
	"                                     delimiter: tabulator (0x08)\n"
	"                                     columns:\n"
	"                                     YYYY-MM-DD HH:MM:SS MAC_AP ESSID ENC_TYPE CIPHER AKM COUNTRY_INFO CHANNEL RSSI\n"
	"                                     to convert it to other formats, use bash tools or scripting languages\n"
	"--log=<file>                       : output logfile\n"
	"--raw-out=<file>                   : output frames in HEX ASCII\n"
	"                                   : format: TIMESTAMP*LINKTYPE*FRAME*CHECKSUM\n"
	"--raw-in=<file>                    : input frames in HEX ASCII\n"
	"                                   : format: TIMESTAMP*LINKTYPE*FRAME*CHECKSUM\n"
	"--pmkid=<file>                     : output deprecated PMKID file (delimter *)\n"
	"--hccapx=<file>                    : output deprecated hccapx v4 file\n"
	"--hccap=<file>                     : output deprecated hccap file\n"
	"--john=<file>                      : output deprecated PMKID/EAPOL (JtR wpapsk-opencl/wpapsk-pmk-opencl)\n"
	"--prefix=<file>                    : convert everything to lists using this prefix (overrides single options):\n"
	"                                      -o <file.22000>           : output PMKID/EAPOL hash file\n"
	"                                      -E <file.essid>           : output wordlist (autohex enabled on non ASCII characters) to use as input wordlist for cracker\n"
	"                                      -I <file.identitiy>       : output unsorted identity list to use as input wordlist for cracker\n"
	"                                      -U <file.username>        : output unsorted username list to use as input wordlist for cracker\n"
	"                                     --eapmd5=<file.4800>       : output EAP MD5 CHALLENGE (hashcat -m 4800)\n"
	"                                     --eapleap=<file.5500>      : output EAP LEAP and MSCHAPV2 CHALLENGE (hashcat -m 5500, john netntlm)\n"
	"                                     --tacacs-plus=<file.16100> : output TACACS+ (hashcat -m 16100, john tacacs-plus)\n"
	"                                     --nmea=<file.nmea>         : output GPS data in NMEA format\n"
	"--help                             : show this help\n"
	"--version                          : show version\n"
	"\n"
	"bitmask for message pair field:\n"
	"bit 0-2\n"
	" 000 = M1+M2, EAPOL from M2 (challenge)\n"
	" 001 = M1+M4, EAPOL from M4 if not zeroed (authorized)\n"
	" 010 = M2+M3, EAPOL from M2 (authorized)\n"
	" 011 = M2+M3, EAPOL from M3 (authorized) - unused\n"
	" 100 = M3+M4, EAPOL from M3 (authorized) - unused\n"
	" 101 = M3+M4, EAPOL from M4 if not zeroed (authorized)\n"
	"3: reserved\n"
	"4: ap-less attack (set to 1) - no nonce-error-corrections necessary\n"
	"5: LE router detected (set to 1) - nonce-error-corrections only for LE necessary\n"
	"6: BE router detected (set to 1) - nonce-error-corrections only for BE necessary\n"
	"7: not replaycount checked (set to 1) - replaycount not checked, nonce-error-corrections definitely necessary\n"
	"\n"
	"Do not edit, merge or convert pcapng files! This will remove optional comment fields!\n"
	"Detection of bit errors does not work on cleaned dump files!\n"
	"Do not use %s in combination with third party cap/pcap/pcapng cleaning tools (except: tshark and/or Wireshark)!\n"
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcapngtool will understand this.\n"
	"Recommended tool to convert to hash formats accepted by hashcat and john: hcxpcapngtool\n"
	"Recommended tools to show additional 802.11 fields or to decrypt WiFi traffic: Wireshark and/or tshark\n"
	"\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname, eigenname, eigenname, eigenname, eigenname,
	EAPOLTIMEOUT /1000, NONCEERRORCORRECTION, ESSIDSMAX,
	eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static int exitcode;
static char *pmkideapoloutname;
static char *eapmd5outname;
static char *eapmd5johnoutname;
static char *eapleapoutname;
static char *tacacspoutname;
static char *essidoutname;
static char *essidproberequestoutname;
static char *identityoutname;
static char *usernameoutname;
static char *nmeaoutname;
static char *csvoutname;
static char *logoutname;
static char *rawoutname;
static char *rawinname;
static char *pmkideapoljtroutnamedeprecated;
static char *pmkidoutnamedeprecated;
static char *hccapxoutnamedeprecated;
static char *hccapoutnamedeprecated;

static const char *prefixoutname;
static const char *pmkideapolsuffix = ".22000";
static const char *eapmd5suffix = ".4800";
static const char *eapleapsuffix = ".5500";
static const char *tacacspsuffix = ".16100";
static const char *essidsuffix = ".essid";
static const char *essidproberequestsuffix = ".essidproberequest";
static const char *identitysuffix = ".identity";
static const char *usernamesuffix = ".username";
static const char *nmeasuffix = ".nmea";
static const char *csvsuffix = ".csv";

static char pmkideapolprefix[PATH_MAX];
static char eapmd5prefix[PATH_MAX];
static char eapleapprefix[PATH_MAX];
static char tacacspprefix[PATH_MAX];
static char essidprefix[PATH_MAX];
static char essidproberequestprefix[PATH_MAX];
static char identityprefix[PATH_MAX];
static char usernameprefix[PATH_MAX];
static char nmeaprefix[PATH_MAX];
static char csvprefix[PATH_MAX];

struct timeval tv;
static struct stat statinfo;

static const char *short_options = "o:E:R:I:U:hv";
static const struct option long_options[] =
{
	{"all",				no_argument,		NULL,	HCX_CONVERT_ALL},
	{"eapoltimeout",		required_argument,	NULL,	HCX_EAPOL_TIMEOUT},
	{"nonce-error-corrections",	required_argument,	NULL,	HCX_NC},
	{"ignore-ie",			no_argument,		NULL,	HCX_IE},
	{"max-essids",			required_argument,	NULL,	HCX_ESSIDS},
	{"nmea",			required_argument,	NULL,	HCX_NMEA_OUT},
	{"csv",				required_argument,	NULL,	HCX_CSV_OUT},
	{"raw-out",			required_argument,	NULL,	HCX_RAW_OUT},
	{"raw-in",			required_argument,	NULL,	HCX_RAW_IN},
	{"log",				required_argument,	NULL,	HCX_LOG_OUT},
	{"pmkid",			required_argument,	NULL,	HCX_PMKID_OUT_DEPRECATED},
	{"eapmd5",			required_argument,	NULL,	HCX_EAPMD5_OUT},
	{"eapmd5-john",			required_argument,	NULL,	HCX_EAPMD5_JOHN_OUT},
	{"eapleap",			required_argument,	NULL,	HCX_EAPLEAP_OUT},
	{"tacacs-plus",			required_argument,	NULL,	HCX_TACACSP_OUT},
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
exitcode = EXIT_SUCCESS;
ignoreieflag = false;
donotcleanflag = false;
eapoltimeoutvalue = EAPOLTIMEOUT;
ncvalue = NONCEERRORCORRECTION;
essidsvalue = ESSIDSMAX;

pmkideapoloutname = NULL;
eapmd5outname = NULL;
eapmd5johnoutname = NULL;
eapleapoutname = NULL;
tacacspoutname = NULL;
essidoutname = NULL;
essidproberequestoutname = NULL;
identityoutname = NULL;
usernameoutname = NULL;
nmeaoutname = NULL;
csvoutname = NULL;
logoutname = NULL;
rawoutname = NULL;
rawinname = NULL;
prefixoutname = NULL;
pmkideapoljtroutnamedeprecated = NULL;
pmkidoutnamedeprecated = NULL;
hccapxoutnamedeprecated = NULL;
hccapoutnamedeprecated = NULL;

fh_pmkideapol = NULL;
fh_eapmd5 = NULL;
fh_eapmd5john = NULL;
fh_eapleap = NULL;
fh_tacacsp = NULL;
fh_essid = NULL;
fh_essidproberequest = NULL;
fh_identity = NULL;
fh_username = NULL;
fh_nmea = NULL;
fh_csv = NULL;
fh_log = NULL;
fh_raw_out = NULL;
fh_pmkideapoljtrdeprecated = NULL;
fh_pmkiddeprecated = NULL;
fh_hccapxdeprecated = NULL;
fh_hccapdeprecated = NULL;

gzipstat = 0;
capstat = 0;
pcapngstat = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCX_EAPOL_TIMEOUT:
		eapoltimeoutvalue = strtoull(optarg, NULL, 10);
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

		case HCX_TACACSP_OUT:
		tacacspoutname = optarg;
		break;

		case HCX_ESSID_OUT:
		essidoutname = optarg;
		break;

		case HCX_ESSIDPROBEREQUEST_OUT:
		essidproberequestoutname = optarg;
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

		case HCX_CSV_OUT:
		csvoutname = optarg;
		break;

		case HCX_RAW_OUT:
		rawoutname = optarg;
		break;

		case HCX_RAW_IN:
		rawinname = optarg;
		break;

		case HCX_LOG_OUT:
		logoutname = optarg;
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

if((optind == argc) && (rawinname == NULL))
	{
	printf("no input file(s) selected\n");
	exit(EXIT_FAILURE);
	}

if(testfilename(pmkideapoloutname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, eapmd5outname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, eapleapoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, tacacspoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, nmeaoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, csvoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, rawoutname) == true) exit(EXIT_FAILURE);
if(testfilename(pmkideapoloutname, logoutname) == true) exit(EXIT_FAILURE);

if(testfilename(eapmd5outname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, eapleapoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, tacacspoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, nmeaoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, csvoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, rawoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapmd5outname, logoutname) == true) exit(EXIT_FAILURE);

if(testfilename(eapleapoutname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, tacacspoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, nmeaoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, csvoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, rawoutname) == true) exit(EXIT_FAILURE);
if(testfilename(eapleapoutname, logoutname) == true) exit(EXIT_FAILURE);

if(testfilename(tacacspoutname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, nmeaoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, csvoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, rawoutname) == true) exit(EXIT_FAILURE);
if(testfilename(tacacspoutname, logoutname) == true) exit(EXIT_FAILURE);

if(testfilename(nmeaoutname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(nmeaoutname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(nmeaoutname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(nmeaoutname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(nmeaoutname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);
if(testfilename(nmeaoutname, rawoutname) == true) exit(EXIT_FAILURE);
if(testfilename(nmeaoutname, logoutname) == true) exit(EXIT_FAILURE);

if(testfilename(rawoutname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(rawoutname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(rawoutname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(rawoutname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(rawoutname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);
if(testfilename(rawoutname, logoutname) == true) exit(EXIT_FAILURE);

if(testfilename(logoutname, essidoutname) == true) exit(EXIT_FAILURE);
if(testfilename(logoutname, essidproberequestoutname) == true) exit(EXIT_FAILURE);
if(testfilename(logoutname, identityoutname) == true) exit(EXIT_FAILURE);
if(testfilename(logoutname, usernameoutname) == true) exit(EXIT_FAILURE);
if(testfilename(logoutname, eapmd5johnoutname) == true) exit(EXIT_FAILURE);

if(prefixoutname != NULL)
	{
	strncpy(pmkideapolprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(pmkideapolprefix, pmkideapolsuffix, PREFIX_BUFFER_MAX);
	pmkideapoloutname = pmkideapolprefix;

	strncpy(essidprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(essidprefix, essidsuffix, PREFIX_BUFFER_MAX);
	essidoutname = essidprefix;

	strncpy(essidproberequestprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(essidproberequestprefix, essidproberequestsuffix, PREFIX_BUFFER_MAX);
	essidproberequestoutname = essidprefix;

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

	strncpy(tacacspprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(tacacspprefix, tacacspsuffix, PREFIX_BUFFER_MAX);
	tacacspoutname = tacacspprefix;

	strncpy(nmeaprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(nmeaprefix, nmeasuffix, PREFIX_BUFFER_MAX);
	nmeaoutname = nmeaprefix;

	strncpy(csvprefix, prefixoutname, PREFIX_BUFFER_MAX);
	strncat(csvprefix, csvsuffix, PREFIX_BUFFER_MAX);
	csvoutname = csvprefix;
	}
if((pmkideapoloutname != NULL) && (nmeaoutname != NULL))
	{
	if(strcmp(pmkideapoloutname, nmeaoutname) == 0)
		{
		printf("same file names for different file types not allowed: %s - %s\n", pmkideapoloutname, usernameoutname);
		exit(EXIT_FAILURE);
		}
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
if(tacacspoutname != NULL)
	{
	if((fh_tacacsp = fopen(tacacspoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", tacacspoutname, strerror(errno));
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
if(essidproberequestoutname != NULL)
	{
	if((fh_essidproberequest = fopen(essidproberequestoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", essidproberequestoutname, strerror(errno));
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
if(csvoutname != NULL)
	{
	if((fh_csv = fopen(csvoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n", csvoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(rawoutname != NULL)
	{
	if((fh_raw_out = fopen(rawoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n",rawoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}
if(logoutname != NULL)
	{
	if((fh_log = fopen(logoutname, "a")) == NULL)
		{
		printf("error opening file %s: %s\n",logoutname, strerror(errno));
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
	if(processcapfile(argv[index]) == false) exitcode = EXIT_FAILURE;
	}

if(rawinname != NULL) processrawfile(rawinname);

if(fh_pmkideapol != NULL) fclose(fh_pmkideapol);
if(fh_eapmd5 != NULL) fclose(fh_eapmd5);
if(fh_eapmd5john != NULL) fclose(fh_eapmd5john);
if(fh_eapleap != NULL) fclose(fh_eapleap);
if(fh_tacacsp != NULL) fclose(fh_tacacsp);
if(fh_essid != NULL) fclose(fh_essid);
if(fh_essidproberequest != NULL) fclose(fh_essidproberequest);
if(fh_identity != NULL) fclose(fh_identity);
if(fh_username != NULL) fclose(fh_username);
if(fh_nmea != NULL) fclose(fh_nmea);
if(fh_csv != NULL) fclose(fh_csv);
if(fh_raw_out != NULL) fclose(fh_raw_out);
if(fh_log != NULL) fclose(fh_log);
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
if(tacacspoutname != NULL)
	{
	if(stat(tacacspoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(tacacspoutname);
		}
	}
if(essidoutname != NULL)
	{
	if(stat(essidoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(essidoutname);
		}
	}
if(essidproberequestoutname != NULL)
	{
	if(stat(essidproberequestoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(essidproberequestoutname);
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
if(csvoutname != NULL)
	{
	if(stat(csvoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(csvoutname);
		}
	}
if(rawoutname != NULL)
	{
	if(stat(rawoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(rawoutname);
		}
	}
if(logoutname != NULL)
	{
	if(stat(logoutname, &statinfo) == 0)
		{
		if(statinfo.st_size == 0) remove(logoutname);
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
if((gzipstat == 0) && (pcapngstat == 0) && (capstat == 0)) return exitcode;
printf("\nsession summary\n---------------\n");
if(gzipstat > 0)		printf("gzip compressed dump files............: %d\n", gzipstat);
if(pcapngstat > 0)		printf("processed pcapng files................: %d\n", pcapngstat);
if(capstat > 0)			printf("processed cap files...................: %d\n", capstat);
printf("\n");
return exitcode;
}
/*===========================================================================*/

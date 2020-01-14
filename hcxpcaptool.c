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
#include <unistd.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <sys/types.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#if defined (__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#include <sys/socket.h>
#else
#include <stdio_ext.h>
#endif
#ifdef __linux__
#include <linux/limits.h>
#endif

#include "include/version.h"
#include "include/hcxpcaptool.h"
#include "include/ieee80211.old.c"
#include "include/strings.c"
#include "include/byteops.c"
#include "include/fileops.c"
#include "include/hashops.c"
#include "include/pcap.c"
#include "include/gzops.c"
#include "include/hashcatops.c"
#include "include/johnops.c"

#define MAX_TV_DIFF 600000000llu
#define MAX_RC_DIFF 8
#define MAX_ESSID_CHANGES 1

#define HCXT_REPLAYCOUNTGAP				1
#define HCXT_TIMEGAP					2
#define HCXT_MAX_ESSID_CHANGES				3
#define HCXT_NETNTLM_OUT				4
#define HCXT_MD5_OUT					5
#define HCXT_MD5_JOHN_OUT				6
#define HCXT_TACACSP_OUT				7
#define HCXT_EAPOL_OUT					8
#define HCXT_NETWORK_OUT				9
#define HCXT_HEXDUMP_OUT				10
#define HCXT_HCCAP_OUT					11
#define HCXT_HCCAP_OUT_RAW				12
#define HCXT_FILTER_MAC					13
#define HCXT_IGNORE_FAKE_FRAMES				14
#define HCXT_IGNORE_ZEROED_PMKS				15
#define HCXT_IGNORE_REPLAYCOUNT				16
#define HCXT_IGNORE_MAC					17
#define HCXT_PREFIX_OUT					18
#define HCXT_NMEA_NAME					19

#define HCXT_WPA12_OUT			'w'
#define HCXT_HCCAPX_OUT			'o'
#define HCXT_HCCAPX_OUT_RAW		'O'
#define HCXT_HC_OUT_PMKID		'k'
#define HCXT_HC_OUT_PMKID_RAW		'K'
#define HCXT_HC_OUT_PMKID_OLD		'z'
#define HCXT_HC_OUT_PMKID_RAW_OLD	'Z'
#define HCXT_JOHN_OUT			'j'
#define HCXT_JOHN_OUT_RAW		'J'
#define HCXT_ESSID_OUT			'E'
#define HCXT_STAESSID_OUT		'X'
#define HCXT_TRAFFIC_OUT		'T'
#define HCXT_GPX_OUT			'g'
#define HCXT_IDENTITY_OUT		'I'
#define HCXT_USERNAME_OUT		'U'
#define HCXT_IMSI_OUT			'M'
#define HCXT_DEVICEINFO_OUT		'D'
#define HCXT_PMK_OUT			'P'
#define HCXT_VERBOSE_OUT		'V'
#define HCXT_HELP			'h'
#define HCXT_VERSION			'v'

#define GPSDDATA_MAX 1536

void process80211packet(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet);

/*===========================================================================*/
/* global var */

bool hexmodeflag;
bool verboseflag;
bool filtermacflag;
bool fakeframeflag;
bool zeroedpmkflag;
bool fcsflag;
bool wantrawflag;
bool gpxflag;
bool nmeaflag;
bool tscleanflag;
bool tssameflag;
bool replaycountcheckflag;
bool maccheckflag;
bool hcxdumptoolcbflag;
bool hcxdumptoolcoflag;

unsigned long long int maxtvdiff;
unsigned long long int maxrcdiff;
int maxessidchanges;

unsigned long long int apstaessidcount;
apstaessidl_t *apstaessidliste;
unsigned long long int apstaessidcountcleaned;
apstaessidl_t *apstaessidlistecleaned;

unsigned long long int eapolcount;
eapoll_t *eapolliste;

pmkidl_t *pmkidliste;

unsigned long long int handshakecount;
unsigned long long int handshakeaplesscount;
hcxl_t *handshakeliste;

unsigned long long int rawhandshakecount;
unsigned long long int rawhandshakeaplesscount;
hcxl_t *rawhandshakeliste;

unsigned long long int pmkidallcount;
unsigned long long int pmkidcount;
unsigned long long int pmkidapcount;
unsigned long long int pmkidstacount;
unsigned long long int zeroedpmkcount;
unsigned long long int zeroedpmkidcount;

unsigned long long int leapcount;
leapl_t *leapliste;

unsigned long long int leap2count;
leapl_t *leap2liste;

unsigned long long int md5count;
md5l_t *md5liste;

unsigned long long int tacacspcount;
tacacspl_t *tacacspliste;

unsigned long long int gpsdframecount;
unsigned long long int gpsnmeaframecount;
unsigned long long int fcsframecount;
unsigned long long int wdsframecount;
unsigned long long int beaconframecount;
unsigned long long int beaconframedamagedcount;
unsigned long long int wpsframecount;
unsigned long long int deviceinfoframecount;
unsigned long long int meshidframecount;
unsigned long long int proberequestframecount;
unsigned long long int proberesponseframecount;
unsigned long long int associationrequestframecount;
unsigned long long int associationresponseframecount;
unsigned long long int reassociationrequestframecount;
unsigned long long int reassociationresponseframecount;
unsigned long long int authenticationunknownframecount;
unsigned long long int authenticationosframecount;
unsigned long long int authenticationskframecount;
unsigned long long int authenticationfbtframecount;
unsigned long long int authenticationsaeframecount;
unsigned long long int authenticationfilsframecount;
unsigned long long int authenticationfilspfsframecount;
unsigned long long int authenticationfilspkframecount;
unsigned long long int authenticationnetworkeapframecount;
unsigned long long int authenticationbroadcomframecount;
unsigned long long int authenticationsonosframecount;
unsigned long long int authenticationappleframecount;
unsigned long long int authenticationnetgearframecount;
unsigned long long int authenticationwiliboxframecount;
unsigned long long int authenticationciscoframecount;
unsigned long long int deauthenticationframecount;
unsigned long long int disassociationframecount;
unsigned long long int actionframecount;
unsigned long long int atimframecount;
unsigned long long int eapolframecount;
unsigned long long int eapoloversizedframecount;
unsigned long long int eapolwpaakmframecount;
unsigned long long int eapolwpa1framecount;
unsigned long long int eapolwpa2framecount;
unsigned long long int eapolwpa2kv3framecount;
unsigned long long int eapolpmkidwpaakmframecount;
unsigned long long int eapolpmkidwpa1framecount;
unsigned long long int eapolpmkidwpa2framecount;
unsigned long long int eapolpmkidwpa2kv3framecount;
unsigned long long int groupkeyframecount;
unsigned long long int rc4descriptorframecount;
unsigned long long int eapolstartframecount;
unsigned long long int eapollogoffframecount;
unsigned long long int eapolasfframecount;
unsigned long long int eapolmkaframecount;
unsigned long long int eapframecount;
unsigned long long int ipv4framecount;
unsigned long long int ipv6framecount;
unsigned long long int icmp4framecount;
unsigned long long int icmp6framecount;
unsigned long long int tcpframecount;
unsigned long long int udpframecount;
unsigned long long int greframecount;
unsigned long long int chapframecount;
unsigned long long int papframecount;
unsigned long long int tacacspframecount;
unsigned long long int radiusframecount;
unsigned long long int dhcpframecount;
unsigned long long int tzspframecount;
unsigned long long int dhcp6framecount;
unsigned long long int wepframecount;
unsigned long long int tzspframecount;
unsigned long long int tzspethernetframecount;
unsigned long long int tzsptokenringframecount;
unsigned long long int tzspslipframecount;
unsigned long long int tzsppppframecount;
unsigned long long int tzspfddiframecount;
unsigned long long int tzsprawframecount;
unsigned long long int tzsp80211framecount;
unsigned long long int tzsp80211prismframecount;
unsigned long long int tzsp80211avsframecount;

static long double lat = 0;
static long double lon = 0;
static long double alt = 0;
static int nmealen = 0;

static int day = 0;
static int month = 0;
static int year = 0;
static int hour = 0;
static int minute = 0;
static int second = 0;

char *hexmodeoutname;
char *wpa12bestoutname;
char *hccapxbestoutname;
char *hccapxrawoutname;
char *hcpmkidoutname;
char *hcpmkidrawoutname;
char *hcpmkidoldoutname;
char *hcpmkidrawoldoutname;
char *hccapbestoutname;
char *hccaprawoutname;
char *johnbestoutname;
char *johnrawoutname;
char *essidoutname;
char *staessidoutname;
char *trafficoutname;
char *gpxoutname;
char *nmeaoutname;
char *pmkoutname;
char *identityoutname;
char *useroutname;
char *imsioutname;
char *deviceinfooutname;
char *netntlm1outname;
char *md5outname;
char *md5johnoutname;
char *tacacspoutname;
char *eapoloutname;
char *networkoutname;
char *prefixoutname;

FILE *fhhexmode;
FILE *fhgpx;
FILE *fhnmea;
FILE *fheapol;
FILE *fhnetwork;

int endianess;
int pcapreaderrors;
unsigned long long int rawpacketcount;
unsigned long long int skippedpacketcount;
uint16_t versionmajor;
uint16_t versionminor;
uint16_t dltlinktype;

struct timeval mintv;
struct timeval maxtv;

uint8_t myaktap[6];
uint8_t myaktsta[6];
uint8_t myaktanonce[32];
uint8_t myaktsnonce[32];
uint64_t myaktreplaycount;

uint8_t filtermac[6];

char pcapnghwinfo[1024];
char pcapngosinfo[1024];
char pcapngapplinfo[1024];
char pcapngoptioninfo[1024];
uint8_t pcapngdeviceinfo[6];
char weakcandidate[64];
int exeaptype[256];
char nmeasentence[NMEA_MAX];
/*===========================================================================*/
/* global init */

bool globalinit()
{
hexmodeoutname = NULL;
wpa12bestoutname = NULL;
hccapxbestoutname = NULL;
hccapxrawoutname = NULL;
hcpmkidoutname = NULL;
hcpmkidrawoutname = NULL;
hcpmkidoldoutname = NULL;
hcpmkidrawoldoutname = NULL;
hccapbestoutname = NULL;
hccaprawoutname = NULL;
johnbestoutname = NULL;
johnrawoutname = NULL;
essidoutname = NULL;
staessidoutname = NULL;
trafficoutname = NULL;
gpxoutname = NULL;
nmeaoutname = NULL;
pmkoutname = NULL;
identityoutname = NULL;
useroutname = NULL;
imsioutname = NULL;
deviceinfooutname = NULL;
netntlm1outname = NULL;
md5outname = NULL;
md5johnoutname = NULL;
tacacspoutname = NULL;
eapoloutname = NULL;
networkoutname = NULL;
prefixoutname = NULL;

verboseflag = false;
hexmodeflag = false;
wantrawflag = false;
filtermacflag = false;
fakeframeflag = false;
zeroedpmkflag = false;
replaycountcheckflag = false;
maccheckflag = false;

gpxflag = false;
nmeaflag = false;

maxtvdiff = MAX_TV_DIFF;
maxrcdiff = MAX_RC_DIFF;
maxessidchanges = MAX_ESSID_CHANGES;

setbuf(stdout, NULL);
srand(time(NULL));

memset(&pcapngdeviceinfo, 0, 6);
memset(&myaktap, 0, 6);
memset(&myaktanonce, 0, 32);
memset(&myaktsta, 0, 6);
memset(&myaktsnonce, 0, 32);
memset(&weakcandidate, 0, 64);
memset(&nmeasentence, 0, NMEA_MAX);
return true;
}
/*===========================================================================*/
char *geteaptypestring(int exapt) 
{
switch(exapt)
	{
	case EAP_TYPE_ID: return "EAP type ID";
	case EAP_TYPE_NAK: return "Legacy Nak";
	case EAP_TYPE_MD5: return "MD5-Challenge";
	case EAP_TYPE_OTP: return "One-Time Password (OTP)";
	case EAP_TYPE_GTC: return "Generic Token Card (GTC)";
	case EAP_TYPE_RSA: return "RSA Public Key Authentication";
	case EAP_TYPE_EXPAND: return "WPS Authentication";
	case EAP_TYPE_LEAP: return "EAP-Cisco Wireless Authentication";
	case EAP_TYPE_DSS: return "DSS Unilateral";
	case EAP_TYPE_KEA: return "KEA";
	case EAP_TYPE_KEA_VALIDATE: return "KEA-VALIDATE";
	case EAP_TYPE_TLS: return "EAP-TLS Authentication";
	case EAP_TYPE_AXENT: return "Defender Token (AXENT)";
	case EAP_TYPE_RSA_SSID: return "RSA Security SecurID EAP";
	case EAP_TYPE_RSA_ARCOT: return "Arcot Systems EAP";
	case EAP_TYPE_SIM: return "EAP-SIM (GSM Subscriber Modules) Authentication";
	case EAP_TYPE_SRP_SHA1: return "SRP-SHA1 Authentication";
	case EAP_TYPE_TTLS: return "EAP-TTLS Authentication";
	case EAP_TYPE_RAS: return "Remote Access Service";
	case EAP_TYPE_AKA: return "UMTS Authentication and Key Agreement (EAP-AKA)";
	case EAP_TYPE_3COMEAP: return "EAP-3Com Wireless Authentication";
	case EAP_TYPE_PEAP: return "PEAP Authentication";
	case EAP_TYPE_MSEAP: return "MS-EAP Authentication";
	case EAP_TYPE_MAKE: return "Mutual Authentication w/Key Exchange (MAKE)";
	case EAP_TYPE_CRYPTOCARD: return "CRYPTOCard";
	case EAP_TYPE_MSCHAPV2: return "EAP-MSCHAP-V2 Authentication";
	case EAP_TYPE_DYNAMICID: return "DynamicID";
	case EAP_TYPE_ROB: return "Rob EAP";
	case EAP_TYPE_POTP: return "Protected One-Time Password";
	case EAP_TYPE_MSTLV: return "MS-Authentication-TLV";
	case EAP_TYPE_SENTRI: return "SentriNET";
	case EAP_TYPE_AW: return "EAP-Actiontec Wireless Authentication";
	case EAP_TYPE_CSBA: return "Cogent Systems Biometrics Authentication EAP";
	case EAP_TYPE_AIRFORT: return "AirFortress EAP";
	case EAP_TYPE_HTTPD: return "EAP-HTTP Digest";
	case EAP_TYPE_SS: return "SecureSuite EAP";
	case EAP_TYPE_DC: return "DeviceConnect EAP";
	case EAP_TYPE_SPEKE: return "EAP-SPEKE Authentication";
	case EAP_TYPE_MOBAC: return "EAP-MOBAC Authentication";
	case EAP_TYPE_FAST: return "FAST Authentication";
	case EAP_TYPE_ZLXEAP: return "ZoneLabs EAP (ZLXEAP)";
	case EAP_TYPE_LINK: return "EAP-Link Authentication";
	case EAP_TYPE_PAX: return "EAP-PAX Authentication";
	case EAP_TYPE_PSK: return "EAP-PSK Authentication";
	case EAP_TYPE_SAKE: return "EAP-SAKE Authentication";
	case EAP_TYPE_IKEV2: return "EAP-IKEv2 Authentication";
	case EAP_TYPE_AKA1: return "EAP-AKA Authentication";
	case EAP_TYPE_GPSK: return "EAP-GPSK Authentication";
	case EAP_TYPE_PWD: return "EAP-pwd Authentication";
	case EAP_TYPE_EKE1: return "EAP-EKE Version 1 Authentication";
	case EAP_TYPE_PTEAP: return "EAP Method Type for PT-EAP Authentication";
	case EAP_TYPE_TEAP: return "TEAP Authentication";
	case EAP_TYPE_EXPERIMENTAL: return "Experimental Authentication";
	default: return "unknown authentication type";
	}
return "unknown authentication type";
}
/*===========================================================================*/
char *getdltstring(int networktype) 
{
switch(networktype)
	{
	case DLT_NULL: return "DLT_NULL";
	case DLT_EN10MB: return "DLT_EN10MB";
	case DLT_AX25: return "DLT_AX25";
	case DLT_IEEE802: return "DLT_IEEE802";
	case DLT_ARCNET: return "DLT_ARCNET";
	case DLT_SLIP: return "DLT_SLIP";
	case DLT_PPP: return "DLT_PPP";
	case DLT_FDDI: return "DLT_FDDI";
	case DLT_PPP_SERIAL: return "DLT_PPP_SERIAL";
	case DLT_PPP_ETHER: return "DLT_PPP_ETHER";
	case DLT_ATM_RFC1483: return "DLT_ATM_RFC1483";
	case DLT_RAW: return "DLT_RAW";
	case DLT_C_HDLC: return "DLT_C_HDLC";
	case DLT_IEEE802_11: return "DLT_IEEE802_11";
	case DLT_FRELAY: return "DLT_FRELAY";
	case DLT_LOOP: return "DLT_LOOP";
	case DLT_LINUX_SLL: return "DLT_LINUX_SLL";
	case DLT_LTALK: return "DLT_LTALK";
	case DLT_PFLOG: return "DLT_PFLOG";
	case DLT_PRISM_HEADER: return "DLT_PRISM_HEADER";
	case DLT_IP_OVER_FC: return "DLT_IP_OVER_FC";
	case DLT_SUNATM: return "DLT_SUNATM";
	case DLT_IEEE802_11_RADIO: return "DLT_IEEE802_11_RADIO";
	case DLT_ARCNET_LINUX: return "DLT_ARCNET_LINUX";
	case DLT_APPLE_IP_OVER_IEEE1394: return "DLT_APPLE_IP_OVER_IEEE1394";
	case DLT_MTP2_WITH_PHDR: return "DLT_MTP2_WITH_PHDR";
	case DLT_MTP2: return "DLT_MTP2";
	case DLT_MTP3: return "DLT_MTP3";
	case DLT_SCCP: return "DLT_SCCP";
	case DLT_DOCSIS: return "DLT_DOCSIS";
	case DLT_LINUX_IRDA: return "DLT_LINUX_IRDA";
	case DLT_IEEE802_11_RADIO_AVS: return "DLT_IEEE802_11_RADIO_AVS";
	case DLT_BACNET_MS_TP: return "DLT_BACNET_MS_TP";
	case DLT_PPP_PPPD: return "DLT_PPP_PPPD";
	case DLT_GPRS_LLC: return "DLT_GPRS_LLC";
	case DLT_GPF_T: return "DLT_GPF_T";
	case DLT_GPF_F: return "DLT_GPF_F";
	case DLT_LINUX_LAPD: return "DLT_LINUX_LAPD";
	case DLT_BLUETOOTH_HCI_H4: return "DLT_BLUETOOTH_HCI_H4";
	case DLT_USB_LINUX: return "DLT_USB_LINUX";
	case DLT_PPI: return "DLT_PPI";
	case DLT_IEEE802_15_4: return "DLT_IEEE802_15_4";
	case DLT_SITA: return "DLT_SITA";
	case DLT_ERF: return "DLT_ERF";
	case DLT_BLUETOOTH_HCI_H4_WITH_PHDR: return "DLT_BLUETOOTH_HCI_H4_WITH_PHDR";
	case DLT_AX25_KISS: return "DLT_AX25_KISS";
	case DLT_LAPD: return "DLT_LAPD";
	case DLT_PPP_WITH_DIR: return "DLT_PPP_WITH_DIR";
	case DLT_C_HDLC_WITH_DIR: return "DLT_C_HDLC_WITH_DIR";
	case DLT_FRELAY_WITH_DIR: return "DLT_FRELAY_WITH_DIR";
	case DLT_IPMB_LINUX: return "DLT_IPMB_LINUX";
	case DLT_IEEE802_15_4_NONASK_PHY: return "DLT_IEEE802_15_4_NONASK_PHY";
	case DLT_USB_LINUX_MMAPPED: return "DLT_USB_LINUX_MMAPPED";
	case DLT_FC_2: return "DLT_FC_2";
	case DLT_FC_2_WITH_FRAME_DELIMS: return "DLT_FC_2_WITH_FRAME_DELIMS";
	case DLT_IPNET: return "DLT_IPNET";
	case DLT_CAN_SOCKETCAN: return "DLT_CAN_SOCKETCAN";
	case DLT_IPV4: return "DLT_IPV4";
	case DLT_IPV6: return "DLT_IPV6";
	case DLT_IEEE802_15_4_NOFCS: return "DLT_IEEE802_15_4_NOFCS";
	case DLT_DBUS: return "DLT_DBUS";
	case DLT_DVB_CI: return "DLT_DVB_CI";
	case DLT_MUX27010: return "DLT_MUX27010";
	case DLT_STANAG_5066_D_PDU: return "DLT_STANAG_5066_D_PDU";
	case DLT_NFLOG: return "DLT_NFLOG";
	case DLT_NETANALYZER: return "DLT_NETANALYZER";
	case DLT_NETANALYZER_TRANSPARENT: return "DLT_NETANALYZER_TRANSPARENT";
	case DLT_IPOIB: return "DLT_IPOIB";
	case DLT_MPEG_2_TS: return "DLT_MPEG_2_TS";
	case DLT_NG40: return "DLT_NG40";
	case DLT_NFC_LLCP: return "DLT_NFC_LLCP";
	case DLT_INFINIBAND: return "DLT_INFINIBAND";
	case DLT_SCTP: return "DLT_SCTP";
	case DLT_USBPCAP: return "DLT_USBPCAP";
	case DLT_RTAC_SERIAL: return "DLT_RTAC_SERIAL";
	case DLT_BLUETOOTH_LE_LL: return "DLT_BLUETOOTH_LE_LL";
	case DLT_NETLINK: return "DLT_NETLINK";
	case DLT_BLUETOOTH_LINUX_MONITOR: return "DLT_BLUETOOTH_LINUX_MONITOR";
	case DLT_BLUETOOTH_BREDR_BB: return "DLT_BLUETOOTH_BREDR_BB";
	case DLT_BLUETOOTH_LE_LL_WITH_PHDR: return "DLT_BLUETOOTH_LE_LL_WITH_PHDR";
	case DLT_PROFIBUS_DL: return "DLT_PROFIBUS_DL";
	case DLT_PKTAP: return "DLT_PKTAP";
	case DLT_EPON: return "DLT_EPON";
	case DLT_IPMI_HPM_2: return "DLT_IPMI_HPM_2";
	case DLT_ZWAVE_R1_R2: return "DLT_ZWAVE_R1_R2";
	case DLT_ZWAVE_R3: return "DLT_ZWAVE_R3";
	case DLT_WATTSTOPPER_DLM: return "DLT_WATTSTOPPER_DLM";
	case DLT_ISO_14443: return "DLT_ISO_14443";
	case DLT_RDS: return "DLT_RDS";
	default: return "unknown network type";
	}
return "unknown network type";
}
/*===========================================================================*/
char *geterrorstat(int errorstat) 
{
switch(errorstat)
	{
	case 0: return "flawless";
	case 1: return "yes";
	default: return "unknown";
	}
return "unknown";
}
/*===========================================================================*/
char *getendianessstring(int endianess) 
{
switch(endianess)
	{
	case 0: return "little endian";
	case 1: return "big endian";
	default: return "unknown endian";
	}
return "unknow nendian";
}
/*===========================================================================*/
void printcapstatus(char *pcaptype, char *pcapinname, int version_major, int version_minor, int networktype, int endianess, unsigned long long int rawpacketcount, unsigned long long int skippedpacketcount, int pcapreaderrors, bool tscleanflag)
{
int p;

static char *hcxsignedinfo = "(custom options)";
static char *hcxunsignedinfo = "(no custom options)";

static char mintimestring[32];
static char maxtimestring[32];


static char *hcxsignedptr;

hcxsignedptr = hcxsignedinfo;
if(hcxdumptoolcbflag == false)
	{
	hcxsignedptr = hcxunsignedinfo;
	}
strftime(mintimestring, 32, "%d.%m.%Y %H:%M:%S", gmtime(&mintv.tv_sec));
strftime(maxtimestring, 32, "%d.%m.%Y %H:%M:%S", gmtime(&maxtv.tv_sec));
printf( "                                                \n"
	"summary capture file:                           \n"
	"---------------------\n"
	"file name........................: %s\n"
	"file type........................: %s %d.%d\n"
	"file hardware information........: %s\n"
	"capture device vendor information: %02x%02x%02x\n"
	"file os information..............: %s\n"
	"file application information.....: %s %s\n"
	"network type.....................: %s (%d)\n"
	"endianness.......................: %s\n"
	"read errors......................: %s\n"
	"minimum time stamp...............: %s (GMT)\n"
	"maximum time stamp...............: %s (GMT)\n"
	"packets inside...................: %llu\n"
	"skipped damaged packets..........: %llu\n"
	"packets with GPS NMEA data.......: %llu\n"
	"packets with GPS data (JSON old).: %llu\n"
	"packets with FCS.................: %llu\n"
	, basename(pcapinname), pcaptype, version_major, version_minor, pcapnghwinfo, pcapngdeviceinfo[0], pcapngdeviceinfo[1], pcapngdeviceinfo[2], pcapngosinfo, pcapngapplinfo, hcxsignedptr, getdltstring(networktype), networktype, getendianessstring(endianess), geterrorstat(pcapreaderrors), mintimestring, maxtimestring, rawpacketcount, skippedpacketcount, gpsnmeaframecount, gpsdframecount, fcsframecount);
if(tscleanflag == true)
	{
	printf("warning..........................: zero value time stamps detected\n"
		"                                   this prevents EAPOL timeout calculation\n");
	}
if(tssameflag == true)
	{
	printf("warning..........................: EAPOL packet time stamps with the same value detected\n"
		"                                   this prevents EAPOL timeout calculation\n");
	}
if(wdsframecount != 0)
	{
	printf("WDS packets......................: %llu\n", wdsframecount);
	}
if(beaconframecount != 0)
	{
	printf("beacons (total)..................: %llu\n", beaconframecount);
	}
if(beaconframedamagedcount != 0)
	{
	printf("beacons (damaged)................: %llu\n", beaconframedamagedcount);
	}
if(wpsframecount != 0)
	{
	printf("beacons (WPS info inside)........: %llu\n", wpsframecount);
	}
if(deviceinfoframecount != 0)
	{
	printf("beacons (device info inside).....: %llu\n", deviceinfoframecount);
	}
if(meshidframecount != 0)
	{
	printf("beacons (MESH-ID inside).........: %llu\n", meshidframecount);
	}
if(proberequestframecount != 0)
	{
	printf("probe requests...................: %llu\n", proberequestframecount);
	}
if(proberesponseframecount != 0)
	{
	printf("probe responses..................: %llu\n", proberesponseframecount);
	}
if(associationrequestframecount != 0)
	{
	printf("association requests.............: %llu\n", associationrequestframecount);
	}
if(associationresponseframecount != 0)
	{
	printf("association responses............: %llu\n", associationresponseframecount);
	}
if(reassociationrequestframecount != 0)
	{
	printf("reassociation requests...........: %llu\n", reassociationrequestframecount);
	}
if(reassociationresponseframecount != 0)
	{
	printf("reassociation responses..........: %llu\n", reassociationresponseframecount);
	}
if(authenticationunknownframecount != 0)
	{
	printf("authentications (UNKNOWN)........: %llu\n", authenticationunknownframecount);
	}
if(authenticationosframecount != 0)
	{
	printf("authentications (OPEN SYSTEM)....: %llu\n", authenticationosframecount);
	}
if(authenticationskframecount != 0)
	{
	printf("authentications (SHARED KEY).....: %llu\n", authenticationskframecount);
	}
if(authenticationfbtframecount != 0)
	{
	printf("authentications (FBT)............: %llu\n", authenticationfbtframecount);
	}
if(authenticationsaeframecount != 0)
	{
	printf("authentications (SAE)............: %llu\n", authenticationsaeframecount);
	}
if(authenticationfilsframecount != 0)
	{
	printf("authentications (FILS)...........: %llu\n", authenticationfilsframecount);
	}
if(authenticationfilspfsframecount != 0)
	{
	printf("authentications (FILS PFS).......: %llu\n", authenticationfilspfsframecount);
	}
if(authenticationfilspkframecount != 0)
	{
	printf("authentications (FILS PK)........: %llu\n", authenticationfilspkframecount);
	}
if(authenticationnetworkeapframecount != 0)
	{
	printf("authentications (NETWORK EAP)....: %llu\n", authenticationnetworkeapframecount);
	}
if(authenticationbroadcomframecount != 0)
	{
	printf("authentications (BROADCOM).......: %llu\n", authenticationbroadcomframecount);
	}
if(authenticationsonosframecount != 0)
	{
	printf("authentications (SONOS)..........: %llu\n", authenticationsonosframecount);
	}
if(authenticationappleframecount != 0)
	{
	printf("authentications (APPLE)..........: %llu\n", authenticationappleframecount);
	}
if(authenticationnetgearframecount != 0)
	{
	printf("authentications (NETGEAR)........: %llu\n", authenticationnetgearframecount);
	}
if(authenticationwiliboxframecount != 0)
	{
	printf("authentications (WILIBOX)........: %llu\n", authenticationwiliboxframecount);
	}
if(authenticationciscoframecount != 0)
	{
	printf("authentications (CISCO)..........: %llu\n", authenticationciscoframecount);
	}
if(deauthenticationframecount != 0)
	{
	printf("deauthentications................: %llu\n", deauthenticationframecount);
	}
if(disassociationframecount != 0)
	{
	printf("disassociations..................: %llu\n", disassociationframecount);
	}
if(actionframecount != 0)
	{
	printf("action packets...................: %llu\n", actionframecount);
	}
if(atimframecount != 0)
	{
	printf("ATIM packets.....................: %llu\n", atimframecount);
	}
if(eapolframecount != 0)
	{
	printf("EAPOL packets (total)............: %llu\n", eapolframecount);
	}
if(eapoloversizedframecount != 0)
	{
	printf("EAPOL packets (oversized)........: %llu\n", eapoloversizedframecount);
	}
if(eapolwpaakmframecount != 0)
	{
	printf("EAPOL packets (AKM defined)......: %llu\n", eapolwpaakmframecount);
	}
if(eapolwpa1framecount != 0)
	{
	printf("EAPOL packets (WPA1).............: %llu\n", eapolwpa1framecount);
	}
if(eapolwpa2framecount != 0)
	{
	printf("EAPOL packets (WPA2).............: %llu\n", eapolwpa2framecount);
	}
if(eapolwpa2kv3framecount != 0)
	{
	printf("EAPOL packets (WPA2 kever 3).....: %llu\n", eapolwpa2kv3framecount);
	}
if(zeroedpmkidcount != 0)
	{
	printf("PMKIDs (zeroed and useless)......: %llu\n", zeroedpmkidcount);
	}
if(pmkidallcount != 0)
	{
	printf("PMKIDs (not zeroed - total)......: %llu\n", pmkidallcount);
	}
if(eapolpmkidwpaakmframecount != 0)
	{
	printf("PMKIDs (AKM defined).............: %llu\n", eapolpmkidwpaakmframecount);
	}
if(eapolpmkidwpa1framecount != 0)
	{
	printf("PMKIDs (WPA1)....................: %llu\n", eapolpmkidwpa1framecount);
	}
if(eapolpmkidwpa2framecount != 0)
	{
	printf("PMKIDs (WPA2)....................: %llu\n", eapolpmkidwpa2framecount);
	}
if(eapolpmkidwpa2kv3framecount != 0)
	{
	printf("PMKIDs (WPA2 keyver 3)...........: %llu\n", eapolpmkidwpa2kv3framecount);
	}
if(pmkidapcount != 0)
	{
	printf("PMKIDs from access points........: %llu\n", pmkidapcount);
	}
if(pmkidstacount != 0)
	{
	printf("PMKIDs from stations.............: %llu\n", pmkidstacount);
	}
if(rc4descriptorframecount != 0)
	{
	printf("EAPOL RC4 KEYs...................: %llu\n", rc4descriptorframecount);
	}
if(groupkeyframecount != 0)
	{
	printf("EAPOL GROUP KEYs.................: %llu\n", groupkeyframecount);
	}
if(eapframecount != 0)
	{
	printf("EAP packets......................: %llu\n", eapframecount);
	}
if(eapolstartframecount != 0)
	{
	printf("EAP START packets................: %llu\n", eapolstartframecount);
	}
if(eapollogoffframecount != 0)
	{
	printf("EAP LOGOFF packets...............: %llu\n", eapollogoffframecount);
	}
if(eapolasfframecount != 0)
	{
	printf("EAP ASF ALERT packets............: %llu\n", eapolasfframecount);
	}
if(wepframecount != 0)
	{
	printf("WEP packets......................: %llu\n", wepframecount);
	}
if(ipv4framecount != 0)
	{
	printf("IPv4 packets.....................: %llu\n", ipv4framecount);
	}
if(ipv6framecount != 0)
	{
	printf("IPv6 packets.....................: %lld\n", ipv6framecount);
	}
if(tcpframecount != 0)
	{
	printf("TCP packets......................: %lld\n", tcpframecount);
	}
if(udpframecount != 0)
	{
	printf("UDP packets......................: %lld\n", udpframecount);
	}
if(icmp4framecount != 0)
	{
	printf("ICMPv4 packets...................: %lld\n", icmp4framecount);
	}
if(icmp6framecount != 0)
	{
	printf("ICMPv6 packets...................: %lld\n", icmp6framecount);
	}
if(dhcpframecount != 0)
	{
	printf("DHCP packets.....................: %lld\n", dhcpframecount);
	}
if(dhcp6framecount != 0)
	{
	printf("DHCPv6 packets...................: %lld\n", dhcp6framecount);
	}
if(greframecount != 0)
	{
	printf("GRE packets......................: %lld\n", greframecount);
	}
if(tzspframecount != 0)
	{
	printf("TZSP packets.....................: %lld\n", tzspframecount);
	}
if(tzspethernetframecount != 0)
	{
	printf("TZSP (ETHERNET) packets..........: %lld\n", tzspethernetframecount);
	}
if(tzsptokenringframecount != 0)
	{
	printf("TZSP (TOKEN RING) packets........: %lld\n", tzsptokenringframecount);
	}
if(tzspslipframecount != 0)
	{
	printf("TZSP (SLIP) packets..............: %lld\n", tzspslipframecount);
	}
if(tzsppppframecount != 0)
	{
	printf("TZSP (PPP) packets...............: %lld\n", tzsppppframecount);
	}
if(tzspfddiframecount != 0)
	{
	printf("TZSP (FDDI) packets..............: %lld\n", tzspfddiframecount);
	}
if(tzsprawframecount != 0)
	{
	printf("TZSP (RAW) packets...............: %lld\n", tzsprawframecount);
	}
if(tzsp80211framecount != 0)
	{
	printf("TZSP (802.11) packets............: %lld\n", tzsp80211framecount);
	}
if(tzsp80211prismframecount != 0)
	{
	printf("TZSP (802.11 PRSIM) packets......: %lld\n", tzsp80211prismframecount);
	}
if(tzsp80211avsframecount != 0)
	{
	printf("TZSP (802.11 AVS) packets........: %lld\n", tzsp80211avsframecount);
	}
for(p = 0; p < 256; p++)
	{
	if(exeaptype[p] != 0)
		{
		printf("found............................: %s\n", geteaptypestring(p));
		}
	}
if(eapolmkaframecount != 0)
	{
	printf("found............................: MKA Authentication (Macsec Key Agreement protocol)\n");
	}
if(chapframecount != 0)
	{
	printf("found............................: PPP-CHAP Authentication\n");
	}
if(papframecount != 0)
	{
	printf("found............................: PPP-PAP Authentication\n");
	}
if(tacacspframecount != 0)
	{
	printf("found............................: TACACS+ Authentication\n");
	}
if(radiusframecount != 0)
	{
	printf("found............................: RADIUS Authentication\n");
	}
if(zeroedpmkcount != 0)
	{
	printf("zeroed PMK(s)....................: %llu\n", zeroedpmkcount);
	}
if(rawhandshakecount != 0)
	{
	printf("raw handshakes...................: %llu (ap-less: %llu)\n", rawhandshakecount, rawhandshakeaplesscount);
	}
if(handshakecount != 0)
	{
	printf("best handshakes (total)..........: %llu (ap-less: %llu)\n", handshakecount, handshakeaplesscount);
	}
if(pmkidcount != 0)
	{
	printf("best PMKIDs (total)..............: %llu\n", pmkidcount);
	}
printf("\n");
return;
}
/*===========================================================================*/
/* PMKID zeroed PMK check */
bool testpmkidzeropmk(uint8_t *macsta, uint8_t *macap, uint8_t *pmkid)
{
char *pmkname = "PMK Name";

uint8_t zeropmk[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t salt[32];
uint8_t zeropmkid[32];

memcpy(&salt, pmkname, 8);
memcpy(&salt[8], macap, 6);
memcpy(&salt[14], macsta, 6);

HMAC(EVP_sha1(), zeropmk, 32, salt, 20, zeropmkid, NULL);

if(memcmp(&zeropmkid, pmkid, 16) == 0)
	{
	return true;
	}
return false;
}
/*===========================================================================*/
int omac1_aes_128_vector(const uint8_t *key, size_t num_elem, const uint8_t *addr[], const size_t *len, uint8_t *mac)
{
CMAC_CTX *ctx;
int ret = -1;
size_t outlen, i;

ctx = CMAC_CTX_new();
if (ctx == NULL)
	{
	return -1;
	}
if (!CMAC_Init(ctx, key, 16, EVP_aes_128_cbc(), NULL))
	{
	goto fail;
	}
for (i = 0; i < num_elem; i++)
	{
	if (!CMAC_Update(ctx, addr[i], len[i]))
		{
		goto fail;
		}
	}
if (!CMAC_Final(ctx, mac, &outlen) || outlen != 16)
	{
	goto fail;
	}

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
/* EAPOL zeroed PMK check */
bool testeapolzeropmk(uint8_t keyver, uint8_t *macsta, uint8_t *macap, uint8_t *nonceap, uint8_t *noncesta, uint8_t eapollen, uint8_t *eapolmessage)
{
int p;
uint8_t *pkeptr;
wpakey_t *wpakzero, *wpak;

uint8_t zeropmk[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

uint8_t pkedata[102];
uint8_t pkedata_prf[2 + 98 + 2];
uint8_t ptk[128];
uint8_t eapoldata[0xff];
uint8_t miczero[16];

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

	if(memcmp(nonceap, noncesta, 32) < 0)
		{
		memcpy (pkeptr +35, nonceap, 32);
		memcpy (pkeptr +67, noncesta, 32);
		}
	else
		{
		memcpy (pkeptr +35, noncesta, 32);
		memcpy (pkeptr +67, nonceap, 32);
		}

	for (p = 0; p < 4; p++)
		{
		pkedata[99] = p;
		HMAC(EVP_sha1(), zeropmk, 32, pkedata, 100, ptk + p *20, NULL);
		}
	if(keyver == 1)
		{
		HMAC(EVP_md5(), &ptk, 16, eapoldata, eapollen, miczero, NULL);
		if(memcmp(&miczero, wpak->keymic, 16) == 0)
			{
			return true;
			}
		}
	else if(keyver == 2)
		{
		HMAC(EVP_sha1(), ptk, 16, eapoldata, eapollen, miczero, NULL);
		if(memcmp(&miczero, wpak->keymic, 16) == 0)
			{
			return true;
			}
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
	if(memcmp(nonceap, noncesta, 32) < 0)
		{
		memcpy (pkeptr +34, nonceap, 32);
		memcpy (pkeptr +66, noncesta, 32);
		}
	else
		{
		memcpy (pkeptr +34, noncesta, 32);
		memcpy (pkeptr +66, nonceap, 32);
		}
	pkedata_prf[0] = 1;
	pkedata_prf[1] = 0;
	memcpy (pkedata_prf + 2, pkedata, 98);
	pkedata_prf[100] = 0x80;
	pkedata_prf[101] = 1;
	HMAC(EVP_sha256(), zeropmk, 32, pkedata_prf, 2 + 98 + 2, ptk, NULL);
	omac1_aes_128(ptk, eapoldata, eapollen, miczero);
	if(memcmp(&miczero, wpak->keymic, 16) == 0)
		{
		return true;
		}
	}
return false;
}
/*===========================================================================*/
void packethexdump(uint32_t tv_sec, uint32_t ts_usec, unsigned long long int packetnr, uint32_t networktype, uint32_t snaplen, uint32_t caplen, uint32_t len, uint8_t *packet)
{
int c;
uint32_t d;
time_t pkttime;
struct tm *pkttm;
char tmbuf[64], pcktimestr[512];

pkttime = tv_sec;
pkttm = localtime(&pkttime);
strftime(tmbuf, sizeof tmbuf, "%d.%m.%Y\ntime.......: %H:%M:%S", pkttm);
snprintf(pcktimestr, sizeof(pcktimestr), "%s.%06lu", tmbuf, (long int)ts_usec);

fprintf(fhhexmode, "packet.....: %lld\n"
	"date.......: %s\n"
	"networktype: %s (%d)\n"
	"snaplen....: %d\n"
	"caplen.....: %d\n"
	"len........: %d\n", packetnr, pcktimestr, getdltstring(networktype), networktype, snaplen, caplen, len);

d = 0;
while(d < caplen)
	{
	for(c = 0; c < 16; c++)
		{
		if((d +c) < caplen)
			{
			fprintf(fhhexmode, "%02x ", packet[d +c]);
			}
		else
			{
			fprintf(fhhexmode, "   ");
			}
		}
	fprintf(fhhexmode, "    ");
	for(c = 0; c < 16; c++)
		{
		if((d +c < caplen) && (packet[d +c] >= 0x20) && (packet[d +c] < 0x7f))
			{
			fprintf(fhhexmode, "%c", packet[d +c]);
			}
		else if(d +c < caplen)
			{
			fprintf(fhhexmode, ".");
			}
		}
	fprintf(fhhexmode, "\n");
	d += 16;
	}
fprintf(fhhexmode, "\n");
return;
}
/*===========================================================================*/
void outputessidlists()
{
unsigned long long int c;
FILE *fhoutlist = NULL;
int wecl;
apstaessidl_t *zeiger, *zeigerold;

if(essidoutname != NULL)
	{
	if((fhoutlist = fopen(essidoutname, "a+")) != NULL)
		{
		zeiger = apstaessidliste;
		zeigerold = zeiger;
		qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_essid);
		wecl = strlen(weakcandidate);
		if((wecl > 0) && (wecl < 64))
			{
			fprintf(fhoutlist, "%s\n", weakcandidate); 
			}
		for(c = 0; c < apstaessidcount; c++)
			{
			if(c == 0)
				{
				fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
				}
			else if(memcmp(zeigerold->essid, zeiger->essid, 32) != 0)
				{
				fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
				}
			zeigerold = zeiger;
			zeiger++;
			}
		}
	fclose(fhoutlist);
	removeemptyfile(essidoutname);
	}

if(staessidoutname != NULL)
	{
	if((fhoutlist = fopen(staessidoutname, "a+")) != NULL)
		{
		zeiger = apstaessidliste;
		zeigerold = zeiger;
		qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_essid);
		for(c = 0; c < apstaessidcount; c++)
			{
			if(memcmp(zeiger->mac_sta, &mac_broadcast, 6) != 0)
				{
				if(c == 0)
					{
					fwriteaddr1(zeiger->mac_sta, fhoutlist);
					fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
					}
				else if(memcmp(zeigerold->essid, zeiger->essid, 32) != 0)
					{
					fwriteaddr1(zeiger->mac_sta, fhoutlist);
					fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
					}
				}
			zeigerold = zeiger;
			zeiger++;
			}
		}
	fclose(fhoutlist);
	removeemptyfile(staessidoutname);
	}

if(pmkoutname != NULL)
	{
	if((fhoutlist = fopen(pmkoutname, "a+")) != NULL)
		{
		zeiger = apstaessidliste;
		zeigerold = zeiger;
		qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_essid);
		for(c = 0; c < apstaessidcount; c++)
			{
			if(c == 0)
				{
				if(zeiger->essidlen == 32)
					{
					fwritehexbuff(32, zeiger->essid, fhoutlist);
					}
				}
			else if(memcmp(zeigerold->essid, zeiger->essid, 32) != 0)
				{
				if(zeiger->essidlen == 32)
					{
					fwritehexbuff(32, zeiger->essid, fhoutlist);
					}
				}
			zeiger++;
			}
		}
	fclose(fhoutlist);
	removeemptyfile(pmkoutname);
	}

if(trafficoutname != NULL)
	{
	if((fhoutlist = fopen(trafficoutname, "a+")) != NULL)
		{
		zeiger = apstaessidliste;
		zeigerold = apstaessidliste;
		qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_sta_essid);
		for(c = 0; c < apstaessidcount; c++)
			{
			if(c == 0)
				{
				fwriteaddr1addr2(zeiger->mac_sta, zeiger->mac_ap, fhoutlist);
				fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
				}
			else if((memcmp(zeigerold->mac_ap, zeiger->mac_ap, 6) != 0) && (memcmp(zeigerold->mac_sta, zeiger->mac_sta, 6) != 0) && (memcmp(zeigerold, zeiger->essid, 32) != 0))
				{
				fwriteaddr1addr2(zeiger->mac_sta, zeiger->mac_ap, fhoutlist);
				fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
				}
			zeigerold = zeiger;
			zeiger++;
			}
		}
	fclose(fhoutlist);
	removeemptyfile(trafficoutname);
	}
return;
}
/*===========================================================================*/
static int getmessagepair(hcxl_t *zeiger)
{
int messagepair = 0x80;

if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 4))
	{
	messagepair = MESSAGE_PAIR_M12E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		messagepair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 4))
	{
	messagepair = MESSAGE_PAIR_M32E2;
	if(zeiger->replaycount_ap -1 != zeiger->replaycount_sta)
		{
		messagepair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 16) && (zeiger->keyinfo_sta == 4))
	{
	messagepair = MESSAGE_PAIR_M32E3;
	if(zeiger->replaycount_ap -1 != zeiger->replaycount_sta)
		{
		messagepair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 8))
	{
	messagepair = MESSAGE_PAIR_M14E4;
	if(zeiger->replaycount_ap +1 != zeiger->replaycount_sta)
		{
		messagepair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 8))
	{
	messagepair = MESSAGE_PAIR_M34E4;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		messagepair |= 0x80;
		}
	}
messagepair |= zeiger->endianess;
return messagepair;
}

/*===========================================================================*/
void outputwpacrossoverlists()
{
unsigned long long int c, d, p;
uint8_t essidok;
hcxl_t *zeiger;
pmkidl_t *zeigerpmkid;
apstaessidl_t *zeigeressid;
FILE *fhoutlist = NULL;
unsigned long long int writtencount, essidchangecount;

uint8_t essidold[ESSID_LEN_MAX];

if(handshakeliste == NULL)
	{
	return;
	}
if(apstaessidlistecleaned != NULL)
	{
	qsort(apstaessidlistecleaned, apstaessidcountcleaned, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_essid);
	}

if(apstaessidliste != NULL)
	{
	qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_essid);
	}

if((apstaessidlistecleaned != NULL) && (wpa12bestoutname != NULL))
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(wpa12bestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidlistecleaned;
			essidchangecount = 0;
			memset(&essidold, 0,32);
			essidok = 0;
			for(d = 0; d < apstaessidcountcleaned; d++)
				{
				if((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) && (memcmp(zeiger->mac_sta, zeigeressid->mac_sta, 6) == 0))
					{
					if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
						{
						zeiger->essidlen = zeigeressid->essidlen;
						memset(zeiger->essid, 0, 32);
						memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
						writtencount++;
						essidchangecount++;
						memset(&essidold, 0,32);
						memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
						essidok = 1;
						}
					}
				if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
					{
					break;
					}
				zeigeressid++;
				}
			if(essidok == 0)
				{
				zeigeressid = apstaessidlistecleaned;
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							writtencount++;
							essidchangecount++;
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							}
						}
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					zeigeressid++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hccapxbestoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu handshake(s) written to %s\n", writtencount, wpa12bestoutname);
		}
	}

if((apstaessidlistecleaned != NULL) && (wpa12bestoutname != NULL))
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(wpa12bestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeigerpmkid = pmkidliste;
		for(c = 0; c < pmkidcount; c++)
			{
			zeigeressid = apstaessidlistecleaned;
			essidchangecount = 0;
			memset(&essidold, 0,32);
			essidok = 0;
			for(d = 0; d < apstaessidcountcleaned; d++)
				{
				if((memcmp(zeigerpmkid->mac_ap, zeigeressid->mac_ap, 6) == 0) && (memcmp(zeigerpmkid->mac_sta, zeigeressid->mac_sta, 6) == 0))
					{
					if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
						{
						for(p = 0; p < 16; p++)
							{
							fprintf(fhoutlist, "%02x", zeigerpmkid->pmkid[p]);
							}
						fprintf(fhoutlist, ":");
						for(p = 0; p < 6; p++)
							{
							fprintf(fhoutlist, "%02x", zeigerpmkid->mac_ap[p]);
							}
						fprintf(fhoutlist, ":");
						for(p = 0; p < 6; p++)
							{
							fprintf(fhoutlist, "%02x", zeigerpmkid->mac_sta[p]);
							}
						fprintf(fhoutlist, ":");
						for(p = 0; p < zeigeressid->essidlen; p++)
							{
							fprintf(fhoutlist, "%02x", zeigeressid->essid[p]);
							}
						fprintf(fhoutlist, "\n");
						writtencount++;
						essidchangecount++;
						memset(&essidold, 0,32);
						memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
						essidok = 1;
						}
					}
				if(memcmp(zeigeressid->mac_ap, zeigerpmkid->mac_ap, 6) > 0)
					{
					break;
					}
				zeigeressid++;
				}
			if(essidok == 0)
				{
				zeigeressid = apstaessidlistecleaned;
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigerpmkid->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
							{


							for(p = 0; p < 16; p++)
								{
								fprintf(fhoutlist, "%02x", zeigerpmkid->pmkid[p]);
								}
							fprintf(fhoutlist, ":");
							for(p = 0; p < 6; p++)
								{
								fprintf(fhoutlist, "%02x", zeigerpmkid->mac_ap[p]);
								}
							fprintf(fhoutlist, ":");
							for(p = 0; p < 6; p++)
								{
								fprintf(fhoutlist, "%02x", zeigerpmkid->mac_sta[p]);
								}
							fprintf(fhoutlist, ":");
							for(p = 0; p < zeigeressid->essidlen; p++)
								{
								fprintf(fhoutlist, "%02x", zeigeressid->essid[p]);
								}
							fprintf(fhoutlist, "\n");


							writtencount++;
							essidchangecount++;
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							}
						}
					if(memcmp(zeigeressid->mac_ap, zeigerpmkid->mac_ap, 6) > 0)
						{
						break;
						}
					zeigeressid++;
					}
				}
			zeigerpmkid++;
			}
		fclose(fhoutlist);
		removeemptyfile(hcpmkidoldoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu PMKID(s) written to %s\n", writtencount, wpa12bestoutname);
		}
	}
return;
}
/*===========================================================================*/
void outputwpalists(char *pcapinname)
{
unsigned long long int c, d;
hcxl_t *zeiger;
apstaessidl_t *zeigeressid;
FILE *fhoutlist = NULL;
unsigned long long int writtencount;
int essidchangecount;
bool essidchangeflag;
int mp;
unsigned long long int mp0c = 0;
unsigned long long int mp1c = 0;
unsigned long long int mp2c = 0;
unsigned long long int mp3c = 0;
unsigned long long int mp4c = 0;
unsigned long long int mp5c = 0;
unsigned long long int mp80c = 0;
unsigned long long int mp81c = 0;
unsigned long long int mp82c = 0;
unsigned long long int mp83c = 0;
unsigned long long int mp84c = 0;
unsigned long long int mp85c = 0;

uint8_t essidold[ESSID_LEN_MAX];

if(handshakeliste == NULL)
	{
	return;
	}

if(apstaessidlistecleaned != NULL)
	{
	qsort(apstaessidlistecleaned, apstaessidcountcleaned, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_count_essid);
	}
	
if((apstaessidlistecleaned != NULL) && (hccapxbestoutname != NULL))
	{
	mp0c = 0;
	mp1c = 0;
	mp2c = 0;
	mp3c = 0;
	mp4c = 0;
	mp5c = 0;
	mp80c = 0;
	mp81c = 0;
	mp82c = 0;
	mp83c = 0;
	mp84c = 0;
	mp85c = 0;
	essidchangecount = 0;
	if((fhoutlist = fopen(hccapxbestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		essidchangeflag = false;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidlistecleaned;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			mp = getmessagepair(zeiger);
			if(((mp & 0x80) != 0x80) || (replaycountcheckflag == true))
				{
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					if(((maccheckflag == false) &&
					((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) &&
					((memcmp(zeiger->mac_sta, zeigeressid->mac_sta, 6) == 0) || (memcmp(&mac_broadcast, zeigeressid->mac_sta, 6) == 0)))) ||
					((maccheckflag == true) &&
					(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)))
						{
						if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							if(essidchangecount < maxessidchanges)
								{
								mp = getmessagepair(zeiger);
								writehccapxrecord(zeiger, fhoutlist);
								writtencount++;
								if((mp & 0x07) == MESSAGE_PAIR_M12E2)
									{
									mp0c++;
									if((mp & 0x80) == 0x80)
										{
										mp80c++;
										}
									}
								if((mp & 0x07) == MESSAGE_PAIR_M14E4)
									{
									mp1c++;
									if((mp & 0x80) == 0x80)
										{
										mp81c++;
										}
									}
								if((mp & 0x07) == MESSAGE_PAIR_M32E2)
									{
									mp2c++;
									if((mp & 0x80) == 0x80)
										{
										mp82c++;
										}
									}
								if((mp & 0x07) == MESSAGE_PAIR_M32E3)
									{
									mp3c++;
									if((mp & 0x80) == 0x80)
										{
										mp83c++;
										}
									}
								if((mp & 0x07) == MESSAGE_PAIR_M34E3)
									{
									mp4c++;
									if((mp & 0x80) == 0x80)
										{
										mp84c++;
										}
									}
								if((mp & 0x07) == MESSAGE_PAIR_M34E4)
									{
									mp5c++;
									if((mp & 0x80) == 0x80)
										{
										mp85c++;
										}
									}
								}
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							essidchangecount++;
							if(essidchangecount > 1)
								{
								essidchangeflag = true;
								}
							}
						}
					zeigeressid++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hccapxbestoutname);
		if(essidchangeflag == true)
			{
			printf("%llu handshake(s) written to %s (warning: ESSID changes detected)\n", writtencount, hccapxbestoutname);
			}
		else
			{
			printf("%llu handshake(s) written to %s\n", writtencount, hccapxbestoutname);
			}
		}
	}

if((apstaessidlistecleaned != NULL) && (hccapbestoutname != NULL))
	{
	mp0c = 0;
	mp1c = 0;
	mp2c = 0;
	mp3c = 0;
	mp4c = 0;
	mp5c = 0;
	mp80c = 0;
	mp81c = 0;
	mp82c = 0;
	mp83c = 0;
	mp84c = 0;
	mp85c = 0;
	essidchangecount = 0;
	if((fhoutlist = fopen(hccapbestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		essidchangeflag = false;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidlistecleaned;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			mp = getmessagepair(zeiger);
			if(((mp & 0x80) != 0x80) || (replaycountcheckflag == true))
				{
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					if(((maccheckflag == false) &&
					((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) &&
					((memcmp(zeiger->mac_sta, zeigeressid->mac_sta, 6) == 0) || (memcmp(&mac_broadcast, zeigeressid->mac_sta, 6) == 0)))) ||
					((maccheckflag == true) &&
					(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)))
						{
						if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							if(essidchangecount < maxessidchanges)
								{
								if(maxrcdiff > 8)
									{
									writehccaprecord(8, zeiger, fhoutlist);
									}
								else
									{
									writehccaprecord(maxrcdiff, zeiger, fhoutlist);
									}
								writehccaprecord(maxrcdiff, zeiger, fhoutlist);
								writtencount++;
								if((mp & 0x07) == 0)
									{
									mp0c++;
									if((mp & 0x80) == 0x80)
										{
										mp80c++;
										}
									}
								if((mp & 0x07) == 1)
									{
									mp1c++;
									if((mp & 0x80) == 0x80)
										{
										mp81c++;
										}
									}
								if((mp & 0x07) == 2)
									{
									mp2c++;
									if((mp & 0x80) == 0x80)
										{
										mp82c++;
										}
									}
								if((mp & 0x07) == 3)
									{
									mp3c++;
									if((mp & 0x80) == 0x80)
										{
										mp83c++;
										}
									}
								if((mp & 0x07) == 4)
									{
									mp4c++;
									if((mp & 0x80) == 0x80)
										{
										mp84c++;
										}
									}
								if((mp & 0x07) == 5)
									{
									mp5c++;
									if((mp & 0x80) == 0x80)
										{
										mp85c++;
										}
									}
								}
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							essidchangecount++;
							if(essidchangecount > 1)
								{
								essidchangeflag = true;
								}
							}
						}
					zeigeressid++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hccapbestoutname);
		if(essidchangeflag == true)
			{
			printf("%llu handshake(s) written to %s (warning: ESSID changes detected)\n", writtencount, hccapbestoutname);
			}
		else
			{
			printf("%llu handshake(s) written to %s\n", writtencount, hccapbestoutname);
			}
		}
	}

if((apstaessidlistecleaned != NULL) && (johnbestoutname != NULL))
	{
	mp0c = 0;
	mp1c = 0;
	mp2c = 0;
	mp3c = 0;
	mp4c = 0;
	mp5c = 0;
	mp80c = 0;
	mp81c = 0;
	mp82c = 0;
	mp83c = 0;
	mp84c = 0;
	mp85c = 0;
	essidchangecount = 0;
	if((fhoutlist = fopen(johnbestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		essidchangeflag = false;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidlistecleaned;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			mp = getmessagepair(zeiger);
			if(((mp & 0x80) != 0x80) || (replaycountcheckflag == true))
				{
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					if(((maccheckflag == false) &&
					((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) &&
					((memcmp(zeiger->mac_sta, zeigeressid->mac_sta, 6) == 0) || (memcmp(&mac_broadcast, zeigeressid->mac_sta, 6) == 0)))) ||
					((maccheckflag == true) &&
					(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)))
						{
						if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							if(essidchangecount < maxessidchanges)
								{
								if(maxrcdiff > 8)
									{
									writejohnrecord(8, zeiger, fhoutlist, pcapinname);
									}
								else
									{
									writejohnrecord(maxrcdiff, zeiger, fhoutlist, pcapinname);
									}
								writtencount++;
								if((mp & 0x07) == 0)
									{
									mp0c++;
									if((mp & 0x80) == 0x80)
										{
										mp80c++;
										}
									}
								if((mp & 0x07) == 1)
									{
									mp1c++;
									if((mp & 0x80) == 0x80)
										{
										mp81c++;
										}
									}
								if((mp & 0x07) == 2)
									{
									mp2c++;
									if((mp & 0x80) == 0x80)
										{
										mp82c++;
										}
									}
								if((mp & 0x07) == 3)
									{
									mp3c++;
									if((mp & 0x80) == 0x80)
										{
										mp83c++;
										}
									}
								if((mp & 0x07) == 4)
									{
									mp4c++;
									if((mp & 0x80) == 0x80)
										{
										mp84c++;
										}
									}
								if((mp & 0x07) == 5)
									{
									mp5c++;
									if((mp & 0x80) == 0x80)
										{
										mp85c++;
										}
									}
								}
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							essidchangecount++;
							if(essidchangecount > 1)
								{
								essidchangeflag = true;
								}
							}
						}
					zeigeressid++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(johnbestoutname);
		if(essidchangeflag == true)
			{
			printf("%llu handshake(s) written to %s (warning: ESSID changes detected)\n", writtencount, johnbestoutname);
			}
		else
			{
			printf("%llu handshake(s) written to %s\n", writtencount, johnbestoutname);
			}
		}
	}
if(mp0c != 0)
	{
	printf("message pair M12E2...............: %lld", mp0c);
	if(mp80c != 0)
		{
		printf(" (warning: %lld not replaycount checked)", mp80c);
		}
	printf("\n");
	}
if(mp1c != 0)
	{
	printf("message pair M14E4...............: %lld", mp1c);
	if(mp81c != 0)
		{
		printf(" (warning: %lld not replaycount checked)", mp81c);
		}
	printf("\n");
	}
if(mp2c != 0)
	{
	printf("message pair M32E2...............: %lld", mp2c);
	if(mp82c != 0)
		{
		printf(" (warning: %lld not replaycount checked)", mp82c);
		}
	printf("\n");
	}
if(mp3c != 0)
	{
	printf("message pair M32E3...............: %lld", mp3c);
	if(mp83c != 0)
		{
		printf(" (warning: %lld not replaycount checked)", mp83c);
		}
	printf("\n");
	}
if(mp4c != 0)
	{
	printf("message pair M34E3...............: %lld", mp4c);
	if(mp84c != 0)
		{
		printf(" (warning: %lld not replaycount checked)", mp84c);
		}
	printf("\n");
	}
if(mp5c != 0)
	{
	printf("message pair M34E4...............: %lld", mp5c);
	if(mp85c != 0)
		{
		printf(" (warning: %lld not replaycount checked)", mp85c);
		}
	printf("\n");
	}
return;
}
/*===========================================================================*/
void outputrawwpalists(char *pcapinname)
{
unsigned long long int c, d;
hcxl_t *zeiger;
apstaessidl_t *zeigeressid;
FILE *fhoutlist = NULL;
unsigned long long int writtencount, essidchangecount;

uint8_t essidold[ESSID_LEN_MAX];

if(rawhandshakeliste == NULL)
	{
	return;
	}
if(apstaessidlistecleaned != NULL)
	{
	qsort(apstaessidlistecleaned, apstaessidcountcleaned, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_essid);
	}

if(hccapxrawoutname != NULL)
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(hccapxrawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = rawhandshakeliste;
		for(c = 0; c < rawhandshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			if(apstaessidliste != NULL)
				{
				zeigeressid = apstaessidliste;
				essidchangecount = 0;
				memset(&essidold, 0,32);
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							writehccapxrecord(zeiger, fhoutlist);
							writtencount++;
							essidchangecount++;
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							}
						}
					zeigeressid++;
					}
				}
			else
				{
				if(writtencount == 0)
					{
					memset(zeiger->essid, 0, 32);
					zeiger->essidlen = 0;
					writehccapxrecord(zeiger, fhoutlist);
					writtencount++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hccapxrawoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu handshake(s) written to %s\n", writtencount, hccapxrawoutname);
		}
	}

if(hccaprawoutname != NULL)
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(hccaprawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = rawhandshakeliste;
		for(c = 0; c < rawhandshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			if(apstaessidliste != NULL)
				{
				zeigeressid = apstaessidliste;
				essidchangecount = 0;
				memset(&essidold, 0,32);
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							if(maxrcdiff > 8)
								{
								writehccaprecord(8, zeiger, fhoutlist);
								}
							else
								{
								writehccaprecord(maxrcdiff, zeiger, fhoutlist);
								}
							writtencount++;
							essidchangecount++;
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							}
						}
					zeigeressid++;
					}
				}
			else
				{
				if(writtencount == 0)
					{
					memset(zeiger->essid, 0, 32);
					zeiger->essidlen = 0;
					if(maxrcdiff > 8)
						{
						writehccaprecord(8, zeiger, fhoutlist);
						}
					else
						{
						writehccaprecord(maxrcdiff, zeiger, fhoutlist);
						}
					writtencount++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hccaprawoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu handshake(s) written to %s\n", writtencount, hccaprawoutname);
		}
	}

if(johnrawoutname != NULL)
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(johnrawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = rawhandshakeliste;
		for(c = 0; c < rawhandshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			if(apstaessidliste != NULL)
				{
				zeigeressid = apstaessidliste;
				memset(&essidold, 0,32);
				essidchangecount = 0;
				for(d = 0; d < apstaessidcountcleaned; d++)
					{
					if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
						{
						break;
						}
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							if(maxrcdiff > 8)
								{
								writejohnrecord(8, zeiger, fhoutlist, pcapinname);
								}
							else
								{
								writejohnrecord(maxrcdiff, zeiger, fhoutlist, pcapinname);
								}
							writtencount++;
							essidchangecount++;
							memset(&essidold, 0,32);
							memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
							}
						}
					zeigeressid++;
					}
				}
			else
				{
				if(writtencount == 0)
					{
					memset(zeiger->essid, 0, 32);
					zeiger->essidlen = 0;
					if(maxrcdiff > 8)
						{
						writejohnrecord(8, zeiger, fhoutlist, pcapinname);
						}
					else
						{
						writejohnrecord(maxrcdiff, zeiger, fhoutlist, pcapinname);
						}
					writtencount++;
					}
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hccaprawoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu handshake(s) written to %s\n", writtencount, johnrawoutname);
		}
	}
return;
}
/*===========================================================================*/
void outputpmkidlists()
{
unsigned long long int c, d, p, writtencount;
int essidchangecount;
bool essidchangeflag;
pmkidl_t *zeiger;
apstaessidl_t *zeigeressid;
FILE *fhoutlist = NULL;

uint8_t essidold[ESSID_LEN_MAX];

if(apstaessidlistecleaned != NULL)
	{
	qsort(apstaessidlistecleaned, apstaessidcountcleaned, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_count_essid);
	}

if((apstaessidlistecleaned != NULL) && (hcpmkidoutname != NULL))
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(hcpmkidoutname, "a+")) != NULL)
		{
		writtencount = 0;
		essidchangeflag = false;
		zeiger = pmkidliste;
		for(c = 0; c < pmkidcount; c++)
			{
			zeigeressid = apstaessidlistecleaned;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			for(d = 0; d < apstaessidcountcleaned; d++)
				{
				if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
					{
					break;
					}
				if(((maccheckflag == false) &&
				((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) &&
				((memcmp(zeiger->mac_sta, zeigeressid->mac_sta, 6) == 0) || (memcmp(&mac_broadcast, zeigeressid->mac_sta, 6) == 0)))) ||
				((maccheckflag == true) &&
				(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)))
					{
					if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
						{
						if(essidchangecount < maxessidchanges)
							{
							for(p = 0; p < 16; p++)
								{
								fprintf(fhoutlist, "%02x", zeiger->pmkid[p]);
								}
							fprintf(fhoutlist, ":");
							for(p = 0; p < 6; p++)
								{
								fprintf(fhoutlist, "%02x", zeiger->mac_ap[p]);
								}
							fprintf(fhoutlist, ":");
							for(p = 0; p < 6; p++)
								{
								fprintf(fhoutlist, "%02x", zeiger->mac_sta[p]);
								}
							fprintf(fhoutlist, ":");
							for(p = 0; p < zeigeressid->essidlen; p++)
								{
								fprintf(fhoutlist, "%02x", zeigeressid->essid[p]);
								}
							fprintf(fhoutlist, "\n");
							writtencount++;
							}
						memset(&essidold, 0,32);
						memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
						essidchangecount++;
						if(essidchangecount > 1)
							{
							essidchangeflag = true;
							}
						}
					}
				zeigeressid++;
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hcpmkidoutname);
		if(essidchangeflag == true)
			{
			printf("%llu PMKID(s) written to %s (warning: ESSID changes detected)\n", writtencount, hcpmkidoutname);
			}
		else
			{
			printf("%llu PMKID(s) written to %s\n", writtencount, hcpmkidoutname);
			}
		}
	}

if((apstaessidlistecleaned != NULL) && (hcpmkidoldoutname != NULL))
	{
	essidchangecount = 0;
	if((fhoutlist = fopen(hcpmkidoldoutname, "a+")) != NULL)
		{
		writtencount = 0;
		essidchangeflag = false;
		zeiger = pmkidliste;
		for(c = 0; c < pmkidcount; c++)
			{
			zeigeressid = apstaessidlistecleaned;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			for(d = 0; d < apstaessidcountcleaned; d++)
				{
				if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
					{
					break;
					}
				if(((maccheckflag == false) &&
				((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) &&
				((memcmp(zeiger->mac_sta, zeigeressid->mac_sta, 6) == 0) || (memcmp(&mac_broadcast, zeigeressid->mac_sta, 6) == 0)))) ||
				((maccheckflag == true) &&
				(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)))
					{
					if(memcmp(&essidold, zeigeressid->essid, 32) != 0)
						{
						for(p = 0; p < 16; p++)
							{
							fprintf(fhoutlist, "%02x", zeiger->pmkid[p]);
							}
						fprintf(fhoutlist, "*");
						for(p = 0; p < 6; p++)
							{
							fprintf(fhoutlist, "%02x", zeiger->mac_ap[p]);
							}
						fprintf(fhoutlist, "*");
						for(p = 0; p < 6; p++)
							{
							fprintf(fhoutlist, "%02x", zeiger->mac_sta[p]);
							}
						fprintf(fhoutlist, "*");
						for(p = 0; p < zeigeressid->essidlen; p++)
							{
							fprintf(fhoutlist, "%02x", zeigeressid->essid[p]);
							}
						fprintf(fhoutlist, "\n");
						writtencount++;
						memset(&essidold, 0,32);
						memcpy(&essidold, zeigeressid->essid, zeigeressid->essidlen);
						essidchangecount++;
						if(essidchangecount > 1)
							{
							essidchangeflag = true;
							}
						if(essidchangecount >= maxessidchanges)
							{
							break;
							}
						}
					}
				zeigeressid++;
				}
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hcpmkidoldoutname);
		if(essidchangeflag == true)
			{
			printf("%llu PMKID(s) written to %s (warning: ESSID changes detected)\n", writtencount, hcpmkidoldoutname);
			}
		else
			{
			printf("%llu PMKID(s) written to %s\n", writtencount, hcpmkidoldoutname);
			}
		}
	}
return;
}
/*===========================================================================*/
void outputrawpmkidlists()
{
unsigned long long int c, p, writtencount;
pmkidl_t *zeiger;
FILE *fhoutlist = NULL;

if(hcpmkidrawoutname != NULL)
	{
	if((fhoutlist = fopen(hcpmkidrawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = pmkidliste;
		for(c = 0; c < pmkidcount; c++)
			{
			for(p = 0; p < 16; p++)
				{
				fprintf(fhoutlist, "%02x", zeiger->pmkid[p]);
				}
			fprintf(fhoutlist, ":");
			for(p = 0; p < 6; p++)
				{
				fprintf(fhoutlist, "%02x", zeiger->mac_ap[p]);
				}
			fprintf(fhoutlist, ":");
			for(p = 0; p < 6; p++)
				{
				fprintf(fhoutlist, "%02x", zeiger->mac_sta[p]);
				}
			fprintf(fhoutlist, "\n");
			writtencount++;
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hcpmkidrawoutname);
		printf("%llu raw PMKID(s) written to %s\n", writtencount, hcpmkidrawoutname);
		}
	}

if(hcpmkidrawoldoutname != NULL)
	{
	if((fhoutlist = fopen(hcpmkidrawoldoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = pmkidliste;
		for(c = 0; c < pmkidcount; c++)
			{
			for(p = 0; p < 16; p++)
				{
				fprintf(fhoutlist, "%02x", zeiger->pmkid[p]);
				}
			fprintf(fhoutlist, "*");
			for(p = 0; p < 6; p++)
				{
				fprintf(fhoutlist, "%02x", zeiger->mac_ap[p]);
				}
			fprintf(fhoutlist, "*");
			for(p = 0; p < 6; p++)
				{
				fprintf(fhoutlist, "%02x", zeiger->mac_sta[p]);
				}
			fprintf(fhoutlist, "\n");
			writtencount++;
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(hcpmkidrawoldoutname);
		printf("%llu raw PMKID(s) written to %s\n", writtencount, hcpmkidrawoldoutname);
		}
	}
return;
}
/*===========================================================================*/
void outputleaplist()
{
unsigned long long int c, d, writtencount;
leapl_t *zeigerrq, *zeigerrs;
FILE *fhoutlist = NULL;

if(netntlm1outname != NULL)
	{
	if((fhoutlist = fopen(netntlm1outname, "a+")) != NULL)
		{
		writtencount = 0;
		zeigerrq = leapliste;
		for(c = 0; c < leapcount; c++)
			{
			if(zeigerrq->code == EAP_CODE_REQ)
				{
				zeigerrs = leapliste;
				for(d = 0; d < leapcount; d++)
					{
					if(zeigerrs->code == EAP_CODE_RESP)
						{
						if((zeigerrq->id == zeigerrs->id) && (zeigerrq->username_len != 0))
							{
							fwriteessidstrnoret(zeigerrq->username_len, zeigerrq->username, fhoutlist);
							fprintf(fhoutlist, ":::");
							fwritehexbuffraw(zeigerrs->len, zeigerrs->data, fhoutlist);
							fprintf(fhoutlist, ":");
							fwritehexbuff(zeigerrq->len, zeigerrq->data, fhoutlist);
							writtencount++;
							}
						else if((zeigerrq->id == zeigerrs->id) && (zeigerrs->username_len != 0))
							{
							fwriteessidstrnoret(zeigerrs->username_len, zeigerrs->username, fhoutlist);
							fprintf(fhoutlist, ":::");
							fwritehexbuffraw(zeigerrs->len, zeigerrs->data, fhoutlist);
							fprintf(fhoutlist, ":");
							fwritehexbuff(zeigerrq->len, zeigerrq->data, fhoutlist);
							writtencount++;
							}
						}
					zeigerrs++;
					}
				}
			zeigerrq++;
			}
		fclose(fhoutlist);
		removeemptyfile(netntlm1outname);
		printf("%llu netNTLMv1 written to %s\n", writtencount, netntlm1outname);
		}
	}
return;
}
/*===========================================================================*/
void outputpppchaplist()
{
unsigned long long int c, d, writtencount;
leapl_t *zeigerrq, *zeigerrs;
FILE *fhoutlist = NULL;
char *un_ptr = NULL;
SHA_CTX ctxsha1;
unsigned char digestsha1[SHA_DIGEST_LENGTH];

if(netntlm1outname != NULL)
	{
	if((fhoutlist = fopen(netntlm1outname, "a+")) != NULL)
		{
		writtencount = 0;
		zeigerrq = leap2liste;
		for(c = 0; c < leap2count; c++)
			{
			if(zeigerrq->code == EAP_CODE_REQ)
				{
				zeigerrs = leap2liste;
				for(d = 0; d < leap2count; d++)
					{
					if(zeigerrs->code == EAP_CODE_RESP)
						{
						if((zeigerrq->id == zeigerrs->id) && (zeigerrs->username_len != 0))
							{
							fwriteessidstrnoret(zeigerrs->username_len, zeigerrs->username, fhoutlist);
							fprintf(fhoutlist, ":::");
							fwritehexbuffraw(24, &zeigerrs->data[zeigerrs->len -25], fhoutlist);
							fprintf(fhoutlist, ":");
							SHA1_Init(&ctxsha1);
							SHA1_Update(&ctxsha1, zeigerrs->data, 16);
							SHA1_Update(&ctxsha1, zeigerrq->data, 16);
							un_ptr = strchr((const char*)zeigerrs->username, '\\');
							if(un_ptr == NULL)
								{
								SHA1_Update(&ctxsha1, zeigerrs->username, zeigerrs->username_len);
								}
							else
								{
								un_ptr++;
								SHA1_Update(&ctxsha1, un_ptr, strlen(un_ptr));
								}
							SHA1_Final(digestsha1, &ctxsha1);
							fwritehexbuff(8, digestsha1, fhoutlist);
							writtencount++;
							}
						}
					zeigerrs++;
					}
				}
			zeigerrq++;
			}
		fclose(fhoutlist);
		removeemptyfile(netntlm1outname);
		printf("%llu PPP-CHAP written to %s\n", writtencount, netntlm1outname);
		}
	}
return;
}
/*===========================================================================*/
void outputmd5list()
{
unsigned long long int c, d, writtencount;
md5l_t *zeigerrq, *zeigerrs;
FILE *fhoutlist = NULL;

if(md5outname != NULL)
	{
	if((fhoutlist = fopen(md5outname, "a+")) != NULL)
		{
		writtencount = 0;
		zeigerrq = md5liste;
		for(c = 0; c < md5count; c++)
			{
			if(zeigerrq->code == EAP_CODE_REQ)
				{
				zeigerrs = md5liste;
				for(d = 0; d < md5count; d++)
					{
					if(zeigerrs->code == EAP_CODE_RESP)
						{
						if(zeigerrq->id == zeigerrs->id)
							{
							fwritehexbuffraw(zeigerrs->len, zeigerrs->data, fhoutlist);
							fprintf(fhoutlist, ":");
							fwritehexbuffraw(zeigerrq->len, zeigerrq->data, fhoutlist);
							fprintf(fhoutlist, ":%02x\n", zeigerrs->id);
							writtencount++;
							}
						}
					zeigerrs++;
					}
				}
			zeigerrq++;
			}
		fclose(fhoutlist);
		removeemptyfile(md5outname);
		printf("%llu MD5 challenge written to %s\n", writtencount, md5outname);
		}
	}

if(md5johnoutname != NULL)
	{
	if((fhoutlist = fopen(md5johnoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeigerrq = md5liste;
		for(c = 0; c < md5count; c++)
			{
			if(zeigerrq->code == EAP_CODE_REQ)
				{
				zeigerrs = md5liste;
				for(d = 0; d < md5count; d++)
					{
					if(zeigerrs->code == EAP_CODE_RESP)
						{
						if(zeigerrq->id == zeigerrs->id)
							{
							fprintf(fhoutlist, "$chap$%x*", zeigerrs->id);
							fwritehexbuffraw(zeigerrq->len, zeigerrq->data, fhoutlist);
							fprintf(fhoutlist, "*");
							fwritehexbuffraw(zeigerrs->len, zeigerrs->data, fhoutlist);
							fprintf(fhoutlist, "\n");
							writtencount++;
							}
						}
					zeigerrs++;
					}
				}
			zeigerrq++;
			}
		fclose(fhoutlist);
		removeemptyfile(md5outname);
		printf("%llu MD5 challenge written to %s\n", writtencount, md5johnoutname);
		}
	}
return;
}
/*===========================================================================*/
void outputtacacsplist()
{
unsigned long long int c, writtencount;
uint32_t d;
tacacspl_t *zeiger;
FILE *fhoutlist = NULL;

zeiger = tacacspliste;
if(tacacspoutname != NULL)
	{
	if((fhoutlist = fopen(tacacspoutname, "a+")) != NULL)
		{
		writtencount = 0;
		for(c = 0; c < tacacspcount; c++)
			{
			fprintf(fhoutlist, "$tacacs-plus$0$%08x$", ntohl(zeiger->sessionid));
			for(d = 0; d < zeiger->len; d++)
				{
				fprintf(fhoutlist, "%02x", zeiger->data[d]);
				}
			fprintf(fhoutlist, "$%02x%02x\n", zeiger->version, zeiger->sequencenr);
			writtencount++;
			zeiger++;
			}
		fclose(fhoutlist);
		removeemptyfile(tacacspoutname);
		printf("%llu TACACS+ autnetication written to %s\n", writtencount, tacacspoutname);
		}
	}
return;
}
/*===========================================================================*/
void outlistusername(uint32_t ulen, uint8_t *packet)
{
FILE *fhoutlist = NULL;

if(packet[0] == 0)
	{
	return;
	}

if(useroutname != NULL)
	{
	if((fhoutlist = fopen(useroutname, "a+")) != NULL)
		{
		fwriteessidstr(ulen, packet, fhoutlist);
		fclose(fhoutlist);
		}
	}
return;
}
/*===========================================================================*/
void outlistidentity(uint32_t idlen, uint8_t *packet)
{
FILE *fhoutlist = NULL;
uint32_t idcount = 5;

if(idlen <= idcount)
	{
	return;
	}

if((packet[idcount] == 0) && (idlen > idcount +1))
	{
	idcount++;
	if((packet[idcount] == 0) && (idlen <= idcount +1))
		{
		return;
		}
	}
if(identityoutname != NULL)
	{
	if((fhoutlist = fopen(identityoutname, "a+")) != NULL)
		{
		fwriteessidstr(idlen -idcount, (packet +idcount), fhoutlist);
		fclose(fhoutlist);
		}
	}
return;
}
/*===========================================================================*/
void outlistimsi(uint32_t idlen, uint8_t *packet)
{
FILE *fhoutlist = NULL;
uint32_t idcount = 5;

if(idlen <= idcount)
	{
	return;
	}

if((packet[idcount] == 0) && (idlen > idcount +1))
	{
	idcount++;
	if((packet[idcount] == 0) && (idlen <= idcount +1))
		{
		return;
		}
	}
if((idlen -idcount) < 17)
	{
	return;
	}
if(packet[idcount] != '0')
	{
	return;
	}
if(packet[idcount +16] != '@')
	{
	return;
	}
if(imsioutname != NULL)
	{
	if((fhoutlist = fopen(imsioutname, "a+")) != NULL)
		{
		fwriteessidstr(15, (packet +idcount +1), fhoutlist);
		fclose(fhoutlist);
		}
	}
return;
}
/*===========================================================================*/
static void writegpwpl(uint8_t *mac)
{
static int c;
static int cs;

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
fprintf(fhnmea, "%s\n", gpwpl);
return;
}
/*===========================================================================*/
void addtacacsp(uint8_t version, uint8_t sequencenr, uint32_t sessionid, uint32_t len, uint8_t *data)
{
tacacspl_t *zeiger;
unsigned long long int c;

if(tacacspliste == NULL)
	{
	tacacspliste = malloc(TACACSPLIST_SIZE);
	if(tacacspliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(tacacspliste, 0, TACACSPLIST_SIZE);
	tacacspliste->version = version;
	tacacspliste->sequencenr = sequencenr;
	tacacspliste->sessionid = sessionid;
	tacacspliste->len = len;
	memcpy(tacacspliste->data, data, len);
	tacacspcount++;
	return;
	}

zeiger = tacacspliste;
for(c = 0; c < tacacspcount; c++)
	{
	if((zeiger->version == version) && (zeiger->sequencenr == sequencenr) && (zeiger->sessionid == sessionid) && (zeiger->len == len) && (memcmp(zeiger->data, data, len) == 0))
		{
		return;
		}
	zeiger++;
	}

zeiger = realloc(tacacspliste, (tacacspcount +1) *TACACSPLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
tacacspliste = zeiger;
zeiger = tacacspliste +tacacspcount;
memset(zeiger, 0, TACACSPLIST_SIZE);
zeiger->version = version;
zeiger->sequencenr = sequencenr;
zeiger->sessionid = sessionid;
zeiger->len = len;
memcpy(zeiger->data, data, len);
tacacspcount++;
return;
}
/*===========================================================================*/
void addeapmd5(uint8_t code, uint8_t id, uint8_t len, uint8_t *data)
{
md5l_t *zeiger;
unsigned long long int c;

if(md5liste == NULL)
	{
	md5liste = malloc(MD5LIST_SIZE);
	if(md5liste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(md5liste, 0, MD5LIST_SIZE);
	md5liste->code = code;
	md5liste->id = id;
	md5liste->len = len;
	memcpy(md5liste->data, data, len);
	md5count++;
	return;
	}

zeiger = md5liste;
for(c = 0; c < md5count; c++)
	{
	if((zeiger->code == code) && (zeiger->id == id) && (zeiger->len == len) && (memcmp(zeiger->data, data, len) == 0))
		{
		return;
		}
	zeiger++;
	}
zeiger = realloc(md5liste, (md5count +1) *MD5LIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
md5liste = zeiger;
zeiger = md5liste +md5count;
memset(zeiger, 0, MD5LIST_SIZE);
zeiger->code = code;
zeiger->id = id;
zeiger->len = len;
memcpy(zeiger->data, data, len);
md5count++;
return;
}
/*===========================================================================*/
void addpppchapleap(uint8_t code, uint8_t id, uint8_t count, uint8_t *data, uint8_t usernamelen, uint8_t *username)
{
leapl_t *zeiger;
unsigned long long int c;

if(leap2liste == NULL)
	{
	leap2liste = malloc(LEAPLIST_SIZE);
	if(leap2liste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(leap2liste, 0, LEAPLIST_SIZE);
	leap2liste->code = code;
	leap2liste->id = id;
	leap2liste->len = count;
	memcpy(leap2liste->data, data, count);
	leap2liste->username_len = usernamelen;
	memcpy(leap2liste->username, username, usernamelen);
	leap2count++;
	return;
	}

zeiger = leap2liste;
for(c = 0; c < leap2count; c++)
	{
	if((zeiger->code == code) && (zeiger->id == id) && (zeiger->len == count) && (memcmp(zeiger->data, data, count) == 0))
		{
		return;
		}
	zeiger++;
	}
zeiger = realloc(leap2liste, (leap2count +1) *LEAPLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
leap2liste = zeiger;
zeiger = leap2liste +leap2count;
memset(zeiger, 0, LEAPLIST_SIZE);
zeiger->code = code;
zeiger->id = id;
zeiger->len = count;
memcpy(zeiger->data, data, count);
zeiger->username_len = usernamelen;
memcpy(zeiger->username, username, usernamelen);
leap2count++;
return;
}
/*===========================================================================*/
void addeapleap(uint8_t code, uint8_t id, uint8_t count, uint8_t *data, uint16_t usernamelen, uint8_t *username)
{
leapl_t *zeiger;
unsigned long long int c;

if(leapliste == NULL)
	{
	leapliste = malloc(LEAPLIST_SIZE);
	if(leapliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(leapliste, 0, LEAPLIST_SIZE);
	leapliste->code = code;
	leapliste->id = id;
	leapliste->len = count;
	memcpy(leapliste->data, data, count);
	leapliste->username_len = usernamelen;
	memcpy(leapliste->username, username, usernamelen);
	leapcount++;
	return;
	}

zeiger = leapliste;
for(c = 0; c < leapcount; c++)
	{
	if((zeiger->code == code) && (zeiger->id == id) && (zeiger->len == count) && (memcmp(zeiger->data, data, count) == 0) && (zeiger->username_len == usernamelen) && (memcmp(zeiger->username, username, usernamelen) == 0))
		{
		return;
		}
	zeiger++;
	}

zeiger = realloc(leapliste, (leapcount +1) *LEAPLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
leapliste = zeiger;
zeiger = leapliste +leapcount;
memset(zeiger, 0, LEAPLIST_SIZE);
zeiger->code = code;
zeiger->id = id;
zeiger->len = count;
memcpy(zeiger->data, data, count);
zeiger->username_len = usernamelen;
memcpy(zeiger->username, username, usernamelen);
leapcount++;
return;
}
/*===========================================================================*/
void addrawhandshake(uint64_t tv_ea, eapoll_t *zeigerea, uint64_t tv_eo, eapoll_t *zeigereo, uint64_t timegap, uint64_t rcgap)
{
hcxl_t *zeiger;
unsigned long long int c;
wpakey_t *wpae, *wpaea, *wpaeo;
uint32_t anonce, anonceold;

bool checkok = false;

wpaea = (wpakey_t*)(zeigerea->eapol +EAPAUTH_SIZE);
wpaeo = (wpakey_t*)(zeigereo->eapol +EAPAUTH_SIZE);

if((zeigerea->keyinfo == 4) && (zeigereo->keyinfo == 1) && (zeigerea->replaycount == zeigereo->replaycount) && (tv_ea > tv_eo))
	{
	checkok = true;
	}
if((zeigerea->keyinfo == 8) && (zeigereo->keyinfo == 2) && (zeigerea->replaycount == zeigereo->replaycount) && (tv_ea > tv_eo))
	{
	checkok = true;
	}
if(((zeigerea->keyinfo == 8) && (zeigereo->keyinfo == 1)) && (zeigerea->replaycount == zeigereo->replaycount +1) && (tv_ea > tv_eo))
	{
	checkok = true;
	}
if(((zeigerea->keyinfo == 4) && (zeigereo->keyinfo == 2)) && (zeigerea->replaycount == zeigereo->replaycount -1) && (tv_ea < tv_eo))
	{
	checkok = true;
	}

if(checkok == false)
	return;

if(rawhandshakeliste == NULL)
	{
	if(timegap == 0)
		{
		tssameflag = true;
		}
	rawhandshakeliste = malloc(HCXLIST_SIZE);
	if(rawhandshakeliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(rawhandshakeliste, 0, HCXLIST_SIZE);
	rawhandshakeliste->tv_ea = tv_ea;
	rawhandshakeliste->tv_eo = tv_eo;
	rawhandshakeliste->tv_diff = timegap;
	rawhandshakeliste->replaycount_ap = zeigereo->replaycount;
	rawhandshakeliste->replaycount_sta = zeigerea->replaycount;
	rawhandshakeliste->rc_diff = rcgap;
	memcpy(rawhandshakeliste->mac_ap, zeigerea->mac_ap, 6);
	memcpy(rawhandshakeliste->mac_sta, zeigerea->mac_sta, 6);
	rawhandshakeliste->keyinfo_ap = zeigereo->keyinfo;
	rawhandshakeliste->keyinfo_sta = zeigerea->keyinfo;
	memcpy(rawhandshakeliste->nonce, wpaeo->nonce, 32);
	rawhandshakeliste->authlen = zeigerea->authlen;
	memcpy(rawhandshakeliste->eapol, zeigerea->eapol, zeigerea->authlen);
	if((zeigerea->replaycount == myaktreplaycount) && (zeigereo->replaycount == myaktreplaycount) && (memcmp(wpaeo->nonce, &myaktanonce, 32) == 0))
		{
		rawhandshakeliste->endianess = 0x10;
		rawhandshakeaplesscount++;
		}
	rawhandshakecount++;
	return;
	}

zeiger = rawhandshakeliste;
for(c = 0; c < rawhandshakecount; c++)
	{
	if((memcmp(zeiger->mac_ap, zeigerea->mac_ap, 6) == 0) && (memcmp(zeiger->mac_sta, zeigerea->mac_sta, 6) == 0))
		{
		wpae = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
		anonce = wpaeo->nonce[31] | (wpaeo->nonce[30] << 8) | (wpaeo->nonce[29] << 16) | (wpaeo->nonce[28] << 24);
		anonceold = zeiger->nonce[31] | (zeiger->nonce[30] << 8) | (zeiger->nonce[29] << 16) | (zeiger->nonce[28] << 24);
		if(((anonce > anonceold) && (anonce < anonceold +0xfff)) || ((anonce < anonceold) && (anonce > anonceold -0xfff)))
			{
			zeiger->endianess = 0x20;
			}
		anonce = wpaeo->nonce[28] | (wpaeo->nonce[29] << 8) | (wpaeo->nonce[30] << 16) | (wpaeo->nonce[31] << 24);
		anonceold = zeiger->nonce[28] | (zeiger->nonce[29] << 8) | (zeiger->nonce[30] << 16) | (zeiger->nonce[31] << 24);
		if(((anonce > anonceold) && (anonce < anonceold +0xfff)) || ((anonce < anonceold) && (anonce > anonceold -0xfff)))
			{
			zeiger->endianess = 0x40;
			}
		if((zeigerea->replaycount == myaktreplaycount) && (zeigereo->replaycount == myaktreplaycount) && (memcmp(wpaeo->nonce, &myaktanonce, 32) == 0))
			{
			if((zeiger->replaycount_ap != myaktreplaycount) && (zeiger->replaycount_sta != myaktreplaycount) && (memcmp(zeiger->nonce, &myaktanonce, 32) == 0))
				{
				rawhandshakeaplesscount++;
				}
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_ea;
			zeiger->tv_diff = 0;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = 0;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			zeiger->endianess = 0x10;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memset(zeiger->eapol, 0, 256);
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		else if((memcmp(wpae->keymic, wpaea->keymic, 16) == 0) && (memcmp(zeiger->nonce, wpaeo->nonce, 32) == 0) && (memcmp(wpae->nonce, wpaea->nonce, 32) == 0))
			{
			if(zeiger->tv_diff >= timegap)
				{
				zeiger->tv_ea = tv_ea;
				zeiger->tv_eo = tv_eo;
				zeiger->tv_diff = timegap;
				zeiger->replaycount_ap = zeigereo->replaycount;
				zeiger->replaycount_sta = zeigerea->replaycount;
				zeiger->rc_diff = rcgap;
				memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
				memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
				zeiger->keyinfo_ap = zeigereo->keyinfo;
				zeiger->keyinfo_sta = zeigerea->keyinfo;
				memcpy(zeiger->nonce, wpaeo->nonce, 32);
				zeiger->authlen = zeigerea->authlen;
				memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
				}
			return;
			}
		}
	zeiger++;
	}

if(timegap == 0)
	{
	tssameflag = true;
	}

zeiger = realloc(rawhandshakeliste, (rawhandshakecount +1) *HCXLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
rawhandshakeliste = zeiger;
zeiger = rawhandshakeliste +rawhandshakecount;
memset(zeiger, 0, HCXLIST_SIZE);
zeiger->tv_ea = tv_ea;
zeiger->tv_eo = tv_eo;
zeiger->tv_diff = timegap;
zeiger->replaycount_ap = zeigereo->replaycount;
zeiger->replaycount_sta = zeigerea->replaycount;
zeiger->rc_diff = rcgap;
memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
zeiger->keyinfo_ap = zeigereo->keyinfo;
zeiger->keyinfo_sta = zeigerea->keyinfo;
memcpy(zeiger->nonce, wpaeo->nonce, 32);
zeiger->authlen = zeigerea->authlen;
memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
if((zeigerea->replaycount == myaktreplaycount) && (zeigereo->replaycount == myaktreplaycount) && (memcmp(wpaeo->nonce, &myaktanonce, 32) == 0))
	{
	zeiger->endianess = 0x10;
	rawhandshakeaplesscount++;
	}
rawhandshakecount++;
return;
}
/*===========================================================================*/
void addwchandshake(eapoll_t *zeigerap)
{
uint64_t timewc;
hcxl_t *zeiger;
unsigned long long int c;

if(zeigerap->authlen > 0x0fc)
	{
	return;
	}
timewc = ((uint64_t)zeigerap->tv_sec *1000000) +zeigerap->tv_usec;
if(handshakeliste == NULL)
	{
	handshakeliste = malloc(HCXLIST_SIZE);
	if(handshakeliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(handshakeliste, 0, HCXLIST_SIZE);
	handshakeliste->tv_ea = timewc;
	handshakeliste->tv_eo = timewc +1;
	handshakeliste->tv_diff = 0;
	handshakeliste->replaycount_ap = zeigerap->replaycount;
	handshakeliste->replaycount_sta = zeigerap->replaycount -1;
	handshakeliste->rc_diff = 0;
	memcpy(handshakeliste->mac_ap, zeigerap->mac_ap, 6);
	memcpy(handshakeliste->mac_sta, &myaktsta, 6);
	handshakeliste->keyinfo_ap = 16;
	handshakeliste->keyinfo_sta = 4;
	memcpy(handshakeliste->nonce, &myaktsnonce, 32);
	handshakeliste->authlen = zeigerap->authlen;
	memcpy(handshakeliste->eapol, zeigerap->eapol, zeigerap->authlen);
	handshakeliste->endianess = 0x10;
	handshakecount++;
	return;
	}

zeiger = handshakeliste;
for(c = 0; c < handshakecount; c++)
	{
	if((memcmp(zeiger->mac_ap, zeigerap->mac_ap, 6) == 0) && (memcmp(zeiger->mac_sta, zeigerap->mac_sta, 6) == 0))
		{
		return;
		}
	zeiger++;
	}
zeiger = realloc(handshakeliste, (handshakecount +1) *HCXLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
handshakeliste = zeiger;
zeiger = handshakeliste +handshakecount;
memset(zeiger, 0, HCXLIST_SIZE);
zeiger->tv_ea = timewc;
zeiger->tv_eo = timewc +1;
zeiger->tv_diff = 0;
zeiger->replaycount_ap = zeigerap->replaycount;
zeiger->replaycount_sta = zeigerap->replaycount -1;
zeiger->rc_diff = 0;
memcpy(zeiger->mac_ap, zeigerap->mac_ap, 6);
memcpy(zeiger->mac_sta, &myaktsta, 6);
zeiger->keyinfo_ap = 16;
zeiger->keyinfo_sta = 4;
memcpy(zeiger->nonce, &myaktsnonce, 32);
zeiger->authlen = zeigerap->authlen;
memcpy(zeiger->eapol, zeigerap->eapol, zeigerap->authlen);
zeiger->endianess = 0x10;
handshakecount++;
return;
}
/*===========================================================================*/
void addhandshake(uint64_t tv_ea, eapoll_t *zeigerea, uint64_t tv_eo, eapoll_t *zeigereo, uint64_t timegap, uint64_t rcgap)
{
hcxl_t *zeiger;
unsigned long long int c;
wpakey_t *wpae, *wpaea, *wpaeo;
uint16_t keyverea, keyvereo;
uint32_t anonce, anonceold;

wpaea = (wpakey_t*)(zeigerea->eapol +EAPAUTH_SIZE);
wpaeo = (wpakey_t*)(zeigereo->eapol +EAPAUTH_SIZE);

keyverea = ntohs(wpaea->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
keyvereo = ntohs(wpaea->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if(keyverea != keyvereo)
	{
	return;
	}
if((keyverea < 1) || (keyverea > 3))
	{
	return;
	}

if(handshakeliste == NULL)
	{
	if(timegap == 0)
		{
		tssameflag = true;
		}
	if(testeapolzeropmk(keyverea, zeigerea->mac_sta, zeigerea->mac_ap, wpaeo->nonce, wpaea->nonce, zeigerea->authlen, zeigerea->eapol) == true)
		{
		zeroedpmkcount++;
		if(zeroedpmkflag == true)
			{
			return;
			}
		}
	handshakeliste = malloc(HCXLIST_SIZE);
	if(handshakeliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(handshakeliste, 0, HCXLIST_SIZE);
	handshakeliste->tv_ea = tv_ea;
	handshakeliste->tv_eo = tv_eo;
	handshakeliste->tv_diff = timegap;
	handshakeliste->replaycount_ap = zeigereo->replaycount;
	handshakeliste->replaycount_sta = zeigerea->replaycount;
	handshakeliste->rc_diff = rcgap;
	memcpy(handshakeliste->mac_ap, zeigerea->mac_ap, 6);
	memcpy(handshakeliste->mac_sta, zeigerea->mac_sta, 6);
	handshakeliste->keyinfo_ap = zeigereo->keyinfo;
	handshakeliste->keyinfo_sta = zeigerea->keyinfo;
	memcpy(handshakeliste->nonce, wpaeo->nonce, 32);
	handshakeliste->authlen = zeigerea->authlen;
	memcpy(handshakeliste->eapol, zeigerea->eapol, zeigerea->authlen);
	if((zeigerea->replaycount == myaktreplaycount) && (zeigereo->replaycount == myaktreplaycount) && (memcmp(wpaeo->nonce, &myaktanonce, 32) == 0))
		{
		handshakeliste->endianess = 0x10;
		handshakeaplesscount++;
		}
	handshakecount++;
	return;
	}
zeiger = handshakeliste;
for(c = 0; c < handshakecount; c++)
	{
	if((memcmp(zeiger->mac_ap, zeigerea->mac_ap, 6) == 0) && (memcmp(zeiger->mac_sta, zeigerea->mac_sta, 6) == 0))
		{
		wpae = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
		anonce = wpaeo->nonce[31] | (wpaeo->nonce[30] << 8) | (wpaeo->nonce[29] << 16) | (wpaeo->nonce[28] << 24);
		anonceold = zeiger->nonce[31] | (zeiger->nonce[30] << 8) | (zeiger->nonce[29] << 16) | (zeiger->nonce[28] << 24);
		if(((anonce > anonceold) && (anonce < anonceold +0xfff)) || ((anonce < anonceold) && (anonce > anonceold -0xfff)))
			{
			zeiger->endianess = 0x20;
			}
		anonce = wpaeo->nonce[28] | (wpaeo->nonce[29] << 8) | (wpaeo->nonce[30] << 16) | (wpaeo->nonce[31] << 24);
		anonceold = zeiger->nonce[28] | (zeiger->nonce[29] << 8) | (zeiger->nonce[30] << 16) | (zeiger->nonce[31] << 24);
		if(((anonce > anonceold) && (anonce < anonceold +0xfff)) || ((anonce < anonceold) && (anonce > anonceold -0xfff)))
			{
			zeiger->endianess = 0x40;
			}
		if((zeigerea->replaycount == myaktreplaycount) && (zeigereo->replaycount == myaktreplaycount) && (memcmp(wpaeo->nonce, &myaktanonce, 32) == 0))
			{
			if((zeiger->replaycount_ap != myaktreplaycount) && (zeiger->replaycount_sta != myaktreplaycount) && (memcmp(zeiger->nonce, &myaktanonce, 32) != 0))
				{
				handshakeaplesscount++;
				}
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_ea;
			zeiger->tv_diff = 0;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = 0;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			zeiger->endianess = 0x10;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memset(zeiger->eapol, 0, 256);
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		else if((memcmp(wpae->keymic, wpaea->keymic, 16) == 0) && (memcmp(zeiger->nonce, wpaeo->nonce, 32) == 0) && (memcmp(wpae->nonce, wpaea->nonce, 32) == 0))
			{
			if(zeiger->tv_diff >= timegap)
				{
				zeiger->tv_ea = tv_ea;
				zeiger->tv_eo = tv_eo;
				zeiger->tv_diff = timegap;
				zeiger->replaycount_ap = zeigereo->replaycount;
				zeiger->replaycount_sta = zeigerea->replaycount;
				zeiger->rc_diff = rcgap;
				memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
				memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
				zeiger->keyinfo_ap = zeigereo->keyinfo;
				zeiger->keyinfo_sta = zeigerea->keyinfo;
				memcpy(zeiger->nonce, wpaeo->nonce, 32);
				zeiger->authlen = zeigerea->authlen;
				memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
				}
			return;
			}
		else if((zeigerea->keyinfo == 4) && (zeigereo->keyinfo == 1) && (zeigerea->replaycount == zeigereo->replaycount) && (tv_ea > tv_eo) && (zeiger->tv_diff >= timegap))
			{
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_eo;
			zeiger->tv_diff = timegap;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = rcgap;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		else if((zeigerea->keyinfo == 8) && (zeigereo->keyinfo == 2) && (zeigerea->replaycount == zeigereo->replaycount) && (tv_ea > tv_eo) && (zeiger->tv_diff >= timegap))
			{
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_eo;
			zeiger->tv_diff = timegap;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = rcgap;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		else if(((zeigerea->keyinfo == 8) && (zeigereo->keyinfo == 1)) && (zeigerea->replaycount == zeigereo->replaycount +1) && (tv_ea > tv_eo) && (zeiger->tv_diff >= timegap))
			{
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_eo;
			zeiger->tv_diff = timegap;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = rcgap;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		else if(((zeigerea->keyinfo == 4) && (zeigereo->keyinfo == 2)) && (zeigerea->replaycount == zeigereo->replaycount -1) && (tv_ea < tv_eo) && (zeiger->tv_diff >= timegap))
			{
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_eo;
			zeiger->tv_diff = timegap;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = rcgap;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		else if((zeiger->rc_diff > 1) && (zeiger->tv_diff >= timegap))
			{
			zeiger->tv_ea = tv_ea;
			zeiger->tv_eo = tv_eo;
			zeiger->tv_diff = timegap;
			zeiger->replaycount_ap = zeigereo->replaycount;
			zeiger->replaycount_sta = zeigerea->replaycount;
			zeiger->rc_diff = rcgap;
			memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
			memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
			zeiger->keyinfo_ap = zeigereo->keyinfo;
			zeiger->keyinfo_sta = zeigerea->keyinfo;
			memcpy(zeiger->nonce, wpaeo->nonce, 32);
			zeiger->authlen = zeigerea->authlen;
			memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
			return;
			}
		return;
		}
	zeiger++;
	}

if(timegap == 0)
	{
	tssameflag = true;
	}

if(testeapolzeropmk(keyverea, zeigerea->mac_sta, zeigerea->mac_ap, wpaeo->nonce, wpaea->nonce, zeigerea->authlen, zeigerea->eapol) == true)
	{
	zeroedpmkcount++;
	if(zeroedpmkflag == true)
		{
		return;
		}
	}
zeiger = realloc(handshakeliste, (handshakecount +1) *HCXLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
handshakeliste = zeiger;
zeiger = handshakeliste +handshakecount;
memset(zeiger, 0, HCXLIST_SIZE);
zeiger->tv_ea = tv_ea;
zeiger->tv_eo = tv_eo;
zeiger->tv_diff = timegap;
zeiger->replaycount_ap = zeigereo->replaycount;
zeiger->replaycount_sta = zeigerea->replaycount;
zeiger->rc_diff = rcgap;
memcpy(zeiger->mac_ap, zeigerea->mac_ap, 6);
memcpy(zeiger->mac_sta, zeigerea->mac_sta, 6);
zeiger->keyinfo_ap = zeigereo->keyinfo;
zeiger->keyinfo_sta = zeigerea->keyinfo;
memcpy(zeiger->nonce, wpaeo->nonce, 32);
zeiger->authlen = zeigerea->authlen;
memcpy(zeiger->eapol, zeigerea->eapol, zeigerea->authlen);
if((zeigerea->replaycount == myaktreplaycount) && (zeigereo->replaycount == myaktreplaycount) && (memcmp(wpaeo->nonce, &myaktanonce, 32) == 0))
	{
	zeiger->endianess = 0x10;
	handshakeaplesscount++;
	}
handshakecount++;
return;
}
/*===========================================================================*/
void findhandshake()
{
eapoll_t *zeigerea, *zeigereo;
unsigned long long int c, d;
uint64_t lltimeea, lltimeeo;
uint64_t timegap;
uint64_t rcgap;

zeigerea = eapolliste;
for(c = 0; c < eapolcount; c++)
	{
	if((zeigerea->keyinfo == 2) && (memcmp(&myaktsta, &mac_null, 6) != 0))
		{
		if((memcmp(zeigerea->mac_sta, &myaktsta, 6) == 0) && (memcmp(&myaktsnonce, &nullnonce, 32) != 0))
			{
			addwchandshake(zeigerea);
			}
		}
	if((zeigerea->keyinfo >= 4) && (memcmp(zeigerea->mac_sta, &myaktsta, 6) != 0))
		{

		lltimeea = ((uint64_t)zeigerea->tv_sec *1000000) +zeigerea->tv_usec;
		for(d = 1; d <= c; d++)
			{
			zeigereo = zeigerea -d;
			lltimeeo = ((uint64_t)zeigereo->tv_sec *1000000) +zeigereo->tv_usec;
			if(lltimeea > lltimeeo)
				{
				timegap = lltimeea -lltimeeo;
				}
			else
				{
				timegap = lltimeeo -lltimeea;
				}
			if(timegap > (maxtvdiff))
				{
				break;
				}
			if(zeigereo->keyinfo <= 3)
				{
				if(zeigerea->replaycount > zeigereo->replaycount)
					{
					rcgap = zeigerea->replaycount - zeigereo->replaycount;
					}
				else
					{
					rcgap = zeigereo->replaycount - zeigerea->replaycount;
					}
				if(rcgap <= maxrcdiff)
					{
					if((memcmp(zeigerea->mac_ap, zeigereo->mac_ap, 6) == 0) && (memcmp(zeigerea->mac_sta, zeigereo->mac_sta, 6) == 0))
						{
						addhandshake(lltimeea, zeigerea, lltimeeo, zeigereo, timegap, rcgap);
						if(wantrawflag == true)
							{
							addrawhandshake(lltimeea, zeigerea, lltimeeo, zeigereo, timegap, rcgap);
							}
						}
					}
				}
			}
		for(d = 1; d < eapolcount -c; d++)
			{
			zeigereo = zeigerea +d;
			lltimeeo = ((uint64_t)zeigereo->tv_sec *1000000) +zeigereo->tv_usec;
			if(lltimeea > lltimeeo)
				{
				timegap = lltimeea -lltimeeo;
				}
			else
				{
				timegap = lltimeeo -lltimeea;
				}
			if(timegap > (maxtvdiff))
				{
				break;
				}
			if(zeigereo->keyinfo <= 3)
				{
				if(zeigerea->replaycount > zeigereo->replaycount)
					{
					rcgap = zeigerea->replaycount - zeigereo->replaycount;
					}
				else
					{
					rcgap = zeigereo->replaycount - zeigerea->replaycount;
					}
				if(rcgap <= maxrcdiff)
					{
					if((memcmp(zeigerea->mac_ap, zeigereo->mac_ap, 6) == 0) && (memcmp(zeigerea->mac_sta, zeigereo->mac_sta, 6) == 0))
						{
						addhandshake(lltimeea, zeigerea, lltimeeo, zeigereo, timegap, rcgap);
						if(wantrawflag == true)
							{
							addrawhandshake(lltimeea, zeigerea, lltimeeo, zeigereo, timegap, rcgap);
							}
						}
					}
				}
			}
		}
	zeigerea++;
	}
return;
}
/*===========================================================================*/
void addpmkid(uint8_t *mac_sta, uint8_t *mac_ap, uint8_t *authpacket)
{
unsigned long long int c;
wpakey_t *wpak;
uint16_t keyver;
pmkid_t *pmkid;
pmkidl_t *zeiger;

uint8_t pmkidoui[] =
{
0x00, 0x0f, 0xac
};
#define PMKIDOUI_SIZE sizeof(pmkidoui)

wpak = (wpakey_t*)authpacket;
if(ntohs(wpak->wpadatalen) != 22)
	{
	return;
	}
keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
if((keyver < 1) || (keyver > 3))
	{
	return;
	}
pmkid = (pmkid_t*)(authpacket + WPAKEY_SIZE);
if((pmkid->id != 0xdd) && (pmkid->id != 0x14))
	{
	return;
	}
if(memcmp(&pmkidoui, pmkid->oui, PMKIDOUI_SIZE) != 0)
	{
	return;
	}
if(pmkid->type != 0x04)
	{
	return;
	}
if(memcmp(mac_ap, &mac_broadcast, 6) == 0)
	{
	return;
	}
if(memcmp(mac_sta, &mac_broadcast, 6) == 0)
	{
	return;
	}
if(memcmp(pmkid->pmkid, &nullnonce, 16) == 0)
	{
	zeroedpmkidcount++;
	return;
	}
if(memcmp(&pmkid->pmkid[2], &nullnonce, 4) == 0)
	{
	return;
	}
if(memcmp(&pmkid->pmkid[4], &nullnonce, 4) == 0)
	{
	return;
	}
if(memcmp(&pmkid->pmkid[6], &nullnonce, 4) == 0)
	{
	return;
	}
if(memcmp(&pmkid->pmkid[8], &nullnonce, 4) == 0)
	{
	return;
	}
if(memcmp(&pmkid->pmkid[10], &nullnonce, 4) == 0)
	{
	return;
	}
if(memcmp(&pmkid->pmkid[12], &nullnonce, 4) == 0)
	{
	return;
	}

if(pmkidliste == NULL)
	{
	if(testpmkidzeropmk(mac_sta, mac_ap, pmkid->pmkid) == true)
		{
		zeroedpmkcount++;
		if(zeroedpmkflag == true)
			{
			return;
			}
		}
	pmkidliste = malloc(PMKIDLIST_SIZE);
	if(pmkidliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memcpy(pmkidliste->mac_ap, mac_ap, 6);
	memcpy(pmkidliste->mac_sta, mac_sta, 6);
	memcpy(pmkidliste->pmkid, pmkid->pmkid, 16);
	pmkidcount++;
	pmkidallcount++;
	pmkidapcount++;
	return;
	}

zeiger = pmkidliste;
for(c = 0; c < pmkidcount; c++)
	{
	if((memcmp(zeiger->mac_ap, mac_ap, 6) == 0) && (memcmp(zeiger->mac_sta, mac_sta, 6) == 0) && (memcmp(zeiger->pmkid, pmkid->pmkid, 16) == 0))
		{
		return;
		}
	zeiger++;
	}
if(testpmkidzeropmk(mac_sta, mac_ap, pmkid->pmkid) == true)
	{
	zeroedpmkcount++;
	if(zeroedpmkflag == true)
		{
		return;
		}
	}
zeiger = realloc(pmkidliste, (pmkidcount +1) *PMKIDLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
pmkidliste = zeiger;
zeiger = pmkidliste +pmkidcount;
memcpy(zeiger->mac_ap, mac_ap, 6);
memcpy(zeiger->mac_sta, mac_sta, 6);
memcpy(zeiger->pmkid, pmkid->pmkid, 16);
pmkidcount++;
pmkidallcount++;
pmkidapcount++;
return;
}
/*===========================================================================*/
void printeapol(uint8_t *mac_sta, uint8_t *mac_ap, uint32_t authlen, uint8_t *authpacket)
{
uint32_t c;

for(c = 0; c < 6; c++)
	{
	fprintf(fheapol, "%02x",mac_ap[c]);
	}
fprintf(fheapol, ":");
for(c = 0; c < 6; c++)
	{
	fprintf(fheapol, "%02x",mac_sta[c]);
	}
fprintf(fheapol, ":");
for(c = 0; c < authlen; c++)
	{
	fprintf(fheapol, "%02x",authpacket[c]);
	}
fprintf(fheapol, "\n");
return;
}
/*===========================================================================*/
uint16_t rsnietagwalk(uint8_t *tagdata, int taglen)
{
ietag_t *tagl;
tagl = (ietag_t*)tagdata;

while(0 < taglen)
	{
	if(tagl->id == TAG_RSN)
		{
		if(tagl->len == 0)
			{
			return 0;
			}
		return tagl->len;
		}
	tagl = (ietag_t*)((uint8_t*)tagl +tagl->len +IETAG_SIZE);
	taglen -= tagl->len;
	}
return 0;
}
/*===========================================================================*/
void addeapol(uint32_t tv_sec, uint32_t tv_usec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t ki, uint64_t rc, uint32_t authlen, uint8_t *authpacket)
{
eapoll_t *zeiger;
wpakey_t *eaptest;

eaptest = (wpakey_t*)(authpacket +EAPAUTH_SIZE);
if(ntohs(eaptest->wpadatalen) > (authlen -99))
	{
	return;
	}
if(authlen > 0xff)
	{
	eapoloversizedframecount++;
	}
if((ki == 1) || (ki == 2))
	{
	if(authlen > 0xff)
		{
		authlen = 0xff;
		}
	}
if((ki == 4) || (ki == 8))
	{
	if(authlen > 0xff)
		{
		return;
		}
	}
if(eapoloutname != NULL)
	{
	printeapol(mac_sta, mac_ap, authlen, authpacket);
	}
if(eapolliste == NULL)
	{
	eapolliste = malloc(EAPOLLIST_SIZE);
	if(eapolliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(eapolliste, 0, EAPOLLIST_SIZE);
	eapolliste->tv_sec = tv_sec;
	eapolliste->tv_usec = tv_usec;
	memcpy(eapolliste->mac_ap, mac_ap, 6);
	memcpy(eapolliste->mac_sta, mac_sta, 6);
	eapolliste->replaycount = rc;
	eapolliste->keyinfo = ki;
	eapolliste->authlen = authlen;
	memcpy(eapolliste->eapol, authpacket, authlen);
	eapolcount++;
	return;
	}
zeiger = realloc(eapolliste, (eapolcount +1) *EAPOLLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
eapolliste = zeiger;
zeiger = eapolliste +eapolcount;
memset(zeiger, 0, EAPOLLIST_SIZE);
zeiger->tv_sec = tv_sec;
zeiger->tv_usec = tv_usec;
memcpy(zeiger->mac_ap, mac_ap, 6);
memcpy(zeiger->mac_sta, mac_sta, 6);
zeiger->replaycount = rc;
zeiger->keyinfo = ki;
zeiger->authlen = authlen;
memcpy(zeiger->eapol, authpacket, authlen);
eapolcount++;
return;
}
/*===========================================================================*/
void cleanapstaessid()
{
unsigned long long int c;
apstaessidl_t *zeiger1;
apstaessidl_t *zeiger2;

if(apstaessidcount < 1)
	{
	return;
	}

qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_sta);

if((apstaessidlistecleaned = calloc((apstaessidcount), APSTAESSIDLIST_SIZE)) == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}

zeiger1 = apstaessidliste;
zeiger2 = apstaessidlistecleaned;
memset(apstaessidlistecleaned, 0, apstaessidcount *APSTAESSIDLIST_SIZE);
memcpy(zeiger2->mac_ap, zeiger1->mac_ap, 6);
memcpy(zeiger2->mac_sta, zeiger1->mac_sta, 6);
zeiger2->essidlen = zeiger1->essidlen;
memset(zeiger2->essid, 0, 32);
memcpy(zeiger2->essid, zeiger1->essid, zeiger1->essidlen);
zeiger2->essidcount = 1;
apstaessidcountcleaned = 1;
zeiger1++;
for(c = 1; c < apstaessidcount; c++)
	{
	if((memcmp(zeiger1->mac_ap, zeiger2->mac_ap, 6) == 0) && (memcmp(zeiger1->mac_sta, zeiger2->mac_sta, 6) == 0) && (memcmp(zeiger1->essid, zeiger2->essid, 5) == 0))
		{
		zeiger2->essidcount +=1;
		zeiger1++;
		continue;
		}
	zeiger2++;
	memcpy(zeiger2->mac_ap, zeiger1->mac_ap, 6);
	memcpy(zeiger2->mac_sta, zeiger1->mac_sta, 6);
	zeiger2->essidlen = zeiger1->essidlen;
	memset(zeiger2->essid, 0, 32);
	memcpy(zeiger2->essid, zeiger1->essid, zeiger1->essidlen);
	zeiger2->essidcount = 1;
	apstaessidcountcleaned++;
	zeiger1++;
	}
return;
}
/*===========================================================================*/
void printnetwork(uint8_t *mac_ap, uint8_t essidlen, uint8_t *essid)
{
uint8_t c;

if(memcmp(mac_ap, mac_broadcast,6) == 0)
	{
	return;
	}
for(c = 0; c < 6; c++)
	{
	fprintf(fhnetwork, "%02x",mac_ap[c]);
	}
fprintf(fhnetwork, ":");
fwriteessidstr(essidlen, essid, fhnetwork);
return;
}
/*===========================================================================*/
void addapstaessid(uint32_t tv_sec, uint32_t tv_usec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essidlen, uint8_t *essid)
{
if(networkoutname != NULL)
	{
	printnetwork(mac_ap, essidlen, essid);
	}
apstaessidl_t *zeiger;
if(apstaessidliste == NULL)
	{
	apstaessidliste = malloc(APSTAESSIDLIST_SIZE);
	if(apstaessidliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(apstaessidliste, 0, APSTAESSIDLIST_SIZE);
	apstaessidliste->tv_sec = tv_sec;
	apstaessidliste->tv_usec = tv_usec;
	memcpy(apstaessidliste->mac_ap, mac_ap, 6);
	memcpy(apstaessidliste->mac_sta, mac_sta, 6);
	memcpy(apstaessidliste->essid, essid, essidlen);
	apstaessidliste->essidlen = essidlen;
	apstaessidcount++;
	return;
	}

zeiger = realloc(apstaessidliste, (apstaessidcount +1) *APSTAESSIDLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
apstaessidliste = zeiger;
zeiger = apstaessidliste +apstaessidcount;
memset(zeiger, 0, APSTAESSIDLIST_SIZE);
zeiger->tv_sec = tv_sec;
zeiger->tv_usec = tv_usec;
memcpy(zeiger->mac_ap, mac_ap, 6);
memcpy(zeiger->mac_sta, mac_sta, 6);
memcpy(zeiger->essid, essid, essidlen);
zeiger->essidlen = essidlen;
apstaessidcount++;
return;
}
/*===========================================================================*/
uint8_t *gettag(uint8_t tag, uint8_t *tagptr, uint32_t plen)
{
ietag_t *tagfield;
uint32_t tlen;

tlen = 0;
while(tlen < plen)
	{
	tagfield = (ietag_t*)tagptr;
	if(tagfield->id == tag)
		{
		if((tlen +tagfield->len +2) <= plen)
			{
			return tagptr;
			}
		else
			{
			return NULL;
			}
		}
	tagptr += tagfield->len +IETAG_SIZE;
	tlen += tagfield->len +IETAG_SIZE;
	}
return NULL;
}
/*===========================================================================*/
uint8_t *getrsncipher(uint8_t *suiteptr, int restlen) 
{
uint8_t c;
rsnlisttag_t *pwcilist; 
rsnlisttag_t *akmcilist; 
rsnsuitetag_t *rsnsuite;
pmkidlisttag_t *pmklisttag = NULL;

uint8_t rsnoiu[] =
{
0x00, 0x0f, 0xac
};

pwcilist = (rsnlisttag_t*)suiteptr;
suiteptr += RSNLISTTAG_SIZE;
restlen -= RSNLISTTAG_SIZE;
for(c = 0; c < pwcilist->count; c++) 
	{
	suiteptr += RSNSUITETAG_SIZE;
	restlen -= RSNSUITETAG_SIZE;
	if(restlen < 0)
		{
		return NULL;
		}
	}

akmcilist = (rsnlisttag_t*)suiteptr;
suiteptr += RSNLISTTAG_SIZE;
restlen -= RSNLISTTAG_SIZE;
if(restlen < 0)
	{
	return NULL;
	}
for(c = 0; c < akmcilist->count; c++) 
	{
	rsnsuite = (rsnsuitetag_t*)suiteptr;
	if(memcmp(&rsnoiu, rsnsuite->oui,3) == 0)
		{
		if(rsnsuite->type == 8)
			{
			return NULL;
			}
		}
	suiteptr += RSNSUITETAG_SIZE;
	restlen -= RSNSUITETAG_SIZE;
	if(restlen < 0)
		{
		return NULL;
		}
	}

suiteptr += RSNCAPATAG_SIZE;
restlen -= RSNCAPATAG_SIZE;
if(restlen < 0)
	{
	return NULL;
	}

pmklisttag = (pmkidlisttag_t*)(suiteptr); 
if(pmklisttag->count != 1)
	{
	return NULL;
	}

if(restlen < 16)
	{
	return NULL;
	}

if(memcmp(&nullnonce, pmklisttag->data, 16) == 0)
	{
	return NULL;
	}
return suiteptr;
}
/*===========================================================================*/
uint8_t *getwpstag(uint16_t tag, uint8_t *tagptr, int restlen)
{
static mscwpsietag_t *mscwpsietag;

while(0 < restlen)
	{
	mscwpsietag = (mscwpsietag_t*)tagptr;
	if(ntohs(mscwpsietag->detype) == tag)
		{
		if(restlen >= ntohs(mscwpsietag->detypelen) +(int)MSCWPSIETAG_SIZE)
			{
			return tagptr;
			}
		else
			{
			return NULL;
			}
		}
	tagptr += ntohs(mscwpsietag->detypelen) +MSCWPSIETAG_SIZE;
	restlen -= ntohs(mscwpsietag->detypelen) +MSCWPSIETAG_SIZE;
	}
return NULL;
}
/*===========================================================================*/
void addpmkidsta(uint8_t *macsta, uint8_t *macap, uint8_t *stapmkid)
{
pmkidl_t *zeiger;
unsigned long long int c;

pmkidallcount++;
pmkidstacount++;
if(testpmkidzeropmk(macsta, macap, stapmkid) == true)
	{
	zeroedpmkcount++;
	if(zeroedpmkflag == true)
		{
		skippedpacketcount++;
		return;
		}
	}

if(pmkidliste == NULL)
	{
	pmkidliste = malloc(PMKIDLIST_SIZE);
	if(pmkidliste == NULL)
		{
		printf("failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memcpy(pmkidliste->mac_ap, macap, 6);
	memcpy(pmkidliste->mac_sta, macsta, 6);
	memcpy(pmkidliste->pmkid, stapmkid, 16);
	pmkidcount++;
	return;
	}

zeiger = pmkidliste;
for(c = 0; c < pmkidcount; c++)
	{
	if((memcmp(zeiger->mac_ap, macap, 6) == 0) && (memcmp(zeiger->mac_sta, macsta, 6) == 0) && (memcmp(zeiger->pmkid, stapmkid, 16) == 0))
		{
		return;
		}
	zeiger++;
	}
zeiger = realloc(pmkidliste, (pmkidcount +1) *PMKIDLIST_SIZE);
if(zeiger == NULL)
	{
	printf("failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
pmkidliste = zeiger;
zeiger = pmkidliste +pmkidcount;
memcpy(zeiger->mac_ap, macap, 6);
memcpy(zeiger->mac_sta, macsta, 6);
memcpy(zeiger->pmkid, stapmkid, 16);
pmkidcount++;
return;
}
/*===========================================================================*/
void process80211wds()
{

wdsframecount++;
return;
}
/*===========================================================================*/
void process80211beacon(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
mac_t *macf;
uint8_t *packet_ptr;
uint8_t *tagptr;
ietag_t *thetag;
mscwpstag_t *mscwpstag;
mscwpsietag_t *mscwpsietag;
FILE *fhoutlist;

uint8_t mscoui[] =
{
0x00, 0x50, 0xf2
};

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)CAPABILITIESAP_SIZE +2)
	{
	beaconframedamagedcount++;
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +wdsoffset +CAPABILITIESAP_SIZE;
beaconframecount++;

if(memcmp(macf->addr1, &mac_broadcast, 6) != 0)
	{
	beaconframedamagedcount++;
	}

if(fhnmea != 0) writegpwpl(macf->addr2);

tagptr = gettag(TAG_SSID, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESAP_SIZE);
if(tagptr != NULL)
	{
	thetag = (ietag_t*)tagptr;
	if((thetag->len > 0) && (thetag->len <= 32))
		{
		if(thetag ->data[0] != 0)
			{
			addapstaessid(tv_sec, tv_usec, macf->addr1, macf->addr2, thetag->len, thetag->data);
			}
		}
	}


tagptr = gettag(TAG_MESH_ID, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESAP_SIZE);
if(tagptr != NULL)
	{
	thetag = (ietag_t*)tagptr;
	if((thetag ->len > 0) && (thetag ->len < 64))
		{
		if(thetag ->data[0] != 0)
			{
			meshidframecount++;
			}
		}
	}

tagptr = gettag(TAG_VENDOR, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESAP_SIZE);
if(tagptr != NULL)
	{
	mscwpstag = (mscwpstag_t*)tagptr;
	if(memcmp(&mscoui, mscwpstag->oui, 3) == 0)
		{
		if(mscwpstag->type == 4)
			{
			wpsframecount++;
			tagptr = getwpstag(MSCWPSDEVICENAME, mscwpstag->data, mscwpstag->taglen);
			if(tagptr != NULL)
				{
				mscwpsietag = (mscwpsietag_t*)tagptr;
				if( ntohs(mscwpsietag->detypelen) > 0)
					{
					deviceinfoframecount++;
					if(deviceinfooutname != NULL)
						{
						if((fhoutlist = fopen(deviceinfooutname, "a+")) != NULL)
							{
							fwriteaddr1(macf->addr2, fhoutlist);
							fwriteessidstr(ntohs(mscwpsietag->detypelen), mscwpsietag->data, fhoutlist);
							fclose(fhoutlist);
							}
						}
					}
				}
			}
		}
	}
return;
}
/*===========================================================================*/
void process80211probe_req(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
uint8_t *tagptr;
ietag_t *thetag;

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +wdsoffset;
proberequestframecount++;

tagptr = gettag(TAG_SSID, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset);
if(tagptr != NULL)
	{
	thetag = (ietag_t*)tagptr;
	if((thetag ->len > 0) && (thetag ->len <= 32))
		{
		if(thetag ->data[0] != 0)
			{
			addapstaessid(tv_sec, tv_usec, macf->addr2, macf->addr1, thetag->len, thetag->data);
			}
		}
	}
return;
}
/*===========================================================================*/
void process80211probe_resp(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
uint8_t *tagptr;
ietag_t *thetag;

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)CAPABILITIESAP_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +wdsoffset +CAPABILITIESAP_SIZE;
proberesponseframecount++;
if(fhnmea != 0) writegpwpl(macf->addr2);
tagptr = gettag(TAG_SSID, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESAP_SIZE);
if(tagptr != NULL)
	{
	thetag = (ietag_t*)tagptr;
	if((thetag ->len > 0) && (thetag ->len <= 32))
		{
		if(thetag ->data[0] != 0)
			{
			addapstaessid(tv_sec, tv_usec, macf->addr1, macf->addr2, thetag->len, thetag->data);
			}
		}
	}
return;
}
/*===========================================================================*/
void process80211assoc_req(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
uint8_t *tagptr;
ietag_t *thetag;
uint8_t *rsntagptr;
rsntag_t *rsntag;
pmkidlisttag_t *pmklisttag = NULL;

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)CAPABILITIESSTA_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +wdsoffset +CAPABILITIESSTA_SIZE;
associationrequestframecount++;

tagptr = gettag(TAG_SSID, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESSTA_SIZE);
if(tagptr != NULL)
	{
	thetag = (ietag_t*)tagptr;
	if((thetag ->len > 0) && (thetag ->len <= 32))
		{
		if(thetag ->data[0] != 0)
			{
			addapstaessid(tv_sec, tv_usec, macf->addr2, macf->addr1, thetag->len, thetag->data);
			}
		}
	}

rsntagptr = gettag(TAG_RSN, packet_ptr,  caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESSTA_SIZE);
if(rsntagptr == NULL)
	{
	return;
	}
rsntag = (rsntag_t*)rsntagptr;
if(rsntag->version != 1)
	{
	return;
	}
rsntagptr += RSNTAG_SIZE +RSNSUITETAG_SIZE; /* skip groupcypher */
rsntagptr = getrsncipher(rsntagptr, rsntag->len +2 -RSNTAG_SIZE -RSNSUITETAG_SIZE);
	{
	if( rsntagptr == NULL)
		{
		return;
		}
	}

pmklisttag = (pmkidlisttag_t*)(rsntagptr); 
if(pmklisttag->count != 1)
	{
	return;
	}
addpmkidsta(macf->addr2, macf->addr1, pmklisttag->data); 
return;
}
/*===========================================================================*/
void process80211assoc_resp()
{

associationresponseframecount++;
return;
}
/*===========================================================================*/
void process80211reassoc_req(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
uint8_t *tagptr;
ietag_t *thetag;
uint8_t *rsntagptr = NULL;
rsntag_t *rsntag = NULL;
pmkidlisttag_t *pmklisttag = NULL;

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)CAPABILITIESRESTA_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +wdsoffset +CAPABILITIESRESTA_SIZE;
reassociationrequestframecount++;

tagptr = gettag(TAG_SSID, packet_ptr,  caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESSTA_SIZE);
if(tagptr != NULL)
	{
	thetag = (ietag_t*)tagptr;
	if((thetag ->len > 0) && (thetag ->len <= 32))
		{
		if(thetag ->data[0] != 0)
			{
			addapstaessid(tv_sec, tv_usec, macf->addr2, macf->addr1, thetag->len, thetag->data);
			}
		}
	}

rsntagptr = gettag(TAG_RSN, packet_ptr, caplen -MAC_SIZE_NORM -wdsoffset -CAPABILITIESSTA_SIZE);
if(rsntagptr == NULL)
	{
	return;
	}
rsntag = (rsntag_t*)rsntagptr;
if(rsntag->version != 1)
	{
	return;
	}
rsntagptr += RSNTAG_SIZE +RSNSUITETAG_SIZE; /* skip groupcypher */
rsntagptr = getrsncipher(rsntagptr, rsntag->len +2 -RSNTAG_SIZE -RSNSUITETAG_SIZE);
	{
	if( rsntagptr == NULL)
		{
		return;
		}
	}

pmklisttag = (pmkidlisttag_t*)(rsntagptr); 
if(pmklisttag->count != 1)
	{
	return;
	}
addpmkidsta(macf->addr2, macf->addr1, pmklisttag->data); 
return;
}
/*===========================================================================*/
void process80211reassoc_resp()
{

reassociationresponseframecount++;
return;
}
/*===========================================================================*/
void process80211fbtauthentication()
{


authenticationfbtframecount++;
return;
}
/*===========================================================================*/
void process80211saeauthentication()
{


authenticationsaeframecount++;
return;
}
/*===========================================================================*/
void process80211authentication(uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
authf_t *auth;
vendor_t *vendorauth;
uint8_t *packet_ptr;

#define VENDORAUTHOUI_SIZE 3
uint8_t broadcomauthoui[] = { 0x00, 0x10, 0x18 };
uint8_t sonosauthoui[] = { 0x00, 0x0e, 0x58 };
uint8_t netgearauthoui[] = { 0x00, 0x14, 0x6c };
uint8_t appleauthoui[] = { 0x00, 0x17, 0xf2 };
uint8_t wiliboxauthoui[] = { 0x00, 0x19, 0x3b };
uint8_t ciscoauthoui[] = { 0x00, 0x40, 0x96 };

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)AUTHENTICATIONFRAME_SIZE)
	{
	return;
	}
mac_t *macf;
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +wdsoffset;
auth = (authf_t*)packet_ptr;

if(macf->protected == 1)
	{
	authenticationskframecount++;
	}
else if(auth->authentication_algho == OPEN_SYSTEM)
	{
	authenticationosframecount++;
	}
else if(auth->authentication_algho == SHARED_KEY)
	{
	authenticationskframecount++;
	}
else if(auth->authentication_algho == FBT)
	{
	process80211fbtauthentication();
	}
else if(auth->authentication_algho == SAE)
	{
	process80211saeauthentication();
	}
else if(auth->authentication_algho == FILS)
	{
	authenticationfilsframecount++;
	}
else if(auth->authentication_algho == FILSPFS)
	{
	authenticationfilspfsframecount++;
	}
else if(auth->authentication_algho == FILSPK)
	{
	authenticationfilspkframecount++;
	}
else if(auth->authentication_algho == NETWORKEAP)
	{
	authenticationnetworkeapframecount++;
	}
else
	{
	authenticationunknownframecount++;
	}

if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)AUTHENTICATIONFRAME_SIZE +(uint32_t)VENDORTAG_SIZE)
	{
	return;
	}

packet_ptr = packet +MAC_SIZE_NORM +wdsoffset +AUTHENTICATIONFRAME_SIZE;
vendorauth = (vendor_t*)packet_ptr;
if(vendorauth->tagnr != 0xdd)
	{
	return;
	}
if(memcmp(&broadcomauthoui, vendorauth->oui, VENDORAUTHOUI_SIZE) == 0)
	{
	authenticationbroadcomframecount++;
	}
else if(memcmp(&sonosauthoui, vendorauth->oui, VENDORAUTHOUI_SIZE) == 0)
	{
	authenticationsonosframecount++;
	}
else if(memcmp(&netgearauthoui, vendorauth->oui, VENDORAUTHOUI_SIZE) == 0)
	{
	authenticationnetgearframecount++;
	}
else if(memcmp(&appleauthoui, vendorauth->oui, VENDORAUTHOUI_SIZE) == 0)
	{
	authenticationappleframecount++;
	}
else if(memcmp(&wiliboxauthoui, vendorauth->oui, VENDORAUTHOUI_SIZE) == 0)
	{
	authenticationwiliboxframecount++;
	}
else if(memcmp(&ciscoauthoui, vendorauth->oui, VENDORAUTHOUI_SIZE) == 0)
	{
	authenticationciscoframecount++;
	}
return;
}
/*===========================================================================*/
void process80211deauthentication()
{

deauthenticationframecount++;
return;
}
/*===========================================================================*/
void process80211disassociation()
{

disassociationframecount++;
return;
}
/*===========================================================================*/
void process80211action()
{

actionframecount++;
return;
}
/*===========================================================================*/
void process80211atim()
{

atimframecount++;
return;
}
/*===========================================================================*/
void process80211eapolauthentication(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *macaddr1, uint8_t *macaddr2, uint8_t *packet)
{
eapauth_t *eap;
wpakey_t *wpak;
uint16_t keyinfo;
uint16_t keyver;
uint16_t authlen;
uint64_t rc;
uint16_t kl;
rsntag_t *rsntag = NULL;
uint8_t *rsntagptr = NULL;
pmkidlisttag_t *pmklisttag = NULL;

uint8_t fakeanonce1[] =
{
0x07, 0xbc, 0x92, 0xea, 0x2f, 0x5a, 0x1e, 0xe2, 0x54, 0xf6, 0xb1, 0xb7, 0xe0, 0xaa, 0xd3, 0x53,
0xf4, 0x5b, 0x0a, 0xac, 0xf9, 0xc9, 0x90, 0x2f, 0x90, 0xd8, 0x78, 0x80, 0xb7, 0x03, 0x0a, 0x20
};

uint8_t fakesnonce1[] =
{
0x95, 0x30, 0xd1, 0xc7, 0xc3, 0x55, 0xb9, 0xab, 0xe6, 0x83, 0xd6, 0xf3, 0x7e, 0xcb, 0x78, 0x02,
0x75, 0x1f, 0x53, 0xcc, 0xb5, 0x81, 0xd1, 0x52, 0x3b, 0xb4, 0xba, 0xad, 0x23, 0xab, 0x01, 0x07
};

if(caplen < (uint32_t)RC4DES_SIZE)
	{
	return;
	}

eap = (eapauth_t*)packet;
wpak = (wpakey_t*)(packet +EAPAUTH_SIZE);

if(wpak->keydescriptor == RC4DESCRIPTOR)
	{
	rc4descriptorframecount++;
	eapolframecount++;
	return;
	}

if(caplen < (uint32_t)WPAKEY_SIZE)
	{
	return;
	}

keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));

if((ntohs(wpak->keyinfo) & WPA_KEY_INFO_KEY_TYPE) == 0)
	{
	groupkeyframecount++;
	}

#ifndef BIG_ENDIAN_HOST
rc = byte_swap_64(wpak->replaycount);
#else
rc = wpak->replaycount;
#endif

authlen = ntohs(eap->len);
if(authlen < 0x5f)
	{
	return;
	}
if(authlen > caplen -4)
	{
	return;
	}
kl = ntohs(wpak->keylen);
if((kl %16) != 0)
	{
	return;
	}

if(memcmp(&nullnonce, wpak->nonce, 32) == 0)
	{
	eapolframecount++;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver == 0)
		{
		eapolwpaakmframecount++;
		}
	if(keyver == 1)
		{
		eapolwpa1framecount++;
		}
	if(keyver == 2)
		{
		eapolwpa2framecount++;
		}
	if(keyver == 3)
		{
		eapolwpa2kv3framecount++;
		}
	return;
	}

if(fakeframeflag == true)
	{
	if((rc == 17) && (memcmp(&fakeanonce1, wpak->nonce, 32) == 0))
		{
		skippedpacketcount++;
		return;
		}
	if((rc == 17) && (memcmp(&fakesnonce1, wpak->nonce, 32) == 0))
		{
		skippedpacketcount++;
		return;
		}
	}

if(keyinfo == 1)
	{
	if(authlen < 0x5f)
		{
		return;
		}
	addeapol(tv_sec, tv_usec, macaddr1, macaddr2, 1, rc, authlen +4, packet);
	eapolframecount++;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver == 0)
		{
		eapolwpaakmframecount++;
		}
	if(keyver == 1)
		{
		eapolwpa1framecount++;
		}
	if(keyver == 2)
		{
		eapolwpa2framecount++;
		}
	if(keyver == 3)
		{
		eapolwpa2kv3framecount++;
		}
	if(authlen == 0x75)
		{
		addpmkid(macaddr1, macaddr2, packet +EAPAUTH_SIZE);
		if(keyver == 0)
			{
			eapolpmkidwpaakmframecount++;
			}
		if(keyver == 1)
			{
			eapolpmkidwpa1framecount++;
			}
		if(keyver == 2)
			{
			eapolpmkidwpa2framecount++;
			}
		if(keyver == 3)
			{
			eapolpmkidwpa2kv3framecount++;
			}
		}
	}
else if(keyinfo == 3)
	{
	addeapol(tv_sec, tv_usec, macaddr1, macaddr2, 2, rc, authlen +4, packet);
	eapolframecount++;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver == 0)
		{
		eapolwpaakmframecount++;
		}
	if(keyver == 1)
		{
		eapolwpa1framecount++;
		}
	if(keyver == 2)
		{
		eapolwpa2framecount++;
		}
	if(keyver == 3)
		{
		eapolwpa2kv3framecount++;
		}
	}
else if(keyinfo == 2)
	{
	addeapol(tv_sec, tv_usec, macaddr2, macaddr1, 4, rc, authlen +4, packet);
	eapolframecount++;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver == 0)
		{
		eapolwpaakmframecount++;
		}
	if(keyver == 1)
		{
		eapolwpa1framecount++;
		}
	if(keyver == 2)
		{
		eapolwpa2framecount++;
		}
	if(keyver == 3)
		{
		eapolwpa2kv3framecount++;
		}
	if(ntohs(wpak->wpadatalen) > 0)
		{
		rsntag = (rsntag_t*)wpak->data;
		if(rsntag->version == 1)
			{
			rsntagptr = wpak->data;
			rsntagptr += RSNTAG_SIZE +RSNSUITETAG_SIZE; /* skip groupcypher */
			rsntagptr = getrsncipher(rsntagptr, rsntag->len +2 -RSNTAG_SIZE -RSNSUITETAG_SIZE);
				{
				if( rsntagptr != NULL)
					{
					pmklisttag = (pmkidlisttag_t*)(rsntagptr); 
					if(pmklisttag->count == 1)
						{
						addpmkidsta(macaddr2, macaddr1, pmklisttag->data); 
						}
					}
				}
			}
		}
	}
else if(keyinfo == 4)
	{
	addeapol(tv_sec, tv_usec, macaddr2, macaddr1, 8, rc, authlen +4, packet);
	eapolframecount++;
	keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
	if(keyver == 0)
		{
		eapolwpaakmframecount++;
		}
	if(keyver == 1)
		{
		eapolwpa1framecount++;
		}
	if(keyver == 2)
		{
		eapolwpa2framecount++;
		}
	if(keyver == 3)
		{
		eapolwpa2kv3framecount++;
		}
	}
return;
}
/*===========================================================================*/
void processeapolstartauthentication()
{


eapolstartframecount++;
return;
}
/*===========================================================================*/
void processeapollogoffauthentication()
{


eapollogoffframecount++;
return;
}
/*===========================================================================*/
void processeapolasfauthentication()
{


eapolasfframecount++;
return;
}
/*===========================================================================*/
void processeapolmkaauthentication()
{


eapolmkaframecount++;
return;
}
/*===========================================================================*/
void processeapakaauthentication(uint32_t eaplen, uint8_t *packet)
{
eapaka_t *aka;
FILE *fhoutlist = NULL;

aka = (eapaka_t*)packet;
if(eaplen < 29)
	{
	return;
	}
if(aka->code != EAP_CODE_RESP)
	{
	return;
	}
if(aka->subtype != AKA_IDENTITY)
	{
	return;
	}
if(aka->aka_prefix != AKA_PERMANENT)
	{
	return;
	}
if(aka->data[15] != '@')
	{
	return;
	}
if(imsioutname != NULL)
	{
	if((fhoutlist = fopen(imsioutname, "a+")) != NULL)
		{
		fwriteessidstr(15, aka->data, fhoutlist);
		fclose(fhoutlist);
		}
	}
return;
}
/*===========================================================================*/
void processeapsimauthentication(uint32_t eaplen, uint8_t *packet)
{
eapsim_t *sim;
FILE *fhoutlist = NULL;

sim = (eapsim_t*)packet;
if(eaplen < 29)
	{
	return;
	}
if(sim->code != EAP_CODE_RESP)
	{
	return;
	}
if(sim->subtype != SIM_SIM_START)
	{
	return;
	}
if(sim->sim_prefix != SIM_PERMANENT)
	{
	return;
	}
if(sim->data[15] != '@')
	{
	return;
	}
if(imsioutname != NULL)
	{
	if((fhoutlist = fopen(imsioutname, "a+")) != NULL)
		{
		fwriteessidstr(15, sim->data, fhoutlist);
		fclose(fhoutlist);
		}
	}
return;
}
/*===========================================================================*/
void processeapmd5authentication(uint32_t eaplen, uint8_t *packet)
{
md5_t *md5;

if(eaplen < 22)
	{
	return;
	}
md5 = (md5_t*)packet;
if(eaplen -6 < md5->data_len)
	{
	return;
	}
addeapmd5(md5->code, md5->id, md5->data_len, md5->data);
return;
}
/*===========================================================================*/
void processeapleapauthentication(uint32_t eaplen, uint8_t *packet)
{
eapleap_t *leap;
uint16_t leaplen;
uint16_t usernamelen;

if(eaplen < 4)
	{
	return;
	}
leap = (eapleap_t*)packet;
leaplen = ntohs(leap->len);

if(leaplen > eaplen)
	{
	return;
	}
if(leap->version != 1)
	{
	return;
	}
if(leap->count > leaplen)
	{
	return;
	}
usernamelen = leaplen -8 -leap->count;
if(usernamelen > LEAP_LEN_MAX)
	{
	return;
	}
if((leap->code == EAP_CODE_REQ) || (leap->code == EAP_CODE_RESP))
	{
	addeapleap(leap->code, leap->id, leap->count, leap->data, usernamelen, packet +8 +leap->count);
	if(leaplen -8 -leap->count != 0)
		{
		outlistusername(usernamelen, packet +8 +leap->count);
		}
	}
return;
}
/*===========================================================================*/
void processexeapauthentication(uint32_t eaplen, uint8_t *packet)
{
exteap_t *exeap; 

if(eaplen < (uint32_t)EXTEAP_SIZE)
	{
	return;
	}
exeap = (exteap_t*)packet;

if(exeap->exttype == EAP_TYPE_ID)
	{
	if(eaplen != 0)
		{
		outlistidentity(eaplen, packet);
		outlistimsi(eaplen, packet);
		}
	}
else if(exeap->exttype == EAP_TYPE_AKA)
	{
	processeapakaauthentication(eaplen, packet);
	}
else if(exeap->exttype == EAP_TYPE_SIM)
	{
	processeapsimauthentication(eaplen, packet);
	}
else if(exeap->exttype == EAP_TYPE_LEAP)
	{
	processeapleapauthentication(eaplen, packet);
	}
else if(exeap->exttype == EAP_TYPE_MD5)
	{
	processeapmd5authentication(eaplen, packet);
	}

exeaptype[exeap->exttype] = 1;
eapframecount++;
return;
}
/*===========================================================================*/
void process80211networkauthentication(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *macaddr1, uint8_t *macaddr2, uint8_t *packet)
{
eapauth_t *eap;

if(caplen < (uint32_t)EAPAUTH_SIZE)
	{
	return;
	}
eap = (eapauth_t*)packet;

if(eap->type == EAPOL_KEY)
	{
	process80211eapolauthentication(tv_sec, tv_usec, caplen, macaddr1, macaddr2, packet);
	}
else if((eap->type == EAP_PACKET) && (caplen > ntohs(eap->len)))
	{
	processexeapauthentication(ntohs(eap->len), packet  +EAPAUTH_SIZE);
	}
else if(eap->type == EAPOL_START)
	{
	processeapolstartauthentication();
	}
else if(eap->type == EAPOL_LOGOFF)
	{
	processeapollogoffauthentication();
	}
else if(eap->type == EAPOL_ASF)
	{
	processeapolasfauthentication();
	}
else if(eap->type == EAPOL_MKA)
	{
	processeapolmkaauthentication();
	}
return;
}
/*===========================================================================*/
void processradiuspacket()
{

radiusframecount++;
return;
}
/*===========================================================================*/
void processdhcp6packet()
{

dhcp6framecount++;
return;
}
/*===========================================================================*/
void processdhcppacket()
{

dhcpframecount++;
return;
}
/*===========================================================================*/
uint16_t dotzsptagwalk(int caplen, uint8_t *packet)
{
tzsptag_t *tzsptag;
tzsptag = (tzsptag_t*)packet;
uint16_t tagorglen = 0;

while(0 < caplen)
	{
	if(tzsptag->tag == TZSP_TAG_END)
		{
		return ntohs(tagorglen);
		}
	if(tzsptag->tag == TZSP_TAG_ORGLEN)
		{
		tagorglen = ((uint16_t)tzsptag->data[1] << 8) | tzsptag->data[0];
		}
	tzsptag = (tzsptag_t*)((uint8_t*)tzsptag +tzsptag->len +TZSPTAG_SIZE);
	if(tzsptag->len == 0)
		{
		return 0;
		}
	caplen -= tzsptag->len;
	}
return 0;
}
/*===========================================================================*/
void processtzsppacket(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
tzsp_t *tzsp;

tzsp = (tzsp_t*)packet;
uint16_t tzspdata = 0;

if(caplen < (uint32_t)TZSP_SIZE)
	{
	return;
	}
if(tzsp->version != 1)
	{
	return;
	}
if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_ETHERNET)
	{
	tzspethernetframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_TOKEN_RING)
	{
	tzsptokenringframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_SLIP)
	{
	tzspslipframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_PPP)
	{
	tzsppppframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_FDDI)
	{
	tzspfddiframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_RAW)
	{
	tzsprawframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_IEEE_802_11)
	{
	tzspdata = dotzsptagwalk(caplen -TZSP_SIZE, tzsp->data);
	if(tzspdata != 0)
		{
		if(tzspdata +TZSP_SIZE > caplen)
			{
			return;
			}
		process80211packet(tv_sec, tv_usec, tzspdata, packet +caplen -tzspdata);
		tzsp80211framecount++;
		}
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_IEEE_802_11_PRISM)
	{
	tzsp80211prismframecount++;
	}
else if(ntohs(tzsp->enc_protocol) == TZSP_ENCAP_IEEE_802_11_AVS)
	{
	tzsp80211avsframecount++;
	}
else
	{
	tzspframecount++;
	}
return;
}
/*===========================================================================*/
void processudppacket(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
udp_t *udp;
uint16_t udplen; 
uint8_t *packet_ptr;

if(caplen < (uint32_t)UDP_SIZE)
	{
	return;
	}
udp = (udp_t*)packet;
udplen = ntohs(udp->len);

packet_ptr = packet +UDP_SIZE;

if(caplen < udplen)
	{
	return;
	}
if((ntohs(udp->destinationport) == UDP_RADIUS_DESTINATIONPORT) || (ntohs(udp->sourceport) == UDP_RADIUS_DESTINATIONPORT))
	{
	processradiuspacket();
	}
else if(((ntohs(udp->destinationport) == UDP_DHCP_SERVERPORT) && (ntohs(udp->sourceport) == UDP_DHCP_CLIENTPORT)) || ((ntohs(udp->destinationport) == UDP_DHCP_CLIENTPORT) && (ntohs(udp->sourceport) == UDP_DHCP_SERVERPORT)))
	{
	processdhcppacket();
	}
else if(((ntohs(udp->destinationport) == UDP_DHCP6_SERVERPORT) && (ntohs(udp->sourceport) == UDP_DHCP6_CLIENTPORT)) || ((ntohs(udp->destinationport) == UDP_DHCP6_CLIENTPORT) && (ntohs(udp->sourceport) == UDP_DHCP6_SERVERPORT)))
	{
	processdhcp6packet();
	}
else if(ntohs(udp->destinationport) == UDP_TZSP_DESTINATIONPORT)
	{
	processtzsppacket(tv_sec, tv_usec, udplen -UDP_SIZE, packet_ptr);
	}
udpframecount++;
return;
}
/*===========================================================================*/
void processtacacsppacket(uint32_t caplen, uint8_t *packet)
{
tacacsp_t *tacacsp;
uint8_t *packet_ptr;

uint32_t authlen;

if(caplen < (uint32_t)TACACSP_SIZE)
	{
	return;
	}
tacacsp = (tacacsp_t*)packet;
if(tacacsp->type != TACACS_AUTHENTICATION)
	{
	return;
	}
authlen = ntohl(tacacsp->len);
if((authlen > caplen) || (authlen > 0xff))
	{
	return;
	}
packet_ptr = packet +TACACSP_SIZE;
addtacacsp(tacacsp->version, tacacsp->sequencenr, ntohl(tacacsp->sessionid), authlen, packet_ptr);
tacacspframecount++;
return;
}
/*===========================================================================*/
void processtcppacket(uint32_t caplen, uint8_t *packet)
{
tcp_t *tcp;
tacacsp_t *tacacsp;
uint16_t tcplen; 
uint8_t *packet_ptr;

if(caplen < (uint32_t)TCP_SIZE_MIN)
	{
	return;
	}
tcp = (tcp_t*)packet;
tcplen = byte_swap_8(tcp->len) *4;
if(caplen < tcplen)
	{
	return;
	}
if(caplen < (uint32_t)TCP_SIZE_MIN + (uint32_t)TACACSP_SIZE)
	{
	return;
	}
packet_ptr = packet +tcplen;
tacacsp = (tacacsp_t*)packet_ptr;

if(tacacsp->version == TACACSP_VERSION)
	{
	processtacacsppacket(caplen, packet_ptr);
	}
tcpframecount++;
return;
}
/*===========================================================================*/
void processpppchappacket(uint32_t caplen, uint8_t *packet)
{
chap_t *chap;
uint16_t chaplen;
uint16_t authlen;
uint16_t usernamelen;

if(caplen < (uint32_t)CHAP_SIZE)
	{
	return;
	}
chap = (chap_t*)packet;
chaplen = ntohs(chap->len);
authlen = chap->data[0];
usernamelen = chaplen -authlen -CHAP_SIZE;

//printf("%d %d %d %d\n", caplen, chaplen, authlen, hashlen);

if(chaplen > caplen)
	{
	return;
	}
if(authlen > chaplen)
	{
	return;
	}
if(usernamelen > authlen)
	{
	return;
	}
if((usernamelen == 0) || (usernamelen > LEAP_LEN_MAX))
	{
	return;
	}
if((authlen == 0) || (authlen > LEAP_LEN_MAX))
	{
	return;
	}

if((chap->code == CHAP_CODE_REQ) || (chap->code == CHAP_CODE_RESP))
	{
	addpppchapleap(chap->code, chap->id, authlen, chap->data +1, usernamelen, packet +authlen +CHAP_SIZE);
	if(chaplen -authlen -CHAP_SIZE != 0)
		{
		outlistusername(usernamelen, packet +authlen +CHAP_SIZE);
		}
	}
chapframecount++;
return;
}
/*===========================================================================*/
void processppppappacket()
{


papframecount++;
return;
}
/*===========================================================================*/

void processicmp6packet()
{

icmp6framecount++;
return;
}
/*===========================================================================*/
void processicmp4packet()
{

icmp4framecount++;
return;
}
/*===========================================================================*/
void processgrepacket(uint32_t caplen, uint8_t *packet)
{
gre_t *gre;
ptp_t *ptp;
uint8_t *packet_ptr;

if(caplen < (uint32_t)GRE_SIZE)
	{
	return;
	}
gre = (gre_t*)packet;
if((ntohs(gre->flags) & GRE_MASK_VERSION) != 0x1) /* only GRE v1 supported */
	{
	return;
	}
if(ntohs(gre->type) != GREPROTO_PPP)
	{
	return;
	}
packet_ptr = packet +GRE_SIZE;
if((ntohs(gre->flags) & GRE_FLAG_SNSET) == GRE_FLAG_SNSET)
	{
	packet_ptr += 4;
	}
if((ntohs(gre->flags) & GRE_FLAG_ACKSET) == GRE_FLAG_ACKSET)
	{
	packet_ptr += 4;
	}
ptp = (ptp_t*)(packet_ptr);
if(ntohs(ptp->type) == PROTO_CHAP)
	{
	processpppchappacket(caplen, packet_ptr +PTP_SIZE);
	}
else if(ntohs(ptp->type) == PROTO_PAP)
	{
	processppppappacket();
	}
greframecount++;
return;
}
/*===========================================================================*/
void processipv4packet(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
ipv4_t *ipv4;
uint32_t ipv4len;
uint8_t *packet_ptr;

if(caplen < (uint32_t)IPV4_SIZE_MIN)
	{
	return;
	}
ipv4 = (ipv4_t*)packet;

if((ipv4->ver_hlen & 0xf0) != 0x40)
	{
	return;
	}

ipv4len = (ipv4->ver_hlen & 0x0f) *4;
if(caplen < (uint32_t)ipv4len)
	{
	return;
	}
packet_ptr = packet +ipv4len;

if(ipv4->nextprotocol == NEXTHDR_ICMP4)
	{
	processicmp4packet();
	}
else if(ipv4->nextprotocol == NEXTHDR_TCP)
	{
	processtcppacket(ntohs(ipv4->len) -ipv4len, packet_ptr);
	}
else if(ipv4->nextprotocol == NEXTHDR_UDP)
	{
	processudppacket(tv_sec, tv_usec, ntohs(ipv4->len) -ipv4len, packet_ptr);
	}
else if(ipv4->nextprotocol == NEXTHDR_GRE)
	{
	processgrepacket(ntohs(ipv4->len) -ipv4len, packet_ptr);
	}

ipv4framecount++;
return;
}
/*===========================================================================*/
void processipv6packet(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
ipv6_t *ipv6;
uint8_t *packet_ptr;

if(caplen < (uint32_t)IPV6_SIZE)
	{
	return;
	}
ipv6 = (ipv6_t*)packet;
if((ntohl(ipv6->ver_class) & 0xf0000000) != 0x60000000)
	{
	return;
	}

packet_ptr = packet +IPV6_SIZE;
if(caplen < ntohs(ipv6->len))
	{
	return;
	}
if(ipv6->nextprotocol == NEXTHDR_ICMP6)
	{
	processicmp6packet();
	}
else if(ipv6->nextprotocol == NEXTHDR_TCP)
	{
	processtcppacket(ntohs(ipv6->len), packet_ptr);
	}
else if(ipv6->nextprotocol == NEXTHDR_UDP)
	{
	processudppacket(tv_sec, tv_usec, ntohs(ipv6->len), packet_ptr);
	}
else if(ipv6->nextprotocol == NEXTHDR_GRE)
	{
	processgrepacket(ntohs(ipv6->len), packet_ptr);
	}

ipv6framecount++;
return;
}
/*===========================================================================*/
void processweppacket()
{

wepframecount++;
return;
}
/*===========================================================================*/
void process80211datapacket(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint32_t wdsoffset, uint8_t *packet)
{
mac_t *macf;
llc_t *llc;
mpdu_t *mpdu;

uint8_t *packet_ptr;
macf = (mac_t*)packet;
packet_ptr = packet;

if((macf->subtype == IEEE80211_STYPE_DATA) || (macf->subtype == IEEE80211_STYPE_DATA_CFACK) || (macf->subtype == IEEE80211_STYPE_DATA_CFPOLL) || (macf->subtype == IEEE80211_STYPE_DATA_CFACKPOLL))
	{
	if(caplen < (uint32_t)MAC_SIZE_NORM +wdsoffset +(uint32_t)LLC_SIZE)
		{
		return;
		}
	llc = (llc_t*)(packet +MAC_SIZE_NORM +wdsoffset);
	packet_ptr += MAC_SIZE_NORM +wdsoffset +LLC_SIZE;
	if((ntohs(llc->type) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211networkauthentication(tv_sec, tv_usec, caplen -MAC_SIZE_NORM -wdsoffset -LLC_SIZE, macf->addr1, macf->addr2, packet_ptr);
		}
	else if((ntohs(llc->type) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv4packet(tv_sec, tv_usec, caplen -MAC_SIZE_NORM -wdsoffset -LLC_SIZE, packet_ptr);
		}
	else if((ntohs(llc->type) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv6packet(tv_sec, tv_usec, caplen -MAC_SIZE_NORM -wdsoffset -LLC_SIZE, packet_ptr);
		}
	else if(macf->protected == 1)
		{
		mpdu = (mpdu_t*)(packet +MAC_SIZE_NORM +wdsoffset);
		if(((mpdu->keyid >> 5) &1) == 0)
			{
			processweppacket();
			}
		}
	return;
	}

if((macf->subtype == IEEE80211_STYPE_QOS_DATA) || (macf->subtype == IEEE80211_STYPE_QOS_DATA_CFACK) || (macf->subtype == IEEE80211_STYPE_QOS_DATA_CFPOLL) || (macf->subtype == IEEE80211_STYPE_QOS_DATA_CFACKPOLL))
	{
	if(caplen < (uint32_t)MAC_SIZE_QOS +wdsoffset +(uint32_t)LLC_SIZE)
		{
		return;
		}
	llc = (llc_t*)(packet +MAC_SIZE_QOS +wdsoffset);
	packet_ptr += MAC_SIZE_QOS +wdsoffset +LLC_SIZE;
	if((ntohs(llc->type) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211networkauthentication(tv_sec, tv_usec, caplen -MAC_SIZE_QOS -wdsoffset -LLC_SIZE, macf->addr1, macf->addr2, packet_ptr);
		}
	else if((ntohs(llc->type) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv4packet(tv_sec, tv_usec, caplen -MAC_SIZE_QOS -wdsoffset -LLC_SIZE, packet_ptr);
		}
	else if((ntohs(llc->type) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv6packet(tv_sec, tv_usec, caplen -MAC_SIZE_QOS -wdsoffset -LLC_SIZE, packet_ptr);
		}
	else if(macf->protected == 1)
		{
		mpdu = (mpdu_t*)(packet +MAC_SIZE_QOS +wdsoffset);
		if(((mpdu->keyid >> 5) &1) == 0)
			{
			processweppacket();
			}
		}
	}
return;
}
/*===========================================================================*/
void process80211packet(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
uint32_t wdsoffset = 0;
mac_t *macf;

struct timeval gpstime;
char timestring[64];

gpstime.tv_sec = tv_sec;
gpstime.tv_usec = tv_usec;
unsigned long long int macsrc;

strftime(timestring, 62, "    <time>%Y-%m-%dT%H:%M:%SZ</time>", gmtime(&gpstime.tv_sec));
macf = (mac_t*)packet;
if((macf->from_ds == 1) && (macf->to_ds == 1))
	{
	process80211wds();
	wdsoffset = 6;
	}

if(gpxflag == true)
	{
	if((lat != 0) && (lon != 0))
		{
		if(caplen >= (uint32_t)MAC_SIZE_NORM +wdsoffset)
			{
			macsrc = macf->addr2[0];
			macsrc = (macsrc << 8) + macf->addr2[1];
			macsrc = (macsrc << 8) + macf->addr2[2];
			macsrc = (macsrc << 8) + macf->addr2[3];
			macsrc = (macsrc << 8) + macf->addr2[4];
			macsrc = (macsrc << 8) + macf->addr2[5];
			fprintf(fhgpx, "  <trkpt lat=\"%Lf\" lon=\"%LF\">\n    <ele>%Lf</ele>\n%s\n    <name>%012llx</name>\n    <cmt>GPS-TIME:%04d-%02d-%02dT%02d:%02d:%02dZ</cmt>\n  </trkpt>\n", lat, lon, alt, timestring, macsrc, year, month, day, hour, minute, second);
			}
		}
	}

if((filtermacflag == true) && (caplen >= (uint32_t)MAC_SIZE_NORM))
	{
	if((memcmp(macf->addr1, &filtermac, 6) != 0) && (memcmp(macf->addr2, &filtermac, 6) != 0) && (memcmp(macf->addr3, &filtermac, 6) != 0))
		{
		return;
		}
	}

if(memcmp(macf->addr2, &mac_null, 6) == 0)
	{
	skippedpacketcount++;
	return;
	}
if(memcmp(macf->addr1, &mac_null, 6) == 0)
	{
	skippedpacketcount++;
	return;
	}
if(macf->type == IEEE80211_FTYPE_MGMT)
	{
	if(macf->subtype == IEEE80211_STYPE_BEACON)
		{
		process80211beacon(tv_sec, tv_usec, caplen, wdsoffset, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		process80211probe_req(tv_sec, tv_usec, caplen, wdsoffset, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_PROBE_RESP)
		{
		process80211probe_resp(tv_sec, tv_usec, caplen, wdsoffset, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_ASSOC_REQ)
		{
		process80211assoc_req(tv_sec, tv_usec, caplen, wdsoffset, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_ASSOC_RESP)
		{
		process80211assoc_resp();
		}
	else if (macf->subtype == IEEE80211_STYPE_REASSOC_REQ)
		{
		process80211reassoc_req(tv_sec, tv_usec, caplen, wdsoffset, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_REASSOC_RESP)
		{
		process80211reassoc_resp();
		}
	else if (macf->subtype == IEEE80211_STYPE_AUTH)
		{
		process80211authentication(caplen, wdsoffset, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_DEAUTH)
		{
		process80211deauthentication();
		}
	else if (macf->subtype == IEEE80211_STYPE_DISASSOC)
		{
		process80211disassociation();
		}
	else if (macf->subtype == IEEE80211_STYPE_ACTION)
		{
		process80211action();
		}
	else if (macf->subtype == IEEE80211_STYPE_ATIM)
		{
		process80211atim();
		}
	return;
	}

else if (macf->type == IEEE80211_FTYPE_DATA)
	{
	process80211datapacket(tv_sec, tv_usec, caplen, wdsoffset, packet);
	}
return;
}
/*===========================================================================*/
void processethernetpacket(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
eth2_t *eth2;
uint8_t *packet_ptr;

eth2 = (eth2_t*)packet;
packet_ptr = packet;
packet_ptr += ETH2_SIZE;
caplen -= ETH2_SIZE;
if(ntohs(eth2->ether_type) == LLC_TYPE_IPV4)
	{
	processipv4packet(tv_sec, tv_usec, caplen, packet_ptr);
	}
if(ntohs(eth2->ether_type) == LLC_TYPE_IPV6)
	{
	processipv6packet(tv_sec, tv_usec, caplen, packet_ptr);
	}

if(ntohs(eth2->ether_type) == LLC_TYPE_AUTH)
	{
	process80211networkauthentication(tv_sec, tv_usec, caplen, eth2->addr1, eth2->addr2, packet_ptr);
	}
return;
}
/*===========================================================================*/
void processloopbackpacket(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
loba_t *loba;
uint8_t *packet_ptr;

loba = (loba_t*)packet;
packet_ptr = packet +LOBA_SIZE;
caplen -= LOBA_SIZE;

if(ntohl(loba->family == AF_INET))
	{
	processipv4packet(tv_sec, tv_usec, caplen, packet_ptr);
	processipv6packet(tv_sec, tv_usec, caplen, packet_ptr);
	}
return;
}
/*===========================================================================*/
void processpacket(uint32_t tv_sec, uint32_t tv_usec, int linktype, uint32_t caplen, uint8_t *packet)
{
uint8_t *packet_ptr;
rth_t *rth;
fcs_t *fcs;
prism_t *prism;
avs_t *avs;
ppi_t *ppi;
uint32_t crc;
struct timeval tvtmp;

if(mintv.tv_sec == 0)
	{
	mintv.tv_sec = tv_sec;
	}

if((long int)tv_sec <= mintv.tv_sec)
	{
	mintv.tv_sec = tv_sec;
	}

if((long int)tv_sec >= maxtv.tv_sec)
	{
	maxtv.tv_sec = tv_sec;
	}

packet_ptr = packet;
if(caplen < (uint32_t)MAC_SIZE_NORM)
	{
	return;	
	}
if((tv_sec == 0) && (tv_usec == 0)) 
	{
	tscleanflag = true;
	gettimeofday(&tvtmp, NULL);
	tv_sec = tvtmp.tv_sec;
	tv_usec = tvtmp.tv_usec;
	}

if(linktype == DLT_NULL)
	{
	if(caplen < (uint32_t)LOBA_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read loopback header\n");
		return;
		}
	processloopbackpacket(tv_sec, tv_usec, caplen, packet);
	return;
	}
else if(linktype == DLT_EN10MB)
	{
	if(caplen < (uint32_t)ETH2_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read ethernet header\n");
		return;
		}
	processethernetpacket(tv_sec, tv_usec, caplen, packet);
	return;
	}
else if(linktype == DLT_IEEE802_11_RADIO)
	{
	if(caplen < (uint32_t)RTH_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read radiotap header\n");
		return;
		}
	rth = (rth_t*)packet;
	#ifdef BIG_ENDIAN_HOST
	rth->it_len	= byte_swap_16(rth->it_len);
	rth->it_present	= byte_swap_32(rth->it_present);
	#endif
	if(rth->it_len > caplen)
		{
		pcapreaderrors++;
		printf("failed to read radiotap header\n");
		return;
		}
	packet_ptr += rth->it_len;
	caplen -= rth->it_len;
	}
else if(linktype == DLT_IEEE802_11)
	{
	/* nothing to do */
	}
else if(linktype == DLT_PRISM_HEADER)
	{
	if(caplen < (uint32_t)PRISM_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read prism header\n");
		return;
		}
	prism = (prism_t*)packet;
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
	packet_ptr += prism->msglen;
	caplen -= prism->msglen;
	}
else if(linktype == DLT_IEEE802_11_RADIO_AVS)
	{
	if(caplen < (uint32_t)AVS_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read avs header\n");
		return;
		}
	avs = (avs_t*)packet;
	#ifdef BIG_ENDIAN_HOST
	avs->len		= byte_swap_32(avs->len);
	#endif
	if(avs->len > caplen)
		{
		pcapreaderrors++;
		printf("failed to read avs header\n");
		return;
		}
	packet_ptr += avs->len;
	caplen -= avs->len;
	}
else if(linktype == DLT_PPI)
	{
	if(caplen < (uint32_t)PPI_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read ppi header\n");
		return;
		}
	ppi = (ppi_t*)packet;
	#ifdef BIG_ENDIAN_HOST
	ppi->pph_len	= byte_swap_16(ppi->pph_len);
	#endif
	if(ppi->pph_len > caplen)
		{
		pcapreaderrors++;
		printf("failed to read ppi header\n");
		return;
		}
	packet_ptr += ppi->pph_len;
	caplen -= ppi->pph_len;
	}
else
	{
	printf("unsupported network type %d\n", linktype);
	return;
	}

if(caplen < 4)
	{
	pcapreaderrors++;
	printf("failed to read packet\n");
	return;
	}
fcs = (fcs_t*)(packet_ptr +caplen -4);

crc = fcscrc32check(packet_ptr, caplen -4);

#ifdef BIG_ENDIAN_HOST
crc	= byte_swap_32(crc);
#endif
if(endianess == 1)
	{
	crc	= byte_swap_32(crc);
	}

if(crc == fcs->fcs)
	{
	fcsflag = true;
	fcsframecount++;
	caplen -= 4;
	}

process80211packet(tv_sec, tv_usec, caplen, packet_ptr);

return;
}

/*===========================================================================*/
void pcapngcustomoptionwalk(uint8_t *optr, int restlen)
{
hcxdumptoolcoflag = true;

option_header_t *option;
int padding;

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
	if((option->option_length  %4))
		{
		padding = 4 -(option->option_length %4);
		}
	if(option->option_code == SHB_EOC)
		{
		return;
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
		if(option->option_length == 6)
			{
			memcpy(&myaktap, &option->data, 6);
			}
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
		if(option->option_length == 32)
			{
			memcpy(&myaktanonce, &option->data, 32);
			}
		}
	else if(option->option_code == OPTIONCODE_MACCLIENT)
		{
		if(option->option_length == 6)
			{
			memcpy(&myaktsta, &option->data, 6);
			}
		}
	else if(option->option_code == OPTIONCODE_SNONCE)
		{
		if(option->option_length == 32)
			{
			memcpy(&myaktsnonce, &option->data, 32);
			}
		}
	else if(option->option_code == OPTIONCODE_WEAKCANDIDATE)
		{
		if(option->option_length < 64)
			{
			memset(&weakcandidate, 0, 64);
			memcpy(&weakcandidate, &option->data, option->option_length);
			}
		}
	else if(option->option_code == OPTIONCODE_NMEA)
		{
		if(option->option_length >= 66)
			{
			memset(&nmeasentence, 0, NMEA_MAX);
			memcpy(&nmeasentence, &option->data, option->option_length);
			}
		}
	optr += option->option_length +padding +OH_SIZE;
	restlen -= option->option_length +padding +OH_SIZE;
	}
return;
}
/*===========================================================================*/
void pcapngoptionwalk(uint32_t blocktype, uint8_t *optr, int restlen)
{
option_header_t *option;
int padding;
char *gpsdptr;
char *gpsd_date = "date:";
char *gpsd_time = "time:";
char *gpsd_lat = "lat:";
char *gpsd_lon = "lon:";
char *gpsd_alt = "alt:";

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
	if((option->option_length  %4))
		{
		padding = 4 -(option->option_length %4);
		}

	if(option->option_code == SHB_EOC)
		{
		return;
		}

	else if((option->option_code == SHB_COMMENT) && (blocktype == 6))
		{
		memset(&pcapngoptioninfo, 0, 1024);
		if(option->option_length < 1024)
			{
			memset(&pcapngoptioninfo, 0, 1024);
			memcpy(&pcapngoptioninfo, option->data, option->option_length);
			}
		lat = 0;
		lon = 0;
		alt = 0;
		day = 0;
		month = 0;
		year = 0;
		hour = 0;
		minute = 0;
		second = 0;
		if((gpsdptr = strstr(pcapngoptioninfo, gpsd_lat)) != NULL)
			{
			sscanf(gpsdptr +4, "%Lf", &lat);
			}
		if((gpsdptr = strstr(pcapngoptioninfo, gpsd_lon)) != NULL)
			{
			sscanf(gpsdptr +4, "%Lf", &lon);
			}
		if((gpsdptr = strstr(pcapngoptioninfo, gpsd_alt)) != NULL)
			{
			sscanf(gpsdptr +4, "%Lf", &alt);
			}
		if((gpsdptr = strstr(pcapngoptioninfo, gpsd_date)) != NULL)
			{
			sscanf(gpsdptr +5, "%d.%d.%d", &day, &month, &year);
			}
		if((gpsdptr = strstr(pcapngoptioninfo, gpsd_time)) != NULL)
			{
			sscanf(gpsdptr +5, "%d:%d:%d", &hour, &minute, &second);
			}
		if((lat != 0) && (lon != 0))
			{
			gpsdframecount++;
			}
		}
	else if((option->option_code == SHB_HARDWARE) && (blocktype == PCAPNGBLOCKTYPE))
		{
		if(option->option_length < 1024)
			{
			memset(&pcapnghwinfo, 0, 1024);
			memcpy(&pcapnghwinfo, option->data, option->option_length);
			}
		}
	else if((option->option_code == SHB_OS) && (blocktype == PCAPNGBLOCKTYPE))
		{
		if(option->option_length < 1024)
			{
			memset(&pcapngosinfo, 0, 1024);
			memcpy(&pcapngosinfo, option->data, option->option_length);
			}
		}
	else if((option->option_code == SHB_USER_APPL) && (blocktype == PCAPNGBLOCKTYPE))
		{
		if(option->option_length < 1024)
			{
			memset(&pcapngapplinfo, 0, 1024);
			memcpy(&pcapngapplinfo, option->data, option->option_length);
			}
		}
	else if((option->option_code == IF_MACADDR) && (blocktype == 1) && (hcxdumptoolcbflag != true))
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
			if((memcmp(&option->data[0], &hcxmagic, 4) == 0) && (memcmp(&option->data[4], &hcxmagic, 32) == 0))
				{
				pcapngcustomoptionwalk(optr +OH_SIZE +36, option->option_length -36);
				}
			else if((memcmp(&option->data[1], &hcxmagic, 4) == 0) && (memcmp(&option->data[5], &hcxmagic, 32) == 0))
				{
				pcapngcustomoptionwalk(optr +OH_SIZE +1 +36, option->option_length -36);
				}
			}
		}
	else if((hcxdumptoolcbflag == true) && (blocktype != CBID))
		{
		optr += option->option_length +padding +OH_SIZE;
		restlen -= option->option_length +padding +OH_SIZE;
		continue;
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
		if(option->option_length == 6)
			{
			memcpy(&myaktap, &option->data, 6);
			}
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
		if(option->option_length == 32)
			{
			memcpy(&myaktanonce, &option->data, 32);
			}
		}
	else if(option->option_code == OPTIONCODE_MACCLIENT)
		{
		if(option->option_length == 6)
			{
			memcpy(&myaktsta, &option->data, 6);
			}
		}
	else if(option->option_code == OPTIONCODE_SNONCE)
		{
		if(option->option_length == 32)
			{
			memcpy(&myaktsnonce, &option->data, 32);
			}
		}
	else if(option->option_code == OPTIONCODE_WEAKCANDIDATE)
		{
		if(option->option_length < 64)
			{
			memset(&weakcandidate, 0, 64);
			memcpy(&weakcandidate, &option->data, option->option_length);
			}
		}
	else if(option->option_code == OPTIONCODE_NMEA)
		{
		if(option->option_length >= 66)
			{
			nmealen = option->option_length;
			memset(&nmeasentence, 0, NMEA_MAX);
			memcpy(&nmeasentence, &option->data, option->option_length);
			if(fhnmea != NULL) fprintf(fhnmea, "%s\n", nmeasentence);
			gpsnmeaframecount++;
			}
		}
	optr += option->option_length +padding +OH_SIZE;
	restlen -= option->option_length +padding +OH_SIZE;
	}
return;
}
/*===========================================================================*/
void processpcapng(int fd, char *pcapinname)
{
unsigned int res;
off_t fdsize;
off_t aktseek;
off_t resseek;

uint64_t timestamp;
uint32_t timestamp_sec;
uint32_t timestamp_usec;
uint32_t snaplen;
uint32_t blocktype;
uint32_t blocklen;
uint32_t blockmagic;
int padding;

block_header_t *pcapngbh;
section_header_block_t *pcapngshb;
interface_description_block_t *pcapngidb;
packet_block_t *pcapngpb;
enhanced_packet_block_t *pcapngepb;
custom_block_t *pcapngcb;

uint8_t pcpngblock[2 *MAXPACPSNAPLEN];
uint8_t packet[MAXPACPSNAPLEN];

printf("\nreading from %s\n", basename(pcapinname));
hcxdumptoolcbflag = false;
hcxdumptoolcoflag = false;
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

if(gpxflag == true)
	{
	fprintf(fhgpx, "<trk>\n  <name>%s</name>\n  <trkseg>\n", basename(pcapinname));
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
			printf("detected oversized snaplen (%d)          \n", snaplen);
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
		timestamp = 0;
		timestamp = 0;
		timestamp_sec = 0;
		timestamp_usec = 0;
		tscleanflag = true;
		if(pcapngpb->caplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("caplen > MAXSNAPLEN (%d > %d)             \n", pcapngpb->caplen, MAXPACPSNAPLEN);
			continue;
			}
		if(pcapngpb->caplen > blocklen)
			{
			pcapreaderrors++;
			printf("caplen > blocklen (%d > %d )             \n", pcapngpb->caplen, blocklen);
			continue;
			}
		rawpacketcount++;
		if(verboseflag == true)
			{
			processpacket(timestamp_sec, timestamp_usec, dltlinktype, pcapngpb->caplen, pcapngpb->data);
			}
		if(hexmodeflag == true)
			{
			packethexdump(timestamp_sec, timestamp_usec, rawpacketcount, dltlinktype, snaplen, pcapngepb->caplen, pcapngpb->len, pcapngpb->data);
			}
		if((rawpacketcount > 100000) && ((rawpacketcount %100000) == 0))
			{
			printf("%lld packets processed - be patient!\r", rawpacketcount);
			}
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
		timestamp = pcapngepb->timestamp_high;
		timestamp = (timestamp << 32) +pcapngepb->timestamp_low;
		timestamp_sec = timestamp /1000000;
		timestamp_usec = timestamp %1000000;
		if((pcapngepb->timestamp_high == 0) && (pcapngepb->timestamp_low == 0))
			{
			tscleanflag = true;
			}
		if(pcapngepb->caplen != pcapngepb->len)
			{
			pcapreaderrors++;
			printf("caplen != len (%d != %d)          \n", pcapngepb->caplen, pcapngepb->len);
			continue;
			}
		if(pcapngepb->caplen > MAXPACPSNAPLEN)
			{
			pcapreaderrors++;
			printf("caplen > MAXSNAPLEN (%d > %d)             \n", pcapngepb->caplen, MAXPACPSNAPLEN);
			continue;
			}
		if(pcapngepb->caplen > blocklen)
			{
			pcapreaderrors++;
			printf("caplen > blocklen (%d > %d)             \n", pcapngepb->caplen, blocklen);
			continue;
			}
		rawpacketcount++;
		if(verboseflag == true)
			{
			processpacket(timestamp_sec, timestamp_usec, dltlinktype, pcapngepb->caplen, pcapngepb->data);
			}
		if(hexmodeflag == true)
			{
			packethexdump(timestamp_sec, timestamp_usec, rawpacketcount, dltlinktype, snaplen, pcapngepb->caplen, pcapngepb->len, pcapngepb->data);
			}
		if((rawpacketcount > 100000) && ((rawpacketcount %100000) == 0))
			{
			printf("%lld packets processed - be patient!\r", rawpacketcount);
			}
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
		hcxdumptoolcbflag = true;
		pcapngoptionwalk(blocktype, pcapngcb->data, blocklen -CB_SIZE);
		}
	else
		{
		skippedpacketcount++;
		}
	}
if(gpxflag == true)
	{
	fprintf(fhgpx, "  </trkseg>\n</trk>\n");
	}
return;
}
/*===========================================================================*/
void processpcap(int fd, char *pcapinname)
{
unsigned int res;
off_t resseek;

pcap_hdr_t pcapfhdr;
pcaprec_hdr_t pcaprhdr;
uint8_t packet[MAXPACPSNAPLEN];

printf("\nreading from %s\n", basename(pcapinname));
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
	printf("unsupported pcap version                 \n");
	return;
	}
if(pcapfhdr.version_minor != PCAP_MINOR_VER)
	{
	pcapreaderrors++;
	printf("unsupported pcap version                 \n");
	return;
	}
if(pcapfhdr.snaplen > MAXPACPSNAPLEN)
	{
	pcapreaderrors++;
	printf("detected oversized snaplen (%d)          \n", pcapfhdr.snaplen);
	}

while(1)
	{
	res = read(fd, &pcaprhdr, PCAPREC_SIZE);
	if(res == 0) 
		{
		break;
		}
	if(res != PCAPREC_SIZE)
		{
		pcapreaderrors++;
		printf("failed to read pcap packet header for packet %lld\n", rawpacketcount);
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
//		printf("failed to read packet %lld (incl len %d > snaplen %d)\n", rawpacketcount, pcaprhdr.incl_len, pcapfhdr.snaplen);
		}
/*
	if(pcaprhdr.incl_len > pcaprhdr.orig_len)
		{
		pcapreaderrors++;
		printf("failed to read packet %lld  (incl len %d > orig len %d)\n", rawpacketcount, pcaprhdr.incl_len, pcaprhdr.orig_len);
		}
*/
	if(pcaprhdr.incl_len < MAXPACPSNAPLEN)
		{
		res = read(fd, &packet, pcaprhdr.incl_len);
		if(res != pcaprhdr.incl_len)
			{
			pcapreaderrors++;
			printf("failed to read packet %lld (packet len %d != incl len %d   \n", rawpacketcount, res, pcaprhdr.incl_len);
			break;
			}
		rawpacketcount++;
		}
	else
		{
		resseek = lseek(fd, pcaprhdr.incl_len, SEEK_CUR);
		if(resseek < 0)
			{
			pcapreaderrors++;
			printf("failed to set file pointer\n");
			break;
			}
		skippedpacketcount++;
		continue;
		}

	if(pcaprhdr.incl_len > 0)
		{
		if(hexmodeflag == true)
			{
			packethexdump(pcaprhdr.ts_sec, pcaprhdr.ts_usec, rawpacketcount, pcapfhdr.network, pcapfhdr.snaplen, pcaprhdr.incl_len, pcaprhdr.orig_len, packet);
			}
		if(verboseflag == true)
			{
			processpacket(pcaprhdr.ts_sec, pcaprhdr.ts_usec, pcapfhdr.network, pcaprhdr.incl_len, packet);
			}
		if((rawpacketcount > 100000) && ((rawpacketcount %100000) == 0))
			{
			printf("%lld packets processed - be patient!\r", rawpacketcount);
			}
		}
	}
return;
}
/*===========================================================================*/
void processmsnetmon1(int fd, char *pcapinname)
{
unsigned int res;
int resseek;
msntm_t msnthdr;
uint8_t packet[MAXPACPSNAPLEN];

printf("start reading from %s\n", pcapinname);
memset(&packet, 0, MAXPACPSNAPLEN);
resseek = lseek(fd, 4L, SEEK_SET);
if(resseek < 0)
	{
	pcapreaderrors++;
	printf("failed to set file pointer\n");
	return;
	}

res = read(fd, &msnthdr, MSNETMON_SIZE);
if(res != MSNETMON_SIZE)
	{
	printf("failed to read Microsoft NetworkMonitor header\n");
	return;
	}

#ifdef BIG_ENDIAN_HOST
msnthdr.network = byte_swap_16(msnthdr.network);
#endif

versionmajor = msnthdr.version_major;
versionminor = msnthdr.version_minor;
dltlinktype  = msnthdr.network;
return;
}
/*===========================================================================*/
void processmsnetmon2(int fd, char *pcapinname)
{
unsigned int res;
int resseek;
msntm_t msnthdr;
uint8_t packet[MAXPACPSNAPLEN];

printf("start reading from %s\n", pcapinname);
memset(&packet, 0, MAXPACPSNAPLEN);
resseek = lseek(fd, 4L, SEEK_SET);
if(resseek < 0)
	{
	pcapreaderrors++;
	printf("failed to set file pointer\n");
	return;
	}
res = read(fd, &msnthdr, MSNETMON_SIZE);
if(res != MSNETMON_SIZE)
	{
	printf("failed to read Microsoft NetworkMonitor header\n");
	return;
	}

#ifdef BIG_ENDIAN_HOST
msnthdr.network = byte_swap_16(msnthdr.network);
#endif

versionmajor = msnthdr.version_major;
versionminor = msnthdr.version_minor;
dltlinktype  = msnthdr.network;
return;
}
/*===========================================================================*/
void processcapfile(char *pcapinname)
{
int resseek = 0;
int pcapr_fd;
uint32_t magicnumber;
bool needrmflag = false;
char *pcapart;

fcsflag = false;
apstaessidliste = NULL;
apstaessidlistecleaned = NULL;
eapolliste = NULL;
pmkidliste = NULL;
handshakeliste = NULL;
leapliste = NULL;
leap2liste = NULL;
md5liste = NULL;
tacacspliste = NULL;

char *pcapstr = "pcap";
char *pcapngstr = "pcapng";
char *msnetmon1str = "Microsoft NetworkMonitor 1";
char *msnetmon2str = "Microsoft NetworkMonitor 2";

tscleanflag = false;
tssameflag = false;

versionmajor = 0;
versionminor = 0;
dltlinktype  = 0;
endianess = 0;
pcapreaderrors = 0;
rawpacketcount = 0;
skippedpacketcount = 0;
apstaessidcount = 0;
apstaessidcountcleaned = 0;
eapolcount = 0;
gpsdframecount = 0;
gpsnmeaframecount = 0;
fcsframecount = 0;
wdsframecount = 0;
beaconframecount = 0;
beaconframedamagedcount = 0;
wpsframecount = 0;
deviceinfoframecount = 0;
meshidframecount = 0;
proberequestframecount = 0;
proberesponseframecount = 0;
associationrequestframecount = 0;
associationresponseframecount = 0;
reassociationrequestframecount = 0;
reassociationresponseframecount = 0;
authenticationunknownframecount = 0;
authenticationosframecount = 0;
authenticationskframecount = 0;
authenticationfbtframecount = 0;
authenticationsaeframecount = 0;
authenticationfilsframecount = 0;
authenticationfilspfsframecount = 0;
authenticationfilspkframecount = 0;
authenticationnetworkeapframecount = 0;
authenticationbroadcomframecount = 0;
authenticationsonosframecount = 0;
authenticationappleframecount = 0;
authenticationwiliboxframecount = 0;
authenticationciscoframecount = 0;
deauthenticationframecount = 0;
disassociationframecount = 0;
handshakecount = 0;
handshakeaplesscount = 0;
rawhandshakecount = 0;
rawhandshakeaplesscount = 0;
leapcount = 0;
actionframecount = 0;
atimframecount = 0;
eapolframecount = 0;
eapoloversizedframecount = 0;
eapolwpaakmframecount = 0;
eapolwpa1framecount = 0;
eapolwpa2framecount = 0;
eapolwpa2kv3framecount = 0;
pmkidcount = 0;
pmkidapcount = 0;
pmkidstacount = 0;
pmkidallcount = 0;
zeroedpmkcount = 0;
zeroedpmkidcount = 0;
eapolpmkidwpaakmframecount = 0;
eapolpmkidwpa1framecount = 0;
eapolpmkidwpa2framecount = 0;
eapolpmkidwpa2kv3framecount = 0;
groupkeyframecount = 0;
rc4descriptorframecount = 0;
eapolstartframecount = 0;
eapollogoffframecount = 0;
eapolasfframecount = 0;
eapolmkaframecount = 0;
eapframecount = 0;
ipv4framecount = 0;
ipv6framecount = 0;
icmp4framecount = 0;
icmp6framecount = 0;
tcpframecount = 0;
udpframecount = 0;
greframecount = 0;
chapframecount = 0;
papframecount = 0;
tacacspframecount = 0;
radiusframecount = 0;
dhcpframecount = 0;
dhcp6framecount = 0;
tzspframecount = 0;
tzspethernetframecount = 0;
tzsptokenringframecount = 0;
tzspslipframecount = 0;
tzsppppframecount = 0;
tzspfddiframecount = 0;
tzsprawframecount = 0;
tzsp80211framecount = 0;
tzsp80211prismframecount = 0;
tzsp80211avsframecount = 0;
wepframecount = 0;
lat = 0;
lon = 0;
alt = 0;

mintv.tv_sec = 0;
mintv.tv_usec = 0;

maxtv.tv_sec = 0;
maxtv.tv_usec = 0;

char *unknown = "unknown";
char tmpoutname[PATH_MAX+1];

memset(&pcapngdeviceinfo, 0, 6);
memset(&myaktap, 0, 6);
memset(&myaktsta, 0, 6);
memset(&myaktsnonce, 0, 32);
memset(&weakcandidate, 0, 64);

myaktreplaycount = MYREPLAYCOUNT;
memcpy(&myaktanonce, &mynonce, 32);
strcpy(pcapnghwinfo, unknown);
strcpy(pcapngosinfo, unknown);
strcpy(pcapngapplinfo, unknown);

if(testgzipfile(pcapinname) == true)
	{
	memset(&tmpoutname, 0, PATH_MAX+1);
	snprintf(tmpoutname, PATH_MAX, "/tmp/%s.tmp", basename(pcapinname));
	if(decompressgz(pcapinname, tmpoutname) == false)
		{
		return;
		}
	pcapinname = tmpoutname;
	needrmflag = true;
	}

memset(exeaptype, 0, sizeof(int) *256);
pcapr_fd = open(pcapinname, O_RDONLY);
if(pcapr_fd == -1)
	{
	if(needrmflag == true)
		{
		remove(tmpoutname);
		}
	printf("\nwarning: no capture file loaded\n\n");
	return;
	}

magicnumber = getmagicnumber(pcapr_fd);

if((magicnumber != PCAPMAGICNUMBER) && (magicnumber != PCAPMAGICNUMBERBE) && (magicnumber != PCAPNGBLOCKTYPE) && (magicnumber != MSNETMON1) && (magicnumber != MSNETMON2))
	{
	printf("failed to get magicnumber from %s\n", basename(pcapinname));
	close(pcapr_fd);
	if(needrmflag == true)
		{
		remove(tmpoutname);
		}
	return;
	}
resseek = lseek(pcapr_fd, 0L, SEEK_SET);
if(resseek < 0)
	{
	pcapreaderrors++;
	printf("failed to set file pointer\n");
	return;
	}

pcapart = pcapstr;
if(magicnumber == MSNETMON1)
	{
	processmsnetmon1(pcapr_fd, pcapinname);
	close(pcapr_fd);
	pcapart = msnetmon1str;
	}

else if(magicnumber == MSNETMON2)
	{
	processmsnetmon1(pcapr_fd, pcapinname);
	close(pcapr_fd);
	pcapart = msnetmon2str;
	}

else if((magicnumber == PCAPMAGICNUMBER) || (magicnumber == PCAPMAGICNUMBERBE))
	{
	processpcap(pcapr_fd, pcapinname);
	close(pcapr_fd);
	pcapart = pcapstr;
	}

else if(magicnumber == PCAPNGBLOCKTYPE)
	{
	processpcapng(pcapr_fd, pcapinname);
	close(pcapr_fd);
	pcapart = pcapngstr;
	}

if(needrmflag == true)
	{
	remove(tmpoutname);
	}

if(apstaessidliste != NULL)
	{
	cleanapstaessid();
	}

if(eapolliste != NULL)
	{
	findhandshake();
	}
printcapstatus(pcapart, pcapinname, versionmajor, versionminor, dltlinktype, endianess, rawpacketcount, skippedpacketcount, pcapreaderrors, tscleanflag);

printf(	"summary output file(s):\n"
	"-----------------------\n");

if(apstaessidliste != NULL) 
	{
	outputessidlists();
	}

if(pmkidliste != NULL)
	{
	outputrawpmkidlists();
	outputpmkidlists();
	}

if(rawhandshakeliste != NULL)
	{
	outputrawwpalists(pcapinname);
	}

if(handshakeliste != NULL)
	{
	outputwpalists(pcapinname);
	}

if(leapliste != NULL)
	{
	outputleaplist();
	}

if(leap2liste != NULL)
	{
	outputpppchaplist();
	}

if(md5liste != NULL)
	{
	outputmd5list();
	}

if(tacacspliste != NULL)
	{
	outputtacacsplist();
	}

if(gpxflag == true)
	{
	if(gpsdframecount == 1)
		{
		printf("%llu track point written to %s\n", gpsdframecount, gpxoutname);
		}
	else if(gpsdframecount > 1)
		{
		printf("%llu track points written to %s\n", gpsdframecount, gpxoutname);
		}
	if(gpsnmeaframecount == 1)
		{
		printf("%llu track point written to %s\n", gpsnmeaframecount, nmeaoutname);
		}
	else if(gpsnmeaframecount > 1)
		{
		printf("%llu track points written to %s\n", gpsnmeaframecount, nmeaoutname);
		}
	}

if(leapliste != NULL)
	{
	free(leapliste);
	}

if(leap2liste != NULL)
	{
	free(leap2liste);
	}

if(md5liste != NULL)
	{
	free(md5liste);
	}

if(tacacspliste != NULL)
	{
	free(tacacspliste);
	}

if(handshakeliste != NULL)
	{
	free(handshakeliste);
	}

if(eapolliste != NULL)
	{
	free(eapolliste);
	}

if(pmkidliste != NULL)
	{
	free(pmkidliste);
	}

if(apstaessidlistecleaned != NULL)
	{
	free(apstaessidlistecleaned);
	}

if(apstaessidliste != NULL)
	{
	free(apstaessidliste);
	}

return;
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
	"%s <options> [input.pcap] [input.pcap] ...\n"
	"%s <options> *.cap\n"
	"%s <options> *.*\n"
	"\n"
	"options:\n"
//	"-w <file> : output WPA1/2 EAPOL/PMKID hash file (hashcat)\n"
	"-o <file> : output hccapx file (hashcat -m 2500/2501)\n"
	"-O <file> : output raw hccapx file (hashcat -m 2500/2501)\n"
	"            this will disable all(!) 802.11 validity checks\n"
	"            very slow!\n"
	"-k <file> : output PMKID file (hashcat hashmode -m 16800 new format)\n"
	"-K <file> : output raw PMKID file (hashcat hashmode -m 16801 new format)\n"
	"            this will disable usage of ESSIDs completely\n"
	"-z <file> : output PMKID file (hashcat hashmode -m 16800 old format and john)\n"
	"-Z <file> : output raw PMKID file (hashcat hashmode -m 16801 old format and john)\n"
	"            this will disable usage of ESSIDs completely\n"
	"-j <file> : output john WPAPSK-PMK file (john wpapsk-opencl)\n"
	"-J <file> : output raw john WPAPSK-PMK file (john wpapsk-opencl)\n"
	"            this will disable all(!) 802.11 validity checks\n"
	"            very slow!\n"
	"-E <file> : output wordlist (autohex enabled) to use as input wordlist for cracker\n"
	"-I <file> : output unsorted identity list\n"
	"-U <file> : output unsorted username list\n"
	"-M <file> : output unsorted IMSI number list\n"
	"-P <file> : output possible WPA/WPA2 plainmasterkey list\n"
	"-T <file> : output management traffic information list\n"
	"            format = mac_sta:mac_ap:essid\n"
	"-X <file> : output client probelist\n"
	"            format: mac_sta:probed ESSID (autohex enabled)\n"
	"-D <file> : output unsorted device information list\n"
	"            format = mac_device:device information string\n"
	"-g <file> : output GPS file\n"
	"            format = GPX (accepted for example by Viking and GPSBabel)\n"
	"-V        : verbose (but slow) status output\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--filtermac=<mac>                 : filter output by MAC address\n"
	"                                    format: 112233445566\n"
	"--ignore-fake-frames              : do not convert fake frames\n"
	"--ignore-zeroed-pmks              : do not convert frames which use a zeroed plainmasterkey (PMK)\n"
	"--ignore-replaycount              : allow not replaycount checked best handshakes\n"
	"--ignore-mac                      : do not check MAC addresses\n"
	"                                    this will allow to use ESSIDs from frames with damaged broadcast MAC address\n"
	"--time-error-corrections=<digit>  : maximum time gap between EAPOL frames - EAPOL TIMEOUT (default: %llus)\n"
	"--nonce-error-corrections=<digit> : maximum replycount/nonce gap to be converted (default: %llu)\n"
	"                                    example: --nonce-error-corrections=60 \n"
	"                                    convert handshakes up to a possible packetloss of 59 packets\n"
	"                                    hashcat nonce-error-corrections should be twice as much as hcxpcaptool value\n"
	"--max-essid-changes=<digit>       : allow maximum ESSID changes (default: %d - no ESSID change is allowed)\n"
	"--eapol-out=<file>                : output EAPOL packets in hex\n"
	"                                    format = mac_ap:mac_sta:EAPOL\n"
	"--netntlm-out=<file>              : output netNTLMv1 file (hashcat -m 5500, john netntlm)\n"
	"--md5-out=<file>                  : output MD5 challenge file (hashcat -m 4800)\n"
	"--md5-john-out=<file>             : output MD5 challenge file (john chap)\n"
	"--tacacsplus-out=<file>           : output TACACS+ authentication file (hashcat -m 16100, john tacacs-plus)\n"
	"--network-out=<file>              : output network information\n"
	"                                    format = mac_ap:ESSID\n"
	"--hexdump-out=<file>              : output dump raw packets in hex\n"
	"--hccap-out=<file>                : output old hccap file (hashcat -m 2500)\n"
	"--hccap-raw-out=<file>            : output raw old hccap file (hashcat -m 2500)\n"
	"                                    this will disable all(!) 802.11 validity checks\n"
	"                                    very slow!\n"
	"--nmea=<file>                     : save track to file\n"
	"                                    format: NMEA 0183 $GPGGA, $GPRMC, $GPWPL\n"
	"                                    to convert it to gpx, use GPSBabel:\n"
	"                                    gpsbabel -i nmea -f hcxdumptool.nmea -o gpx -F file.gpx\n"
	"                                    to display the track, open file.gpx with viking\n"
	"--prefix-out=<file>               : convert everything to lists using this prefix (overrides single options):\n"
	"                                    hccapx (-o) file.hccapx\n"
	"                                    PMKID (-k) file.16800\n"
	"                                    netntlm (--netntlm-out) file.5500\n"
	"                                    md5 (--md5-out) file.4800\n"
	"                                    tacacsplus (--tacacsplus) file.16100\n"
	"                                    wordlist (-E) file.essidlist\n"
	"                                    identitylist (-I) file.identitylist \n"
	"                                    usernamelist (-U) file.userlist\n"
	"                                    imsilist (-M) file.imsilist\n"
	"                                    networklist (-network-out) file.networklist\n"
	"                                    trafficlist (-T) file.networklist\n"
	"                                    clientlist (-X) file.clientlist\n"
	"                                    deviceinfolist (-D) file.deviceinfolist\n"
	"--help                            : show this help\n"
	"--version                         : show version\n"
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
	"It is much better to run gzip to compress the files. Wireshark, tshark and hcxpcaptool will understand this.\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname, eigenname, maxtvdiff/1000000, maxrcdiff, maxessidchanges, eigenname);
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
int auswahl;
int index;

char *gpxhead = "<?xml version=\"1.0\"?>\n"
		"<gpx version=\"1.0\" creator=\"hcxpcaptool\"\n"
		"xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"\n"
		"xmlns=\"http://www.topografix.com/GPX/1/0\"\n"
		"xsi:schemaLocation=\"http://www.topografix.com/GPX/1/0 http://www.topografix.com/GPX/1/0/gpx.xsd\">\n";

char *gpxtail = "</gpx>\n";

char *suffixhccapx = ".hccapx";
char *suffixpmkid = ".16800";
char *suffixnetntlm1 = ".5500";
char *suffixmd5 = ".4800";
char *suffixtacacsp = ".16100";
char *suffixessid = ".essidlist";
char *suffixidentity = ".identitylist";
char *suffixuser = ".userlist";
char *suffiximsi = ".imsilist";
char *suffixnetwork = ".networklist";
char *suffixtraffic = ".trafficlist";
char *suffixstaessid = ".clientlist";
char *suffixdeviceinfo = ".deviceinfolist";

char prefixhccapxname[PATH_MAX];
char prefix16800name[PATH_MAX];
char prefixnetntlm1name[PATH_MAX];
char prefixmd5name[PATH_MAX];
char prefixtacacspname[PATH_MAX];
char prefixessidname[PATH_MAX];
char prefixidentityname[PATH_MAX];
char prefixusername[PATH_MAX];
char prefiximsiname[PATH_MAX];
char prefixnetworkname[PATH_MAX];
char prefixtrafficname[PATH_MAX];
char prefixstaessidname[PATH_MAX];
char prefixdeviceinfoname[PATH_MAX];

static const char *short_options = "w:o:O:k:K:z:Z:j:J:E:X:I:U:M:D:P:T:g:H:Vhv";
static const struct option long_options[] =
{
	{"nonce-error-corrections",	required_argument,	NULL,	HCXT_REPLAYCOUNTGAP},
	{"time-error-corrections",	required_argument,	NULL,	HCXT_TIMEGAP},
	{"max-essid-changess",		required_argument,	NULL,	HCXT_MAX_ESSID_CHANGES},
	{"netntlm-out",			required_argument,	NULL,	HCXT_NETNTLM_OUT},
	{"md5-out",			required_argument,	NULL,	HCXT_MD5_OUT},
	{"md5-john-out",		required_argument,	NULL,	HCXT_MD5_JOHN_OUT},
	{"tacacsplus-out",		required_argument,	NULL,	HCXT_TACACSP_OUT},
	{"eapol-out",			required_argument,	NULL,	HCXT_EAPOL_OUT},
	{"network-out",			required_argument,	NULL,	HCXT_NETWORK_OUT},
	{"hexdump-out",			required_argument,	NULL,	HCXT_HEXDUMP_OUT},
	{"hccap-out",			required_argument,	NULL,	HCXT_HCCAP_OUT},
	{"hccap-raw-out",		required_argument,	NULL,	HCXT_HCCAP_OUT_RAW},
	{"filtermac",			required_argument,	NULL,	HCXT_FILTER_MAC},
	{"ignore-fake-frames",		no_argument,		NULL,	HCXT_IGNORE_FAKE_FRAMES},
	{"ignore-zeroed-pmks",		no_argument,		NULL,	HCXT_IGNORE_ZEROED_PMKS},
	{"ignore-replaycount",		no_argument,		NULL,	HCXT_IGNORE_REPLAYCOUNT},
	{"ignore-mac",			no_argument,		NULL,	HCXT_IGNORE_MAC},
	{"nmea",			required_argument,	NULL,	HCXT_NMEA_NAME},
	{"prefix-out",			required_argument,	NULL,	HCXT_PREFIX_OUT},
	{"version",			no_argument,		NULL,	HCXT_VERSION},
	{"help",			no_argument,		NULL,	HCXT_HELP},
	{NULL,				0,			NULL,	0}
};

if(globalinit() == false)
	{
	printf("global  ‎initialization failed\n");
	exit(EXIT_FAILURE);
	}

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;

while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCXT_TIMEGAP:
		maxtvdiff = strtoull(optarg, NULL, 10);
		if(maxtvdiff < 1)
			{
			maxtvdiff = 1;
			}
		maxtvdiff *= 1000000;
		break;

		case HCXT_REPLAYCOUNTGAP:
		maxrcdiff = strtoull(optarg, NULL, 10);
		if(maxrcdiff < 1)
			{
			maxrcdiff = 1;
			}
		break;

		case HCXT_MAX_ESSID_CHANGES:
		maxessidchanges = strtoull(optarg, NULL, 10);
		if(maxessidchanges < 1)
			{
			maxessidchanges = 1;
			}
		break;

		case HCXT_NETNTLM_OUT:
		netntlm1outname = optarg;
		verboseflag = true;
		break;

		case HCXT_MD5_OUT:
		md5outname = optarg;
		verboseflag = true;
		break;

		case HCXT_MD5_JOHN_OUT:
		md5johnoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_TACACSP_OUT:
		tacacspoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_EAPOL_OUT:
		eapoloutname = optarg;
		verboseflag = true;
		break;

		case HCXT_NETWORK_OUT:
		networkoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HEXDUMP_OUT:
		hexmodeflag = true;
		hexmodeoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HCCAP_OUT:
		hccapbestoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HCCAP_OUT_RAW:
		hccaprawoutname = optarg;
		verboseflag = true;
		wantrawflag = true;
		break;

		case HCXT_WPA12_OUT:
		wpa12bestoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HCCAPX_OUT:
		hccapxbestoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HCCAPX_OUT_RAW:
		hccapxrawoutname = optarg;
		verboseflag = true;
		wantrawflag = true;
		break;

		case HCXT_HC_OUT_PMKID:
		hcpmkidoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HC_OUT_PMKID_RAW:
		hcpmkidrawoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HC_OUT_PMKID_OLD:
		hcpmkidoldoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HC_OUT_PMKID_RAW_OLD:
		hcpmkidrawoldoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_JOHN_OUT:
		johnbestoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_JOHN_OUT_RAW:
		johnrawoutname = optarg;
		verboseflag = true;
		wantrawflag = true;
		break;

		case HCXT_ESSID_OUT:
		essidoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_STAESSID_OUT:
		staessidoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_IDENTITY_OUT:
		identityoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_USERNAME_OUT:
		useroutname = optarg;
		verboseflag = true;
		break;

		case HCXT_IMSI_OUT:
		imsioutname = optarg;
		verboseflag = true;
		break;

		case HCXT_DEVICEINFO_OUT:
		deviceinfooutname = optarg;
		verboseflag = true;
		break;

		case HCXT_PMK_OUT:
		pmkoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_TRAFFIC_OUT:
		trafficoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_GPX_OUT:
		gpxoutname = optarg;
		gpxflag = true;
		verboseflag = true;
		break;

		case HCXT_NMEA_NAME:
		nmeaoutname = optarg;
		break;

		case HCXT_PREFIX_OUT:
		prefixoutname = optarg;
		if(strlen(prefixoutname) > (PATH_MAX -20))
			{
			printf("prefix filename is too long\n");
			exit(EXIT_FAILURE);
			}
		verboseflag = true;
		break;

		case HCXT_FILTER_MAC:
		if(strlen(optarg) != 12)
			{
			printf("wrong MAC format (112233445566)\n");
			exit(EXIT_FAILURE);
			}
		if(hex2bin(optarg, filtermac, 6) == false)
			{
			printf("wrong MAC format (112233445566)\n");
			exit(EXIT_FAILURE);
			}
		filtermacflag = true;
		verboseflag = true;
		break;

		case HCXT_IGNORE_FAKE_FRAMES:
		fakeframeflag = true;
		break;

		case HCXT_IGNORE_ZEROED_PMKS:
		zeroedpmkflag = true;
		break;

		case HCXT_IGNORE_REPLAYCOUNT:
		replaycountcheckflag = true;
		maxrcdiff = 2147483647;
		break;

		case HCXT_IGNORE_MAC:
		maccheckflag = true;
		break;

		case HCXT_VERBOSE_OUT:
		verboseflag = true;
		break;

		case HCXT_HELP:
		usage(basename(argv[0]));
		break;

		case HCXT_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

if(argc < 2)
	{
	printf("no option selected\n");
	return EXIT_SUCCESS;
	}

if(gpxflag == true) 
	{
	if((fhgpx = fopen(gpxoutname, "w+")) == NULL)
		{
		printf("error opening file %s: %s\n", gpxoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	fprintf(fhgpx, "%s", gpxhead);
	fprintf(fhgpx, "<name>%s</name>\n", basename(gpxoutname));
	}

fhnmea = NULL;
if(nmeaoutname != NULL) 
	{
	if((fhnmea = fopen(nmeaoutname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", nmeaoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(hexmodeflag == true) 
	{
	if((fhhexmode = fopen(hexmodeoutname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", hexmodeoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(prefixoutname != NULL)
	{
	strcpy(prefixhccapxname, prefixoutname);
	strncat(prefixhccapxname, suffixhccapx, PATH_MAX -20);
	hccapxbestoutname = prefixhccapxname;

	strcpy(prefix16800name, prefixoutname);
	strncat(prefix16800name, suffixpmkid, PATH_MAX -20);
	hcpmkidoutname = prefix16800name;

	strcpy(prefixnetntlm1name, prefixoutname);
	strncat(prefixnetntlm1name, suffixnetntlm1, PATH_MAX -20);
	netntlm1outname = prefixnetntlm1name;

	strcpy(prefixmd5name, prefixoutname);
	strncat(prefixmd5name, suffixmd5, PATH_MAX -20);
	md5outname = prefixmd5name;

	strcpy(prefixtacacspname, prefixoutname);
	strncat(prefixtacacspname, suffixtacacsp, PATH_MAX -20);
	tacacspoutname = prefixtacacspname;

	strcpy(prefixessidname, prefixoutname);
	strncat(prefixessidname, suffixessid, PATH_MAX -20);
	essidoutname = prefixessidname;

	strcpy(prefixidentityname, prefixoutname);
	strncat(prefixidentityname, suffixidentity, PATH_MAX -20);
	identityoutname = prefixidentityname;

	strcpy(prefixusername, prefixoutname);
	strncat(prefixusername, suffixuser, PATH_MAX -20);
	useroutname = prefixusername;

	strcpy(prefiximsiname, prefixoutname);
	strncat(prefiximsiname, suffiximsi, PATH_MAX -20);
	imsioutname = prefiximsiname;

	strcpy(prefixnetworkname, prefixoutname);
	strncat(prefixnetworkname, suffixnetwork, PATH_MAX -20);
	networkoutname = prefixnetworkname;

	strcpy(prefixtrafficname, prefixoutname);
	strncat(prefixtrafficname, suffixtraffic, PATH_MAX -20);
	trafficoutname = prefixtrafficname;

	strcpy(prefixstaessidname, prefixoutname);
	strncat(prefixstaessidname, suffixstaessid, PATH_MAX -20);
	staessidoutname = prefixstaessidname;

	strcpy(prefixdeviceinfoname, prefixoutname);
	strncat(prefixdeviceinfoname, suffixdeviceinfo, PATH_MAX -20);
	deviceinfooutname = prefixdeviceinfoname;
	}

if(eapoloutname != NULL)
	{
	if((fheapol = fopen(eapoloutname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", eapoloutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

if(networkoutname != NULL)
	{
	if((fhnetwork = fopen(networkoutname, "a+")) == NULL)
		{
		printf("error opening file %s: %s\n", networkoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

for(index = optind; index < argc; index++)
	{
	processcapfile(argv[index]);
	}

if(networkoutname != NULL)
	{
	fclose(fhnetwork);
	removeemptyfile(networkoutname);
	}

if(eapoloutname != NULL)
	{
	fclose(fheapol);
	removeemptyfile(eapoloutname);
	}

if(hexmodeflag == true)
	{
	fclose(fhhexmode);
	removeemptyfile(hexmodeoutname);
	}

if(gpxflag == true)
	{
	fprintf(fhgpx, "%s", gpxtail);
	fclose(fhgpx);
	}

if(fhnmea != NULL)
	{
	fclose(fhnmea);
	}

printf("\n");
return EXIT_SUCCESS;
}
/*===========================================================================*/

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
#ifdef __APPLE__
#define PATH_MAX 255
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#ifdef __linux__
#include <linux/limits.h>
#endif

#include "include/version.h"
#include "include/hcxpcaptool.h"
#include "include/ieee80211.c"
#include "include/strings.c"
#include "include/byteops.c"
#include "include/fileops.c"
#include "include/hashops.c"
#include "include/pcap.c"
#include "include/gzops.c"
#include "include/hashcatops.c"
#include "include/johnops.c"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

#define MAX_TV_DIFF 600000000llu

#define MAX_RC_DIFF 8

#define HCXT_REPLAYCOUNTGAP	1
#define HCXT_TIMEGAP		2
#define HCXT_NETNTLM_OUT	3
#define HCXT_MD5_OUT		4
#define HCXT_MD5_JOHN_OUT	5
#define HCXT_TACACSP_OUT	6

#define HCXT_HCCAPX_OUT		'o'
#define HCXT_HCCAPX_OUT_RAW	'O'
#define HCXT_HCCAP_OUT		'x'
#define HCXT_HCCAP_OUT_RAW	'X'
#define HCXT_JOHN_OUT		'j'
#define HCXT_JOHN_OUT_RAW	'J'
#define HCXT_ESSID_OUT		'E'
#define HCXT_TRAFFIC_OUT	'T'
#define HCXT_IDENTITY_OUT	'I'
#define HCXT_USERNAME_OUT	'U'
#define HCXT_PMK_OUT		'P'
#define HCXT_HEXDUMP_OUT	'H'
#define HCXT_VERBOSE_OUT	'V'

/*===========================================================================*/
/* global var */

bool hexmodeflag;
bool verboseflag;
bool fcsflag;
bool wantrawflag;

unsigned long long int maxtvdiff;
unsigned long long int maxrcdiff;

unsigned long long int apstaessidcount;
apstaessidl_t *apstaessidliste;

unsigned long long int eapolcount;
eapoll_t *eapolliste;

unsigned long long int handshakecount;
unsigned long long int handshakeaplesscount;
hcxl_t *handshakeliste;

unsigned long long int rawhandshakecount;
unsigned long long int rawhandshakeaplesscount;
hcxl_t *rawhandshakeliste;

unsigned long long int leapcount;
leapl_t *leapliste;

unsigned long long int leap2count;
leapl_t *leap2liste;

unsigned long long int md5count;
md5l_t *md5liste;

unsigned long long int tacacspcount;
tacacspl_t *tacacspliste;

unsigned long long int fcsframecount;
unsigned long long int wdsframecount;
unsigned long long int beaconframecount;
unsigned long long int proberequestframecount;
unsigned long long int proberesponseframecount;
unsigned long long int associationrequestframecount;
unsigned long long int associationresponseframecount;
unsigned long long int reassociationrequestframecount;
unsigned long long int reassociationresponseframecount;
unsigned long long int authenticationframecount;
unsigned long long int deauthenticationframecount;
unsigned long long int disassociationframecount;
unsigned long long int actionframecount;
unsigned long long int atimframecount;
unsigned long long int eapolframecount;
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
unsigned long long int dhcp6framecount;
unsigned long long int wepframecount;

char *hexmodeoutname;
char *hccapxbestoutname;
char *hccapxrawoutname;
char *hccapbestoutname;
char *hccaprawoutname;
char *johnbestoutname;
char *johnrawoutname;
char *essidoutname;
char *trafficoutname;
char *pmkoutname;
char *identityoutname;
char *useroutname;
char *netntlm1outname;
char *md5outname;
char *md5johnoutname;
char *tacacspoutname;

FILE *fhhexmode;

bool tscleanflag;
int endianess;
int pcapreaderrors;
unsigned long long int rawpacketcount;
unsigned long long int skippedpacketcount;
uint16_t versionmajor;
uint16_t versionminor;
uint16_t dltlinktype;

int exeaptype[256];
/*===========================================================================*/
/* global init */

bool globalinit()
{
hexmodeoutname = NULL;
hccapxbestoutname = NULL;
hccapxrawoutname = NULL;
hccapbestoutname = NULL;
hccaprawoutname = NULL;
johnbestoutname = NULL;
johnrawoutname = NULL;
essidoutname = NULL;
trafficoutname = NULL;
pmkoutname = NULL;
identityoutname = NULL;
useroutname = NULL;
netntlm1outname = NULL;
md5outname = NULL;
md5johnoutname = NULL;
tacacspoutname = NULL;

verboseflag = false;
hexmodeflag = false;
wantrawflag = false;

maxtvdiff = MAX_TV_DIFF;
maxrcdiff = MAX_RC_DIFF;

setbuf(stdout, NULL);
srand(time(NULL));
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
	case EAP_TYPE_LINK: return "EAP-Link Authetication";
	case EAP_TYPE_PAX: return "EAP-PAX Authetication";
	case EAP_TYPE_PSK: return "EAP-PSK Authetication";
	case EAP_TYPE_SAKE: return "EAP-SAKE Authetication";
	case EAP_TYPE_IKEV2: return "EAP-IKEv2 Authetication";
	case EAP_TYPE_AKA1: return "EAP-AKA Authetication";
	case EAP_TYPE_GPSK: return "EAP-GPSK Authetication";
	case EAP_TYPE_PWD: return "EAP-pwd Authetication";
	case EAP_TYPE_EKE1: return "EAP-EKE Version 1 Authetication";
	case EAP_TYPE_PTEAP: return "EAP Method Type for PT-EAP Authetication";
	case EAP_TYPE_TEAP: return "TEAP Authetication";
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
printf( "                                               \n"
	"summary:                                        \n--------\n"
	"file name..............: %s\n"
	"file type..............: %s %d.%d\n"
	"network type...........: %s (%d)\n"
	"endianess..............: %s\n"
	"read errors............: %s\n"
	"packets inside.........: %llu\n"
	"skipped packets........: %llu\n"
	"packets with FCS.......: %llu\n"
	, basename(pcapinname), pcaptype, version_major, version_minor, getdltstring(networktype), networktype, getendianessstring(endianess), geterrorstat(pcapreaderrors), rawpacketcount, skippedpacketcount, fcsframecount);

if(tscleanflag == true)
	{
	printf("warning................: zero value timestamps detected\n");
	}

if(wdsframecount != 0)
	{
	printf("WDS packets............: %llu\n", wdsframecount);
	}
if(beaconframecount != 0)
	{
	printf("beacons................: %llu\n", beaconframecount);
	}
if(proberequestframecount != 0)
	{
	printf("probe requests.........: %llu\n", proberequestframecount);
	}
if(proberesponseframecount != 0)
	{
	printf("probe responses........: %llu\n", proberesponseframecount);
	}
if(associationrequestframecount != 0)
	{
	printf("association requests...: %llu\n", associationrequestframecount);
	}
if(associationresponseframecount != 0)
	{
	printf("association responses..: %llu\n", associationresponseframecount);
	}
if(reassociationrequestframecount != 0)
	{
	printf("reassociation requests.: %llu\n", reassociationrequestframecount);
	}
if(reassociationresponseframecount != 0)
	{
	printf("reassociation responses: %llu\n", reassociationresponseframecount);
	}
if(authenticationframecount != 0)
	{
	printf("authentications........: %llu\n", authenticationframecount);
	}
if(deauthenticationframecount != 0)
	{
	printf("deauthentications......: %llu\n", deauthenticationframecount);
	}
if(disassociationframecount != 0)
	{
	printf("disassociations........: %llu\n", disassociationframecount);
	}
if(actionframecount != 0)
	{
	printf("action packets.........: %llu\n", actionframecount);
	}
if(atimframecount != 0)
	{
	printf("ATIM packets...........: %llu\n", atimframecount);
	}
if(eapolframecount != 0)
	{
	printf("EAPOL packets..........: %llu\n", eapolframecount);
	}
if(eapframecount != 0)
	{
	printf("EAP packets............: %llu\n", eapframecount);
	}
if(wepframecount != 0)
	{
	printf("WEP packets............: %llu\n", wepframecount);
	}
if(ipv4framecount != 0)
	{
	printf("IPv4 packets...........: %llu\n", ipv4framecount);
	}
if(ipv6framecount != 0)
	{
	printf("IPv6 packets...........: %lld\n", ipv6framecount);
	}
if(tcpframecount != 0)
	{
	printf("TCP packets............: %lld\n", tcpframecount);
	}
if(udpframecount != 0)
	{
	printf("UDP packets............: %lld\n", udpframecount);
	}
if(icmp4framecount != 0)
	{
	printf("ICMPv4 packets.........: %lld\n", icmp4framecount);
	}
if(icmp6framecount != 0)
	{
	printf("ICMPv6 packets.........: %lld\n", icmp6framecount);
	}
if(dhcpframecount != 0)
	{
	printf("DHCP packets...........: %lld\n", dhcpframecount);
	}
if(dhcp6framecount != 0)
	{
	printf("DHCPv6 packets.........: %lld\n", dhcp6framecount);
	}
if(greframecount != 0)
	{
	printf("GRE packets............: %lld\n", greframecount);
	}
for(p = 0; p < 256; p++)
	{
	if(exeaptype[p] != 0)
		{
		printf("found..................: %s\n", geteaptypestring(p));
		}
	}
if(eapolmkaframecount != 0)
	{
	printf("found..................: MKA Authentication (Macsec Key Agreement protocol)\n");
	}
if(chapframecount != 0)
	{
	printf("found..................: PPP-CHAP Authentication\n");
	}
if(papframecount != 0)
	{
	printf("found..................: PPP-PAP Authentication\n");
	}
if(tacacspframecount != 0)
	{
	printf("found..................: TACACS+ Authentication\n");
	}
if(radiusframecount != 0)
	{
	printf("found..................: RADIUS Authentication\n");
	}

if(rawhandshakecount != 0)
	{
	printf("raw handshakes.........: %llu (ap-less: %llu)\n", rawhandshakecount, rawhandshakeaplesscount);
	}
if(handshakecount != 0)
	{
	printf("best handshakes........: %llu (ap-less: %llu)\n", handshakecount, handshakeaplesscount);
	}
printf("\n");
return;
}
/*===========================================================================*/
void packethexdump(uint32_t tv_sec, uint32_t ts_usec, unsigned long long int packetnr, uint32_t networktype, uint32_t snaplen, uint32_t caplen, uint32_t len, uint8_t *packet)
{
int c;
uint32_t d;
time_t pkttime;
struct tm *pkttm;
char tmbuf[64], pcktimestr[64];

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
apstaessidl_t *zeiger, *zeigerold;

if(essidoutname != NULL)
	{
	if((fhoutlist = fopen(essidoutname, "a+")) != NULL)
		{
		zeiger = apstaessidliste;
		zeigerold = zeiger;
		qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_essid);
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
				fwritetimestamphigh(zeiger->tv_sec, fhoutlist);
				fprintf(fhoutlist, "%08x:", zeiger->tv_sec);
				fwriteaddr1addr2(zeiger->mac_sta, zeiger->mac_ap, fhoutlist);
				fwriteessidstr(zeiger->essidlen, zeiger->essid, fhoutlist); 
				}
			else if((memcmp(zeigerold->mac_ap, zeiger->mac_ap, 6) != 0) && (memcmp(zeigerold->mac_sta, zeiger->mac_sta, 6) != 0) && (memcmp(zeigerold, zeiger->essid, 32) != 0))
				{
				fwritetimestamphigh(zeiger->tv_sec, fhoutlist);
				fprintf(fhoutlist, "%08x:", zeiger->tv_sec);
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
void outputwpalists(char *pcapinname)
{
unsigned long long int c, d;
uint8_t essidok;
hcxl_t *zeiger;
apstaessidl_t *zeigeressid;
FILE *fhoutlist = NULL;
unsigned long long int writtencount, essidchangecount;

uint8_t essidold[32];

if((handshakeliste == NULL) || (apstaessidliste == NULL))
	{
	return;
	}

qsort(apstaessidliste, apstaessidcount, APSTAESSIDLIST_SIZE, sort_apstaessidlist_by_ap_essid);
essidchangecount = 0;
if(hccapxbestoutname != NULL)
	{
	if((fhoutlist = fopen(hccapxbestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidliste;
			essidchangecount = 0;
			memset(&essidold, 0,32);
			essidok = 0;
			for(d = 0; d < apstaessidcount; d++)
				{
				if((memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0) && (zeigeressid->status != 2))
					{
					if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
						{
						zeiger->essidlen = zeigeressid->essidlen;
						memset(zeiger->essid, 0, 32);
						memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
						writehccapxrecord(zeiger, fhoutlist);
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
				zeigeressid = apstaessidliste;
				for(d = 0; d < apstaessidcount; d++)
					{
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
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
		printf("%llu handshake(s) written to %s\n", writtencount, hccapxbestoutname);
		}
	}

if(hccapxrawoutname != NULL)
	{
	if((fhoutlist = fopen(hccapxrawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = rawhandshakeliste;
		for(c = 0; c < rawhandshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidliste;
			essidchangecount = 0;
			memset(&essidold, 0,32);
			for(d = 0; d < apstaessidcount; d++)
				{
				if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
					{
					if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
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
				if(memcmp(zeigeressid->mac_ap, zeiger->mac_ap, 6) > 0)
					{
					break;
					}
				zeigeressid++;
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

if(hccapbestoutname != NULL)
	{
	if((fhoutlist = fopen(hccapbestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidliste;
			essidchangecount = 0;
			memset(&essidold, 0,32);
			essidok = 0;
			for(d = 0; d < apstaessidcount; d++)
				{
				if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
					{
					if((memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0) && (zeigeressid->status != 2))
						{
						zeiger->essidlen = zeigeressid->essidlen;
						memset(zeiger->essid, 0, 32);
						memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
						writehccaprecord(maxrcdiff, zeiger, fhoutlist);
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
				zeigeressid = apstaessidliste;
				for(d = 0; d < apstaessidcount; d++)
					{
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							writehccaprecord(maxrcdiff, zeiger, fhoutlist);
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
		removeemptyfile(hccapbestoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu handshake(s) written to %s\n", writtencount, hccapbestoutname);
		}
	}

if(hccaprawoutname != NULL)
	{
	if((fhoutlist = fopen(hccaprawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = rawhandshakeliste;
		for(c = 0; c < rawhandshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidliste;
			essidchangecount = 0;
			memset(&essidold, 0,32);
			for(d = 0; d < apstaessidcount; d++)
				{
				if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
					{
					if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
						{
						zeiger->essidlen = zeigeressid->essidlen;
						memset(zeiger->essid, 0, 32);
						memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
						writehccaprecord(maxrcdiff, zeiger, fhoutlist);
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

if(johnbestoutname != NULL)
	{
	if((fhoutlist = fopen(johnbestoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = handshakeliste;
		for(c = 0; c < handshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidliste;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			essidok = 0;
			for(d = 0; d < apstaessidcount; d++)
				{
				if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
					{
					if((memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0) && (zeigeressid->status != 2))
						{
						zeiger->essidlen = zeigeressid->essidlen;
						memset(zeiger->essid, 0, 32);
						memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
						writejohnrecord(maxrcdiff, zeiger, fhoutlist, pcapinname);
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
				zeigeressid = apstaessidliste;
				for(d = 0; d < apstaessidcount; d++)
					{
					if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
						{
						if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
							{
							zeiger->essidlen = zeigeressid->essidlen;
							memset(zeiger->essid, 0, 32);
							memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
							writejohnrecord(maxrcdiff, zeiger, fhoutlist, pcapinname);
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
		removeemptyfile(johnbestoutname);
		if(essidchangecount > 1)
			{
			printf("%llu ESSID changes detected\n", essidchangecount);
			}
		printf("%llu handshake(s) written to %s\n", writtencount, johnbestoutname);
		}
	}

if(johnrawoutname != NULL)
	{
	if((fhoutlist = fopen(johnrawoutname, "a+")) != NULL)
		{
		writtencount = 0;
		zeiger = rawhandshakeliste;
		for(c = 0; c < rawhandshakecount; c++)
			{
			zeiger->tv_diff = zeiger->tv_ea;
			zeigeressid = apstaessidliste;
			memset(&essidold, 0,32);
			essidchangecount = 0;
			for(d = 0; d < apstaessidcount; d++)
				{
				if(memcmp(zeiger->mac_ap, zeigeressid->mac_ap, 6) == 0)
					{
					if(memcmp(&essidold, zeigeressid->essid, zeigeressid->essidlen) != 0)
						{
						zeiger->essidlen = zeigeressid->essidlen;
						memset(zeiger->essid, 0, 32);
						memcpy(zeiger->essid, zeigeressid->essid, zeigeressid->essidlen);
						writejohnrecord(maxrcdiff, zeiger, fhoutlist, pcapinname);
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

if(idlen <= 5)
	{
	return;
	}

if(packet[5] == 0)
	{
	return;
	}

if(identityoutname != NULL)
	{
	if((fhoutlist = fopen(identityoutname, "a+")) != NULL)
		{
		fwriteessidstr(idlen -5, (packet +5), fhoutlist);
		fclose(fhoutlist);
		}
	}
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
void addpppchapleap(uint8_t code, uint8_t id, uint8_t count, uint8_t *data, uint16_t usernamelen, uint8_t *username)
{
leapl_t *zeiger;
unsigned long long int c;

if(usernamelen > 255)
	{
	usernamelen = 255;
	}
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

if(usernamelen > 255)
	{
	usernamelen = 255;
	}
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
	if((zeigerea->replaycount == MYREPLAYCOUNT) && (zeigereo->replaycount == MYREPLAYCOUNT) && (memcmp(wpaeo->nonce, &mynonce, 32) == 0))
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
		if((zeigerea->replaycount == MYREPLAYCOUNT) && (zeigereo->replaycount == MYREPLAYCOUNT) && (memcmp(wpaeo->nonce, &mynonce, 32) == 0))
			{
			if((zeiger->replaycount_ap != MYREPLAYCOUNT) && (zeiger->replaycount_sta != MYREPLAYCOUNT) && (memcmp(zeiger->nonce, &mynonce, 32) == 0))
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
if((zeigerea->replaycount == MYREPLAYCOUNT) && (zeigereo->replaycount == MYREPLAYCOUNT) && (memcmp(wpaeo->nonce, &mynonce, 32) == 0))
	{
	zeiger->endianess = 0x10;
	rawhandshakeaplesscount++;
	}
rawhandshakecount++;
return;
}
/*===========================================================================*/
void addhandshake(uint64_t tv_ea, eapoll_t *zeigerea, uint64_t tv_eo, eapoll_t *zeigereo, uint64_t timegap, uint64_t rcgap)
{
hcxl_t *zeiger;
unsigned long long int c;
wpakey_t *wpae, *wpaea, *wpaeo;
uint32_t anonce, anonceold;

wpaea = (wpakey_t*)(zeigerea->eapol +EAPAUTH_SIZE);
wpaeo = (wpakey_t*)(zeigereo->eapol +EAPAUTH_SIZE);

if(handshakeliste == NULL)
	{
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
	if((zeigerea->replaycount == MYREPLAYCOUNT) && (zeigereo->replaycount == MYREPLAYCOUNT) && (memcmp(wpaeo->nonce, &mynonce, 32) == 0))
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
		if((zeigerea->replaycount == MYREPLAYCOUNT) && (zeigereo->replaycount == MYREPLAYCOUNT) && (memcmp(wpaeo->nonce, &mynonce, 32) == 0))
			{
			if((zeiger->replaycount_ap != MYREPLAYCOUNT) && (zeiger->replaycount_sta != MYREPLAYCOUNT) && (memcmp(zeiger->nonce, &mynonce, 32) == 0))
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
if((zeigerea->replaycount == MYREPLAYCOUNT) && (zeigereo->replaycount == MYREPLAYCOUNT) && (memcmp(wpaeo->nonce, &mynonce, 32) == 0))
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
	if(zeigerea->keyinfo >= 4)
		{
		lltimeea = zeigerea->tv_sec *1000000LL +zeigerea->tv_usec;
		for(d = 1; d <= c; d++)
			{
			zeigereo = zeigerea -d;
			lltimeeo = zeigereo->tv_sec *1000000LL +zeigereo->tv_usec;
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
			lltimeeo = zeigereo->tv_sec *1000000LL +zeigereo->tv_usec;
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
void addeapol(uint32_t tv_sec, uint32_t tv_usec, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t ki, uint64_t rc, uint32_t authlen, uint8_t *authpacket)
{
eapoll_t *zeiger;
wpakey_t *eaptest;

eaptest = (wpakey_t*)(authpacket +EAPAUTH_SIZE);

if(ntohs(eaptest->wpadatalen) > authlen)
	{
	return;
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
if(memcmp(eaptest->keyid, &nulliv, 8) != 0)
	{
	return;
	}
if((ki == 1) || (ki == 4))
	{
	if(memcmp(eaptest->keyiv, &nulliv, 16) != 0)
		{
		return;
		}
	if(eaptest->keyrsc != 0)
		{
		return;
		}
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
void addapstaessid(uint32_t tv_sec, uint32_t tv_usec, uint8_t status, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essidlen, uint8_t *essid)
{
apstaessidl_t *zeiger;
unsigned long long int c;
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
	apstaessidliste->status = status;
	memcpy(apstaessidliste->mac_ap, mac_ap, 6);
	memcpy(apstaessidliste->mac_sta, mac_sta, 6);
	memset(apstaessidliste->essid, 0, 32);
	memcpy(apstaessidliste->essid, essid, 32);
	apstaessidliste->essidlen = essidlen;
	apstaessidcount++;
	return;
	}
zeiger = apstaessidliste;
for(c = 0; c < apstaessidcount; c++)
	{
	if((essidlen == zeiger->essidlen) && (memcmp(mac_ap, zeiger->mac_ap, 6) == 0) && (memcmp(mac_sta, zeiger->mac_sta, 6) == 0) && (memcmp(essid, zeiger->essid, zeiger->essidlen) == 0))
		{
		zeiger->status |= status;
		return;
		}
	zeiger++;
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
zeiger->status = status;
memcpy(zeiger->mac_ap, mac_ap, 6);
memcpy(zeiger->mac_sta, mac_sta, 6);
memset(zeiger->essid, 0, 32);
memcpy(zeiger->essid, essid, 32);
zeiger->essidlen = essidlen;
apstaessidcount++;
return;
}
/*===========================================================================*/
uint16_t getessid(uint8_t *tagdata, int taglen, uint8_t *essidstr)
{
ietag_t *tagl;
tagl = (ietag_t*)tagdata;

while(0 < taglen)
	{
	if(tagl->id == TAG_SSID)
		{
		if((tagl->len == 0) || (tagl->len > 32))
			{
			return 0;
			}
		if(tagl->data[0] == 0)
			{
			return 0;
			}
		memcpy(essidstr, tagl->data, tagl->len);
		return tagl->len;
		}
	tagl = (ietag_t*)((uint8_t*)tagl +tagl->len +IETAG_SIZE);
	taglen -= tagl->len;
	}
return 0;
}
/*===========================================================================*/
void process80211wds()
{

wdsframecount++;
return;
}
/*===========================================================================*/
void process80211beacon(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
int essidlen;
uint8_t essidstr[32];

if(caplen < (uint32_t)MAC_SIZE_NORM +(uint32_t)CAPABILITIESAP_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +CAPABILITIESAP_SIZE;
memset(&essidstr, 0, 32);
essidlen = getessid(packet_ptr, caplen -MAC_SIZE_NORM -CAPABILITIESAP_SIZE, essidstr);
if(essidlen == 0)
	{
	return;
	}

addapstaessid(tv_sec, tv_usec, 1, macf->addr1, macf->addr2, essidlen, essidstr);
beaconframecount++;
return;
}
/*===========================================================================*/
void process80211probe_req(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
int essidlen;
uint8_t essidstr[32];

if(caplen < (uint32_t)MAC_SIZE_NORM +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM;
memset(&essidstr, 0, 32);
essidlen = getessid(packet_ptr, caplen -MAC_SIZE_NORM +2, essidstr);
if(essidlen == 0)
	{
	return;
	}
addapstaessid(tv_sec, tv_usec, 0x18, macf->addr2, macf->addr1, essidlen, essidstr);
proberequestframecount++;
return;
}
/*===========================================================================*/
void process80211probe_resp(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
int essidlen;
uint8_t essidstr[32];

if(caplen < (uint32_t)MAC_SIZE_NORM +(uint32_t)CAPABILITIESAP_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +CAPABILITIESAP_SIZE;
memset(&essidstr, 0, 32);
essidlen = getessid(packet_ptr, caplen -MAC_SIZE_NORM -CAPABILITIESAP_SIZE, essidstr);
if(essidlen == 0)
	{
	return;
	}
addapstaessid(tv_sec, tv_usec, 2, macf->addr1, macf->addr2, essidlen, essidstr);
proberesponseframecount++;
return;
}
/*===========================================================================*/
void process80211assoc_req(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
int essidlen;
uint8_t essidstr[32];

if(caplen < (uint32_t)MAC_SIZE_NORM +(uint32_t)CAPABILITIESSTA_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +CAPABILITIESSTA_SIZE;
memset(&essidstr, 0, 32);
essidlen = getessid(packet_ptr, caplen -MAC_SIZE_NORM -CAPABILITIESSTA_SIZE, essidstr);
if(essidlen == 0)
	{
	return;
	}
addapstaessid(tv_sec, tv_usec, 4, macf->addr2, macf->addr1, essidlen, essidstr);
associationrequestframecount++;
return;
}
/*===========================================================================*/
void process80211assoc_resp()
{

associationresponseframecount++;
return;
}
/*===========================================================================*/
void process80211reassoc_req(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
uint8_t *packet_ptr;
mac_t *macf;
int essidlen;
uint8_t essidstr[32];

if(caplen < (uint32_t)MAC_SIZE_NORM +(uint32_t)CAPABILITIESRESTA_SIZE +2)
	{
	return;
	}
macf = (mac_t*)packet;
packet_ptr = packet +MAC_SIZE_NORM +CAPABILITIESRESTA_SIZE;
memset(&essidstr, 0, 32);
essidlen = getessid(packet_ptr, caplen -MAC_SIZE_NORM -CAPABILITIESRESTA_SIZE, essidstr);
if(essidlen == 0)
	{
	return;
	}
addapstaessid(tv_sec, tv_usec, 8, macf->addr2, macf->addr1, essidlen, essidstr);
reassociationrequestframecount++;
return;
}
/*===========================================================================*/
void process80211reassoc_resp()
{

reassociationresponseframecount++;
return;
}
/*===========================================================================*/
void process80211authentication()
{


authenticationframecount++;
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
uint16_t authlen;

if(caplen < (uint32_t)WPAKEY_SIZE)
	{
	return;
	}
eap = (eapauth_t*)packet;
wpak = (wpakey_t*)(packet +EAPAUTH_SIZE);

keyinfo = (getkeyinfo(ntohs(wpak->keyinfo)));
#ifdef BIG_ENDIAN_HOST
wpak->replaycount = byte_swap_64(wpak->replaycount);
#endif

authlen = ntohs(eap->len);
if(authlen > caplen -4)
	{
	return;
	}
if(memcmp(&nullnonce, wpak->nonce, 32) == 0)
	{
	return;
	}

if(keyinfo == 1)
	{
	addeapol(tv_sec, tv_usec, macaddr1, macaddr2, 1, byte_swap_64(wpak->replaycount), authlen +4, packet);
	}
else if(keyinfo == 3)
	{
	addeapol(tv_sec, tv_usec, macaddr1, macaddr2, 2, byte_swap_64(wpak->replaycount), authlen +4, packet);
	}
else if(keyinfo == 2)
	{
	addeapol(tv_sec, tv_usec, macaddr2, macaddr1, 4, byte_swap_64(wpak->replaycount), authlen +4, packet);
	}
else if(keyinfo == 4)
	{
	addeapol(tv_sec, tv_usec, macaddr2, macaddr1, 8, byte_swap_64(wpak->replaycount), authlen +4, packet);
	}
else
	{
	return;
	}
eapolframecount++;
return;
}
/*===========================================================================*/
void processeapolmkaauthentication()
{


eapolmkaframecount++;
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

if(eaplen < 4)
	{
	return;
	}
leap = (eapleap_t*)packet;
leaplen = ntohs(leap->len);
if(eaplen < leaplen)
	{
	return;
	}
if(leap->version != 1)
	{
	return;
	}
if((leap->code == EAP_CODE_REQ) || (leap->code == EAP_CODE_RESP))
	{
	addeapleap(leap->code, leap->id, leap->count, leap->data, leaplen -8 -leap->count, packet +8 +leap->count);
	if(leaplen -8 -leap->count != 0)
		{
		outlistusername(leaplen -8 -leap->count, packet +8 +leap->count);
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
exeap = (exteap_t*)(packet +EAPAUTH_SIZE);
if(exeap->exttype == EAP_TYPE_ID)
	{
	if(eaplen != 0)
		{
		outlistidentity(eaplen, packet +EAPAUTH_SIZE);
		}
	}
else if(exeap->exttype == EAP_TYPE_LEAP)
	{
	processeapleapauthentication(eaplen, packet +EAPAUTH_SIZE);
	}

else if(exeap->exttype == EAP_TYPE_MD5)
	{
	processeapmd5authentication(eaplen, packet +EAPAUTH_SIZE);
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
if(eap->type == 3)
	{
	process80211eapolauthentication(tv_sec, tv_usec, caplen, macaddr1, macaddr2, packet);
	}
else if(eap->type == 0)
	{
	 processexeapauthentication(ntohs(eap->len), packet);
	}

else if(eap->type == 5)
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
void processudppacket(uint32_t caplen, uint8_t *packet)
{
udp_t *udp;
uint16_t udplen; 

if(caplen < (uint32_t)UDP_SIZE)
	{
	return;
	}
udp = (udp_t*)packet;
udplen = ntohs(udp->len);
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
uint8_t authlen;

if(caplen < (uint32_t)CHAP_SIZE)
	{
	return;
	}
chap = (chap_t*)packet;
chaplen = ntohs(chap->len);
authlen = chap->data[0];
if(caplen < chaplen)
	{
	return;
	}
if((chap->code == CHAP_CODE_REQ) || (chap->code == CHAP_CODE_RESP))
	{
	if((chaplen -authlen -CHAP_SIZE) < caplen)
		{
		addpppchapleap(chap->code, chap->id, authlen, chap->data +1, chaplen -authlen -CHAP_SIZE, packet +authlen +CHAP_SIZE);
		if(chaplen -authlen -CHAP_SIZE != 0)
			{
			outlistusername(chaplen -authlen -CHAP_SIZE, packet +authlen +CHAP_SIZE);
			}
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
	processudppacket(ntohs(ipv4->len) -ipv4len, packet_ptr);
	}
else if(ipv4->nextprotocol == NEXTHDR_GRE)
	{
	processgrepacket(ntohs(ipv4->len) -ipv4len, packet_ptr);
	}



/* satisfy gcc warning */
tv_sec += 1;
tv_usec += 1;
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
	processudppacket(ntohs(ipv6->len), packet_ptr);
	}
else if(ipv6->nextprotocol == NEXTHDR_GRE)
	{
	processgrepacket(ntohs(ipv6->len), packet_ptr);
	}



/* satisfy gcc warning */
tv_sec += 1;
tv_usec += 1;
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
void process80211datapacket(uint32_t tv_sec, uint32_t tv_usec, uint32_t caplen, uint8_t *packet)
{
mac_t *macf;
llc_t *llc;
mpdu_t *mpdu;

uint8_t *packet_ptr;
macf = (mac_t*)packet;
packet_ptr = packet;
if((macf->subtype == IEEE80211_STYPE_DATA) || (macf->subtype == IEEE80211_STYPE_DATA_CFACK) || (macf->subtype == IEEE80211_STYPE_DATA_CFPOLL) || (macf->subtype == IEEE80211_STYPE_DATA_CFACKPOLL))
	{
	if(caplen < (uint32_t)MAC_SIZE_NORM +(uint32_t)LLC_SIZE)
		{
		return;
		}
	llc = (llc_t*)(packet+MAC_SIZE_NORM);
	packet_ptr += MAC_SIZE_NORM +LLC_SIZE;
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211networkauthentication(tv_sec, tv_usec, caplen -MAC_SIZE_NORM -LLC_SIZE, macf->addr1, macf->addr2, packet_ptr);
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv4packet(tv_sec, tv_usec, caplen -MAC_SIZE_NORM -LLC_SIZE, packet_ptr);
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv6packet(tv_sec, tv_usec, caplen -MAC_SIZE_NORM -LLC_SIZE, packet_ptr);
		}
	else if(macf->protected == 1)
		{
		mpdu = (mpdu_t*)(packet +MAC_SIZE_NORM);
		if(((mpdu->keyid >> 5) &1) == 0)
			{
			processweppacket();
			}
		}
	}
else if((macf->subtype == IEEE80211_STYPE_QOS_DATA) || (macf->subtype == IEEE80211_STYPE_QOS_DATA_CFACK) || (macf->subtype == IEEE80211_STYPE_QOS_DATA_CFPOLL) || (macf->subtype == IEEE80211_STYPE_QOS_DATA_CFACKPOLL))
	{
	if(caplen < (uint32_t)MAC_SIZE_QOS +(uint32_t)LLC_SIZE)
		{
		return;
		}
	llc = (llc_t*)(packet +MAC_SIZE_QOS);
	packet_ptr += MAC_SIZE_QOS +LLC_SIZE;
	if(((ntohs(llc->type)) == LLC_TYPE_AUTH) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		process80211networkauthentication(tv_sec, tv_usec, caplen -MAC_SIZE_QOS -LLC_SIZE, macf->addr1, macf->addr2, packet_ptr);
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV4) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv4packet(tv_sec, tv_usec, caplen -MAC_SIZE_QOS -LLC_SIZE, packet_ptr);
		}
	else if(((ntohs(llc->type)) == LLC_TYPE_IPV6) && (llc->dsap == LLC_SNAP) && (llc->ssap == LLC_SNAP))
		{
		processipv6packet(tv_sec, tv_usec, caplen -MAC_SIZE_QOS -LLC_SIZE, packet_ptr);
		}
	else if(macf->protected == 1)
		{
		mpdu = (mpdu_t*)(packet +MAC_SIZE_QOS);
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
mac_t *macf;

macf = (mac_t*)packet;
if((macf->from_ds == 1) && (macf->to_ds == 1))
	{
	process80211wds();
	}

else if(macf->type == IEEE80211_FTYPE_MGMT)
	{
	if(macf->subtype == IEEE80211_STYPE_BEACON)
		{
		process80211beacon(tv_sec, tv_usec, caplen, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_PROBE_REQ)
		{
		process80211probe_req(tv_sec, tv_usec, caplen, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_PROBE_RESP)
		{
		process80211probe_resp(tv_sec, tv_usec, caplen, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_ASSOC_REQ)
		{
		process80211assoc_req(tv_sec, tv_usec, caplen, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_ASSOC_RESP)
		{
		process80211assoc_resp();
		}
	else if (macf->subtype == IEEE80211_STYPE_REASSOC_REQ)
		{
		process80211reassoc_req(tv_sec, tv_usec, caplen, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_REASSOC_RESP)
		{
		process80211reassoc_resp(tv_sec, tv_usec, caplen, packet);
		}
	else if (macf->subtype == IEEE80211_STYPE_AUTH)
		{
		process80211authentication();
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
	process80211datapacket(tv_sec, tv_usec, caplen, packet);
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
packet_ptr = packet;
if(ntohl(loba->family == AF_INET))
	{
	packet_ptr += LOBA_SIZE;
	caplen -= LOBA_SIZE;
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
ppi_t *ppi;
uint32_t crc;
struct timeval tvtmp;

packet_ptr = packet;
if(caplen < MAC_SIZE_NORM)
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
		printf("failed to read ethernet header\n");
		return;
		}
	packet_ptr += ETH2_SIZE;
	caplen -= ETH2_SIZE;
	processethernetpacket(tv_sec, tv_usec, caplen, packet);
	return;
	}

else if(linktype == DLT_IEEE802_11_RADIO)
	{
	if(caplen < (uint32_t)RTH_SIZE)
		{
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
		printf("failed to read prism header\n");
		return;
		}
	prism = (prism_t*)packet;
	#ifdef BIG_ENDIAN_HOST
	prism->msgcode	= byte_swap_32(prism->msgcode);
	prism->msglen	= byte_swap_32(prism->msglen);
	#endif
	if(prism->msglen > caplen)
		{
		printf("failed to read prism header\n");
		return;
		}
	packet_ptr += prism->msglen;
	caplen -= prism->msglen;
	}
else if(linktype == DLT_PPI)
	{
	if(caplen < (uint32_t)PPI_SIZE)
		{
		printf("failed to read ppi header\n");
		return;
		}
	ppi = (ppi_t*)packet;
	#ifdef BIG_ENDIAN_HOST
	ppi->pph_len	= byte_swap_16(ppi->pph_len);
	#endif
	if(ppi->pph_len > caplen)
		{
		printf("failed to read ppi header\n");
		return;
		}
	packet_ptr += ppi->pph_len;
	caplen -= ppi->pph_len;
	}
else
	{
	return;
	}

if(caplen < 4)
	{
	printf("failed to read packet\n");
	return;
	}
fcs = (fcs_t*)(packet_ptr +caplen -4);
#ifdef BIG_ENDIAN_HOST
fcs->fcs	= byte_swap_32(fcs->fcs);
#endif
crc = fcscrc32check(packet_ptr, caplen -4);
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
void processpcapng(int fd, char *pcapinname)
{
unsigned int res;

block_header_t pcapngbh;
section_header_block_t pcapngshb;
interface_description_block_t pcapngidb;
packet_block_t pcapngpb;
enhanced_packet_block_t pcapngepb;
uint8_t packet[MAXPACPSNAPLEN];

printf("start reading from %s\n", pcapinname);
memset(&packet, 0, MAXPACPSNAPLEN);
while(1)
	{
	res = read(fd, &pcapngbh, BH_SIZE);
	if(res == 0)
		{
		break;
		}
	if(res != BH_SIZE)
		{
		pcapreaderrors = 1;
		printf("failed to read pcapng header block\n");
		break;
		}
	if(pcapngbh.block_type == PCAPNGBLOCKTYPE)
		{
		res = read(fd, &pcapngshb, SHB_SIZE);
		if(res != SHB_SIZE)
			{
			pcapreaderrors = 1;
			printf("failed to read pcapng section header block\n");
			break;
			}
		#ifdef BIG_ENDIAN_HOST
		pcapngbh.total_length = byte_swap_32(pcapngbh.total_length);
		pcapngshb.byte_order_magic	= byte_swap_32(pcapngshb.byte_order_magic);
		pcapngshb.major_version		= byte_swap_16(pcapngshb.major_version);
		pcapngshb.minor_version		= byte_swap_16(pcapngshb.minor_version);
		pcapngshb.section_length	= byte_swap_64(pcapngshb.section_length);
		#endif
		if(pcapngshb.byte_order_magic == PCAPNGMAGICNUMBERBE)
			{
			endianess = 1;
			pcapngbh.total_length = byte_swap_32(pcapngbh.total_length);
			pcapngshb.byte_order_magic	= byte_swap_32(pcapngshb.byte_order_magic);
			pcapngshb.major_version		= byte_swap_16(pcapngshb.major_version);
			pcapngshb.minor_version		= byte_swap_16(pcapngshb.minor_version);
			pcapngshb.section_length	= byte_swap_64(pcapngshb.section_length);
			}
		lseek(fd, pcapngbh.total_length -BH_SIZE -SHB_SIZE, SEEK_CUR);
		continue;
		}
	#ifdef BIG_ENDIAN_HOST
	pcapngbh.block_type = byte_swap_32(pcapngbh.block_type);
	pcapngbh.total_length = byte_swap_32(pcapngbh.total_length);
	#endif
	if(endianess == 1)
		{
		pcapngbh.block_type = byte_swap_32(pcapngbh.block_type);
		pcapngbh.total_length = byte_swap_32(pcapngbh.total_length);
		}

	if(pcapngbh.block_type == 1)
		{
		res = read(fd, &pcapngidb, IDB_SIZE);
		if(res != IDB_SIZE)
			{
			pcapreaderrors = 1;
			printf("failed to get pcapng interface description block\n");
			break;
			}
		#ifdef BIG_ENDIAN_HOST
		pcapngidb.linktype	= byte_swap_16(pcapngidb.linktype);
		pcapngidb.snaplen	= byte_swap_32(pcapngidb.snaplen);
		#endif
		if(endianess == 1)
			{
			pcapngidb.linktype	= byte_swap_16(pcapngidb.linktype);
			pcapngidb.snaplen	= byte_swap_32(pcapngidb.snaplen);
			}
		if(pcapngidb.snaplen > MAXPACPSNAPLEN)
			{
			printf("detected oversized snaplen (%d) \n", pcapngidb.snaplen);
			pcapreaderrors = 1;
			}
		lseek(fd, pcapngbh.total_length -BH_SIZE -IDB_SIZE, SEEK_CUR);
		}

	else if(pcapngbh.block_type == 2)
		{
		res = read(fd, &pcapngpb, PB_SIZE);
		if(res != PB_SIZE)
			{
			pcapreaderrors = 1;
			printf("failed to get pcapng packet block (obsolete)\n");
			break;
			}
		#ifdef BIG_ENDIAN_HOST
		pcapngpb.interface_id	= byte_swap_16(pcapngpb.interface_id);
		pcapngpb.drops_count	= byte_swap_16(pcapngpb.drops_count);
		pcapngpb.timestamp_high	= byte_swap_32(pcapngpb.timestamp_high);
		pcapngpb.timestamp_low	= byte_swap_32(pcapngpb.timestamp_low);
		pcapngpb.caplen		= byte_swap_32(pcapngpb.caplen);
		pcapngpb.len		= byte_swap_32(pcapngpb.len);
		#endif
		if(endianess == 1)
			{
			pcapngpb.interface_id	= byte_swap_16(pcapngpb.interface_id);
			pcapngpb.drops_count	= byte_swap_16(pcapngpb.drops_count);
			pcapngpb.timestamp_high	= byte_swap_32(pcapngpb.timestamp_high);
			pcapngpb.timestamp_low	= byte_swap_32(pcapngpb.timestamp_low);
			pcapngpb.caplen		= byte_swap_32(pcapngpb.caplen);
			pcapngpb.len		= byte_swap_32(pcapngpb.len);
			}

		if((pcapngepb.timestamp_high == 0) && (pcapngepb.timestamp_low == 0))
			{
			tscleanflag = true;
			}

		if(pcapngpb.caplen < MAXPACPSNAPLEN)
			{
			res = read(fd, &packet, pcapngpb.caplen);
			if(res != pcapngpb.caplen)
				{
				printf("failed to read packet %lld\n", rawpacketcount);
				pcapreaderrors = 1;
				break;
				}
			lseek(fd, pcapngbh.total_length -BH_SIZE -PB_SIZE -pcapngepb.caplen, SEEK_CUR);
			rawpacketcount++;
			}
		else
			{
			lseek(fd, pcapngbh.total_length -BH_SIZE -PB_SIZE +pcapngpb.caplen, SEEK_CUR);
			pcapngpb.caplen = 0;
			pcapngpb.len = 0;
			skippedpacketcount++;
			}

		res = read(fd, &packet, pcapngpb.caplen);
		if(res != pcapngpb.caplen)
			{
			printf("failed to read packet %lld\n", rawpacketcount);
			pcapreaderrors = 1;
			break;
			}

		rawpacketcount++;
		lseek(fd, pcapngbh.total_length -BH_SIZE -PB_SIZE -pcapngpb.caplen, SEEK_CUR);
		}

	else if(pcapngbh.block_type == 3)
		{
		lseek(fd, pcapngbh.total_length -BH_SIZE, SEEK_CUR);
		}

	else if(pcapngbh.block_type == 4)
		{
		lseek(fd, pcapngbh.total_length -BH_SIZE, SEEK_CUR);
		}

	else if(pcapngbh.block_type == 5)
		{
		lseek(fd, pcapngbh.total_length -BH_SIZE, SEEK_CUR);
		}

	else if(pcapngbh.block_type == 6)
		{
		res = read(fd, &pcapngepb, EPB_SIZE);
		if(res != EPB_SIZE)
			{
			pcapreaderrors = 1;
			printf("failed to get pcapng enhanced packet block\n");
			break;
			}
		#ifdef BIG_ENDIAN_HOST
		pcapngepb.interface_id		= byte_swap_32(pcapngepb.interface_id);
		pcapngepb.timestamp_high	= byte_swap_32(pcapngepb.timestamp_high);
		pcapngepb.timestamp_low		= byte_swap_32(pcapngepb.timestamp_low);
		pcapngepb.caplen		= byte_swap_32(pcapngepb.caplen);
		pcapngepb.len			= byte_swap_32(pcapngepb.len);
		#endif
		if(endianess == 1)
			{
			pcapngepb.interface_id		= byte_swap_32(pcapngepb.interface_id);
			pcapngepb.timestamp_high	= byte_swap_32(pcapngepb.timestamp_high);
			pcapngepb.timestamp_low		= byte_swap_32(pcapngepb.timestamp_low);
			pcapngepb.caplen		= byte_swap_32(pcapngepb.caplen);
			pcapngepb.len			= byte_swap_32(pcapngepb.len);
			}

		if(pcapngepb.caplen < MAXPACPSNAPLEN)
			{
			res = read(fd, &packet, pcapngepb.caplen);
			if(res != pcapngepb.caplen)
				{
				printf("failed to read packet %lld\n", rawpacketcount);
				pcapreaderrors = 1;
				break;
				}
			lseek(fd, pcapngbh.total_length -BH_SIZE -EPB_SIZE -pcapngepb.caplen, SEEK_CUR);
			rawpacketcount++;
			}
		else
			{
			lseek(fd, pcapngbh.total_length -BH_SIZE -EPB_SIZE +pcapngepb.caplen, SEEK_CUR);
			pcapngepb.caplen = 0;
			pcapngepb.len = 0;
			skippedpacketcount++;
			}
		}
	else
		{
		lseek(fd, pcapngbh.total_length -BH_SIZE, SEEK_CUR);
		}
	if(pcapngepb.caplen > 0)
		{
		if(hexmodeflag == true)
			{
			packethexdump(pcapngepb.timestamp_high, pcapngepb.timestamp_low, rawpacketcount, pcapngidb.linktype, pcapngidb.snaplen, pcapngepb.caplen, pcapngepb.len, packet);
			}
		if(verboseflag == true)
			{
			processpacket(pcapngepb.timestamp_high, pcapngepb.timestamp_low, pcapngidb.linktype, pcapngepb.caplen, packet);
			}
		if((rawpacketcount %100000) == 0)
			{
			printf("%lld packets processed - be patient!\r", rawpacketcount);
			}
		}
	}
versionmajor = pcapngshb.major_version;
versionminor = pcapngshb.minor_version;
dltlinktype = pcapngidb.linktype;
return;
}
/*===========================================================================*/
void processpcap(int fd, char *pcapinname)
{
unsigned int res;

pcap_hdr_t pcapfhdr;
pcaprec_hdr_t pcaprhdr;
uint8_t packet[MAXPACPSNAPLEN];

printf("start reading from %s\n", pcapinname);
memset(&packet, 0, MAXPACPSNAPLEN);
res = read(fd, &pcapfhdr, PCAPHDR_SIZE);
if(res != PCAPHDR_SIZE)
	{
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
	endianess = 1;
	pcapfhdr.version_major	= byte_swap_16(pcapfhdr.version_major);
	pcapfhdr.version_minor	= byte_swap_16(pcapfhdr.version_minor);
	pcapfhdr.thiszone	= byte_swap_32(pcapfhdr.thiszone);
	pcapfhdr.sigfigs	= byte_swap_32(pcapfhdr.sigfigs);
	pcapfhdr.snaplen	= byte_swap_32(pcapfhdr.snaplen);
	pcapfhdr.network	= byte_swap_32(pcapfhdr.network);
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
		pcapreaderrors = 1;
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

	if(pcaprhdr.incl_len < MAXPACPSNAPLEN)
		{
		res = read(fd, &packet, pcaprhdr.incl_len);
		if(res != pcaprhdr.incl_len)
			{
			printf("failed to read packet %lld\n", rawpacketcount);
			pcapreaderrors = 1;
			break;
			}
		rawpacketcount++;
		}
	else
		{
		lseek(fd, pcaprhdr.incl_len, SEEK_CUR);
		pcaprhdr.incl_len = 0;
		pcaprhdr.orig_len = 0;
		skippedpacketcount++;
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
		if((rawpacketcount %100000) == 0)
			{
			printf("%lld packets processed - be patient!\r", rawpacketcount);
			}
		}
	}
versionmajor = pcapfhdr.version_major;
versionminor = pcapfhdr.version_minor;
dltlinktype  = pcapfhdr.network;
return;
}
/*===========================================================================*/
void processcapfile(char *pcapinname)
{
int pcapr_fd;
uint32_t magicnumber;
bool needrmflag = false;
char *pcapart;

fcsflag = false;
apstaessidliste = NULL;
eapolliste = NULL;
handshakeliste = NULL;
leapliste = NULL;
leap2liste = NULL;
md5liste = NULL;
tacacspliste = NULL;

char *pcapstr = "pcap";
char *pcapngstr = "pcapng";

versionmajor = 0;
versionminor = 0;
dltlinktype  = 0;
tscleanflag = false;
endianess = 0;
pcapreaderrors = 0;
rawpacketcount = 0;
skippedpacketcount = 0;
apstaessidcount = 0;
eapolcount = 0;
fcsframecount = 0;
wdsframecount = 0;
beaconframecount = 0;
proberequestframecount = 0;
proberesponseframecount = 0;
associationrequestframecount = 0;
associationresponseframecount = 0;
reassociationrequestframecount = 0;
reassociationresponseframecount = 0;
authenticationframecount = 0;
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
wepframecount = 0;

char tmpoutname[PATH_MAX+1];

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
	return;
	}

magicnumber = getmagicnumber(pcapr_fd);
if((magicnumber != PCAPMAGICNUMBER) && (magicnumber != PCAPMAGICNUMBERBE) && (magicnumber != PCAPNGBLOCKTYPE))
	{
	printf("failed to get magicnumber from %s\n", basename(pcapinname));
	close(pcapr_fd);
	if(needrmflag == true)
		{
		remove(tmpoutname);
		}
	return;
	}
lseek(pcapr_fd, 0L, SEEK_SET);


pcapart = pcapstr;
if((magicnumber == PCAPMAGICNUMBER) || (magicnumber == PCAPMAGICNUMBERBE))
	{
	processpcap(pcapr_fd, pcapinname);
	pcapart = pcapstr;
	}

else if(magicnumber == PCAPNGBLOCKTYPE)
	{
	processpcapng(pcapr_fd, pcapinname);
	pcapart = pcapngstr;
	}

close(pcapr_fd);
if(needrmflag == true)
	{
	remove(tmpoutname);
	}

if((apstaessidliste != NULL) && (eapolliste != NULL))
	{
	findhandshake();
	}

printcapstatus(pcapart, pcapinname, versionmajor, versionminor, dltlinktype, endianess, rawpacketcount, skippedpacketcount, pcapreaderrors, tscleanflag);

if(apstaessidliste != NULL) 
	{
	outputessidlists();
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
	"-o <file> : output hccapx file (hashcat -m 2500/2501)\n"
	"-O <file> : output raw hccapx file (hashcat -m 2500/2501)\n"
	"-x <file> : output hccap file (hashcat -m 2500)\n"
	"-X <file> : output raw hccap file (hashcat -m 2500)\n"
	"-j <file> : output john WPAPSK-PMK file (john wpapsk-opencl)\n"
	"-J <file> : output raw john WPAPSK-PMK file (john wpapsk-opencl)\n"
	"-E <file> : output wordlist (autohex enabled) to use as input wordlist for cracker\n"
	"-I <file> : output unsorted identity list\n"
	"-U <file> : output unsorted username list\n"
	"-P <file> : output possible WPA/WPA2 plainmasterkey list\n"
	"-T <file> : output management traffic information list\n"
	"          : european date : timestamp : mac_sta : mac_ap : essid\n"
	"-H <file> : output dump raw packets in hex\n"
	"-V        : verbose (but slow) status output\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--time-error-corrections=<digit>  : maximum allowed time gap (default: %llus)\n"
	"--nonce-error-corrections=<digit> : maximum allowed nonce gap (default: %llu)\n"
	"                                  : should be the same value as in hashcat\n"
	"--netntlm-out=<file>              : output netNTLMv1 file (hashcat -m 5500, john netntlm)\n"
	"--md5-out=<file>                  : output MD5 challenge file (hashcat -m 4800)\n"
	"--md5-john-out=<file>             : output MD5 challenge file (john chap)\n"
	"--tacacsplus-out=<file>           : output TACACS+ authentication file (hashcat -m 16100, john tacacs-plus)\n"
	"\n"
	"bitmask for message:\n"
	"0001 M1\n"
	"0010 M2\n"
	"0100 M3\n"
	"1000 M4\n"
	"\n"
	"Do not use %s in combination with third party cap/pcap/pcapng cleaning tools!\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname, eigenname, maxtvdiff/1000000, maxrcdiff, eigenname);
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

static const char *short_options = "o:O:x:X:j:J:E:I:U:P:T:H:Vhv";
static const struct option long_options[] =
{
	{"nonce-error-corrections",	required_argument,	NULL,	HCXT_REPLAYCOUNTGAP},
	{"time-error-corrections",	required_argument,	NULL,	HCXT_TIMEGAP},
	{"netntlm-out",			required_argument,	NULL,	HCXT_NETNTLM_OUT},
	{"md5-out",			required_argument,	NULL,	HCXT_MD5_OUT},
	{"md5-john-out",		required_argument,	NULL,	HCXT_MD5_JOHN_OUT},
	{"tacacsplus-out",		required_argument,	NULL,	HCXT_TACACSP_OUT},
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

		case '?':
		printf("invalid argument specified\n");
		exit(EXIT_FAILURE);
		break;
		}
	}

optind = 1;
optopt = 0;
index = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCXT_HCCAPX_OUT:
		hccapxbestoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_HCCAPX_OUT_RAW:
		hccapxrawoutname = optarg;
		verboseflag = true;
		wantrawflag = true;
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

		case HCXT_IDENTITY_OUT:
		identityoutname = optarg;
		verboseflag = true;
		break;

		case HCXT_USERNAME_OUT:
		useroutname = optarg;
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

		case HCXT_HEXDUMP_OUT:
		hexmodeflag = true;
		hexmodeoutname = optarg;
		break;

		case HCXT_VERBOSE_OUT:
		verboseflag = true;
		break;

		case 'h':
		usage(basename(argv[0]));
		break;

		case 'v':
		version(basename(argv[0]));
		break;

		case '?':
		printf("invalid argument specified\n");
		exit(EXIT_FAILURE);
		break;
		}
	}


if(hexmodeflag == true) 
	{
	if((fhhexmode = fopen(hexmodeoutname, "a+")) == NULL)
		{
		fprintf(stderr, "error opening file %s: %s\n", hexmodeoutname, strerror(errno));
		exit(EXIT_FAILURE);
		}
	}

for(index = optind; index < argc; index++)
	{
	processcapfile(argv[index]);
	}

if(hexmodeflag == true)
	{
	fclose(fhhexmode);
	}
removeemptyfile(hexmodeoutname);

return EXIT_SUCCESS;
}
/*===========================================================================*/

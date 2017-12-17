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
#ifdef __APPLE__
#define strdupa strdup
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif

#include "include/version.h"
#include "common.h"


#define MAGIC_PCAP		0xa1b2c3d4
#define MAGIC_PCAP_SWAPPED	0xd4c3b2a1
#define MAGIC_PCAP_NS		0xa1b23c4d
#define MAGIC_PCAP_NS_SWAPPED	0x4d3cb2a1
#define MAGIC_PCAP_NG		0x0a0d0d0a


/*===========================================================================*/
static bool getpcapinfo(char *pcapinname)
{
//struct stat statinfo;
pcap_t *pcapin = NULL;
struct pcap_pkthdr *pkh;

FILE *fhc;
int magicsize = 0;
int datalink = 0;
int majorversion = 0;
int minorversion = 0;
int pcapstatus;
long int packetcount = 0;
uint32_t magic = 0;
const uint8_t *packet;

const char *datalinkstring = "";
const char *pcapformatstring = "";

const char *dlt0 = "(DLT_NULL)";
const char *dlt1 = "(DLT_EN10MB)";
const char *dlt3 = "(DLT_AX25)";
const char *dlt6 = "(DLT_IEEE802)";
const char *dlt7 = "(DLT_ARCNET)";
const char *dlt8 = "(DLT_SLIP)";
const char *dlt9 = "(DLT_PPP)";
const char *dlt10 = "(DLT_FDDI)";
const char *dlt50 = "(DLT_PPP_SERIAL)";
const char *dlt51 = "(DLT_PPP_ETHER)";
const char *dlt100 = "(DLT_ATM_RFC1483)";
const char *dlt101 = "(DLT_RAW)";
const char *dlt104 = "(DLT_C_HDLC)";
const char *dlt105 = "(DLT_IEEE802_11)";
const char *dlt107 = "(DLT_FRELAY)";
const char *dlt108 = "(DLT_LOOP)";
const char *dlt113 = "(DLT_LINUX_SLL)";
const char *dlt114 = "(DLT_LTALK)";
const char *dlt117 = "(DLT_PFLOG)";
const char *dlt119 = "(DLT_PRISM_HEADER)";
const char *dlt122 = "(DLT_IP_OVER_FC)";
const char *dlt123 = "(DLT_SUNATM)";
const char *dlt127 = "(DLT_IEEE802_11_RADIO)";
const char *dlt129 = "(DLT_ARCNET_LINUX)";
const char *dlt138 = "(DLT_APPLE_IP_OVER_IEEE1394)";
const char *dlt139 = "(DLT_MTP2_WITH_PHDR)";
const char *dlt140 = "(DLT_MTP2)";
const char *dlt141 = "(DLT_MTP3)";
const char *dlt142 = "(DLT_SCCP)";
const char *dlt143 = "(DLT_DOCSIS)";
const char *dlt144 = "(DLT_LINUX_IRDA)";
const char *dlt147162 = "(DLT_USER0-DLT_USER15)";
const char *dlt163 = "(DLT_IEEE802_11_RADIO_AVS)";
const char *dlt165 = "(DLT_BACNET_MS_TP)";
const char *dlt166 = "(DLT_PPP_PPPD)";
const char *dlt169 = "(DLT_GPRS_LLC)";
const char *dlt170 = "(DLT_GPF_T)";
const char *dlt171 = "(DLT_GPF_F)";
const char *dlt177 = "(DLT_LINUX_LAPD)";
const char *dlt187 = "(DLT_BLUETOOTH_HCI_H4)";
const char *dlt189 = "(DLT_USB_LINUX)";
const char *dlt192 = "(DLT_PPI)";
const char *dlt195 = "(DLT_IEEE802_15_4)";
const char *dlt196 = "(DLT_SITA)";
const char *dlt197 = "(DLT_ERF)";
const char *dlt201 = "(DLT_BLUETOOTH_HCI_H4_WITH_PHDR)";
const char *dlt202 = "(DLT_AX25_KISS)";
const char *dlt203 = "(DLT_LAPD)";
const char *dlt204 = "(DLT_PPP_WITH_DIR)";
const char *dlt205 = "(DLT_C_HDLC_WITH_DIR)";
const char *dlt206 = "(DLT_FRELAY_WITH_DIR)";
const char *dlt209 = "(DLT_IPMB_LINUX)";
const char *dlt215 = "(DLT_IEEE802_15_4_NONASK_PHY)";
const char *dlt220 = "(DLT_USB_LINUX_MMAPPED)";
const char *dlt224 = "(DLT_FC_2)";
const char *dlt225 = "(DLT_FC_2_WITH_FRAME_DELIMS)";
const char *dlt226 = "(DLT_IPNET)";
const char *dlt227 = "(DLT_CAN_SOCKETCAN)";
const char *dlt228 = "(DLT_IPV4)";
const char *dlt229 = "(DLT_IPV6)";
const char *dlt230 = "(DLT_IEEE802_15_4_NOFCS)";
const char *dlt231 = "(DLT_DBUS)";
const char *dlt235 = "(DLT_DVB_CI)";
const char *dlt236 = "(DLT_MUX27010)";
const char *dlt237 = "(DLT_STANAG_5066_D_PDU)";
const char *dlt239 = "(DLT_NFLOG)";
const char *dlt240 = "(DLT_NETANALYZER)";
const char *dlt241 = "(DLT_NETANALYZER_TRANSPARENT)";
const char *dlt242 = "(DLT_IPOIB)";
const char *dlt243 = "(DLT_MPEG_2_TS)";
const char *dlt244 = "(DLT_NG40)";
const char *dlt245 = "(DLT_NFC_LLCP)";
const char *dlt247 = "(DLT_INFINIBAND)";
const char *dlt248 = "(DLT_SCTP)";
const char *dlt249 = "(DLT_USBPCAP)";
const char *dlt250 = "(DLT_RTAC_SERIAL)";
const char *dlt251 = "(DLT_BLUETOOTH_LE_LL)";
const char *dlt253 = "(DLT_NETLINK)";
const char *dlt254 = "(DLT_BLUETOOTH_LINUX_MONITOR)";
const char *dlt255 = "(DLT_BLUETOOTH_BREDR_BB)";
const char *dlt256 = "(DLT_BLUETOOTH_LE_LL_WITH_PHDR)";
const char *dlt257 = "(DLT_PROFIBUS_DL)";
const char *dlt258 = "(DLT_PKTAP)";
const char *dlt259 = "(DLT_EPON)";
const char *dlt260 = "(DLT_IPMI_HPM_2)";
const char *dlt261 = "(DLT_ZWAVE_R1_R2)";
const char *dlt262 = "(DLT_ZWAVE_R3)";
const char *dlt263 = "(DLT_WATTSTOPPER_DLM)";
const char *dlt264 = "(DLT_ISO_14443)";
const char *dlt265 = "(DLT_RDS)";
const char *dlt266 = "(DLT_USB_DARWIN)";
const char *dlt268 = "(DLT_SDLC)";

const char *pcap = "(cap/pcap)";
const char *pcapng = "(pcapng)";
const char *pcapsw = "(swapped cap/pcap)";
const char *pcapns = "(cap/pcap - ns)";
const char *pcapnssw = "(swapped cap/pcap - ns)";
const char *noerror = "flawless";
char pcaperrorstring[PCAP_ERRBUF_SIZE];

if (!(pcapin = pcap_open_offline(pcapinname, pcaperrorstring)))
	{
	fprintf(stderr, "error opening %s %s\n", pcaperrorstring, pcapinname);
	return false;
	}

majorversion = pcap_major_version(pcapin);
minorversion = pcap_minor_version(pcapin);
datalink = pcap_datalink(pcapin);

memset(&pcaperrorstring, 0, PCAP_ERRBUF_SIZE);
strcpy(pcaperrorstring, noerror);
while((pcapstatus = pcap_next_ex(pcapin, &pkh, &packet)) != -2)
	{
	if(pcapstatus == -1)
		{
		strcpy(pcaperrorstring, pcap_geterr(pcapin));
		continue;
		}
	packetcount++;


	}
pcap_close(pcapin);


if((fhc = fopen(pcapinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s\n", pcapinname);
	return false;
	}
magicsize = fread(&magic, 4, 1, fhc);
fclose(fhc);
if(magicsize != 1)
	{
	fprintf(stderr, "error reading file header %s\n", pcapinname);
	return false;
	}


if(magic == MAGIC_PCAP)
	pcapformatstring = pcap;

else if(magic == MAGIC_PCAP_NG)
	pcapformatstring = pcapng;

else if(magic == MAGIC_PCAP_SWAPPED)
	pcapformatstring = pcapsw;

else if(magic == MAGIC_PCAP_NS)
	pcapformatstring = pcapns;

else if(magic == MAGIC_PCAP_NS_SWAPPED)
	pcapformatstring = pcapnssw;


if(datalink == 0)
	datalinkstring = dlt0;

else if(datalink == 1)
	datalinkstring = dlt1;

else if(datalink == 3)
	datalinkstring = dlt3;

else if(datalink == 6)
	datalinkstring = dlt6;

else if(datalink == 7)
	datalinkstring = dlt7;

else if(datalink == 8)
	datalinkstring = dlt8;

else if(datalink == 9)
	datalinkstring = dlt9;

else if(datalink == 10)
	datalinkstring = dlt10;

else if(datalink == 50)
	datalinkstring = dlt50;

else if(datalink == 51)
	datalinkstring = dlt51;

else if(datalink == 100)
	datalinkstring = dlt100;

else if(datalink == 101)
	datalinkstring = dlt101;

else if(datalink == 104)
	datalinkstring = dlt104;

else if(datalink == 105)
	datalinkstring = dlt105;

else if(datalink == 107)
	datalinkstring = dlt107;

else if(datalink == 108)
	datalinkstring = dlt108;

else if(datalink == 113)
	datalinkstring = dlt113;

else if(datalink == 114)
	datalinkstring = dlt114;

else if(datalink == 117)
	datalinkstring = dlt117;

else if(datalink == 119)
	datalinkstring = dlt119;

else if(datalink == 122)
	datalinkstring = dlt122;

else if(datalink == 123)
	datalinkstring = dlt123;

else if(datalink == 127)
	datalinkstring = dlt127;

else if(datalink == 129)
	datalinkstring = dlt129;

else if(datalink == 138)
	datalinkstring = dlt138;

else if(datalink == 139)
	datalinkstring = dlt139;

else if(datalink == 140)
	datalinkstring = dlt140;

else if(datalink == 141)
	datalinkstring = dlt141;

else if(datalink == 142)
	datalinkstring = dlt142;

else if(datalink == 143)
	datalinkstring = dlt143;

else if(datalink == 144)
	datalinkstring = dlt144;

else if((datalink >= 147) && (datalink <= 162))
	datalinkstring = dlt147162;

else if(datalink == 163)
	datalinkstring = dlt163;

else if(datalink == 165)
	datalinkstring = dlt165;

else if(datalink == 166)
	datalinkstring = dlt166;

else if(datalink == 169)
	datalinkstring = dlt169;

else if(datalink == 170)
	datalinkstring = dlt170;

else if(datalink == 171)
	datalinkstring = dlt171;

else if(datalink == 177)
	datalinkstring = dlt177;

else if(datalink == 187)
	datalinkstring = dlt187;

else if(datalink == 189)
	datalinkstring = dlt189;

else if(datalink == 192)
	datalinkstring = dlt192;

else if(datalink == 195)
	datalinkstring = dlt195;

else if(datalink == 196)
	datalinkstring = dlt196;

else if(datalink == 197)
	datalinkstring = dlt197;

else if(datalink == 201)
	datalinkstring = dlt201;

else if(datalink == 202)
	datalinkstring = dlt202;

else if(datalink == 203)
	datalinkstring = dlt203;

else if(datalink == 204)
	datalinkstring = dlt204;

else if(datalink == 205)
	datalinkstring = dlt205;

else if(datalink == 206)
	datalinkstring = dlt206;

else if(datalink == 209)
	datalinkstring = dlt209;

else if(datalink == 215)
	datalinkstring = dlt215;

else if(datalink == 220)
	datalinkstring = dlt220;

else if(datalink == 224)
	datalinkstring = dlt224;

else if(datalink == 225)
	datalinkstring = dlt225;

else if(datalink == 226)
	datalinkstring = dlt226;

else if(datalink == 227)
	datalinkstring = dlt227;

else if(datalink == 228)
	datalinkstring = dlt228;

else if(datalink == 229)
	datalinkstring = dlt229;

else if(datalink == 230)
	datalinkstring = dlt230;

else if(datalink == 231)
	datalinkstring = dlt231;

else if(datalink == 235)
	datalinkstring = dlt235;

else if(datalink == 236)
	datalinkstring = dlt236;

else if(datalink == 237)
	datalinkstring = dlt237;

else if(datalink == 239)
	datalinkstring = dlt239;

else if(datalink == 240)
	datalinkstring = dlt240;

else if(datalink == 241)
	datalinkstring = dlt241;

else if(datalink == 242)
	datalinkstring = dlt242;

else if(datalink == 243)
	datalinkstring = dlt243;

else if(datalink == 244)
	datalinkstring = dlt244;

else if(datalink == 245)
	datalinkstring = dlt245;

else if(datalink == 247)
	datalinkstring = dlt247;

else if(datalink == 248)
	datalinkstring = dlt248;

else if(datalink == 249)
	datalinkstring = dlt249;

else if(datalink == 250)
	datalinkstring = dlt250;

else if(datalink == 251)
	datalinkstring = dlt251;

else if(datalink == 253)
	datalinkstring = dlt253;

else if(datalink == 254)
	datalinkstring = dlt254;

else if(datalink == 255)
	datalinkstring = dlt255;

else if(datalink == 256)
	datalinkstring = dlt256;

else if(datalink == 257)
	datalinkstring = dlt257;

else if(datalink == 258)
	datalinkstring = dlt258;

else if(datalink == 259)
	datalinkstring = dlt259;

else if(datalink == 260)
	datalinkstring = dlt260;

else if(datalink == 261)
	datalinkstring = dlt261;

else if(datalink == 262)
	datalinkstring = dlt262;

else if(datalink == 263)
	datalinkstring = dlt263;

else if(datalink == 264)
	datalinkstring = dlt264;

else if(datalink == 265)
	datalinkstring = dlt265;

else if(datalink == 266)
	datalinkstring = dlt266;

else if(datalink == 268)
	datalinkstring = dlt268;

printf( "input file.......: %s\n"
	"magic file number: 0x%04x %s\n"
	"major version....: %d\n"
	"minor version....: %d\n"
	"data link type...: %d %s [http://www.tcpdump.org/linktypes.html]\n"
	"packets inside...: %ld\n"
	"last pcap error..: %s\n"
	, pcapinname, magic, pcapformatstring, majorversion, minorversion, datalink, datalinkstring, packetcount, pcaperrorstring);

return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file> : input pcap file\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;

char *eigenname;
char *eigenpfadname;
char *pcapinname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		pcapinname = optarg;
		break;

		default:
		usage(eigenname);
		}
	}

if(pcapinname != NULL)
	getpcapinfo(pcapinname);

return EXIT_SUCCESS;
}

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

	
#define MAGIC_PCAP		0xa1b2c3d4
#define MAGIC_PCAP_SWAPPED	0xd4c3b2a1
#define MAGIC_PCAP_NS		0xa1b23c4d
#define MAGIC_PCAP_NS_SWAPPED	0x4d3cb2a1
#define MAGIC_PCAP_NG		0x0a0d0d0a


/*===========================================================================*/
int getpcapinfo(char *pcapinname)
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
const uint8_t *packet = NULL;

char *datalinkstring = "";
char *pcapformatstring = "";

char *dlt0 = "(DLT_NULL)";
char *dlt1 = "(DLT_EN10MB)";
char *dlt3 = "(DLT_AX25)";
char *dlt6 = "(DLT_IEEE802)";
char *dlt7 = "(DLT_ARCNET)";
char *dlt8 = "(DLT_SLIP)";
char *dlt9 = "(DLT_PPP)";
char *dlt10 = "(DLT_FDDI)";
char *dlt50 = "(DLT_PPP_SERIAL)";
char *dlt51 = "(DLT_PPP_ETHER)";
char *dlt100 = "(DLT_ATM_RFC1483)";
char *dlt101 = "(DLT_RAW)";
char *dlt104 = "(DLT_C_HDLC)";
char *dlt105 = "(DLT_IEEE802_11)";
char *dlt107 = "(DLT_FRELAY)";
char *dlt108 = "(DLT_LOOP)";
char *dlt113 = "(DLT_LINUX_SLL)";
char *dlt114 = "(DLT_LTALK)";
char *dlt117 = "(DLT_PFLOG)";
char *dlt119 = "(DLT_PRISM_HEADER)";
char *dlt122 = "(DLT_IP_OVER_FC)";
char *dlt123 = "(DLT_SUNATM)";
char *dlt127 = "(DLT_IEEE802_11_RADIO)";
char *dlt129 = "(DLT_ARCNET_LINUX)";
char *dlt138 = "(DLT_APPLE_IP_OVER_IEEE1394)";
char *dlt139 = "(DLT_MTP2_WITH_PHDR)";
char *dlt140 = "(DLT_MTP2)";
char *dlt141 = "(DLT_MTP3)";
char *dlt142 = "(DLT_SCCP)";
char *dlt143 = "(DLT_DOCSIS)";
char *dlt144 = "(DLT_LINUX_IRDA)";
char *dlt147162 = "(DLT_USER0-DLT_USER15)";
char *dlt163 = "(DLT_IEEE802_11_RADIO_AVS)";
char *dlt165 = "(DLT_BACNET_MS_TP)";
char *dlt166 = "(DLT_PPP_PPPD)";
char *dlt169 = "(DLT_GPRS_LLC)";
char *dlt170 = "(DLT_GPF_T)";
char *dlt171 = "(DLT_GPF_F)";
char *dlt177 = "(DLT_LINUX_LAPD)";
char *dlt187 = "(DLT_BLUETOOTH_HCI_H4)";
char *dlt189 = "(DLT_USB_LINUX)";
char *dlt192 = "(DLT_PPI)";
char *dlt195 = "(DLT_IEEE802_15_4)";
char *dlt196 = "(DLT_SITA)";
char *dlt197 = "(DLT_ERF)";
char *dlt201 = "(DLT_BLUETOOTH_HCI_H4_WITH_PHDR	)";
char *dlt202 = "(DLT_AX25_KISS)";
char *dlt203 = "(DLT_LAPD)";
char *dlt204 = "(DLT_PPP_WITH_DIR)";
char *dlt205 = "(DLT_C_HDLC_WITH_DIR)";
char *dlt206 = "(DLT_FRELAY_WITH_DIR)";
char *dlt209 = "(DLT_IPMB_LINUX)";
char *dlt215 = "(DLT_IEEE802_15_4_NONASK_PHY)";
char *dlt220 = "(DLT_USB_LINUX_MMAPPED)";
char *dlt224 = "(DLT_FC_2)";
char *dlt225 = "(DLT_FC_2_WITH_FRAME_DELIMS)";
char *dlt226 = "(DLT_IPNET)";
char *dlt227 = "(DLT_CAN_SOCKETCAN)";
char *dlt228 = "(DLT_IPV4)";
char *dlt229 = "(DLT_IPV6)";
char *dlt230 = "(DLT_IEEE802_15_4_NOFCS)";
char *dlt231 = "(DLT_DBUS)";
char *dlt235 = "(DLT_DVB_CI)";
char *dlt236 = "(DLT_MUX27010)";
char *dlt237 = "(DLT_STANAG_5066_D_PDU)";
char *dlt239 = "(DLT_NFLOG)";
char *dlt240 = "(DLT_NETANALYZER)";
char *dlt241 = "(DLT_NETANALYZER_TRANSPARENT)";
char *dlt242 = "(DLT_IPOIB)";
char *dlt243 = "(DLT_MPEG_2_TS)";
char *dlt244 = "(DLT_NG40)";
char *dlt245 = "(DLT_NFC_LLCP)";
char *dlt247 = "(DLT_INFINIBAND)";
char *dlt248 = "(DLT_SCTP)";
char *dlt249 = "(DLT_USBPCAP)";
char *dlt250 = "(DLT_RTAC_SERIAL)";
char *dlt251 = "(DLT_BLUETOOTH_LE_LL)";
char *dlt253 = "(DLT_NETLINK)";
char *dlt254 = "(DLT_BLUETOOTH_LINUX_MONITOR)";
char *dlt255 = "(DLT_BLUETOOTH_BREDR_BB)";
char *dlt256 = "(DLT_BLUETOOTH_LE_LL_WITH_PHDR)";
char *dlt257 = "(DLT_PROFIBUS_DL)";
char *dlt258 = "(DLT_PKTAP)";
char *dlt259 = "(DLT_EPON)";
char *dlt260 = "(DLT_IPMI_HPM_2)";
char *dlt261 = "(DLT_ZWAVE_R1_R2)";
char *dlt262 = "(DLT_ZWAVE_R3)";
char *dlt263 = "(DLT_WATTSTOPPER_DLM)";
char *dlt264 = "(DLT_ISO_14443)";
char *dlt265 = "(DLT_RDS)";
char *dlt266 = "(DLT_USB_DARWIN)";
char *dlt268 = "(DLT_SDLC)";

char *pcap = "(cap/pcap)";
char *pcapng = "(pcapng)";
char *pcapsw = "(swapped cap/pcap)";
char *pcapns = "(cap/pcap - ns)";
char *pcapnssw = "(swapped cap/pcap - ns)";
char *noerror = "flawless";
char pcaperrorstring[PCAP_ERRBUF_SIZE];

if (!(pcapin = pcap_open_offline(pcapinname, pcaperrorstring)))
	{
	fprintf(stderr, "error opening %s %s\n", pcaperrorstring, pcapinname);
	return FALSE;
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
	return FALSE;
	}
magicsize = fread(&magic, 4, 1, fhc);
if(magicsize != 1)
	{
	fprintf(stderr, "error reading file header %s\n", pcapinname);
	return FALSE;
	}

fclose(fhc);


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

return TRUE;	
}
/*===========================================================================*/
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

char *eigenname = NULL;
char *eigenpfadname = NULL;
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

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

if(pcapinname != NULL)
	getpcapinfo(pcapinname);

return EXIT_SUCCESS;
}

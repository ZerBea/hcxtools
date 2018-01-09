#define _GNU_SOURCE
#include <ctype.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#ifdef __APPLE__
#define strdupa strdup
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif

#include "include/version.h"
#include "include/byteops.c"
#include "include/fileops.c"
#include "include/pcap.c"

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif

/*===========================================================================*/
/* global var */


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
	case 147 :return "DLT_USER0-DLT_USER15";
	case 148:return "DLT_USER0-DLT_USER15";
	case 149:return "DLT_USER0-DLT_USER15";
	case 150:return "DLT_USER0-DLT_USER15";
	case 151:return "DLT_USER0-DLT_USER15";
	case 152:return "DLT_USER0-DLT_USER15";
	case 153:return "DLT_USER0-DLT_USER15";
	case 154:return "DLT_USER0-DLT_USER15";
	case 155:return "DLT_USER0-DLT_USER15";
	case 156:return "DLT_USER0-DLT_USER15";
	case 157:return "DLT_USER0-DLT_USER15";
	case 158:return "DLT_USER0-DLT_USER15";
	case 159:return "DLT_USER0-DLT_USER15";
	case 160:return "DLT_USER0-DLT_USER15";
	case 161:return "DLT_USER0-DLT_USER15";
	case 162:return "DLT_USER0-DLT_USER15";
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
	case DLT_USB_DARWIN: return "DLT_USB_DARWIN";
	case DLT_SDLC: return "DLT_SDLC";
	default: return "unknown network type";
	}
return "unknown network type";
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
return "unknow endian";
}
/*===========================================================================*/
void printcapstatus(char *pcaptype, int version_major, int version_minor, int networktype, int endianess, unsigned long long int rawpacketcount, char *pcapreaderrors, bool wpacleanflag)
{
printf("file type........: %s %d.%d\n"
	"network type.....: %s (%d)\n"
	"endianess........: %s\n"
	"packets inside...: %lld\n"
	"read errors......: %s\n"
	, pcaptype, version_major, version_minor, getdltstring(networktype), networktype, getendianessstring(endianess), rawpacketcount, pcapreaderrors);

if(wpacleanflag == true)
	{
	printf("warning..........: use of wpaclean detected\n");
	}
printf("\n");
return;
}
/*===========================================================================*/
void processpcapng(int fd, char *pcapinname)
{
bool pcapreaderrors = false;
bool wpacleanflag = false;
int endianess = 0;
unsigned int res;
unsigned long long int rawpacketcount = 0;

block_header_t pcapngbh;
section_header_block_t pcapngshb;
interface_description_block_t pcapngidb;
packet_block_t pcapngpb;
enhanced_packet_block_t pcapngepb;
uint8_t packet[MAXPACPSNAPLEN];

printf("start reading from %s\n", basename(pcapinname));
while(1)
	{
	res = read(fd, &pcapngbh, BH_SIZE);
	if(res == 0)
		{
		break;
		}
	if(res != BH_SIZE)
		{
		pcapreaderrors = true;
		printf("failed to read pcapng header block\n");
		break;
		}
	if(pcapngbh.block_type == PCAPNGBLOCKTYPE)
		{
		res = read(fd, &pcapngshb, SHB_SIZE);
		if(res != SHB_SIZE)
			{
			pcapreaderrors = true;
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
			pcapreaderrors = true;
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
			pcapreaderrors = true;
			}
		lseek(fd, pcapngbh.total_length -BH_SIZE -IDB_SIZE, SEEK_CUR);
		}

	else if(pcapngbh.block_type == 2)
		{
		res = read(fd, &pcapngpb, PB_SIZE);
		if(res != PB_SIZE)
			{
			pcapreaderrors = true;
			printf("failed to get pcapng packet block (obsolete)\n");
			break;
			}
		#ifdef BIG_ENDIAN_HOST
		pcapngpb.interface_id	= byte_swap_16(pcapngpb.interface_id);
		pcapngpbdrops_count.	= byte_swap_16(pcapngpb.drops_count);
		pcapngpbtimestamp_high.	= byte_swap_32(pcapngpb.timestamp_high);
		pcapngpbtimestamp_low.	= byte_swap_32(pcapngpb.timestamp_low);
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
		if(pcapngpb.caplen > MAXPACPSNAPLEN)
			{
			printf("detected oversized snaplen (%d) \n", pcapngpb.caplen);
			pcapreaderrors = true;
			break;
			}
		if((pcapngepb.timestamp_high == 0) && (pcapngepb.timestamp_low == 0))
			{
			wpacleanflag = true;
			}

		res = read(fd, &packet, pcapngpb.caplen);
		if(res != pcapngpb.caplen)
			{
			printf("failed to read packet\n");
			pcapreaderrors = true;
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
			pcapreaderrors = true;
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
		if(pcapngepb.caplen > MAXPACPSNAPLEN)
			{
			printf("detected oversized snaplen (%d) \n", pcapngepb.caplen);
			pcapreaderrors = true;
			break;
			}

		if((pcapngepb.timestamp_high == 0) && (pcapngepb.timestamp_low == 0))
			{
			wpacleanflag = true;
			}

		res = read(fd, &packet, pcapngepb.caplen);
		if(res != pcapngepb.caplen)
			{
			printf("failed to read packet\n");
			pcapreaderrors = true;
			break;
			}
		rawpacketcount++;
		lseek(fd, pcapngbh.total_length -BH_SIZE -EPB_SIZE -pcapngepb.caplen, SEEK_CUR);
		}

	else
		{
		lseek(fd, pcapngbh.total_length -BH_SIZE, SEEK_CUR);
		}


/* process packet */


	}

if(pcapreaderrors == false)
	{
	printcapstatus("pcapng", pcapngshb.major_version, pcapngshb.minor_version, pcapngidb.linktype, endianess, rawpacketcount, "flawless", wpacleanflag);
	}
else
	{
	printcapstatus("pcapng", pcapngshb.major_version, pcapngshb.minor_version, pcapngidb.linktype, endianess, rawpacketcount, "yes", wpacleanflag);
	}
return;
}
/*===========================================================================*/
void processpcap(int fd, char *pcapinname)
{
bool pcapreaderrors = false;
bool wpacleanflag = false;
int endianess = 0;
unsigned int res;
unsigned long long int rawpacketcount = 0;

pcap_hdr_t pcapfhdr;
pcaprec_hdr_t pcaprhdr;
uint8_t packet[MAXPACPSNAPLEN];

printf("start reading from %s\n", basename(pcapinname));
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
		pcapreaderrors = true;
		printf("failed to read pcap packet header\n");
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

	if(pcaprhdr.incl_len > MAXPACPSNAPLEN)
		{
		printf("detected oversized snaplen\n");
		pcapreaderrors = true;
		break;
		}
	if((pcaprhdr.ts_sec == 0) && (pcaprhdr.ts_usec == 0))
		{
		wpacleanflag = true;
		}

	res = read(fd, &packet, pcaprhdr.incl_len);
	if(res != pcaprhdr.incl_len)
		{
		printf("failed to read packet\n");
		pcapreaderrors = true;
		break;
		}
	rawpacketcount++;


/* process packet */


	}

if(pcapreaderrors == false)
	{
	printcapstatus("pcap", pcapfhdr.version_major, pcapfhdr.version_minor, pcapfhdr.network, endianess, rawpacketcount, "flawless", wpacleanflag);
	}
else
	{
	printcapstatus("pcap", pcapfhdr.version_major, pcapfhdr.version_minor, pcapfhdr.network, endianess, rawpacketcount, "yes", wpacleanflag);
	}
return;
}
/*===========================================================================*/
void processcapfile(char *pcapinname)
{
int pcapr_fd;
uint32_t magicnumber;

pcapr_fd = open(pcapinname, O_RDONLY);
if(pcapr_fd == -1)
	{
	return;
	}

magicnumber = getmagicnumber(pcapr_fd);
if(magicnumber == 0)
	{
	printf("failed to get magicnumber from %s\n", basename(pcapinname));
	close(pcapr_fd);
	return;
	}
lseek(pcapr_fd, 0L, SEEK_SET);

if((magicnumber == PCAPMAGICNUMBER) || (magicnumber == PCAPMAGICNUMBERBE))
	processpcap(pcapr_fd, pcapinname);

else if(magicnumber == PCAPNGBLOCKTYPE)
	processpcapng(pcapr_fd, pcapinname);

close(pcapr_fd);
return;
}
/*===========================================================================*/
bool testgzipfile(char *pcapinname)
{
int pcapr_fd;
uint32_t magicnumber;

pcapr_fd = open(pcapinname, O_RDONLY);
if(pcapr_fd == -1)
	{
	return false;
	}
magicnumber = getmagicnumber(pcapr_fd);
close(pcapr_fd);

if((magicnumber &0xffff) != GZIPMAGICNUMBER)
	{
	return false;
	}
printf("gezipped %s\n", pcapinname);
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
	"%s <options> [input.pcap] [input.pcap] ...\n"
	"%s <options> *.cap\n"
	"%s <options> *.*\n"
	"\n"
	"options:\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname, eigenname);
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
char *eigenpfadname, *eigenname;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "hv")) != -1)
	{
	switch (auswahl)
		{
		case 'h':
		usage(eigenname);

		case 'v':
		version(eigenname);

		default:
		usageerror(eigenname);
		}
	}


for(index = optind; index < argc; index++)
	{
	testgzipfile(argv[index]);
	processcapfile(argv[index]);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

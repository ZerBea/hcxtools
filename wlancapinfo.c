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

char *dlt105 = "(DLT_IEEE802_11)";
char *dlt119 = "(DLT_PRISM_HEADER)";
char *dlt127 = "(DLT_IEEE802_11_RADIO)";
char *dlt163 = "(DLT_IEEE802_11_RADIO_AVS)";
char *dlt192 = "(DLT_IEEE802_11_PPI_HDR)";

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



if(datalink == 105)
	datalinkstring = dlt105;

else if(datalink == 119)
	datalinkstring = dlt119;

else if(datalink == 127)
	datalinkstring = dlt127;

else if(datalink == 163)
	datalinkstring = dlt163;

else if(datalink == 192)
	datalinkstring = dlt192;



printf( "input file.......: %s\n"
	"magic file number: 0x%04x %s\n"
	"major version....: %d\n"
	"minor version....: %d\n"
	"data link type...: %d %s\n"
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

#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>
#include <time.h>
#include <pcap.h>
#include <linux/wireless.h>
#include "common.h"

/*===========================================================================*/
/* Definitionen */


#define NEWENTRY -1
#define MACLISTESIZEMAX 1024

#define PKART_BEACON		0b000000001
#define PKART_PROBE_REQ		0b000000010
#define PKART_DIR_PROBE_REQ	0b000000100
#define PKART_PROBE_RESP	0b000001000
#define PKART_ASSOC_REQ		0b000010000
#define PKART_REASSOC_REQ	0b000100000
#define PKART_HIDDENESSID	0b001000000


/*===========================================================================*/
/* globale variablen */

pcap_t *pcapin = NULL;
pcap_dumper_t *pcapout = NULL;
macl_t *netlist = NULL; 

/*===========================================================================*/
int initgloballists()
{

if((netlist = malloc(MACLISTESIZEMAX * MACL_SIZE)) == NULL)
	return FALSE;
memset(netlist, 0, MACLISTESIZEMAX * MACL_SIZE);


return TRUE;
}
/*===========================================================================*/
void printhex(uint8_t channel, const uint8_t *macaddr1, const uint8_t *macaddr2, int destflag)
{
int c;

fprintf(stdout, "%02d ", channel);

for (c = 0; c < 6; c++)
	fprintf(stdout, "%02x", macaddr1[c]);

if(destflag == TRUE)
	fprintf(stdout, " <- ");
else
	fprintf(stdout, " -> ");

for (c = 0; c < 6; c++)
	fprintf(stdout, "%02x", macaddr2[c]);

fprintf(stdout, " ");

return;
}
/*===========================================================================*/
void sigalarm(int signum)
{
if(signum == SIGALRM)
	{
	pcap_breakloop(pcapin);
	alarm(5);
	}
return;
}
/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	pcap_dump_flush(pcapout);
	pcap_dump_close(pcapout);
	pcap_close(pcapin);
	printf("program terminated...\n");
	exit (EXIT_SUCCESS);
	}
return;
}
/*===========================================================================*/
int handlepacket(uint8_t pkart, uint8_t *mac_sta, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
macl_t *zeiger;
int c;

zeiger = netlist;
for(c = 0; c < MACLISTESIZEMAX; c++)
	{
	if(zeiger->pkart == 0)
		break;

	if((zeiger->pkart == pkart) && (memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		return TRUE;
	zeiger++;
	}

if(c == MACLISTESIZEMAX)
	{
	zeiger = netlist;
	memset(netlist, 0, MACLISTESIZEMAX * MACL_SIZE);
	}

zeiger->pkart = pkart;
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
memcpy(zeiger->addr_sta.addr, mac_sta, 6);
zeiger->essid_len = essid_len;
memcpy(zeiger->essid, essidname, essid_len);
return NEWENTRY;
}
/*===========================================================================*/
void setchannel(char *interfacename, uint8_t channel)
{
struct iwreq wrq;

int sock = 0;
int result = 0;
memset(&wrq, 0, sizeof(struct iwreq));
strncpy(wrq.ifr_name, interfacename , IFNAMSIZ);
if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	{
        fprintf(stderr, "Socket open for ioctl() on '%s' failed with '%d'\n", interfacename, sock);
	programmende(SIGINT);
	}

wrq.u.freq.m = channel;
wrq.u.freq.e = 0;
wrq.u.freq.flags = IW_FREQ_FIXED;
if(ioctl(sock, SIOCSIWFREQ, &wrq) < 0)
	{
	usleep(100);
	if((result = ioctl(sock, SIOCSIWFREQ, &wrq)) < 0)
		{
		fprintf(stderr, "ioctl(SIOCSIWFREQ) on '%s' failed with '%d'\n", interfacename, result);
		fprintf(stderr, "unable to set channel on '%s', exiting\n", interfacename);
		programmende(SIGINT);
		}
	}
close(sock);
return;
}
/*===========================================================================*/
void pcaploop(char *interfacename, int has_rth, uint8_t channel)
{
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
struct pcap_pkthdr *pkh;
rth_t *rth = NULL;
mac_t *macf = NULL;
eap_t *eap = NULL;
essid_t *essidf;
uint8_t	*payload = NULL;
int pcapstatus = 1;
int macl = 0;
int fcsl = 0;
uint8_t field = 0;

char essidstring[34];

while(1)
	{
	pcapstatus = pcap_next_ex(pcapin, &pkh, &packet);
	if(pcapstatus == 0)
		continue;

	if(pcapstatus == -1)
		{
#ifdef RASPBERRY
		system("reboot");
#endif
		continue;
		}

	if(pcapstatus == -2)
		{
		pcap_dump_flush(pcapout);
		channel++;
		if(channel > 13)
			channel = 1;
		setchannel(interfacename, channel);
		continue;
		}

	if(pkh->caplen != pkh->len)
		continue;

	/* check radiotap-header */
	h80211 = packet;
	if(has_rth == TRUE)
		{
		rth = (rth_t*)packet;
		fcsl = 0;
		if((rth->it_present & 0x02) == 0x02)
			{
			field = 0x08;
			if((rth->it_present & 0x01) == 0x01)
				field += 0x0c;
			if((rth->it_present & 0x80000000) == 0x80000000)
				field += 0x04;
			if((packet[field] & 0x10) == 0x10)
				fcsl = 4;
			}

		pkh->caplen -= rth->it_len +fcsl;
		pkh->len -=  rth->it_len +fcsl;
		h80211 = packet + rth->it_len;
		}

	macf = (mac_t*)(h80211);
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
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if((essidf->info_essid_len == 0) || (&essidf->essid[0] == 0))
				{
				if(handlepacket(PKART_HIDDENESSID, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == NEWENTRY)
					{
					pcap_dump((u_char *) pcapout, pkh, h80211);
					printhex(channel, macf->addr1.addr, macf->addr2.addr, TRUE);
					fprintf(stdout, "(hidden ssid - beacon)\n");
					}
				continue;
				}

			if(handlepacket(PKART_BEACON, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == NEWENTRY)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
				printhex(channel, macf->addr1.addr, macf->addr2.addr, TRUE);
				memset(&essidstring, 0, 34);
				memcpy(&essidstring, essidf->essid, essidf->info_essid_len);
				fprintf(stdout, "%s (beacon)\n", essidstring);
				}
			continue;
			}
		else if(macf->subtype == MAC_ST_PROBE_RESP)
			{
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			if(handlepacket(PKART_PROBE_RESP, macf->addr1.addr, macf->addr2.addr, essidf->info_essid_len, essidf->essid) == NEWENTRY)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
				printhex(channel, macf->addr1.addr, macf->addr2.addr, TRUE);
				memset(&essidstring, 0, 34);
				memcpy(&essidstring, essidf->essid, essidf->info_essid_len);
				fprintf(stdout, "%s (proberesponse)\n", essidstring);
				}
			continue;
			}

		/* check proberequest frames */
		else if(macf->subtype == MAC_ST_PROBE_REQ)
			{
			essidf = (essid_t*)(payload);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			if(handlepacket(PKART_PROBE_REQ, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid) == NEWENTRY)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
				printhex(channel, macf->addr2.addr, macf->addr1.addr, FALSE);
				memset(&essidstring, 0, 34);
				memcpy(&essidstring, essidf->essid, essidf->info_essid_len);
				fprintf(stdout, "%s (proberequest)\n", essidstring);
				}
			continue;
			}

		/* check associationrequest - reassociationrequest frames */
		else if(macf->subtype == MAC_ST_ASSOC_REQ)
			{
			essidf = (essid_t*)(payload +ASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			if(handlepacket(PKART_ASSOC_REQ, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid) == NEWENTRY)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
				printhex(channel, macf->addr2.addr, macf->addr1.addr, FALSE);
				memset(&essidstring, 0, 34);
				memcpy(&essidstring, essidf->essid, essidf->info_essid_len);
				fprintf(stdout, "%s (associationrequest)\n", essidstring);
				}
			continue;
			}

		else if(macf->subtype == MAC_ST_REASSOC_REQ)
			{
			essidf = (essid_t*)(payload +REASSOCIATIONREQF_SIZE);
			if(essidf->info_essid != 0)
				continue;
			if(essidf->info_essid_len > 32)
				continue;
			if(essidf->info_essid_len == 0)
				continue;
			if (&essidf->essid[0] == 0)
				continue;
			if(handlepacket(PKART_REASSOC_REQ, macf->addr2.addr, macf->addr1.addr, essidf->info_essid_len, essidf->essid) == NEWENTRY)
				{
				pcap_dump((u_char *) pcapout, pkh, h80211);
				printhex(channel, macf->addr2.addr, macf->addr1.addr, FALSE);
				memset(&essidstring, 0, 34);
				memcpy(&essidstring, essidf->essid, essidf->info_essid_len);
				fprintf(stdout, "%s (reassociationrequest)\n", essidstring);
				}
			continue;
			}

		continue;
		}

	/* check handshake frames */
	if(macf->type == MAC_TYPE_DATA && LLC_SIZE <= pkh->len && be16toh(((llc_t*)payload)->type) == LLC_TYPE_AUTH)
		{
		eap = (eap_t*)(payload + LLC_SIZE);

		if(eap->type == 3)
			{
			pcap_dump((u_char *) pcapout, pkh, h80211);
			if(macf->from_ds == 1)
				{
				printhex(channel, macf->addr1.addr, macf->addr2.addr, TRUE);
				fprintf(stdout, "(handshake)\n");
				}
			else
				{
				printhex(channel, macf->addr2.addr, macf->addr1.addr, FALSE);
				fprintf(stdout, "(handshake)\n");
				}
			}
		}
	}
return;
}
/*===========================================================================*/
int startcapturing(char *interfacename, char *pcapoutname)
{
struct stat statinfo;
struct bpf_program filter;
pcap_t *pcapdh = NULL;
int filecount = 1;
int datalink = 0;
int pcapstatus;
int has_rth = FALSE;
int channel = 1;

char newpcapoutname[PATH_MAX +2];
char pcaperrorstring[PCAP_ERRBUF_SIZE];


if(pcapoutname == NULL)
	{
	fprintf(stderr, "no output file selected\n");
	exit(EXIT_FAILURE);
	}


pcapin = pcap_create(interfacename,pcaperrorstring);
if(pcapin == NULL)
	{
	fprintf(stderr, "error opening device %s\n", interfacename);
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_snaplen(pcapin, 0xfff);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting snaplen\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_buffer_size(pcapin, 0xffffff);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting buffersize\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_timeout(pcapin, 0);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting timeoutn\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_set_promisc(pcapin, 1);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error setting promisc mode\n");
	exit(EXIT_FAILURE);
	}

pcapstatus = pcap_activate(pcapin);
if(pcapstatus != 0)
	{
	fprintf(stderr, "error activating capture\n");
	exit(EXIT_FAILURE);
	}

datalink = pcap_datalink(pcapin);
	if (datalink == DLT_IEEE802_11_RADIO)
		has_rth = TRUE;

if (pcap_compile(pcapin, &filter,filterstring, 1, 0) < 0)
	{
	fprintf(stderr, "error compiling bpf filter %s \n", pcap_geterr(pcapin));
	exit(EXIT_FAILURE);
	}
if (pcap_setfilter(pcapin, &filter) < 0)
	{
	sprintf(pcaperrorstring, "error installing packet filter ");
	pcap_perror(pcapin, pcaperrorstring);
	exit(EXIT_FAILURE);
	}

pcap_freecode(&filter);


strcpy(newpcapoutname, pcapoutname);
while(stat(newpcapoutname, &statinfo) == 0)
	{
	snprintf(newpcapoutname, PATH_MAX, "%s-%d.cap", pcapoutname, filecount);
	filecount++;
	}
pcapdh = pcap_open_dead(DLT_IEEE802_11, 65535);
if ((pcapout = pcap_dump_open(pcapdh, newpcapoutname)) == NULL)
	{
	fprintf(stderr, "error creating dump file %s\n", newpcapoutname);
	exit(EXIT_FAILURE);
	}


setchannel(interfacename, channel);

signal(SIGINT, programmende);
signal(SIGALRM, sigalarm);
alarm(5);

pcaploop(interfacename, has_rth, channel);

pcap_dump_flush(pcapout);
pcap_dump_close(pcapout);
pcap_close(pcapin);
printf("program unconditionally stopped...\n");
return TRUE;
}
/*===========================================================================*/
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"(ctrl+c terminates program)\n"
	"options:\n"
	"-i <interface> : wlan interface\n"
	"-o <file>      : output cap file\n"
	"-h             : help screen\n"
	"-v             : version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
static void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
pcap_if_t *alldevs, *d;
int auswahl;
char *eigenpfadname, *eigenname;
char *devicename = NULL;
char *pcapoutname = NULL;

char pcaperrorstring[PCAP_ERRBUF_SIZE];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);


setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "i:o:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		devicename = optarg;
		if(devicename == NULL)
			{
			fprintf(stderr, "no interface specified\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'o':
		pcapoutname = optarg;
		break;

		case 'h':
		usage(eigenname);
		break;

		case 'v':
		version(eigenname);
		break;

		default:
		usageerror(eigenname);
		break;
		}
	}

if( getuid() != 0 )
	{
	fprintf(stderr, "this programm requires root privileges\n" );
	exit(EXIT_FAILURE);
	}

if(devicename == NULL)
	{
	fprintf(stdout,"\nno device selected - suitable devices:\n--------------------------------------\n");

	if(pcap_findalldevs(&alldevs, pcaperrorstring) == -1)
		{
		fprintf(stderr,"error in pcap_findalldevs: %s\n", pcaperrorstring);
		exit (EXIT_FAILURE);
		}

	for(d=alldevs; d; d=d->next)
		{
		fprintf(stdout, "%s", d->name);
		if(d->description)
			printf(" (%s)\n", d->description);

		else
		fprintf(stdout," (no description available)\n");
		}

	pcap_freealldevs(alldevs);
	exit (EXIT_FAILURE);
	}

if(initgloballists() != TRUE)
	{
	fprintf(stderr, "could not allocate memory for tables\n" );
	exit (EXIT_FAILURE);
	}

if(startcapturing(devicename, pcapoutname) == FALSE)
	{
	fprintf(stderr, "could not init devices or outputfile\n" );
	exit (EXIT_FAILURE);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

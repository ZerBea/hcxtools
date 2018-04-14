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
#include <stdbool.h>
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

#include "include/version.h"
#include "common.h"

/*===========================================================================*/
/* Definitionen */

#define APLISTESIZEMAX 10000
#define ALARMTIME 1
#define DEFAULTLOOP 3


struct aplist
{
 uint8_t	channel;
 adr_t		addr_ap;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct aplist apl_t;
#define	APL_SIZE (sizeof(apl_t))

/*===========================================================================*/
/* globale variablen */

static pcap_t *pcapin = NULL;
static uint8_t chlistp = 0;
static uint8_t channel = 1;


static apl_t *apliste = NULL;
static adr_t nullmac;
static int netcount = 0;
static int loop = DEFAULTLOOP;

static char *interfacename = NULL;

/*===========================================================================*/
/* Konstante */

/*===========================================================================*/
static bool initgloballists(void)
{
memset(&nullmac, 0, 6);

if((apliste = malloc(APLISTESIZEMAX * APL_SIZE)) == NULL)
	return false;
memset(apliste, 0, APLISTESIZEMAX * APL_SIZE);
return true;
}
/*===========================================================================*/
static int sort_by_channel(const void *a, const void *b)
{
const apl_t *ia = (const apl_t *)a;
const apl_t *ib = (const apl_t *)b;

return ia->channel > ib->channel;
}
/*===========================================================================*/
static void printstatus(void)
{
int c, m;
apl_t *zeiger = apliste;

char essidstr[34];
const char *hiddenstr = "hidden ssid";

qsort(apliste, APLISTESIZEMAX, APL_SIZE, sort_by_channel);
printf("ch  mac_ap       essid\n------------------------------------------------------\n");
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if(zeiger->channel > 0)
		{
		memset(essidstr, 0, 34);
		memcpy(&essidstr, zeiger->essid, zeiger->essid_len);
		if((essidstr[0] == 0) || (zeiger->essid_len == 0))
			strcpy(essidstr, hiddenstr);
		printf("%03d ", zeiger->channel);
		for (m = 0; m < 6; m++)
			printf("%02x", zeiger->addr_ap.addr[m]);
		printf(" %s\n", essidstr);
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static tag_t *dotagwalk(uint8_t *tagdata, int taglen, uint8_t searchtag)
{
tag_t *tagl;
tagl = (tag_t*)(tagdata);
while( 0 < taglen)
	{
	if(tagl->id == searchtag)
		return tagl;
	tagl = (tag_t*)((uint8_t*)tagl +tagl->len +TAGINFO_SIZE);
	taglen -= tagl->len;
	}
return NULL;
}
/*===========================================================================*/
static bool handleapframes(uint8_t *mac_ap, uint8_t *tagdata, int taglen)
{
apl_t *zeiger;
tag_t *essidtag;
tag_t *channeltag;
int c;

essidtag = dotagwalk(tagdata, taglen, TAG_SSID);
if((essidtag == NULL) || (essidtag->len > 32))
	return false;

zeiger = apliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (zeiger->essid_len == essidtag->len) && (memcmp(zeiger->essid, essidtag->data, essidtag->len) == 0))
		{
		return true;
		}
	if(memcmp(&nullmac.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}

channeltag = dotagwalk(tagdata, taglen, TAG_CHAN);
if(channeltag != NULL)
	zeiger->channel = *channeltag->data;
else
	zeiger->channel = channel;

memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essidtag->len;
memcpy(zeiger->essid, essidtag->data, essidtag->len);
return false;
}
/*===========================================================================*/
static void sigalarm(int signum)
{
if(signum == SIGALRM)
	{
	pcap_breakloop(pcapin);
	alarm(ALARMTIME);
	}
return;
}
/*===========================================================================*/
static void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	pcap_close(pcapin);
	printf("\nscan finished...\n");
	if(netcount > 0)
		printstatus();
	exit (EXIT_SUCCESS);
	}
return;
}
/*===========================================================================*/
static void setchannel(void)
{
struct iwreq wrq;

int sock = 0;
int result = 0;
memset(&wrq, 0, sizeof(struct iwreq));
strncpy(wrq.ifr_name, interfacename , IFNAMSIZ);
if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
	return;

wrq.u.freq.m = channel;
wrq.u.freq.e = 0;
wrq.u.freq.flags = IW_FREQ_FIXED;
if(ioctl(sock, SIOCSIWFREQ, &wrq) < 0)
	{
	usleep(100);
	if((result = ioctl(sock, SIOCSIWFREQ, &wrq)) < 0)
		{
		close(sock);
		return;
		}
	}
close(sock);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void pcaploop(int has_rth)
{
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
struct pcap_pkthdr *pkh;
const rth_t *rth;
mac_t *macf = NULL;
uint8_t	*payload = NULL;
int pcapstatus = 1;
int macl = 0;
int fcsl = 0;
uint8_t field = 0;

printf("start scanning...\n");
printf("\rloop: %d channel: %03d found nets: %d", loop, channel, netcount);

while(1)
	{
	pcapstatus = pcap_next_ex(pcapin, &pkh, &packet);
	if(pcapstatus == 0)
		continue;

	if(pcapstatus == -1)
		{
		fprintf(stderr, "pcap read error: %s \n", pcap_geterr(pcapin));
		continue;
		}

	if(pcapstatus == -2)
		{
		chlistp++;
		if(chlistp >= CHANNELLIST_SIZE)
			{
			chlistp = 0;
			loop--;
			}
		if(loop == 0)
			programmende(SIGINT);
		channel = channellist [chlistp];
		setchannel();
		printf("\rloop: %d channel: %03d found nets: %d", loop, channel, netcount);
		continue;
		}

	if(pkh->caplen != pkh->len)
		continue;

	/* check radiotap-header */
	h80211 = packet;
	if(has_rth == true)
		{
		if(RTH_SIZE > pkh->len)
			continue;
		rth = (const rth_t*)packet;
		fcsl = 0;
		field = 8;
		if((rth->it_present & 0x01) == 0x01)
			field += 8;
		if((rth->it_present & 0x80000000) == 0x80000000)
			field += 4;
		if((rth->it_present & 0x02) == 0x02)
			{
			if((packet[field] & 0x10) == 0x10)
				fcsl = 4;
			}
		pkh->caplen -= rth->it_len +fcsl;
		pkh->len -=  rth->it_len +fcsl;
		h80211 = packet + rth->it_len;
		}

	macf = (mac_t*)(h80211);
	if((macf->to_ds == 1) && (macf->from_ds == 1))
		macl = MAC_SIZE_LONG;
	else
		macl = MAC_SIZE_NORM;


	if(MAC_SIZE_NORM > pkh->len)
		continue;

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
			if(handleapframes(macf->addr2.addr, payload +BEACONINFO_SIZE, pkh->len -macl -BEACONINFO_SIZE) == false)
				netcount++;
			}
		}
	}
}
/*===========================================================================*/
static bool startcapturing(void)
{
int datalink = 0;
int has_rth = false;

char pcaperrorstring[PCAP_ERRBUF_SIZE];

pcapin = pcap_open_live(interfacename, 65535, 1, 5, pcaperrorstring);
if(pcapin == NULL)
	{
	fprintf(stderr, "error opening device %s: %s\n", interfacename, pcaperrorstring);
	exit(EXIT_FAILURE);
	}

datalink = pcap_datalink(pcapin);
	if (datalink == DLT_IEEE802_11_RADIO)
		has_rth = true;


setchannel();

signal(SIGINT, programmende);
signal(SIGALRM, sigalarm);
alarm(ALARMTIME);

pcaploop(has_rth);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"(ctrl+c terminates program)\n"
	"options:\n"
	"-i <interface> : WLAN interface\n"
	"-l <digit>     : loops (default = 3)\n"
	"-h             : help screen\n"
	"-v             : version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
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

char pcaperrorstring[PCAP_ERRBUF_SIZE];

setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "i:l:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		interfacename = optarg;
		if(interfacename == NULL)
			{
			fprintf(stderr, "no interface specified\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'l':
		loop = strtol(optarg, NULL, 10);
		break;

		case 'h':
		usage(basename(argv[0]));

		case 'v':
		version(basename(argv[0]));

		default:
		usageerror(basename(argv[0]));
		}
	}

if( getuid() != 0 )
	{
	fprintf(stderr, "this program requires root privileges\n" );
	exit(EXIT_FAILURE);
	}

if(interfacename == NULL)
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

if(initgloballists() != true)
	{
	fprintf(stderr, "could not allocate memory for tables\n" );
	exit (EXIT_FAILURE);
	}


if(startcapturing() == false)
	{
	fprintf(stderr, "could not init device\n" );
	exit (EXIT_FAILURE);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

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

#include "common.h"

/*===========================================================================*/
/* Definitionen */

#define APLISTESIZEMAX 10000
#define ALARMTIME 1

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

pcap_t *pcapin = NULL;
uint8_t chlistp = 0;
uint8_t channel = 1;


apl_t *apliste = NULL;
adr_t nullmac;
int netcount = 0;

char *interfacename = NULL;

/*===========================================================================*/
/* Konstante */

/*===========================================================================*/
bool initgloballists()
{
memset(&nullmac, 0, 6);

if((apliste = malloc(APLISTESIZEMAX * APL_SIZE)) == NULL)
	return false;
memset(apliste, 0, APLISTESIZEMAX * APL_SIZE);
return true;
}
/*===========================================================================*/
int sort_by_channel(const void *a, const void *b)
{
apl_t *ia = (apl_t *)a;
apl_t *ib = (apl_t *)b;

return ia->channel > ib->channel;
}
/*===========================================================================*/
void printstatus()
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

		printf(" %s (%d)\n", essidstr, zeiger->essid_len);
		}

	zeiger++;
	}


return;
}
/*===========================================================================*/
bool handleapframes(uint8_t channel, uint8_t *mac_ap, uint8_t essid_len, uint8_t **essidname)
{
apl_t *zeiger;
int c;

zeiger = apliste;
for(c = 0; c < APLISTESIZEMAX; c++)
	{
	if((memcmp(mac_ap, zeiger->addr_ap.addr, 6) == 0) && (zeiger->essid_len == essid_len) && (memcmp(zeiger->essid, essidname, essid_len) == 0))
		{
		return true;
		}
	if(memcmp(&nullmac.addr, zeiger->addr_ap.addr, 6) == 0)
		break;
	zeiger++;
	}

zeiger->channel = channel;
memcpy(zeiger->addr_ap.addr, mac_ap, 6);
zeiger->essid_len = essid_len;
memcpy(zeiger->essid, essidname, essid_len);
return false;
}
/*===========================================================================*/
void sigalarm(int signum)
{
if(signum == SIGALRM)
	{
	pcap_breakloop(pcapin);
	alarm(ALARMTIME);
	}
return;
}
/*===========================================================================*/
void programmende(int signum)
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
void setchannel()
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
void pcaploop(int has_rth)
{
const uint8_t *packet = NULL;
const uint8_t *h80211 = NULL;
struct pcap_pkthdr *pkh;
rth_t *rth = NULL;
mac_t *macf = NULL;
tag_t *tagf = NULL;
uint8_t	*payload = NULL;
essid_t *essidf;
int pcapstatus = 1;
int macl = 0;
int fcsl = 0;
int taglen = 0;
int loop = 3;
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
		rth = (rth_t*)packet;
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
			essidf = (essid_t*)(payload +BEACONINFO_SIZE);
			if(essidf->info_essid_len > 32)
				continue;

			taglen = pkh->len -macl -BEACONINFO_SIZE;
			tagf = (tag_t*)(payload +BEACONINFO_SIZE);
			while(taglen > 0)
				{
				if(tagf->id == TAG_CHAN)
					{
					if(handleapframes(tagf->data[0], macf->addr2.addr, essidf->info_essid_len, essidf->essid) == false)
						netcount++;
					break;
					}



				taglen -= tagf->len +TAGINFO_SIZE;
				tagf = (tag_t*)((uint8_t*)tagf +tagf->len +TAGINFO_SIZE);
				}
			}
		}
	}
return;
}
/*===========================================================================*/
bool startcapturing()
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

pcap_close(pcapin);
printf("program unconditionally stopped...\n");
return true;
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
	"-i <interface> : WLAN interface\n"
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

char pcaperrorstring[PCAP_ERRBUF_SIZE];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);


setbuf(stdout, NULL);
srand(time(NULL));
while ((auswahl = getopt(argc, argv, "i:hv")) != -1)
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

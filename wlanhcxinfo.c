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

#define OM_MAC_AP	0b000000000000000001
#define OM_MAC_STA	0b000000000000000010
#define OM_MESSAGE_PAIR	0b000000000000000100
#define OM_NONCE_AP	0b000000000000001000
#define OM_NONCE_STA	0b000000000000010000
#define OM_KEYMIC	0b000000000000100000
#define OM_REPLAYCOUNT	0b000000000001000000
#define OM_KEYVER	0b000000000010000000
#define OM_KEYTYPE	0b000000000100000000
#define OM_ESSID_LEN	0b000000001000000000
#define OM_ESSID	0b000000010000000000

/*===========================================================================*/
/* globale Variablen */

hcx_t *hcxdata = NULL;

/*===========================================================================*/
void printhex(const uint8_t *buffer, int size)
{
int c;
for (c = 0; c < size; c++)
	fprintf(stdout, "%02x", buffer[c]);
return;
}
/*===========================================================================*/
uint8_t geteapkeytype(uint8_t *eapdata)
{
eap_t *eap;
uint16_t keyinfo;
int eapkey = 0;

eap = (eap_t*)(uint8_t*)(eapdata);
keyinfo = (((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8));
if (keyinfo & WPA_KEY_INFO_ACK)
	{
	if(keyinfo & WPA_KEY_INFO_INSTALL)
		{
		/* handshake 3 */
		eapkey = 3;
		}
	else
		{
		/* handshake 1 */
		eapkey = 1;
		}
	}
else
	{
	if(keyinfo & WPA_KEY_INFO_SECURE)
		{
		/* handshake 4 */
		eapkey = 4;
		}
	else
		{
		/* handshake 2 */
		eapkey = 2;
		}
	}
return eapkey;
}
/*===========================================================================*/
uint8_t geteapkeyver(uint8_t *eapdata)
{
eap_t *eap;
int eapkeyver;

eap = (eap_t*)(uint8_t*)(eapdata);
eapkeyver = ((((eap->keyinfo & 0xff) << 8) | (eap->keyinfo >> 8)) & WPA_KEY_INFO_TYPE_MASK);
return eapkeyver;
}
/*===========================================================================*/
unsigned long long int geteapreplaycount(uint8_t *eapdata)
{
eap_t *eap;
unsigned long long int replaycount = 0;

eap = (eap_t*)(uint8_t*)(eapdata);
replaycount = be64toh(eap->replaycount);
return replaycount;
}
/*===========================================================================*/
void writehcxinfo(long int hcxrecords, int outmode)
{
hcx_t *zeigerhcx;
long int c;
uint8_t pf;
uint8_t keyver;
uint8_t keytype;
unsigned long long int replaycount;
int wldflag = FALSE;

char essidoutstr[34];

c = 0;
while(c < hcxrecords)
	{
	pf = FALSE;
	zeigerhcx = hcxdata +c;
	replaycount = geteapreplaycount(zeigerhcx->eapol);
	if((replaycount == 63232) && (memcmp(&mynonce, zeigerhcx->nonce_ap, 32) == 0))
		wldflag = TRUE;

	if((outmode & OM_MAC_AP) == OM_MAC_AP)
		{
		printhex(zeigerhcx->mac_ap.addr, 6);
		pf = TRUE;
		}

	if((outmode & OM_NONCE_AP) == OM_NONCE_AP)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_ap, 32);
		pf = TRUE;
		}

	if((outmode & OM_MAC_STA) == OM_MAC_STA)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		printhex(zeigerhcx->mac_sta.addr, 6);
		pf = TRUE;
		}

	if((outmode & OM_NONCE_STA) == OM_NONCE_STA)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_sta, 32);
		pf = TRUE;
		}

	if((outmode & OM_KEYMIC) == OM_KEYMIC)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		printhex(zeigerhcx->keymic, 16);
		pf = TRUE;
		}

	if((outmode & OM_REPLAYCOUNT) == OM_REPLAYCOUNT)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		fprintf(stdout, "%016llx", replaycount);
		pf = TRUE;
		}

	if((outmode & OM_KEYVER) == OM_KEYVER)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		keyver = geteapkeyver(zeigerhcx->eapol);
		fprintf(stdout, "%d", keyver);
		pf = TRUE;
		}

	if((outmode & OM_KEYTYPE) == OM_KEYTYPE)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		keytype = geteapkeytype(zeigerhcx->eapol);
		fprintf(stdout, "%d", keytype);
		pf = TRUE;
		}

	if((outmode & OM_MESSAGE_PAIR) == OM_MESSAGE_PAIR)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		fprintf(stdout, "%02x", zeigerhcx->message_pair);
		pf = TRUE;
		}

	if((outmode & OM_ESSID_LEN) == OM_ESSID_LEN)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");
		fprintf(stdout, "%02d", zeigerhcx->essid_len);
		pf = TRUE;
		}


	if((outmode & OM_ESSID) == OM_ESSID)
		{
		if(pf == TRUE)
			fprintf(stdout, ":");

		memset(&essidoutstr, 0, 34);
		if(zeigerhcx->essid_len > 32)
			zeigerhcx->essid_len = 32;
		memcpy(&essidoutstr, zeigerhcx->essid, zeigerhcx->essid_len); 

		memcpy(&essidoutstr, zeigerhcx->essid, zeigerhcx->essid_len); 
		fprintf(stdout, "%s", essidoutstr);
		pf = TRUE;
		}

	if((outmode) != 0)
		fprintf(stdout, "\n");
	c++;
	}

if(wldflag == TRUE)
	fprintf(stderr, "\x1B[32mfound wlandump forced handshakes inside\x1B[0m\n");
return;
}
/*===========================================================================*/
int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return FALSE;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return FALSE;
	}

if((statinfo.st_size % HCX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return FALSE;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxinname);
	return FALSE;
	}

hcxdata = malloc(statinfo.st_size);
if(hcxdata == NULL)	
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		return FALSE;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
if(hcxsize != statinfo.st_size)	
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return FALSE;
	}
fclose(fhhcx);

fprintf(stderr, "%ld records readed from %s\n", hcxsize / HCX_SIZE, hcxinname);
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-o <file> : output info file (default stdout)\n"
	"-a        : list access points\n"
	"-A        : list anonce\n"
	"-s        : list stations\n"
	"-S        : list snonce\n"
	"-M        : list key mic\n"
	"-R        : list replay count\n"
	"-w        : list wpa version\n"
	"-P        : list key key number\n"
	"-p        : list messagepair\n"
	"-l        : list essid len\n"
	"-e        : list essid\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int outmode = 0;
long int hcxorgrecords = 0;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *infoname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:aAsSMRwpPlehv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'o':
		infoname = optarg;
		fclose(stdout);
		if ((stdout = fopen(infoname,"w")) == NULL)
			{
			fprintf(stderr, "unable to open outputfile %s\n", infoname);
			exit (EXIT_FAILURE);
			}
		break;

		case 'a':
		outmode |= OM_MAC_AP;
		break;

		case 'A':
		outmode |= OM_NONCE_AP;
		break;

		case 's':
		outmode |= OM_MAC_STA;
		break;

		case 'S':
		outmode |= OM_NONCE_STA;
		break;

		case 'M':
		outmode |= OM_KEYMIC;
		break;

		case 'R':
		outmode |= OM_REPLAYCOUNT;
		break;

		case 'w':
		outmode |= OM_KEYVER;
		break;

		case 'P':
		outmode |= OM_KEYTYPE;
		break;

		case 'p':
		outmode |= OM_MESSAGE_PAIR;
		break;

		case 'r':
		outmode |= OM_REPLAYCOUNT;
		break;

		case 'l':
		outmode |= OM_ESSID_LEN;
		break;

		case 'e':
		outmode |= OM_ESSID;
		break;

		default:
		usage(eigenname);
		break;
		}
	}

hcxorgrecords = readhccapx(hcxinname);
fprintf(stderr, "%ld records loaded\n", hcxorgrecords);

if(hcxorgrecords == 0)
	return EXIT_SUCCESS;


writehcxinfo(hcxorgrecords, outmode);

if(hcxdata != NULL)
	free(hcxdata);

if(infoname != NULL)
	fclose(stdout);

return EXIT_SUCCESS;
}

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
int checkessid(uint8_t essid_len, uint8_t *essid)
{
uint8_t p;

if(essid_len == 0)
	return false;

if(essid_len > 32)
	return false;

for(p = 0; p < essid_len; p++)
	if((essid[p] < 0x20) || (essid[p] > 0x7e))
		return false;
return true;
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
uint8_t get8021xver(uint8_t *eapdata)
{
eap_t *eap;
eap = (eap_t*)(uint8_t*)(eapdata);
return eap->version;
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
int sort_by_nonce_ap(const void *a, const void *b)
{
hcx_t *ia = (hcx_t *)a;
hcx_t *ib = (hcx_t *)b;

return memcmp(ia->nonce_ap, ib->nonce_ap, 32);
}
/*===========================================================================*/
void writehcxinfo(long int hcxrecords, int outmode)
{
hcx_t *zeigerhcx;
long int c, c1;
uint8_t pf;
uint8_t eapver;
uint8_t keyver;
uint8_t keytype;
unsigned long long int replaycount;

long int totalrecords = 0;
long int wldcount = 0;
long int xverc1 = 0;
long int xverc2 = 0;
long int wpakv1c = 0;
long int wpakv2c = 0;
long int wpakv3c = 0;
long int wpakv4c = 0;

long int mp0c = 0;
long int mp1c = 0;
long int mp2c = 0;
long int mp3c = 0;
long int mp4c = 0;
long int mp5c = 0;

long int mp80c = 0;
long int mp81c = 0;
long int mp82c = 0;
long int mp83c = 0;
long int mp84c = 0;
long int mp85c = 0;
long int noessidcount = 0;

uint8_t noncecorr = false;

uint8_t nonceold[32];
char essidoutstr[34];

memset(nonceold, 0, 32);
qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_nonce_ap);

c = 0;
while(c < hcxrecords)
	{
	pf = false;
	zeigerhcx = hcxdata +c;
	eapver = get8021xver(zeigerhcx->eapol);
	keyver = geteapkeyver(zeigerhcx->eapol);

	if(keyver == 1)
		wpakv1c++;

	if(keyver == 2)
		wpakv2c++;

	if(keyver == 3)
		wpakv3c++;

	if((keyver &4) == 4)
		wpakv4c++;


	replaycount = geteapreplaycount(zeigerhcx->eapol);
	if((replaycount == MYREPLAYCOUNT) && (memcmp(&mynonce, zeigerhcx->nonce_ap, 32) == 0))
		wldcount++;

	if((memcmp(&nonceold, zeigerhcx->nonce_ap, 28) == 0) && (memcmp(&nonceold, zeigerhcx->nonce_ap, 32) != 0))
		noncecorr = true;
	memcpy(&nonceold, zeigerhcx->nonce_ap, 32);


	if((outmode & OM_MAC_AP) == OM_MAC_AP)
		{
		printhex(zeigerhcx->mac_ap.addr, 6);
		pf = true;
		}

	if((outmode & OM_NONCE_AP) == OM_NONCE_AP)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_ap, 32);
		pf = true;
		}

	if((outmode & OM_MAC_STA) == OM_MAC_STA)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->mac_sta.addr, 6);
		pf = true;
		}

	if((outmode & OM_NONCE_STA) == OM_NONCE_STA)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->nonce_sta, 32);
		pf = true;
		}

	if((outmode & OM_KEYMIC) == OM_KEYMIC)
		{
		if(pf == true)
			fprintf(stdout, ":");
		printhex(zeigerhcx->keymic, 16);
		pf = true;
		}

	if((outmode & OM_REPLAYCOUNT) == OM_REPLAYCOUNT)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%016llx", replaycount);
		pf = true;
		}

	if((outmode & OM_KEYVER) == OM_KEYVER)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%d", keyver);
		pf = true;
		}

	if((outmode & OM_KEYTYPE) == OM_KEYTYPE)
		{
		if(pf == true)
			fprintf(stdout, ":");
		keytype = geteapkeytype(zeigerhcx->eapol);
		fprintf(stdout, "%d", keytype);
		pf = true;
		}

	if((outmode & OM_MESSAGE_PAIR) == OM_MESSAGE_PAIR)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%02x", zeigerhcx->message_pair);
		pf = true;
		}

	if((outmode & OM_ESSID_LEN) == OM_ESSID_LEN)
		{
		if(pf == true)
			fprintf(stdout, ":");
		fprintf(stdout, "%02d", zeigerhcx->essid_len);
		pf = true;
		}

	if((outmode & OM_ESSID) == OM_ESSID)
		{
		if(pf == true)
			fprintf(stdout, ":");

		if(zeigerhcx->essid_len > 32)
			zeigerhcx->essid_len = 32;
		memset(&essidoutstr, 0, 34);
		memcpy(&essidoutstr, zeigerhcx->essid, zeigerhcx->essid_len);

		if(checkessid(zeigerhcx->essid_len, zeigerhcx->essid) == true)
			fprintf(stdout, "%s", essidoutstr);

		else if(zeigerhcx->essid_len != 0)
			{
			fprintf(stdout, "$HEX[");
			for(c1 = 0; c1 < zeigerhcx->essid_len; c1++)
				fprintf(stdout, "%02x", zeigerhcx->essid[c1]);
			fprintf(stdout, "]");
			}
		else
			fprintf(stdout, "<empty ESSID>");

		pf = true;
		}

	if((outmode) != 0)
		fprintf(stdout, "\n");

	if(eapver == 1)
		xverc1++;

	if(eapver == 2)
		xverc2++;

	if((zeigerhcx->message_pair & 0x7f) == 0)
		{
		mp0c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
		mp80c++;
		}

	if((zeigerhcx->message_pair & 0x7f) == 1)
		{
		mp1c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
		mp81c++;
		}

	if((zeigerhcx->message_pair & 0x7f) == 2)
		{
		mp2c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
		mp82c++;
		}

	if((zeigerhcx->message_pair & 0x7f) == 3)
		{
		mp3c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
		mp83c++;
		}

	if((zeigerhcx->message_pair & 0x7f) == 4)
		{
		mp4c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
		mp84c++;
		}

	if((zeigerhcx->message_pair & 0x7f) == 5)
		{
		mp5c++;
		if((zeigerhcx->message_pair & 0x80) == 0x80)
		mp85c++;
		}

	if((zeigerhcx->essid_len == 0) && (zeigerhcx->essid[0] == 0))
		noessidcount++;

	totalrecords++;
	c++;
	}

if(outmode == 0)
	{
	fprintf(stdout, "total hashes read from file.......: %ld\n"
			"\x1B[32mwlandump-ng forced handshakes.....: %ld\x1B[0m\n"
			"zeroed ESSID......................: %ld\n"
			"802.1x Version 2001...............: %ld\n"
			"802.1x Version 2004...............: %ld\n"
			"WPA1 RC4 Cipher, HMAC-MD5.........: %ld\n"
			"WPA2 AES Cipher, HMAC-SHA1........: %ld\n"
			"WPA2 AES Cipher, AES-128-CMAC.....: %ld\n"
			"Group keys........................: %ld\n"
			"message pair M12E2................: %ld (%ld not replaycount checked)\n"
			"message pair M14E4................: %ld (%ld not replaycount checked)\n"
			"message pair M32E2................: %ld (%ld not replaycount checked)\n"
			"message pair M32E3................: %ld (%ld not replaycount checked)\n"
			"message pair M34E3................: %ld (%ld not replaycount checked)\n"
			"message pair M34E4................: %ld (%ld not replaycount checked)"
			"\n", totalrecords, wldcount, noessidcount, xverc1, xverc2, wpakv1c, wpakv2c, wpakv3c, wpakv4c, mp0c, mp80c, mp1c, mp81c, mp2c, mp82c, mp3c, mp83c, mp4c, mp84c, mp5c, mp85c);

	if(noncecorr == true)
		fprintf(stdout, "\x1B[32mhashcat --nonce-error-corrections is working on that file\x1B[0m\n");
	}

return;
}
/*===========================================================================*/
long int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return 0;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return 0;
	}

if((statinfo.st_size % HCX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return 0;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxinname);
	return 0;
	}

hcxdata = malloc(statinfo.st_size);
if(hcxdata == NULL)
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		return 0;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
if(hcxsize != statinfo.st_size)
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return 0;
	}
fclose(fhhcx);
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage..: %s <options>\n"
	"example: %s -i <hashfile> show general informations about file\n"
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
	"-h        : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname);
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
		}
	}

hcxorgrecords = readhccapx(hcxinname);

if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

writehcxinfo(hcxorgrecords, outmode);

if(hcxdata != NULL)
	free(hcxdata);

if(infoname != NULL)
	fclose(stdout);

return EXIT_SUCCESS;
}

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

struct hccap
{
  char essid[36];
  uint8_t mac1[6];	/* bssid */
  uint8_t mac2[6];	/* client */
  uint8_t nonce1[32];	/* snonce client */
  uint8_t nonce2[32];	/* anonce bssid */
  uint8_t eapol[256];
  int eapol_size;
  int keyver;
  uint8_t keymic[16];
};
typedef struct hccap hccap_t;
#define	HCCAP_SIZE (sizeof(hccap_t))

/*===========================================================================*/
/* globale Variablen */


char *hcxoutname = NULL;
char *essidoutname = NULL;
/*===========================================================================*/
int checkessid(uint8_t essid_len, char *essid)
{
int p;

if(essid_len == 0)
	return FALSE;

if(essid_len > 32)
	return FALSE;

for(p = 0; p < essid_len; p++)
	if ((essid[p] < 0x20) || (essid[p] > 0x7e))
		return FALSE;
return TRUE;
}
/*===========================================================================*/
uint8_t geteapkey(uint8_t *eapdata)
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
void processhc(long int hcsize, hccap_t *zeiger)
{
FILE *fhhcx = NULL;
FILE *fhessid = NULL;
long int p;
int essid_len;
uint8_t m;

hcx_t hcxrecord;

char essidout[36];

if(hcxoutname != NULL)
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", hcxoutname);
		return;
		}
	}

if(essidoutname != NULL)
	{
	if((fhessid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidoutname);
		return;
		}
	}

for(p = 0; p < hcsize; p++)
	{
	memset(&essidout, 0, 36);
	memcpy(&essidout, zeiger->essid, 36);
	essid_len = strlen(essidout);
	if(essid_len > 32)
		{
		zeiger++;
		continue;
		}

	if(fhessid != NULL)
		{
		if(checkessid(essid_len, essidout) == TRUE)
			fprintf(fhessid, "%s\n", essidout);
		}

	if(fhhcx != 0)
		{
		if(zeiger->essid[0] == 0)
			{
			zeiger++;
			continue;
			}
		memset(&hcxrecord, 0, HCX_SIZE);
		hcxrecord.signature = HCCAPX_SIGNATURE;
		hcxrecord.version = HCCAPX_VERSION;
		m = geteapkey(zeiger->eapol);
		if(m == 2)
			hcxrecord.message_pair = MESSAGE_PAIR_M12E2;
		if(m == 3)
			hcxrecord.message_pair = MESSAGE_PAIR_M32E3;
		if(m == 4)
			hcxrecord.message_pair = MESSAGE_PAIR_M14E4;
		hcxrecord.essid_len = essid_len;
		memcpy(hcxrecord.essid, zeiger->essid, essid_len);
		hcxrecord.keyver = geteapkeyver(zeiger->eapol);
		memcpy(hcxrecord.mac_ap.addr, zeiger->mac1, 6);
		memcpy(hcxrecord.nonce_ap, zeiger->nonce2, 32);
		memcpy(hcxrecord.mac_sta.addr, zeiger->mac2, 6);
		memcpy(hcxrecord.nonce_sta, zeiger->nonce1, 32);
		hcxrecord.eapol_len = zeiger->eapol_size;
		memcpy(hcxrecord.eapol, zeiger->eapol, zeiger->eapol_size +4);
		memcpy(hcxrecord.keymic, zeiger->keymic, 16);
		memset(&hcxrecord.eapol[0x51], 0, 16);
		fwrite(&hcxrecord, HCX_SIZE, 1,fhhcx);
		}
	zeiger++;
	}

if(fhessid != NULL)
	fclose(fhessid);

if(fhhcx != 0)
	fclose(fhhcx);

return;	
}
/*===========================================================================*/
void processhcx(long int hcxsize, hcx_t *zeiger)
{
FILE *fhhcx = NULL;
FILE *fhessid = NULL;
long int p;
uint8_t m;
char essidout[36];

if(hcxoutname != NULL)
	{
	if((fhhcx = fopen(hcxoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", hcxoutname);
		return;
		}
	}

if(essidoutname != NULL)
	{
	if((fhessid = fopen(essidoutname, "a")) == NULL)
		{
		fprintf(stderr, "error opening essid file %s\n", essidoutname);
		return;
		}
	}

for(p = 0; p < hcxsize; p++)
	{
	if(zeiger->signature == HCCAPX_SIGNATURE)
		{
		if(fhessid != NULL)
			{
			memset(&essidout, 0, 36);
			memcpy(&essidout, zeiger->essid, zeiger->essid_len);
			if(checkessid(zeiger->essid_len, essidout) == TRUE)
				fprintf(fhessid, "%s\n", essidout);
			}

		if(fhhcx != 0)
			{
			m = geteapkey(zeiger->eapol);
			if(m == 2)
				zeiger->message_pair = MESSAGE_PAIR_M12E2;
			if(m == 3)
				zeiger->message_pair = MESSAGE_PAIR_M32E3;
			if(m == 4)
				zeiger->message_pair = MESSAGE_PAIR_M14E4;
			zeiger->keyver = geteapkeyver(zeiger->eapol);
			fwrite(zeiger, HCX_SIZE, 1,fhhcx);
			}

		}
	zeiger++;
	}

if(fhessid != NULL)
	fclose(fhessid);
	
if(fhhcx != 0)	
	fclose(fhhcx);
	
return;	
}
/*===========================================================================*/
int processdata(char *hcinname)
{
struct stat statinfo;
FILE *fhhc;
uint8_t *data = NULL;
hcx_t *zeigerhcx = NULL;
hccap_t *zeigerhc = NULL;
long int datasize = 0;
long int hcxsize = 0;
long int hcsize = 0;

if(hcinname == NULL)
	return FALSE;

if(stat(hcinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcinname);
	return FALSE;
	}

if((fhhc = fopen(hcinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s\n", hcinname);
	return FALSE;
	}

data = malloc(statinfo.st_size);
if(data == NULL)	
	{
	fprintf(stderr, "out of memory to store hc data\n");
	return FALSE;
	}


datasize = fread(data, 1, statinfo.st_size, fhhc);
if(datasize != statinfo.st_size)	
	{
	fprintf(stderr, "error reading hc file %s\n", hcinname);
	free(data);
	return FALSE;
	}
fclose(fhhc);

hcxsize = datasize / HCX_SIZE;
hcsize = datasize / HCCAP_SIZE;


zeigerhcx = (hcx_t*)(data);
zeigerhc = (hccap_t*)(data);
if(((datasize % HCX_SIZE) == 0) && (zeigerhcx->signature == HCCAPX_SIGNATURE))
	{
	printf("%ld records readed from %s\n", hcxsize, hcinname);
	processhcx(hcxsize, zeigerhcx); 
	}

else if((datasize % HCCAP_SIZE) == 0)
	{
	printf("%ld records readed from %s\n", hcsize, hcinname);
	processhc(hcsize, zeigerhc); 
	}
else
	printf("invalid file size %s\n", hcinname);


free(data);
return TRUE;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.hccap(x)] [input.hccap(x)] ...\n"
	"\n"
	"options:\n"
	"-o <file> : output hccapx file\n"
	"-e <file> : output essidlist\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int index;
int auswahl;

char *eigenname = NULL;
char *eigenpfadname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "o:e:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'o':
		hcxoutname = optarg;
		break;

		case 'e':
		essidoutname = optarg;
		break;

		default:
		usage(eigenname);
		break;
		}
	}

for (index = optind; index < argc; index++)
	{
	if(processdata(argv[index]) == FALSE)
		{
		fprintf(stderr, "error processing records from %s\n", (argv[index]));
		exit(EXIT_FAILURE);
		}
	}


return EXIT_SUCCESS;
}

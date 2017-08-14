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
#include "common.c"
#include "com_md5_64.c"

struct hcxhrc
{
 uint32_t salt_buf[64];
 uint32_t pke[25];
 uint32_t eapol[64 + 16];
 uint32_t keymic[4];
};
typedef struct hcxhrc hcxhrc_t;


/*===========================================================================*/
/* globale Variablen */

hcx_t *hcxdata = NULL;
/*===========================================================================*/
void showhashrecord(hcx_t *hcxrecord, FILE *fhhash)
{
int i;
hcxhrc_t hashrec;
uint32_t hash[4];
uint32_t block[16];
uint8_t *block_ptr = (uint8_t*)block;
uint8_t *pke_ptr = (uint8_t*)hashrec.pke;
uint8_t *eapol_ptr = (uint8_t*)hashrec.eapol;

char essidstring[36];

hash[0] = 0;
hash[1] = 1;
hash[2] = 2;
hash[3] = 3;
memset(&block, 0, sizeof(block));

memset(&hashrec, 0, sizeof(hashrec));
memcpy(&hashrec.salt_buf, hcxrecord->essid, hcxrecord->essid_len);

memcpy(pke_ptr, "Pairwise key expansion", 23);
if(memcmp(hcxrecord->mac_ap.addr, hcxrecord->mac_sta.addr, 6) < 0)
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_ap.addr,  6);
	memcpy(pke_ptr + 29, hcxrecord->mac_sta.addr, 6);
	}
else
	{
	memcpy(pke_ptr + 23, hcxrecord->mac_sta.addr, 6);
	memcpy(pke_ptr + 29, hcxrecord->mac_ap.addr,  6);
	}

if(memcmp(hcxrecord->nonce_ap, hcxrecord->nonce_sta, 32) < 0)
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_ap,  32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_sta, 32);
	}
else
	{
	memcpy (pke_ptr + 35, hcxrecord->nonce_sta, 32);
	memcpy (pke_ptr + 67, hcxrecord->nonce_ap,  32);
	}
for (int i = 0; i < 25; i++)
	{
	hashrec.pke[i] = byte_swap_32(hashrec.pke[i]);
	}

memcpy(eapol_ptr, hcxrecord->eapol, hcxrecord->eapol_len);
memset(eapol_ptr + hcxrecord->eapol_len, 0, (256 +64) -hcxrecord->eapol_len);
eapol_ptr[hcxrecord->eapol_len] = 0x80;

memcpy (&hashrec.keymic, hcxrecord->keymic, 16);

if(hcxrecord->keyver == 1)
	{
	// nothing to do
	}
else
	{
	for(i = 0; i < 64; i++)
		{
		hashrec.eapol[i] = byte_swap_32 (hashrec.eapol[i]);
		}
	hashrec.keymic[0] = byte_swap_32(hashrec.keymic[0]);
	hashrec.keymic[1] = byte_swap_32(hashrec.keymic[1]);
	hashrec.keymic[2] = byte_swap_32(hashrec.keymic[2]);
	hashrec.keymic[3] = byte_swap_32(hashrec.keymic[3]);
	}

for(i = 0; i < 16; i++)
	block[i] = hashrec.salt_buf[i];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.pke[i +0];
md5_64(block, hash);

for(i = 0; i < 9; i++)
	block[i] = hashrec.pke[i +16];
md5_64(block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +0];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +16];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i +32];
md5_64 (block, hash);

for(i = 0; i < 16; i++)
	block[i] = hashrec.eapol[i + 48];
md5_64 (block, hash);

for(i = 0; i < 6; i++)
	block_ptr[i +0] = hcxrecord->mac_ap.addr[i];
for(i = 0; i < 6; i++)
	block_ptr[i +6] = hcxrecord->mac_sta.addr[i];
md5_64 (block, hash);

for(i = 0; i < 32; i++)
	block_ptr[i +0] = hcxrecord->nonce_ap[i];
for(i = 0; i < 32; i++)
	block_ptr[i +32] = hcxrecord->nonce_sta[i];
md5_64 (block, hash);

block[0] = hashrec.keymic[0];
block[1] = hashrec.keymic[1];
block[2] = hashrec.keymic[2];
block[3] = hashrec.keymic[3];
md5_64 (block, hash);

memset(&essidstring, 0, 36);
memcpy(&essidstring, hcxrecord->essid, hcxrecord->essid_len);
fprintf(fhhash, "%08x%08x%08x%08x:%02x%02x%02x%02x%02x%02x:%02x%02x%02x%02x%02x%02x:%s\n",
hash[0], hash[1], hash[2], hash[3],
hcxrecord->mac_ap.addr[0], hcxrecord->mac_ap.addr[1], hcxrecord->mac_ap.addr[2], hcxrecord->mac_ap.addr[3], hcxrecord->mac_ap.addr[4], hcxrecord->mac_ap.addr[5],
hcxrecord->mac_sta.addr[0], hcxrecord->mac_sta.addr[1], hcxrecord->mac_sta.addr[2], hcxrecord->mac_sta.addr[3], hcxrecord->mac_sta.addr[4], hcxrecord->mac_sta.addr[5],
essidstring);

return;
}
/*===========================================================================*/
void hashhcx(long int hcxrecords, FILE* fhhash)
{
hcx_t *zeigerhcx;
long int c;

c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	showhashrecord(zeigerhcx, fhhash);
	c++;
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
		return false;
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
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage..: %s <options>\n"
	"example: %s -i <hashfile> show general informations about file\n"
	"\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-S <file> : output info for identified hccapx handshake to file\n"
	"-h        : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
long int hcxorgrecords = 0;
FILE *fhhash = NULL;
char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *hashoutname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:S:hv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'S':
		hashoutname = optarg;
		break;

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

hcxorgrecords = readhccapx(hcxinname);

if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

if(hashoutname != NULL)
	{
	if((fhhash = fopen(hashoutname, "ab")) == NULL)
		{
		fprintf(stderr, "error opening hccapx file %s\n", hashoutname);
		exit(EXIT_FAILURE);
		}
	hashhcx(hcxorgrecords, fhhash);
	fclose(fhhash);
	}

if(hcxdata != NULL)
	free(hcxdata);

return EXIT_SUCCESS;
}

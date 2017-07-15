#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdio_ext.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include "common.h"
#include "common.c"

/*===========================================================================*/
int hex2bin(const char *str, uint8_t *bytes, size_t blen)
{
size_t c;
uint8_t pos;
uint8_t idx0;
uint8_t idx1;

const uint8_t hashmap[] =
{
0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, // 01234567
0x08, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 89:;<=>?
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // @ABCDEFG
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // HIJKLMNO
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PQRSTUVW
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // XYZ[\]^_
0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00, // `abcdefg
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // hijklmno
};

for(c = 0; c < blen; c++)
	{
	if(str[c] < '0')
		return FALSE;
	if(str[c] > 'f')
		return FALSE;
	if((str[c] > '9') && (str[c] < 'A'))
		return FALSE;
	if((str[c] > 'F') && (str[c] < 'a'))
		return FALSE;
	}

bzero(bytes, blen);
for (pos = 0; ((pos < (blen*2)) && (pos < strlen(str))); pos += 2)
	{
	idx0 = ((uint8_t)str[pos+0] & 0x1F) ^ 0x10;
	idx1 = ((uint8_t)str[pos+1] & 0x1F) ^ 0x10;
	bytes[pos/2] = (uint8_t)(hashmap[idx0] << 4) | hashmap[idx1];
	};
return TRUE;
}
/*===========================================================================*/
char *base64(const unsigned char *input, int len)
{
BIO *bmem, *b64;
BUF_MEM *bptr;
b64 = BIO_new(BIO_f_base64());
bmem = BIO_new(BIO_s_mem());
b64 = BIO_push(b64, bmem);
BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
BIO_write(b64, input, len);
BIO_flush(b64);
BIO_get_mem_ptr(b64, &bptr);
char *buff = (char *)malloc(bptr->length);
memcpy(buff, bptr->data, bptr->length-1);
buff[bptr->length-1] = 0;
BIO_free_all(b64);
return buff;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-e <essid> : input single essid (networkname: 1 .. 32 characters)\n"
	"-p <pmk>   : input plainmasterkey (64 xdigits)\n"
	"-h         : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
int essidlen = 0;
int pmklen = 0;
char *eigenname = NULL;
char *eigenpfadname = NULL;
char *pmkname = NULL;
char *essidname = NULL;
char *hashrecord = NULL;

unsigned char essidstr[34];
unsigned char pmkstr[64];

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "e:p:h")) != -1)
	{
	switch (auswahl)
		{
		case 'e':
		essidname = optarg;
		essidlen = strlen(essidname);
		if((essidlen < 1) || (essidlen > 32))
			{
			fprintf(stderr, "error wrong essid len)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'p':
		pmkname = optarg;
		pmklen = strlen(pmkname);
		if(pmklen != 64)
			{
			fprintf(stderr, "error wrong plainmasterkey len)\n");
			exit(EXIT_FAILURE);
			}
		if(hex2bin(pmkname, pmkstr, 64) != TRUE)
			{
			fprintf(stderr, "error wrong plainmasterkey\n");
			exit(EXIT_FAILURE);
			}
 		break;

		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

if((essidname == NULL) || (pmkname == NULL))
	{
	usage(eigenname);
	return EXIT_SUCCESS;
	}

printf("\nuse hashcat hash-mode -m 12000 to get password\n");

memset(essidstr, 0, 34);
memcpy(&essidstr, essidname, essidlen);
hashrecord = base64(essidstr, essidlen);
printf("sha1:4096:%s:", hashrecord);
free(hashrecord);

hashrecord = base64(pmkstr, 32);
printf("%s\n\n", hashrecord);
free(hashrecord);



return EXIT_SUCCESS;
}

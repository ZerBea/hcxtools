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
#include <openssl/evp.h>
#include "common.h"

#define COWPATTY_SIGNATURE 0x43575041L

struct cow_head
{
 uint32_t magic;
 uint8_t reserved1[3];
 uint8_t essidlen;
 uint8_t essid[32];
};
typedef struct cow_head cow_head_t;
#define	COWHEAD_SIZE (sizeof(cow_head_t))


/*===========================================================================*/
/* globale Variablen */

uint8_t progende = FALSE;
/*===========================================================================*/
void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL))
	{
	progende = TRUE;
	}
return;
}
/*===========================================================================*/
size_t chop(char *buffer, size_t len)
{
char *ptr = buffer +len -1;

while(len)
	{
	if (*ptr != '\n')
		break;
	*ptr-- = 0;
	len--;
	}

while(len)
	{
	if (*ptr != '\r')
		break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
int fgetline(FILE *inputstream, size_t size, char *buffer)
{
if(feof(inputstream))
	return -1;
char *buffptr = fgets (buffer, size, inputstream);

if(buffptr == NULL)
	return -1;

size_t len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
void filepmkout(FILE *pwlist, FILE *fhascii,  FILE *fhasciipw, FILE *fhcow, char *essidname, uint8_t essidlen)
{
int pwlen;
int c;
int cr;
cow_head_t cow;
uint8_t cowreclen = 0;
long int pmkcount = 0;
long int skippedcount = 0;
unsigned char salt[64];
char password[64];
unsigned char pmk[64];


signal(SIGINT, programmende);
memcpy(&salt, essidname, essidlen);
if((fhcow != NULL) && (essidname != NULL))
	{
	memset(&cow, 0, COWHEAD_SIZE);
	cow.magic = COWPATTY_SIGNATURE;
	memcpy(cow.essid, essidname, essidlen);
	cow.essidlen = essidlen;
	cr = fwrite(&cow, COWHEAD_SIZE, 1, fhcow);
	if(cr != 1)
		{
		fprintf(stderr, "error writing cowpatty file\n");
		exit(EXIT_FAILURE);
		}
	}

while((progende != TRUE) && ((pwlen = fgetline(pwlist, 64, password)) != -1))
	{
	if((pwlen < 8) || pwlen > 63)
		{
		skippedcount++;
		continue;
		}

	if( PKCS5_PBKDF2_HMAC_SHA1(password, pwlen, salt, essidlen, 4096, 32, pmk) != 0 )
		{
		cowreclen = sizeof(cowreclen) + pwlen + 32;
		if(fhcow != NULL)
			{
			cr = fwrite(&cowreclen, sizeof(cowreclen), 1, fhcow);
			if(cr != 1)
				{
				fprintf(stderr, "error writing cowpatty file\n");
				exit(EXIT_FAILURE);
				}
			fprintf(fhcow, "%s", password);
			cr = fwrite(&pmk, sizeof(uint8_t), 32, fhcow);
			if(cr != 32)
				{
				fprintf(stderr, "error writing cowpatty file\n");
				exit(EXIT_FAILURE);
				}
			}
		for(c = 0; c< 32; c++)
			{
			if(fhascii != NULL)
				fprintf(fhascii, "%02x", pmk[c]);

			if(fhasciipw != NULL)
				fprintf(fhasciipw, "%02x", pmk[c]);
			}
		if(fhascii != NULL)
			fprintf(fhascii, "\n");

		if(fhasciipw != NULL)
			fprintf(fhasciipw, ":%s\n", password);

		pmkcount++;
		if((pmkcount %1000) == 0)
			printf("\r%ld", pmkcount);
		}
	}	

printf("\r%ld plainmasterkeys generated, %ld password(s) skipped\n", pmkcount, skippedcount);
return;
}
/*===========================================================================*/
void singlepmkout(char *pwname, int pwlen, char *essidname, int essidlen)
{
int c;

char password[64];
unsigned char salt[64];
unsigned char pmk[64];

memcpy(&password, pwname, pwlen);
memcpy(&salt, essidname, essidlen);

fprintf(stdout, "\n"
		"essid (networkname): %s\n"
		"password...........: %s\n"
		"plainmasterkey.....: "
		, essidname, pwname);
if( PKCS5_PBKDF2_HMAC_SHA1(password, pwlen, salt, essidlen, 4096, 32, pmk) != 0 )
	{
	for(c = 0; c< 32; c++)
		{
		fprintf(stdout, "%02x", pmk[c]);
		}
	fprintf(stdout, "\n\n");
	}
return;	
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>\n"
	"\n"
	"options:\n"
	"-e <essid>    : input single essid (networkname: 1 .. 32 characters)\n"
	"-p <password> : input single password (8 .. 63 characters)\n"
	"-i <file>     : input passwordlist\n"
	"-a <file>     : output plainmasterkeys as ASCII file (hashcat -m 2501)\n"
	"-A <file>     : output plainmasterkeys:password as ASCII file\n"
	"-c <file>     : output cowpatty hashfile (existing file will be replaced)\n"
	"-h            : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
FILE *fhpwlist = NULL;
FILE *fhascii = NULL;
FILE *fhasciipw = NULL;
FILE *fhcow = NULL;
int auswahl;

int pwlen = 0;
uint8_t essidlen = 0;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *pwname = NULL;
char *essidname = NULL;



eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "p:e:i:a:A:c:h")) != -1)
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
		pwname = optarg;
		pwlen = strlen(pwname);
		if((pwlen < 8) || (pwlen > 63))
			{
			fprintf(stderr, "error wrong password len)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'i':
		if((fhpwlist = fopen(optarg, "r")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'a':
		if((fhascii = fopen(optarg, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'A':
		if((fhasciipw = fopen(optarg, "a")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
			exit(EXIT_FAILURE);
			}
		break;

		case 'c':
		if((fhcow = fopen(optarg, "w")) == NULL)
			{
			fprintf(stderr, "error opening %s\n", optarg);
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

if((essidname != NULL) && (pwname != NULL))
	singlepmkout(pwname, pwlen, essidname, essidlen);

else if(essidname != NULL)
	filepmkout(fhpwlist, fhascii, fhasciipw, fhcow, essidname, essidlen);



if(fhpwlist != NULL)
	fclose(fhpwlist);

if(fhascii != NULL)
	fclose(fhascii);

return EXIT_SUCCESS;
}

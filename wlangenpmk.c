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
#include <openssl/evp.h>
#include "common.h"

/*===========================================================================*/
/* globale Variablen */

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
		"planmasterkey......: "
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
	"-h            : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;

int pwlen = 0;
int essidlen = 0;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *pwname = NULL;
char *essidname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "p:e:h")) != -1)
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

return EXIT_SUCCESS;
}

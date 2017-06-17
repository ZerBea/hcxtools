#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio_ext.h>
#include <curl/curl.h>
#include "common.h"


/*===========================================================================*/
/* globale Konstante */

const char *wpasecurl = "http://wpa-sec.stanev.org";

/*===========================================================================*/
int testwpasec()
{
CURL *curl;
CURLcode res = 0;

printf("connecting to %s\n", wpasecurl);
curl_global_init(CURL_GLOBAL_ALL);
curl = curl_easy_init();
if(curl)
	{
	curl_easy_setopt(curl, CURLOPT_URL, wpasecurl);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
	curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
		fprintf(stderr, "couldn't connect to %s: %s\n", wpasecurl, curl_easy_strerror(res));
	curl_easy_cleanup(curl);
	}
curl_global_cleanup();

return res;
}
/*===========================================================================*/
void sendcap2wpasec(char *sendcapname)
{
CURL *curl;
CURLcode res;
 
struct curl_httppost *formpost=NULL;
struct curl_httppost *lastptr=NULL;
struct curl_slist *headerlist=NULL;
static const char buf[] = "Expect:";

printf("uploading %s to %s\n", sendcapname, wpasecurl);
curl_global_init(CURL_GLOBAL_ALL);
curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_FILE, sendcapname, CURLFORM_END);
curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "webfile", CURLFORM_COPYCONTENTS, sendcapname, CURLFORM_END);
curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "submit", CURLFORM_COPYCONTENTS, "Submit capture", CURLFORM_END);
curl = curl_easy_init();
headerlist = curl_slist_append(headerlist, buf);
if(curl)
	{
	curl_easy_setopt(curl, CURLOPT_URL, wpasecurl);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30L);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	res = curl_easy_perform(curl);
	if(res != CURLE_OK)
		fprintf(stderr, "\x1B[31mupload to %s failed: %s\x1B[0m\n\n", wpasecurl, curl_easy_strerror(res));

	else
		printf("\x1B[32mupload done\x1B[0m\n\n");

	curl_easy_cleanup(curl);
	curl_formfree(formpost);
	curl_slist_free_all(headerlist);
	}
return;
}
/*===========================================================================*/
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.cap] [input.cap] ...\n"
	"       %s <options> *.cap\n"
	"       %s <options> *.*\n"
	"\n"
	"options:\n"
	"-h        : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
struct stat statinfo;
int auswahl;
int index;

char *eigenname = NULL;
char *eigenpfadname = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "hv")) != -1)
	{
	switch (auswahl)
		{
		case 'h':
		usage(eigenname);
		break;

		default:
		usage(eigenname);
		break;
		}
	}

if(testwpasec() != CURLE_OK)
	return EXIT_SUCCESS;

for(index = optind; index < argc; index++)
	{
	if(stat(argv[index], &statinfo) == 0)
		sendcap2wpasec(argv[index]);
	}


return EXIT_SUCCESS;
}

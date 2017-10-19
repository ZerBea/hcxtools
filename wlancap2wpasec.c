#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>

#ifdef __APPLE__
#define strdupa strdup
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include <curl/curl.h>
#include "common.h"


/*===========================================================================*/
/* globale Konstante */

long int uploadcountok;
long int uploadcountfailed;
const char *wpasecurl = "http://wpa-sec.stanev.org";
/*===========================================================================*/
int testwpasec(long int timeout)
{
CURL *curl;
CURLcode res = 0;

printf("connecting to %s\n", wpasecurl);
curl_global_init(CURL_GLOBAL_ALL);
curl = curl_easy_init();
if(curl)
	{
	curl_easy_setopt(curl, CURLOPT_URL, wpasecurl);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
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
bool sendcap2wpasec(char *sendcapname, long int timeout)
{
CURL *curl;
CURLcode res;
bool uploadflag = true;

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
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	res = curl_easy_perform(curl);
	if(res == CURLE_OK)
		{
		printf("\x1B[32mupload done\x1B[0m\n\n");
		}
	else
		{
		fprintf(stderr, "\x1B[31mupload to %s failed: %s\x1B[0m\n\n", wpasecurl, curl_easy_strerror(res));
		uploadflag = false;
		}

	curl_easy_cleanup(curl);
	curl_formfree(formpost);
	curl_slist_free_all(headerlist);
	}
return uploadflag;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage: %s <options> [input.cap] [input.cap] ...\n"
	"       %s <options> *.cap\n"
	"       %s <options> *.*\n"
	"\n"
	"options:\n"
	"-t <seconds> : set connection timeout (default 30 seconds)\n"
	"-h           : this help\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
struct stat statinfo;
int auswahl;
int index;
long int timeout = 30;
char *eigenname;
char *eigenpfadname;

uploadcountok = 0;
uploadcountfailed = 0;
eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "t:hv")) != -1)
	{
	switch (auswahl)
		{
		case 't':
		timeout = strtol(optarg, NULL, 10);
		if(timeout < 1)
			{
			fprintf(stderr, "wrong connection timeout\nsetting connection timeout to 30 seconds\n");
			timeout = 30;
			}
		break;

		default:
		usage(eigenname);
		}
	}

if(testwpasec(timeout) != CURLE_OK)
	return EXIT_SUCCESS;

for(index = optind; index < argc; index++)
	{
	if(stat(argv[index], &statinfo) == 0)
		{
		if(sendcap2wpasec(argv[index], timeout) == false)
			{
			if(sendcap2wpasec(argv[index], 60) == true)
				{
				uploadcountok++;
				}
			else
				uploadcountfailed++;
			}
		else
			uploadcountok++;
		}
	}

if(uploadcountok == 1)
	printf("\x1B[32m%ld cap uploaded to %s\x1B[0m\n", uploadcountok, wpasecurl);

if(uploadcountok > 1)
	printf("\x1B[32m%ld caps uploaded to %s\x1B[0m\n", uploadcountok, wpasecurl);

if(uploadcountfailed == 1)
	printf("\x1B[31m%ld cap failed to upload to %s\x1B[0m\n", uploadcountfailed, wpasecurl);

if(uploadcountfailed > 1)
	printf("\x1B[31m%ld caps failed to upload to %s\x1B[0m\n", uploadcountfailed, wpasecurl);

return EXIT_SUCCESS;
}

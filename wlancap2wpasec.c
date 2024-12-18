#define _GNU_SOURCE
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <curl/curl.h>

/*===========================================================================*/
/* globale Konstante */

struct memory
{
char *response;
size_t size;
};

static long int uploadcountok;
static long int uploadcountfailed;
static const char *wpasecurl = "https://wpa-sec.stanev.org";
static bool removeflag = false;
static struct memory *curlmem;
/*===========================================================================*/
static int testwpasec(long int timeout)
{
CURL *curl;
CURLcode res = CURLE_OK;

fprintf(stdout, "connecting to %s\n", wpasecurl);
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
static size_t cb(void *data, size_t size, size_t nmemb, void *userp)
{
char *ptr;
size_t realsize = size *nmemb;
curlmem = (struct memory*)userp;
 
ptr = (char*)realloc(curlmem->response, curlmem->size +realsize +1);
if(ptr == NULL) return 0;
curlmem->response = ptr;
memcpy(&(curlmem->response[curlmem->size]), data, realsize);
curlmem->size += realsize;
curlmem->response[curlmem->size] = 0;
return realsize;
}
/*===========================================================================*/
static bool sendcap2wpasec(char *sendcapname, long int timeout, char *keyheader, char *emailheader)
{
CURL *curl;
CURLcode res;
curl_mime *mime;
curl_mimepart *part;
bool uploadflag = true;
int ret;

struct curl_slist *headerlist=NULL;
static const char buf[] = "Expect:";
struct memory chunk;

fprintf(stdout, "uploading %s to %s\n", sendcapname, wpasecurl);
memset(&chunk, 0, sizeof(chunk));
curl_global_init(CURL_GLOBAL_ALL);

curl = curl_easy_init();
mime = curl_mime_init(curl);
part = curl_mime_addpart(mime);

curl_mime_filedata(part, sendcapname);
curl_mime_type(part, "file");
curl_mime_name(part, "file");

if(emailheader != NULL)
	{
	curl_mime_data(part, emailheader, CURL_ZERO_TERMINATED);
	curl_mime_name(part, "email");
	}

headerlist = curl_slist_append(headerlist, buf);
if(curl)
	{
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
	curl_easy_setopt(curl, CURLOPT_URL, wpasecurl);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout);
	curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
	if(keyheader) curl_easy_setopt(curl, CURLOPT_COOKIE, keyheader);
	res = curl_easy_perform(curl);
	if(res == CURLE_OK)
		{
		if(curlmem->response != NULL)
			{
			fprintf(stdout, "\n%s\n\n", curlmem->response);
			if(removeflag == true)
				{
				ret = remove(sendcapname);
				if(ret != 0) fprintf(stdout, "couldn't remove %s\n", sendcapname);
				}
			free(curlmem->response);
			}
		else
			{
			fprintf(stdout, "upload not confirmed by server\n");
			uploadflag = false;
			}
		}
	else
		{
		fprintf(stderr, "\n\x1B[31mupload to %s failed: %s\x1B[0m\n\n", wpasecurl, curl_easy_strerror(res));
		uploadflag = false;
		}
	curl_easy_cleanup(curl);
	curl_mime_free(mime);
	curl_slist_free_all(headerlist);
	}
return uploadflag;
}
/*===========================================================================*/
__attribute__ ((noreturn))
void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n"
	"usage: %s <options>  [input.pcapng] [input.pcap] [input.cap] [input.pcapng.gz]...\n"
	"       %s <options> *.pcapng\n"
	"       %s <options> *.gz\n"
	"       %s <options> *.*\n"
	"\n"
	"options:\n"
	"-k <key>           : wpa-sec user key\n"
	"-u <url>           : set user defined URL\n"
	"                     default = %s\n"
	"-t <seconds>       : set connection timeout\n"
	"                     default = 30 seconds\n"
	"-e <email address> : set email address, if required\n"
	"-R                 : remove cap if upload was successful\n"
	"-h                 : this help\n"
	"-v                 : show version\n"
	"\n"
	"Do not merge different cap files to a single cap file.\n"
	"This will lead to unexpected behaviour on ESSID changes\n"
	"or different link layer types.\n"
	"To ‎remove unnecessary packets, run tshark:\n"
	"tshark -r input.cap -R \"(wlan.fc.type_subtype == 0x00 || wlan.fc.type_subtype == 0x02 || wlan.fc.type_subtype == 0x04 || wlan.fc.type_subtype == 0x05 || wlan.fc.type_subtype == 0x08 || eapol)\" -2 -F pcapng -w output.pcapng\n"
	"To reduce the size of the cap file, compress it with gzip:\n"
	"gzip capture.pcapng\n"
	"\n"
	"\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname, eigenname, eigenname, eigenname, wpasecurl);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
struct stat statinfo;
int auswahl;
int index;
char keyheader[4+32+1+2] = {0};
char *emailaddr = NULL;
long int timeout = 30;
uploadcountok = 0;
uploadcountfailed = 0;

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "k:u:t:e:Rhv")) != -1)
	{
	switch (auswahl)
		{
		case 'k':
		if((strlen(optarg) == 32) && (optarg[strspn(optarg, "0123456789abcdefABCDEF")] == 0))
			{
			snprintf(keyheader, sizeof(keyheader), "key=%s", optarg);
			fprintf(stdout, "\x1B[32muser key set\x1B[0m\n");
			}
		else
			{
			fprintf(stdout, "wrong user key value\n");
			}
		break;

		case 'u':
		wpasecurl = optarg;
		break;

		case 't':
		timeout = strtol(optarg, NULL, 10);
		if(timeout < 1)
			{
			fprintf(stdout, "wrong connection timeout\nsetting connection timeout to 30 seconds\n");
			timeout = 30;
			}
		break;

		case 'e':
		emailaddr = optarg;
		if(strlen(emailaddr) > 120)
			{
			fprintf(stderr, "email address is too long\n");
			exit (EXIT_FAILURE);
			}
		break;

		case 'R':
		removeflag = true;
		break;

		case 'v':
		version(basename(argv[0]));
		break;

		default:
		usage(basename(argv[0]));
		}
	}

if(testwpasec(timeout) != CURLE_OK) return EXIT_SUCCESS;

for(index = optind; index < argc; index++)
	{
	if(stat(argv[index], &statinfo) == 0)
		{
		if(sendcap2wpasec(argv[index], timeout, keyheader, emailaddr) == false)
			{
			if(sendcap2wpasec(argv[index], 60, keyheader, emailaddr) == true) uploadcountok++;
			else uploadcountfailed++;
			}
		else uploadcountok++;
		}
	else fprintf(stdout, "file not found: %s\n", argv[index]);
	}

if(uploadcountok == 1) fprintf(stdout, "\x1B[32m%ld cap uploaded to %s\x1B[0m\n", uploadcountok, wpasecurl);
if(uploadcountok > 1) fprintf(stdout, "\x1B[32m%ld caps uploaded to %s\x1B[0m\n", uploadcountok, wpasecurl);
if(uploadcountfailed == 1) fprintf(stdout, "\x1B[31m%ld cap failed to upload to %s\x1B[0m\n", uploadcountfailed, wpasecurl);
if(uploadcountfailed > 1) fprintf(stdout, "\x1B[31m%ld caps failed to upload to %s\x1B[0m\n", uploadcountfailed, wpasecurl);
return EXIT_SUCCESS;
}

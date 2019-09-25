#define _GNU_SOURCE
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <limits.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>

#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/version.h"
#include "include/hcxmactool.h"
#include "include/strings.c"
#include "include/fileops.c"

/*===========================================================================*/
/* global var */

static int ouicount;

static int pmkidcount = 0;
static int hccapxcount = 0;

static intoui_t *ouilist = NULL;
static intpmkid_t *pmkidlist = NULL;
static inthccapx_t *hccapxlist = NULL;

static char *hccapxinname = NULL;
static char *pmkidinname = NULL;

static char *hccapxoutname = NULL;
static char *pmkidoutname = NULL;

static char *vendorapname = NULL;
static char *vendorstaname = NULL;

static bool ouiapflag = false;
static bool nicapflag = false;
static bool macapflag = false;
static bool vendorapflag = false;

static bool ouistaflag = false;
static bool nicstaflag = false;
static bool macstaflag = false;
static bool vendorstaflag = false;

static uint8_t ouiap[3];
static uint8_t nicap[3];
static uint8_t macap[6];

static uint8_t ouista[3];
static uint8_t nicsta[3];
static uint8_t macsta[6];

static char separator = ':';
/*===========================================================================*/
static void globalclose()
{
if(ouilist != NULL)
	{
	free(ouilist);
	}

if(pmkidlist != NULL)
	{
	free(pmkidlist);
	}

if(hccapxlist != NULL)
	{
	free(hccapxlist);
	}
return;
}
/*===========================================================================*/
static bool isvendorsta(uint8_t *macsta)
{
static intoui_t *zeiger;

if(ouicount == 0)
	{
	return false;
	}

zeiger = ouilist;
for(zeiger = ouilist; zeiger < (ouilist +ouicount); zeiger++)
	{
	if(memcmp(zeiger->oui, macsta, 3) == 0)
		{
		if(strstr(zeiger->vendor, vendorapname) != NULL)
			{
			return true;
			}
		}
	}
return false;
}
/*===========================================================================*/
static bool isvendorap(uint8_t *macap)
{
static intoui_t *zeiger;

if(ouicount == 0)
	{
	return false;
	}

zeiger = ouilist;
for(zeiger = ouilist; zeiger < (ouilist +ouicount); zeiger++)
	{
	if(memcmp(zeiger->oui, macap, 3) == 0)
		{
		if(strstr(zeiger->vendor, vendorapname) != NULL)
			{
			return true;
			}
		}
	if(memcmp(zeiger->oui, macap, 3) > 0)
		{
		return false;
		}
	}
return false;
}
/*===========================================================================*/
static int writehccapxline(int fd_file, inthccapx_t *hccapxline, int written)
{
if((write(fd_file, hccapxline, INTHCCAPX_SIZE)) == -1)
	{
	perror("failed to write hccapx record");
	}
written++;
return written;
}
/*===========================================================================*/
static void writehccapxfile()
{
static int written;
static int fd_file;
static inthccapx_t *zeiger;

if((fd_file = open(hccapxoutname, O_WRONLY | O_CREAT | O_APPEND, 0644)) == -1)
	{
	perror("f");
	fprintf(stderr, "failed to open HCCAPX file %s\n", hccapxoutname);
	return;
	}

written = 0;
zeiger = hccapxlist;
for(zeiger = hccapxlist; zeiger < (hccapxlist +hccapxcount); zeiger++)
	{
	if((ouiapflag == true) && (memcmp(zeiger->macap, ouiap, 3) == 0))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((nicapflag == true) && (memcmp(&zeiger->macap[3], nicap, 3) == 0))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((macapflag == true) && (memcmp(zeiger->macap, macap, 6) == 0))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((vendorapflag == true) && (isvendorap(zeiger->macap) == true))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((ouistaflag == true) && (memcmp(zeiger->macsta, ouista, 3) == 0))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((nicstaflag == true) && (memcmp(&zeiger->macsta[3], nicsta, 3) == 0))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((macstaflag == true) && (memcmp(zeiger->macsta, macsta, 6) == 0))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((vendorapflag == true) && (isvendorsta(zeiger->macsta) == true))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	if((ouiapflag != true) && (nicapflag != true) && (macapflag != true) && (vendorapflag != true) && (ouistaflag != true) && (nicstaflag != true) && (macstaflag != true) && (vendorstaflag != true))
		{
		written = writehccapxline(fd_file, zeiger, written);
		continue;
		}
	}
close(fd_file);
printf("%d record(s) written to %s\n", written, basename(hccapxoutname));
return;
}
/*===========================================================================*/
static bool readhccapxfile()
{
static int count;
static inthccapx_t *zeiger;
static struct stat st;
static int fd_file;

if(stat(hccapxinname, &st) == -1)
	{
	perror("stat hccapx failed\n");
	return false;
	}
if((st.st_size %INTHCCAPX_SIZE) != 0)
	{
	fprintf(stderr, "failed to open corrupt HCCAPX file %s\n", hccapxinname);
	return false;
	}

hccapxlist = malloc(st.st_size +INTHCCAPX_SIZE);

if(hccapxlist == NULL)
	{
	printf("failed to allocate memory\n");
	return false;
	}
if((fd_file = open(hccapxinname, O_RDONLY)) == -1)
	{
	fprintf(stderr, "failed to open hccapx file %s\n", hccapxinname);
	return false;
	}

hccapxcount = 0;
zeiger = hccapxlist;
while((count = read(fd_file, zeiger, INTHCCAPX_SIZE)))
	{
	if(zeiger->signature != HCCAPX_SIGNATURE)
		{
		fprintf(stderr, "%d record has a wrong HCCAPX signature\n", hccapxcount);
		break;
		}
	hccapxcount++;
	zeiger++;
	}
memset(zeiger, 0, INTHCCAPX_SIZE);
close(fd_file);
if(hccapxcount > 0)
	{
	qsort(hccapxlist, hccapxcount, INTHCCAPX_SIZE, sort_inthccapx_by_macap);
	}
printf("%d record(s) read from %s\n", hccapxcount, hccapxinname);
return true;
}
/*===========================================================================*/
/*===========================================================================*/
static int writepmkidline(FILE *fh_file, intpmkid_t *pmkidline, int written)
{
static int c;

for(c = 0; c < 16; c++)
	{
	fprintf(fh_file, "%02x", pmkidline->pmkid[c]);
	}
fprintf(fh_file, "%c", separator);
for(c = 0; c < 6; c++)
	{
	fprintf(fh_file, "%02x", pmkidline->macap[c]);
	}
fprintf(fh_file, "%c", separator);
for(c = 0; c < 6; c++)
	{
	fprintf(fh_file, "%02x", pmkidline->macsta[c]);
	}
fprintf(fh_file, "%c", separator);
for(c = 0; c < pmkidline->essidlen; c++)
	{
	fprintf(fh_file, "%02x", pmkidline->essid[c]);
	}
fprintf(fh_file, "\n");
written++;
return written;
}
/*===========================================================================*/
static void writepmkidfile()
{
static int written;
static FILE *fh_file;
static intpmkid_t *zeiger;

if((fh_file = fopen(pmkidoutname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open PMKID file %s\n", pmkidoutname);
	return;
	}

written = 0;
zeiger = pmkidlist;
for(zeiger = pmkidlist; zeiger < (pmkidlist +pmkidcount); zeiger++)
	{
	if((ouiapflag == true) && (memcmp(zeiger->macap, ouiap, 3) == 0))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((nicapflag == true) && (memcmp(&zeiger->macap[3], nicap, 3) == 0))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((macapflag == true) && (memcmp(zeiger->macap, macap, 6) == 0))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((vendorapflag == true) && (isvendorap(zeiger->macap) == true))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((ouistaflag == true) && (memcmp(zeiger->macsta, ouista, 3) == 0))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((nicstaflag == true) && (memcmp(&zeiger->macsta[3], nicsta, 3) == 0))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((macstaflag == true) && (memcmp(zeiger->macsta, macsta, 6) == 0))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((vendorapflag == true) && (isvendorsta(zeiger->macsta) == true))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	if((ouiapflag != true) && (nicapflag != true) && (macapflag != true) && (vendorapflag != true) && (ouistaflag != true) && (nicstaflag != true) && (macstaflag != true) && (vendorstaflag != true))
		{
		written = writepmkidline(fh_file, zeiger, written);
		continue;
		}
	}
fclose(fh_file);
printf("%d record(s) written to %s\n", written, basename(pmkidoutname));
return;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
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
static int fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream))
	return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL)
	return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool readpmkidfile()
{
static int len;
static int aktread;
static intpmkid_t *zeiger;
static struct stat st;
static FILE *fh_file;

static char linein[PMKID_LINE_LEN];

if(stat(pmkidinname, &st) == -1)
	{
	perror("stat pmkid file failed\n");
	return false;
	}
pmkidlist = malloc(st.st_size +INTPMKID_SIZE);
if(pmkidlist == NULL)
	{
	printf("failed to allocate memory\n");
	return false;
	}

if((fh_file = fopen(pmkidinname, "r")) == NULL)
	{
	fprintf(stderr, "failed to read PMKID file %s\n", pmkidinname);
	return false;
	}

pmkidcount = 0;
zeiger = pmkidlist;
while(1)
	{
	memset(zeiger, 0, INTPMKID_SIZE);
	if((len = fgetline(fh_file, PMKID_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if((len < 61) || ((len > 59 +(ESSID_LEN_MAX *2))))
		{
		fprintf(stderr, "skipping line %d: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((linein[32] == ':') && (linein[45] == ':') && (linein[58] == ':'))
		{
		separator = ':';
		}
	else if((linein[32] == '*') && (linein[45] == '*') && (linein[58] == '*'))
		{
		separator = '*';
		}
	else
		{
		fprintf(stderr, "skipping line %d: %s\n", aktread, linein);
		aktread++;
		continue;
		}

	if(hex2bin(&linein[0], zeiger->pmkid, 16) == false)
		{
		fprintf(stderr, "skipping line %d: %s:\n", aktread, linein);
		aktread++;
		continue;
		}

	if(hex2bin(&linein[33], zeiger->macap, 6) == false)
		{
		fprintf(stderr, "skipping line %d: %s:\n", aktread, linein);
		aktread++;
		continue;
		}

	if(hex2bin(&linein[46], zeiger->macsta, 6) == false)
		{
		fprintf(stderr, "skipping line %d: %s:\n", aktread, linein);
		aktread++;
		continue;
		}
	zeiger->essidlen = len -59;
	if((zeiger->essidlen == 0) || (zeiger->essidlen > 64) || ((zeiger->essidlen %2) != 0))
		{
		fprintf(stderr, "skipping line %d: %s:\n", aktread, linein);
		aktread++;
		continue;
		}

	zeiger->essidlen = zeiger->essidlen /2;
	if(hex2bin(&linein[59], zeiger->essid, zeiger->essidlen) ==false)
		{
		fprintf(stderr, "skipping line %d: %s:\n", aktread, linein);
		aktread++;
		continue;
		}
	pmkidcount++;
	zeiger++;
	aktread++;
	}
fclose(fh_file);
if(pmkidcount > 0)
	{
	qsort(pmkidlist, pmkidcount, INTPMKID_SIZE, sort_intpmkid_by_macap);
	}
printf("%d record(s) read from %s\n", pmkidcount, pmkidinname);
return true;
}
/*===========================================================================*/
static void readouifile()
{
static int len;
static int uid;
struct passwd *pwd;
static intoui_t *zeiger;
static struct stat st;
static FILE *fh_file;
static char *ouiname = NULL;
static char *vendorname = NULL;

static char *ouinameuser = "/.hcxtools/oui.txt";
static char *ouinamesystemwide = "/usr/share/ieee-data/oui.txt";

static char ouinameuserhome[PATH_MAX +1];
static char linein[OUI_LINE_LEN];

if(stat(ouinamesystemwide, &st) == 0)
	{
	ouiname = ouinamesystemwide;
	}
uid = getuid();
pwd = getpwuid(uid);
if(pwd != NULL)
	{
	strncpy(ouinameuserhome, pwd->pw_dir, PATH_MAX);
	strncat(ouinameuserhome, ouinameuser, PATH_MAX);
	if(stat(ouinameuserhome, &st) == 0)
		{
		ouiname = ouinameuserhome;
		}
	}
if(ouiname == NULL)
	{
	printf("no oui file found\n");
	return;
	}
printf("using oui from %s\n", ouiname);

ouilist = malloc(st.st_size +INTOUI_SIZE);
if(ouilist == NULL)
	{
	printf("failed to allocate memory\n");
	return;
	}

if((fh_file = fopen(ouiname, "r")) == NULL)
	{
	fprintf(stderr, "failed to read OUI file %s\n", ouiname);
	return;
	}

ouicount = 0;
zeiger = ouilist;
while(1)
	{
	memset(zeiger, 0, INTOUI_SIZE);
	if((len = fgetline(fh_file, OUI_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if(strstr(linein, "(base 16)") == NULL)
		{
		continue;
		}

	if(hex2bin(&linein[0], zeiger->oui, 3) == false)
		{
		continue;
		}
	vendorname = strrchr(linein, '\t');
	if(vendorname == NULL)
		{
		continue;
		}
	strncpy(zeiger->vendor, vendorname, OUI_LINE_LEN);
	ouicount++;
	zeiger++;
	}
fclose(fh_file);
if(ouicount > 0)
	{
	qsort(ouilist, ouicount, INTOUI_SIZE, sort_intoui_by_oui);
	}
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-o <oui>    : filter access point by OUI\n"
	"-n <nic>    : filter access point by NIC\n"
	"-m <mac>    : filter access point by MAC\n"
	"-a <vendor> : filter access point by VENDOR name\n"
	"-O <oui>    : filter client by OUI\n"
	"-N <nic>    : filter client point by NIC\n"
	"-M <mac>    : filter client point by MAC\n"
	"-A <vendor> : filter client by VENDOR name\n"
	"-h          : show this help\n"
	"-v          : show version\n"
	"\n"
	"--pmkidin=<file>       : input PMKID file 1\n"
	"--pmkidout=<file>      : output PMKID file 1\n"
	"--hccapxin=<file>      : input HCCAPX file\n"
	"--hccapxout=<file>     : output HCCAPX file\n"
	"--help                 : show this help\n"
	"--version              : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;

unsigned long long int macinput;

static const char *short_options = "e:E:l:o:n:m:a:O:N:M:A:hv";
static const struct option long_options[] =
{
	{"pmkidin",			required_argument,	NULL,	HCXD_PMKID_IN},
	{"pmkidout",			required_argument,	NULL,	HCXD_PMKID_OUT},
	{"hccapxin",			required_argument,	NULL,	HCXD_HCCAPX_IN},
	{"hccapxout",			required_argument,	NULL,	HCXD_HCCAPX_OUT},
	{"version",			no_argument,		NULL,	HCXD_VERSION},
	{"help",			no_argument,		NULL,	HCXD_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;
while((auswahl = getopt_long (argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HCXD_PMKID_IN:
		pmkidinname = optarg;
		break;

		case HCXD_PMKID_OUT:
		pmkidoutname = optarg;
		break;

		case HCXD_HCCAPX_IN:
		hccapxinname = optarg;
		break;

		case HCXD_HCCAPX_OUT:
		hccapxoutname = optarg;
		break;

		case HCXD_FILTER_OUI_AP:
		if(strlen(optarg) != 6)
			{
			fprintf(stderr, "wrong OUI format (allowed: 112233)\n");
			exit(EXIT_FAILURE);
			}
		macinput = strtoull(optarg, NULL, 16);
		ouiap[2] = macinput & 0xff;
		ouiap[1] = (macinput >> 8) & 0xff;
		ouiap[0] = (macinput >> 16) & 0xff;
		ouiapflag = true;
		break;

		case HCXD_FILTER_NIC_AP:
		if(strlen(optarg) != 6)
			{
			fprintf(stderr, "wrong OUI format (allowed: 112233)\n");
			exit(EXIT_FAILURE);
			}
		macinput = strtoull(optarg, NULL, 16);
		nicap[2] = macinput & 0xff;
		nicap[1] = (macinput >> 8) & 0xff;
		nicap[0] = (macinput >> 16) & 0xff;
		nicapflag = true;
		break;

		case HCXD_FILTER_MAC_AP:
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "wrong OUI format (allowed: 112233445566)\n");
			exit(EXIT_FAILURE);
			}
		macinput = strtoull(optarg, NULL, 16);
		macap[5] = macinput & 0xff;
		macap[4] = (macinput >> 8) & 0xff;
		macap[3] = (macinput >> 16) & 0xff;
		macap[2] = (macinput >> 24) & 0xff;
		macap[1] = (macinput >> 32) & 0xff;
		macap[0] = (macinput >> 40) & 0xff;
		macapflag = true;
		break;

		case HCXD_FILTER_VENDOR_AP:
		vendorapname = optarg;
		vendorapflag = true;
		break;

		case HCXD_FILTER_OUI_STA:
		if(strlen(optarg) != 6)
			{
			fprintf(stderr, "wrong OUI format (allowed: 112233)\n");
			exit(EXIT_FAILURE);
			}
		macinput = strtoull(optarg, NULL, 16);
		ouista[2] = macinput & 0xff;
		ouista[1] = (macinput >> 8) & 0xff;
		ouista[0] = (macinput >> 16) & 0xff;
		ouistaflag = true;
		break;

		case HCXD_FILTER_NIC_STA:
		if(strlen(optarg) != 6)
			{
			fprintf(stderr, "wrong OUI format (allowed: 112233)\n");
			exit(EXIT_FAILURE);
			}
		macinput = strtoull(optarg, NULL, 16);
		nicsta[2] = macinput & 0xff;
		nicsta[1] = (macinput >> 8) & 0xff;
		nicsta[0] = (macinput >> 16) & 0xff;
		nicstaflag = true;
		break;

		case HCXD_FILTER_MAC_STA:
		if(strlen(optarg) != 12)
			{
			fprintf(stderr, "wrong OUI format (allowed: 112233445566)\n");
			exit(EXIT_FAILURE);
			}
		macinput = strtoull(optarg, NULL, 16);
		macsta[5] = macinput & 0xff;
		macsta[4] = (macinput >> 8) & 0xff;
		macsta[3] = (macinput >> 16) & 0xff;
		macsta[2] = (macinput >> 24) & 0xff;
		macsta[1] = (macinput >> 32) & 0xff;
		macsta[0] = (macinput >> 40) & 0xff;
		macstaflag = true;
		break;

		case HCXD_FILTER_VENDOR_STA:
		vendorstaname = optarg;
		vendorstaflag = true;
		break;


		case HCXD_HELP:
		usage(basename(argv[0]));
		break;

		case HCXD_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

if(argc < 2)
	{
	fprintf(stderr, "no option selected\n");
	return EXIT_SUCCESS;
	}

readouifile();
if(((vendorapflag == true) || (vendorstaflag == true)) && (ouicount == 0))
	{
	fprintf(stderr, "VENDOR requested, but no OUI file found)\n");
	globalclose();
	exit(EXIT_FAILURE);
	}

if(pmkidinname != NULL)
	{
	readpmkidfile();
	}

if(hccapxinname != NULL)
	{
	readhccapxfile();
	}

if((pmkidoutname != NULL) && (pmkidcount > 0))
	{
	writepmkidfile();
	}

if((hccapxoutname != NULL) && (hccapxcount > 0))
	{
	writehccapxfile();
	}

globalclose();

return EXIT_SUCCESS;
}
/*===========================================================================*/

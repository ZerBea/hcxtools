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
#include <sys/types.h>
#include <sys/stat.h>

#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/version.h"
#include "include/hcxessidtool.h"
#include "include/strings.c"
#include "include/fileops.c"

/*===========================================================================*/
/* global var */

static int essidonlylen = 0;

static int essidfilterlen = 0;
static int essidpartfilterlen = 0;

static char *essidfiltername = NULL;
static char *essidpartfiltername = NULL;

static int pmkid1count = 0;
static int pmkid2count = 0;

static char *pmkid1name = NULL;
static char *pmkid2name = NULL;
static char *pmkid12outname = NULL;
static char *pmkid1outname = NULL;
static char *pmkid2outname = NULL;
static char *pmkidoutname = NULL;

static intpmkid_t *pmkid1list = NULL, *pmkidzeiger1 = NULL, *pmkidzeigerakt1 = NULL;
static intpmkid_t *pmkid2list = NULL, *pmkidzeiger2 = NULL, *pmkidzeigerakt2 = NULL;

static int hccapx1count = 0;
static int hccapx2count = 0;;

static char *hccapx1name = NULL;
static char *hccapx2name = NULL;
static char *hccapx12outname = NULL;
static char *hccapx1outname = NULL;
static char *hccapx2outname = NULL;
static char *hccapxoutname = NULL;

static bool pmkidgroupflag = false;
static bool hccapxgroupflag = false;

static inthccapx_t *hccapx1list = NULL, *hccapxzeiger1 = NULL, *hccapxzeigerakt1 = NULL;
static inthccapx_t *hccapx2list = NULL, *hccapxzeiger2 = NULL, *hccapxzeigerakt2 = NULL;

static char *essidoutname = NULL;
static char *essidmacapoutname = NULL;

static char separator = ':';
/*===========================================================================*/
static void globalclose()
{
if(pmkid1list != NULL)
	{
	free(pmkid1list);
	}

if(pmkid2list != NULL)
	{
	free(pmkid2list);
	}

if(hccapx1list != NULL)
	{
	free(hccapx1list);
	}

if(hccapx2list != NULL)
	{
	free(hccapx2list);
	}
return;
}
/*===========================================================================*/
static void writeessidmacaphccapx(char *sourcefile, inthccapx_t *hccapxlist, int hccapxcount)
{
static int written;
static FILE *fh_file;
static inthccapx_t *zeiger, *zeigernext;

if((fh_file = fopen(essidmacapoutname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open ESSID file %s\n", essidmacapoutname);
	return;
	}
written = 0;
zeiger = hccapxlist;
for(zeiger = hccapxlist; zeiger < (hccapxlist +hccapxcount); zeiger++)
	{
	zeigernext = zeiger;
	zeigernext++;
	if(zeigernext->essidlen != zeiger->essidlen)
		{
		fwriteaddr1(zeiger->macap, fh_file); 
		fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
		written++;
		}
	else
		{
		if((memcmp(zeigernext->macap, zeiger->macap, 6) != 0) || (memcmp(zeigernext->essid, zeiger->essid, zeiger->essidlen) != 0))
			{
			fwriteaddr1(zeiger->macap, fh_file); 
			fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
			written++;
			}
		}
	}
fclose(fh_file);
printf("%d ESSID(s) written to %s from %s\n", written, basename(essidmacapoutname), basename(sourcefile));
return;
}
/*===========================================================================*/
static void writeessidmacappmkid(char *sourcefile, intpmkid_t *pmkidlist, int pmkidcount)
{
static int written;
static FILE *fh_file;
static intpmkid_t *zeiger, *zeigernext;

if((fh_file = fopen(essidmacapoutname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open ESSID file %s\n", essidmacapoutname);
	return;
	}
written = 0;
zeiger = pmkidlist;
for(zeiger = pmkidlist; zeiger < (pmkidlist +pmkidcount); zeiger++)
	{
	zeigernext = zeiger;
	zeigernext++;
	if(zeigernext->essidlen != zeiger->essidlen)
		{
		fwriteaddr1(zeiger->macap, fh_file); 
		fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
		written++;
		}
	else
		{
		if((memcmp(zeigernext->macap, zeiger->macap, 6) != 0) || (memcmp(zeigernext->essid, zeiger->essid, zeiger->essidlen) != 0))
			{
			fwriteaddr1(zeiger->macap, fh_file); 
			fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
			written++;
			}
		}
	}
fclose(fh_file);
printf("%d ESSID(s) written to %s from %s\n", written, basename(essidmacapoutname), basename(sourcefile));
return;
}
/*===========================================================================*/
static void writeessidhccapx(char *sourcefile, inthccapx_t *hccapxlist, int hccapxcount)
{
static int written;
static FILE *fh_file;
static inthccapx_t *zeiger, *zeigernext;

if((fh_file = fopen(essidoutname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open ESSID file %s\n", essidoutname);
	return;
	}
written = 0;
zeiger = hccapxlist;
for(zeiger = hccapxlist; zeiger < (hccapxlist +hccapxcount); zeiger++)
	{
	zeigernext = zeiger;
	zeigernext++;
	if(zeigernext->essidlen != zeiger->essidlen)
		{
		fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
		written++;
		}
	else
		{
		if(memcmp(zeigernext->essid, zeiger->essid, zeiger->essidlen) != 0)
			{
			fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
			written++;
			}
		}
	}
fclose(fh_file);
printf("%d ESSID(s) written to %s from %s\n", written, basename(essidoutname), basename(sourcefile));
return;
}
/*===========================================================================*/
static void writeessidpmkid(char *sourcefile, intpmkid_t *pmkidlist, int pmkidcount)
{
static int written;
static FILE *fh_file;
static intpmkid_t *zeiger, *zeigernext;

if((fh_file = fopen(essidoutname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open ESSID file %s\n", essidoutname);
	return;
	}
written = 0;
zeiger = pmkidlist;
for(zeiger = pmkidlist; zeiger < (pmkidlist +pmkidcount); zeiger++)
	{
	zeigernext = zeiger;
	zeigernext++;
	if(zeigernext->essidlen != zeiger->essidlen)
		{
		fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
		written++;
		}
	else
		{
		if(memcmp(zeigernext->essid, zeiger->essid, zeiger->essidlen) != 0)
			{
			fwriteessidstr(zeiger->essidlen, zeiger->essid, fh_file); 
			written++;
			}
		}
	}
fclose(fh_file);
printf("%d ESSID(s) written to %s from %s\n", written, basename(essidoutname), basename(sourcefile));
return;
}
/*===========================================================================*/
static int writehccapxline(int fd_file, inthccapx_t *hccapxline, int written)
{
static int c;
static bool foundflag;

if(essidonlylen > 0)
	{
	if(hccapxline->essidlen != essidonlylen)
		{
		return written;
		}
	}
if(essidfilterlen > 0)
	{
	if(hccapxline->essidlen != essidfilterlen)
		{
		return written;
		}
	if(memcmp(hccapxline->essid, essidfiltername, essidfilterlen) != 0)
		{
		return written;
		}
	}
if(essidpartfilterlen > 0)
	{
	if(hccapxline->essidlen < essidpartfilterlen)
		{
		return written;
		}
	foundflag = false;
	for(c = 0; c <= hccapxline->essidlen -essidpartfilterlen; c++)
		{
		if(memcmp(&hccapxline->essid[0], essidpartfiltername, essidpartfilterlen) == 0)
			{
			foundflag = true;
			break;
			}
		}
	if(foundflag == false)
		{
		return written;
		}
	}
if((write(fd_file, hccapxline, INTHCCAPX_SIZE)) == -1)
	{
	perror("failed to write hccapx record");
	}
written++;
return written;
}
/*===========================================================================*/
static void writehccapxgroups()
{
static int written;
static int fd_file;
static int cei;
static int ceo;

char digit[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

char groupoutname[256];

written = 0;
hccapxzeiger1 = hccapx1list;
for(hccapxzeiger1 = hccapx1list; hccapxzeiger1 < (hccapx1list +hccapx1count); hccapxzeiger1++)
	{
	if(essidonlylen > 0)
		{
		if(hccapxzeiger1->essidlen != essidonlylen)
			{
			continue;
			}
		}
	ceo = 0;
	for (cei = 0; cei < hccapxzeiger1->essidlen; cei++)
		{
		groupoutname[ceo] = digit[(hccapxzeiger1->essid[cei] & 0xff) >> 4];
		ceo++;
		groupoutname[ceo] = digit[hccapxzeiger1->essid[cei] & 0x0f];
		ceo++;
		}
	groupoutname[ceo] = 0;
	strcat(&groupoutname[ceo], ".hccapx");

	if((fd_file = open(groupoutname, O_WRONLY | O_CREAT | O_APPEND, 0644)) == -1)
		{
		perror("f");
		fprintf(stderr, "failed to open HCCAPX file %s\n",groupoutname);
		return;
		}
	written = writehccapxline(fd_file, hccapxzeiger1, written);
	close(fd_file);
	}
printf("%d hashes written to HCCAPX groups\n", written);
return;
}
/*===========================================================================*/
static bool findhccapx21()
{
for(hccapxzeiger1 = hccapxzeigerakt1; hccapxzeiger1 < (hccapx1list +hccapx1count); hccapxzeiger1++)
	{
	if(memcmp(hccapxzeiger2->essid, hccapxzeiger1->essid, ESSID_LEN_MAX) == 0)
		{
		hccapxzeigerakt1 = hccapxzeiger1;
		return true;
		}
	if(memcmp(hccapxzeiger2->essid, hccapxzeiger1->essid, ESSID_LEN_MAX) > 0)
		{
		return false;
		}
	}
return false;
}
/*===========================================================================*/
static bool findhccapx12()
{
for(hccapxzeiger2 = hccapx2list; hccapxzeiger2 < (hccapx2list +hccapx2count); hccapxzeiger2++)
	{
	if(memcmp(hccapxzeiger1->essid, hccapxzeiger2->essid, ESSID_LEN_MAX) == 0)
		{
		hccapxzeigerakt2 = hccapxzeiger2;
		return true;
		}
	if(memcmp(hccapxzeiger1->essid, hccapxzeiger2->essid, ESSID_LEN_MAX) > 0)
		{
		return false;
		}
	}
return false;
}
/*===========================================================================*/
static void writehccapx()
{
static int written;
static int fd_file;

if((fd_file = open(hccapxoutname, O_WRONLY | O_CREAT | O_APPEND, 0644)) == -1)
	{
	perror("f");
	fprintf(stderr, "failed to open HCCAPX file %s\n", hccapxoutname);
	return;
	}

written = 0;
hccapxzeiger1 = hccapx1list;
for(hccapxzeiger1 = hccapx1list; hccapxzeiger1 < (hccapx1list +hccapx1count); hccapxzeiger1++)
	{
	written = writehccapxline(fd_file, hccapxzeiger1, written);
	}
close(fd_file);
printf("%d record(s) written to %s\n", written, basename(hccapxoutname));
return;
}
/*===========================================================================*/
static void writehccapx2()
{
static int written;
static int fd_file;

if((fd_file = open(hccapx2outname, O_WRONLY | O_CREAT | O_APPEND, 0644)) == -1)
	{
	fprintf(stderr, "failed to open HCCAPX file %s\n", hccapx2outname);
	return;
	}

written = 0;
hccapxzeiger1 = hccapx1list;
hccapxzeiger2 = hccapx2list;
hccapxzeigerakt1 = hccapx1list;
hccapxzeigerakt2 = hccapx2list;
for(hccapxzeiger2 = hccapx2list; hccapxzeiger2 < (hccapx2list +hccapx2count); hccapxzeiger2++)
	{
	if(findhccapx21() == true)
		{
		written = writehccapxline(fd_file, hccapxzeiger2, written);
		}
	}
close(fd_file);
printf("%d record(s) written to %s\n", written, basename(hccapx2outname));
return;
}
/*===========================================================================*/
static void writehccapx1()
{
static int written;
static int fd_file;

printf("%s\n", hccapx1outname);
if((fd_file = open(hccapx1outname, O_WRONLY | O_CREAT | O_APPEND, 0644)) == -1)
	{
	fprintf(stderr, "failed to open HCCAPX file %s\n", hccapx1outname);
	return;
	}

written = 0;
hccapxzeiger1 = hccapx1list;
hccapxzeiger2 = hccapx2list;
hccapxzeigerakt1 = hccapx1list;
hccapxzeigerakt2 = hccapx2list;
for(hccapxzeiger1 = hccapx1list; hccapxzeiger1 < (hccapx1list +hccapx1count); hccapxzeiger1++)
	{
	if(findhccapx12() == true)
		{
		written = writehccapxline(fd_file, hccapxzeiger1, written);
		}
	}
close(fd_file);
printf("%d record(s) written to %s\n", written, basename(hccapx1outname));
return;
}
/*===========================================================================*/
static void writehccapx12()
{
static int written;
static int fd_file;

if((fd_file = open(hccapx12outname, O_WRONLY | O_CREAT, 0644)) == -1)
	{
	perror("f");
	fprintf(stderr, "failed to open HCCAPX file %s\n", hccapx12outname);
	return;
	}

written = 0;
hccapxzeiger1 = hccapx1list;
hccapxzeiger2 = hccapx2list;
hccapxzeigerakt1 = hccapx1list;
hccapxzeigerakt2 = hccapx2list;
for(hccapxzeiger1 = hccapx1list; hccapxzeiger1 < (hccapx1list +hccapx1count); hccapxzeiger1++)
	{
	if(findhccapx12() == true)
		{
		written = writehccapxline(fd_file, hccapxzeiger1, written);
		}
	}

hccapxzeiger1 = hccapx1list;
hccapxzeiger2 = hccapx2list;
hccapxzeigerakt1 = hccapx1list;
hccapxzeigerakt2 = hccapx2list;
for(hccapxzeiger2 = hccapx2list; hccapxzeiger2 < (hccapx2list +hccapx2count); hccapxzeiger2++)
	{
	if(findhccapx21() == true)
		{
		written = writehccapxline(fd_file, hccapxzeiger2, written);
		}
	}

close(fd_file);
printf("%d record(s) written to %s\n", written, basename(hccapx12outname));
return;
}
/*===========================================================================*/
static bool readhccapx2file()
{
static int count;
static inthccapx_t *zeiger;
static struct stat st;
static int fd_file;

if(stat(hccapx2name, &st) == -1)
	{
	perror("stat HCCAPX2 failed\n");
	return false;
	}
if((st.st_size %INTHCCAPX_SIZE) != 0)
	{
	fprintf(stderr, "failed to open corrupt HCCAPX file %s\n", hccapx2name);
	return false;
	}

hccapx2list = malloc(st.st_size +INTHCCAPX_SIZE);
if(hccapx2list == NULL)
	{
	printf("failed to allocate memory\n");
	return false;
	}
if((fd_file = open(hccapx2name, O_RDONLY)) == -1)
	{
	fprintf(stderr, "failed to open hccapx file %s\n", hccapx2name);
	return false;
	}

hccapx2count = 0;
zeiger = hccapx2list;
while((count = read(fd_file, zeiger, INTHCCAPX_SIZE)))
	{
	if(zeiger->signature != HCCAPX_SIGNATURE)
		{
		fprintf(stderr, "%d record has a wrong HCCAPX signature\n", hccapx2count);
		break;
		}
	hccapx2count++;
	zeiger++;
	}
memset(zeiger, 0, INTHCCAPX_SIZE);
close(fd_file);
if(hccapx2count > 0)
	{
	qsort(hccapx2list, hccapx2count, INTHCCAPX_SIZE, sort_inthccapx_by_essid);
	}
printf("%d record(s) read from %s\n", hccapx2count, hccapx2name);
return true;
}
/*===========================================================================*/
static bool readhccapx1file()
{
static int count;
static inthccapx_t *zeiger;
static struct stat st;
static int fd_file;

if(stat(hccapx1name, &st) == -1)
	{
	perror("stat HCCAPX1 failed\n");
	return false;
	}
if((st.st_size %INTHCCAPX_SIZE) != 0)
	{
	fprintf(stderr, "failed to open corrupt HCCAPX file %s\n", hccapx1name);
	return false;
	}

hccapx1list = malloc(st.st_size +INTHCCAPX_SIZE);

if(hccapx1list == NULL)
	{
	printf("failed to allocate memory\n");
	return false;
	}
if((fd_file = open(hccapx1name, O_RDONLY)) == -1)
	{
	fprintf(stderr, "failed to open hccapx file %s\n", hccapx1name);
	return false;
	}

hccapx1count = 0;
zeiger = hccapx1list;
while((count = read(fd_file, zeiger, INTHCCAPX_SIZE)))
	{
	if(zeiger->signature != HCCAPX_SIGNATURE)
		{
		fprintf(stderr, "%d record has a wrong HCCAPX signature\n", hccapx1count);
		break;
		}
	hccapx1count++;
	zeiger++;
	}
memset(zeiger, 0, INTHCCAPX_SIZE);
close(fd_file);
if(hccapx1count > 0)
	{
	qsort(hccapx1list, hccapx1count, INTHCCAPX_SIZE, sort_inthccapx_by_essid);
	}
printf("%d record(s) read from %s\n", hccapx1count, hccapx1name);
return true;
}
/*===========================================================================*/
static int writepmkidline(FILE *fh_file, intpmkid_t *pmkidline, int written)
{
static int c;
static bool foundflag;

if(essidonlylen > 0)
	{
	if(pmkidline->essidlen != essidonlylen)
		{
		return written;
		}
	}
if(essidfilterlen > 0)
	{
	if(pmkidline->essidlen != essidfilterlen)
		{
		return written;
		}
	if(memcmp(pmkidline->essid, essidfiltername, essidfilterlen) != 0)
		{
		return written;
		}
	}
if(essidpartfilterlen > 0)
	{
	if(pmkidline->essidlen < essidpartfilterlen)
		{
		return written;
		}
	foundflag = false;
	for(c = 0; c <= pmkidline->essidlen -essidpartfilterlen; c++)
		{
		if(memcmp(&pmkidline->essid[0], essidpartfiltername, essidpartfilterlen) == 0)
			{
			foundflag = true;
			break;
			}
		}
	if(foundflag == false)
		{
		return written;
		}
	}
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
static void writepmkidgroups()
{
static int written;
static FILE *fh_file;
static int cei;
static int ceo;

char digit[16] = {'0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'};

char groupoutname[256];

written = 0;
pmkidzeiger1 = pmkid1list;
for(pmkidzeiger1 = pmkid1list; pmkidzeiger1 < (pmkid1list +pmkid1count); pmkidzeiger1++)
	{
	if(essidonlylen > 0)
		{
		if(pmkidzeiger1->essidlen != essidonlylen)
			{
			continue;
			}
		}
	ceo = 0;
	for (cei = 0; cei < pmkidzeiger1->essidlen; cei++)
		{
		groupoutname[ceo] = digit[(pmkidzeiger1->essid[cei] & 0xff) >> 4];
		ceo++;
		groupoutname[ceo] = digit[pmkidzeiger1->essid[cei] & 0x0f];
		ceo++;
		}
	groupoutname[ceo] = 0;
	strcat(&groupoutname[ceo], ".16800");
	if((fh_file = fopen(groupoutname, "a")) == NULL)
		{
		perror("f");
		fprintf(stderr, "failed to open pmkid file %s\n", groupoutname);
		return;
		}
	written = writepmkidline(fh_file, pmkidzeiger1, written);
	fclose(fh_file);
	}
printf("%d record(s) written to PMKID groups\n", written);
return;
}
/*===========================================================================*/
static bool findpmkid21()
{
for(pmkidzeiger1 = pmkidzeigerakt1; pmkidzeiger1 < (pmkid1list +pmkid1count); pmkidzeiger1++)
	{
	if(memcmp(pmkidzeiger2->essid, pmkidzeiger1->essid, ESSID_LEN_MAX) == 0)
		{
		pmkidzeigerakt1 = pmkidzeiger1;
		return true;
		}
	if(memcmp(pmkidzeiger2->essid, pmkidzeiger1->essid, ESSID_LEN_MAX) > 0)
		{
		return false;
		}
	}
return false;
}
/*===========================================================================*/
static bool findpmkid12()
{
for(pmkidzeiger2 = pmkid2list; pmkidzeiger2 < (pmkid2list +pmkid2count); pmkidzeiger2++)
	{
	if(memcmp(pmkidzeiger1->essid, pmkidzeiger2->essid, ESSID_LEN_MAX) == 0)
		{
		pmkidzeigerakt2 = pmkidzeiger2;
		return true;
		}
	if(memcmp(pmkidzeiger1->essid, pmkidzeiger2->essid, ESSID_LEN_MAX) > 0)
		{
		return false;
		}
	}
return false;
}
/*===========================================================================*/
static void writepmkid()
{
static int written;
static FILE *fh_file;

if((fh_file = fopen(pmkidoutname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open PMKID file %s\n", pmkidoutname);
	return;
	}
written = 0;
pmkidzeiger1 = pmkid1list;
for(pmkidzeiger1 = pmkid1list; pmkidzeiger1 < (pmkid1list +pmkid1count); pmkidzeiger1++)
	{
	written = writepmkidline(fh_file, pmkidzeiger1, written);
	}
fclose(fh_file);
printf("%d record(s) written to %s\n", written, basename(pmkidoutname));
return;
}
/*===========================================================================*/
static void writepmkid2()
{
static int written;
static FILE *fh_file;

if((fh_file = fopen(pmkid2outname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open PMKID file %s\n", pmkid2outname);
	return;
	}
written = 0;
pmkidzeiger2 = pmkid2list;
pmkidzeigerakt1 = pmkid1list;
pmkidzeigerakt2 = pmkid2list;
for(pmkidzeiger2 = pmkid2list; pmkidzeiger2 < (pmkid2list +pmkid2count); pmkidzeiger2++)
	{
	if(findpmkid21() == false)
		{
		written = writepmkidline(fh_file, pmkidzeiger2, written);
		}
	}
fclose(fh_file);
printf("%d record(s) written to %s\n", written, basename(pmkid2outname));
return;
}
/*===========================================================================*/
static void writepmkid1()
{
static int written;
static FILE *fh_file;

if((fh_file = fopen(pmkid1outname, "a")) == NULL)
	{
	fprintf(stderr, "failed to open PMKID file %s\n", pmkid1outname);
	return;
	}
written = 0;
pmkidzeiger1 = pmkid1list;
pmkidzeigerakt1 = pmkid1list;
pmkidzeigerakt2 = pmkid2list;
for(pmkidzeiger1 = pmkid1list; pmkidzeiger1 < (pmkid1list +pmkid1count); pmkidzeiger1++)
	{
	if(findpmkid12() == false)
		{
		written = writepmkidline(fh_file, pmkidzeiger1, written);
		}
	}
fclose(fh_file);
printf("%d record(s) written to %s\n", written, basename(pmkid1outname));
return;
}
/*===========================================================================*/
static void writepmkid12()
{
static int written;
static FILE *fh_file;

if((fh_file = fopen(pmkid12outname, "w+")) == NULL)
	{
	fprintf(stderr, "failed to open PMKID file %s\n", pmkid12outname);
	return;
	}

written = 0;
pmkidzeiger1 = pmkid1list;
pmkidzeiger2 = pmkid2list;
pmkidzeigerakt1 = pmkid1list;
pmkidzeigerakt2 = pmkid2list;
for(pmkidzeiger1 = pmkid1list; pmkidzeiger1 < (pmkid1list +pmkid1count); pmkidzeiger1++)
	{
	if(findpmkid12() == true)
		{
		written = writepmkidline(fh_file, pmkidzeiger1, written);
		}
	}
pmkidzeiger1 = pmkid1list;
pmkidzeiger2 = pmkid2list;
pmkidzeigerakt1 = pmkid1list;
pmkidzeigerakt2 = pmkid2list;
for(pmkidzeiger2 = pmkid2list; pmkidzeiger2 < (pmkid2list +pmkid2count); pmkidzeiger2++)
	{
	if(findpmkid21() == true)
		{
		written = writepmkidline(fh_file, pmkidzeiger2, written);
		}
	}
fclose(fh_file);
printf("%d record(s) written to %s\n", written, basename(pmkid12outname));
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
static bool readpmkid2file()
{
static int len;
static int aktread;
static intpmkid_t *zeiger;
static struct stat st;
static FILE *fh_file;

static char linein[PMKID_LINE_LEN];

if(stat(pmkid2name, &st) == -1)
	{
	perror("stat PMKID2 file failed\n");
	return false;
	}
pmkid2list = malloc(st.st_size +INTPMKID_SIZE);
if(pmkid2list == NULL)
	{
	printf("failed to allocate memory\n");
	return false;
	}

if((fh_file = fopen(pmkid2name, "r")) == NULL)
	{
	fprintf(stderr, "failed to open PMKID file %s\n", pmkid2name);
	return false;
	}

pmkid2count = 0;
zeiger = pmkid2list;
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
	pmkid2count++;
	zeiger++;
	aktread++;
	}
fclose(fh_file);
if(pmkid2count > 0)
	{
	qsort(pmkid2list, pmkid2count, INTPMKID_SIZE, sort_intpmkid_by_essid);
	}
printf("%d record(s) read from %s\n", pmkid2count, pmkid2name);
return true;
}
/*===========================================================================*/
static bool readpmkid1file()
{
static int len;
static int aktread;
static intpmkid_t *zeiger;
static struct stat st;
static FILE *fh_file;

static char linein[PMKID_LINE_LEN];

if(stat(pmkid1name, &st) == -1)
	{
	perror("stat PMKID1 file failed\n");
	return false;
	}
pmkid1list = malloc(st.st_size +INTPMKID_SIZE);
if(pmkid1list == NULL)
	{
	printf("failed to allocate memory\n");
	return false;
	}

if((fh_file = fopen(pmkid1name, "r")) == NULL)
	{
	fprintf(stderr, "failed to read PMKID file %s\n", pmkid1name);
	return false;
	}

pmkid1count = 0;
zeiger = pmkid1list;
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
	pmkid1count++;
	zeiger++;
	aktread++;
	}
fclose(fh_file);
if(pmkid1count > 0)
	{
	qsort(pmkid1list, pmkid1count, INTPMKID_SIZE, sort_intpmkid_by_essid);
	}
printf("%d record(s) read from %s\n", pmkid1count, pmkid1name);
return true;
}
/*===========================================================================*/

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
	"-e <essid>  : filter by ESSID\n"
	"-E <essid>  : filter by part of ESSID\n"
	"-l <essid>  : filter by ESSID length\n"
	"-h          : show this help\n"
	"-v          : show version\n"
	"\n"
	"--pmkid1=<file>        : input PMKID file 1\n"
	"--pmkid2=<file>        : input PMKID file 2\n"
	"--pmkidout12=<file>    : output only lines present in both PMKID1 and PMKID2\n"
	"--pmkidout1=<file>     : output only lines present in PMKID1\n"
	"--pmkidout2=<file>     : output only lines present in PMKID2\n"
	"--pmkidout=<file>      : output only ESSID filtered lines present in PMKID1\n"
	"--pmkidgroupout=<file> : output ESSID groups from ESSIDs present in PMKID1\n"
	"--hccapx1=<file>       : input HCCAPX1\n"
	"--hccapx2=<file>       : input HCCAPX2\n"
	"--hccapxout12=<file>   : output only lines present in both HCCAPX1 and HCCAPX2\n"
	"--hccapxout1=<file>    : output only lines present in HCCAPX1\n"
	"--hccapxout2=<file>    : output only lines present in HCCAPX2\n"
	"--hccapxout=<file>     : output only ESSID filtered lines present in HCCAPX1\n"
	"--hccapxgroupout=<file>: output ESSID groups from ESSIDs present in HCCAPX1\n"
	"--essidout=<file>      : output ESSID list\n"
	"--essidmacapout=<file> : output MAC_AP:ESSID list\n"
	"--help                 : show this help\n"
	"--version              : show version\n"
	"\n"
	"Main purpose is to get full advantage of reuse of PBKDF2\n"
	"while merging (only) the same ESSIDs from different hash files\n"
	"examples:\n"
	"hcxessidtool --pmkid1=file1.16800 --pmkid2=file2.16800 --pmkidout12=joint.16800\n"
	"hcxessidtool --pmkid1=file1.16800 -l 10 --pmkidout=filtered.16800\n"
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

static const char *short_options = "e:E:l:hv";
static const struct option long_options[] =
{
	{"pmkid1",			required_argument,	NULL,	HCXD_PMKID1},
	{"pmkid2",			required_argument,	NULL,	HCXD_PMKID2},
	{"pmkidout12",			required_argument,	NULL,	HCXD_WRITE_PMKID12},
	{"pmkidout1",			required_argument,	NULL,	HCXD_WRITE_PMKID1},
	{"pmkidout2",			required_argument,	NULL,	HCXD_WRITE_PMKID2},
	{"pmkidout",			required_argument,	NULL,	HCXD_WRITE_PMKID},
	{"pmkidgroupout",		no_argument,		NULL,	HCXD_WRITE_PMKID_GROUP},
	{"hccapx1",			required_argument,	NULL,	HCXD_HCCAPX1},
	{"hccapx2",			required_argument,	NULL,	HCXD_HCCAPX2},
	{"hccapxout12",			required_argument,	NULL,	HCXD_WRITE_HCCAPX12},
	{"hccapxout1",			required_argument,	NULL,	HCXD_WRITE_HCCAPX1},
	{"hccapxout2",			required_argument,	NULL,	HCXD_WRITE_HCCAPX2},
	{"hccapxout",			required_argument,	NULL,	HCXD_WRITE_HCCAPX},
	{"hccapxgroupout",		no_argument,		NULL,	HCXD_WRITE_HCCAPX_GROUP},
	{"essidout",			required_argument,	NULL,	HCXD_WRITE_ESSIDLIST},
	{"essidmacapout",		required_argument,	NULL,	HCXD_WRITE_ESSID_MACAP_LIST},
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
		case HCXD_PMKID1:
		pmkid1name = optarg;
		break;

		case HCXD_PMKID2:
		pmkid2name = optarg;
		break;

		case HCXD_WRITE_PMKID12:
		pmkid12outname = optarg;
		break;

		case HCXD_WRITE_PMKID1:
		pmkid1outname = optarg;
		break;

		case HCXD_WRITE_PMKID2:
		pmkid2outname = optarg;
		break;

		case HCXD_WRITE_PMKID:
		pmkidoutname = optarg;
		break;

		case HCXD_WRITE_PMKID_GROUP:
		pmkidgroupflag = true;
		break;

		case HCXD_HCCAPX1:
		hccapx1name = optarg;
		break;

		case HCXD_HCCAPX2:
		hccapx2name = optarg;
		break;

		case HCXD_WRITE_HCCAPX12:
		hccapx12outname = optarg;
		break;

		case HCXD_WRITE_HCCAPX1:
		hccapx1outname = optarg;
		break;

		case HCXD_WRITE_HCCAPX2:
		hccapx2outname = optarg;
		break;

		case HCXD_WRITE_HCCAPX:
		hccapxoutname = optarg;
		break;

		case HCXD_WRITE_HCCAPX_GROUP:
		hccapxgroupflag = true;
		break;

		case HCXD_WRITE_ESSIDLIST:
		essidoutname = optarg;
		break;

		case HCXD_WRITE_ESSID_MACAP_LIST:
		essidmacapoutname = optarg;
		break;
	
		case HCXD_ESSID_LEN:
		essidonlylen = strtoull(optarg, NULL, 10);
		if((essidonlylen < 1) || (essidonlylen > 32))
			{
			printf("wrong ESSID length (allowed 1...32 characters)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_ESSID:
		essidfiltername = optarg;
		essidfilterlen = strlen(optarg);
		if((essidfilterlen < 1) || (essidfilterlen > 32))
			{
			printf("wrong ESSID length (allowed 1...32 characters)\n");
			exit(EXIT_FAILURE);
			}
		break;

		case HCXD_ESSID_PART:
		essidpartfiltername = optarg;
		essidpartfilterlen = strlen(optarg);
		if((essidpartfilterlen < 1) || (essidpartfilterlen > 32))
			{
			printf("wrong ESSID length (allowed 1...32 characters)\n");
			exit(EXIT_FAILURE);
			}
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

if(pmkid1name != NULL)
	{
	readpmkid1file();
	}
if(pmkid2name != NULL)
	{
	readpmkid2file();
	}
if((pmkid12outname != NULL) && (pmkid1count > 0) && (pmkid2count > 0))
	{
	writepmkid12();
	}
if((pmkid1outname != NULL) && (pmkid1count > 0) && (pmkid2count > 0))
	{
	writepmkid1();
	}
if((pmkid2outname != NULL) && (pmkid1count > 0) && (pmkid2count > 0))
	{
	writepmkid2();
	}
if((pmkidoutname != NULL) && (pmkid1count > 0))
	{
	writepmkid();
	}
if((pmkidgroupflag == true) && (pmkid1count > 0))
	{
	writepmkidgroups();
	}

if(hccapx1name != NULL)
	{
	readhccapx1file();
	}
if(hccapx2name != NULL)
	{
	readhccapx2file();
	}
if((hccapx12outname != NULL) && (hccapx1count > 0) && (hccapx2count > 0))
	{
	writehccapx12();
	}
if((hccapx1outname != NULL) && (hccapx1count > 0) && (hccapx2count > 0))
	{
	writehccapx1();
	}
if((hccapx2outname != NULL) && (hccapx1count > 0) && (hccapx2count > 0))
	{
	writehccapx2();
	}
if((hccapxoutname != NULL) && (hccapx1count > 0))
	{
	writehccapx();
	}
if((hccapxgroupflag == true) && (hccapx1count > 0))
	{
	writehccapxgroups();
	}

if((essidoutname != NULL) && (pmkid1count > 0))
	{
	writeessidpmkid(pmkid1name, pmkid1list, pmkid1count);
	}
if((essidoutname != NULL) && (pmkid2count > 0))
	{
	writeessidpmkid(pmkid2name, pmkid2list, pmkid2count);
	}
if((essidoutname != NULL) && (hccapx1count > 0))
	{
	writeessidhccapx(hccapx1name, hccapx1list, hccapx1count);
	}
if((essidoutname != NULL) && (hccapx2count > 0))
	{
	writeessidhccapx(hccapx2name, hccapx2list, hccapx2count);
	}

if((essidmacapoutname != NULL) && (pmkid1count > 0))
	{
	writeessidmacappmkid(pmkid1name, pmkid1list, pmkid1count);
	}
if((essidmacapoutname != NULL) && (pmkid2count > 0))
	{
	writeessidmacappmkid(pmkid2name, pmkid2list, pmkid2count);
	}
if((essidmacapoutname != NULL) && (hccapx1count > 0))
	{
	writeessidmacaphccapx(hccapx1name, hccapx1list, hccapx1count);
	}
if((essidmacapoutname != NULL) && (hccapx2count > 0))
	{
	writeessidhccapx(hccapx2name, hccapx2list, hccapx2count);
	}




globalclose();

return EXIT_SUCCESS;
}
/*===========================================================================*/

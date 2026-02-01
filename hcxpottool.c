#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
 #include <sys/sysinfo.h>
#include <sys/types.h>
#include <unistd.h>
#include <utime.h>

#include "include/types.h"
#include "include/hcxpottool.h"

/*===========================================================================*/
/* globals */

static long int pmkcount = 0;
static long int pmkreaderrorcount = 0;
static long int pmkdoublecount = 0;
static long int pmkcalculatedcount = 0;
static long int pmkcorrectedcount = 0;
static long int pmkerrorcount = 0;

static pmklist_t *pmklist = NULL;
static FILE *fh_faulty = NULL;
static bool wantstopflag = false;
OSSL_LIB_CTX *library_context;
EVP_MD *md;
EVP_MD_CTX *mdctx;
static unsigned int mdlen;
static unsigned char *mdval;
static unsigned char *mdvalfile;
const char *option_properties;

static const char hexfmt[] = "$HEX[";
static const char hcpbkdf2fmt[] = "sha1:4096:";
static const char jtrpbkdf2fmt[] = "$pbkdf2-hmac-sha1$4096.";
static const char jtrpotfmt1[] = "$pbkdf2-hmac-sha1$4096$";
static const u8 base64map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const u8 hashmap1[] =
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
static const u8 hashmap2[] =
{
0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, // 01234567
0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66  // 89abcdef 
};
static const u8 zeromap32[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};
static char linein[INPUTLINEMAX];
static char lineout[OUTPUTLINEMAX];
/*===========================================================================*/
static inline void programmende(int signum)
{
if((signum == SIGINT) || (signum == SIGTERM) || (signum == SIGKILL)) wantstopflag = true;
return;
}
/*===========================================================================*/
static bool globalinit(void)
{
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
mdlen = 0;
md = NULL;
library_context = NULL;
option_properties = NULL;

library_context = OSSL_LIB_CTX_new();
if(library_context == NULL)
	{
	fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
	return false;
	}
md = EVP_MD_fetch(library_context, "SHA1", option_properties);
if(md == NULL)
	{
	fprintf(stderr, "EVP_MD_fetch could not find SHA1.");
	return false;
	}
mdlen = EVP_MD_get_size(md);
if(mdlen <= 0)
	{
	fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
	return false;
	}
mdval = OPENSSL_malloc(mdlen);
if(mdval == NULL)
	{
	fprintf(stderr, "No memory.\n");
	return false;
	}
mdvalfile = OPENSSL_malloc(mdlen);
if(mdvalfile == NULL)
	{
	fprintf(stderr, "No memory.\n");
	return false;
	}
mdctx = EVP_MD_CTX_new();
if(mdctx == NULL)
	{
	fprintf(stderr, "EVP_MD_CTX_new failed.\n");
	return false;
	}
if((pmklist = (pmklist_t*)calloc(PMKLISTLEN, PMKRECLEN)) == NULL) return false;
signal(SIGINT, programmende);
return true;
}
/*===========================================================================*/
static void globaldeinit(void)
{
if(mdctx != NULL) EVP_MD_CTX_free(mdctx);
if(mdvalfile != NULL) OPENSSL_free(mdvalfile);
if(mdval != NULL) OPENSSL_free(mdval);
if(md != NULL) EVP_MD_free(md);
if(library_context != NULL) OSSL_LIB_CTX_free(library_context);
EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();

if(pmklist != NULL) free(pmklist);
return;
}
/*===========================================================================*/
static void printstatus(void)
{
if(pmkcount != 0)		fprintf(stdout, "%ld valid entries \n", pmkcount);
if(pmkdoublecount != 0)		fprintf(stdout, "%ld double entries\n", pmkdoublecount);
if(pmkreaderrorcount != 0)	fprintf(stdout, "%ld PMK read errors\n", pmkreaderrorcount);
if(pmkcalculatedcount != 0)	fprintf(stdout, "%ld PMK(s) calculated\n", pmkcalculatedcount);
if(pmkcorrectedcount != 0)	fprintf(stdout, "%ld PMK(s) corrected\n", pmkcorrectedcount);
return;
}
/*===========================================================================*/
static bool needemuhexify(size_t flen, u8 *fin)
{
static size_t c;

if(fin[0] < 0x20) return true;
if(fin[0] == 0x7f) return true;
for(c = 1; c < flen; c++)
	{
	if(fin[c] < 0x20) return true;
	if(fin[c] == 0x7f) return true;
	if(fin[c - 1] == 0xc2)
		{
		if((fin[c] >= 0x80) && (fin[c] <= 0xa0)) return true;
		}
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool needasciihexify(size_t flen, u8 *fin)
{
static size_t c;
for(c = 0; c < flen; c++)
	{
	if(fin[c] < 0x20) return true;
	if(fin[c] > 0x7e) return true;
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool needdelimhexify(size_t flen, u8 *fin)
{
static size_t c;
for(c = 0; c < flen; c++)
	{
	if(fin[c] < 0x21) return true;
	if(fin[c] == ':') return true;
	if(fin[c] > 0x7e) return true;
	}
return false;
}
/*---------------------------------------------------------------------------*/
static bool needhexify(size_t flen, u8 *fin)
{
static size_t c;
for(c = 0; c < flen; c++)
	{
	if(fin[c] < 0x21) return true;
	if(fin[c] > 0x7e) return true;
	}
return false;
}
/*===========================================================================*/
static size_t writehex(size_t flen, u8 *fin, char *fout)
{
static size_t c;
static size_t i;
static u8 idx0;
static u8 idx1;

i = 0;
for(c = 0; c < flen; c++)
	{
	idx0 = (fin[c] >> 4) & 0xf;
	idx1 = fin[c] & 0xf;
	fout[i + 0] = (char)hashmap2[idx0];
	fout[i + 1] = (char)hashmap2[idx1];
	i += 2;
	}
return i;
}
/*---------------------------------------------------------------------------*/
static size_t writechar(size_t flen, u8 *fin, char *fout)
{
static size_t c;

for(c = 0; c < flen; c++)
	{
	fout[c] = fin[c];
	if(fout[c] == '\0') return c;
	}
return c;
}
/*===========================================================================*/
static int sort_pmklist_by_essidlen(const void *a, const void *b)
{
const pmklist_t *ia = (const pmklist_t *)a;
const pmklist_t *ib = (const pmklist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ESSIDLEN) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ESSIDLEN) < 0) return -1;
if(ia->psklen > ib->psklen) return 1;
else if(ia->psklen < ib->psklen) return -1;
if(memcmp(ia->psk, ib->psk, PSKLEN) > 0) return 1;
else if(memcmp(ia->psk, ib->psk, PSKLEN) < 0) return -1;

// sort by status ?

if(memcmp(ia->pmk, ib->pmk, PMKLEN) > 0) return -1;
else if(memcmp(ia->pmk, ib->pmk, PMKLEN) < 0) return 1;
return 0;
}
/*===========================================================================*/
static void writejtrpbkdf2file(char *jtrpbkdf2outname)
{
static long int c;
static size_t lopos;
static FILE *fh_jtrpbkdf2file;

if((fh_jtrpbkdf2file = fopen(jtrpbkdf2outname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", jtrpbkdf2outname, strerror(errno));
	return;
	}
memcpy(lineout, jtrpbkdf2fmt, 23);
for(c = 0; c < pmkcount; c++)
	{
	if((pmklist + c)->essidlen == 0) continue;
	if(memcmp(zeromap32, (pmklist + c)->pmk, PMKLEN) == 0) continue;
	lopos = 23;
	lopos += writehex((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
	lineout[lopos++] = '.';
	lopos += writehex(PMKLEN, (pmklist + c)->pmk, &lineout[lopos]);
	lineout[lopos] = '\0';
	fprintf(fh_jtrpbkdf2file, "%s\n", lineout);
	}
fclose(fh_jtrpbkdf2file);
return;
}
/*===========================================================================*/
static void writehcpbkdf2file(char *hcpbkdf2outname)
{
static long int c;
static size_t i;
static size_t lopos;
static size_t r;
static u32 buf24;
static FILE *fh_hcbkdf2file;

if((fh_hcbkdf2file = fopen(hcpbkdf2outname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", hcpbkdf2outname, strerror(errno));
	return;
	}
memcpy(lineout, hcpbkdf2fmt, 10);
for(c = 0; c < pmkcount; c++)
	{
	if((pmklist + c)->essidlen == 0) continue;
	if(memcmp(zeromap32, (pmklist + c)->pmk, PMKLEN) == 0) continue;
	i = 0;
	lopos = 10;
	while(i < (pmklist + c)->essidlen)
		{
		buf24 = 0;
		r = ((pmklist + c)->essidlen - i);
		buf24 |= ((u32)(pmklist + c)->essid[i++]) << 16;
		if(r > 1) buf24 |= ((u32)(pmklist + c)->essid[i++]) << 8;
		if(r > 2) buf24 |= (u32)(pmklist + c)->essid[i++];
		lineout[lopos++] = base64map[(buf24 >> 18) & 0x3F];
		lineout[lopos++] = base64map[(buf24 >> 12) & 0x3F];
		lineout[lopos++] = (r > 1) ? base64map[(buf24 >> 6) & 0x3F] : '=';
		lineout[lopos++] = (r > 2) ? base64map[buf24 & 0x3F] : '=';
		}
	lineout[lopos++] = ':';
	i = 0;
	while(i < PMKLEN)
		{
		buf24 = 0;
		r = (PMKLEN - i);
		buf24 |= ((u32)(pmklist + c)->pmk[i++]) << 16;
		if(r > 1) buf24 |= ((u32)(pmklist + c)->pmk[i++]) << 8;
		if(r > 2) buf24 |= (u32)(pmklist + c)->pmk[i++];
		lineout[lopos++] = base64map[(buf24 >> 18) & 0x3F];
		lineout[lopos++] = base64map[(buf24 >> 12) & 0x3F];
		lineout[lopos++] = (r > 1) ? base64map[(buf24 >> 6) & 0x3F] : '=';
		lineout[lopos++] = (r > 2) ? base64map[buf24 & 0x3F] : '=';
		}
	lineout[lopos] = '\0';
	fprintf(fh_hcbkdf2file, "%s\n", lineout);
	}
fclose(fh_hcbkdf2file);
return;
}
/*===========================================================================*/
static void writetabnhfile(char *tabnhoutname)
{
static long int c;
static size_t lopos = 0;
static size_t written = 0;
static FILE *fh_tabnhfile;

if((fh_tabnhfile = fopen(tabnhoutname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", tabnhoutname, strerror(errno));
	return;
	}
for(c = 0; c < pmkcount; c++)
	{
	if(((pmklist + c)->status & DOUBLEESSIDPSK) == DOUBLEESSIDPSK) continue;
	lopos = 0;
	written = writehex(PMKLEN, (pmklist + c)->pmk, &lineout[lopos]);
	lopos += written;
	lineout[lopos++] = '\t';
	if(needemuhexify((pmklist + c)->essidlen, (pmklist + c)->essid) == false)
		{
		written = writechar((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = '\t';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\t';
		}
	if(needemuhexify((pmklist + c)->psklen, (pmklist + c)->psk) == false)
		{
		written = writechar((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos] = '\0';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\0';
		}
	fprintf(fh_tabnhfile, "%s\n", lineout);
	}
fclose(fh_tabnhfile);
return;
}/*===========================================================================*/
static void writetabspfile(char *tabspoutname)
{
static long int c;
static size_t lopos = 0;
static size_t written = 0;
static FILE *fh_tabspfile;

if((fh_tabspfile = fopen(tabspoutname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", tabspoutname, strerror(errno));
	return;
	}
for(c = 0; c < pmkcount; c++)
	{
	if(((pmklist + c)->status & DOUBLEESSIDPSK) == DOUBLEESSIDPSK) continue;
	lopos = 0;
	written = writehex(PMKLEN, (pmklist + c)->pmk, &lineout[lopos]);
	lopos += written;
	lineout[lopos++] = '\t';
	if(needasciihexify((pmklist + c)->essidlen, (pmklist + c)->essid) == false)
		{
		written = writechar((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = '\t';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\t';
		}
	if(needasciihexify((pmklist + c)->psklen, (pmklist + c)->psk) == false)
		{
		written = writechar((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos] = '\0';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\0';
		}
	fprintf(fh_tabspfile, "%s\n", lineout);
	}
fclose(fh_tabspfile);
return;
}
/*===========================================================================*/
static void writetabfile(char *taboutname)
{
static long int c;
static size_t lopos = 0;
static size_t written = 0;
static FILE *fh_tabfile;

if((fh_tabfile = fopen(taboutname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", taboutname, strerror(errno));
	return;
	}
for(c = 0; c < pmkcount; c++)
	{
	if(((pmklist + c)->status & DOUBLEESSIDPSK) == DOUBLEESSIDPSK) continue;
	lopos = 0;
	written = writehex(PMKLEN, (pmklist + c)->pmk, &lineout[lopos]);
	lopos += written;
	lineout[lopos++] = '\t';
	if(needhexify((pmklist + c)->essidlen, (pmklist + c)->essid) == false)
		{
		written = writechar((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = '\t';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\t';
		}
	if(needhexify((pmklist + c)->psklen, (pmklist + c)->psk) == false)
		{
		written = writechar((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos] = '\0';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\0';
		}
	fprintf(fh_tabfile, "%s\n", lineout);
	}
fclose(fh_tabfile);
return;
}
/*===========================================================================*/
static void writepotfile(char *potoutname)
{
static long int c;
static size_t lopos = 0;
static size_t written = 0;
static FILE *fh_potfile;

if((fh_potfile = fopen(potoutname, "a")) == NULL)
	{
	fprintf(stdout, "error opening file %s: %s\n", potoutname, strerror(errno));
	return;
	}
for(c = 0; c < pmkcount; c++)
	{
	if(((pmklist + c)->status & DOUBLEESSIDPSK) == DOUBLEESSIDPSK) continue;
	lopos = 0;
	written = writehex(PMKLEN, (pmklist + c)->pmk, &lineout[lopos]);
	lopos += written;
	lineout[lopos++] = '*';
	written = writehex((pmklist + c)->essidlen, (pmklist + c)->essid, &lineout[lopos]);
	lopos += written;
	lineout[lopos++] = ':';
	if(needdelimhexify((pmklist + c)->psklen, (pmklist + c)->psk) == false)
		{
		written = writechar((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos] = '\0';
		}
	else
		{
		lineout[lopos++] = '$';
		lineout[lopos++] = 'H';
		lineout[lopos++] = 'E';
		lineout[lopos++] = 'X';
		lineout[lopos++] = '[';
		written = writehex((pmklist + c)->psklen, (pmklist + c)->psk, &lineout[lopos]);
		lopos += written;
		lineout[lopos++] = ']';
		lineout[lopos++] = '\0';
		}
	fprintf(fh_potfile, "%s\n", lineout);
	}
fclose(fh_potfile);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void sortandclean(void)
{
static long int c;

qsort(pmklist, pmkcount, PMKRECLEN, sort_pmklist_by_essidlen);
for(c = 1; c < pmkcount; c++)
	{
	if((pmklist + c)->essidlen != (pmklist + c -1)->essidlen) continue;
	if((pmklist + c)->psklen != (pmklist + c -1)->psklen) continue;
	if(memcmp((pmklist + c)->essid, (pmklist + c -1)->essid, ESSIDLEN) != 0) continue;
	if(memcmp((pmklist + c)->psk, (pmklist + c -1)->psk, PSKLEN) != 0) continue;
	pmkdoublecount += 1;
	(pmklist + c)->status |= DOUBLEESSIDPSK;
	}
return;
}
/*===========================================================================*/
static size_t getflen(size_t flen, u8 *fin)
{
static size_t c;

for(c = 0; c < flen; c++)
	{
	if(fin[c] == 0) return c;
	}
return c;
}
/*===========================================================================*/
static ssize_t readhex(size_t flen, char delim, char *fin, u8 *fout)
{
static size_t c;
static size_t i;
static u8 idx0;
static u8 idx1;

i = 0;
for(c = 0; c < (flen * 2); c += 2)
	{
	if(fin[c] == delim) return i;
	if(!isxdigit(fin[c])) return -1;
	if(!isxdigit(fin[c + 1])) return -1;
	idx0 = ((u8)fin[c + 0] & 0x1F) ^ 0x10;
	idx1 = ((u8)fin[c + 1] & 0x1F) ^ 0x10;
	fout[i] = (u8)(hashmap1[idx0] << 4) | hashmap1[idx1];
	i++;
	}
return i;
}
/*---------------------------------------------------------------------------*/
static ssize_t readchar(size_t flen, char delim, char *fin, u8 *fout)
{
static size_t c;

for(c = 0; c < flen; c++)
	{
	if(fin[c] == delim) return c;
	fout[c] = (u8)(fin[c]);
	}
return c;
}
/*===========================================================================*/
static size_t chop(char *buffer, size_t len)
{
static char *ptr;

ptr = buffer +len -1;
while(len)
	{
	if (*ptr != '\n') break;
	*ptr-- = 0;
	len--;
	}
while(len)
	{
	if (*ptr != '\r') break;
	*ptr-- = 0;
	len--;
	}
return len;
}
/*---------------------------------------------------------------------------*/
static ssize_t fgetline(FILE *inputstream, size_t size, char *buffer)
{
static size_t len;
static char *buffptr;

if(feof(inputstream)) return -1;
buffptr = fgets (buffer, size, inputstream);
if(buffptr == NULL) return -1;
len = strlen(buffptr);
len = chop(buffptr, len);
return len;
}
/*===========================================================================*/
static bool readoutfile(char *hcoutfileinname)
{
static ssize_t len = 0;
static ssize_t essidlen = 0;
static ssize_t psklen = 0;
static size_t lipos = 0;
static pmklist_t *pmklistnew = NULL;
static FILE *hcoutfile = NULL;

if((hcoutfile = fopen(hcoutfileinname, "rb")) == NULL) return false;
while(1)
	{
	if((len = fgetline(hcoutfile, INPUTLINEMAX, linein)) == -1) break;
	if(len < 61)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(linein[32] != ':')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(linein[33] == ':')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(linein[58] != ':')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	memset((pmklist + pmkcount)->pmk, 0, PMKLEN);
	lipos = 59;
	memset((pmklist + pmkcount)->essid, 0, ESSIDLEN);
	if(memcmp(&linein[lipos], hexfmt, 5) == 0)
		{
		lipos += 5;
		if((essidlen = readhex(ESSIDLEN, ']', &linein[lipos], (pmklist + pmkcount)->essid)) == -1)
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		lipos += essidlen * 2;
		if(linein[lipos] != ']')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		(pmklist + pmkcount)->essidlen = essidlen;
		lipos += 1;
		if(linein[lipos] != ':')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		lipos += 1;
		}
	else
		{
		essidlen = readchar(ESSIDLEN, ':', &linein[lipos], (pmklist + pmkcount)->essid);
		lipos += essidlen;
		if(linein[lipos] != ':')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		(pmklist + pmkcount)->essidlen = essidlen;
		lipos += 1;
		}
	memset((pmklist + pmkcount)->psk, 0, PSKLEN);
	if((memcmp(&linein[lipos], hexfmt, 5) == 0) && (linein[len - 1] == ']'))
		{
		lipos += 5;
		if((psklen = readhex(PSKLEN, ']', &linein[lipos], (pmklist + pmkcount)->psk)) == -1)
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		if(linein[lipos + psklen * 2] != ']')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		psklen = getflen(PSKLEN, (pmklist + pmkcount)->psk);
		}
	else
		{
		psklen = readchar(PSKLEN, 0, &linein[lipos], (pmklist + pmkcount)->psk);
		if(linein[lipos + psklen] != '\0')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		}
	if(psklen < 8) (pmklist + pmkcount)->psklen = 8;
	else (pmklist + pmkcount)->psklen = psklen;
	(pmklist + pmkcount)->status = UNCHECKED;
	pmkcount += 1;
	if((pmkcount % PMKLISTLEN) == 0)
		{
		pmklistnew = (pmklist_t*)realloc(pmklist, (pmkcount + PMKLISTLEN)* PMKRECLEN);
		if(pmklistnew == NULL)
			{
			pmkreaderrorcount += 1;
			fclose(hcoutfile);
			return false;
			}
		pmklist = pmklistnew;
		}
	}
fclose(hcoutfile);
return true;
}
/*===========================================================================*/
void *calculatepmkthreadcpu(void *arg)
{
long int c;
thread_info *tdata;

tdata = arg;
for(c = tdata->thread_num; c < pmkcount; c += tdata->cpucount)
	{
	if(wantstopflag == true) return NULL;
	if((pmklist + c)->status != UNCHECKED) continue;
	tdata->essidlen = (pmklist + c)->essidlen;
	memcpy(tdata->essid, (pmklist + c)->essid, (pmklist + c)->essidlen);
	tdata->psklen = (pmklist + c)->psklen;
	memcpy(tdata->psk, (pmklist + c)->psk, (pmklist + c)->psklen);
	if(PKCS5_PBKDF2_HMAC_SHA1((const char*)tdata->psk, tdata->psklen, tdata->essid, tdata->essidlen, 4096, PMKLEN, tdata->pmk) != 0)
		{
		(pmklist + c)->status = CALCULATED;
		tdata->calculatedcount += 1;
		if(memcmp(tdata->pmk, (pmklist + c)->pmk, PMKLEN) != 0)
			{
			memcpy((pmklist + c)->pmk, tdata->pmk, PMKLEN);
			tdata->correctedcount += 1;
			}
		}
	else tdata->errorcount += 1;
	}
return NULL;
}
/*---------------------------------------------------------------------------*/
static void calculatepmks(void)
{
static int c;
static int cpucount;
static int ret;
static void *res;
static thread_info tinfo[CPU_MAX];

cpucount = get_nprocs();
if(cpucount > CPU_MAX) cpucount = CPU_MAX;
fprintf(stdout, "%d threads started to calculate PMKs...\n", cpucount);
for(c = 0; c < cpucount; c++)
	{
	tinfo[c].thread_num = c;
	tinfo[c].cpucount = cpucount;
	tinfo[c].errorcount = 0;
	tinfo[c].calculatedcount = 0;
	tinfo[c].correctedcount = 0;
	ret = pthread_create(&tinfo[c].thread_id, NULL, &calculatepmkthreadcpu, &tinfo[c]);
	if(ret != 0)
		{
		fprintf(stderr, "failed to create threads\n");
		pmkerrorcount += 1;
		return;
		}
	}
for(c = 0; c < cpucount; c++)
	{
	ret = pthread_join(tinfo[c].thread_id, &res);
	pmkerrorcount += tinfo[c].errorcount;
	pmkcalculatedcount += tinfo[c].calculatedcount;
	pmkcorrectedcount += tinfo[c].correctedcount;
	if(ret != 0)
		{
		fprintf(stderr, "failed to join threads\n");
		pmkerrorcount += 1;
		return;
		}
	}
return;
}
/*===========================================================================*/
static bool readjtrpotfile(char *jtrpotfileinname)
{
static ssize_t len = 0;
static size_t lipos;
static size_t essidlen;
static size_t psklen;
static pmklist_t *pmklistnew = NULL;
static FILE *jtrpotfile = NULL;

if((jtrpotfile = fopen(jtrpotfileinname, "rb")) == NULL) return false;
while(1)
	{
	if((len = fgetline(jtrpotfile, INPUTLINEMAX, linein)) == -1) break;
	if(len < 91)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	lipos = 22;
	if(linein[lipos++] != '$') 
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(memcmp(linein, jtrpotfmt1, lipos) != 0)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	memset((pmklist + pmkcount)->essid, 0, ESSIDLEN);
	if((essidlen = readhex(ESSIDLEN, '$', &linein[lipos], (pmklist + pmkcount)->essid)) <= 0)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	(pmklist + pmkcount)->essidlen = essidlen;
	lipos += essidlen * 2;
	if(linein[lipos++] != '$')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(readhex(PMKLEN , ':', &linein[lipos], (pmklist + pmkcount)->pmk) != PMKLEN)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	lipos += PMKLEN * 2;
	if(linein[lipos++] != ':')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	memset((pmklist + pmkcount)->psk, 0, PSKLEN);
	psklen = readchar(PSKLEN, 0, &linein[lipos], (pmklist + pmkcount)->psk);
	if(linein[lipos + psklen] != '\0')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(psklen < 8) (pmklist + pmkcount)->psklen = 8;
	else (pmklist + pmkcount)->psklen = psklen;
	pmkcount += 1;
	if((pmkcount % PMKLISTLEN) == 0)
		{
		pmklistnew = (pmklist_t*)realloc(pmklist, (pmkcount + PMKLISTLEN)* PMKRECLEN);
		if(pmklistnew == NULL)
			{
			pmkreaderrorcount += 1;
			fclose(jtrpotfile);
			return false;
			}
		pmklist = pmklistnew;
		}
	}
fclose(jtrpotfile);
return true;
}
/*===========================================================================*/
static bool readpotfile(char *hcpotfileinname)
{
static ssize_t len = 0;
static ssize_t essidlen = 0;
static ssize_t psklen = 0;
static size_t lipos = 0;
static pmklist_t *pmklistnew = NULL;
static FILE *hcpotfile = NULL;

if((hcpotfile = fopen(hcpotfileinname, "rb")) == NULL) return false;
while(1)
	{
	if((len = fgetline(hcpotfile, INPUTLINEMAX, linein)) == -1) break;
	if(len < 68)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	lipos = 64;
	if(linein[lipos] != '*')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	if(readhex(PMKLEN , '*', linein, (pmklist + pmkcount)->pmk) != PMKLEN)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	lipos++;
	memset((pmklist + pmkcount)->essid, 0, ESSIDLEN);
	if((essidlen = readhex(ESSIDLEN, ':', &linein[lipos], (pmklist + pmkcount)->essid)) <= 0)
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	(pmklist + pmkcount)->essidlen = essidlen;
	lipos += essidlen * 2;
	if(linein[lipos] != ':')
		{
		if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
		pmkreaderrorcount += 1;
		continue;
		}
	lipos++;
	memset((pmklist + pmkcount)->psk, 0, PSKLEN);
	if((memcmp(&linein[lipos], hexfmt, 5) == 0) && (linein[len - 1] == ']'))
		{
		lipos += 5;
		if((psklen = readhex(PSKLEN, ']', &linein[lipos], (pmklist + pmkcount)->psk)) == -1)
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		if(linein[lipos + psklen * 2] != ']')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		psklen = getflen(PSKLEN, (pmklist + pmkcount)->psk);
		}
	else
		{
		psklen = readchar(PSKLEN, 0, &linein[lipos], (pmklist + pmkcount)->psk);
		if(linein[lipos + psklen] != '\0')
			{
			if(fh_faulty != NULL) fprintf(fh_faulty, "%s\n", linein);
			pmkreaderrorcount += 1;
			continue;
			}
		}
	if(psklen < 8) (pmklist + pmkcount)->psklen = 8;
	else (pmklist + pmkcount)->psklen = psklen;
	(pmklist + pmkcount)->status = 0;
	pmkcount += 1;
	if((pmkcount % PMKLISTLEN) == 0)
		{
		pmklistnew = (pmklist_t*)realloc(pmklist, (pmkcount + PMKLISTLEN)* PMKRECLEN);
		if(pmklistnew == NULL)
			{
			pmkreaderrorcount += 1;
			fclose(hcpotfile);
			return false;
			}
		pmklist = pmklistnew;
		}
	}
fclose(hcpotfile);
return true;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
fprintf(stdout, "%s %s  (C) %s ZeroBeat\n"
	"usage  : %s <options>\n"
	"\n"
	"short options:\n"
	"-h                   : show this help\n"
	"-v                   : show version\n"
	"\n"
	"long options:\n"
	"--hcpotin=<file>     : input potfile in hashcat pot file format\n"
	"                        format: PMK*ESSID:PSK\n"
	"--hcoutin=<file>     : input outfile in hashcat out file format\n"
	"                        format: MIC/PMKID:MAC_AP:MAC_CLIENT:ESSID:PSK\n"
	"                        verify/calculate plain master keys enabled by default\n"
	"--jtrpotin=<file>    : input potfile in john pot file format\n"
	"                        format: $pbkdf2-hmac-sha1$ESSID$PMK:PSK\n" 
	"--hcpotout=<file>    : output potfile in hashcat format\n"
	"                        hexified characters < 0x20\n"
	"                        hexified characters > 0x7e\n"
	"                        hexified delimiter :\n"
	"--hcpbkdf2out=<file> : output hashcat hash file format 12000\n"
	"--jtrpbkdf2out=<file>: output john hash file format PBKDF2-HMAC-SHA1-opencl / PBKDF2-HMAC-SHA1\n"
	"--tabout=<file>      : output tabulator separated file\n"
	"                        hexified characters < 0x21\n"
	"                        hexified characters > 0x7e\n"
	"--tabspout=<file>    : output tabulator separated file\n"
	"                        hexified characters < 0x20\n"
	"                        hexified characters > 0x7e\n"
	"--tabnhout=<file>    : output tabulator separated file\n"
	"                        hexified characters < 0x20\n"
	"                        use with care\n"
	"--faultyout=<file>   : output faulty lines file\n"
	"--pmkoff             : disable verification/calculation of plain master keyss\n"
	"--help               : show this help\n"
	"--version            : show version\n\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s by ZeroBeat\n"
	"usage: %s -h for help\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
static int auswahl;
static int index;
static bool pmkoff = false;
static char *potinname = NULL;
static char *outinname = NULL;
static char *potoutname = NULL;
static char *hcpbkdf2outname = NULL;
static char *jtrpotinname = NULL;
static char *jtrpbkdf2outname = NULL;
static char *taboutname = NULL;
static char *tabspoutname = NULL;
static char *tabnhoutname = NULL;
static char *faultyoutname = NULL;

static const char *short_options = "hv";
static const struct option long_options[] =
{
	{"hcpotin",			required_argument,	NULL,	HC_POTIN},
	{"hcoutin",			required_argument,	NULL,	HC_OUTIN},
	{"jtrpotin",			required_argument,	NULL,	JTR_POTIN},
	{"tabout",			required_argument,	NULL,	HCX_TABOUT},
	{"tabspout",			required_argument,	NULL,	HCX_TABSPOUT},
	{"tabnhout",			required_argument,	NULL,	HCX_TABNHOUT},
	{"hcpotout",			required_argument,	NULL,	HC_POTOUT},
	{"hcpbkdf2out",			required_argument,	NULL,	HC_PBKDF2OUT},
	{"jtrpbkdf2out",		required_argument,	NULL,	JTR_PBKDF2OUT},
	{"faultyout",			required_argument,	NULL,	HCX_FAULTYOUT},
	{"pmkoff",			no_argument,		NULL,	HCX_PMKOFF},
	{"version",			no_argument,		NULL,	HCX_VERSION},
	{"help",			no_argument,		NULL,	HCX_HELP},
	{NULL,				0,			NULL,	0}
};

auswahl = -1;
index = 0;
optind = 1;
optopt = 0;

while((auswahl = getopt_long(argc, argv, short_options, long_options, &index)) != -1)
	{
	switch (auswahl)
		{
		case HC_POTIN:
		potinname = optarg;
		break;

		case HC_OUTIN:
		outinname = optarg;
		break;

		case HC_POTOUT:
		potoutname = optarg;
		break;

		case HC_PBKDF2OUT:
		hcpbkdf2outname = optarg;
		break;

		case JTR_POTIN:
		jtrpotinname = optarg;
		break;

		case JTR_PBKDF2OUT:
		jtrpbkdf2outname = optarg;
		break;

		case HCX_TABOUT:
		taboutname = optarg;
		break;

		case HCX_TABSPOUT:
		tabspoutname = optarg;
		break;

		case HCX_TABNHOUT:
		tabnhoutname = optarg;
		break;
		case HCX_FAULTYOUT:
		faultyoutname = optarg;
		break;

		case HCX_PMKOFF:
		pmkoff = true;
		break;

		case HCX_HELP:
		usage(basename(argv[0]));
		break;

		case HCX_VERSION:
		version(basename(argv[0]));
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}
setbuf(stdout, NULL);

if(globalinit() == false)
	{
	fprintf(stderr, "failed to init lists\n");
	return EXIT_FAILURE;
	}

if(faultyoutname != NULL)
	{
	if((fh_faulty = fopen(faultyoutname, "a+")) == NULL) fprintf(stdout, "error opening file %s: %s\n", faultyoutname, strerror(errno));
	}

if(potinname != NULL)
	{
	if(readpotfile(potinname) == false)
		{
		fprintf(stderr, "failed to read %s\n", potinname);
		goto ende;
		}
	}

if(outinname != NULL)
	{
	pmkoff = false;
	if(readoutfile(outinname) == false)
		{
		fprintf(stderr, "failed to read %s\n", outinname);
		goto ende;
		}
	}

if(jtrpotinname != NULL)
	{
	if(readjtrpotfile(jtrpotinname) == false)
		{
		fprintf(stderr, "failed to read %s\n", jtrpotinname);
		goto ende;
		}
	}

if(pmkcount > 1) sortandclean();

if(pmkcount > 0)
	{
	if(pmkoff == false) calculatepmks();
	if(potoutname != NULL) writepotfile(potoutname);
	if(taboutname != NULL) writetabfile(taboutname);
	if(tabspoutname != NULL) writetabspfile(tabspoutname);
	if(tabnhoutname != NULL) writetabnhfile(tabnhoutname);
	if(hcpbkdf2outname != NULL) writehcpbkdf2file(hcpbkdf2outname);
	if(jtrpbkdf2outname != NULL) writejtrpbkdf2file(jtrpbkdf2outname);
	}
ende:
if(faultyoutname != NULL) fclose(fh_faulty);
printstatus();
globaldeinit();
return EXIT_SUCCESS;
}
/*===========================================================================*/

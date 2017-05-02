#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <utime.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

/*===========================================================================*/
int main(int argc, char *argv[])
{
int p;
int k;
int maclen = 12;
int keysetlen = 58;

char *macstring = NULL;
char *keystring = NULL;

SHA_CTX ctx;
MD5_CTX mctx;

unsigned char digest[SHA_DIGEST_LENGTH];
unsigned char digestm[MD5_DIGEST_LENGTH];

char testmacstring[] = "112233445566";
char testkeysetstring[] = "123456789abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";

macstring = testmacstring;
keystring = testkeysetstring;

if(argc == 3)
	{
	macstring = argv[1];
	maclen = strlen(argv[1]);
	keystring = argv[2];
	keysetlen = strlen(argv[2]);
	}

else
	{
	printf("usage: pwhash word charset\nexample: pwhash %s %s\n", testmacstring, testkeysetstring);
	}


SHA1_Init(&ctx);
SHA1_Update(&ctx, macstring, maclen);
SHA1_Final(digest, &ctx);

printf("\nsha1-hex: ");
for (p = 0; p < SHA_DIGEST_LENGTH; ++p)
	{
	printf("%02x",digest[p]);
	}

printf("\nsha1....: ");
for (p = 0; p < SHA_DIGEST_LENGTH; ++p)
	{
	k = (digest[p] %keysetlen);
	printf("%c",keystring[k]);
	}

MD5_Init(&mctx);
MD5_Update(&mctx, macstring, maclen);
MD5_Final(digestm, &mctx);

printf("\nmd5-hex.: ");
for (p = 0; p < MD5_DIGEST_LENGTH; ++p)
	{
	printf("%02x",digestm[p]);
	}

printf("\nmd5.....: ");
for (p = 0; p < MD5_DIGEST_LENGTH; ++p)
	{
	k = (digestm[p] %keysetlen);
	printf("%c",keystring[k]);
	}

printf("\n");

return EXIT_SUCCESS;
}

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <ctype.h>
#include <sys/stat.h>
#include <stdio_ext.h>
#include <openssl/md5.h>

#include "common.h"

/*===========================================================================*/
/* globale Variablen */

hcx_t *hcxdata = NULL;

bool stdoutflag = false;
bool fileflag = false;
bool wpsflag = false;
bool eudateflag = false;
bool usdateflag = false;

FILE *fhpsk;

int thisyear = 0;

char pskstring[66];

/*===========================================================================*/
/* globale Initialisierung */

bool globalinit()
{
time_t t = time(NULL);
struct tm *tm = localtime(&t);

thisyear = tm->tm_year +1900;
return true;
}
/*===========================================================================*/
void writepsk(const char *pskstring)
{
bool lflag = false;
bool uflag = false;

int p, l;
l = strlen(pskstring);

char lowerpskstring[66];
char upperpskstring[66];

if((l < 8) || (l > 32))
	return;

memset(&lowerpskstring, 0, 66);
memset(&upperpskstring, 0, 66);

for(p = 0; p < l; p++)
	{
	if(islower(pskstring[p]))
		{
		upperpskstring[p] = toupper(pskstring[p]);
		uflag = true;
		}
	else
		{
		upperpskstring[p] = pskstring[p];
		}

	if(isupper(pskstring[p]))
		{
		lowerpskstring[p] = tolower(pskstring[p]);
		lflag = true;
		}
	else
		{
		lowerpskstring[p] = pskstring[p];
		}
	}

if(stdoutflag == true)
	{
	fprintf(stdout,"%s\n", pskstring);
	if(uflag == true)
		fprintf(stdout,"%s\n", upperpskstring);
	if(lflag == true)
		fprintf(stdout,"%s\n", lowerpskstring);
	}

if(fileflag == true)
	{
	fprintf(fhpsk,"%s\n", pskstring);
	if(uflag == true)
		fprintf(fhpsk,"%s\n", upperpskstring);
	if(lflag == true)
		fprintf(fhpsk,"%s\n", lowerpskstring);

	}
return;
}
/*===========================================================================*/
void keywriteweakpass()
{
size_t w;

const char *weakword[] =
{
"00000000", "0000000000", "01234567", "0123456789", "0123456789012345", "0987654321",
"1029384756", "11111111", "1111111111", "111222333", "11223344", "1122334455", "11235813",
"1123581321", "12121212", "123123123", "123321123", "12341234", "12344321", "1234512345",
"123454321", "1234554321", "12345678", "123456789", "1234567890", "12345678910",
"123456789a", "12345678a", "1234567a", "123456abc", "12345qwert", "1234abcd",
"1234qwer", "123654789", "12369874", "123698745", "123789456", "123qweasd",
"123qweasdzxc", "12qwaszx", "1357924680", "147258369", "147852369", "14789632",
"147896325", "192837465", "1a2b3c4d", "1q2w3e4r", "1q2w3e4r", "1q2w3e4r5t",
"1q2w3e4r5t6y", "1qaz2wsx", "1qazxsw2", "22222222", "321654987", "4815162342",
"55555555", "741852963", "76543210", "77777777", "789456123", "87654321",
"88888888", "963852741", "987654321", "9876543210", "999999999", "a1234567",
"a123456789", "a1b2c3d4", "a1b2c3d4e5", "a1s2d3f4", "Aa123456", "aaaaaaaa",
"aaaaaaaaaa", "abc12345", "abcd1234", "abcdefgh", "adgjmptw", "alexander",
"Alexandra", "Amsterdam", "Anderson", "Angelina", "Apollo13", "asdasdasd",
"asdf1234", "asdfasdf", "asdfghjk", "asdfghjkl", "Assassin", "Atlantis",
"Australia", "azertyuiop", "Babygirl", "Barcelona", "Baseball", "Basketball",
"Benjamin", "BigDaddy", "BlaBlaBla", "BlahBlah", "Blink182", "Blizzard",
"Brooklyn", "Bullshit", "Butterfly", "California", "CallofDuty", "Carolina",
"Caroline", "Carpediem", "Catherine", "Champion", "Changeme", "Charlie1",
"Charlotte", "Cheyenne", "Chocolate", "Christian", "Christina", "Christine",
"Christopher", "Cocacola", "Colorado", "Computer", "Corvette", "Courtney",
"Creative", "Danielle", "Darkness", "December", "Dolphins", "DragonBall",
"drowssap", "Einstein", "Elephant", "Elizabeth", "Evolution", "Facebook",
"Fernando", "Fireball", "Firebird", "Football", "Football1", "Franklin",
"FuckYou2", "Gangster", "Garfield", "Giovanni", "Godzilla", "Goldfish",
"GoodLuck", "GreenDay", "Hallo123", "Hardcore", "Harrison", "HarryPotter",
"Hello123", "HelloKitty", "Hercules", "IceCream", "idontknow", "iloveyou",
"Infinity", "Internet", "Inuyasha", "Isabella", "Isabelle", "JamesBond",
"Jennifer", "Jonathan", "Jordan23", "justdoit", "Juventus", "Kamikaze",
"Kawasaki", "Kimberly", "KingKong", "Kristina", "LasVegas", "Leonardo",
"LinkinPark", "Liverpool", "Logitech", "Lollipop", "LoveLove", "Manchester",
"Marlboro", "Marshall", "Maverick", "Mercedes", "Metallica", "Michael1",
"Michelle", "Microsoft", "Midnight", "Mitchell", "MoonLight", "MotherFucker",
"Motorola", "Napoleon", "NewCastle", "Nicholas", "Nightmare", "Nintendo",
"November", "Pa55w0rd", "Pa55word", "Pakistan", "Panasonic", "Paradise",
"Passport", "Passw0rd", "Password1", "Password123", "Passwort", "Patricia",
"Pavilion", "PeterPan", "Pineapple", "Platinum", "Playstation", "PoohBear",
"Portugal", "Precious", "Predator", "Princess", "P@ssw0rd", "q1w2e3r4",
"q1w2e3r4t5", "qazwsx123", "qazwsxedc", "qweasdzxc", "qwer1234", "qwerasdf",
"qwert123", "qwerty12", "qwerty123", "qwertyui", "qwertyuiop", "Rammstein",
"RealMadrid", "Remember", "Rockstar", "Ronaldo7", "RunEscape", "Rush2112",
"Samantha", "Savannah", "Scarface", "Scorpion", "Scotland", "Sebastian",
"Security", "September", "Serenity", "Simpsons", "Skateboard", "Skittles",
"Skywalker", "Slipknot", "Snickers", "Snowball", "Snowboard", "Something",
"Southpark", "Spiderman", "Spitfire", "SpongeBob", "Starcraft", "Stargate",
"StarTrek", "StarWars", "Steelers", "Stephanie", "Strawberry", "Sunflower",
"Sunshine", "Superman", "Superstar", "Swordfish", "Serminator", "SestTest",
"Tinkerbell", "TrustNo1", "Twilight", "Undertaker", "Valentina", "Valentine",
"Veronica", "Victoria", "Warcraft", "Warhammer", "Welcome1", "Westside",
"WhatEver", "Williams", "Wolverine", "Wordpass", "zaq12wsx", "zaq1xsw2"
};

for(w = 0; w < (sizeof(weakword) / sizeof(weakword[0])); w++)
	writepsk(weakword[w]);

return;
}
/*===========================================================================*/
void keywriteeudate()
{
int d ,m ,y;

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 1; d <= 28; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, 64, "%02d%02d%04d", d, m, y);
			writepsk(pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 29; d <= 30; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, 64, "%02d%02d%04d", d, m, y);
			writepsk(pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, 64, "3101%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "3103%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "3105%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "3107%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "3108%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "3110%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "3112%04d", y);
	writepsk(pskstring);
	}

for(y = 1900; y <= thisyear; y++)
	{
	if (((y %4 == 0) && (y %100 != 0)) || (y %400 == 0))
		{
		snprintf(pskstring, 64, "2902%04d", y);
		writepsk(pskstring);
		}
	}
return;
}
/*===========================================================================*/
void keywriteusdate()
{
int d ,m ,y;

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 1; d <= 28; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, 64, "%02d%02d%04d", m, d, y);
			writepsk(pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 29; d <= 30; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, 64, "%02d%02d%04d", m, d, y);
			writepsk(pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, 64, "0131%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "0331%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "0531%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "0731%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "0831%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "1031%04d", y);
	writepsk(pskstring);

	snprintf(pskstring, 64, "1231%04d", y);
	writepsk(pskstring);
	}

for(y = 1900; y <= thisyear; y++)
	{
	if (((y %4 == 0) && (y %100 != 0)) || (y %400 == 0))
		{
		snprintf(pskstring, 64, "0229%04d", y);
		writepsk(pskstring);
		}
	}
return;
}
/*===========================================================================*/
void keywriteyearyear()
{
int y, y2;

for(y = 1900; y <= thisyear; y++)
	{
	for(y2 = 1900; y2 <= thisyear; y2++)
		{
		snprintf(pskstring, 64, "%04d%04d", y, y2);
		writepsk(pskstring);
		}
	}
return;
}
/*===========================================================================*/
void keywritemd5mac(unsigned long long int mac_in)
{
MD5_CTX ctxmd5;
int k;
int p;
const char keystring[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char macstring[20];
unsigned char digestmd5[MD5_DIGEST_LENGTH];

snprintf(macstring, 14, "%012llX", mac_in);
MD5_Init(&ctxmd5);
MD5_Update(&ctxmd5, macstring, 12);
MD5_Final(digestmd5, &ctxmd5);

for (p = 0; p < 10; p++)
	{
	if(stdoutflag == true)
		fprintf(stdout, "%02x",digestmd5[p]);
	if(fileflag == true)
		fprintf(fhpsk, "%02x",digestmd5[p]);
	}
if(stdoutflag == true)
	fprintf(stdout, "\n");
if(fileflag == true)
	fprintf(fhpsk, "\n");

for (p = 0; p < 8; p++)
	{
	k = (digestmd5[p] %26);
	if(stdoutflag == true)
		fprintf(stdout, "%c",keystring[k]);
	if(fileflag == true)
		fprintf(fhpsk, "%c",keystring[k]);
	}
if(stdoutflag == true)
	fprintf(stdout, "\n");
if(fileflag == true)
	fprintf(fhpsk, "\n");

for (p = 0; p < 10; p++)
	{
	k = (digestmd5[p] %26);
	if(stdoutflag == true)
		fprintf(stdout, "%c",keystring[k]);
	if(fileflag == true)
		fprintf(fhpsk, "%c",keystring[k]);
	}
if(stdoutflag == true)
	fprintf(stdout, "\n");
if(fileflag == true)
	fprintf(fhpsk, "\n");

for (p = 0; p < 15 ; p +=2)
	{
	k = (digestmd5[p] %26);
	if(stdoutflag == true)
		fprintf(stdout, "%c",keystring[k]);
	if(fileflag == true)
		fprintf(fhpsk, "%c",keystring[k]);
	}
if(stdoutflag == true)
	fprintf(stdout, "\n");
if(fileflag == true)
	fprintf(fhpsk, "\n");

for (p = 1; p < 16 ; p +=2)
	{
	k = (digestmd5[p] %26);
	if(stdoutflag == true)
		fprintf(stdout, "%c",keystring[k]);
	if(fileflag == true)
		fprintf(fhpsk, "%c",keystring[k]);
	}
if(stdoutflag == true)
	fprintf(stdout, "\n");
if(fileflag == true)
	fprintf(fhpsk, "\n");
return;
}
/*===========================================================================*/
void keywritemac(unsigned long long int mac_in)
{
unsigned long long int mac_out;

snprintf(pskstring, 64,  "%012llx", mac_in);
writepsk(pskstring);
snprintf(pskstring, 64,  "%08lld", mac_in);
writepsk(pskstring);

mac_out = mac_in & 0xfffffffffff;
snprintf(pskstring, 64,  "%011llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);

mac_out = mac_in & 0xffffffffff;
snprintf(pskstring, 64,  "%010llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);

mac_out = mac_in & 0xfffffffff;
snprintf(pskstring, 64,  "%09llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);

mac_out = mac_in & 0xffffffff;
snprintf(pskstring, 64,  "%08llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);

mac_out = mac_in & 0xfffffff;
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);

mac_out = mac_in & 0xffffff;
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);

mac_out = (mac_in & 0xfffffffffff0) >> 4;
snprintf(pskstring, 64,  "%011llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%011lld", mac_out);
writepsk(pskstring);

mac_out = (mac_in & 0xffffffffff00) >> 8;
snprintf(pskstring, 64,  "%010llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%010lld", mac_out);
writepsk(pskstring);

mac_out = (mac_in & 0xfffffffff000) >> 12;
snprintf(pskstring, 64,  "%09llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%09lld", mac_out);
writepsk(pskstring);

mac_out = (mac_in & 0xffffffff0000) >> 16;
snprintf(pskstring, 64,  "%08llx", mac_out);
writepsk(pskstring);
snprintf(pskstring, 64,  "%08lld", mac_out);
writepsk(pskstring);
return;
}
/*---------------------------------------------------------------------------*/
unsigned int wpspinchecksum(unsigned int pin)
{
unsigned int accum = 0;

while (pin)
	{
	accum += 3 * (pin % 10);
	pin /= 10;
	accum += pin % 10;
	pin /= 10;
	}
return (10 - accum % 10) % 10;
}
/*---------------------------------------------------------------------------*/
void keywritemacwps(unsigned long long int mac)
{
unsigned int pin;

if(wpsflag == true)
	return;
pin = (mac & 0xffffff) % 10000000;
pin = ((pin * 10) + wpspinchecksum(pin));
snprintf(pskstring, 64, "%08d", pin);
writepsk(pskstring);
return;
}
/*===========================================================================*/
void keywriteallwpskeys()
{
int c, cs;

for(c = 0; c < 10000000; c++)
	{
	cs = wpspinchecksum(c);
	snprintf(pskstring, 64, "%07d%d", c, cs);
	writepsk(pskstring);
	}
return;
}
/*===========================================================================*/
void keywritemacrange(unsigned long long int mac)
{
keywritemac(mac);
keywritemac(mac -1);
keywritemac(mac +1);
keywritemac(mac -2);
keywritemac(mac +2);
keywritemac(mac -3);
keywritemac(mac +3);
keywritemac(mac -4);
keywritemac(mac +4);
keywritemacwps(mac);
keywritemacwps(mac -1);
keywritemacwps(mac +1);
keywritemacwps(mac -2);
keywritemacwps(mac +2);
keywritemacwps(mac -3);
keywritemacwps(mac +3);
keywritemacwps(mac -4);
keywritemacwps(mac +4);
return;
}
/*===========================================================================*/
void keywritemacvariants(unsigned long long int mac)
{
snprintf(pskstring, 64, "2%012llX", mac);
writepsk(pskstring);

snprintf(pskstring, 64, "m%012llX", mac);
writepsk(pskstring);

snprintf(pskstring, 64, "8747%06llx", mac &0xffffff);
writepsk(pskstring);

snprintf(pskstring, 64, "555A5053%08llX", mac &0xffffffff);
writepsk(pskstring);

snprintf(pskstring, 64, "555A5053%08llX", mac &0xffffffff);
writepsk(pskstring);

snprintf(pskstring, 64, "PLDTWIFI%05llX", mac &0xfffff);
writepsk(pskstring);

snprintf(pskstring, 64, "myBROWIFI%05llX", mac &0xfffff);
writepsk(pskstring);

return;
}
/*===========================================================================*/
void keywritemaccaesar(unsigned long long int mac)
{
int c;
int k = 0;

uint8_t caesar1[] = { 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 0x9, 0x8, 0x7, 0x6, 0x5, 0x4, 0x3, 0x2, 0x1, 0x0 };

for(c = 20; c >= 0; c -=4)
	k |= caesar1[mac >> c &0xf] << c; 

snprintf(pskstring, 64, "wlan%06x", k);
writepsk(pskstring);

return;
}
/*===========================================================================*/
unsigned long long int net2mac(const uint8_t *netadr)
{
int c;
unsigned long long int mac;

mac = 0;
for (c = 0; c < 6; c++)
	mac = (mac << 8) + netadr[c];
return mac;
}
/*===========================================================================*/
int sort_by_mac_ap(const void *a, const void *b)
{
hcx_t *ia = (hcx_t *)a;
hcx_t *ib = (hcx_t *)b;

if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap.addr, ib->mac_ap.addr, 6) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
void processbssid(long int hcxrecords)
{
hcx_t *zeigerhcx;
hcx_t *zeigerhcx1;
long int c;
unsigned long long int mac;

qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_mac_ap);
c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	zeigerhcx1 = hcxdata +c +1;
	if(memcmp(zeigerhcx->mac_ap.addr, zeigerhcx1->mac_ap.addr, 6) == 0)
		{
		c++;
		continue;
		}
	mac = net2mac(zeigerhcx->mac_ap.addr);
	keywritemacrange(mac);
	keywritemacvariants(mac);
	keywritemacvariants(mac -1);
	keywritemaccaesar(mac);
	keywritemaccaesar(mac -1);
	keywritemd5mac(mac);
	keywritemd5mac(mac -1);
	c++;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
void keywriteessiddigitxxx(char *basestring)
{
int d;

for(d = 0; d < 1000; d++)
	{
	snprintf(pskstring, 64, "%s%03d", basestring, d);
	writepsk(pskstring);
	snprintf(pskstring, 64, "%03d%s", d, basestring);
	writepsk(pskstring);
	}
return;
}
/*===========================================================================*/
void keywriteessiddigitxx(char *basestring)
{
int d;

for(d = 0; d < 100; d++)
	{
	snprintf(pskstring, 64, "%s%02d", basestring, d);
	writepsk(pskstring);
	snprintf(pskstring, 64, "%02d%s", d, basestring);
	writepsk(pskstring);
	}
return;
}
/*===========================================================================*/
void keywriteessiddigitx(char *basestring)
{
int d;

for(d = 0; d < 10; d++)
	{
	snprintf(pskstring, 64, "%s%d", basestring, d);
	writepsk(pskstring);
	snprintf(pskstring, 64, "%d%s", d, basestring);
	writepsk(pskstring);
	}
return;
}
/*===========================================================================*/
void keywriteessidyear(char *basestring)
{
int y;

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, 64, "%s%04d", basestring, y);
	writepsk(pskstring);
	snprintf(pskstring, 64, "%04d%s", y, basestring);
	writepsk(pskstring);
	}
return;
}
/*===========================================================================*/
void keywritepreappend5(char *basestring)
{
snprintf(pskstring, 64, "%s12345", basestring);
writepsk(pskstring);
snprintf(pskstring, 64, "12345%s", basestring);
writepsk(pskstring);
return;
}
/*===========================================================================*/
void keywritepreappend4(char *basestring)
{
snprintf(pskstring, 64, "%s1234", basestring);
writepsk(pskstring);
snprintf(pskstring, 64, "1234%s", basestring);
writepsk(pskstring);
return;
}
/*===========================================================================*/
void keywritepreappend1(char *basestring)
{
snprintf(pskstring, 64, "%s!", basestring);
writepsk(pskstring);
snprintf(pskstring, 64, "!%s", basestring);
writepsk(pskstring);
return;
}
/*===========================================================================*/
void sweepessidstr(int essidlenin, uint8_t *essidstrin)
{
int l1, l2;
char essidstr[34];

memset(&essidstr, 0, 34);
memcpy(essidstr, essidstrin, essidlenin);

for(l1 = 3; l1 <= essidlenin; l1++)
	{
	for(l2 = 0; l2 <= essidlenin -l1; l2++)
		{
		memset(&essidstr, 0, 34);
		memcpy(&essidstr, &essidstrin[l2], l1);
		if((l1 > 2) && (l1 < 59))
			{
			keywritepreappend5(essidstr);
			}
		if((l1 > 3) && (l1 < 60))
			{
			keywriteessidyear(essidstr);
			keywritepreappend4(essidstr);
			}
		if((l1 > 4) && (l1 < 61))
			keywriteessiddigitxxx(essidstr);
		if((l1 > 5) && (l1 < 62))
			keywriteessiddigitxx(essidstr);
		if((l1 > 6) && (l1 < 63))
			{
			keywriteessiddigitx(essidstr);
			keywritepreappend1(essidstr);
			}
		if((l1 > 7) && (l1 < 63))
			writepsk(essidstr);

		}
	}
return;
}
/*===========================================================================*/
void removesweepessidstr(int essidlenin, uint8_t *essidstrin)
{
int p1,p2;
int essidlenneu;
bool removeflag = false;
uint8_t essidstr[34];

memset(&essidstr, 0, 34);
essidlenneu = essidlenin;
p2 = 0;
for(p1 = 0; p1 < essidlenin; p1++)
	{
	if(((essidstrin[p1] >= 'A') && (essidstrin[p1] <= 'Z')) || ((essidstrin[p1] >= 'a') && (essidstrin[p1] <= 'z')))
		{
		essidstr[p2] = essidstrin[p1];
		removeflag = true;
		p2++;
		}
	else
		essidlenneu--;

	}

if(removeflag == true)
	sweepessidstr(essidlenneu, essidstr);

return;
}
/*===========================================================================*/
int sort_by_essid(const void *a, const void *b)
{
hcx_t *ia = (hcx_t *)a;
hcx_t *ib = (hcx_t *)b;

return memcmp(ia->essid, ib->essid, 32);
}
/*===========================================================================*/
void processessid(long int hcxrecords)
{
hcx_t *zeigerhcx;
hcx_t *zeigerhcx1;

long int c;


qsort(hcxdata, hcxrecords, HCX_SIZE, sort_by_essid);
c = 0;
while(c < hcxrecords)
	{
	zeigerhcx = hcxdata +c;
	zeigerhcx1 = hcxdata +c +1;

	if((zeigerhcx->essid_len == 0) || (zeigerhcx->essid_len > 32))
		{
		c++;
		continue;
		}
	if((zeigerhcx->essid_len == zeigerhcx1->essid_len) && (memcmp(zeigerhcx->essid, zeigerhcx1->essid, zeigerhcx->essid_len) == 0))
		{
		c++;
		continue;
		}
	sweepessidstr(zeigerhcx->essid_len, zeigerhcx->essid);
	removesweepessidstr(zeigerhcx->essid_len, zeigerhcx->essid);
	c++;
	}

return;
}
/*===========================================================================*/
long int readhccapx(char *hcxinname)
{
struct stat statinfo;
FILE *fhhcx;
long int hcxsize = 0;

if(hcxinname == NULL)
	return 0;

if(stat(hcxinname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hcxinname);
	return 0;
	}

if((statinfo.st_size % HCX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return 0;
	}

if((fhhcx = fopen(hcxinname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hcxinname);
	return 0;
	}

hcxdata = malloc(statinfo.st_size +HCX_SIZE);
if(hcxdata == NULL)
		{
		fprintf(stderr, "out of memory to store hccapx data\n");
		return 0;
		}

hcxsize = fread(hcxdata, 1, statinfo.st_size +HCX_SIZE, fhhcx);
if(hcxsize != statinfo.st_size)
	{
	fprintf(stderr, "error reading hccapx file %s", hcxinname);
	return 0;
	}
fclose(fhhcx);
return hcxsize / HCX_SIZE;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage..: %s <options>\n"
	"example: %s -i <hccapx> -W -s | hashcat -m 2500 <hccapx>\n"
	"\n"
	"options:\n"
	"-i <file> : input hccapx file\n"
	"-o <file> : output plainkeys to file\n"
	"-s        : output plainkeys to stdout (pipe to hashcat)\n"
	"-W        : include wps keys\n"
	"-D        : include european date\n"
	"-d        : include american date\n"
	"-h        : this help\n"
	"-v        : version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname, eigenname);
exit(EXIT_FAILURE);
}
/*===========================================================================*/
int main(int argc, char *argv[])
{
int auswahl;
long int hcxorgrecords = 0;

char *eigenname = NULL;
char *eigenpfadname = NULL;
char *hcxinname = NULL;
char *pskfilename = NULL;

eigenpfadname = strdupa(argv[0]);
eigenname = basename(eigenpfadname);

setbuf(stdout, NULL);
while ((auswahl = getopt(argc, argv, "i:o:sWDdhv")) != -1)
	{
	switch (auswahl)
		{
		case 'i':
		hcxinname = optarg;
		break;

		case 'o':
		pskfilename = optarg;
		fileflag = true;
		break;

		case 's':
		stdoutflag = true;
		break;

		case 'W':
		wpsflag = true;
		break;

		case 'D':
		eudateflag = true;
		break;

		case 'd':
		usdateflag = true;
		break;

		default:
		usage(eigenname);
		}
	}

if(globalinit() == false)
	{
	fprintf(stderr, "initialization failed\n");
	exit(EXIT_FAILURE);
	}

hcxorgrecords = readhccapx(hcxinname);

if(hcxorgrecords == 0)
	{
	fprintf(stderr, "%ld records loaded\n", hcxorgrecords);
	return EXIT_SUCCESS;
	}

if(pskfilename != NULL)
	{
	if((fhpsk = fopen(pskfilename, "w")) == NULL)
		{
		fprintf(stderr, "1 error opening psk file %s\n", pskfilename);
		exit(EXIT_FAILURE);
		}
	}

if((stdoutflag == true) || (fileflag == true))
	{
	keywriteweakpass();
	processbssid(hcxorgrecords);
	processessid(hcxorgrecords);
	if(wpsflag == true)
		keywriteallwpskeys();
	if(eudateflag == true)
		keywriteeudate();
	if(usdateflag == true)
		keywriteusdate();
	if((eudateflag == true) ||(usdateflag == true))
		keywriteyearyear();
	}

if(hcxdata != NULL)
	free(hcxdata);

if(pskfilename != NULL)
	fclose(fhpsk);

return EXIT_SUCCESS;
}

#define _GNU_SOURCE
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
#include <openssl/md5.h>
#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/version.h"
#include "include/hcxpsktool.h"
#include "include/hashcatops.h"
#include "include/strings.c"

/*===========================================================================*/
/* global var */

apessidl_t *apessidliste;
int apessidcount;
int thisyear;
/*===========================================================================*/
/*===========================================================================*/
static void writepsk(FILE *fhout, const char *pskstring)
{
bool lflag = false;
bool uflag = false;
int p, l;
char lowerpskstring[PSKSTRING_LEN_MAX] = {};
char upperpskstring[PSKSTRING_LEN_MAX] = {};

l = strlen(pskstring);
if((l < 8) || (l > PSKSTRING_LEN_MAX))
	{
	return;
	}
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

fprintf(fhout,"%s\n", pskstring);
if(uflag == true)
	fprintf(fhout,"%s\n", upperpskstring);
if(lflag == true)
	fprintf(fhout,"%s\n", lowerpskstring);
return;
}
/*===========================================================================*/
static void keywritenetgear(FILE *fhout)
{
size_t ca, cn, cs;

char pskstring[PSKSTRING_LEN_MAX] = {};

const char *adjectiv[] = { "absurd", "ancient", "antique", "aquatic",
	"baby", "basic", "big", "bitter", "black", "blue", "bold", "bottled", "brave", "breezy", "bright", "brown",
	"calm", "carrot", "cash", "charming", "cheerful", "chip", "chummy", "classy", "clean", "clear", "clever", "cloudy", "cold", "cool", "crispy", "curly",
	"daily", "deep", "delightful", "dizzy", "dynamic",
	"east", "elated", "elegant", "excite", "excited", "exotic",
	"famous", "fancy", "fearless", "festive", "fluffy", "free", "fresh", "friendly", "funny", "fuzzy",
	"gentle", "gifted", "gigantic", "good", "graceful", "grand", "great", "green",
	"happy", "heavy", "helpful", "hot", "hungry", "husky",
	"icy", "imaginary", "invisible",
	"jagged", "jolly", "joyful", "joyous",
	"kind",
	"large", "light", "little", "lively", "lovely", "lucky", "lumpy",
	"magical", "manic", "mellow", "melodic", "mighty", "misty", "modern",
	"narrow", "new", "nice", "nifty", "noisy", "normal",
	"occur", "odd", "old", "orange", "ordinary",
	"painless", "pastel", "peaceful", "perfect", "phobic", "pink", "polite", "poor", "precious", "pretty", "purple",
	"quaint", "quick", "quiet",
	"rapid", "red", "rocky", "rough", "round", "royal", "rustic",
	"safe", "sandy", "shiny", "short", "silent", "silky", "silly", "slender", "slow", "small", "smart", "smiling", "smooth", "snug", "soft", "sour", "strange", "strong", "sunny", "sweet", "swift",
	"thirsty", "thoughtful", "tiny",
	"uneven", "unusual",
	"vanilla", "vast", "violet"
	"warm", "watery", "weak", "white", "wide", "wild", "wilde", "windy", "wise", "witty", "wonderful",
	"yellow", "young",
	"zany" };

const char *substantiv[] = { "airplane", "apple", "automobile",
	 "ball", "balloon", "banana", "beach", "bird", "boat", "bolt", "boot", "bottle", "box", "bread", "breeze", "bubble", "bug", "bunny", "bush", "butter",
	 "canoe", "car", "carrot", "cartoon", "cello", "chair", "cheese", "chip", "coast", "coconut", "comet", "cream", "curly", "curtain",
	 "daisy", "deal", "desk", "diamond", "dink", "door",
	 "earth", "elephant", "emerald",
	 "finch", "fire", "flamingo", "flower", "flute", "forest",
	 "gadfly", "gate", "gear", "giant", "giraffe", "girl", "glove", "grape", "grasshopper",
	 "hair", "hat", "hill", "hippo",
	 "ink", "iris",
	 "jade", "jet", "jungle",
	 "kangaroo", "kayak",
	 "lake", "lemon", "lightning", "lion", "lotus", "lump",
	 "mango", "mesa", "mint", "monkey", "moon", "motorcycle", "mountain",
	 "nest",
	 "oboe", "ocean", "octopus", "onion", "orange", "orchestra", "owl",
	 "panda", "path", "pear", "penguin", "phoenix", "piano", "pineapple", "planet", "plum", "pond", "potato", "prairie",
	 "quail",
	 "rabbit", "raccoon", "raid", "rain", "raven", "river", "road", "robert", "rosebud", "ruby",
	 "sea", "sheep", "ship", "shoe", "shore", "shrub", "side", "silver", "sitter", "skates", "sky", "snake", "socks", "sparrow", "spider", "squash", "squirrel", "star", "stream", "street", "sun",
	 "table", "teapot", "terrain", "tiger", "toast", "tomato", "trail", "train", "tree", "truck", "trumpet", "tuba", "tulip", "tullip",
	 "umbrella", "unicorn", "unit",
	 "valley", "vase", "violet", "violin",
	 "water", "whale", "west", "wind", "window",
	 "zebra", "zoo" };

for(ca = 0; ca < (sizeof(adjectiv) / sizeof(char *)); ca++)
	for(cs = 0; cs < (sizeof(substantiv) / sizeof(char *)); cs++)
		{
		for (cn = 0; cn < 1000; cn++)
			{
			snprintf(pskstring, 64, "%s%s%zu", adjectiv[ca], substantiv[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			if(cn < 10)
				{
				snprintf(pskstring, 64, "%s%s%02zu", adjectiv[ca], substantiv[cs], cn);
				fprintf(fhout,"%s\n", pskstring);
				}
			if(cn < 100)
				{
				snprintf(pskstring, 64, "%s%s%03zu", adjectiv[ca], substantiv[cs], cn);
				fprintf(fhout,"%s\n", pskstring);
				}
			}
		}
return;
}
/*===========================================================================*/
static void keywriteweakpass(FILE *fhout)
{
static size_t w;
static int y;

static char pskstring[PSKSTRING_LEN_MAX] = {};
const char *weakword[] =
{
"00000000", "0000000000", "01234567", "0123456789", "0123456789012345", "022844444", "0987654321",
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
"Fernando", "Fireball", "Firebird", "Football", "Football1", "free-tau", "Franklin",
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
"TaxiLinQ", "Tinkerbell", "TrustNo1", "Twilight", "Undertaker", "Valentina", "Valentine",
"Veronica", "Victoria", "Warcraft", "Warhammer", "Welcome1", "Westside",
"WhatEver", "Williams", "Wolverine", "Wordpass", "zaq12wsx", "zaq1xsw2"
};

for(w = 0; w < (sizeof(weakword) /sizeof(weakword[0])); w++)
	writepsk(fhout, weakword[w]);

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, 64, "abcd%04d", y);
	writepsk(fhout, pskstring);
	}

for(y = 0; y < 1000; y++)
	{
	snprintf(pskstring, 64, "%03d%03d%03d", y, y, y);
	writepsk(fhout, pskstring);
	}
return;
}
/*===========================================================================*/
static void keywriteeudate(FILE *fhout)
{
static int d ,m ,y;
static char pskstring[PSKSTRING_LEN_MAX] = {};

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 1; d <= 28; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%02d%02d%04d", d, m, y);
			writepsk(fhout, pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 29; d <= 30; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%02d%02d%04d", d, m, y);
			writepsk(fhout, pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3101%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3103%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3105%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3107%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3108%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3110%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "3112%04d", y);
	writepsk(fhout, pskstring);
	}

for(y = 1900; y <= thisyear; y++)
	{
	if (((y %4 == 0) && (y %100 != 0)) || (y %400 == 0))
		{
		snprintf(pskstring, PSKSTRING_LEN_MAX, "2902%04d", y);
		writepsk(fhout, pskstring);
		}
	}
return;
}
/*===========================================================================*/
static void keywriteusdate(FILE *fhout)
{
static int d ,m ,y;
static char pskstring[PSKSTRING_LEN_MAX] = {};

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 1; d <= 28; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%02d%02d%04d", m, d, y);
			writepsk(fhout, pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 29; d <= 30; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%02d%02d%04d", m, d, y);
			writepsk(fhout, pskstring);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, PSKSTRING_LEN_MAX, "0131%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "0331%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "0531%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "0731%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "0831%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "1031%04d", y);
	writepsk(fhout, pskstring);
	snprintf(pskstring, PSKSTRING_LEN_MAX, "1231%04d", y);
	writepsk(fhout, pskstring);
	}

for(y = 1900; y <= thisyear; y++)
	{
	if (((y %4 == 0) && (y %100 != 0)) || (y %400 == 0))
		{
		snprintf(pskstring, PSKSTRING_LEN_MAX, "0229%04d", y);
		writepsk(fhout, pskstring);
		}
	}
return;
}
/*===========================================================================*/
static void keywriteyearyear(FILE *fhout)
{
static int y, y2, y3;
static char pskstring[PSKSTRING_LEN_MAX] = {};

for(y = 1900; y <= thisyear; y++)
	{
	for(y2 = 1900; y2 <= thisyear; y2++)
		{
		snprintf(pskstring, PSKSTRING_LEN_MAX, "%04d%04d", y, y2);
		writepsk(fhout, pskstring);
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(y2 = 1900; y2 <= thisyear; y2++)
		{
		for(y3 = 1900; y3 <= thisyear; y3++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%04d%04d%04d", y, y2, y3);
			writepsk(fhout, pskstring);
			}
		}
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writeessidadd(FILE *fhout, char *essid)
{
int c;
static char essidstring[PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX] = {};

for(c = 1900; c <= thisyear; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%04d%s", c, essid);
	writepsk(fhout, essidstring);
	}

for(c = 0; c < 1000; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%d%s", c, essid);
	writepsk(fhout, essidstring);
	}
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s123456789", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s12345678", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1234567", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s123456", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s12345", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1234", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s9876543210", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s987654321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s87654321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s7654321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s654321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s54321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s4321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s321", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@Home", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@WiFi", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@1234", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@123", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1234!", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s123!", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s12!", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1!", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s!", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX, "%s%s%s", essid, essid, essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%s", essid, essid);
writepsk(fhout, essidstring);
return;
}
/*===========================================================================*/
static bool writeessidremoved(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int pi;
static int po;
static int essidlentmp;
static bool removeflag;

static char essidtmp[PSKSTRING_LEN_MAX] = {};

po = 0;
removeflag = false;
essidlentmp = essidlen;
memset(&essidtmp, 0, PSKSTRING_LEN_MAX);
for(pi = 0; pi < essidlen; pi++)
	{
	if(((essid[pi] >= 'A') && (essid[pi] <= 'Z')) || ((essid[pi] >= 'a') && (essid[pi] <= 'z')))
		{
		essidtmp[po] = essid[pi];
		po++;
		}
	else
		{
		essidlentmp--;
		removeflag = true;
		}
	}
if(removeflag == false)
	{
	writeessidadd(fhout, essidtmp);
	}
return removeflag;
}
/*===========================================================================*/
static void writeessidsweeped(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int l1, l2;
static uint8_t sweepstring[PSKSTRING_LEN_MAX] = {};

for(l1 = 3; l1 <= essidlen; l1++)
	{
	for(l2 = 0; l2 <= essidlen -l1; l2++)
		{
		memset(&sweepstring, 0, PSKSTRING_LEN_MAX);
		memcpy(&sweepstring, &essid[l2], l1);
		if(writeessidremoved(fhout, l1, sweepstring) == true)
			{
			writepsk(fhout, (char*)sweepstring);
			}
		}
	}
return;
}
/*===========================================================================*/
static void testalcatellinkzone(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
int k1;
static char *ali = "Alcatel LINKZONE ";
if(essidlen != 21)
	{
	return;
	}
if(memcmp(essid, ali, 17) != 0)
	{
	return;
	}
if((!isdigit(essid[17])) || (!isdigit(essid[18])) || (!isdigit(essid[19])) || (!isdigit(essid[20])))
	{
	return;
	}
for(k1 = 0; k1 < 10000; k1++)
	{
	fprintf(fhout, "%04d%c%c%c%c\n", k1, essid[17], essid[18], essid[19], essid[20]);
	}
return;
}
/*===========================================================================*/
static void testarristg(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
int k1;
static char *tg852g =  "TG852G";
static char *tg862g =  "TG862G";
static char *tg1672g = "TG1672G";

if(essidlen == 8)
	{
	if((!isxdigit(essid[6])) || (!isxdigit(essid[7])))
		{
		return;
		}
	if(memcmp(essid, tg852g, 6) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++)
			{
			fprintf(fhout, "TG852G%04X%c%c\n", k1, essid[6], essid[7]);
			}
		}
	if(memcmp(essid, tg862g, 6) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++)
			{
			fprintf(fhout, "TG862G%04X%c%c\n", k1, essid[6], essid[7]);
			}
		}
	return;
	}
if(essidlen == 9)
	{
	if(memcmp(essid, tg1672g, 7) != 0)
		{
		return;
		}
	if((!isxdigit(essid[7])) || (!isxdigit(essid[8])))
		{
		return;
		}
	for(k1 = 0; k1 < 0x10000; k1++)
		{
		fprintf(fhout, "TG1672G%04X%c%c\n", k1, essid[7], essid[8]);
		}
	return;
	}
return;
}
/*===========================================================================*/
static void testattwifi(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
int k1, k2, k3, k4;
static char *attwifi = "ATT-WIFI-";
if(essidlen != 13)
	{
	return;
	}
if(memcmp(essid, attwifi, 9) != 0)
	{
	return;
	}
if((!isdigit(essid[9])) || (!isdigit(essid[10])) || (!isdigit(essid[11])) || (!isdigit(essid[12])))
	{
	return;
	}
for(k1 = 0; k1 < 10; k1++)
	for(k2 = 0; k2 < 10; k2++)
		for(k3 = 0; k3 < 10; k3++)
			for(k4 = 0; k4 < 10; k4++)
				{
				fprintf(fhout, "%d%c%d%c%d%c%d%c\n", k1, essid[9], k2, essid[10], k3, essid[12], k4, essid[11]);
				}
return;
}
/*===========================================================================*/
static void testwifirsu(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
int k1;
static char *wifirsu = "WiFiRSU_";
if(essidlen < 10)
	{
	return;
	}
if(memcmp(essid, wifirsu, 8) != 0)
	{
	return;
	}
if(essidlen == 10)
	{
	if((!isxdigit(essid[8])) || (!isxdigit(essid[9])))
		{
		return;
		}
	for(k1 = 0; k1 < 0x10000; k1++)
		{
		fprintf(fhout, "88%04x%c%c\n", k1, essid[8], essid[9]);
		}
	return;
	}
if(essidlen == 13)
	{
	if((!isxdigit(essid[8])) || (!isxdigit(essid[9])) || (!isxdigit(essid[10])) || (!isxdigit(essid[11])) || (!isxdigit(essid[12])))
		{
		return;
		}
	for(k1 = 0; k1 < 0x10; k1++)
		{
		fprintf(fhout, "88%x%c%c%c%c%c\n", k1, essid[8], essid[9], essid[10], essid[11], essid[12]);
		}
	return;
	}
return;
}
/*===========================================================================*/
static void prepareessid(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
int pi, po;
static char essidtmp[PSKSTRING_LEN_MAX] = {};

testalcatellinkzone(fhout, essidlen, essid);
testarristg(fhout, essidlen, essid);
testattwifi(fhout, essidlen, essid);
testwifirsu(fhout, essidlen, essid);

writeessidsweeped(fhout, essidlen, essid);
po = 0;
memset(&essidtmp, 0, PSKSTRING_LEN_MAX);
for(pi = essidlen -1; pi >= 0; pi--)
	{
	essidtmp[po] = essid[pi];
	po++;
	}
writepsk(fhout, essidtmp);
return;
}
/*===========================================================================*/
static void processessids(FILE *fhout)
{
static int c;
static apessidl_t *zeiger;
static apessidl_t *zeiger1;

qsort(apessidliste, apessidcount, APESSIDLIST_SIZE, sort_apessidlist_by_essid);
zeiger = apessidliste;
for(c = 0; c < apessidcount; c++)
	{
	if(c == 0)
		{
		prepareessid(fhout, zeiger->essidlen, zeiger->essid);
		}
	else
		{
		zeiger1 = zeiger -1;
		if(zeiger->essidlen != zeiger1->essidlen)
			{
			if(memcmp(zeiger->essid, zeiger1->essid, zeiger->essidlen) != 0)
				{
				prepareessid(fhout, zeiger->essidlen, zeiger->essid);
				}
			}
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writebssidmd5(FILE *fhout, unsigned long long int macaddr)
{
MD5_CTX ctxmd5;
int k;
int p;
char keystring[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
char macstring[PSKSTRING_LEN_MAX] = {};
unsigned char digestmd5[MD5_DIGEST_LENGTH];

snprintf(macstring, 14, "%012llX", macaddr);
MD5_Init(&ctxmd5);
MD5_Update(&ctxmd5, macstring, 12);
MD5_Final(digestmd5, &ctxmd5);

for (p = 0; p < 10; p++)
	{
	fprintf(fhout, "%02x",digestmd5[p]);
	}
fprintf(fhout, "\n");

for (p = 0; p < 8; p++)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");

for (p = 0; p < 10; p++)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");

for (p = 0; p < 15 ; p +=2)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");

for (p = 1; p < 16 ; p +=2)
	{
	k = (digestmd5[p] %26);
	fprintf(fhout, "%c",keystring[k]);
	}
fprintf(fhout, "\n");
return;
}
/*===========================================================================*/
static unsigned int wpspinchecksum(unsigned int pin)
{
static int accum = 0;

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
static void writebssidwps(FILE *fhout, unsigned long long int macaddr)
{
static int pin;

pin = (macaddr & 0xffffff) % 10000000;
pin = ((pin * 10) + wpspinchecksum(pin));
fprintf(fhout, "%08d \n", pin);
return;
}
/*===========================================================================*/
static void writewpsall(FILE *fhout)
{
static int c, cs;

for(c = 0; c < 10000000; c++)
	{
	cs = wpspinchecksum(c);
	fprintf(fhout, "%07d%d\n", c, cs);
	}
return;
}
/*===========================================================================*/
static void writebssid(FILE *fhout, unsigned long long int macaddr)
{
char pskstring[PSKSTRING_LEN_MAX] = {};

snprintf(pskstring, PSKSTRING_LEN_MAX, "0%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "8747%06llx", macaddr &0xffffff);
writepsk(fhout, pskstring);

snprintf(pskstring, PSKSTRING_LEN_MAX, "%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%011llx", macaddr &0xfffffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%010llx", macaddr &0xffffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%09llx", macaddr &0xfffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%08llx", macaddr &0xffffffff);
writepsk(fhout, pskstring);
writebssidmd5(fhout, macaddr);
writebssidwps(fhout, macaddr);
return;
}
/*===========================================================================*/
static void preparebssid(FILE *fhout, unsigned long long int macaddr)
{
int c;
unsigned long long int oui;
unsigned long long int nic;

oui = macaddr &0xffffff000000L;
nic = (macaddr &0xffffffL) -8;
for(c = 0; c < 0x10; c++)
	{
	writebssid(fhout, oui +nic +c);
	}




return;
}
/*===========================================================================*/
static void processbssids(FILE *fhout)
{
static int c;
static apessidl_t *zeiger;
static apessidl_t *zeiger1;

qsort(apessidliste, apessidcount, APESSIDLIST_SIZE, sort_apessidlist_by_ap);
zeiger = apessidliste;
for(c = 0; c < apessidcount; c++)
	{
	if(c == 0)
		{
		preparebssid(fhout, zeiger->macaddr);
		}
	else
		{
		zeiger1 = zeiger -1;
		if(zeiger->macaddr != zeiger1->macaddr)
			{
			preparebssid(fhout, zeiger->macaddr);
			}
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static void processadditionals(FILE *fhout, bool weakpassflag, bool eudateflag, bool usdateflag, bool wpsflag, bool netgearflag)
{
if(netgearflag == true)
	{
	keywritenetgear(fhout);
	}
if(weakpassflag == true)
	{
	keywriteweakpass(fhout);
	}
if(eudateflag == true)
	{
	keywriteeudate(fhout);
	}
if(usdateflag == true)
	{
	keywriteusdate(fhout);
	}
if((eudateflag == true) || (usdateflag == true))
	{
	keywriteyearyear(fhout);
	}
if(wpsflag == true)
	{
	writewpsall(fhout);
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void addapessid(uint64_t macaddr, uint8_t essidlen, uint8_t *essid)
{
static apessidl_t *zeiger;

if(essidlen > ESSID_LEN_MAX)
	{
	return;
	}
if(apessidliste == NULL)
	{
	apessidliste = malloc(APESSIDLIST_SIZE);
	if(apessidliste == NULL)
		{
		fprintf(stderr, "failed to allocate memory\n");
		exit(EXIT_FAILURE);
		}
	memset(apessidliste, 0, APESSIDLIST_SIZE);
	apessidliste->macaddr = macaddr;
	apessidliste->essidlen = essidlen;
	memcpy(apessidliste->essid, essid, essidlen);
	apessidcount++;
	return;
	}
zeiger = apessidliste +apessidcount -1;
if((zeiger->macaddr == macaddr) && (zeiger->essidlen == essidlen) && (memcmp(zeiger->essid, essid, essidlen) == 0))
	{
	return;
	}
zeiger = realloc(apessidliste, (apessidcount +1) *APESSIDLIST_SIZE);
if(zeiger == NULL)
	{
	fprintf(stderr, "failed to allocate memory\n");
	exit(EXIT_FAILURE);
	}
apessidliste = zeiger;
zeiger = apessidliste +apessidcount;
memset(zeiger, 0, APESSIDLIST_SIZE);
zeiger->macaddr = macaddr;
zeiger->essidlen = essidlen;
memcpy(zeiger->essid, essid, essidlen);
apessidcount++;
return;
}
/*===========================================================================*/
/*===========================================================================*/
static inline size_t chop(char *buffer, size_t len)
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
static inline int fgetline(FILE *inputstream, size_t size, char *buffer)
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
static inline void readpmkidfile(char *pmkidname)
{
static int len;
static int aktread = 1;
static int essidlen;
static char *macaddrstop = NULL;
static unsigned long long int macaddr;
static FILE *fh_file;

static char linein[PMKID_LINE_LEN];
static uint8_t essid[ESSID_LEN_MAX];

if((fh_file = fopen(pmkidname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", pmkidname);
	return;
	}

while(1)
	{
	if((len = fgetline(fh_file, PMKID_LINE_LEN, linein)) == -1)
		{
		break;
		}
	if((len < 61) || ((len > 59 +(ESSID_LEN_MAX *2))))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((linein[32] != '*') && (linein[45] != '*') && (linein[58] != '*'))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	essidlen = len -59;
	if((essidlen %2) != 0)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	macaddr = strtoull(linein +33, &macaddrstop, 16);
	if((macaddrstop -linein) != 45)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if(hex2bin(&linein[59], essid, essidlen/2) == true)
		{
		addapessid(macaddr, essidlen/2, essid);
		}
	aktread++;
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
static inline void readhccapxfile(char *hccapxname)
{
static struct stat statinfo;
static hccapx_t *hcxptr;
static FILE *fhhcx;
static unsigned long long int macaddr;

static uint8_t hcxdata[HCCAPX_SIZE];

if(stat(hccapxname, &statinfo) != 0)
	{
	fprintf(stderr, "can't stat %s\n", hccapxname);
	return;
	}

if((statinfo.st_size %HCCAPX_SIZE) != 0)
	{
	fprintf(stderr, "file corrupt\n");
	return;
	}

if((fhhcx = fopen(hccapxname, "rb")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapxname);
	return;
	}

hcxptr = (hccapx_t*)hcxdata;
while(fread(&hcxdata, HCCAPX_SIZE, 1, fhhcx) == 1)
	{
	if(hcxptr->signature != HCCAPX_SIGNATURE)
		{
		continue;
		}
	if((hcxptr->version != 3) && (hcxptr->version != 4))
		{
		continue;
		}
	if(hcxptr->essid_len > ESSID_LEN_MAX)
		{
		continue;
		}
	macaddr = 0;
	macaddr = hcxptr->mac_ap[0];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[1];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[2];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[3];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[4];
	macaddr = (macaddr << 8) + hcxptr->mac_ap[5];
	addapessid(macaddr, hcxptr->essid_len, hcxptr->essid);
	}
fclose(fhhcx);
return;
}
/*===========================================================================*/
static inline void readcommandline(char *macapname, char *essidname)
{
static int essidlen = 0;
static int essidlenuh = 0;
static char *macaddrstop = NULL;
static unsigned long long int macaddr = 0xffffffffffffL;
static uint8_t essid[ESSID_LEN_MAX];

if(macapname != NULL)
	{
	macaddr = strtoull(macapname, &macaddrstop, 16);
	if((macaddrstop -macapname) != 12)
			{
			fprintf(stderr, "invalid MAC specified\n");
			}
	}

memset(&essid, 0, ESSID_LEN_MAX);
essidlen = strlen(essidname);
if(essidname != NULL)
	{
	essidlenuh = ishexify(essidname);
	if((essidlenuh > 0) && (essidlenuh <= ESSID_LEN_MAX))
		{
		if(hex2bin(&essidname[5], essid, essidlenuh) == true)
			{
			addapessid(macaddr, essidlenuh, essid);
			}
		return;
		}
	memset(&essid, 0, ESSID_LEN_MAX);
	if(essidlen <= ESSID_LEN_MAX)
		{
		memcpy(&essid, essidname, essidlen);
		}
	}
addapessid(macaddr, essidlen, essid);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static inline void version(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION, VERSION_JAHR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usage(char *eigenname)
{
printf("%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-i <file> : input EAPOL hash file (hccapx)\n"
	"-z <file> : input PMKID hash file\n"
	"-e <file> : input ESSID\n"
	"-b <file> : input MAC access point\n"
	"            format: 112233445566\n"
	"-o <file> : output PSK file\n"
	"            default: stdout\n"
	"            output list must be sorted unique!\n"
	"-h        : show this help\n"
	"-v        : show version\n"
	"\n"
	"--netgear : include NETGEAR candidates\n"
	"--weakpass: include weak password candidates\n"
	"--eudate  : include complete european dates\n"
	"--usdate  : include complete american dates\n"
	"--wpskeys : include complete WPS keys\n"
	"--help    : show this help\n"
	"--version : show version\n"
	"\n", eigenname, VERSION, VERSION_JAHR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static inline void usageerror(char *eigenname)
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
static FILE *fhpsk;
static time_t t;
static struct tm *tm;

static bool netgearflag = false;
static bool weakpassflag = false;
static bool eudateflag = false;
static bool usdateflag = false;
static bool wpskeysflag = false;

static char *hccapxname = NULL;
static char *pmkidname = NULL;
static char *essidname = NULL;
static char *macapname = NULL;
static char *pskname = NULL;

apessidliste = NULL;
apessidcount = 0;

static const char *short_options = "i:z:o:e:b:o:hv";
static const struct option long_options[] =
{
	{"netgear",			no_argument,		NULL,	HCXD_NETGEAR},
	{"weakpass",			no_argument,		NULL,	HCXD_WEAKPASS},
	{"eudate",			no_argument,		NULL,	HCXD_EUDATE},
	{"usdate",			no_argument,		NULL,	HCXD_USDATE},
	{"wpskeys",			no_argument,		NULL,	HCXD_WPSKEYS},
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
		case HCXD_NETGEAR:
		netgearflag = true;
		break;

		case HCXD_WEAKPASS:
		weakpassflag = true;
		break;

		case HCXD_EUDATE:
		eudateflag = true;
		break;

		case HCXD_USDATE:
		usdateflag = true;
		break;

		case HCXD_WPSKEYS:
		wpskeysflag = true;
		break;

		case HCXD_HELP:
		usage(basename(argv[0]));
		break;

		case HCXD_VERSION:
		version(basename(argv[0]));
		break;

		case 'i':
		hccapxname = optarg;
		break;

		case 'z':
		pmkidname = optarg;
		break;

		case 'e':
		essidname = optarg;
		break;

		case 'b':
		macapname = optarg;
		if(strlen(macapname) != 12)
			{
			fprintf(stderr, "invalid MAC specified\n");
			exit(EXIT_FAILURE);
			}
		break;

		case 'o':
		pskname = optarg;
		break;

		case '?':
		usageerror(basename(argv[0]));
		break;
		}
	}

t = time(NULL);
tm = localtime(&t);
thisyear = tm->tm_year +1900;

if((macapname != NULL) || (essidname != NULL))
	{
	readcommandline(macapname, essidname);
	}

if(pmkidname != NULL)
	{
	readpmkidfile(pmkidname);
	}

if(hccapxname != NULL)
	{
	readhccapxfile(hccapxname);
	}

if(apessidliste == NULL)
	{
	fprintf(stderr, "no hashes loaded\n");
	}

if(pskname != NULL)
	{
	if((fhpsk = fopen(pskname, "w")) == NULL)
		{
		fprintf(stderr, "1 error opening psk file %s\n", pskname);
		exit(EXIT_FAILURE);
		}
	processbssids(fhpsk);
	processessids(fhpsk);
	processadditionals(fhpsk, weakpassflag, eudateflag, usdateflag, wpskeysflag, netgearflag);
	}
else
	{
	processbssids(stdout);
	processessids(stdout);
	processadditionals(stdout, weakpassflag, eudateflag, usdateflag, wpskeysflag, netgearflag);
	}


if(pskname != NULL)
	{
	fclose(fhpsk);
	}

return EXIT_SUCCESS;
}
/*===========================================================================*/

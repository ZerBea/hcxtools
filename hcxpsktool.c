#define _GNU_SOURCE
#include <ctype.h>
#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "include/hcxpsktool.h"
#include "include/hashcatops.h"
#include "include/strings.c"
#include "include/fileops.c"
/*===========================================================================*/
/* global var */

static apessidl_t *apessidliste;
static int apessidcount;
static unsigned int thisyear;

static bool airtelflag;
static bool alticeoptimumflag;
static bool asusflag;
static bool digit10flag;
static bool easyboxflag;
static bool eeflag;
static bool eeupperflag;
static bool egnflag;
static bool eudateflag;
static bool hb5flag;
static bool maconlyflag;
static bool netgearflag;
static bool noessidcombinationflag;
static bool phomeflag;
static bool podaflag;
static bool simpleflag;
static bool spectrumflag;
static bool tendaflag;
static bool ukrtelecomflag;
static bool usdateflag;
static bool weakpassflag;
static bool wpskeysflag;
static bool znidflag;

static uint8_t essidglen;
/*===========================================================================*/
static void globalinit(void)
{
static time_t t;
static struct tm *tm;

apessidliste = NULL;
apessidcount = 0;
essidglen = 32;
t = time(NULL);
tm = localtime(&t);
thisyear = tm->tm_year +1900;
ERR_load_crypto_strings();
OpenSSL_add_all_algorithms();
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writepsk(FILE *fhout, const char *pskstring)
{
static bool lflag = false;
static bool uflag = false;
static int p, l;
static char lowerpskstring[PSKSTRING_LEN_MAX] = { 0 };
static char upperpskstring[PSKSTRING_LEN_MAX] = { 0 };

l = strlen(pskstring);
if((l < 8) || (l > PSKSTRING_LEN_MAX)) return;
fprintf(fhout,"%s\n", pskstring);
for(p = 0; p < l; p++)
	{
	if(islower((unsigned char)pskstring[p]))
		{
		upperpskstring[p] = toupper((unsigned char)pskstring[p]);
		uflag = true;
		}
	else upperpskstring[p] = pskstring[p];
	if(isupper((unsigned char)pskstring[p]))
		{
		lowerpskstring[p] = tolower((unsigned char)pskstring[p]);
		lflag = true;
		}
	else lowerpskstring[p] = pskstring[p];
	}
upperpskstring[p] = 0;
lowerpskstring[p] = 0;
if(uflag == true) fprintf(fhout,"%s\n", upperpskstring);
if(lflag == true) fprintf(fhout,"%s\n", lowerpskstring);
if((lowerpskstring[0] >= 'a') && (lowerpskstring[0] <= 'z'))
	{
	lowerpskstring[0] = toupper((unsigned char)lowerpskstring[0]);
	fprintf(fhout,"%s\n", lowerpskstring);
	}
return;
}
/*===========================================================================*/
static void keywritedigit10(FILE *fhout)
{
static int i;
static uint16_t f1, f2;
static unsigned long long int ec, el, eu;
static unsigned int digestmd5len;
static EVP_MD_CTX* mdctx;

static uint32_t fixseed1[] =
{
0xb100, 0xb300, 0xf200, 0xf800, 0xf900, 0xfa00
};
#define FIXSEED1_SIZE sizeof(fixseed1) /sizeof(uint32_t)

static char message[PSKSTRING_LEN_MAX];
static uint8_t digestmd5[EVP_MAX_MD_SIZE];

for(f1 = 0; f1 < FIXSEED1_SIZE; f1++)
	{
	for(f2 = 0; f2 <=0xff; f2++)
		{
		for(ec = 0; ec <= 0xffff; ec++)
			{
			snprintf(message, PSKSTRING_LEN_MAX, "D0542D-01%010lld", ec | (fixseed1[f1] +f2) << 16);
			digestmd5len = 16;
			mdctx = EVP_MD_CTX_create();
			if(mdctx == NULL) continue;
			if(EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) == 0)
				{
				EVP_MD_CTX_free(mdctx);
				continue;
				}
			if(EVP_DigestUpdate(mdctx, message, 19) == 0)
				{
				EVP_MD_CTX_free(mdctx);
				continue;
				}
			if(EVP_DigestFinal_ex(mdctx, digestmd5, &digestmd5len) == 0)
				{
				EVP_MD_CTX_free(mdctx);
				continue;
				}
			EVP_MD_CTX_free(mdctx);
			}
		el = 0;
		eu = 0;
		for(i = 0; i < 8; i++)
			{
			eu = (el >> 0x18 | ((eu << 8) &0xffffffff)) &0xffffffff;
			el = (((el << 8) &0xffffffff) | digestmd5[i + 8]) &0xffffffff;
			}
		fprintf(fhout, "%010lld\n", ((eu << 32) +el) %0x2540be400);
		}
	}
return;
}
/*===========================================================================*/
static void keywritenetgear(FILE *fhout)
{
static size_t ca, cs;
static int cn;
static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

static const char *firstword[] =
{
"absurd", "ancient", "aquatic",
"basic", "bass", "big", "black", "blue", "bold", "brave", "breezy",
"bright", "brown",
"calm", "cheerful", "chilly", "chummy", "classy", "clever", "cloudy", "cool",
"crispy", "curly",
"daily", "deep", "delightful", "dizzy", "dynamic",
"eagle", "elated", "elegant", "epic", "excited", "exotic", "extra",
"famous", "fancy", "fearless", "festive", "fluffy", "four", "free", "fresh",
"friendly", "funny", "fuzzy",
"gentle", "gifted", "gigantic", "graceful", "grand", "great", "green",
"happy", "heavy", "helpful", "hot", "hungry", "husky",
"icy", "imaginary",
"jagged", "jagger", "jolly", "joyous", "juicy", "justic",
"kind",
"large", "light", "little", "lime", "lively", "long", "loud", "lucky",
"lunar",
"magical", "manic", "melodic", "mighty", "misty", "modern",
"narrow", "new", "nifty", "noisy",
"odd", "orange",
"pastel", "perfect", "phobic", "pink", "plain", "polite", "precious", "purple",
"quaint", "quick", "quiet",
"rapid", "red", "rocky", "round", "royal", "ruby", "rustic",
"savage", "shiny", "simple", "silent", "silky", "silly", "slow", "small",
"smiley", "smiling", "smooth", "strong", "sunny", "sweet",
"tablet", "thirsty", "thoughtful", "tiny",
"ultra", "uneven", "unusual",
"vanilla", "vast",
"watery", "white", "wide", "windy", "witty", "wonderful",
"yellow", "young",
"zany"
};

static const char *secondword[] =
{
"airplane", "apple",
"balloon", "banana", "bangle", "bay", "berry", "bike", "bird", "blue",
"boat", "bolt", "boot", "box", "brain", "bread", "breeze", "bug",
"butter",
"canary", "canoe", "car", "carrot", "cartoon", "cat", "cello", "chair",
"cheese", "coconut", "cold", "comet", "couture", "cream", "curtain",
"daisy", "deer", "diamond", "dog", "domain",
"earth", "ecasa", "elephant",
"field", "finch", "fire", "fish", "flamingo", "flower", "flute",
"gate", "gadfly", "giant", "goat", "grasshopper",
"hat", "hill", "hippo", "house",
"ink", "iris",
"jade", "jet", "jetcar", "jungle",
"kangaroo", "kayak",
"lake", "lemon", "lightning", "link", "lion", "lotus",
"mango", "mesa", "mint", "mobile", "moon", "mountain",
"nest", "net",
"oboe", "ocean", "octopus", "onion", "orchestra", "owl",
"panda", "phoenix", "piano", "pineapple", "planet", "player", "plum", "police",
"pond", "poodle", "potato", "prairie",
"quail",
"rabbit", "raccoon", "raven", "rise", "river", "road", "rosebud",
"sea", "sheep", "ship", "shoe", "shrub", "skates", "sky", "snail",
"shoe", "socks", "sparrow", "spider", "squash", "squirrel", "star", "stone",
"street", "sun",
"table", "tail", "teapot", "time", "tomato", "trail", "train", "tree",
"truck", "trumpet", "tuba", "tulip", "turkey",
"umbrella", "unicorn", "unit",
"valley", "vase", "vinyl", "violet", "violin",
"water", "way", "wind", "window", "wombat",
"zoo"
};

for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		for (cn = 0; cn < 1000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%03d", firstword[ca], secondword[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		for (cn = 0; cn < 100; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%02d", firstword[ca], secondword[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		for (cn = 0; cn < 10; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%d", firstword[ca], secondword[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s", firstword[ca], secondword[cs]);
		fprintf(fhout,"%s\n", pskstring);
		}
	}
return;
}
/*===========================================================================*/
static void keywritespectrum(FILE *fhout)
{
static size_t ca, cs;
static int cn;
static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

static const char *firstword[] =
{
"absurd", "acre", "active", "actual", "adorable", "agency", "agent", "ago",
"album", "alive", "all", "alter", "anchor", "ancient", "angry", "apart",
"aquatic", "author", "aware", "away", "bakery", "barrel", "basic", "basket",
"bench", "better", "black", "blue", "bold", "born", "botany", "brave",
"breezy", "brew", "bridge", "brief", "bright", "broad", "brown", "busy",
"calm", "camera", "chance", "check", "cheerful", "chilly", "choice", "chorus",
"chummy", "classy", "clean", "clerk", "clever", "close", "cloudy", "clumsy",
"coffee", "cold", "common", "content", "cool", "cosmic", "crispy", "curly",
"daily", "damp", "dear", "decent", "deep", "degree", "desert", "dig",
"direct", "dizzy", "dnamic", "domain", "double", "due", "dusty", "duty",
"dynamic", "each", "eager", "eagle", "east", "easy", "eggplant", "either",
"elated", "elegant", "empty", "energy", "engine", "enough", "entire", "epic",
"epicn", "errand", "even", "evenp", "every", "exact", "excited", "exotic",
"expert", "extra", "fair", "famous", "fancy", "farmer", "fast", "fearless",
"festive", "few", "finish", "first", "fit", "fluent", "fluffy", "formal",
"former", "free", "freep", "fresh", "friend", "friendly", "front", "frosty",
"full", "funny", "furry", "future", "fuzzy", "gallon", "genius", "gentle",
"giddy", "gifted", "glad", "global", "gold", "good", "goofy", "grain",
"grand", "grateful", "great", "green", "grumpy", "guitar", "happy", "harbor",
"hearty", "heavy", "height", "helpful", "high", "hockey", "home", "honest",
"honor", "hot", "hotel", "hour", "hungry", "husky", "icy", "idea",
"ideal", "imaginary", "immune", "input", "internal", "invent", "islan", "island",
"jacket", "jagged", "jazz", "jeans", "jewel", "jolly", "joyous", "judge",
"juicy", "just", "kettle", "key", "kind", "king", "kite", "knight",
"known", "ladder", "ladderspace", "large", "last", "latter", "lazy", "leader",
"least", "left", "legal", "less", "light", "like", "little", "lively",
"living", "long", "lost", "lotus", "loud", "love", "loyal", "lucky",
"magical", "major", "manic", "many", "marble", "market", "master", "medium",
"mellow", "melodic", "middle", "mighty", "minute", "mirror", "misty", "mobile",
"modern", "month", "most", "much", "museum", "narrow", "nature", "nearby",
"neat", "nest", "new", "newj", "next", "nice", "nifty", "night",
"nine", "noble", "noisy", "normal", "north", "novel", "oasis", "object",
"ocean", "odd", "olive", "one", "only", "open", "orange", "other",
"outlet", "oxygen", "palm", "palmw", "parade", "party", "past", "pastel",
"patron", "perfect", "phobic", "phone", "pink", "plain", "plane", "pledge",
"plenty", "plus", "pocket", "polite", "pony", "pool", "praise", "precious",
"prior", "prize", "proof", "proper", "prose", "proud", "purple", "quaint",
"quick", "quiet", "quote", "rain", "rainy", "rapid", "rare", "ready",
"real", "reason", "recent", "red", "remedy", "remote", "review", "reward",
"rich", "rocket", "rocky", "root", "rough", "round", "royal", "runner",
"rusti", "rustic", "safe", "safety", "salt", "salute", "scary", "scout",
"select", "senior", "shadow", "shelf", "shiny", "short", "silent", "silky",
"silly", "silver", "simple", "sleepy", "slight", "slow", "small", "smart",
"smiley", "smiling", "smooth", "soccer", "solid", "some", "south", "space",
"spare", "square", "stable", "statue", "stealth", "still", "stock", "street",
"strict", "strong", "studio", "such", "sudden", "summit", "sunny", "super",
"sure", "sweet", "swift", "tablet", "tall", "teal", "terrific", "that",
"theory", "thick", "think", "thirsty", "this", "tight", "timber", "tiny",
"top", "total", "tough", "town", "train", "turtle", "uneven", "union",
"unique", "unite", "unusual", "upset", "urban", "useful", "usual", "valley",
"vanilla", "vast", "verse", "violet", "violin", "voyage", "wagon", "walnut",
"warm", "watch", "watery", "weekly", "west", "whale", "what", "wide",
"wild", "windy", "wine", "winter", "wise", "witty", "wonderful", "wooden",
"worth", "writer", "yacht", "yard", "year", "yellow", "young", "youngs",
"zany", "zeal", "zebra", "zone"
};

static const char *secondword[] =
{
"", "acre", "actor", "ad", "advice", "affect", "agency", "air",
"airplane", "album", "anchor", "apple", "area", "art", "aspect", "ature",
"author", "ave", "bakery", "ball", "balloon", "banana", "barrel", "basis",
"basket", "beach", "bead", "bear", "beer", "bench", "berry", "bike",
"bird", "board", "boat", "bolt", "bonus", "book", "boot", "botany",
"box", "brain", "bread", "breeze", "bridge", "bubble", "bug", "bunny",
"bus", "butter", "butterfly", "cafe", "camera", "canoe", "car", "card",
"carrot", "cartoon", "cat", "cello", "chair", "check", "cheek", "cheese",
"chill", "chorus", "city", "clerk", "client", "clock", "coat", "coconut",
"coffee", "comet", "cookie", "cosmic", "country", "county", "course", "cow",
"cream", "crown", "currency", "curtain", "daisy", "data", "day", "dealer",
"deeper", "deer", "degree", "desert", "desk", "diamond", "dinner", "dirt",
"disk", "dog", "doll", "domain", "drama", "drawer", "dremedy", "driver",
"duty", "eagle", "ear", "earth", "editor", "effort", "energy", "engine",
"epic", "errand", "error", "est", "estate", "event", "extent", "fact",
"famous", "farmer", "field", "fig", "film", "finch", "finish", "fire",
"fish", "flo", "flower", "fluent", "flute", "form", "formal", "fox",
"friend", "gadfly", "gallon", "garden", "gate", "gene", "genius", "giant",
"girl", "global", "goal", "grain", "green", "guest", "guide", "guitar",
"guppy", "hair", "hall", "hand", "harbor", "hat", "height", "hill",
"hippo", "hockey", "home", "hone", "honor", "horse", "hotel", "house",
"idea", "idol", "immune", "income", "ink", "input", "invent", "iris",
"island", "jacket", "jade", "jazz", "jeans", "jet", "jewel", "judge",
"jungle", "kayak", "kettle", "key", "king", "kite", "knight", "ladder",
"lake", "law", "lawn", "leader", "lemon", "length", "life", "light",
"lion", "list", "lotus", "loyal", "major", "mall", "mango", "map",
"marble", "market", "math", "meal", "media", "memory", "menu", "mesa",
"method", "mint", "mirror", "mobile", "moment", "month", "moon", "movie",
"mud", "museum", "music", "nail", "nation", "nature", "nest", "news",
"night", "noble", "north", "number", "oasis", "object", "oboe", "ocean",
"octopus", "office", "onion", "orange", "outlet", "owl", "own", "owner",
"oxygen", "palm", "panda", "pant", "paper", "parade", "park", "parm",
"patron", "peach", "pear", "pencil", "people", "phoenix", "phone", "piano",
"pizza", "place", "planet", "player", "pledge", "plum", "pocket", "poem",
"poet", "poetry", "policy", "pond", "poodle", "potato", "prairie", "praise",
"prose", "puppy", "quail", "quaint", "quick", "quote", "rabbit", "raccoon",
"radio", "raft", "rain", "rairie", "ratio", "raven", "reason", "region",
"remedy", "review", "reward", "river", "road", "robin", "rock", "rocket",
"role", "rose", "rosebud", "runner", "safety", "salad", "salute", "sample",
"scout", "sea", "sector", "seed", "series", "shark", "sheep", "shelf",
"ship", "shoe", "shrub", "side", "singer", "skates", "sky", "sled",
"snail", "snake", "snall", "soccer", "socks", "sofa", "soks", "song",
"soup", "space", "spark", "sparrow", "speech", "spider", "spoon", "squash",
"squirrel", "squirrelp", "stable", "star", "state", "statue", "steak", "storm",
"story", "stove", "straw", "street", "studio", "study", "summit", "sun",
"table", "tablet", "tea", "teapot", "teapoty", "teen", "tennis", "tent",
"thanks", "theory", "tiger", "timber", "time", "tomato", "tooth", "topic",
"town", "trail", "train", "tree", "truck", "trumpet", "truth", "tuba",
"tulip", "turkey", "turtle", "two", "type", "ungle", "unicorn", "union",
"unit", "unite", "urban", "useful", "valley", "value", "vase", "verse",
"video", "violet", "violin", "volume", "voyage", "wagon", "walnut", "watch",
"wate", "water", "way", "wealth", "week", "west", "whale", "while",
"wind", "window", "windy", "winner", "wolf", "work", "world", "writer",
"yacht", "yard", "year", "youth", "zeal", "zebra", "zone", "zoo"
};

for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		for (cn = 0; cn < 1000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%03d", firstword[ca], secondword[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		for (cn = 0; cn < 100; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%02d", firstword[ca], secondword[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		for (cn = 0; cn < 10; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%d", firstword[ca], secondword[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(firstword) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(secondword) / sizeof(char *)); cs++)
		{
		if(strcmp(firstword[ca], secondword[cs]) == 0) continue;
		snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s", firstword[ca], secondword[cs]);
		fprintf(fhout,"%s\n", pskstring);
		}
	}
return;
}
/*===========================================================================*/
static void keywritephome(FILE *fhout)
{
static size_t ca, cs;
static int cn;

static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

static const char *five[] =
{
"about", "again", "agree", "ahead", "aisle", "alert", "alley", "allow", "amaze", "angle", "apple", "apron", "arrow",
"attic", "award",
"bacon", "badge", "bagel", "baked", "basic", "beard", "begin", "being", "below", "berry", "bison", "block", "bloom", "board",
"boast", "bonus", "booth", "bored", "brace", "bread", "brick", "bring", "brush", "brook", "build", "built",
"cabin", "cause", "chair", "camel", "canal", "chair", "charm", "chart", "charm", "chase", "check", "cheer", "chime",
"chord", "chore", "chose", "chunk", "cough", "class", "clear", "coast", "cocoa", "cough", "cover", "count", "court",
"creak", "cream", "creek", "crumb", "curve",
"daily", "dairy", "daisy", "dance", "delay", "diner", "dodge", "dough", "dozed", "drain", "dried", "drink",
"eager", "eagle", "earth", "eight", "elbow", "elect", "empty", "enter", "entry", "equal", "event", "exact",
"fancy", "favor", "feast", "fence", "fever", "field", "fifty"
};

static const char *six[] =
{
"across", "action", "advice", "almost", "always", "amount", "anchor", "animal", "answer", "anyone", "anyway", "appear",
"arctic", "around", "arrive", "artist", "autumn", "awhile",
"baking", "banana", "basket", "become", "beside", "better", "borrow", "bottle", "breezy", "bridge", "bright", "bucket",
"buckle", "button",
"cactus", "called", "career", "carpet", "camera", "candid", "canvas", "canyon", "castle", "cattle", "caught", "celery",
"cellar", "center", "chance", "change", "charge", "cheery", "chores", "chosen", "circle", "cities", "clever", "collar",
"column", "comedy", "common", "copied", "corral", "county", "course", "create", "crumbs", "crunch",
"degree", "depend", "design", "detail", "diesel", "dimmed", "dinner", "direct",
"easier", "effect", "eighty", "eleven", "energy", "engine", "entire", "escape",
"factor", "famous", "fasten", "faucet", "filter", "finish", "flight", "flower", "folded", "follow", "forest",
"garden", "gather", "guitar",
"happen", "harbor", "hardly", "health"
};

for(ca = 0; ca < (sizeof(five) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(six) / sizeof(char *)); cs++)
		{
		for (cn = 0; cn < 10000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%04d%s", five[ca], cn, six[cs]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%04d%s", six[cs], cn, five[ca]);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
return;
}
/*===========================================================================*/
static void keywritetenda(FILE *fhout)
{
static size_t ca, cs;
static int cn;

static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

static const char *word[] =
{
"able", "about", "above", "actor", "after", "again", "alone", "also", "apple",
"baby", "back", "bath", "bean", "best", "bike", "bird", "blue", "body", "book",
"cafe", "cake", "calm", "card", "carry", "cash", "chair", "child", "cold", "come", "cool", "cute",
"daily", "dance", "dark", "dash", "dear", "desk", "done", "door", "down", "duck", "duty",
"each", "early", "earth", "east", "easy", "edit", "envy", "even", "every", "exist", "exit",
"face", "fact", "fall", "fast", "feed", "feel", "fill", "fish", "five", "four",
"game", "ghost", "girl", "giude", "give", "good", "green", "group", "guest",
"hair", "hand", "happy", "hard", "have", "haven", "head", "high", "hike", "horse", "house",
"into",
"jade", "jazz", "jean", "jeep", "join", "joke", "juice", "july", "june",
"keep", "kind",
"lable", "labor", "lack", "lake", "land", "light", "like", "live", "lock", "loop", "lose",
"mail", "main", "major", "make", "math", "meet", "milk", "moon", "more", "most", "mouth", "much",
"name", "near", "need", "nine", "none", "north", "nose", "note",
"occur", "ocean", "once", "open", "over",
"pace", "pain", "park", "part", "pass", "past", "path", "photo", "piece", "pink",
"queen", "quest", "quick", "quit", "quite",
"rainy", "reach", "read", "rice", "ride", "road", "room", "rope", "rose", "rule", "rush",
"safe", "said", "sale", "salt", "same", "sick", "soul", "soup", "south", "sunny",
"table", "take", "tale", "talk", "tall", "team", "tell", "test", "think", "ture",
"under", "unit", "upper",
"walk", "waste", "water", "weak", "week", "west", "what", "where", "wind", "word"
};

for(ca = 0; ca < (sizeof(word) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(word) / sizeof(char *)); cs++)
		{
		if (ca == cs) continue;
		for (cn = 0; cn < 1000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%03d", word[ca], word[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	for (cn = 0; cn < 10000; cn++)
		{
		snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%04d", word[ca], cn);
		fprintf(fhout,"%s\n", pskstring);
		}
	}
return;
}
/*===========================================================================*/
static void keywriteee(FILE *fhout, bool upper)
{
static size_t w3, w4, w5;

static char pskstring[16] = { 0 };

const char *pskmask = "%s-%s-%s\n";

char** uword3 = NULL;
char** uword4 = NULL;
char** uword5 = NULL;

static const char *word3[] =
{
"abs", "ace", "act", "add", "ado", "age", "ago", "aid", "ail", "aim", "all", "amp",
"any", "ape", "apt", "art", "ask",
"bad", "bay", "bee", "beg", "bet", "bid", "big", "bow", "box", "bud", "bug", "bun",
"bus", "buy",
"cad", "cam", "can", "cob", "cog", "cop", "cud", "cup", "cut",
"dam", "did", "die", "dig", "dim", "dip", "dog", "dry", "dub", "due", "dug",
"ear", "ego", "elk", "end", "era", "eye",
"fab", "fan", "far", "fat", "fax", "fee", "few", "fin", "fit", "fix", "fly", "fog",
"fox", "fry",
"gap", "gel", "gem", "get", "god",
"hem", "hid", "hip", "hit", "hop", "hot", "how", "hub",
"ice", "icy", "ink", "inn",
"jar", "jet", "job", "jog", "jot",
"key",
"lag", "lap", "law", "lay", "led", "leg", "let", "lid", "lie", "lip", "lit", "lob",
"lop", "lot", "low",
"mad", "map", "max", "mid", "mix", "mob", "mop", "mow", "mud", "mug",
"nag", "nap", "net", "new", "nod", "nor", "not", "now",
"oar", "oat", "odd", "off", "oil", "old", "one", "opt", "our", "out", "owe", "own",
"pad", "pal", "pay", "pea", "peg", "pen", "per", "pet", "pie", "pin", "ply", "pop",
"pro", "pub", "put",
"ran", "rat", "raw", "red", "rid", "rig", "rob", "rot", "rug", "run",
"sad", "sea", "set", "sew", "shy", "sim", "sin", "sip", "sir", "sit", "six", "sow",
"soy", "spy",
"tad", "tag", "tap", "tax", "ten", "tic", "tip", "ton", "top", "tow", "toy", "try",
"two",
"use",
"van", "vex", "vow",
"wet", "win", "won"
};

static const char *word4[] =
{
"able", "acre", "aqua", "arch", "area",
"bait", "bake", "bald", "ball", "bark", "base", "bath", "bats", "bead", "beat", "bell", "best",
"boat", "boil", "bold", "bore", "both", "busy",
"calm", "camp", "cape", "card", "case", "cash", "cent", "chef", "city", "clad", "clay", "club",
"clue", "coat", "cook", "cool", "cope", "copy", "cute",
"dame", "damp", "dare", "dash", "date", "days", "deaf", "deal", "desk", "dial", "dish", "dive",
"door", "duty", "dove", "down", "draw", "drop",
"each", "east", "edge", "edit", "epic", "even", "ever", "exit",
"face", "fair", "fake", "fast", "fall", "fame", "fast", "fine", "firm", "flag", "flee", "foam",
"fold", "foot", "four", "full", "fund", "fuse",
"gaps", "gate", "gave", "gear", "gift", "glad", "gown", "gray",
"half", "hang", "hard", "hats", "head", "heat", "hide", "high", "hill", "hint", "hire", "hold",
"hook", "huge", "hurt", "hymn",
"idea", "iron",
"jets", "joke", "judo",
"keen", "kiss",
"lace", "lack", "land", "late", "lawn", "lazy", "less", "link", "live", "loaf", "loan", "logo",
"look", "lord", "loss", "loud",
"melt", "menu", "mere", "mill", "mine", "mint", "mist", "mode", "moon", "most", "move", "much",
"name", "neat", "need", "nest", "noon", "nude",
"oars", "oust",
"pace", "pads", "page", "paid", "pain", "pale", "pane", "park", "pars", "part", "pass", "past",
"pear", "pegs", "pens", "pier", "pine", "pins", "pint", "pity", "plan", "poem", "poet", "pond",
"pool", "poor", "post", "pure",
"rack", "rare", "real", "rest", "rich", "riot", "ripe", "road", "roam", "room", "root", "rude",
"rule",
"safe", "sail", "sale", "same", "sand", "save", "scan", "seal", "seat", "seem", "send", "sent",
"shin", "shop", "shut", "sick", "side", "sift", "sign", "silk", "sing", "skip", "slim", "slip",
"slum", "soap", "soil", "sold", "solo", "sore", "sour", "spit", "step", "stew", "sure",
"tall", "teak", "team", "tear", "tent", "then", "tide", "time", "tone", "tour", "town", "trim",
"trod", "true", "tube", "tune", "turn",
"used",
"vain", "vast", "vend", "vote",
"wait", "walk", "want", "ward", "warn", "wave", "west", "wild", "wind", "wing", "wire", "wise",
"worm",
"zone"
};

static const char *word5[] =
{
"aback", "acres", "adapt", "agent", "agony", "ahead", "alarm", "alert", "align", "alien", "allot", "amble",
"angle", "ankle", "arena", "armed", "arrow", "audio", "award",
"beams", "bland", "blank", "bleak", "bless", "boast", "boost", "bored", "bread", "bring", "broke", "buyer",
"cable", "cakes", "canoe", "cards", "cargo", "cause", "chair", "cheap", "chips", "choke", "climb", "clove",
"coact", "coins", "comic", "cough", "count", "cover", "crane", "crash", "crude", "cruel", "cubic", "curry",
"dairy", "delay", "dance", "dense", "desks", "diner", "dines", "dozen", "draft", "dream", "drink", "drown",
"drunk", "dusts", "dusty",
"early", "eight", "elder", "enter", "equal", "equip", "erode", "evens", "event", "exact", "exams", "excel",
"extra",
"fancy", "fares", "fence", "fibre", "fifty", "filed", "files", "final", "first", "floor", "flour", "flute",
"focus", "foggy", "front", "fruit",
"genie", "giant", "glare", "glaze", "gleam", "glory", "glows", "grave", "great", "grids", "group", "grove",
"guess", "guest",
"harps", "hawks", "heavy", "house", "humor",
"ideal", "index", "infer", "inked", "ivory",
"judge",
"knock",
"laces", "large", "lawny", "learn", "light", "lilac", "linen", "lofts", "loose", "lucky", "lunar", "lyric",
"madam", "magic", "major", "malts", "manor", "maple", "march", "marry", "merit", "moist", "molar", "motto",
"mourn", "mouse", "muddy",
"nacho", "novel", "nurse",
"odeon", "offer", "optic",
"pages", "panda", "pants", "pause", "peace", "pedal", "pesto", "piano", "piece", "piety", "pings", "pious",
"pivot", "place", "plant", "plate", "pound", "prime", "prize", "probe", "prose", "proud", "prune", "puppy",
"pylon",
"quiet",
"rally", "refer", "remit", "renew", "repel", "reset", "roach", "rocky", "roofs", "rooks", "rough", "royal",
"rusty",
"salad", "scarf", "scoop", "scoot", "scope", "score", "scorn", "shaft", "share", "sharp", "sheds", "shine",
"share", "shiny", "shirt", "shore", "shrub", "silly", "sixty", "skate", "socks", "sound", "spade", "spare",
"spend", "spent", "squad", "stack", "stand", "stare", "stars", "start", "stats", "steam", "stick", "stoop",
"storm", "story", "sunny", "sweat", "swept", "swift", "swing", "sword",
"tally", "talon", "tempt", "tench", "tents", "these", "thick", "thief", "those", "tidal", "tiger", "title",
"today", "track", "train", "tread", "trend", "trick", "trust", "tuned", "twigs", "twist",
"unbid", "unbox", "uncap", "upend", "upper", "upset",
"valid", "vends", "verge", "verse", "vines", "visit",
"weary", "wheat", "wheel", "whole", "worth", "wound", "wrist",
"yeast",
"zooms"
};

if (upper)
    {
    uword3 = create_upper_array(word3, sizeof(word3) / sizeof(char *));
    uword4 = create_upper_array(word4, sizeof(word4) / sizeof(char *));
    uword5 = create_upper_array(word5, sizeof(word5) / sizeof(char *));
    }

for(w3 = 0; w3 < (sizeof(word3) / sizeof(char *)); w3++)
	{
	for(w4 = 0; w4 < (sizeof(word4) / sizeof(char *)); w4++)
		{
		for(w5 = 0; w5 < (sizeof(word5) / sizeof(char *)); w5++)
			{
			if (upper)
			    {
			    snprintf(pskstring, 16, pskmask, uword3[w3],  word4[w4],  word5[w5]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word3[w3], uword4[w4],  word5[w5]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word3[w3],  word4[w4], uword5[w5]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask, uword3[w3],  word5[w5],  word4[w4]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word3[w3], uword5[w5],  word4[w4]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word3[w3],  word5[w5], uword4[w4]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask, uword4[w4],  word3[w3],  word5[w5]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word4[w4], uword3[w3],  word5[w5]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word4[w4],  word3[w3], uword5[w5]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask, uword4[w4],  word5[w5],  word3[w3]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word4[w4], uword5[w5],  word3[w3]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word4[w4],  word5[w5], uword3[w3]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask, uword5[w5],  word3[w3],  word4[w4]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word5[w5], uword3[w3],  word4[w4]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word5[w5],  word3[w3], uword4[w4]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask, uword5[w5],  word4[w4],  word3[w3]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word5[w5], uword4[w4],  word3[w3]);
			    fputs(pskstring, fhout);
			    snprintf(pskstring, 16, pskmask,  word5[w5],  word4[w4], uword3[w3]);
			    fputs(pskstring, fhout);
			    }
			else
			    {
			    snprintf(pskstring, 16, pskmask,  word3[w3],  word4[w4],  word5[w5]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask,  word3[w3],  word5[w5],  word4[w4]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask,  word4[w4],  word3[w3],  word5[w5]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask,  word4[w4],  word5[w5],  word3[w3]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask,  word5[w5],  word3[w3],  word4[w4]);
			    fputs(pskstring, fhout);

			    snprintf(pskstring, 16, pskmask,  word5[w5],  word4[w4],  word3[w3]);
			    fputs(pskstring, fhout);
			    }
			}
		}
	}

if (upper)
    {
    free_array(uword3, sizeof(word3) / sizeof(char *));
    free_array(uword4, sizeof(word4) / sizeof(char *));
    free_array(uword5, sizeof(word5) / sizeof(char *));
    }

return;
}
/*===========================================================================*/
/* source: soxrok2212, https://github.com/soxrok2212/PSKracker/tree/master/dicts/altice-optimum */
static void keywritealticeoptimum(FILE *fhout)
{
static unsigned int w, i;
char si[7] = {0};

static const char *word[] =
{
"amber", "aqua", "auburn",
"beige", "blue", "brick", "bronze", "burgundy",
"chestnut", "cobalt", "copper", "coral", "cordovan", "crimson", "cyan",
"emerald",
"garnet", "gold", "granite", "green", "grey",
"indigo",
"jade",
"lavender", "lemon", "lime", "linen",
"magenta", "maroon", "mauve",
"navy",
"olive", "orange", "orchid",
"peach", "periwinkle", "pewter", "pink", "plum", "purple",
"rose",
"sage", "sepia", "sienna", "silver", "slate",
"taupe", "teal", "turquoise"
};

for (i = 0; i < 1000000; i++)
{
    sprintf(si, "%06d", i);
    for (w = 0; w < (sizeof(word) / sizeof(char *)); w++ )
	    {
	        // 2-4
	        //fprintf(fhout, "%s-%.2s-%.4s\n", word[w], si, si+2);
	        fprintf(fhout, "%.2s-%s-%.4s\n", si, word[w], si+2);
	        fprintf(fhout, "%.2s-%.4s-%s\n", si, si+2, word[w]);
	        // 3-3
	        fprintf(fhout, "%s-%.3s-%.3s\n", word[w], si, si+3);
	        fprintf(fhout, "%.3s-%s-%.3s\n", si, word[w], si+3);
	        fprintf(fhout, "%.3s-%.3s-%s\n", si, si+3, word[w]);
	        // 4-2
	        fprintf(fhout, "%s-%.4s-%.2s\n", word[w], si, si+4);
	        fprintf(fhout, "%.4s-%s-%.2s\n", si, word[w], si+4);
	        //fprintf(fhout, "%.4s-%.2s-%s\n", si, si+4, word[w]);
	    }
}

return;
}
/*===========================================================================*/
static void keywriteasus(FILE *fhout)
{
static unsigned int w, i;

static const char *word[] =
{
"account", "actor", "alpha", "amazing", "answer", "anyway", "athlete", "autumn", "avenue",
"bakery", "balcony", "banking", "battery", "bedroom", "bicycle", "birthday", "browser",
"calendar", "camping", "category", "center", "charming", "cinema", "cocoa", "coffee", "cupid",
"december", "delivery", "delta", "dollar", "donkey", "drama", "dream",
"economy", "enjoy", "eternity", "everyday", "examiner", "export", "extra", "eyebrow",
"february", "feeling", "flower", "fortune", "founder", "four",
"gasoline", "giant", "glory", "golden", "grape", "guide",
"haircut", "handsome", "harmony", "hawk", "header", "hiking", "hometown", "honor",
"hundred", "hunter",
"jaguar", "jazz", "jogging", "july", "june", "jumper", "junior", "justdoit",
"keeper", "keyboard", "kingdom", "kiss", "kitchen", "knife", "knuckle",
"leopard", "letter", "lighting", "literacy", "lucky", "lunar",
"majesty", "mankind", "mars", "memory", "mercy", "momentum", "morning", "museum",
"network", "next", "night", "noodle", "notebook", "nurse",
"painter", "pajamas", "panda", "parttime", "passion", "popcorn", "puma", "puppet", "pyramid",
"random", "ranking", "reading", "relax", "remark", "revenue", "ribbon",
"salon", "saturday", "science", "sexy", "soccer", "sour", "spider", "star", "sugar", "sunday"
};

for (w = 0; w < (sizeof(word) / sizeof(char *)); w++ )
	{
	for (i = 0; i < 10000; i++)
		{
		fprintf(fhout, "%s_%04d\n", word[w], i);
		}
	}

return;
}
/*===========================================================================*/
static void keywriteweakpass(FILE *fhout)
{
static size_t w;
static unsigned int y;

static char pskstring[PSKSTRING_LEN_MAX] = { 0 };
static const char *weakword[] =
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
"Hello123", "HelloKitty", "helloworld123", "Hercules", "IceCream", "idontknow", "iloveyou",
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
"Skywalker", "Slipknot", "smartbro", "Snickers", "Snowball", "Snowboard", "Something",
"Southpark", "Spiderman", "Spitfire", "SpongeBob", "Starcraft", "Stargate",
"StarTrek", "StarWars", "Steelers", "Stephanie", "Strawberry", "Sunflower",
"Sunshine", "Superman", "Superstar", "Swordfish", "TaxiLinQ",  "Terminator",
"TestTest", "Tinkerbell", "TrustNo1", "Twilight", "Undertaker", "Valentina",
"Valentine", "Veronica", "Victoria", "Warcraft", "Warhammer", "Welcome1",
"Westside", "WhatEver", "Williams", "Wolverine", "Wordpass", "zaq12wsx",
"zaq1xsw2"
};

for(w = 0; w < (sizeof(weakword) /sizeof(weakword[0])); w++)
	writepsk(fhout, weakword[w]);

for(y = 1900; y <= thisyear; y++)
	{
	snprintf(pskstring, PSKSTRING_LEN_MAX, "abcd%04d", y);
	writepsk(fhout, pskstring);
	}

for(y = 0; y < 1000; y++)
	{
	snprintf(pskstring, PSKSTRING_LEN_MAX, "%03d%03d%03d", y, y, y);
	writepsk(fhout, pskstring);
	}
return;
}
/*===========================================================================*/
static void keywritesimple(FILE *fhout)
{
static int a,b,c;

for(a =0x20; a < 0x7f; a++)
 for(b = 0x20; b < 0x7f; b++)
	{
	fprintf(fhout, "12341234%c%c\n", a, b);
	fprintf(fhout, "%c%c12341234\n", a, b);
	fprintf(fhout, "1234512345%c%c\n", a, b);
	fprintf(fhout, "%c%c1234512345\n", a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", a, a, b, b, a, a, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", a, a, b, b, a, a, b, b, a, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c%c\n", a, a, b, b, a, a, b, b, a, a, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", a, b, a, b, a, b, a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", a, b, a, b, a, b, a, b, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", a, b, a, b, a, b, a, b, a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c\n", a, b, a, b, a, b, a, b, a, b, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c%c\n", a, b, a, b, a, b, a, b, a, b, a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", a, b, b, b, b, b, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", a, b, b, b, b, b, b, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", a, b, b, b, b, b, b, b, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c\n", a, b, b, b, b, b, b, b, b, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c%c\n", a, b, b, b, b, b, b, b, b, b, b, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", b, b, b, b, b, b, b, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", b, b, b, b, b, b, b, b, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", b, b, b, b, b, b, b, b, b, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c\n", b, b, b, b, b, b, b, b, b, b, a);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c%c%c\n", b, b, b, b, b, b, b, b, b, b, b, a);
	}
for(a =0x20; a < 0x7f; a++)
 for(b =0x20; b < 0x7f; b++)
  for(c =0x20; c < 0x7f; c++)
	{
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", a, b, c, a, b, c, a, b, c);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", a, a, a, b, b, b, c, c, c);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", a, c, c, c, c, c, c, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", a, c, c, c, c, c, c, c, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", a, c, c, c, c, c, c, c, c, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", a, b, c, c, c, c, c, c);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", a, b, c, c, c, c, c, c, c);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", a, b, c, c, c, c, c, c, c, c);
	fprintf(fhout, "%c%c%c%c%c%c%c%c\n", c, c, c, c, c, c, a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c\n", c, c, c, c, c, c, c, a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", c, c, c, c, c, c, c, c, a, b);
	fprintf(fhout, "%c%c%c%c%c%c%c%c%c%c\n", a, b, b, b, b, c, c, c, c, a);
	}
return;
}
/*===========================================================================*/
static void keywriteeudate(FILE *fhout)
{
static unsigned int d, m, y;

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 1; d <= 28; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			fprintf(fhout, "%02d%02d%04d\n", d, m, y);
			fprintf(fhout, "%02d.%02d.%04d\n", d, m, y);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 29; d <= 30; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			fprintf(fhout, "%02d%02d%04d\n", d, m, y);
			fprintf(fhout, "%02d.%02d.%04d\n", d, m, y);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	fprintf(fhout, "3101%04d\n", y);
	fprintf(fhout, "3103%04d\n", y);
	fprintf(fhout, "3105%04d\n", y);
	fprintf(fhout, "3107%04d\n", y);
	fprintf(fhout, "3108%04d\n", y);
	fprintf(fhout, "3110%04d\n", y);
	fprintf(fhout, "3112%04d\n", y);
	fprintf(fhout, "31.01.%04d\n", y);
	fprintf(fhout, "31.03.%04d\n", y);
	fprintf(fhout, "31.05.%04d\n", y);
	fprintf(fhout, "31.07.%04d\n", y);
	fprintf(fhout, "31.08.%04d\n", y);
	fprintf(fhout, "31.10.%04d\n", y);
	fprintf(fhout, "31.12.%04d\n", y);
	}

for(y = 1900; y <= thisyear; y++)
	{
	if (((y %4 == 0) && (y %100 != 0)) || (y %400 == 0))
		{
		fprintf(fhout, "2902%04d\n", y);
		fprintf(fhout, "29.02.%04d\n", y);
		}
	}
return;
}
/*===========================================================================*/
static void keywriteusdate(FILE *fhout)
{
static unsigned int d, m, y;

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 1; d <= 28; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			fprintf(fhout, "%02d%02d%04d\n", m, d, y);
			fprintf(fhout, "%02d.%02d.%04d\n", m, d, y);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	for(d = 29; d <= 30; d++)
		{
		for(m = 1; m <= 12; m++)
			{
			fprintf(fhout, "%02d%02d%04d\n", m, d, y);
			fprintf(fhout, "%02d.%02d.%04d\n", m, d, y);
			}
		}
	}

for(y = 1900; y <= thisyear; y++)
	{
	fprintf(fhout, "0131%04d\n", y);
	fprintf(fhout, "0331%04d\n", y);
	fprintf(fhout, "0531%04d\n", y);
	fprintf(fhout, "0731%04d\n", y);
	fprintf(fhout, "0831%04d\n", y);
	fprintf(fhout, "1031%04d\n", y);
	fprintf(fhout, "1231%04d\n", y);
	fprintf(fhout, "01.31.%04d\n", y);
	fprintf(fhout, "03.31.%04d\n", y);
	fprintf(fhout, "05.31.%04d\n", y);
	fprintf(fhout, "07.31.%04d\n", y);
	fprintf(fhout, "08.31.%04d\n", y);
	fprintf(fhout, "10.31.%04d\n", y);
	fprintf(fhout, "12.31.%04d\n", y);
	}

for(y = 1900; y <= thisyear; y++)
	{
	if (((y %4 == 0) && (y %100 != 0)) || (y %400 == 0))
		{
		fprintf(fhout, "0229%04d\n", y);
		fprintf(fhout, "02.29.%04d\n", y);
		}
	}
return;
}
/*===========================================================================*/
static void keywriteyearyear(FILE *fhout)
{
static unsigned int y, y2, y3;
static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

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
static void keywriteegn(FILE *fhout)
{
static unsigned int y, m, d, mc, i, j, c;
static char pskstring[PSKSTRING_LEN_MAX] = { 0 };
static unsigned int w[] = {2, 4, 8, 5, 10, 9, 7, 3, 6};

for(y = 1950; y <= thisyear; y++)
	{
	if (y < 2000) mc = 0; else mc = 40;
	for(m = 1; m <= 12; m++)
		{
		for(d = 1; d <= 31; d++)
			{
			if (m == 2)
				{
				if ((((y % 4 == 0) && (y % 100 != 0)) || (y % 400 == 0)))
					{
					if (d > 29) continue;
					}
				else
					{
					if (d > 28) continue;
					}
				}
			if ((m == 4 || m == 6 || m == 9 || m == 11) && d > 30) continue;
			for (i = 0; i < 1000; i++)
				{
				snprintf(pskstring, PSKSTRING_LEN_MAX, "%02d%02d%02d%03d", y % 100, m + mc, d, i);
				c = 0;
				for (j = 0; j < 9; j++)
					{
					c += (pskstring[j] - 48) * w[j];
					}
				c %= 11;
				if (c == 10) c = 0;
				pskstring[9] = c + 48;
				pskstring[10] = 0;
				writepsk(fhout, pskstring);
				}
			}
		}
	}
return;
}
/*===========================================================================*/
static void preparebssidessid(FILE *fhout, unsigned long long int macaddr, uint8_t essidlen, uint8_t *essid)
{
static int k2;
static int ek;
static char *ev;
static unsigned int oui;

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen >= 6)
	{
	if((isxdigit((unsigned char)essid[essidlen -6])) && (isxdigit((unsigned char)essid[essidlen -5])) && (isxdigit((unsigned char)essid[essidlen -4])) && (isxdigit((unsigned char)essid[essidlen -3])) && (isxdigit((unsigned char)essid[essidlen -2])) && (isxdigit((unsigned char)essid[essidlen -1])))
		{
		ev = (char*)(essid +essidlen -6);
		ek = strtol(ev, NULL, 16);
		oui = (macaddr &0xffffff000000L) >> 24;
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "%06x%06x", oui, ek);
		writepsk(fhout, essidtmp);
		}
	}
return;
if(essidlen >= 4)
	{
	if((isxdigit((unsigned char)essid[essidlen -4])) && (isxdigit((unsigned char)essid[essidlen -3])) && (isxdigit((unsigned char)essid[essidlen -2])) && (isxdigit((unsigned char)essid[essidlen -1])))
		{
		ev = (char*)(essid +7);
		ek = strtol(ev, NULL, 16);
		for(k2 = ek -10;  k2 < ek +10; k2++)
			{
			snprintf(essidtmp, PSKSTRING_LEN_MAX, "%08llx%04x", (macaddr >> 16), (k2 &0xffff));
			writepsk(fhout, essidtmp);
			}
		}
	}
return;
}
/*===========================================================================*/
static void processbssidsessids(FILE *fhout)
{
static int c;
static apessidl_t *zeiger;
static apessidl_t *zeiger1;

qsort(apessidliste, apessidcount, APESSIDLIST_SIZE, sort_apessidlist_by_ap);
zeiger = apessidliste;
for(c = 0; c < apessidcount; c++)
	{
	if(c == 0) preparebssidessid(fhout, zeiger->macaddr, zeiger->essidlen, zeiger->essid);
	else
		{
		zeiger1 = zeiger -1;
		if((zeiger->macaddr != zeiger1->macaddr) || (zeiger->essidlen != zeiger1->essidlen) || (memcmp(zeiger->essid, zeiger1->essid, zeiger->essidlen) != 0))
			{
			preparebssidessid(fhout, zeiger->macaddr, zeiger->essidlen, zeiger->essid);
			}
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static void writeessidadd(FILE *fhout, char *essid)
{
static unsigned int c, d;
static char essidstring[PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX] = { 0 };

for(c = 22222; c <= 99999; c += 11111)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
	writepsk(fhout, essidstring);
	}

if(essidglen <= 2)
	{
	for(c = thisyear +1; c < 1000000; c++)
		{
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
		writepsk(fhout, essidstring);
		}
	}

if(essidglen <= 3)
	{
	for(c = thisyear +1; c < 100000; c++)
		{
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
		writepsk(fhout, essidstring);
		}
	}

if(essidglen <= 12)
	{
	for(c = thisyear +1; c < 10000; c++)
		{
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
		writepsk(fhout, essidstring);
		}
	}

if(essidglen > 12)
	{
	for(c = 2222; c <= 9999; c += 1111)
		{
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
		writepsk(fhout, essidstring);
		}
	}

for(c = 0; c <= thisyear; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d!", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%04d%s", c, essid);
	writepsk(fhout, essidstring);
	}

for(c = 100; c < 1000; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%05d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d!", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%d%s", c, essid);
	writepsk(fhout, essidstring);
	}

for(c = 10; c < 100; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%03d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%d!", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%d%s", c, essid);
	writepsk(fhout, essidstring);
	}

for(c = 0; c < 10; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%04d", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%03d", essid, c);
	writepsk(fhout, essidstring);
	}

for(c = 0; c <= 99; c++)
	{
	for(d = 0; d <= 99; d++)
		{
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%02d%s%02d", c, essid, d);
		writepsk(fhout, essidstring);
		}
	}

for(c = 0x21; c < 0x7f; c++)
	{
	for(d = 0x21; d < 0x7f; d++)
		{
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%c%c%s%c%c", c, d, essid, d, c);
		writepsk(fhout, essidstring);
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%c%c", essid, c, d);
		writepsk(fhout, essidstring);
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%c%c%s", c, d, essid);
		writepsk(fhout, essidstring);
		snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%c%s%c", c, essid, d);
		writepsk(fhout, essidstring);
		}
	}

for(c = 0x21; c < 0x7f; c++)
	{
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%c", essid, c);
	writepsk(fhout, essidstring);
	snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%c%s", c, essid);
	writepsk(fhout, essidstring);
	}

snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s1234567890", essid);
writepsk(fhout, essidstring);
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
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s4711", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "1234567890%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "123456789%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "12345678%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "1234567%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "123456%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "12345%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "9876543210%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "987654321%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "87654321%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "7654321%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "654321%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "54321%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@adsl", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@Home", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@WiFi", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@1234", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%sWiFi", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@dsl", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s@123", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX, "%s%s%s", essid, essid, essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s%s", essid, essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "%s", essid);
writepsk(fhout, essidstring);

snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "Family%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "Familie%s", essid);
writepsk(fhout, essidstring);
snprintf(essidstring, PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX , "Familia%s", essid);
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

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

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
writeessidadd(fhout, (char*)essid);
if(removeflag == true) writeessidadd(fhout, essidtmp);
return removeflag;
}
/*===========================================================================*/
static void writeessidsweeped(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int l1, l2;
static uint8_t sweepstring[PSKSTRING_LEN_MAX] = { 0 };

for(l1 = 2; l1 <= essidlen; l1++)
	{
	for(l2 = 0; l2 <= essidlen -l1; l2++)
		{
		memset(&sweepstring, 0, PSKSTRING_LEN_MAX);
		memcpy(&sweepstring, &essid[l2], l1);
		writeessidremoved(fhout, l1, sweepstring);
		}
	}
return;
}
/*===========================================================================*/
static void testairtel(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *air = "Airtel_";

if(airtelflag == true) return;
if(essidlen < 7) return;
if(memcmp(essid, air, 7) != 0) return;
fprintf(fhout, "Airtel@123\n");
for(k = 0; k < 100000; k++) fprintf(fhout, "air%05d\n", k);
airtelflag = true;
return;
}
/*===========================================================================*/
static void testalcatellinkzone(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *ali = "Alcatel LINKZONE ";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen != 21) return;
if(memcmp(essid, ali, 17) != 0) return;
if((!isdigit((unsigned char)essid[17])) || (!isdigit((unsigned char)essid[18])) || (!isdigit((unsigned char)essid[19])) || (!isdigit((unsigned char)essid[20]))) return;
for(k1 = 0; k1 < 10000; k1++)
	{
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "%04d%c%c%c%c", k1, essid[17], essid[18], essid[19], essid[20]);
	writepsk(fhout, essidtmp);
	}
return;
}
/*===========================================================================*/
static void testarrisizzi(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int c;
static uint32_t i;
static const char *izzi = "IZZI-";

static int fixseed2[] =
{
0x001C15, 0x189C27, 0x3C0461, 0x509551, 0x704FB8, 0x8871B1, 0x8C61A3, 0x9CC8FC,
0xA811FC, 0xD4AB82, 0xF0AF85, 0xF82DC0, 0xF88B37, 0xF8F532, 0xFCAE34
};
#define FIXSEED2_SIZE sizeof(fixseed2) /sizeof(int)

if(essidlen < 9) return;
if(memcmp(essid, izzi, 5) != 0) return;
if((!isxdigit((unsigned char)essid[5])) || (!isxdigit((unsigned char)essid[6])) || (!isxdigit((unsigned char)essid[7])) || (!isxdigit((unsigned char)essid[8]))) return;
for(i = 0; i < FIXSEED2_SIZE; i++)
	{
	for(c = 0; c < 0x100; c++) fprintf(fhout, "%06X%02X%lc%lc%lc%lc\n", fixseed2[i], c, essid[5], essid[6], essid[7], essid[8]);
	}
return;
}
/*===========================================================================*/
static void testarristg(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *dg860A = "DG860A";
static const char *tg852g = "TG852G";
static const char *tg862g = "TG862G";
static const char *dg1670A = "DG1670A";
static const char *sbg6580 = "SBG6580";
static const char *tg1672g = "TG1672G";

if(essidlen >= 8)
	{
	if((!isxdigit((unsigned char)essid[6])) || (!isxdigit((unsigned char)essid[7]))) return;
	if(memcmp(essid, dg860A, 6) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "DG860A%04X%c%c\n", k1, essid[6], essid[7]);
		return;
		}
	if(memcmp(essid, tg852g, 6) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "TG852G%04X%c%c\n", k1, essid[6], essid[7]);
		return;
		}
	if(memcmp(essid, tg862g, 6) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "TG862G%04X%c%c\n", k1, essid[6], essid[7]);
		return;
		}
	}
if(essidlen >= 9)
	{
	if((!isxdigit((unsigned char)essid[7])) || (!isxdigit((unsigned char)essid[8]))) return;
	if(memcmp(essid, dg1670A, 7) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "DG1670A%04X%c%c\n", k1, essid[7], essid[8]);
		return;
		}
	if(memcmp(essid, sbg6580, 7) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "SBG6580%04X%c%c\n", k1, essid[7], essid[8]);
		return;
		}
	if(memcmp(essid, tg1672g, 7) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "TG1672G%04X%c%c\n", k1, essid[7], essid[8]);
		return;
		}
	}
return;
}
/*===========================================================================*/
static void testaxtelxtremo(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *axtelxtremo = "AXTEL XTREMO-";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen != 17) return;
if(memcmp(essid, axtelxtremo, 13) != 0) return;
if((!isxdigit((unsigned char)essid[13])) || (!isxdigit((unsigned char)essid[14])) || (!isxdigit((unsigned char)essid[15])) || (!isxdigit((unsigned char)essid[16]))) return;
for(k1 = 0; k1 < 10000; k1++)
	{
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "%04d%c%c%c%c", k1, essid[13], essid[14], essid[15], essid[16]);
	writepsk(fhout, essidtmp);
	}
return;
}
/*===========================================================================*/
static void testattwifi(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1, k2, k3, k4;
static const char *attwifi = "ATT-WIFI-";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen != 13) return;
if(memcmp(essid, attwifi, 9) != 0) return;
if((!isdigit((unsigned char)essid[9])) || (!isdigit((unsigned char)essid[10])) || (!isdigit((unsigned char)essid[11])) || (!isdigit((unsigned char)essid[12]))) return;
for(k1 = 0; k1 < 10; k1++)
	for(k2 = 0; k2 < 10; k2++)
		for(k3 = 0; k3 < 10; k3++)
			for(k4 = 0; k4 < 10; k4++)
				{
				snprintf(essidtmp, PSKSTRING_LEN_MAX, "%d%c%d%c%d%c%d%c", k1, essid[9], k2, essid[10], k3, essid[12], k4, essid[11]);
				writepsk(fhout, essidtmp);
				}
return;
}
/*===========================================================================*/
static void testcabovisao(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *cabovisao = "Cabovisao-";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen != 14) return;
if(memcmp(essid, cabovisao, 10) != 0) return;
if((!isxdigit((unsigned char)essid[10])) || (!isxdigit((unsigned char)essid[11])) || (!isxdigit((unsigned char)essid[12])) || (!isxdigit((unsigned char)essid[13]))) return;
for(k1 = 0; k1 < 0x100; k1++)
	{
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "2ce412%02x%c%c%c%c", k1, essid[10], essid[11], essid[12], essid[13]);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "e0ca94%02x%c%c%c%c", k1, essid[10], essid[11], essid[12], essid[13]);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "e0cec3%02x%c%c%c%c", k1, essid[10], essid[11], essid[12], essid[13]);
	writepsk(fhout, essidtmp);
	}
return;
}
/*===========================================================================*/
static void testcg3000dv2(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *cg3000dv2 = "CG3000DV2";

if(essidlen < 11) return;
if(memcmp(essid, cg3000dv2, 9) != 0) return;
if((!isxdigit((unsigned char)essid[9])) || (!isxdigit((unsigned char)essid[10]))) return;
for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "CG3000DV2%04X%c%c\n", k1, essid[9], essid[10]);
return;
}
/*===========================================================================*/
static void testcpsrf(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *cpcrf1 = "CoolpadSurf_";
static const char *cpcrf2 = "Coolpad Surf ";

if(essidlen < 16) return;
if(memcmp(essid, cpcrf1, 12) == 0)
	{
	if((!isdigit((unsigned char)essid[12])) || (!isdigit((unsigned char)essid[13])) || (!isdigit((unsigned char)essid[14])) || (!isdigit((unsigned char)essid[15]))) return;
	for(k1 = 0; k1 < 10000; k1++) fprintf(fhout, "%04d%.*s\n", k1, 4, &essid[12]);
	return;
	}
if(essidlen < 17) return;
if(memcmp(essid, cpcrf2, 13) == 0)
	{
	if((!isdigit((unsigned char)essid[13])) || (!isdigit((unsigned char)essid[14])) || (!isdigit((unsigned char)essid[15])) || (!isdigit((unsigned char)essid[16]))) return;
	for(k1 = 0; k1 < 10000; k1++) fprintf(fhout, "%04d%.*s\n", k1, 4, &essid[13]);
	return;
	}
return;
}
/*===========================================================================*/
static void testeasybox(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int b;
static int s10, s9, s8 , s7;
static int m12, m11, m10 ,m9;
static int f1, f2;
static int k1, k2, k3, k4, k5, k6, k7, k8, k9;

static const char *easybox = "EasyBox-";

if(easyboxflag == true) return;
if(essidlen != 14) return;
if(memcmp(essid, easybox, 8) != 0) return;
if((!isxdigit((unsigned char)essid[8])) || (!isxdigit((unsigned char)essid[9])) || (!isxdigit((unsigned char)essid[10])) || (!isxdigit((unsigned char)essid[11])) || (!isdigit((unsigned char)essid[12])) || (!isdigit((unsigned char)essid[13]))) return;
for (b = 0; b <= 0xffff; b++)
	{
	m12 =  b &0x000f;
	m11 = (b &0x00f0) >> 4;
	m10 = (b &0x0f00) >> 8;
	m9 =  (b &0xf000) >> 12;
	s10 = b %10;
	s9 = (b /10) %10;
	s8 = (b /100) %10;
	s7 = (b /1000) %10;
	f1 = (s7 +s8 +m11 +m12) & 0xf;
	f2 = (m9 +m10 +s9 +s10) & 0xf;
	k1 = f1 ^s10;
	k2 = f2 ^m10;
	k3 = m11 ^s10;
	k4 = f1 ^s9;
	k5 = f2 ^m11;
	k6 = m12 ^s9;
	k7 = f1 ^s8;
	k8 = f2 ^m12;
	k9 = f1 ^f2;
	fprintf (fhout, "%X%X%X%X%X%X%X%X%X\n", k1, k2, k3, k4, k5, k6, k7, k8, k9);
	}
easyboxflag = true;
return;
}
/*===========================================================================*/
static void testglocal(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1, k2, k3, k4;
static const char *glocalme = "GlocalMe_";

if(essidlen != 14) return;
if(memcmp(essid, glocalme , 9) != 0) return;
if((!isdigit((unsigned char)essid[9])) || (!isdigit((unsigned char)essid[10])) || (!isdigit((unsigned char)essid[11])) || (!isdigit((unsigned char)essid[12])) || (!isdigit((unsigned char)essid[13]))) return;
k2 = essid[11];
k3 = essid[12];
for(k1 = 0; k1 < 100000; k1++)
	{
	for(k4 = 0; k4 < 10; k4++) fprintf(fhout, "%05d%c%c%d\n", k1, k2, k3, k4);
	}

return;
}
/*===========================================================================*/
static void testhotbox(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1, k2;
static char *ev;
static const char *hotbox = "HOTBOX";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen < 7) return;
if(memcmp(essid, hotbox , 6) != 0) return;
if(hb5flag == false)
	{
	for(k1 = 500000000; k1 < 560000000; k1++) fprintf(fhout, "%010d\n", k1);
	for(k1 = 770000000; k1 < 780000000; k1++) fprintf(fhout, "%010d\n", k1);
	}
hb5flag = true;
if(essidlen != 11) return;
if(essid[6] != '-') return;
if((!isxdigit((unsigned char)essid[7])) || (!isxdigit((unsigned char)essid[8])) || (!isxdigit((unsigned char)essid[9])) || (!isxdigit((unsigned char)essid[10]))) return;
ev = (char*)(essid +7);
k2 = strtol(ev, NULL, 16);
for(k1 = 0; k1 < 0x100; k1++)
	{
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "086a0a%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "2ce412%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "4c17eb%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "6c2e85%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "700b01%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "7c034c%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "7cb733%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "a0648f%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "b4eeb4%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "c0ac54%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "d86ce9%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "d8fb5e%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "e0cec3%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "e8d11b%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "fcb4e6%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	}
for(k1 = 500000000; k1 < 560000000; k1++) fprintf(fhout, "%010d\n", k1);
return;
}
/*===========================================================================*/
static void testmtel(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1, k2;
static const char *a1 = "A1_";
static const char *mtel = "M-Tel_";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen == 7)
	{
	if(memcmp(essid, a1, 3) == 0)
		{
		if((isxdigit((unsigned char)essid[3])) && (isxdigit((unsigned char)essid[4])) && (isxdigit((unsigned char)essid[5])) && (isxdigit((unsigned char)essid[6])))
			{
			for(k1 = 0; k1 < 0x100; k1++)
				for(k2 = 0; k2 < 0x100; k2++)
					{
					snprintf(essidtmp, PSKSTRING_LEN_MAX, "48575443%02X%c%c%c%c%02X", k1, essid[3], essid[4], essid[5], essid[6], k2);
					writepsk(fhout, essidtmp);
					snprintf(essidtmp, PSKSTRING_LEN_MAX, "48575443%02X%02X%c%c%c%c", k1, k2, essid[3], essid[4], essid[5], essid[6]);
					writepsk(fhout, essidtmp);
				}
			}
		}
	return;
	}
if(essidlen == 10)
	{
	if(memcmp(essid, mtel, 6) == 0)
		{
		if((isxdigit((unsigned char)essid[6])) && (isxdigit((unsigned char)essid[7])) && (isxdigit((unsigned char)essid[8])) && (isxdigit((unsigned char)essid[9])))
			{
			for(k1 = 0; k1 < 0x100; k1++)
				{
				for(k2 = 0; k2 < 0x100; k2++)
					{
					snprintf(essidtmp, PSKSTRING_LEN_MAX, "48575443%02X%c%c%c%c%02X", k1, essid[6], essid[7], essid[8], essid[9], k2);
					writepsk(fhout, essidtmp);
					}
				}
			}
		}
	return;
	}
return;
}
/*===========================================================================*/
static void testmywifi(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *mywifi = "MY WIFI ";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen != 12) return;
if(memcmp(essid, mywifi, 8) != 0) return;
for(k1 = 0; k1 < 10000; k1++)
	{
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "MYWIFI%04d", k1);
	writepsk(fhout, essidtmp);
	}
return;
}
/*===========================================================================*/
static void testnet2g(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *net2g = "NET_2G";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen < 12) return;
if(memcmp(essid, net2g, 6) != 0) return;
if((isxdigit((unsigned char)essid[6])) && (isxdigit((unsigned char)essid[7])) && (isxdigit((unsigned char)essid[8])) && (isxdigit((unsigned char)essid[9])) && (isxdigit((unsigned char)essid[10])) && (isxdigit((unsigned char)essid[11])))
	{
	for(k = 0; k < 0x100; k++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "%02X%lc%lc%lc%lc%lc%lc", k, essid[6], essid[7], essid[8], essid[9], essid[10], essid[11]);
		writepsk(fhout, essidtmp);
		}
	}
return;
}
/*===========================================================================*/
static void testnetv(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *net2g = "Net-Virtua";

if(essidlen < 15) return;
if(memcmp(essid, net2g, 10) != 0) return;
if((isdigit((unsigned char)essid[11])) && (isdigit((unsigned char)essid[12])) && (isdigit((unsigned char)essid[13])) && (isdigit((unsigned char)essid[14])))
	{
    for(k = 0; k < 1000; k++)
	    {
	    fprintf(fhout,   "%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "15%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "16%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "24%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "31%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "33%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "37%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "38%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "40%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "61%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    fprintf(fhout, "71%03d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    }
    for(k = 0; k < 10000; k++)
	    {
	    fprintf(fhout, "%04d%lc%lc%lc%lc0\n", k, essid[11], essid[12], essid[13], essid[14]);
	    }
	}
return;
}
/*===========================================================================*/
static void testpoda(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *poda = "PODA_";

if(podaflag == true) return;
if(essidlen < 5) return;
if(memcmp(essid, poda, 5) != 0) return;
for(k = 0; k < 1000000; k++) fprintf(fhout, "%06d%06d\n", k, k);
podaflag = true;
return;
}
/*===========================================================================*/
static void testroamingman(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1, k2, k3;
static char *ev;
static const char *roamingman =  "Roamingman_";

if(essidlen != 16) return;
if((!isdigit((unsigned char)essid[11])) || (!isdigit((unsigned char)essid[12])) || (!isdigit((unsigned char)essid[13])) || (!isdigit((unsigned char)essid[14])) || (!isdigit((unsigned char)essid[15]))) return;
if(memcmp(essid, roamingman, 11) != 0) return;
ev = (char*)(essid +11);
k2 = strtol(ev, NULL, 10);
for(k3 = k2 -10; k3 < k2 +10; k3++)
	{
	for(k1 = 0; k1 < 1000; k1++)
		{
		if(k3 < 0) fprintf(fhout, "%03d%05d\n", k1, k3 +100000);
		else if(k3 > 99999) fprintf(fhout, "%03d%05d\n", k1, k3 -100000);
		else fprintf(fhout, "%03d%05d\n", k1, k3);
		}
	}
return;
}
/*===========================================================================*/
static void testrtk(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *rtk = "RTK-";

if(essidlen == 10)
	{
	if((isxdigit((unsigned char)essid[4])) && (isxdigit((unsigned char)essid[5])) && (isxdigit((unsigned char)essid[6])) && (isxdigit((unsigned char)essid[7])) && (isxdigit((unsigned char)essid[8])) && (isxdigit((unsigned char)essid[9])))
		{
		if(memcmp(essid, rtk, 4) == 0)
			{
			for(k1 = 0; k1 < 0x100000; k1++)
				{
				fprintf(fhout, "454C54585C0%05X\n", k1);
				fprintf(fhout, "454C54585C1%05X\n", k1);
				fprintf(fhout, "53434F4D1A0%05X\n", k1);
				fprintf(fhout, "ELTX1A0%05X\n", k1);
				fprintf(fhout, "ELTX5C0%05X\n", k1);
				}
			}
		return;
		}
	}
return;
}
/*===========================================================================*/
static void testtechnicolor(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *tc8715d = "TC8715D";
static const char *tc8717t = "TC8717T";

if(essidlen >= 9)
	{
	if((!isxdigit((unsigned char)essid[7])) || (!isxdigit((unsigned char)essid[8]))) return;
	if(memcmp(essid, tc8715d, 7) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "TC8715D%04X%c%c\n", k1, essid[7], essid[8]);
		}
	if(memcmp(essid, tc8717t, 7) == 0)
		{
		for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "TC8717T%04X%c%c\n", k1, essid[7], essid[8]);
		}
	return;
	}
return;
}
/*===========================================================================*/
static void testtelered(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static uint32_t i;
static int c;
static const char *telered = "TeleRed-";

static uint32_t fix[] =
{
0x324b, 0x96e6, 0x9c67, 0xa266, 0xcfe2
};
#define FIX_SIZE sizeof(fix) /sizeof(int)

if(essidlen < 12) return;
if(memcmp(essid, telered, 8) != 0) return;
if((!isxdigit((unsigned char)essid[8])) || (!isxdigit((unsigned char)essid[9])) || (!isxdigit((unsigned char)essid[10])) || (!isxdigit((unsigned char)essid[11]))) return;

for(i = 0; i < FIX_SIZE; i++)
	{
	for(c = 0; c < 0x100; c++) fprintf(fhout, "%04X%02X%lc%lc%lc%lc\n", fix[i], c, essid[8], essid[9], essid[10], essid[11]);
	}
return;
}
/*===========================================================================*/
static void testukrtelecom(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *ukrtelekom = "UKrtelecom";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(ukrtelecomflag == true) return;
if(essidlen < 10) return;
if(memcmp(essid, ukrtelekom, 10) != 0) return;
for(k = 0; k < 10000; k++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "UKR_%04d", k);
		writepsk(fhout, essidtmp);
		}
ukrtelecomflag = true;
return;
}
/*===========================================================================*/
static void testwe(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;

if(essidlen != 8) return;
if(essid[0] != 'W') return;
if(essid[1] != 'E') return;
if(!isxdigit((unsigned char)essid[6])) return;
if(!isxdigit((unsigned char)essid[7])) return;
for(k1 = 0; k1 < 0x100000; k1++) fprintf(fhout, "%c%c0%05x\n", tolower(essid[6]), tolower(essid[7]), k1);
return;
}
/*===========================================================================*/
static void testwifirsu(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *wifirsu = "WiFiRSU_";

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if(essidlen < 10) return;
if(memcmp(essid, wifirsu, 8) != 0) return;
if(essidlen == 10)
	{
	if((!isxdigit((unsigned char)essid[8])) || (!isxdigit((unsigned char)essid[9]))) return;
	for(k1 = 0; k1 < 0x10000; k1++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "88%04x%c%c", k1, essid[8], essid[9]);
		writepsk(fhout, essidtmp);
		}
	return;
	}
if(essidlen == 13)
	{
	if((!isxdigit((unsigned char)essid[8])) || (!isxdigit((unsigned char)essid[9])) || (!isxdigit((unsigned char)essid[10])) || (!isxdigit((unsigned char)essid[11])) || (!isxdigit((unsigned char)essid[12]))) return;
	for(k1 = 0; k1 < 0x10; k1++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "88%x%c%c%c%c%c", k1, essid[8], essid[9], essid[10], essid[11], essid[12]);
		writepsk(fhout, essidtmp);
		}
	return;
	}
return;
}
/*===========================================================================*/
static void testwlan(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1, k2, k3, k4, k5, k6 ,k7 ,k8, k9;
static const char *wifirsu = "WLAN-";

static const char hextable[] = "0123456789ABCDEF";

if(essidlen != 11) return;
if(memcmp(essid, wifirsu, 5) != 0) return;
if((!isxdigit((unsigned char)essid[5])) || (!isxdigit((unsigned char)essid[6])) || (!isxdigit((unsigned char)essid[7])) || (!isxdigit((unsigned char)essid[8])) || (!isdigit((unsigned char)essid[9])) || (!isdigit((unsigned char)essid[10]))) return;
k1 = essid[9];
k2 = 0;
k3 = essid[10];
k4 = essid[8];
k5 = 0;
k6 = 0;
k7 = 0;
k8 = essid[6];
k9 = essid[7];
for(k2 = 0; k2 < 10; k2++)
	{
	for(k5 = 0; k5 <= 0xffff; k5++)
		{
		fprintf(fhout, "SP-%c%d%c%c%04X%d\n", k1, k2, k3, k4, k5, k2);
		fprintf(fhout, "SP%c%d%c%c%04X%d\n", k1, k2, k3, k4, k5, k2);
		}
	}
for(k2 = 0; k2 < 10; k2++)
	{
	for(k5 = 0; k5 <= 0x0f; k5++)
		{
		for(k6 = 0; k6 <= 0x0f; k6++)
			{
			for(k7 = 0; k7 < 100; k7++) fprintf(fhout, "%c%d%c%02d%02d%02d%02d%d%02d%02d\n", k1, k2, k3, k4, hextable[k5], hextable[k6], k7, k2, k8, k9);
			}
		}
	}
return;
}
/*===========================================================================*/
static void testx2g(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *x2g = "_2G";

if(essidlen < 9) return;
if(memcmp(&essid[essidlen -9], x2g, 2) != 0) return;
if((!isdigit((unsigned char)essid[essidlen -1])) || (!isdigit((unsigned char)essid[essidlen -2])) || (!isdigit((unsigned char)essid[essidlen -3])) || (!isdigit((unsigned char)essid[essidlen -4])) || (!isdigit((unsigned char)essid[essidlen -5])) || (!isdigit((unsigned char)essid[essidlen -6]))) return;
for(k = 0; k < 0x100; k++) fprintf(fhout, "%02X%s\n", k, &essid[essidlen -6]);
return;
}
/*===========================================================================*/
static void testzhone(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *zhone = "Zhone_";

if(znidflag == true) return;
if(essidlen < 6) return;
if(memcmp(essid, zhone, 6) != 0) return;
for(k = 0; k < 10000000; k++) fprintf(fhout, "znid30%07d\n", k);
for(k = 0; k < 10000000; k++) fprintf(fhout, "znid31%07d\n", k);
znidflag = true;
return;
}
/*===========================================================================*/
static void prepareessid(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int pi, po;
static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

if((essidlen == 0) || (essidlen > 32)) return;
testairtel(fhout, essidlen, essid);
testalcatellinkzone(fhout, essidlen, essid);
testarrisizzi(fhout, essidlen, essid);
testarristg(fhout, essidlen, essid);
testattwifi(fhout, essidlen, essid);
testaxtelxtremo(fhout, essidlen, essid);
testcabovisao(fhout, essidlen, essid);
testcg3000dv2(fhout, essidlen, essid);
testcpsrf(fhout, essidlen, essid);
testeasybox(fhout, essidlen, essid);
testglocal(fhout, essidlen, essid);
testhotbox(fhout, essidlen, essid);
testmtel(fhout, essidlen, essid);
testmywifi(fhout, essidlen, essid);
testnet2g(fhout, essidlen, essid);
testnetv(fhout, essidlen, essid);
testpoda(fhout, essidlen, essid);
testroamingman(fhout, essidlen, essid);
testrtk(fhout, essidlen, essid);
testtechnicolor(fhout, essidlen, essid);
testtelered(fhout, essidlen, essid);
testukrtelecom(fhout, essidlen, essid);
testwe(fhout, essidlen, essid);
testwifirsu(fhout, essidlen, essid);
testwlan(fhout, essidlen, essid);
testx2g(fhout, essidlen, essid);
testzhone(fhout, essidlen, essid);
if(noessidcombinationflag == true) return;
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

qsort(apessidliste, apessidcount, APESSIDLIST_SIZE, sort_apessidlist_by_essid);
zeiger = apessidliste;
if( apessidcount == 0) return;
essidglen = zeiger->essidlen;
prepareessid(fhout, zeiger->essidlen, zeiger->essid);
for(c = 1; c < apessidcount; c++)
	{
	if(zeiger->essidlen != (zeiger -1)->essidlen)
		{
		essidglen = zeiger->essidlen;
		prepareessid(fhout, zeiger->essidlen, zeiger->essid);
		}
	else if(memcmp(zeiger->essid, (zeiger -1)->essid, zeiger->essidlen) != 0)
		{
		essidglen = zeiger->essidlen;
		prepareessid(fhout, zeiger->essidlen, zeiger->essid);
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void writebssidmd5(FILE *fhout, unsigned long long int macaddr)
{
static int k;
static int p;
static unsigned int digestmd5len;
static EVP_MD_CTX* mdctx;
static char message[PSKSTRING_LEN_MAX];
static uint8_t digestmd5[EVP_MAX_MD_SIZE];

static char keystring[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

snprintf(message, 14, "%012llX", macaddr);
digestmd5len = 16;
mdctx = EVP_MD_CTX_create();
if(mdctx == NULL) return;
if(EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return;
	}
if(EVP_DigestUpdate(mdctx, message, 12) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return;
	}
if(EVP_DigestFinal_ex(mdctx, digestmd5, &digestmd5len) == 0)
	{
	EVP_MD_CTX_free(mdctx);
	return;
	}
EVP_MD_CTX_free(mdctx);

for (p = 0; p < 10; p++) fprintf(fhout, "%02x",digestmd5[p]);
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
fprintf(fhout, "%08d\n", pin);

pin = (((macaddr >> 24) &0xff) *256 *256) +(((macaddr >> 16) &0xff) *256) + ((macaddr >> 8) &0xff);
pin = pin % 10000000;
pin = ((pin * 10) + wpspinchecksum(pin));
fprintf(fhout, "%08d\n", pin);
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
static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

snprintf(pskstring, PSKSTRING_LEN_MAX, "0%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "2%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "m%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "555A5053%08llX", macaddr &0xffffffff);
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

snprintf(pskstring, PSKSTRING_LEN_MAX, "%011llx", (macaddr >> 4) &0xfffffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%010llx", (macaddr >> 8) &0xffffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%09llx",(macaddr >> 12) &0xfffffffff);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "%08llx", (macaddr >> 16) &0xffffffff);
writepsk(fhout, pskstring);

snprintf(pskstring, PSKSTRING_LEN_MAX, "%010lld", (macaddr) &0xffffff);
writepsk(fhout, pskstring);

writebssidmd5(fhout, macaddr);
writebssidwps(fhout, macaddr);
return;
}
/*===========================================================================*/
static void test000559(FILE *fhout, unsigned long long int macaddr)
{
static int k1;
static unsigned long long int oui;

static char essidtmp[PSKSTRING_LEN_MAX] = { 0 };

oui = macaddr &0xffffff000000L;
oui = oui >> 24;
if(oui == 0x000559)
	{
	for(k1 = 0; k1 < 10000; k1++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "%012llX-%04d", macaddr, k1);
		writepsk(fhout, essidtmp);
		}
	}
return;
}
/*===========================================================================*/
static void preparebssid(FILE *fhout, unsigned long long int macaddr)
{
static int c;
static unsigned long long int oui;
static unsigned long long int nic;
static unsigned int nici;
static int swap;
static int me;
static char pskstring[PSKSTRING_LEN_MAX] = { 0 };

fprintf(fhout, "%012llX\n", macaddr &0xffffffffff);

nici = macaddr &0xffffff;
fprintf(fhout, "SPN3983%06X\n", nici);

nici = ~macaddr &0xffffff;
fprintf(fhout, "wlan%06x\n", nici);

nici = ~macaddr &0xffffffff;
fprintf(fhout, "%08x\n", nici);

nici = (~macaddr >> 8) &0xffffffff;
fprintf(fhout, "%08x\n", nici);

for (c = 0x01; c < 0x10; c ++)
	{
	nici = ~(macaddr -c) &0xffffff;
	fprintf(fhout, "wlan%06x\n", nici);

	nici = ~(macaddr -c) &0xffffffff;
	fprintf(fhout, "%08x\n", nici);

	nici = ((~macaddr -c) >> 8) &0xffffffff;
	fprintf(fhout, "%08x\n", nici);
	}

me = macaddr &0xffffff;
fprintf(fhout, "05%6d\n", me);
oui = macaddr &0xffffff000000L;
nic = (macaddr -0x7f) &0xffffffL;
for(c = 0; c <= 0xff; c++) writebssid(fhout, oui +((nic +c) &0xffffffL));
if(oui == 0xccb171000000L)
	{
	for(c = 0; c <= 0xff; c++) fprintf(fhout, "CCB071%06llX\n", ((nic +c) &0xffffffL));
	}
swap = (nic >> 8) & 0xffff;
	{
	swap = (swap & 0xf000) >> 12 | (swap & 0x0f00) >> 4 | (swap & 0x00f0) << 4 | (swap & 0x000f) << 12;
	snprintf(pskstring, PSKSTRING_LEN_MAX, "000000%04X", swap);
	fprintf(fhout, "%s\n", pskstring);
	}
test000559(fhout, macaddr);
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
	if(c == 0) preparebssid(fhout, zeiger->macaddr);
	else
		{
		zeiger1 = zeiger -1;
		if(zeiger->macaddr != zeiger1->macaddr) preparebssid(fhout, zeiger->macaddr);
		}
	zeiger++;
	}
return;
}
/*===========================================================================*/
static void processadditionals(FILE *fhout)
{
if((eudateflag == true) || (usdateflag == true)) keywriteyearyear(fhout);
if(alticeoptimumflag == true) keywritealticeoptimum(fhout);
if(asusflag == true) keywriteasus(fhout);
if(digit10flag == true) keywritedigit10(fhout);
if(eeflag == true) keywriteee(fhout, false);
if(eeupperflag == true) keywriteee(fhout, true);
if(egnflag == true) keywriteegn(fhout);
if(eudateflag == true) keywriteeudate(fhout);
if(netgearflag == true) keywritenetgear(fhout);
if(phomeflag == true) keywritephome(fhout);
if(simpleflag == true) keywritesimple(fhout);
if(spectrumflag == true) keywritespectrum(fhout);
if(tendaflag == true) keywritetenda(fhout);
if(usdateflag == true) keywriteusdate(fhout);
if(weakpassflag == true) keywriteweakpass(fhout);
if(wpskeysflag == true) writewpsall(fhout);
return;
}
/*===========================================================================*/
/*===========================================================================*/
static void addapessid(uint64_t macaddr, uint8_t essidlen, uint8_t *essid)
{
static apessidl_t *zeiger;

if(essidlen > ESSID_LEN_MAX) return;
if(apessidliste == NULL)
	{
	apessidliste = (apessidl_t*)malloc(APESSIDLIST_SIZE);
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
if((zeiger->macaddr == macaddr) && (zeiger->essidlen == essidlen) && (memcmp(zeiger->essid, essid, essidlen) == 0)) return;
zeiger = (apessidl_t*)realloc(apessidliste, (apessidcount +1) *APESSIDLIST_SIZE);
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
static void readpmkidfile(char *pmkidname)
{
static int len;
static int aktread = 1;
static ssize_t essidlen;
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
	if((len = fgetline(fh_file, PMKID_LINE_LEN, linein)) == -1) break;
	if((len < 61) || ((len > 59 +(ESSID_LEN_MAX *2))))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if(((linein[32] != ':') && (linein[45] != ':') && (linein[58] != ':')) && ((linein[32] != '*') && (linein[45] != '*') && (linein[58] != '*')))
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
	if(hex2bin(&linein[59], essid, essidlen/2) != -1) addapessid(macaddr, essidlen/2, essid);
	aktread++;
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
static void readpmkideapolfile(char *pmkideapolname)
{
static int len;
static int aktread = 1;
static ssize_t essidlen;
static char *macaddrstop = NULL;
static char *essidstop = NULL;
static unsigned long long int macaddr;
static FILE *fh_file;

static const char hlid1[] = { "WPA*01*" };
static const char hlid2[] = { "WPA*02*" };

static char linein[PMKIDEAPOL_LINE_LEN];
static uint8_t essid[ESSID_LEN_MAX];

if((fh_file = fopen(pmkideapolname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", pmkideapolname);
	return;
	}
while(1)
	{
	if((len = fgetline(fh_file, PMKIDEAPOL_LINE_LEN, linein)) == -1) break;
	if(len < 68)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((memcmp(&hlid1, linein, 7) != 0) && (memcmp(&hlid2, linein, 7) != 0))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if((linein[3] != '*') && (linein[6] != '*') && (linein[39] != '*') && (linein[52] != '*') && (linein[65] != '*'))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	essidstop = strchr(&linein[66], '*');
	if(essidstop == NULL)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	essidlen = essidstop -linein -66;
	if((essidlen %2) != 0)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	macaddr = strtoull(linein +40, &macaddrstop, 16);
	if((macaddrstop -linein) != 52)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if(hex2bin(&linein[66], essid, essidlen/2) != -1) addapessid(macaddr, essidlen/2, essid);
	aktread++;
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
static int getwpapskfmt(int lenlinein, char *linein)
{
static int p;
static const char *johnformat = "$WPAPSK$";

for(p = 0; p < lenlinein -8; p++)
	{
	if(memcmp(&linein[p], johnformat, 8) == 0) return p;
	}
return 0;
}
/*===========================================================================*/
static void readjohnfile(char *johnname)
{
static int len;
static int aktread = 1;
static int essidlen;
static int macp;
static char *macaddrstop = NULL;
static unsigned long long int macaddr;
static FILE *fh_file;

static char linein[JOHN_LINE_LEN];

if((fh_file = fopen(johnname, "r")) == NULL)
	{
	fprintf(stderr, "opening hash file failed %s\n", johnname);
	return;
	}
while(1)
	{
	if((len = fgetline(fh_file, JOHN_LINE_LEN, linein)) == -1) break;
	if(len < 475)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	essidlen = getwpapskfmt(len, linein);
	if(essidlen == 0)
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	if(essidlen < 2)
		{
		aktread++;
		continue;
		}
	essidlen--;
	if(memcmp(linein, &linein[essidlen +9], essidlen) != 0)
		{
		aktread++;
		continue;
		}

	macp = (essidlen *2) +10;
	while((macp < essidlen) || (linein[macp] != ':'))
		{
		macp++;
		}

	if((linein[macp +18] != ':') || (linein[macp +36] != ':') || (linein[macp +49] != ':'))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}

	macaddr = strtoull(linein +macp +37, &macaddrstop, 16);
	if((macaddrstop -linein) != (macp +49))
		{
		fprintf(stderr, "reading hash line %d failed: %s\n", aktread, linein);
		aktread++;
		continue;
		}
	fprintf(stdout, "%llx %.*s\n", macaddr, essidlen,  linein);
	addapessid(macaddr, essidlen, (uint8_t*)linein);
	aktread++;
	}
fclose(fh_file);
return;
}
/*===========================================================================*/
static void readhccapxfile(char *hccapxname)
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
if((fhhcx = fopen(hccapxname, "r")) == NULL)
	{
	fprintf(stderr, "error opening file %s", hccapxname);
	return;
	}
hcxptr = (hccapx_t*)hcxdata;
while(fread(&hcxdata, HCCAPX_SIZE, 1, fhhcx) == 1)
	{
	if(hcxptr->signature != HCCAPX_SIGNATURE) continue;
	if((hcxptr->version != 3) && (hcxptr->version != 4)) continue;
	if(hcxptr->essid_len > ESSID_LEN_MAX) continue;
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
static void readcommandline(char *macapname, char *essidname)
{
static int essidlen = 0;
static ssize_t essidlenuh = 0;
static char *macaddrstop = NULL;
static unsigned long long int macaddr = 0xffffffffffffL;
static uint8_t essid[ESSID_LEN_MAX];

if(macapname != NULL)
	{
	macaddr = strtoull(macapname, &macaddrstop, 16);
	if((macaddrstop -macapname) != 12) fprintf(stderr, "invalid MAC specified\n");
	}
memset(&essid, 0, ESSID_LEN_MAX);
if(essidname != NULL)
	{
	essidlen = strlen(essidname);
	essidlenuh = ishexify(essidname);
	if((essidlenuh > 0) && (essidlenuh <= ESSID_LEN_MAX))
		{
		if(hex2bin(&essidname[5], essid, essidlenuh) != -1) addapessid(macaddr, essidlenuh, essid);
		return;
		}
	memset(&essid, 0, ESSID_LEN_MAX);
	if(essidlen <= ESSID_LEN_MAX) memcpy(&essid, essidname, essidlen);
	}
addapessid(macaddr, essidlen, essid);
return;
}
/*===========================================================================*/
__attribute__ ((noreturn))
static void version(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usage(char *eigenname)
{
fprintf(stdout, "%s %s (C) %s ZeroBeat\n"
	"usage:\n"
	"%s <options>\n"
	"\n"
	"options:\n"
	"-c <file>   : input PMKID/EAPOL hash file (hashcat -m 22000/22001)\n"
	"-i <file>   : input EAPOL hash file (hashcat -m 2500/2501)\n"
	"-j <file>   : input EAPOL hash file (john)\n"
	"-z <file>   : input PMKID hash file (hashcat -m 16800/16801 and john)\n"
	"-e <char>   : input ESSID\n"
	"-b <xdigit> : input MAC access point\n"
	"              format: 112233445566\n"
	"-o <file>   : output PSK file\n"
	"              default: stdout\n"
	"              output list must be sorted unique!\n"
	"-h          : show this help\n"
	"-v          : show version\n"
	"\n"
	"--maconly           : print only candidates based on ACCESS POINT MAC\n"
	"--noessidcombination: exclude ESSID combinations\n"
	"--netgear           : include weak NETGEAR / ORBI / NTGR_VMB / ARLO_VMB / FoxtelHub candidates\n"
	"--spectrum          : include weak MySpectrumWiFi / SpectrumSetup / MyCharterWiFi candidates\n"
	"                      list will be > 2.2GB\n"
	"--digit10           : include weak 10 digit candidates (INFINITUM, ALHN, INEA, VodafoneNet, VIVACOM)\n"
	"                      list will be > 1GB\n"
	"--phome             : include weak PEGATRON / Vantiva candidates (CBCI, HOME, [SP/XF]SETUP)\n"
	"                      list will be > 2.9GB\n"
	"--tenda             : include weak Tenda / NOVA / NOVE / BrosTrend candidates\n"
	"--ee                : include weak 5GHz-EE / BrightBox / EE / EE-BrightBox candidates\n"
	"                      list will be > 1.3GB\n"
	"--eeupper           : include weak EE-Hub candidates\n"
	"                      list will be > 3.8GB\n"
	"--alticeoptimum     : include weak Altice/Optimum candidates (MyAltice, MyOptimum)\n"
	"                      list will be > 4.6GB\n"
	"--asus              : include weak ASUS RT-AC candidates (ASUS_XX, RT-AC)\n"
	"--weakpass          : include weak password candidates\n"
	"--eudate            : include complete european dates\n"
	"--usdate            : include complete american dates\n"
	"--wpskeys           : include complete WPS keys\n"
	"--egn               : include Bulgarian EGN\n"
	"--simple            : include simple pattern\n"
	"--help              : show this help\n"
	"--version           : show version\n"
	"\n"
	"if hcxpsktool recovered your password, you should change it immediately!\n\n",
	eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
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
static FILE *fhpsk;

static char *pmkideapolname = NULL;
static char *hccapxname = NULL;
static char *johnname = NULL;
static char *pmkidname = NULL;
static char *essidname = NULL;
static char *macapname = NULL;
static char *pskname = NULL;

airtelflag = false;
alticeoptimumflag = false;
asusflag = false;
digit10flag = false;
easyboxflag = false;
eeflag = false;
egnflag = false;
eudateflag = false;
hb5flag = false;
maconlyflag = false;
netgearflag = false;
noessidcombinationflag = false;
phomeflag = false;
podaflag = false;
simpleflag = false;
spectrumflag = false;
tendaflag = false;
ukrtelecomflag = false;
usdateflag = false;
weakpassflag = false;
wpskeysflag = false;
znidflag = false;

static const char *short_options = "c:i:j:z:o:e:b:o:hv";
static const struct option long_options[] =
{
	{"alticeoptimum",		no_argument,		NULL,	HCXD_ALTICEOPTIMUM},
	{"asus",			no_argument,		NULL,	HCXD_ASUS},
	{"digit10",			no_argument,		NULL,	HCXD_DIGIT10},
	{"ee",				no_argument,		NULL,	HCXD_EE},
	{"eeupper",			no_argument,		NULL,	HCXD_EEUPPER},
	{"egn",				no_argument,		NULL,	HCXD_EGN},
	{"eudate",			no_argument,		NULL,	HCXD_EUDATE},
	{"maconly",			no_argument,		NULL,	HCXD_MACONLY},
	{"netgear",			no_argument,		NULL,	HCXD_NETGEAR},
	{"noessidcombination",		no_argument,		NULL,	HCXD_NOESSIDCOMBINATION},
	{"phome",			no_argument,		NULL,	HCXD_PHOME},
	{"simple",			no_argument,		NULL,	HCXD_SIMPLE},
	{"spectrum",			no_argument,		NULL,	HCXD_SPECTRUM},
	{"tenda",			no_argument,		NULL,	HCXD_TENDA},
	{"usdate",			no_argument,		NULL,	HCXD_USDATE},
	{"weakpass",			no_argument,		NULL,	HCXD_WEAKPASS},
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
		case HCXD_MACONLY:
		maconlyflag = true;
		break;

		case HCXD_NETGEAR:
		netgearflag = true;
		break;

		case HCXD_SPECTRUM:
		spectrumflag = true;
		break;

		case HCXD_NOESSIDCOMBINATION:
		noessidcombinationflag = true;
		break;

		case HCXD_DIGIT10:
		digit10flag = true;
		break;

		case HCXD_PHOME:
		phomeflag = true;
		break;

		case HCXD_TENDA:
		tendaflag = true;
		break;

		case HCXD_EE:
		eeflag = true;
		break;

		case HCXD_EEUPPER:
		eeupperflag = true;
		break;

		case HCXD_ALTICEOPTIMUM:
		alticeoptimumflag = true;
		break;

		case HCXD_ASUS:
		asusflag = true;
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

		case HCXD_EGN:
		egnflag = true;
		break;

		case HCXD_SIMPLE:
		simpleflag = true;
		break;

		case HCXD_HELP:
		usage(basename(argv[0]));
		break;

		case HCXD_VERSION:
		version(basename(argv[0]));
		break;

		case 'c':
		pmkideapolname = optarg;
		break;

		case 'i':
		hccapxname = optarg;
		break;

		case 'j':
		johnname = optarg;
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

if(argc < 2)
	{
	fprintf(stderr, "no option selected\n");
	return EXIT_SUCCESS;
	}

globalinit();

if((macapname != NULL) || (essidname != NULL))
	{
	readcommandline(macapname, essidname);
	}

if(pmkideapolname != NULL)
	{
	readpmkideapolfile(pmkideapolname);
	}

if(pmkidname != NULL)
	{
	readpmkidfile(pmkidname);
	}

if(hccapxname != NULL)
	{
	readhccapxfile(hccapxname);
	}

if(johnname != NULL)
	{
	readjohnfile(johnname);
	}

if(apessidliste == NULL)
	{
	fprintf(stderr, "no hashes loaded\n");
	}

if(pskname != NULL)
	{
	if((fhpsk = fopen(pskname, "w")) == NULL)
		{
		fprintf(stderr, "error opening psk file %s\n", pskname);
		exit(EXIT_FAILURE);
		}
	processbssids(fhpsk);
	if(maconlyflag == false)
		{
		processessids(fhpsk);
		processbssidsessids(fhpsk);
		processadditionals(fhpsk);
		}
	}
else
	{
	processbssids(stdout);
	if(maconlyflag == false)
		{
		processessids(stdout);
		processbssidsessids(stdout);
		processadditionals(stdout);
		}
	}

if(pskname != NULL)
	{
	fclose(fhpsk);
	}

EVP_cleanup();
CRYPTO_cleanup_all_ex_data();
ERR_free_strings();

return EXIT_SUCCESS;
}
/*===========================================================================*/

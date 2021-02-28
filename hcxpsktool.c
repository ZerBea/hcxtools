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
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>

#if defined(__APPLE__) || defined(__OpenBSD__)
#include <libgen.h>
#else
#include <stdio_ext.h>
#endif
#include "include/hcxpsktool.h"
#include "include/hashcatops.h"
#include "include/strings.c"
/*===========================================================================*/
/* global var */

static apessidl_t *apessidliste;
static int apessidcount;
static int thisyear;

static bool airtelflag;
static bool askeyarrisflag;
static bool digit10flag;
static bool easyboxflag;
static bool eeflag;
static bool egnflag;
static bool eudateflag;
static bool hb5flag;
static bool netgearflag;
static bool phomeflag;
static bool podaflag;
static bool tendaflag;
static bool ukrtelecomflag;
static bool usdateflag;
static bool weakpassflag;
static bool wpskeysflag;

uint8_t essidglen;
/*===========================================================================*/
static void globalinit()
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
static char lowerpskstring[PSKSTRING_LEN_MAX] = {};
static char upperpskstring[PSKSTRING_LEN_MAX] = {};

l = strlen(pskstring);
if((l < 8) || (l > PSKSTRING_LEN_MAX)) return;
for(p = 0; p < l; p++)
	{
	if(islower(pskstring[p]))
		{
		upperpskstring[p] = toupper(pskstring[p]);
		uflag = true;
		}
	else upperpskstring[p] = pskstring[p];
	if(isupper(pskstring[p]))
		{
		lowerpskstring[p] = tolower(pskstring[p]);
		lflag = true;
		}
	else lowerpskstring[p] = pskstring[p];
	}
fprintf(fhout,"%s\n", pskstring);
if(uflag == true) fprintf(fhout,"%s\n", upperpskstring);
if(lflag == true) fprintf(fhout,"%s\n", lowerpskstring);
if((lowerpskstring[0] >= 'a') && (lowerpskstring[0] <= 'z'))
	{
	lowerpskstring[0] = toupper(lowerpskstring[0]);
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

static char pskstring[PSKSTRING_LEN_MAX] = {};

static const char *firstword[] =
{ 
"ancient", "aquatic",
"basic", "black", "blue", "bold", "brave", "breezy", "bright",
"calm", "cheerful", "chummy", "classy", "clever", "cloudy", "cool", "crispy", "curly",
"daily", "deep", "delightful", "dizzy", "dynamic",
"elated", "elegant", "excited", "exotic",
"fancy", "fearless", "festive", "fluffy", "free", "fresh", "friendly", "fuzzy",
"gentle", "gifted", "gigantic", "graceful", "grand", "great", "green",
"happy", "heavy", "helpful", "hungry", "husky",
"icy", "imaginary",
"jagged", "jolly", "joyous",
"kind",
"large", "little", "lively", "lucky",
"magical", "manic", "melodic", "mighty", "misty", "modern",
"narrow", "new", "nifty", "noisy",
"odd", "orange",
"pastel", "perfect", "phobic", "pink", "polite", "precious", "purple",
"quaint", "quick", "quiet",
"rapid", "red", "rocky", "round", "royal", "rustic",
"shiny", "silent", "silky", "silly", "slow", "smiling", "smooth", "strong", "sunny", "sweet",
"thirsty", "thoughtful", "tiny",
"uneven", "unusual",
"vanilla", "vast",
"watery", "wide", "windy", "witty", "wonderful",
"yellow", "young",
"zany"
};

static const char *secondword[] =
{
"airplane", "apple",
"balloon", "banana", "berry", "bird", "boat", "bolt", "box", "brain", "breeze", "bug", "butter",
"canoe", "car", "carrot", "cartoon", "cello", "chair", "cheese", "coconut", "comet", "cream", "curtain",
"daisy", "diamond",
"earth", "ecasa", "elephant",
"finch", "fire", "fish", "flamingo", "flower", "flute",
"gadfly", "giant", "grasshopper",
"hat", "hill", "hippo",
"ink", "iris",
"jade", "jet", "jetcar", "jungle",
"kangaroo", "kayak",
"lake", "lightning", "lotus",
"mango", "mesa", "mint", "moon", "mountain",
"nest",
"oboe", "ocean", "octopus", "onion", "orchestra", "owl",
"panda", "phoenix", "piano", "pineapple", "planet", "plum", "pond", "poodle", "potato", "prairie",
"quail",
"rabbit", "raccoon", "raven", "river", "road", "rosebud",
"sea", "sheep", "ship", "shoe", "shrub", "skates", "sky", "snail", "socks", "sparrow", "spider", "squash",
"squirrel", "star", "street", "sun",
"table", "teapot", "tomato", "trail", "train", "tree", "trumpet", "tuba", "tulip", "turkey", 
"umbrella", "unicorn", "unit",
"valley", "vase", "violet", "violin",
"water", "wind", "window",
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
static void keywriteaskeyarris(FILE *fhout)
{
static size_t ca, cs;
static int cn;

static char pskstring[PSKSTRING_LEN_MAX] = {};

static const char *wordlist[] =
{ 
"absent", "absurd", "acre", "adorable", "advice", "agency", "ago", "airplane",
"album", "anchor", "ancient", "apple", "aquatic", "author", "away",
"bakery", "ball", "balloon", "banana", "barrel", "basic", "basket", "bench",
"berry", "better", "bike", "bird", "black", "blue", "boat", "bold",
"bolt", "book", "boot", "botany", "bowl", "box", "brain", "brave",
"bread", "breeze", "breezy", "brew", "bridge", "bright", "bubble", "bug",
"bunny", "butter",
"calm", "camera", "canoe", "car", "carrot", "cartoon", "cello", "chair",
"check", "cheerful", "cheese", "chilly", "chorus", "chummy", "city", "classy",
"clean", "clever", "clock", "cloudy", "clumsy", "coat", "coconut", "coffee",
"comet", "content", "cool", "country", "cow", "cream", "crispy", "crown",
"curly", "curtain",
"daily", "daisy", "damp", "darken", "data", "deep", "deer", "degree",
"desert", "desk", "diamond", "dirt", "dizzy", "dog", "doll", "domain",
"dusty", "duty", "dynamic",
"eager", "eagle", "earth", "easy", "elated", "elegant", "energy", "engine",
"epic", "errand", "event", "excited", "exotic",
"famous", "fancy", "farmer", "fast", "fearless", "festive", "field", "fight",
"finch", "finish", "fire", "fish", "fit", "flower", "fluent", "fluffy",
"flute", "formal", "free", "fresh", "friend", "fruit", "funny", "furry",
"fuzzy",
"gadfly", "gallon", "gate", "genius", "gentle", "giant", "giddy", "gifted",
"global", "gold", "goofy", "grain", "grand", "great", "green", "grumpy",
"guitar", "guppy",
"hall", "hand", "happy", "harbor", "hat", "hearty", "heavy", "height",
"helpful", "hill", "hippo", "honest", "honor", "horse", "hotel", "house",
"hungry", "husky",
"icy", "idea", "imaginary", "immune", "ink", "input", "invent", "iris",
"island",
"jacket", "jade", "jagged", "jazz", "jeans", "jet", "jewel", "jog",
"jolly", "joyous", "judge", "jungle",
"kayak", "kettle", "key", "kind", "kite", "knight",
"ladder", "lake", "large", "lawn", "lazy", "leader", "left", "lemon",
"light", "lion", "little", "lively", "long", "lotus", "loud", "loyal",
"lucky",
"magical", "major", "mango", "manic", "marble", "market", "mellow", "melodic",
"mesa", "mighty", "mint", "mirror", "misty", "mobile", "modern", "month",
"moon", "most", "museum",
"narrow", "nature", "nest", "new", "nifty", "noble", "noisy", "north",
"oasis", "object", "oboe", "ocean", "octopus", "odd", "olive", "onion",
"orange", "owl", "oxygen",
"palm", "panda", "pant", "parade", "park", "pastel", "patron", "pear",
"pencil", "perfect", "phobic", "phoenix", "phone", "piano", "pink", "plain",
"plane", "planet", "pledge", "plum", "pocket", "polite", "pond", "poodle",
"potato", "prairie", "praise", "precious", "prose", "proud", "puppy", "purple",
"quail", "quaint", "quick", "quiet", "quote",
"rabbit", "raccoon", "raft", "rain", "rainy", "rapid", "raven", "reason",
"red", "remedy", "review", "reward", "rich", "river", "road", "robin",
"rock", "rocket", "rocky", "role", "rose", "rosebud", "round", "royal",
"runner", "rustic",
"safety", "salute", "scary", "scout", "sea", "seed", "shark", "sheep",
"shelf", "shiny", "ship", "shirt", "shoe", "short", "shrub", "silent",
"silky", "silly", "silver", "skates", "sky", "sled", "sleepy", "slow",
"small", "smart", "smiley", "smiling", "smooth", "snail", "snake", "soccer",
"socks", "space", "spark", "sparrow", "spider", "spirit", "spoon", "square",
"squash", "squirrel", "stable", "star", "state", "statue", "stealth", "still",
"stove", "straw", "street", "strong", "studio", "summit", "sun", "sunny",
"super", "sweet", "swift",
"table", "tablet", "tall", "teal", "teapot", "tent", "terrific", "theory",
"think", "thirsty", "tiger", "timber", "tiny", "tomato", "topic", "town",
"trail", "train", "tree", "truck", "trumpet", "tuba", "tulip", "turkey",
"turtle",
"uneven", "unicorn", "union", "unit", "unite", "unusual", "urban", "useful",
"valley", "vanilla", "vase", "vast", "verse", "violet", "violin", "voyage",
"wagon", "walnut", "warm", "watch", "water", "way", "watery", "wealth",
"west", "whale", "wide", "wild", "wind", "window", "windy", "witty",
"wolf", "wonderful", "wooden", "world", "writer",
"yacht", "yard", "year", "yellow", "young",
"zany", "zeal", "zebra", "zone", "zoo"
};

for(ca = 0; ca < (sizeof(wordlist) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(wordlist) / sizeof(char *)); cs++)
		{
		if(ca == cs) continue;
		for (cn = 0; cn < 1000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%03d", wordlist[ca], wordlist[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(wordlist) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(wordlist) / sizeof(char *)); cs++)
		{
		if(ca == cs) continue;
		for (cn = 0; cn < 100; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%02d", wordlist[ca], wordlist[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(wordlist) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(wordlist) / sizeof(char *)); cs++)
		{
		if(ca == cs) continue;
		for (cn = 0; cn < 10; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%d", wordlist[ca], wordlist[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(wordlist) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(wordlist) / sizeof(char *)); cs++)
		{
		if(ca == cs) continue;
		snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s", wordlist[ca], wordlist[cs]);
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

static char pskstring[PSKSTRING_LEN_MAX] = {};

static const char *five[] =
{
"about", "again", "aisle", "alley", "amaze", "angle", "apron", "attic", "award",
"bacon", "badge", "bagel", "beard", "begin", "being", "berry", "bloom", "board", "bread", "brick", "bring",
"brush", "brook", "build", "built",
"cause", "chair", "charm", "chart", "charm", "chase", "check", "chime", "chord", "chore", "chose", "cough",
"class", "clear", "coast", "cough", "cover", "court", "creak", "curve",
"daily", "daisy", "dance", "diner", "dodge", "dough", "dozed", "drain", "drink",
"eager", "eagle", "earth", "eight", "elect", "empty", "enter", "equal", "event", "exact",
"fancy", "favor", "feast", "fence", "fever", "field", "fifty"
};

static const char *six[] =
{
"across", "action", "always", "amount", "animal", "answer", "anyone", "appear", "arctic", "autumn",
"basket", "become", "beside", "better", "bottle", "breezy", "bridge", "bright", "button",
"cactus", "called", "carpet", "camera", "candid", "canvas", "canyon", "castle", "cattle", "caught", "celery", "cellar",
"chance", "change", "charge", "cheery", "chores", "chosen", "circle", "cities", "collar", "column", "comedy", "copied",
"county", "create",
"degree", "depend", "design", "detail", "dimmed", "dinner", "direct",
"effect", "eighty", "eleven", "engine",
"factor", "famous", "filter", "finish", "flight", "flower", "follow", "forest",
"garden", "gather",
"harbor", "hardly", "health"
};

for(ca = 0; ca < (sizeof(five) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(six) / sizeof(char *)); cs++)
		{
		for (cn = 0; cn < 10000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%04d%s", five[ca], cn, six[cs]);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
for(ca = 0; ca < (sizeof(six) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(five) / sizeof(char *)); cs++)
		{
		for (cn = 0; cn < 10000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%04d%s", six[ca], cn, five[cs]);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
return;
}
/*===========================================================================*/
static void keywritetenda1(FILE *fhout)
{
static size_t ca, cs;
static int cn;

static char pskstring[PSKSTRING_LEN_MAX] = {};

static const char *word1[] = { "card", "cash",
	"feed",
	"jade",
	"name" };

static const char *word2[] = { "dash",
	"more",
	"ride",
	"think",
	"wind" };

for(ca = 0; ca < (sizeof(word1) / sizeof(char *)); ca++)
	{
	for(cs = 0; cs < (sizeof(word2) / sizeof(char *)); cs++)
		{
		for (cn = 0; cn < 1000; cn++)
			{
			snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%s%03d", word1[ca], word2[cs], cn);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}
return;
}
/*===========================================================================*/
static void keywritetenda2(FILE *fhout)
{
static size_t ca;
static int cn;

static char pskstring[PSKSTRING_LEN_MAX] = {};

static const char *word1[] = { "apple",
	"east",
	"give",
	"lable", "light",
	"north",
	"pace",
	"south",
	"west" };

for(ca = 0; ca < (sizeof(word1) / sizeof(char *)); ca++)
	{
	for (cn = 0; cn < 10000; cn++)
		{
		snprintf(pskstring, PSKSTRING_LEN_MAX, "%s%04d", word1[ca], cn);
		fprintf(fhout,"%s\n", pskstring);
		}
	}
return;
}
/*===========================================================================*/
static void keywriteee(FILE *fhout)
{
static size_t w3, w4, w5;

static char pskstring[15] = {};

char** uword3;
char** uword4;
char** uword5;

static const char *word3[] =
{
    "abs", "ace", "act", "add", "ado", "age", "ago", "aid", "ail", "aim", "all", "amp",
    "any", "ape", "apt", "art", "ask",
    "bad", "bay", "beg", "bet", "bid", "big", "bow", "box", "bud", "bun", "bus", "buy",
    "cad", "cam", "can", "cog", "cop", "cud", "cup", "cut",
    "dam", "did", "die", "dig", "dim", "dip", "dog", "dry", "dub", "due", "dug",
    "ear", "ego", "elk", "end", "era", "eye",
    "fab", "fan", "far", "fat", "fax", "fee", "few", "fit", "fix", "fly", "fog", "fox",
    "fry",
    "gap", "gel", "gem", "get", "god",
    "hem", "hid", "hip", "hit", "hop", "hot", "how", "hub",
    "icy", "ink", "inn",
    "jar", "job", "jog", "jot",
    "key",
    "lay", "led", "leg", "let", "lid", "lie", "lip", "lit", "lob", "lot", "low",
    "mad", "map", "max", "mid", "mix", "mob", "mop", "mow", "mud", "mug",
    "nag", "nap", "net", "new", "nod", "nor", "not", "now",
    "oar", "oat", "odd", "off", "oil", "old", "one", "opt", "our", "out", "owe", "own",
    "pal", "pay", "pea", "pen", "per", "pet", "pie", "pin", "ply", "pop", "pub", "put",
    "ran", "rat", "raw", "red", "rid", "rig", "rob", "rot", "run",
    "sad", "set", "sew", "shy", "sim", "sin", "sip", "sir", "sit", "six", "sow", "spy",
    "tad", "tag", "tap", "tax", "ten", "tic", "tip", "ton", "top", "tow", "toy", "try",
    "two",
    "use",
    "vex", "vow",
    "wet", "win", "won"
};

static const char *word4[] =
{
    "able", "acre", "aqua",
    "bait", "bake", "bald", "ball", "bark", "base", "bath", "bats", "bead", "bell", "best", "boat",
    "boil", "bold", "bore", "both", "busy",
    "calm", "camp", "cape", "card", "case", "cash", "cent", "chef", "city", "clad", "clay", "club",
    "clue", "coat", "cool", "cope", "copy", "cute",
    "dame", "damp", "dare", "dash", "date", "days", "deaf", "deal", "desk", "dive", "door", "dove",
    "down", "draw", "drop",
    "each", "east", "edge", "edit", "epic", "even", "ever", "exit",
    "face", "fair", "fake", "fall", "fast", "fine", "firm", "flag", "flee", "foam", "fold", "foot",
    "four", "full", "fuse",
    "gaps", "gate", "gave", "gift", "gown", "gray",
    "half", "hang", "hard", "hats", "head", "heat", "hide", "high", "hint", "hire", "hold", "hook",
    "huge", "hurt", "hymn",
    "idea", "iron",
    "jets", "joke", "judo",
    "keen", "kiss",
    "lace", "lack", "land", "late", "lawn", "lazy", "less", "link", "live", "loaf", "loan", "logo",
    "lord", "loss", "loud",
    "menu", "mill", "mine", "mint", "mist", "most", "move", "much",
    "name", "neat", "need", "nest", "noon", "nude",
    "oars", "oust",
    "pads", "page", "paid", "pain", "pale", "pane", "pars", "part", "pass", "past", "pear", "pegs",
    "pens", "pier", "pine", "pins", "pint", "pity", "plan", "poem", "poet", "pond", "pool", "poor",
    "post", "pure",
    "rare", "real", "rest", "rich", "riot", "ripe", "road", "roam", "room", "root", "rude",
    "safe", "sail", "sale", "same", "sand", "save", "scan", "seal", "seat", "seem", "send", "sent",
    "shin", "shop", "sick", "side", "sift", "sign", "silk", "sing", "skip", "slim", "slip", "slum",
    "soap", "solo", "sore", "sour", "spit", "stew", "sure",
    "tall", "teak", "team", "tear", "tent", "then", "tide", "time", "tone", "tour", "trim", "trod",
    "true", "tune", "turn",
    "used",
    "vain", "vast", "vend", "vote",
    "wait", "want", "warn", "wave", "west", "wild", "wind", "wing", "wise", "worm"
};

static const char *word5[] =
{
    "aback", "acres", "adapt", "agent", "agony", "ahead", "alarm", "alert", "alien", "allot", "amble", "angle",
    "ankle", "armed", "arrow", "audio",
    "beams", "bland", "blank", "boast", "boost", "bored", "bread", "broke",
    "cable", "cakes", "cards", "cargo", "cause", "chair", "cheap", "chips", "choke", "climb", "clove", "coact",
    "coins", "comic", "count", "cover", "crane", "crash", "crude", "cruel", "cubic", "curry",
    "dance", "dense", "desks", "diner", "dines", "dozen", "draft", "dream", "drink", "drown", "drunk", "dusty",
    "early", "elder", "enter", "equal", "equip", "erode", "evens", "event", "exact", "excel", "extra",
    "fancy", "fares", "fence", "fibre", "fifty", "filed", "files", "final", "floor", "flour", "flute", "focus",
    "foggy", "front", "fruit",
    "genie", "giant", "glare", "gleam", "glows", "grave", "great", "grids", "group", "grove", "guess", "guest",
    "harps", "hawks", "heavy", "house", "humor",
    "ideal", "index", "inked", "ivory",
    "judge",
    "knock",
    "laces", "large", "learn", "light", "lilac", "linen", "loose", "lucky", "lunar", "lyric",
    "madam", "major", "malts", "manor", "maple", "marry", "merit", "moist", "molar", "motto", "mourn", "mouse",
    "muddy",
    "nacho", "novel",
    "optic",
    "pages", "panda", "pause", "pedal", "pesto", "piece", "piety", "pings", "pious", "pivot", "place", "plant",
    "pound", "prime", "prize", "probe", "prose", "prune", "puppy", "pylon",
    "quiet",
    "rally", "refer", "remit", "renew", "repel", "roach", "rocky", "roofs", "rooks", "rough", "royal", "rusty",
    "salad", "scarf", "scoop", "scoot", "scope", "score", "scorn", "shaft", "sharp", "sheds", "shine", "shiny",
    "shirt", "shore", "shrub", "silly", "sixty", "skate", "socks", "sound", "spade", "spare", "spend", "spent",
    "squad", "stack", "stand", "stars", "start", "stats", "steam", "stick", "stoop", "storm", "story", "sunny",
    "sweat", "swift", "swing", "sword",
    "tally", "tempt", "tents", "these", "thick", "thief", "tidal", "tiger", "title", "today", "track", "train",
    "trick", "trust", "tuned", "twigs", "twist",
    "unbid", "unbox", "uncap", "upend", "upper", "upset",
    "valid", "vends", "vines", "visit",
    "weary", "wheel", "whole", "worth", "wound", "wrist",
    "yeast",
    "zooms"
};

uword3 = create_upper_array(word3, sizeof(word3) / sizeof(char *));
uword4 = create_upper_array(word4, sizeof(word4) / sizeof(char *));
uword5 = create_upper_array(word5, sizeof(word5) / sizeof(char *));

for(w3 = 0; w3 < (sizeof(word3) / sizeof(char *)); w3++)
	{
	for(w4 = 0; w4 < (sizeof(word4) / sizeof(char *)); w4++)
		{
		for(w5 = 0; w5 < (sizeof(word5) / sizeof(char *)); w5++)
			{
			snprintf(pskstring, 15, "%s-%s-%s",  word3[w3],  word4[w4],  word5[w5]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s", uword3[w3],  word4[w4],  word5[w5]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word3[w3], uword4[w4],  word5[w5]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word3[w3],  word4[w4], uword5[w5]);
			fprintf(fhout,"%s\n", pskstring);

			snprintf(pskstring, 15, "%s-%s-%s",  word3[w3],  word5[w5],  word4[w4]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s", uword3[w3],  word5[w5],  word4[w4]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word3[w3], uword5[w5],  word4[w4]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word3[w3],  word5[w5], uword4[w4]);
			fprintf(fhout,"%s\n", pskstring);

			snprintf(pskstring, 15, "%s-%s-%s",  word4[w4],  word3[w3],  word5[w5]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s", uword4[w4],  word3[w3],  word5[w5]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word4[w4], uword3[w3],  word5[w5]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word4[w4],  word3[w3], uword5[w5]);
			fprintf(fhout,"%s\n", pskstring);

			snprintf(pskstring, 15, "%s-%s-%s",  word4[w4],  word5[w5],  word3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s", uword4[w4],  word5[w5],  word3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word4[w4], uword5[w5],  word3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word4[w4],  word5[w5], uword3[w3]);
			fprintf(fhout,"%s\n", pskstring);

			snprintf(pskstring, 15, "%s-%s-%s",  word5[w5],  word3[w3],  word4[w4]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s", uword5[w5],  word3[w3],  word4[w4]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word5[w5], uword3[w3],  word4[w4]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word5[w5],  word3[w3], uword4[w4]);
			fprintf(fhout,"%s\n", pskstring);

			snprintf(pskstring, 15, "%s-%s-%s",  word5[w5],  word4[w4],  word3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s", uword5[w5],  word4[w4],  word3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word5[w5], uword4[w4],  word3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			snprintf(pskstring, 15, "%s-%s-%s",  word5[w5],  word4[w4], uword3[w3]);
			fprintf(fhout,"%s\n", pskstring);
			}
		}
	}

free_array(uword3, sizeof(word3) / sizeof(char *));
free_array(uword4, sizeof(word4) / sizeof(char *));
free_array(uword5, sizeof(word5) / sizeof(char *));

return;
}
/*===========================================================================*/
static void keywriteweakpass(FILE *fhout)
{
static size_t w;
static int y;

static char pskstring[PSKSTRING_LEN_MAX] = {};
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
static void keywriteeudate(FILE *fhout)
{
static int d ,m ,y;

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
static int d ,m ,y;

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
static void keywriteegn(FILE *fhout)
{
static int y, m, d, mc, i, j, c;
static char pskstring[PSKSTRING_LEN_MAX] = {};
static int w[] = {2, 4, 8, 5, 10, 9, 7, 3, 6};

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
	            } else {
	            if (d > 28) continue;
	            }
	        }
	        if ((m == 4 || m == 6 || m == 9 || m == 11) && d > 30) continue;

	        for (i = 0; i < 1000; i++)
	            {
	            snprintf(pskstring, PSKSTRING_LEN_MAX, "%02d%02d%02d%03d", y % 100, m + mc, d, i);
	            c = 0;
	            for (j = 0; j < 10; j++)
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

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen >= 4)
	{
	if((isxdigit(essid[essidlen -4])) && (isxdigit(essid[essidlen -3])) && (isxdigit(essid[essidlen -2])) && (isxdigit(essid[essidlen -1])))
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
static int c, d;
static char essidstring[PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX +PSKSTRING_LEN_MAX] = {};

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
writeessidadd(fhout, (char*)essid);
if(removeflag == true) writeessidadd(fhout, essidtmp);
return removeflag;
}
/*===========================================================================*/
static void writeessidsweeped(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int l1, l2;
static uint8_t sweepstring[PSKSTRING_LEN_MAX] = {};

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
static char *air = "Airtel_";

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
static char *ali = "Alcatel LINKZONE ";

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen != 21) return;
if(memcmp(essid, ali, 17) != 0) return;
if((!isdigit(essid[17])) || (!isdigit(essid[18])) || (!isdigit(essid[19])) || (!isdigit(essid[20]))) return;
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
static char *izzi = "IZZI-";

static int fixseed2[] =
{
0x001C15, 0x189C27, 0x3C0461, 0x509551, 0x704FB8, 0x8871B1, 0x8C61A3, 0x9CC8FC,
0xA811FC, 0xD4AB82, 0xF0AF85, 0xF82DC0, 0xF88B37, 0xF8F532, 0xFCAE34
};
#define FIXSEED2_SIZE sizeof(fixseed2) /sizeof(int)

if(essidlen < 9) return;
if(memcmp(essid, izzi, 5) != 0) return;
if((!isxdigit(essid[5])) || (!isxdigit(essid[6])) || (!isxdigit(essid[7])) || (!isxdigit(essid[8]))) return;
for(i = 0; i < FIXSEED2_SIZE; i++)
	{
	for(c = 0; c < 0x100; c++) fprintf(fhout, "%06X%02X%C%C%C%C\n", fixseed2[i], c, essid[5], essid[6], essid[7], essid[8]);
	}
return;
}
/*===========================================================================*/
static void testarristg(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static char *dg860A = "DG860A";
static char *tg852g = "TG852G";
static char *tg862g = "TG862G";
static char *dg1670A = "DG1670A";
static char *sbg6580 = "SBG6580";
static char *tg1672g = "TG1672G";

if(essidlen >= 8)
	{
	if((!isxdigit(essid[6])) || (!isxdigit(essid[7]))) return;
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
	if((!isxdigit(essid[7])) || (!isxdigit(essid[8]))) return;
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
static char *axtelxtremo = "AXTEL XTREMO-";

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen != 17) return;
if(memcmp(essid, axtelxtremo, 13) != 0) return;
if((!isxdigit(essid[13])) || (!isxdigit(essid[14])) || (!isxdigit(essid[15])) || (!isxdigit(essid[16]))) return;
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
static char *attwifi = "ATT-WIFI-";

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen != 13) return;
if(memcmp(essid, attwifi, 9) != 0) return;
if((!isdigit(essid[9])) || (!isdigit(essid[10])) || (!isdigit(essid[11])) || (!isdigit(essid[12]))) return;
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
static char *cabovisao = "Cabovisao-";

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen != 14) return;
if(memcmp(essid, cabovisao, 10) != 0) return;
if((!isxdigit(essid[10])) || (!isxdigit(essid[11])) || (!isxdigit(essid[12])) || (!isxdigit(essid[13]))) return;
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
static char *cg3000dv2 = "CG3000DV2";

if(essidlen < 11) return;
if(memcmp(essid, cg3000dv2, 9) != 0) return;
if((!isxdigit(essid[9])) || (!isxdigit(essid[10]))) return;
for(k1 = 0; k1 < 0x10000; k1++) fprintf(fhout, "CG3000DV2%04X%c%c\n", k1, essid[9], essid[10]);
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
if((!isxdigit(essid[8])) || (!isxdigit(essid[9])) || (!isxdigit(essid[10])) || (!isxdigit(essid[11])) || (!isdigit(essid[12])) || (!isdigit(essid[13]))) return;
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
if((!isdigit(essid[9])) || (!isdigit(essid[10])) || (!isdigit(essid[11])) || (!isdigit(essid[12])) || (!isdigit(essid[13]))) return;
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

static char essidtmp[PSKSTRING_LEN_MAX] = {};

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
if((!isxdigit(essid[7])) || (!isxdigit(essid[8])) || (!isxdigit(essid[9])) || (!isxdigit(essid[10]))) return;
ev = (char*)(essid +7);
k2 = strtol(ev, NULL, 16);
for(k1 = 0; k1 < 0x100; k1++)
	{
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "2ce412%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "4c17eb%02x%04x", k1, k2);
	writepsk(fhout, essidtmp);
	snprintf(essidtmp, PSKSTRING_LEN_MAX, "6c2e85%02x%04x", k1, k2);
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

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen == 7)
	{
	if(memcmp(essid, a1, 3) == 0)
		{
		if((isxdigit(essid[3])) && (isxdigit(essid[4])) && (isxdigit(essid[5])) && (isxdigit(essid[6])))
			{
			for(k1 = 0; k1 < 0x100; k1++)
				for(k2 = 0; k2 < 0x100; k2++)
					{
					snprintf(essidtmp, PSKSTRING_LEN_MAX, "48575443%02X%c%c%c%c%02X", k1, essid[3], essid[4], essid[5], essid[6], k2);
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
		if((isxdigit(essid[6])) && (isxdigit(essid[7])) && (isxdigit(essid[8])) && (isxdigit(essid[9])))
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

static char essidtmp[PSKSTRING_LEN_MAX] = {};

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

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen < 12) return;
if(memcmp(essid, net2g, 6) != 0) return;
if((isxdigit(essid[6])) && (isxdigit(essid[7])) && (isxdigit(essid[8])) && (isxdigit(essid[9])) && (isxdigit(essid[10])) && (isxdigit(essid[11])))
	{
	for(k = 0; k < 0x100; k++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "%02X%C%C%C%C%C%C", k, essid[6], essid[7], essid[8], essid[9], essid[10], essid[11]);
		writepsk(fhout, essidtmp);
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
if((!isdigit(essid[11])) || (!isdigit(essid[12])) || (!isdigit(essid[13])) || (!isdigit(essid[14])) || (!isdigit(essid[15]))) return;
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
static const char *rtk =  "RTK-";

if(essidlen == 10)
	{
	if((isxdigit(essid[4])) && (isxdigit(essid[5])) && (isxdigit(essid[6])) && (isxdigit(essid[7])) && (isxdigit(essid[8])) && (isxdigit(essid[9])))
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
static const char *tc8715d =  "TC8715D";
static const char *tc8717t =  "TC8717T";

if(essidlen >= 9)
	{
	if((!isxdigit(essid[7])) || (!isxdigit(essid[8]))) return;
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
if((!isxdigit(essid[8])) || (!isxdigit(essid[9])) || (!isxdigit(essid[10])) || (!isxdigit(essid[11]))) return;

for(i = 0; i < FIX_SIZE; i++)
	{
	for(c = 0; c < 0x100; c++) fprintf(fhout, "%04X%02X%C%C%C%C\n", fix[i], c, essid[8], essid[9], essid[10], essid[11]);
	}
return;
}
/*===========================================================================*/
static void testukrtelecom(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k;
static const char *ukrtelekom = "UKrtelecom";

static char essidtmp[PSKSTRING_LEN_MAX] = {};

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
static void testwifirsu(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int k1;
static const char *wifirsu = "WiFiRSU_";

static char essidtmp[PSKSTRING_LEN_MAX] = {};

if(essidlen < 10) return;
if(memcmp(essid, wifirsu, 8) != 0) return;
if(essidlen == 10)
	{
	if((!isxdigit(essid[8])) || (!isxdigit(essid[9]))) return;
	for(k1 = 0; k1 < 0x10000; k1++)
		{
		snprintf(essidtmp, PSKSTRING_LEN_MAX, "88%04x%c%c", k1, essid[8], essid[9]);
		writepsk(fhout, essidtmp);
		}
	return;
	}
if(essidlen == 13)
	{
	if((!isxdigit(essid[8])) || (!isxdigit(essid[9])) || (!isxdigit(essid[10])) || (!isxdigit(essid[11])) || (!isxdigit(essid[12]))) return;
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
if((!isxdigit(essid[5])) || (!isxdigit(essid[6])) || (!isxdigit(essid[7])) || (!isxdigit(essid[8])) || (!isdigit(essid[9])) || (!isdigit(essid[10]))) return;
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
			for(k7 = 0; k7 < 100; k7++)
				{
				fprintf(fhout, "%c%d%c%02d%02d%02d%02d%d%02d%02d\n", k1, k2, k3, k4, hextable[k5], hextable[k6], k7, k2, k8, k9);
				}
			}
		}
	}
return;
}
/*===========================================================================*/
static void prepareessid(FILE *fhout, uint8_t essidlen, uint8_t *essid)
{
static int pi, po;
static char essidtmp[PSKSTRING_LEN_MAX] = {};

if((essidlen == 0) || (essidlen > 32)) return;
testairtel(fhout, essidlen, essid);
testalcatellinkzone(fhout, essidlen, essid);
testarrisizzi(fhout, essidlen, essid);
testarristg(fhout, essidlen, essid);
testattwifi(fhout, essidlen, essid);
testaxtelxtremo(fhout, essidlen, essid);
testcabovisao(fhout, essidlen, essid);
testcg3000dv2(fhout, essidlen, essid);
testeasybox(fhout, essidlen, essid);
testglocal(fhout, essidlen, essid);
testhotbox(fhout, essidlen, essid);
testmtel(fhout, essidlen, essid);
testmywifi(fhout, essidlen, essid);
testnet2g(fhout, essidlen, essid);
testpoda(fhout, essidlen, essid);
testroamingman(fhout, essidlen, essid);
testrtk(fhout, essidlen, essid);
testtechnicolor(fhout, essidlen, essid);
testtelered(fhout, essidlen, essid);
testukrtelecom(fhout, essidlen, essid);
testwifirsu(fhout, essidlen, essid);
testwlan(fhout, essidlen, essid);

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
	essidglen = zeiger->essidlen;
	if(c == 0) prepareessid(fhout, zeiger->essidlen, zeiger->essid);
	else
		{
		zeiger1 = zeiger -1;
		if(zeiger->essidlen != zeiger1->essidlen)
			{
			if(memcmp(zeiger->essid, zeiger1->essid, zeiger->essidlen) != 0) prepareessid(fhout, zeiger->essidlen, zeiger->essid);
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
static char pskstring[PSKSTRING_LEN_MAX] = {};

snprintf(pskstring, PSKSTRING_LEN_MAX, "0%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "2%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "m%012llx", macaddr);
writepsk(fhout, pskstring);
snprintf(pskstring, PSKSTRING_LEN_MAX, "555A5053%08llx", macaddr &0xffffffff);
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

static char essidtmp[PSKSTRING_LEN_MAX] = {};

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
static int swap;

static char pskstring[PSKSTRING_LEN_MAX] = {};

oui = macaddr &0xffffff000000L;
nic = (macaddr &0xffffffL) -8;
for(c = 0; c < 0x10; c++) writebssid(fhout, oui +nic +c);
swap = (nic >> 8) & 0xffff;
	{
	swap = (swap & 0xf000) >> 12 | (swap & 0x0f00) >> 4 | (swap & 0x00f0) << 4 |  (swap & 0x000f) << 12;
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
if(netgearflag == true) keywritenetgear(fhout);
if(askeyarrisflag == true) keywriteaskeyarris(fhout);
if(digit10flag == true) keywritedigit10(fhout);
if(phomeflag == true) keywritephome(fhout);
if(tendaflag == true)
	{
	keywritetenda1(fhout);
	keywritetenda2(fhout);
	}
if(eeflag == true) keywriteee(fhout);
if(weakpassflag == true) keywriteweakpass(fhout);
if(eudateflag == true) keywriteeudate(fhout);
if(usdateflag == true) keywriteusdate(fhout);
if((eudateflag == true) || (usdateflag == true)) keywriteyearyear(fhout);
if(wpskeysflag == true) writewpsall(fhout);
if(egnflag == true) keywriteegn(fhout);
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
if((zeiger->macaddr == macaddr) && (zeiger->essidlen == essidlen) && (memcmp(zeiger->essid, essid, essidlen) == 0)) return;
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
static int fgetline(FILE *inputstream, size_t size, char *buffer)
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
static void readpmkidfile(char *pmkidname)
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
	if(hex2bin(&linein[59], essid, essidlen/2) == true) addapessid(macaddr, essidlen/2, essid);
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
static int essidlen;
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
	if(hex2bin(&linein[66], essid, essidlen/2) == true) addapessid(macaddr, essidlen/2, essid);
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
	printf("%llx %.*s\n", macaddr, essidlen,  linein);
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
if((fhhcx = fopen(hccapxname, "rb")) == NULL)
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
static int essidlenuh = 0;
static char *macaddrstop = NULL;
static unsigned long long int macaddr = 0xffffffffffffL;
static uint8_t essid[ESSID_LEN_MAX];

if(macapname != NULL)
	{
	macaddr = strtoull(macapname, &macaddrstop, 16);
	if((macaddrstop -macapname) != 12) fprintf(stderr, "invalid MAC specified\n");
	}

memset(&essid, 0, ESSID_LEN_MAX);
essidlen = strlen(essidname);
if(essidname != NULL)
	{
	essidlenuh = ishexify(essidname);
	if((essidlenuh > 0) && (essidlenuh <= ESSID_LEN_MAX))
		{
		if(hex2bin(&essidname[5], essid, essidlenuh) == true) addapessid(macaddr, essidlenuh, essid);
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
printf("%s %s (C) %s ZeroBeat\n", eigenname, VERSION_TAG, VERSION_YEAR);
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
	"-c <file>   : input PMKID/EAPOL hash file (hashcat -m 22000)\n"
	"-i <file>   : input EAPOL hash file (hashcat)\n"
	"-j <file>   : input EAPOL hash file (john)\n"
	"-z <file>   : input PMKID hash file (hashcat and john)\n"
	"-e <char>   : input ESSID\n"
	"-b <xdigit> : input MAC access point\n"
	"              format: 112233445566\n"
	"-o <file>   : output PSK file\n"
	"              default: stdout\n"
	"              output list must be sorted unique!\n"
	"-h          : show this help\n"
	"-v          : show version\n"
	"\n"
	"--netgear     : include weak NETGEAR / ORBI / NTGR_VMB candidates\n"
	"--askeyarris  : include weak MySpectrumWiFI / SpectrumSetup / MyCharterWiFI candidates\n"
	"                list will be > 3GB\n"
	"--digit10     : include weak 10 digit candidates (INFINITUM, ALHN, INEA, VodafoneNet, VIVACOM)\n"
	"                list will be > 1GB\n"
	"--phome       : include weak PEGATRON HOME candidates\n"
	"--tenda       : include weak TENDA candidates\n"
	"--ee          : include weak EE BrightBox candidates\n"
	"                list will be > 3GB\n"
	"--weakpass    : include weak password candidates\n"
	"--eudate      : include complete european dates\n"
	"--usdate      : include complete american dates\n"
	"--wpskeys     : include complete WPS keys\n"
	"--egn         : include Bulgarian EGN\n"
	"--help        : show this help\n"
	"--version     : show version\n"
	"\n"
	"if hcxpsktool recovered your password, you should change it immediately!\n"
	"\n"
	"examples:\n"
	"hcxpsktool -i hashfile.hccapx | sort | uniq | hashcat -m 2500 hashfile.hccapx\n"
	"hcxpsktool -z hashfile.16800 | sort | uniq | hashcat -m 16800 hashfile.16800\n"
	"hcxpsktool -z hashfile.16800 | sort | uniq | john --stdin --format=wpapsk-opencl hashfile.16800\n"
	"\n", eigenname, VERSION_TAG, VERSION_YEAR, eigenname);
exit(EXIT_SUCCESS);
}
/*---------------------------------------------------------------------------*/
__attribute__ ((noreturn))
static void usageerror(char *eigenname)
{
printf("%s %s (C) %s by ZeroBeat\n"
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
askeyarrisflag = false;
digit10flag = false;
easyboxflag = false;
eeflag = false;
egnflag = false;
eudateflag = false;
hb5flag = false;
netgearflag = false;
phomeflag = false;
podaflag = false;
tendaflag = false;
ukrtelecomflag = false;
usdateflag = false;
weakpassflag = false;
wpskeysflag = false;

static const char *short_options = "c:i:j:z:o:e:b:o:hv";
static const struct option long_options[] =
{
	{"netgear",			no_argument,		NULL,	HCXD_NETGEAR},
	{"askeyarris",			no_argument,		NULL,	HCXD_ASKEYARRIS},
	{"digit10",			no_argument,		NULL,	HCXD_DIGIT10},
	{"phome",			no_argument,		NULL,	HCXD_PHOME},
	{"tenda",			no_argument,		NULL,	HCXD_TENDA},
	{"ee",				no_argument,		NULL,	HCXD_EE},
	{"weakpass",			no_argument,		NULL,	HCXD_WEAKPASS},
	{"eudate",			no_argument,		NULL,	HCXD_EUDATE},
	{"usdate",			no_argument,		NULL,	HCXD_USDATE},
	{"wpskeys",			no_argument,		NULL,	HCXD_WPSKEYS},
	{"egn",				no_argument,		NULL,	HCXD_EGN},
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

		case HCXD_ASKEYARRIS:
		askeyarrisflag = true;
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
	processessids(fhpsk);
	processbssidsessids(fhpsk);
	processadditionals(fhpsk);
	}
else
	{
	processbssids(stdout);
	processessids(stdout);
	processbssidsessids(stdout);
	processadditionals(stdout);
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

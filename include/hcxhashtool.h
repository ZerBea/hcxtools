#define OUILIST_MAX		50000
#define OUI_LINE_LEN		50000

#define HCX_TYPE_PMKID		1
#define HCX_TYPE_EAPOL		2

#define ESSID_LEN_MIN 		0
#define ESSID_LEN_MAX 		32
#define EAPOL_AUTHLEN_MAX	256

#define PMKIDEAPOL_LINE_LEN	1024
#define PMKIDEAPOL_BUFFER_LEN	1024
#define HASHLIST_MAX		50000

#define HCX_HASH_TYPE			1
#define HCX_HASH_MIN			2
#define HCX_HASH_MAX			3
#define HCX_ESSID_GROUP			4
#define HCX_ESSID_LEN			5
#define HCX_ESSID_MIN			6
#define HCX_ESSID_MAX			7
#define HCX_FILTER_ESSID_LIST_IN	8
#define HCX_MAC_GROUP_AP		9
#define HCX_MAC_GROUP_CLIENT		10
#define HCX_OUI_GROUP			11
#define HCX_FILTER_OUI_AP		12
#define HCX_FILTER_OUI_CLIENT		13
#define HCX_FILTER_MAC_AP		14
#define HCX_FILTER_MAC_CLIENT		15
#define HCX_FILTER_MAC_LIST_IN		16
#define HCX_FILTER_VENDOR		17
#define HCX_FILTER_ESSID		18
#define HCX_FILTER_ESSID_PART		19
#define HCX_FILTER_RC			20
#define HCX_FILTER_M12			21
#define HCX_FILTER_M1234		22
#define HCX_FILTER_M1M2ROGUE		23
#define HCX_PSK				24
#define HCX_PMK				25
#define HCX_VENDOR_OUT			26
#define HCX_INFO_OUT			27
#define HCX_HCCAPX_OUT			28
#define HCX_HCCAP_OUT			29
#define HCX_HCCAP_SINGLE_OUT		30
#define HCX_JOHN_OUT			31
#define HCX_PMKIDEAPOL_IN		'i'
#define HCX_PMKIDEAPOL_OUT		'o'
#define HCX_ESSID_OUT			'E'
#define HCX_DOWNLOAD_OUI		'd'
#define HCX_HELP			'h'
#define HCX_VERSION			'v'
/*===========================================================================*/
/*===========================================================================*/
struct hashlist_s
{
 uint8_t		type;
#define HS_PMKID	1;
#define HS_EAPOL	2;
 uint8_t		hash[16];
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
 uint8_t		nonce[32];
 uint16_t		eapauthlen;
 uint8_t		eapol[EAPOL_AUTHLEN_MAX];
 uint8_t		mp;
};
typedef struct hashlist_s hashlist_t;
#define	HASHLIST_SIZE (sizeof(hashlist_t))

static int sort_maclist_by_essid(const void *a, const void *b)
{
const hashlist_t *ia = (const hashlist_t *)a;
const hashlist_t *ib = (const hashlist_t *)b;

if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0) return -1;
return 0;
}

static int sort_maclist_by_essidlen(const void *a, const void *b)
{
const hashlist_t *ia = (const hashlist_t *)a;
const hashlist_t *ib = (const hashlist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ia->essidlen) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ia->essidlen) < 0) return -1;
return 0;
}

static int sort_maclist_by_macap(const void *a, const void *b)
{
const hashlist_t *ia = (const hashlist_t *)a;
const hashlist_t *ib = (const hashlist_t *)b;

if(memcmp(ia->ap, ib->ap, 6) > 0) return 1;
else if(memcmp(ia->ap, ib->ap, 6) < 0) return -1;
return 0;
}

static int sort_maclist_by_macclient(const void *a, const void *b)
{
const hashlist_t *ia = (const hashlist_t *)a;
const hashlist_t *ib = (const hashlist_t *)b;

if(memcmp(ia->client, ib->client, 6) > 0) return 1;
else if(memcmp(ia->client, ib->client, 6) < 0) return -1;
return 0;
}
/*===========================================================================*/
struct ouilist_s
{
 uint8_t		oui[3];
#define VENDOR_LEN_MAX	128
 char			vendor[VENDOR_LEN_MAX];
};
typedef struct ouilist_s ouilist_t;
#define	OUILIST_SIZE (sizeof(ouilist_t))

static int sort_ouilist_by_oui(const void *a, const void *b)
{
const ouilist_t *ia = (const ouilist_t *)a;
const ouilist_t *ib = (const ouilist_t *)b;

if(memcmp(ia->oui, ib->oui, 3) > 0) return 1;
else if(memcmp(ia->oui, ib->oui, 3) < 0) return -1;
return 0;
}
/*===========================================================================*/
struct essidlist_s
{
 int		essidlen;
 uint8_t	essid[ESSID_LEN_MAX];
};
typedef struct essidlist_s essidlist_t;
#define	ESSIDLIST_SIZE (sizeof(essidlist_t))

static int sort_essidlistin(const void *a, const void *b)
{
const essidlist_t *ia = (const essidlist_t *)a;
const essidlist_t *ib = (const essidlist_t *)b;

if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
if(memcmp(ia->essid, ib->essid, ia->essidlen) > 0) return 1;
else if(memcmp(ia->essid, ib->essid, ia->essidlen) < 0) return -1;
return 0;
}
/*===========================================================================*/
struct maclist_s
{
 uint8_t	mac[6];
};
typedef struct maclist_s maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclistin(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;

if(memcmp(ia->mac, ib->mac, 6) > 0) return 1;
else if(memcmp(ia->mac, ib->mac, 6) < 0) return -1;
return 0;
}
/*===========================================================================*/





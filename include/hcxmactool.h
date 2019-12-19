#define HCX_TYPE_PMKID		1
#define HCX_TYPE_EAPOL		2

#define ESSID_LEN_MAX 		32
#define PMKID_LINE_LEN		128
#define OUI_LINE_LEN		128

#define HCXD_PMKIDEAPOL_OUT	1
#define HCXD_PMKID_IN		2
#define HCXD_PMKID_OUT		3
#define HCXD_HCCAPX_IN		4
#define HCXD_HCCAPX_OUT		5

#define HCXD_FILTER_OUI_AP	'o'
#define HCXD_FILTER_NIC_AP	'n'
#define HCXD_FILTER_MAC_AP	'm'
#define HCXD_FILTER_VENDOR_AP	'a'

#define HCXD_FILTER_OUI_STA	'O'
#define HCXD_FILTER_NIC_STA	'N'
#define HCXD_FILTER_MAC_STA	'M'
#define HCXD_FILTER_VENDOR_STA	'A'

#define HCXD_HELP		'h'
#define HCXD_VERSION		'v'

/*===========================================================================*/
struct intoui_s
{
 uint8_t	oui[3];
 char		vendor[OUI_LINE_LEN];
} __attribute__((__packed__));
typedef struct intoui_s intoui_t;
#define	INTOUI_SIZE (sizeof(intoui_t))

static int sort_intoui_by_oui(const void *a, const void *b)
{
const intoui_t *ia = (const intoui_t *)a;
const intoui_t *ib = (const intoui_t *)b;

if(memcmp(ia->oui, ib->oui, 3) > 0)
	return 1;
else if(memcmp(ia->oui, ib->oui, 6) < 0)
	return -1;
if(memcmp(ia->vendor, ib->vendor, OUI_LINE_LEN) > 0)
	return 1;
else if(memcmp(ia->vendor, ib->vendor, OUI_LINE_LEN) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct intpmkid_s
{
 uint8_t	macap[6];
 uint8_t	macsta[6];
 uint8_t	pmkid[16];
 uint8_t	essidlen;
 uint8_t	essid[ESSID_LEN_MAX];
} __attribute__((__packed__));
typedef struct intpmkid_s intpmkid_t;
#define	INTPMKID_SIZE (sizeof(intpmkid_t))
/*===========================================================================*/
static int sort_intpmkid_by_macap(const void *a, const void *b)
{
const intpmkid_t *ia = (const intpmkid_t *)a;
const intpmkid_t *ib = (const intpmkid_t *)b;

if(memcmp(ia->macap, ib->macap, 6) > 0)
	return 1;
else if(memcmp(ia->macap, ib->macap, 6) < 0)
	return -1;
if(memcmp(ia->macsta, ib->macsta, 6) > 0)
	return 1;
else if(memcmp(ia->macsta, ib->macsta, 6) < 0)
	return -1;
if(ia->essidlen > ib->essidlen)
	return 1;
else if(ia->essidlen < ib->essidlen)
	return -1;
if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct inthccapx_s
{
 uint32_t	signature;
#define HCCAPX_SIGNATURE 0x58504348
 uint32_t	version;
#define HCCAPX_VERSION 4
 uint8_t	message_pair;
 uint8_t	essidlen;
 uint8_t	essid[32];
 uint8_t	keyver;
 uint8_t	keymic[16];
 uint8_t	macap[6];
 uint8_t	nonceap[32];
 uint8_t	macsta[6];
 uint8_t	noncesta[32];
 uint16_t	eapollen;
 uint8_t	eapol[256];
} __attribute__((packed));
typedef struct inthccapx_s inthccapx_t;
#define	INTHCCAPX_SIZE (sizeof(inthccapx_t))
/*===========================================================================*/
static int sort_inthccapx_by_macap(const void *a, const void *b)
{
const inthccapx_t *ia = (const inthccapx_t *)a;
const inthccapx_t *ib = (const inthccapx_t *)b;

if(memcmp(ia->macap, ib->macap, 6) > 0)
	return 1;
else if(memcmp(ia->macap, ib->macap, 6) < 0)
	return -1;
if(memcmp(ia->macsta, ib->macsta, 6) > 0)
	return 1;
else if(memcmp(ia->macsta, ib->macsta, 6) < 0)
	return -1;
if(ia->essidlen > ib->essidlen)
	return 1;
else if(ia->essidlen < ib->essidlen)
	return -1;
if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0)
	return -1;
return 0;
}
/*===========================================================================*/





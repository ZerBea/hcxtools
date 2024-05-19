#define ESSID_LEN_MAX 32
#define PMKID_LINE_LEN 255
#define PMKIDEAPOL_LINE_LEN 1024
#define JOHN_LINE_LEN 1024
#define PSKSTRING_LEN_MAX 64

#define HCXD_ALTICEOPTIMUM		1
#define HCXD_ASUS			2
#define HCXD_DIGIT10			3
#define HCXD_EE				4
#define HCXD_EEUPPER			5
#define HCXD_EGN			6
#define HCXD_EUDATE			7
#define HCXD_MACONLY			8
#define HCXD_NETGEAR			9
#define HCXD_NOESSIDCOMBINATION		10
#define HCXD_PHOME			11
#define HCXD_SIMPLE			12
#define HCXD_SPECTRUM			13
#define HCXD_TENDA			14
#define HCXD_USDATE			15
#define HCXD_WEAKPASS			16
#define HCXD_WPSKEYS			17
#define HCXD_HELP			'h'
#define HCXD_VERSION			'v'

#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif
#else
#ifdef __OpenBSD__
# include <endian.h>
# if BYTE_ORDER == BIG_ENDIAN
#   define BIG_ENDIAN_HOST
# endif
#endif
#endif

/*===========================================================================*/
struct apessidlist_s
{
 uint8_t	status;
 unsigned long long int	macaddr;
 uint8_t	essidlen;
 uint8_t	essid[ESSID_LEN_MAX];
} __attribute__((__packed__));
typedef struct apessidlist_s apessidl_t;
#define	APESSIDLIST_SIZE (sizeof(apessidl_t))
/*===========================================================================*/
static int sort_apessidlist_by_ap(const void *a, const void *b)
{
const apessidl_t *ia = (const apessidl_t *)a;
const apessidl_t *ib = (const apessidl_t *)b;
int cmp;

if(ia->macaddr > ib->macaddr)
	return 1;
if(ia->macaddr < ib->macaddr)
	return -1;
cmp = memcmp(ia->essid, ib->essid, ESSID_LEN_MAX);
if(cmp > 0)
	return 1;
else if(cmp < 0)
	return -1;

return 0;
}
/*===========================================================================*/
static int sort_apessidlist_by_essid(const void *a, const void *b)
{
const apessidl_t *ia = (const apessidl_t *)a;
const apessidl_t *ib = (const apessidl_t *)b;
int cmp;

cmp = memcmp(ia->essid, ib->essid, ESSID_LEN_MAX);
if(cmp > 0)
	return 1;
else if(cmp < 0)
	return -1;
if(ia->macaddr > ib->macaddr)
	return 1;
if(ia->macaddr < ib->macaddr)
	return -1;
return 0;
}
/*===========================================================================*/

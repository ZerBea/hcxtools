#define ESSID_LEN_MAX 		32
#define PMKID_LINE_LEN		128

#define HCXD_PMKID1			1
#define HCXD_PMKID2			2
#define HCXD_WRITE_PMKID12		3
#define HCXD_WRITE_PMKID1		4
#define HCXD_WRITE_PMKID2		5
#define HCXD_WRITE_PMKID		6
#define HCXD_WRITE_PMKID_GROUP		7
#define HCXD_HCCAPX1			8
#define HCXD_HCCAPX2			9
#define HCXD_WRITE_HCCAPX12		10
#define HCXD_WRITE_HCCAPX1		11
#define HCXD_WRITE_HCCAPX2		12
#define HCXD_WRITE_HCCAPX		13
#define HCXD_WRITE_HCCAPX_GROUP		14
#define HCXD_WRITE_ESSIDLIST		15
#define HCXD_WRITE_ESSID_MACAP_LIST	16

#define HCXD_ESSID		'e'
#define HCXD_ESSID_PART		'E'
#define HCXD_ESSID_LEN		'l'

#define HCXD_HELP		'h'
#define HCXD_VERSION		'v'

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
static int sort_intpmkid_by_essid(const void *a, const void *b)
{
const intpmkid_t *ia = (const intpmkid_t *)a;
const intpmkid_t *ib = (const intpmkid_t *)b;

if(ia->essidlen > ib->essidlen)
	return 1;
else if(ia->essidlen < ib->essidlen)
	return -1;
if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0)
	return -1;
if(memcmp(ia->macap, ib->macap, 6) > 0)
	return 1;
else if(memcmp(ia->macap, ib->macap, 6) < 0)
	return -1;
if(memcmp(ia->macsta, ib->macsta, 6) > 0)
	return 1;
else if(memcmp(ia->macsta, ib->macsta, 6) < 0)
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
static int sort_inthccapx_by_essid(const void *a, const void *b)
{
const inthccapx_t *ia = (const inthccapx_t *)a;
const inthccapx_t *ib = (const inthccapx_t *)b;

if(ia->essidlen > ib->essidlen)
	return 1;
else if(ia->essidlen < ib->essidlen)
	return -1;
if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, ESSID_LEN_MAX) < 0)
	return -1;
if(memcmp(ia->macap, ib->macap, 6) > 0)
	return 1;
else if(memcmp(ia->macap, ib->macap, 6) < 0)
	return -1;
if(memcmp(ia->macsta, ib->macsta, 6) > 0)
	return 1;
else if(memcmp(ia->macsta, ib->macsta, 6) < 0)
	return -1;
return 0;
}
/*===========================================================================*/





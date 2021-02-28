#define HCX_HASHLINE	'i'
#define HCX_ESSID	'e'
#define HCX_PSK		'p'
#define HCX_PMK		'm'

#define HCX_HELP	'h'
#define HCX_VERSION	'v'

#define ESSID_LEN_MAX		32
#define EAPOL_AUTHLEN_MAX	256
#define PMK_LEN			32
#define HASH_LEN		16
/*===========================================================================*/
typedef struct
{
 uint8_t		type;
#define HS_PMKID	1
#define HS_EAPOL	2
 uint8_t		hash[HASH_LEN];
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
 uint8_t		nonce[32];
 uint16_t		eapauthlen;
 uint8_t		eapol[EAPOL_AUTHLEN_MAX];
 uint8_t		mp;
} hashlist_t;
#define	HASHLIST_SIZE (sizeof(hashlist_t))
/*===========================================================================*/

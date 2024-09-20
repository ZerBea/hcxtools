#define HCX_EAPOL_TIMEOUT			1
#define HCX_NC					2
#define HCX_IE					3
#define HCX_CONVERT_ALL				4
#define HCX_ESSIDS				5
#define HCX_EAPMD5_OUT				6
#define HCX_EAPLEAP_OUT				7
#define HCX_EAPMD5_JOHN_OUT			8
#define HCX_TACACSP_OUT				9
#define HCX_NMEA_OUT				10
#define HCX_CSV_OUT				11
#define HCX_RAW_OUT				12
#define HCX_RAW_IN				13
#define HCX_LTS					14
#define HCX_LOG_OUT				15
#define HCX_PMKID_CLIENT_OUT			16
#define HCX_PMKID_OUT_DEPRECATED		17
#define HCX_HCCAPX_OUT_DEPRECATED		18
#define HCX_HCCAP_OUT_DEPRECATED		19
#define HCX_PMKIDEAPOLJTR_OUT_DEPRECATED	20
#define HCX_PREFIX_OUT				21
#define HCX_ADD_TIMESTAMP			22
#define HCX_TRACK_IN				23
#define HCX_PMKIDEAPOL_OUT			'o'
#define HCX_ESSID_OUT				'E'
#define HCX_ESSIDPROBEREQUEST_OUT		'R'
#define HCX_IDENTITY_OUT			'I'
#define HCX_DEVICEINFO_OUT			'D'
#define HCX_USERNAME_OUT			'U'
#define HCX_HELP				'h'
#define HCX_VERSION				'v'

#define ERROR_WARNING_MAX_L1		10
#define ERROR_WARNING_MAX_L2		50
#define ERROR_WARNING_MAX_L3		100

#define PREFIX_BUFFER_MAX		PATH_MAX -20

#define ESSID_LEN_MAX			32
#define	OPTIONLEN_MAX			1024
#define GPX_MAX				256
#define NMEA_MAX			256

#define MAX_INTERFACE_ID		255

#define RAW_LEN_MAX			131072

#define MACLIST_MAX			100000
#define HANDSHAKELIST_MAX		100000
#define PMKIDLIST_MAX			100000
#define MESSAGELIST_MAX			64
#define EAPOL_AUTHLEN_MAX		251

#define EAPMD5HASHLIST_MAX		1000
#define EAPMD5MSGLIST_MAX		32
#define	EAPMD5_LEN_MAX			16

#define EAPLEAPHASHLIST_MAX		1000
#define EAPLEAPMSGLIST_MAX		32
#define	LEAPREQ_LEN_MAX			8
#define	LEAPRESP_LEN_MAX		24
#define	LEAPUSERNAME_LEN_MAX		120

#define EAPMSCHAPV2HASHLIST_MAX		1000
#define EAPMSCHAPV2MSGLIST_MAX		32
#define MSCHAPV2REQ_LEN_MAX		16
#define MSCHAPV2RESP_LEN_MAX		49
#define MSCHAPV2USERNAME_LEN_MAX	120
#define MSCHAPV2_CHALLENGE_AUTH_LEN_MAX	16
#define MSCHAPV2_CHALLENGE_PEER_LEN_MAX	16
#define MSCHAPV2_CHALLENGE_LEN_MAX	8
#define MSCHAPV2_RESERVED_LEN_MAX	8
#define MSCHAPV2_NTRESPONSE_LEN_MAX	24

#define TACACSPLIST_MAX			1000

#define ESSIDSMAX			1
#define EAPOLTIMEOUT			5000000000ULL
#define NONCEERRORCORRECTION		0

#define HCX_TYPE_PMKID			1
#define HCX_TYPE_EAPOL			2
#define	MESSAGE_PAIR_M12E2		0
#define	MESSAGE_PAIR_M14E4		1
#define	MESSAGE_PAIR_M32E2		2
#define	MESSAGE_PAIR_M32E3		3
#define	MESSAGE_PAIR_M34E3		4
#define	MESSAGE_PAIR_M34E4		5

#define CHANNEL_MAX			255
#define GHZ24				1
#define GHZ5				2
/*===========================================================================*/
/*===========================================================================*/
struct tags_s
{
 uint8_t		channel;
 uint8_t		kdversion;
#define KV_RSNIE	1
#define KV_WPAIE	2
 uint8_t		groupcipher;
 uint8_t		cipher;
#define TCS_WEP40	0x01
#define TCS_TKIP	0x02
#define TCS_WRAP	0x04
#define TCS_CCMP	0x08
#define TCS_GCMP	0x10
#define TCS_WEP104	0x20
#define TCS_BIP		0x40
#define TCS_NOT_ALLOWED	0x80
 uint16_t		akm;
#define	TAK_PMKSA	0x0001
#define	TAK_PSK		0x0002
#define TAK_FT		0x0004
#define TAK_FT_PSK	0x0008
#define	TAK_PMKSA256	0x0010
#define	TAK_PSKSHA256	0x0020
#define	TAK_TDLS	0x0040
#define	TAK_SAE_SHA256	0x0080
#define TAK_FT_SAE	0x0100
#define TAK_AP_PKA	0x0200
#define	TAK_SAE_SHA256B	0x0400
#define	TAK_SAE_SHA384B	0x0800
#define TAK_OWE		0x1000
 uint16_t		mdid;
 uint8_t		r0khidlen;
 uint8_t		r0khid[48];
 uint8_t		r1khidlen;
 uint8_t		r1khid[48];
 uint8_t		pmkid[16];
 uint8_t		wpsinfo;
 char			country[2];
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
#define DEVICE_INFO_MAX		64
 uint8_t		manufacturerlen;
 uint8_t		manufacturer[DEVICE_INFO_MAX];
 uint8_t		modellen;
 uint8_t		model[DEVICE_INFO_MAX];
 uint8_t		serialnumberlen;
 uint8_t		serialnumber[DEVICE_INFO_MAX];
 uint8_t		devicenamelen;
 uint8_t		devicename[DEVICE_INFO_MAX];
#define WPS_ENROLLEE_LEN	16
 uint8_t		enrolleelen;
 uint8_t		enrollee[WPS_ENROLLEE_LEN];
};
typedef struct tags_s tags_t;
#define	TAGS_SIZE (sizeof(tags_t))

/*===========================================================================*/
struct maclist_s
{
 uint64_t		timestamp;
 int			count;
 uint8_t		type;
#define	REMOVED		0
#define	CLIENT		0x01
#define	AP		0x02
 uint8_t		status;
#define ST_PROBE_REQ	1
#define ST_BEACON	2
#define ST_PROBE_RESP	4
#define ST_ASSOC_REQ	8
#define ST_REASSOC_REQ	16
#define ST_ACT_MR_REQ	32
 uint8_t		addr[6];
 uint8_t		kdversion;
 uint8_t		groupcipher;
 uint8_t		cipher;
 uint8_t		akm;
#define	WPA1		1
#define WPA2		2
#define WPA2kv3		4
 uint8_t		algorithm;
 uint8_t		essidlen;
 uint8_t		essid[ESSID_LEN_MAX];
 uint8_t		manufacturerlen;
 uint8_t		manufacturer[DEVICE_INFO_MAX];
 uint8_t		modellen;
 uint8_t		model[DEVICE_INFO_MAX];
 uint8_t		serialnumberlen;
 uint8_t		serialnumber[DEVICE_INFO_MAX];
 uint8_t		devicenamelen;
 uint8_t		devicename[DEVICE_INFO_MAX];
 uint8_t		enrolleelen;
 uint8_t		enrollee[WPS_ENROLLEE_LEN];
};
typedef struct maclist_s maclist_t;
#define	MACLIST_SIZE (sizeof(maclist_t))

static int sort_maclist_by_mac(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;
int cmp;

cmp = memcmp(ia->addr, ib->addr, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
if(ia->essidlen < ib->essidlen) return 1;
else if(ia->essidlen > ib->essidlen) return -1;
cmp = memcmp(ia->essid, ib->essid, ib->essidlen);
if(cmp < 0) return 1;
else if(cmp > 0) return -1;
return 0;
}

static int sort_maclist_by_mac_count(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;
int cmp;

cmp = memcmp(ia->addr, ib->addr, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
if(ia->count < ib->count) return 1;
else if(ia->count > ib->count) return -1;
if(ia->essidlen < ib->essidlen) return 1;
else if(ia->essidlen > ib->essidlen) return -1;
cmp = memcmp(ia->essid, ib->essid, ib->essidlen);
if(cmp < 0) return 1;
else if(cmp > 0) return -1;
return 0;
}

static int sort_maclist_by_essidlen(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;
int cmp;

cmp = memcmp(ia->essid, ib->essid, ib->essidlen);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
if(ia->essidlen > ib->essidlen) return 1;
else if(ia->essidlen < ib->essidlen) return -1;
return 0;
}

static int sort_maclist_by_manufacturer(const void *a, const void *b)
{
const maclist_t *ia = (const maclist_t *)a;
const maclist_t *ib = (const maclist_t *)b;
int cmp;

cmp = memcmp(ia->manufacturer, ib->manufacturer, ib->manufacturerlen);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
if(ia->manufacturerlen > ib->manufacturerlen) return 1;
else if(ia->manufacturerlen < ib->manufacturerlen) return -1;
cmp = memcmp(ia->addr, ib->addr, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
return 0;
}
/*===========================================================================*/
struct messagelist_s
{
 uint64_t		timestamp;
 long int		eapolmsgcount;
 uint8_t		status;
#define	ST_M12E2	0x00
#define	ST_M14E4	0x01
#define	ST_M32E2	0x02
#define	ST_M32E3	0x03
#define	ST_M34E3	0x04
#define	ST_M34E4	0x05
#define	ST_APLESS	0x10
#define	ST_LE		0x20
#define	ST_BE		0x40
#define	ST_ENDIANESS	0x60
#define	ST_NC		0x80
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		message;
#define HS_M1		1
#define HS_M2		2
#define HS_M3		4
#define HS_M4		8
#define HS_PMKID	16
 uint64_t		rc;
 uint8_t		nonce[32];
 uint8_t		pmkid[16];
 uint16_t		eapauthlen;
 uint8_t		eapol[EAPOL_AUTHLEN_MAX];
};
typedef struct messagelist_s messagelist_t;
#define	MESSAGELIST_SIZE (sizeof(messagelist_t))

static int sort_messagelist_by_timestamp(const void *a, const void *b)
{
const messagelist_t *ia = (const messagelist_t *)a;
const messagelist_t *ib = (const messagelist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
struct handshakelist_s
{
 uint64_t		timestampgap;
 uint64_t		timestamp;
 uint8_t		status;
 uint8_t		messageap;
 uint8_t		messageclient;
 uint64_t		rcgap;
 uint8_t		nc;
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		anonce[32];
 uint8_t		pmkid[16];
 uint16_t		eapauthlen;
 uint8_t		eapol[256];
};
typedef struct handshakelist_s handshakelist_t;
#define	HANDSHAKELIST_SIZE (sizeof(handshakelist_t))

static int sort_handshakelist_by_timegap(const void *a, const void *b)
{
const handshakelist_t *ia = (const handshakelist_t *)a;
const handshakelist_t *ib = (const handshakelist_t *)b;
int cmp;

cmp = memcmp(ia->ap, ib->ap, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->client, ib->client, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
if(ia->timestampgap > ib->timestampgap) return 1;
else if(ia->timestampgap < ib->timestampgap) return -1;
if(ia->rcgap > ib->rcgap) return 1;
else if(ia->rcgap < ib->rcgap) return -1;
if(ia->rcgap > ib->rcgap) return 1;
else if(ia->rcgap < ib->rcgap) return -1;
return 0;
}

static int sort_handshakelist_by_rcgap(const void *a, const void *b)
{
const handshakelist_t *ia = (const handshakelist_t *)a;
const handshakelist_t *ib = (const handshakelist_t *)b;
int cmp;

cmp = memcmp(ia->ap, ib->ap, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->client, ib->client, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
if(ia->rcgap > ib->rcgap) return 1;
else if(ia->rcgap < ib->rcgap) return -1;
if(ia->timestampgap > ib->timestampgap) return 1;
else if(ia->timestampgap < ib->timestampgap) return -1;
if(ia->rcgap > ib->rcgap) return 1;
else if(ia->rcgap < ib->rcgap) return -1;
return 0;
}
/*===========================================================================*/
struct pmkidlist_s
{
 uint64_t		timestamp;
 uint8_t		status;
#define PMKID_AP	0x01
#define PMKID_APPSK256	0x02
#define PMKID_CLIENT	0x10
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		anonce[32];
 uint8_t		pmkid[16];
};
typedef struct pmkidlist_s pmkidlist_t;
#define	PMKIDLIST_SIZE (sizeof(pmkidlist_t))

static int sort_pmkidlist_by_mac(const void *a, const void *b)
{
const pmkidlist_t *ia = (const pmkidlist_t *)a;
const pmkidlist_t *ib = (const pmkidlist_t *)b;
int cmp;

cmp = memcmp(ia->ap, ib->ap, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->client, ib->client, 6);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->pmkid, ib->pmkid, 6);
if(cmp < 0) return 1;
else if(cmp > 0) return -1;
return 0;
}
/*===========================================================================*/
struct eapmd5msglist_s
{
 uint64_t		timestamp;
 uint8_t		ap[6];
 uint8_t		client[6];
 uint8_t		type;
 uint8_t		id;
 uint8_t		md5[EAPMD5_LEN_MAX];
};
typedef struct eapmd5msglist_s eapmd5msglist_t;
#define	EAPMD5MSGLIST_SIZE (sizeof(eapmd5msglist_t))

static int sort_eapmd5msglist_by_timestamp(const void *a, const void *b)
{
const eapmd5msglist_t *ia = (const eapmd5msglist_t *)a;
const eapmd5msglist_t *ib = (const eapmd5msglist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
struct eapmd5hashlist_s
{
 uint8_t		id;
 uint8_t		md5request[EAPMD5_LEN_MAX];
 uint8_t		md5response[EAPMD5_LEN_MAX];
};
typedef struct eapmd5hashlist_s eapmd5hashlist_t;
#define	EAPMD5HASHLIST_SIZE (sizeof(eapmd5hashlist_t))

static int sort_eapmd5hashlist_by_id(const void *a, const void *b)
{
const eapmd5hashlist_t *ia = (const eapmd5hashlist_t *)a;
const eapmd5hashlist_t *ib = (const eapmd5hashlist_t *)b;
int cmp;

if(ia->id < ib->id) return 1;
else if(ia->id > ib->id) return -1;
cmp = memcmp(ia->md5request, ib->md5request, EAPMD5_LEN_MAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->md5response, ib->md5response, EAPMD5_LEN_MAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
return 0;
}
/*===========================================================================*/
struct eapleapmsglist_s
{
 uint64_t	timestamp;
 uint8_t	ap[6];
 uint8_t	client[6];
 uint8_t	type;
 uint8_t	id;
 uint8_t	leaprequest[LEAPREQ_LEN_MAX];
 uint8_t	leapresponse[LEAPRESP_LEN_MAX];
 uint8_t	leapusernamelen;
 uint8_t	leapusername[LEAPUSERNAME_LEN_MAX];
};
typedef struct eapleapmsglist_s eapleapmsglist_t;
#define	EAPLEAPMSGLIST_SIZE (sizeof(eapleapmsglist_t))

static int sort_eapleapmsglist_by_timestamp(const void *a, const void *b)
{
const eapleapmsglist_t *ia = (const eapleapmsglist_t *)a;
const eapleapmsglist_t *ib = (const eapleapmsglist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
struct eapleaphashlist_s
{
 uint8_t	id;
 uint8_t	leaprequest[LEAPREQ_LEN_MAX];
 uint8_t	leapresponse[LEAPRESP_LEN_MAX];
 uint8_t	leapusernamelen;
 uint8_t	leapusername[LEAPUSERNAME_LEN_MAX];
};
typedef struct eapleaphashlist_s eapleaphashlist_t;
#define	EAPLEAPHASHLIST_SIZE (sizeof(eapleaphashlist_t))

static int sort_eapleaphashlist_by_id(const void *a, const void *b)
{
const eapleaphashlist_t *ia = (const eapleaphashlist_t *)a;
const eapleaphashlist_t *ib = (const eapleaphashlist_t *)b;
int cmp;

if(ia->id < ib->id) return 1;
else if(ia->id > ib->id) return -1;
if(ia->leapusernamelen > ib->leapusernamelen) return 1;
if(ia->leapusernamelen < ib->leapusernamelen) return -1;
cmp = memcmp(ia->leaprequest, ib->leaprequest, LEAPREQ_LEN_MAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->leapresponse, ib->leapresponse, LEAPRESP_LEN_MAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->leapusername, ib->leapusername, ia->leapusernamelen);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
return 0;
}
/*===========================================================================*/
struct eapmschapv2msglist_s
{
 uint64_t	timestamp;
 uint8_t	ap[6];
 uint8_t	client[6];
 uint8_t	type;
 uint8_t	id;
 uint8_t	mschapv2request[MSCHAPV2REQ_LEN_MAX];
 uint8_t	mschapv2response[MSCHAPV2RESP_LEN_MAX];
 uint8_t	mschapv2usernamelen;
 uint8_t	mschapv2username[MSCHAPV2USERNAME_LEN_MAX];
};
typedef struct eapmschapv2msglist_s eapmschapv2msglist_t;
#define	EAPMSCHAPV2MSGLIST_SIZE (sizeof(eapmschapv2msglist_t))

static int sort_eapmschapv2msglist_by_timestamp(const void *a, const void *b)
{
const eapmschapv2msglist_t *ia = (const eapmschapv2msglist_t *)a;
const eapmschapv2msglist_t *ib = (const eapmschapv2msglist_t *)b;

if(ia->timestamp < ib->timestamp) return 1;
else if(ia->timestamp > ib->timestamp) return -1;
return 0;
}
/*===========================================================================*/
struct eapmschapv2hashlist_s
{
 uint8_t	id;
 uint8_t	mschapv2request[MSCHAPV2REQ_LEN_MAX];
 uint8_t	mschapv2response[MSCHAPV2RESP_LEN_MAX];
 uint8_t	mschapv2usernamelen;
 uint8_t	mschapv2username[MSCHAPV2USERNAME_LEN_MAX];
};
typedef struct eapmschapv2hashlist_s eapmschapv2hashlist_t;
#define	EAPMSCHAPV2HASHLIST_SIZE (sizeof(eapmschapv2hashlist_t))

static int sort_eapmschapv2hashlist_by_id(const void *a, const void *b)
{
const eapmschapv2hashlist_t *ia = (const eapmschapv2hashlist_t *)a;
const eapmschapv2hashlist_t *ib = (const eapmschapv2hashlist_t *)b;
int cmp;

if(ia->id < ib->id) return 1;
else if(ia->id > ib->id) return -1;
if(ia->mschapv2usernamelen > ib->mschapv2usernamelen) return 1;
if(ia->mschapv2usernamelen < ib->mschapv2usernamelen) return -1;
cmp = memcmp(ia->mschapv2request, ib->mschapv2request, MSCHAPV2REQ_LEN_MAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->mschapv2response, ib->mschapv2response, MSCHAPV2RESP_LEN_MAX);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
cmp = memcmp(ia->mschapv2username, ib->mschapv2username, ia->mschapv2usernamelen);
if(cmp > 0) return 1;
else if(cmp < 0) return -1;
return 0;
}
/*===========================================================================*/
#define TACACSPMAX_LEN	0xff
struct tacacsplist_s
{
 uint8_t	version;
 uint8_t	sequencenr;
 uint32_t	sessionid;
 uint32_t	len;
 uint8_t	data[TACACSPMAX_LEN];
} __attribute__((__packed__));
typedef struct tacacsplist_s tacacsplist_t;
#define	TACACSPLIST_SIZE (sizeof(tacacsplist_t))
/*===========================================================================*/



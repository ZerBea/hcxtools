#define MYREPLAYCOUNT 63232

#define	MAC_SIZE_ACK	(10)
#define	MAC_SIZE_RTS	(16)
#define	MAC_SIZE_NORM	(24)
#define	MAC_SIZE_QOS	(26)
#define	MAC_SIZE_LONG	(30)

#define FCS_LEN 4

/* types */
#define IEEE80211_FTYPE_MGMT		0x0
#define IEEE80211_FTYPE_CTL		0x1
#define IEEE80211_FTYPE_DATA		0x2
#define IEEE80211_FTYPE_RCVD		0x3

/* management */
#define IEEE80211_STYPE_ASSOC_REQ	0x0
#define IEEE80211_STYPE_ASSOC_RESP	0x1
#define IEEE80211_STYPE_REASSOC_REQ	0x2
#define IEEE80211_STYPE_REASSOC_RESP	0x3
#define IEEE80211_STYPE_PROBE_REQ	0x4
#define IEEE80211_STYPE_PROBE_RESP	0x5
#define IEEE80211_STYPE_BEACON		0x8
#define IEEE80211_STYPE_ATIM		0x9
#define IEEE80211_STYPE_DISASSOC	0xa
#define IEEE80211_STYPE_AUTH		0xb
#define IEEE80211_STYPE_DEAUTH		0xc
#define IEEE80211_STYPE_ACTION		0xd

/* control */
#define IEEE80211_STYPE_CTL_EXT		0x6
#define IEEE80211_STYPE_BACK_REQ	0x8
#define IEEE80211_STYPE_BACK		0x9
#define IEEE80211_STYPE_PSPOLL		0xa
#define IEEE80211_STYPE_RTS		0xb
#define IEEE80211_STYPE_CTS		0xc
#define IEEE80211_STYPE_ACK		0xd
#define IEEE80211_STYPE_CFEND		0xe
#define IEEE80211_STYPE_CFENDACK	0xf

/* data */
#define IEEE80211_STYPE_DATA			0x0
#define IEEE80211_STYPE_DATA_CFACK		0x1
#define IEEE80211_STYPE_DATA_CFPOLL		0x2
#define IEEE80211_STYPE_DATA_CFACKPOLL		0x3
#define IEEE80211_STYPE_NULLFUNC		0x4
#define IEEE80211_STYPE_CFACK			0x5
#define IEEE80211_STYPE_CFPOLL			0x6
#define IEEE80211_STYPE_CFACKPOLL		0x7
#define IEEE80211_STYPE_QOS_DATA		0x8
#define IEEE80211_STYPE_QOS_DATA_CFACK		0x9
#define IEEE80211_STYPE_QOS_DATA_CFPOLL		0xa
#define IEEE80211_STYPE_QOS_DATA_CFACKPOLL	0xb
#define IEEE80211_STYPE_QOS_NULLFUNC		0xc
#define IEEE80211_STYPE_QOS_CFACK		0xd
#define IEEE80211_STYPE_QOS_CFPOLL		0xe
#define IEEE80211_STYPE_QOS_CFACKPOLL		0xf

/* Reason codes (IEEE 802.11-2007, 7.3.1.7, Table 7-22) */
#define WLAN_REASON_UNSPECIFIED 1
#define WLAN_REASON_PREV_AUTH_NOT_VALID 2
#define WLAN_REASON_DEAUTH_LEAVING 3
#define WLAN_REASON_DISASSOC_DUE_TO_INACTIVITY 4
#define WLAN_REASON_DISASSOC_AP_BUSY 5
#define WLAN_REASON_CLASS2_FRAME_FROM_NONAUTH_STA 6
#define WLAN_REASON_CLASS3_FRAME_FROM_NONASSOC_STA 7
#define WLAN_REASON_DISASSOC_STA_HAS_LEFT 8
#define WLAN_REASON_STA_REQ_ASSOC_WITHOUT_AUTH 9
/* IEEE 802.11h */
#define WLAN_REASON_PWR_CAPABILITY_NOT_VALID 10
#define WLAN_REASON_SUPPORTED_CHANNEL_NOT_VALID 11
/* IEEE 802.11i */
#define WLAN_REASON_INVALID_IE 13
#define WLAN_REASON_MICHAEL_MIC_FAILURE 14
#define WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT 15
#define WLAN_REASON_GROUP_KEY_UPDATE_TIMEOUT 16
#define WLAN_REASON_IE_IN_4WAY_DIFFERS 17
#define WLAN_REASON_GROUP_CIPHER_NOT_VALID 18
#define WLAN_REASON_PAIRWISE_CIPHER_NOT_VALID 19
#define WLAN_REASON_AKMP_NOT_VALID 20
#define WLAN_REASON_UNSUPPORTED_RSN_IE_VERSION 21
#define WLAN_REASON_INVALID_RSN_IE_CAPAB 22
#define WLAN_REASON_IEEE_802_1X_AUTH_FAILED 23
#define WLAN_REASON_CIPHER_SUITE_REJECTED 24

#define IEEE80211_SEQ_SEQ_MASK	0xfff0
#define IEEE80211_SEQ_SEQ_SHIFT	4

#define WBIT(n) (1 << (n))
#define WPA_KEY_INFO_TYPE_MASK (WBIT(0) | WBIT(1) | WBIT(2))
#define WPA_KEY_INFO_TYPE_HMAC_MD5_RC4 WBIT(0)
#define WPA_KEY_INFO_TYPE_HMAC_SHA1_AES WBIT(1)
#define WPA_KEY_INFO_KEY_TYPE WBIT(3) /* 1 = Pairwise, 0 = Group key */
#define WPA_KEY_INFO_KEY_INDEX_MASK (WBIT(4) | WBIT(5))
#define WPA_KEY_INFO_KEY_INDEX_SHIFT 4
#define WPA_KEY_INFO_INSTALL WBIT(6)  /* pairwise */
#define WPA_KEY_INFO_TXRX WBIT(6) /* group */
#define WPA_KEY_INFO_ACK WBIT(7)
#define WPA_KEY_INFO_MIC WBIT(8)
#define WPA_KEY_INFO_SECURE WBIT(9)
#define WPA_KEY_INFO_ERROR WBIT(10)
#define WPA_KEY_INFO_REQUEST WBIT(11)
#define WPA_KEY_INFO_ENCR_KEY_DATA WBIT(12) /* IEEE 802.11i/RSN only */

/*===========================================================================*/
struct radiotap_header
{
 uint8_t	it_version;
 uint8_t	it_pad;
 uint16_t	it_len;
 uint32_t	it_present;
} __attribute__((__packed__));
typedef struct radiotap_header rth_t;
#define	RTH_SIZE (sizeof(rth_t))

/*===========================================================================*/
#define WLAN_DEVNAMELEN_MAX 16
struct prism_item
{
 uint32_t did;
 uint16_t status;
 uint16_t len;
 uint32_t data;
} __attribute__((packed));

struct prism_header
{
 uint32_t msgcode;
 uint32_t msglen;
 char devname[WLAN_DEVNAMELEN_MAX];
 struct prism_item hosttime;
 struct prism_item mactime;
 struct prism_item channel;
 struct prism_item rssi;
 struct prism_item sq;
 struct prism_item signal;
 struct prism_item noise;
 struct prism_item rate;
 struct prism_item istx;
 struct prism_item frmlen;
} __attribute__((packed));
typedef struct prism_item prism_item_t;
typedef struct prism_header prism_t;
#define	PRISM_SIZE (sizeof(prism_t))
/*===========================================================================*/
struct ppi_header
{
 uint8_t  pph_version;
 uint8_t  pph_flags;
 uint16_t pph_len;
 uint32_t pph_dlt;
} __attribute__((packed));
typedef struct ppi_header ppi_t;
#define	PPI_SIZE (sizeof(ppi_t))
/*===========================================================================*/
struct qos_frame
{
 uint8_t	control;
 uint8_t	flags;
} __attribute__((__packed__));
typedef struct qos_frame qos_t;
#define	QOS_SIZE (sizeof(qos_t))
/*===========================================================================*/
/*
 * DS bit usage
 *
 * TA = transmitter address
 * RA = receiver address
 * DA = destination address
 * SA = source address
 *
 * ToDS    FromDS  A1(RA)  A2(TA)  A3      A4      Use
 * -----------------------------------------------------------------
 *  0       0       DA      SA      BSSID   -       IBSS/DLS
 *  0       1       DA      BSSID   SA      -       AP -> STA
 *  1       0       BSSID   SA      DA      -       AP <- STA
 *  1       1       RA      TA      DA      SA      unspecified (WDS)
 */
struct mac_frame
{
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
 unsigned	subtype : 4;
 unsigned	type : 	2;
 unsigned	version : 2;

 unsigned	ordered : 1;
 unsigned	protected : 1;
 unsigned	more_data : 1;
 unsigned	power : 1;
 unsigned	retry : 1;
 unsigned	more_frag : 1;
 unsigned	from_ds : 1;
 unsigned	to_ds : 1;
#else
 unsigned	version : 2;
 unsigned	type : 	2;
 unsigned	subtype : 4;

 unsigned	to_ds : 1;
 unsigned	from_ds : 1;
 unsigned	more_frag : 1;
 unsigned	retry : 1;
 unsigned	power : 1;
 unsigned	more_data : 1;
 unsigned	protected : 1;
 unsigned	ordered : 1;
#endif
 uint16_t	duration;
 uint8_t	addr1[6];
 uint8_t	addr2[6];
 uint8_t	addr3[6];
 uint16_t	sequence;
 uint8_t	addr4[6];
 qos_t		qos;
} __attribute__((__packed__));
typedef struct mac_frame mac_t;
/*===========================================================================*/
struct capabilities_ap_frame
{
 uint64_t	timestamp;
 uint16_t	beaconintervall;
 uint16_t	capapinfo;
} __attribute__((__packed__));
typedef struct capabilities_ap_frame capap_t;
#define	CAPABILITIESAP_SIZE sizeof(capap_t)
/*===========================================================================*/
struct capabilities_sta_frame
{
 uint16_t client_capabilities;
 uint16_t client_listeninterval;
} __attribute__((__packed__));
typedef struct capabilities_sta_frame capsta_t;
#define	CAPABILITIESSTA_SIZE sizeof(capsta_t)
/*===========================================================================*/
struct capabilitiesre_sta_frame
{
 uint16_t client_capabilities;
 uint16_t client_listeninterval;
 uint8_t	addr1[6];
} __attribute__((__packed__));
typedef struct capabilitiesre_sta_frame capresta_t;
#define	CAPABILITIESRESTA_SIZE sizeof(capresta_t)
/*===========================================================================*/
struct ie_tag
{
	uint8_t		id;
#define	TAG_SSID	0
#define	TAG_RATE	1
#define	TAG_CHAN	3
	uint8_t		len;
	uint8_t		data[1];
} __attribute__((__packed__));
typedef struct ie_tag ietag_t;
#define	IETAG_SIZE offsetof(ietag_t, data)
/*===========================================================================*/
struct llc_frame
{
 uint8_t	dsap;
 uint8_t	ssap;
 uint8_t	control;
 uint8_t	org[3];
 uint16_t	type;
#define	LLC_TYPE_AUTH	0x888e
#define	LLC_TYPE_IPV4	0x0800
#define	LLC_TYPE_IPV6	0x86dd
#define	LLC_TYPE_PREAUT	0x88c7
#define	LLC_TYPE_FRRR	0x890d
};
typedef struct llc_frame llc_t;
#define	LLC_SIZE (sizeof(llc_t))
#define	LLC_SNAP 0xaa
/*===========================================================================*/
struct authentication_frame
{
 uint16_t authentication_algho;
 uint16_t authentication_seq;
} __attribute__((__packed__));
typedef struct authentication_frame authf_t;
#define	AUTHENTICATIONFRAME_SIZE (sizeof(authf_t))
/*===========================================================================*/
struct eapauthentication_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	len;
 uint8_t	data[1];
} __attribute__((__packed__));
typedef struct eapauthentication_frame eapauth_t;
#define	EAPAUTH_SIZE offsetof(eapauth_t, data)
/*===========================================================================*/
struct wpakey_frame
{
 uint8_t	keydescriptor;
#define WPA_M1  0b00000001
#define WPA_M2  0b00000010
#define WPA_M3  0b00000100
#define WPA_M4  0b00001000
 uint16_t	keyinfo;
 uint16_t	keylen;
 uint64_t	replaycount;
 uint8_t	nonce[32];
 uint8_t	keyiv[16];
 uint64_t	keyrsc;
 uint8_t	keyid[8];
 uint8_t	keymic[16];
 uint16_t	wpadatalen;
 uint8_t	data[1];
} __attribute__((__packed__));
typedef struct wpakey_frame wpakey_t;
#define	WPAKEY_SIZE offsetof(wpakey_t, data)
/*===========================================================================*/
struct exteap_frame
{
 uint8_t		code;
#define	EAP_CODE_REQ		1
#define	EAP_CODE_RESP		2
#define	EAP_CODE_SUCCESS	3
#define	EAP_CODE_FAILURE	4
#define	EAP_CODE_INITIATE	5
#define	EAP_CODE_FINISH		6
 uint8_t		id;
#define	EAP_TYPE_ID	1
 uint16_t		extlen;
 uint8_t		exttype;
#define EAP_TYPE_EAP		0
#define EAP_TYPE_ID		1
#define EAP_TYPE_NOTIFY		2
#define EAP_TYPE_NAK		3
#define EAP_TYPE_MD5		4
#define EAP_TYPE_OTP		5
#define EAP_TYPE_GTC		6
#define EAP_TYPE_RSA		9
#define EAP_TYPE_DSS		10
#define EAP_TYPE_KEA		11
#define EAP_TYPE_KEA_VALIDATE	12
#define EAP_TYPE_TLS		13
#define EAP_TYPE_AXENT		14
#define EAP_TYPE_RSA_SSID	15
#define EAP_TYPE_RSA_ARCOT	16
#define EAP_TYPE_LEAP		17
#define EAP_TYPE_SIM		18
#define EAP_TYPE_SRP_SHA1	19
#define EAP_TYPE_TTLS		21
#define EAP_TYPE_RAS		22
#define EAP_TYPE_AKA		23
#define EAP_TYPE_3COMEAP	24
#define EAP_TYPE_PEAP		25
#define EAP_TYPE_MSEAP		26
#define EAP_TYPE_MAKE		27
#define EAP_TYPE_CRYPTOCARD	28
#define EAP_TYPE_MSCHAPV2	29
#define EAP_TYPE_DYNAMICID	30
#define EAP_TYPE_ROB		31
#define EAP_TYPE_POTP		32
#define EAP_TYPE_MSTLV		33
#define EAP_TYPE_SENTRI		34
#define EAP_TYPE_AW		35
#define EAP_TYPE_CSBA		36
#define EAP_TYPE_AIRFORT	37
#define EAP_TYPE_HTTPD		38
#define EAP_TYPE_SS		39
#define EAP_TYPE_DC		40
#define EAP_TYPE_SPEKE		41
#define EAP_TYPE_MOBAC		42
#define EAP_TYPE_FAST		43
#define EAP_TYPE_ZLXEAP		44
#define EAP_TYPE_LINK		45
#define EAP_TYPE_PAX		46
#define EAP_TYPE_PSK		47
#define EAP_TYPE_SAKE		48
#define EAP_TYPE_IKEV2		49
#define EAP_TYPE_AKA1		50
#define EAP_TYPE_GPSK		51
#define EAP_TYPE_PWD		52
#define EAP_TYPE_EKE1		53
#define EAP_TYPE_PTEAP		54
#define EAP_TYPE_TEAP		55
#define	EAP_TYPE_EXPAND		254
#define EAP_TYPE_EXPERIMENTAL	255
 uint8_t		data[1];
} __attribute__((__packed__));
typedef struct exteap_frame exteap_t;
#define	EXTEAP_SIZE offsetof(exteap_t, data)
/*===========================================================================*/
struct ipv4_frame
{
 uint8_t	ver_hlen;
 uint8_t	tos;
 uint16_t	len;
 uint16_t	ipid;
 uint16_t	flags_offset;
 uint8_t	ttl;
 uint8_t	nextprotocol;
#define NEXTHDR_GRE	47	/* GRE header. */
#define NEXTHDR_ESP	50	/* Encapsulating security payload. */
#define NEXTHDR_AUTH	51	/* Authentication header. */
 uint16_t	checksum;
 uint8_t	srcaddr[4];
 uint8_t	dstaddr[4];
} __attribute__ ((packed));
typedef struct ipv4_frame ipv4_t;
#define	IPV4_SIZE (sizeof(ipv4_t))
#define	IPV4_SIZE_MIN 20
#define	IPV4_SIZE_MAX 64
/*===========================================================================*/
struct ipv6_frame
{
 uint32_t	ver_class;
 uint16_t	len;
 uint8_t	nextprotocol;
 uint8_t	hoplimint;
 uint8_t	srcaddr[16];
 uint8_t	dstaddr[16];
} __attribute__ ((packed));
typedef struct ipv6_frame ipv6_t;
#define	IPV6_SIZE (sizeof(ipv6_t))
/*===========================================================================*/
struct fcs_frame
{
 uint32_t	fcs;
};
typedef struct fcs_frame fcs_t;
#define	FCS_SIZE (sizeof(fcs_t))
/*===========================================================================*/
/* global var */

static const uint8_t nullnonce[] =
{
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
#define	NULLNONCE_SIZE (sizeof(nullnonce))

static const uint8_t mynonce[] =
{
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9
};
#define ANONCE_SIZE sizeof(anonce)
/*===========================================================================*/

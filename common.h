#include "berkeleyfilter.h"

#define VERSION "3.6.0"
#define VERSION_JAHR "2017"

#if !defined(FALSE)
#define FALSE 0
#endif

#if !defined(TRUE)
#define TRUE 1
#endif

#define NEWENTY -1

#define HCCAPX_SIGNATURE 0x58504348
#define HCCAPX_VERSION 4


#define	MAC_SIZE_ACK	(10)
#define	MAC_SIZE_RTS	(16)
#define	MAC_SIZE_NORM	(24)
#define	MAC_SIZE_QOS	(26)
#define	MAC_SIZE_LONG	(30)

#define	MAC_TYPE_MGMT	0x0
#define	MAC_TYPE_CTRL	0x1
#define	MAC_TYPE_DATA	0x2
#define	MAC_TYPE_RSVD	0x3

// management subtypes
#define	MAC_ST_ASSOC_REQ	0x0
#define	MAC_ST_ASSOC_RESP	0x1
#define	MAC_ST_REASSOC_REQ	0x2
#define	MAC_ST_REASSOC_RESP	0x3
#define	MAC_ST_PROBE_REQ	0x4
#define	MAC_ST_PROBE_RESP	0x5
#define	MAC_ST_BEACON		0x8
#define	MAC_ST_DISASSOC		0xA
#define	MAC_ST_AUTH		0xB
#define	MAC_ST_DEAUTH		0xC
#define	MAC_ST_ACTION		0xD
// data subtypes
#define	MAC_ST_DATA		0x0
#define	MAC_ST_NULL		0x4
#define	MAC_ST_QOSNULL		0xC
#define	MAC_ST_QOSDATA		0x8
// control subtypes
#define	MAC_ST_BACK_REQ		0x8
#define	MAC_ST_BACK		0x9
#define	MAC_ST_RTS		0xB
#define	MAC_ST_CTS		0xC
#define	MAC_ST_ACK		0xD

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


struct radiotap_header
{
 uint8_t	it_version;
 uint8_t	it_pad;
 uint16_t	it_len;
 uint32_t	it_present;
};
typedef struct radiotap_header rth_t;
#define	RTH_SIZE (sizeof(rth_t))


struct adr_frame
{
 uint8_t	addr[6];
};
typedef struct adr_frame adr_t;
#define	ADR_SIZE (sizeof(adr_t))


struct qos_frame
{
 uint8_t	control;
 uint8_t	flags;
};
typedef struct qos_frame qos_t;
#define	QOS_SIZE (sizeof(qos_t))


struct mac_frame
{
#if __BYTE_ORDER == __BIG_ENDIAN
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
 adr_t		addr1;
 adr_t		addr2;
 adr_t		addr3;
 uint16_t	sequence;
 adr_t		addr4;
 qos_t		qos;
};
typedef struct mac_frame mac_t;


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


struct ieee_tag {
 uint8_t		id;
#define	TAG_SSID	0
#define	TAG_RATE	1
#define	TAG_CHAN	3
#define	TAG_XRAT	0x32
 uint8_t		len;
 uint8_t		data[];
} __attribute__((__packed__));
typedef struct ieee_tag tag_t;
#define	TAGINFO_SIZE (sizeof(tag_t))


struct beaconinfo
{
 uint64_t beacon_timestamp;
 uint16_t beacon_interval;
 uint16_t beacon_capabilities;
} __attribute__((__packed__));
typedef struct beaconinfo beacon_t;
#define	BEACONINFO_SIZE (sizeof(beacon_t))


struct essidinfo
{
 uint8_t info_essid;
 uint8_t info_essid_len;
 uint8_t* essid[0];
} __attribute__((__packed__));
typedef struct essidinfo essid_t;
#define	ESSIDINFO_SIZE (sizeof(essid_t))


struct authenticationf
{
 uint16_t authentication_algho;
 uint16_t authentication_seq;
} __attribute__((__packed__));
typedef struct authenticationf authf_t;
#define	AUTHF_SIZE (sizeof(authf_t))


struct associationreqf
{
 uint16_t client_capabilities;
 uint16_t client_listeninterval;
} __attribute__((__packed__));
typedef struct associationreqf assocreq_t;
#define	ASSOCIATIONREQF_SIZE (sizeof(assocreq_t))


struct associationresf
{
 uint16_t ap_capabilities;
 uint16_t ap_status;
 uint16_t ap_associd;
 } __attribute__((__packed__));
typedef struct associationresf assocres_t;
#define	ASSOCIATIONRESF_SIZE (sizeof(assocres_t))


struct reassociationreqf
{
 uint16_t client_capabilities;
 uint16_t client_listeninterval;
 adr_t	  addr3;
} __attribute__((__packed__));
typedef struct reassociationreqf reassocreq_t;
#define	REASSOCIATIONREQF_SIZE (sizeof(reassocreq_t))


struct eap_frame
{
 uint8_t	version;
 uint8_t	type;
 uint16_t	len;
 uint8_t	keytype;
 uint16_t	keyinfo;
 uint16_t	keylen;
 uint64_t	replaycount;
 uint8_t	nonce[32];
 uint8_t	keyiv[16];
 uint8_t	keyrsc[8];
 uint8_t	keyid[8];
 uint8_t	keymic[16];
 uint16_t	wpadatalen;
 uint8_t	wpadata[10];
} __attribute__((__packed__));
typedef struct eap_frame eap_t;
#define	EAP_SIZE (sizeof(eap_t))


struct vendor_id
{
 uint8_t	vid[3];
};
typedef struct vendor_id vid_t;
#define	VID_SIZE (sizeof(vidt_t))


struct eapext_frame
{
 uint8_t		version;
 uint8_t		type;
 uint16_t		len;
 uint8_t		eapcode;
#define	EAP_CODE_REQ		1
#define	EAP_CODE_RESP		2
#define	EAP_CODE_SUCCESS	3
#define	EAP_CODE_FAILURE	4
#define	EAP_CODE_INITIATE	5
#define	EAP_CODE_FINISH		6
 uint8_t		eapid;
 uint16_t		eaplen;
 uint8_t		eaptype;
#define EAP_TYPE_EAP		0
#define EAP_TYPE_ID		1
#define EAP_TYPE_NOTIFY		2
#define EAP_TYPE_NAK		3
#define EAP_TYPE_MD5		4
#define EAP_TYPE_RSA		9
#define EAP_TYPE_TLS		13
#define EAP_TYPE_LEAP		17
#define EAP_TYPE_SIM		18
#define EAP_TYPE_SRP_SHA1	19
#define EAP_TYPE_TTLS		21
#define EAP_TYPE_AKA		23
#define EAP_TYPE_3COMEAP	24
#define EAP_TYPE_PEAP		25
#define EAP_TYPE_MSEAP		26
#define EAP_TYPE_MAKE		27
#define EAP_TYPE_MSCHAPV2	29
#define EAP_TYPE_POTP		32
#define EAP_TYPE_MSTLV		33
#define EAP_TYPE_AW		35
#define EAP_TYPE_CSBA		36
#define EAP_TYPE_HTTPD		38
#define EAP_TYPE_SS		39
#define EAP_TYPE_DC		40
#define EAP_TYPE_FAST		43
#define EAP_TYPE_ZLXEAP		44
#define	EAP_TYPE_EXPAND		254
} __attribute__((__packed__));
typedef struct eapext_frame eapext_t;
#define	EAPEXT_SIZE (sizeof(eapext_t))


struct eapri_frame
{
 uint8_t		version;
 uint8_t		type;
 uint16_t		len;
 uint8_t		eapcode;
 uint8_t		eapid;
 uint16_t		eaplen;
 uint8_t		eaptype;
 uint8_t		identity[];
} __attribute__((__packed__));
typedef struct eapri_frame eapri_t;
#define	EAPRI_SIZE (sizeof(eapri_t))


struct eapleap_frame
{
 uint8_t		version;
 uint8_t		type;
 uint16_t		len;
 uint8_t		eapcode;
 uint8_t		eapid;
 uint16_t		eaplen;
 uint8_t		eaptype;
 uint8_t		leapversion;
 uint8_t		leapreserved;
 uint8_t		leapcount;
 uint8_t		leapdata[];
} __attribute__((__packed__));
typedef struct eapleap_frame eapleap_t;
#define	EAPLEAP_SIZE (sizeof(eapleap_t))


struct eapmd5_frame
{
 uint8_t		version;
 uint8_t		type;
 uint16_t		len;
 uint8_t		eapcode;
 uint8_t		eapid;
 uint16_t		eaplen;
 uint8_t		eaptype;
 uint8_t		eapvaluesize;
 uint8_t		md5data[];
} __attribute__((__packed__));
typedef struct eapmd5_frame eapmd5_t;
#define	EAPMD5_SIZE (sizeof(eapmd5_t))


struct ip_frame
{
 uint8_t		ver_hlen;
 uint8_t		tos;
 uint16_t	len;
 uint16_t	ipid;
 uint16_t	flags_offset;
 uint8_t		ttl;
 uint8_t		proto;
 uint16_t	checksum;
 uint8_t		srcaddr[4];
 uint8_t		dstaddr[4];
} __attribute__ ((packed));
typedef struct ip_frame ip_t;
#define	IP_SIZE (sizeof(ip_t))
#define	IP_SIZE_MIN 20
#define	IP_SIZE_MAX 64


struct netdb
{
 long int	tv_sec;  
 long int	tv_usec;
 adr_t		mac_ap;
 adr_t		mac_sta;
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct netdb netdb_t;
#define	NETDB_SIZE (sizeof(netdb_t))


struct eapdb
{
 long int	tv_sec;  
 time_t		tv_usec;
 adr_t		mac_ap;
 adr_t		mac_sta;
 uint16_t	eapol_len;
 uint8_t	eapol[256];
};
typedef struct eapdb eapdb_t;
#define	EAPDB_SIZE (sizeof(eapdb_t))


#define MYREPLAYCOUNT 63232

#define	MESSAGE_PAIR_M12E2 0
#define	MESSAGE_PAIR_M14E4 1
#define	MESSAGE_PAIR_M32E2 2
#define	MESSAGE_PAIR_M32E3 3
#define	MESSAGE_PAIR_M34E3 4
#define	MESSAGE_PAIR_M34E4 5

#define	MESSAGE_PAIR_M12E2NR 128
#define	MESSAGE_PAIR_M14E4NR 129
#define	MESSAGE_PAIR_M32E2NR 130
#define	MESSAGE_PAIR_M32E3NR 131
#define	MESSAGE_PAIR_M34E3NR 132
#define	MESSAGE_PAIR_M34E4NR 133


struct hcx
{
 uint32_t signature;
 uint32_t version;
 uint8_t  message_pair;
 uint8_t  essid_len;
 uint8_t  essid[32];
 uint8_t  keyver;
 uint8_t  keymic[16];
 adr_t    mac_ap;
 uint8_t  nonce_ap[32];
 adr_t    mac_sta;
 uint8_t  nonce_sta[32];
 uint16_t eapol_len;
 uint8_t  eapol[256];
} __attribute__((packed));
typedef struct hcx hcx_t;
#define	HCX_SIZE (sizeof(hcx_t))


/*===========================================================================*/
/* globale Konstante */


const uint8_t channellist[] = 
{
1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 ,14,
36, 40, 44, 48, 52, 56, 60, 64,
100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
149, 153, 157, 161, 165
};
#define CHANNELLIST_SIZE sizeof(channellist)


const uint8_t mynonce[] =
{
0x68, 0x20, 0x09, 0xe2, 0x1f, 0x0e, 0xbc, 0xe5, 0x62, 0xb9, 0x06, 0x5b, 0x54, 0x89, 0x79, 0x09,
0x9a, 0x65, 0x52, 0x86, 0xc0, 0x77, 0xea, 0x28, 0x2f, 0x6a, 0xaf, 0x13, 0x8e, 0x50, 0xcd, 0xb9
};
#define ANONCE_SIZE sizeof(anonce)

/*===========================================================================*/

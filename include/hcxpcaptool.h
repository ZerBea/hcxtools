/*===========================================================================*/
struct apstaessidlist_s
{
 uint32_t	tv_sec;
 uint32_t	tv_usec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	essidlen;
 uint8_t	essid[32];
} __attribute__((__packed__));
typedef struct apstaessidlist_s apstaessidl_t;
#define	APSTAESSIDLIST_SIZE (sizeof(apstaessidl_t))
/*===========================================================================*/
static int sort_apstaessidlist_by_timestamp(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
	return -1;
if(ia->tv_usec > ib->tv_usec)
	return 1;
else if(ia->tv_usec < ib->tv_usec)
	return -1;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
static int sort_apstaessidlist_by_essid(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
if(memcmp(ia->essid, ib->essid, 32) > 0)
	return 1;
else if(memcmp(ia->essid, ib->essid, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct noncelist_s
{
 uint32_t	tv_sec;
 uint32_t	tv_usec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	keyinfo;
 uint64_t	replaycount;
 uint8_t	nonce[32];
} __attribute__((__packed__));
typedef struct noncelist_s noncel_t;
#define	NONCELIST_SIZE (sizeof(noncel_t))
/*===========================================================================*/
static int sort_noncelist_by_timestamp(const void *a, const void *b)
{
const noncel_t *ia = (const noncel_t *)a;
const noncel_t *ib = (const noncel_t *)b;
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
	return -1;
if(ia->tv_usec > ib->tv_usec)
	return 1;
else if(ia->tv_usec < ib->tv_usec)
	return -1;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
if(memcmp(ia->nonce, ib->nonce, 32) > 0)
	return 1;
else if(memcmp(ia->nonce, ib->nonce, 32) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct eapollist_s
{
 uint32_t	tv_sec;
 uint32_t	tv_usec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	keyinfo;
 uint64_t	replaycount;
 uint8_t	authlen;
 uint8_t	eapol[256];
} __attribute__((__packed__));
typedef struct eapollist_s eapoll_t;
#define	EAPOLLIST_SIZE (sizeof(eapoll_t))
/*===========================================================================*/
static int sort_eapollist_by_timestamp(const void *a, const void *b)
{
const eapoll_t *ia = (const eapoll_t *)a;
const eapoll_t *ib = (const eapoll_t *)b;
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
	return -1;
if(ia->tv_usec > ib->tv_usec)
	return 1;
else if(ia->tv_usec < ib->tv_usec)
	return -1;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
if(memcmp(ia->eapol, ib->eapol, 256) > 0)
	return 1;
else if(memcmp(ia->eapol, ib->eapol, 256) < 0)
	return -1;
return 0;
}
/*===========================================================================*/
struct hcxtoollist_s
{
 uint32_t	tv_sec;
 uint32_t	tv_usec;
 uint32_t	tv_diff;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	keyinfo_ap;
 uint8_t	keyinfo_sta;
 uint64_t	rc_diff;
 uint64_t	replaycount_ap;
 uint64_t	replaycount_sta;
 uint8_t	nonce[32];
 uint8_t	authlen;
 uint8_t	eapol[256];
 uint8_t	essidlen;
 uint8_t	essid[32];
} __attribute__((__packed__));
typedef struct hcxtoollist_s hcxl_t;
#define	HCXLIST_SIZE (sizeof(hcxl_t))
/*===========================================================================*/
/*
static int sort_hcxlist_by_timestamp(const void *a, const void *b)
{
const hcxl_t *ia = (const hcxl_t *)a;
const hcxl_t *ib = (const hcxl_t *)b;
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
	return -1;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
if(memcmp(ia->nonce, ib->nonce, 32) > 0)
	return 1;
else if(memcmp(ia->nonce, ib->nonce, 32) < 0)
	return -1;
return 0;
}
*/
/*===========================================================================*/

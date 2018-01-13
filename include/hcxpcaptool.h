/*===========================================================================*/
struct apstaessidlist_s
{
 uint32_t	tv_sec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	essidlen;
 uint8_t	essid[32];
} __attribute__((__packed__));
typedef struct apstaessidlist_s apstaessidl_t;
#define	APSTAESSIDLIST_SIZE (sizeof(apstaessidl_t))
/*===========================================================================*/
static int sort_apstaessidlist_by_ap(const void *a, const void *b)
{
const apstaessidl_t *ia = (const apstaessidl_t *)a;
const apstaessidl_t *ib = (const apstaessidl_t *)b;
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
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
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
struct anoncelist_s
{
 uint32_t	tv_sec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	keyinfo;
 uint64_t	replaycount;
 uint8_t	anonce[32];
} __attribute__((__packed__));
typedef struct anoncelist_s anoncel_t;
#define	ANONCELIST_SIZE (sizeof(anoncel_t))
/*===========================================================================*/
static int sort_anoncelist_by_ap(const void *a, const void *b)
{
const anoncel_t *ia = (const anoncel_t *)a;
const anoncel_t *ib = (const anoncel_t *)b;
if(memcmp(ia->mac_ap, ib->mac_ap, 6) > 0)
	return 1;
else if(memcmp(ia->mac_ap, ib->mac_ap, 6) < 0)
	return -1;
if(memcmp(ia->mac_sta, ib->mac_sta, 6) > 0)
	return 1;
else if(memcmp(ia->mac_sta, ib->mac_sta, 6) < 0)
	return -1;
if(memcmp(ia->anonce, ib->anonce, 32) > 0)
	return 1;
else if(memcmp(ia->anonce, ib->anonce, 32) < 0)
	return -1;
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
	return -1;
return 0;
}
/*===========================================================================*/
struct eapollist_s
{
 uint32_t	tv_sec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
 uint8_t	authlen;
 uint8_t	eapol[256];
} __attribute__((__packed__));
typedef struct eapollist_s eapoll_t;
#define	EAPOLLIST_SIZE (sizeof(eapoll_t))
/*===========================================================================*/
static int sort_eapollist_by_ap(const void *a, const void *b)
{
const eapoll_t *ia = (const eapoll_t *)a;
const eapoll_t *ib = (const eapoll_t *)b;
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
if(ia->tv_sec > ib->tv_sec)
	return 1;
else if(ia->tv_sec < ib->tv_sec)
	return -1;
return 0;
}
/*===========================================================================*/

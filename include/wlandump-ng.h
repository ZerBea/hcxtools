#define PROBEREQUESTLISTESIZEMAX 256
#define PROBERESPONSELISTESIZEMAX 256
#define HANDSHAKELISTESIZEMAX 256
#define BLACKLISTESIZEMAX 256

#define TXBUFFERSIZEMAX 0x2ff

#define TT_SIGUSR1 (SIGUSR1)
#define TT_SIGUSR2 (SIGUSR2)
#define TIME_INTERVAL_1S 5
#define TIME_INTERVAL_1NS 0

#define TIME_INTERVAL_2S 5
#define TIME_INTERVAL_2NS 0

#define STATUS_NONE	  0b00000000
#define STATUS_ASSOCIATED 0b00000001
#define STATUS_M1	  0b00000010

/*===========================================================================*/
struct maclist
{
 long int	tv_sec;
 uint8_t	mac_addr[6];
};
typedef struct maclist macl_t;
#define	MACLIST_SIZE (sizeof(macl_t))

static int sort_maclist_by_time(const void *a, const void *b)
{
const macl_t *ia = (const macl_t *)a;
const macl_t *ib = (const macl_t *)b;
return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
struct macessidlist
{
 long int	tv_sec;
 uint8_t	mac_addr[6];
 uint8_t	essid_len;
 uint8_t	essid[32];
};
typedef struct macessidlist macessidl_t;
#define	MACESSIDLIST_SIZE (sizeof(macessidl_t))

static int sort_macessidlist_by_time(const void *a, const void *b)
{
const macessidl_t *ia = (const macessidl_t *)a;
const macessidl_t *ib = (const macessidl_t *)b;
return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/
struct macapstalist
{
 long int	tv_sec;
 uint8_t	mac_ap[6];
 uint8_t	mac_sta[6];
};
typedef struct macapstalist macapstal_t;
#define	MACAPSTALIST_SIZE (sizeof(macapstal_t))

static int sort_macapstalist_by_time(const void *a, const void *b)
{
const macapstal_t *ia = (const macapstal_t *)a;
const macapstal_t *ib = (const macapstal_t *)b;
return ia->tv_sec < ib->tv_sec;
}
/*===========================================================================*/

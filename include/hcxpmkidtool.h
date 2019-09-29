#define HCXD_WORDLIST_IN	'w'
#define HCXD_WORD_IN		'W'
#define HCXD_PMK_IN		'K'
#define HCXD_PMKID_IN		'p'
#define HCXD_HELP		'h'
#define HCXD_VERSION		'v'

#define PSKCOUNT		10000
#define PSKLEN			64
#define ESSID_LEN_MAX		32

#define EXHAUSTED		1
#define ABORTED			2
/*===========================================================================*/
struct intpsk_s
{
 int		len;
 char		psk[PSKLEN];
} __attribute__((__packed__));
typedef struct intpsk_s intpsk_t;
#define	INTPSK_SIZE (sizeof(intpsk_t))
/*===========================================================================*/
struct argument_s
{
intpsk_t	*pos;
int		sc;
bool		found;
uint8_t		pmk[32];
int		psklen;
uint8_t		psk[64];
} __attribute__((__packed__));
typedef struct argument_s argument_t;
/*===========================================================================*/





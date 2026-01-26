#define HC_POTIN		1
#define HC_OUTIN		2
#define HC_POTOUT		3
#define HC_PBKDF2OUT		4
#define JTR_POTIN		5
#define JTR_PBKDF2OUT		6
#define HCX_TABOUT		7
#define HCX_TABASCIIOUT		8
#define HCX_FAULTYOUT		9
#define HCX_PMKOFF		10

#define HCX_HELP		'h'
#define HCX_VERSION		'v'

#define ESSIDLEN		32
#define PMKLEN			32
#define PMKASCLEN		64
#define PSKLEN			63

#define CPU_MAX			256

#define INPUTLINEMAX		1024
#define OUTPUTLINEMAX		1024
#define PMKLISTLEN		10000000L

#define UNCHECKED		0x00
#define CALCULATED		0x01
#define DOUBLEESSIDPSK		0x02
#define DOUBLEESSID		0x04
#define DOUBLEPSK		0x08
/*===========================================================================*/
/* struct */

typedef struct
{
 size_t	essidlen;
 size_t	psklen;
 u8	pmk[PMKLEN];
 u8	essid[ESSIDLEN];
 u8	psk[PSKLEN];
 u8	status;
} pmklist_t;
#define PMKRECLEN (sizeof(pmklist_t))
/*---------------------------------------------------------------------------*/
typedef struct
{
 pthread_t	thread_id;
 int		thread_num;
 int		cpucount;
 long		errorcount;
 long		calculatedcount;
 long		correctedcount;
 uint8_t	essidlen;
 uint8_t	psklen;
 uint8_t	pmk[PMKLEN];
 uint8_t	essid[ESSIDLEN];
 uint8_t	psk[PSKLEN];
} thread_info;
/*===========================================================================*/

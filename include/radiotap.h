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

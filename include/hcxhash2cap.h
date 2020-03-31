#define ESSID_LEN_MAX		32
#define PMKID_LINE_LEN		255
#define JOHN_LINE_LEN		1024
#define PMKIDEAPOL_LINE_LEN	1024
#define PMKIDEAPOL_BUFFER_LEN	1024
#define EAPOL_AUTHLEN_MAX	256

#define HCXP_CAP		'c'
#define HCXP_PMKID_EAPOL	'1'
#define HCXP_PMKID		'2'
#define HCXP_HCCAPX		'3'
#define HCXP_HCCAP		'4'
#define HCXP_JOHN		'5'
#define HCXP_HELP		'h'
#define HCXP_VERSION		'v'

#ifdef __BYTE_ORDER__
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_HOST
#endif
#else
#ifdef __OpenBSD__
# include <endian.h>
# if BYTE_ORDER == BIG_ENDIAN
#   define BIG_ENDIAN_HOST
# endif
#endif
#endif

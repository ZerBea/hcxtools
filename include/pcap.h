#define PCAPMAGICNUMBER 0xa1b2c3d4
#define PCAP_MAJOR_VER 2
#define PCAP_MINOR_VER 4
#define PCAP_SNAPLEN 0xffff
#define LINKTYPE_IEEE802_11_RADIOTAP 127
/*===========================================================================*/
struct pcap_hdr_s
{
 uint32_t magic_number;		/* magic number */
 uint16_t version_major;	/* major version number */
 uint16_t version_minor;	/* minor version number */
 int32_t thiszone;		/* GMT to local correction */
 uint32_t sigfigs;		/* accuracy of timestamps */
 uint32_t snaplen;		/* max length of captured packets, in octets */
 uint32_t network;		/* data link type */
} __attribute__((__packed__));
typedef struct pcap_hdr_s pcap_hdr_t;
#define	PCAPHDR_SIZE (sizeof(pcap_hdr_t))
/*===========================================================================*/
struct pcaprec_hdr_s
{
 uint32_t ts_sec;	/* timestamp seconds */
 uint32_t ts_usec;	/* timestamp microseconds */
 uint32_t incl_len;	/* number of octets of packet saved in file */
 uint32_t orig_len;	/* actual length of packet */
 uint8_t data[1];
} __attribute__((__packed__));
typedef struct pcaprec_hdr_s pcaprec_hdr_t;
#define	PCAPREC_SIZE offsetof(pcaprec_hdr_t, data)
/*===========================================================================*/

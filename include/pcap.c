#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stddef.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "pcap.h"

/*===========================================================================*/
bool pcapwritehdr(int fd, int linklayer)
{
pcap_hdr_t pcap_hdr;
int written;

memset(&pcap_hdr, 0, PCAPHDR_SIZE);
pcap_hdr.magic_number = PCAPMAGICNUMBER;
pcap_hdr.version_major = PCAP_MAJOR_VER;
pcap_hdr.version_minor = PCAP_MINOR_VER;
pcap_hdr.snaplen = PCAP_SNAPLEN;
pcap_hdr.network = linklayer;
written = write(fd, &pcap_hdr, PCAPHDR_SIZE);
if(written != PCAPHDR_SIZE) return false;
return true;
}
/*===========================================================================*/
int hcxopencapdump(char *capdumpname)
{
int fd;
int c;
struct stat statinfo;
char newcapdumpname[PATH_MAX +2];

c = 0;
strcpy(newcapdumpname, capdumpname);
while(stat(newcapdumpname, &statinfo) == 0)
	{
	snprintf(newcapdumpname, PATH_MAX, "%s_%d", capdumpname, c);
	c++;
	}

umask(0);
fd = open(newcapdumpname, O_WRONLY | O_CREAT, 0644);
if(fd == -1) return -1;
if(pcapwritehdr(fd, DLT_IEEE802_11) == false)
	{
	close(fd);
	return 0;
	}
return fd;
}
/*===========================================================================*/

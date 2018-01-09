#define _GNU_SOURCE
#include <stdbool.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fileops.h"

/*===========================================================================*/
int getmagicnumber(int fd)
{
int res;
magicnr_t mnr;

res = read(fd, &mnr, 4);
if(res != 4)
	{
	return 0;
	}
return mnr.magic_number;
}
/*===========================================================================*/

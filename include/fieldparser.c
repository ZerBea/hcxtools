#include "fieldparser.h"
/*===========================================================================*/
static ssize_t readhexfield(size_t flen, char fdelim, char *fin, u8 *fout)
{
static size_t c;
static size_t i;
static u8 idx0;
static u8 idx1;

i = 0;
for(c = 0; c < (flen * 2); c += 2)
	{
	if(fin[c] == 0) return -1;
	if(fin[c] == fdelim) return i;
	if(!isxdigit(fin[c])) return -1;
	if(!isxdigit(fin[c + 1])) return -1;
	idx0 = ((u8)fin[c + 0] & 0x1F) ^ 0x10;
	idx1 = ((u8)fin[c + 1] & 0x1F) ^ 0x10;
	fout[i] = (u8)(asciitable[idx0] << 4) | asciitable[idx1];
	i++;
	}
return i;
}
/*===========================================================================*/
static ssize_t readcharfield(size_t flen, char delim, char *fin, u8 *fout)
{
static size_t c;

for(c = 0; c < flen; c++)
	{
	if(fin[c] == 0) return c;
	if(fin[c] == delim) return c;
	fout[c] = (u8)(fin[c]);
	}
return c;
}
/*===========================================================================*/
static bool isfieldhexified(size_t flen,  char *fin)
{
if(flen < 5) return false;
if(fin[0] != '$') return false;
if(fin[1] != 'H') return false;
if(fin[2] != 'E') return false;
if(fin[3] != 'X') return false;
if(fin[4] != '[') return false;
return true;
}
/*===========================================================================*/

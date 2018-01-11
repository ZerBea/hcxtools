/*===========================================================================*/
bool isasciistring(int len, uint8_t *buffer)
{
uint8_t p;
for(p = 0; p < len; p++)
	{
	if((buffer[p] < 0x20) || (buffer[p] > 0x7e))
		{
		return false;
		}
	}
return true;
}
/*===========================================================================*/

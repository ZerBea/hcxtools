#include <stdbool.h>
#include <stddef.h>
#include "hashcatops.h"

/*===========================================================================*/
void writehccapxrecord(hcxl_t *zeiger, FILE *fho)
{
hccapx_t hccapx;
wpakey_t *wpak, *wpak2;

memset (&hccapx, 0, sizeof(hccapx_t));
hccapx.signature = HCCAPX_SIGNATURE;
hccapx.version   = HCCAPX_VERSION;
hccapx.message_pair = 0x80;
if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 4))
	{
	hccapx.message_pair = MESSAGE_PAIR_M12E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		hccapx.message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 4))
	{
	hccapx.message_pair = MESSAGE_PAIR_M32E2;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta +1)
		{
		hccapx.message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 1) && (zeiger->keyinfo_sta == 8))
	{
	hccapx.message_pair = MESSAGE_PAIR_M14E4;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta +1)
		{
		hccapx.message_pair |= 0x80;
		}
	}
else if((zeiger->keyinfo_ap == 2) && (zeiger->keyinfo_sta == 8))
	{
	hccapx.message_pair = MESSAGE_PAIR_M34E4;
	if(zeiger->replaycount_ap != zeiger->replaycount_sta)
		{
		hccapx.message_pair |= 0x80;
		}
	}

wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
hccapx.essid_len = zeiger->essidlen;
memcpy(&hccapx.essid, zeiger->essid, 32);
memcpy(&hccapx.mac_ap, zeiger->mac_ap, 6);
memcpy(&hccapx.nonce_ap, zeiger->nonce, 32);
memcpy(&hccapx.mac_sta, zeiger->mac_sta, 6);
memcpy(&hccapx.nonce_sta, wpak->nonce, 32);
hccapx.eapol_len = zeiger->authlen;
memcpy(&hccapx.eapol, zeiger->eapol, zeiger->authlen);
memcpy(&hccapx.keymic, wpak->keymic, 16);
wpak2 = (wpakey_t*)(hccapx.eapol +EAPAUTH_SIZE);
memset(wpak2->keymic, 0, 16);
hccapx.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
 #ifdef BIG_ENDIAN_HOST
hccapx.signature	= byte_swap_32(hccapx.signature);
hccapx.version		= byte_swap_32(hccapx.version);
hccapx.eapol_len	= byte_swap_16(hccapx.eapol_len);
#endif
fwrite (&hccapx, sizeof(hccapx_t), 1, fho);
return;
}
/*===========================================================================*/
void writehccaprecord(hcxl_t *zeiger, FILE *fho)
{
hccap_t hccap;
wpakey_t *wpak, *wpak2;

memset (&hccap, 0, sizeof(hccap_t));
wpak = (wpakey_t*)(zeiger->eapol +EAPAUTH_SIZE);
memcpy(&hccap.essid, zeiger->essid, 32);
memcpy(&hccap.mac1, zeiger->mac_ap, 6);
memcpy(&hccap.mac2, zeiger->mac_sta, 6);
memcpy(&hccap.nonce1, wpak->nonce, 32);
memcpy(&hccap.nonce2, zeiger->nonce, 32);

hccap.eapol_size = zeiger->authlen;
memcpy(&hccap.eapol, zeiger->eapol, zeiger->authlen);
memcpy(&hccap.keymic, wpak->keymic, 16);
wpak2 = (wpakey_t*)(hccap.eapol +EAPAUTH_SIZE);
memset(wpak2->keymic, 0, 16);
hccap.keyver = ntohs(wpak->keyinfo) & WPA_KEY_INFO_TYPE_MASK;
 #ifdef BIG_ENDIAN_HOST
hccap.eapolsize	= byte_swap_16(hccap.eapolsize);
#endif
fwrite (&hccap, sizeof(hccap_t), 1, fho);
return;
}
/*===========================================================================*/

extern const char *filterstring;

/*===========================================================================*/
/* Berkeley Packet Filter (BPF) - Blacklist */
/* pay attention: the hard-coded BPF is used by wlandump-ng, wlanresponse and wlancap2hcx */

const char *filterstring = "!(wlan host 00:00:00:00:00:00 || wlan src 00:00:00:00:00:00)";

/*===========================================================================*/

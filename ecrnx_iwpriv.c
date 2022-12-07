/**
 ******************************************************************************
 *
 * @file ecrnx_iwpriv.c
 *
 * @brief iwpriv function definitions
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ******************************************************************************
 */

/**
 * INCLUDE FILES
 ******************************************************************************
 */
#include <net/cfg80211.h>
#include <net/iw_handler.h>
#include "ecrnx_defs.h"
#include "eswin_utils.h"
#include <linux/if_arp.h>

#ifdef CONFIG_ECRNX_WIFO_CAIL
#include "ecrnx_amt.h"
#include "core.h"
#endif

#ifdef CONFIG_WIRELESS_EXT

enum
{
    /// BSS is QoS capable
    BSS_QOS_CAPA = CO_BIT(0),
    /// BSS is HT capable
    BSS_HT_CAPA = CO_BIT(1),
    /// BSS is VHT capable
    BSS_VHT_CAPA = CO_BIT(2),
    /// BSS is HE capable
    BSS_HE_CAPA = CO_BIT(3),
    /// BSS is short preamble capable
    BSS_SHORT_PREAMBLE_CAPA = CO_BIT(4),
    #if 0
    BSS_TWT_CAPA = CO_BIT(5),
    #endif
    /// Information about the BSS are valid
    BSS_VALID_CAPA = CO_BIT(31),
};

#define SCAN_ITEM_SIZE 768
#define MAX_SCAN_BUFFER_LEN 65535

#define BSS_CAPA(capa_flags, type) ((capa_flags & BSS_##type##_CAPA) != 0)

u8_l rate_table_g[8] = {12, 18, 24, 36, 48, 72, 96, 108};

u32 rates[] = {1000000, 2000000, 5500000, 11000000,
	6000000, 9000000, 12000000, 18000000, 24000000, 36000000, 48000000, 54000000};

uint8_t rate_table[4][5] = {
        {150, 120, 60, 45, 15},
        {72, 57, 28, 21, 7},
        {114, 77, 51, 25, 8},
        {54, 36, 18, 9, 1}
};

#define MIN_FRAG_THRESHOLD     256U
#define	MAX_FRAG_THRESHOLD     2346U

int chtofreq(int chan)
{
	if (chan >= 1 && chan <= 14) {
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
	} else if (chan >= 36 && chan <= 177)
		return 5000 + chan * 5;

	return 0;
}

bool is_bss_support_g(struct mac_rateset *rateset)
{
    u8 i = 0, j = 0;

    for (i = 0; i < rateset->length; i++)
    {
        for(j = 0; j < 8; j++)
        {
            if(rate_table_g[j] == (rateset->array[i] & 0x7f))
                return true;
        }
    }
    return false;
}

/*
0:b
1:bg
2:bgn
3:bgnax
4:ax
5:n
*/
uint8_t ecrnx_get_bss_mode(uint32_t bss_cap, struct mac_rateset *rateset)
{

    uint8_t mode = 100;
    bool flag_11g = true;
    int i;

    flag_11g = is_bss_support_g(rateset);
    if(BSS_CAPA(bss_cap, HT) && BSS_CAPA(bss_cap, HE))
    {
        mode = 3;
    }
    else if (BSS_CAPA(bss_cap, HE))
    {
        mode = 4;
    }
    else if(BSS_CAPA(bss_cap, HT) && flag_11g)
    {
        mode = 2;
    }
    else if(BSS_CAPA(bss_cap, HT))
    {
        mode = 5;
    }
    else if(flag_11g)
    {
        mode = 1;
    }
    else
    {
        mode = 0;
    }

    return mode;
}


/**
 * FUNCTION DEFINITIONS
 ******************************************************************************
 */
#define IN
#define OUT

#ifdef CONFIG_WEXT_PRIV
 /* This may be wrong. When using the new SIOCIWFIRSTPRIV range, we probably
  * should use only "GET" ioctls (last bit set to 1). "SET" ioctls are root
  * only and don't return the modified struct ifreq to the application which
  * is usually a problem. - Jean II */
#ifdef CONFIG_ECRNX_WIFO_CAIL
#define IOCTL_IWPRIV_AMT                (SIOCIWFIRSTPRIV + 1)
#endif
#define IOCTL_IWPRIV_WD                 (SIOCIWFIRSTPRIV + 3)

#if 0
static int priv_set_int(IN struct net_device *prNetDev,
          IN struct iw_request_info *prIwReqInfo,
          IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    int *flag = (int*)pcExtra;
    ecrnx_printk_wext("cmd=%x, flags=%x\n",
      prIwReqInfo->cmd, prIwReqInfo->flags);
    ecrnx_printk_wext("mode=%x, flags=%x\n",
      prIwReqData->mode, prIwReqData->data.flags);
    *flag = 0x1234;
    prIwReqData->param.value = 0x1230;

    return 1;
}

/*----------------------------------------------------------------------------*/
/*!
* \brief Private ioctl get int handler.
*
* \param[in] pDev Net device requested.
* \param[out] pIwReq Pointer to iwreq structure.
* \param[in] prIwReqData The ioctl req structure, use the field of sub-command.
* \param[out] pcExtra The buffer with put the return value
*
* \retval 0 For success.
* \retval -EOPNOTSUPP If cmd is not supported.
* \retval -EFAULT For fail.
*
*/
/*----------------------------------------------------------------------------*/
static int priv_get_int(IN struct net_device *prNetDev,
      IN struct iw_request_info *prIwReqInfo,
      IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    int status = 0;
    prIwReqData->mode = 0xabcd;
    return status;
}               /* __priv_get_int */

static int priv_set_struct(IN struct net_device *prNetDev,
       IN struct iw_request_info *prIwReqInfo,
       IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
  ecrnx_printk_wext("cmd=%x, flags=%x\n",
       prIwReqInfo->cmd, prIwReqInfo->flags);
  ecrnx_printk_wext("mode=%x, flags=%x\n",
       prIwReqData->mode, prIwReqData->data.flags);

  return 0;
  //return compat_priv(prNetDev, prIwReqInfo,
  //     prIwReqData, pcExtra, __priv_set_struct);
}

static int priv_get_struct(IN struct net_device *prNetDev,
       IN struct iw_request_info *prIwReqInfo,
       IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    ecrnx_printk_wext("cmd=%x, flags=%x\n",
       prIwReqInfo->cmd, prIwReqInfo->flags);
    ecrnx_printk_wext("mode=%x, flags=%x\n",
       prIwReqData->mode, prIwReqData->data.flags);

    prIwReqData->data.length = 6;
    memcpy(pcExtra, "ecrnx", 6);
    return 0;

}

static int priv_get_mac(IN struct net_device *prNetDev,
     IN struct iw_request_info *prIwReqInfo,
     IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    struct sockaddr *dst = (struct sockaddr *) pcExtra;
    struct ecrnx_vif *vif;
    dbg_req_t req;

    req.dbg_level = DBG_TYPE_D;
    req.direct = 0;

    vif = netdev_priv(prNetDev);
    //send cmd to slave
    ecrnx_printk_wext("priv_get_mac: send cmd to slave \n");
    host_send(&req, sizeof(dbg_req_t), TX_FLAG_IWPRIV_IE);
    //wait for slave confirm
    vif->rxdatas = 0;
    wait_event_interruptible_timeout(vif->rxdataq, vif->rxdatas, 2*HZ);

    ecrnx_printk_wext("priv_get_mac: rx_len:%d \n", vif->rxlen);
    if (!vif->rxlen)
        return -1;

    prIwReqData->data.length = vif->rxlen;
    memcpy(dst->sa_data, vif->rxdata, vif->rxlen);
    dst->sa_family = 1;
    prIwReqData->data.length = 1;

    return 0;
}

static int priv_get_vers(IN struct net_device *prNetDev,
      IN struct iw_request_info *prIwReqInfo,
      IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    ecrnx_printk_wext("get vers cmd=%x, flags=%x\n", prIwReqInfo->cmd, prIwReqInfo->flags);
    ecrnx_printk_wext("mode=%x, flags=%x\n", prIwReqData->mode, prIwReqData->data.flags);

   memcpy(pcExtra, "1.0.1", 6);
   prIwReqData->data.length = 6;

    return 0;
}


static int priv_set_debug_level(IN struct net_device *prNetDev,
      IN struct iw_request_info *prIwReqInfo,
      IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    ecrnx_printk_wext("priv_set_debug_level cmd=%x, flags=%x\n",
    prIwReqInfo->cmd, prIwReqInfo->flags);
    ecrnx_printk_wext("mode=%x, flags=%x\n",
    prIwReqData->mode, prIwReqData->data.flags);

    ecrnx_printk_wext("param_value:%d \n", prIwReqData->param.value);

    ecrnx_dbg_level = prIwReqData->param.value;
    return 0;
}
#endif

#ifdef CONFIG_ECRNX_WIFO_CAIL
static int priv_amt(IN struct net_device *prNetDev,
     IN struct iw_request_info *prIwReqInfo,
     IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    struct sockaddr *dst = (struct sockaddr *) pcExtra;

	if (amt_mode == false) {
		ecrnx_printk_err(" The current mode does not support the AMT commands!!\n");
		return -1;
	}
//	printk("buff:%s, len:%d\n", prIwReqData->data.pointer, prIwReqData->data.length);
    //send cmd to slave
    char *reqdata = kzalloc(prIwReqData->data.length, GFP_KERNEL);
    if (!reqdata){
        return 0;
    }
    if (copy_from_user(reqdata, prIwReqData->data.pointer, prIwReqData->data.length)) {
        return 0;
    }
    host_send(reqdata, prIwReqData->data.length, TX_FLAG_AMT_IWPRIV_IE);
    kfree(reqdata);

    //wait for slave confirm
    amt_vif.rxdatas = 0;
	amt_vif.rxlen = 0;

    wait_event_interruptible_timeout(amt_vif.rxdataq, amt_vif.rxdatas, 2*HZ);

    ecrnx_printk_wext("rxdatas: rx_len:%d, rxdata:[%s]\n", amt_vif.rxlen,amt_vif.rxdata);
    if (!amt_vif.rxdatas){
        return -1;
    }

	prIwReqData->data.length = amt_vif.rxlen;
	memcpy(dst->sa_data, amt_vif.rxdata, amt_vif.rxlen);
	dst->sa_family = 1;
	memcpy(pcExtra, amt_vif.rxdata, amt_vif.rxlen);

    return 0;
}
#endif

static struct ecrnx_vif *get_priv_vif(struct ecrnx_hw *ecrnx_hw)
{
    int i;

    for(i = 0; i < NX_VIRT_DEV_MAX + NX_REMOTE_STA_MAX; i++) {
        if (ecrnx_hw->vif_table[i]) {
            return ecrnx_hw->vif_table[i];
        }
    }

    ecrnx_printk_err("get_priv_vif is null");
    return NULL;
}

void priv_copy_data_wakeup(struct ecrnx_hw *ecrnx_hw, struct sk_buff *skb)
{
    struct ecrnx_vif* ecrnx_vif = get_priv_vif(ecrnx_hw);

    ecrnx_printk_wext("iw_cfm vif_start:%d, vif_monitor:%d \n", ecrnx_hw->vif_started, ecrnx_hw->monitor_vif);
    //print_hex_dump(KERN_INFO, DBG_PREFIX_IW_CFM, DUMP_PREFIX_ADDRESS, 32, 1, skb->data, skb->len, false);
    if (ECRNX_RXSIZE > skb->len) {
        ecrnx_vif->rxlen = skb->len;
    } else {
        ecrnx_vif->rxlen = ECRNX_RXSIZE;
    }

    memcpy(ecrnx_vif->rxdata, skb->data, ecrnx_vif->rxlen);
    ecrnx_vif->rxdatas = 1;
    wake_up(&ecrnx_vif->rxdataq);
}

static int priv_wd(IN struct net_device *prNetDev,
     IN struct iw_request_info *prIwReqInfo,
     IN union iwreq_data *prIwReqData, IN OUT char *pcExtra)
{
    struct sockaddr *dst = (struct sockaddr *) pcExtra;
    struct ecrnx_vif *vif;

    //printk("priv_wd:%s, len:%d\n", prIwReqData->data.pointer, prIwReqData->data.length);
    //send cmd to slave
    char *reqdata = kzalloc(prIwReqData->data.length, GFP_KERNEL);
    if (!reqdata){
        return 0;
    }

    if (copy_from_user(reqdata, prIwReqData->data.pointer, prIwReqData->data.length)) {
        return 0;
    }
    host_send(reqdata, prIwReqData->data.length, TX_FLAG_IWPRIV_IE);
    kfree(reqdata);

    //wait for slave confirm
    vif = netdev_priv(prNetDev);
    vif = get_priv_vif(vif->ecrnx_hw);
    if (!vif) {
         return 0;
    }
    vif->rxdatas = 0;
    wait_event_interruptible_timeout(vif->rxdataq, vif->rxdatas, 2*HZ);

    if (!vif->rxdatas)
        return -1;
    
    ecrnx_printk_wext("priv_wd: rx_len:%d rxdata:[%s]\n", vif->rxlen, vif->rxdata);
    prIwReqData->data.length = vif->rxlen;
    memcpy(dst->sa_data, vif->rxdata, vif->rxlen);
    dst->sa_family = 1;
    memcpy(pcExtra, vif->rxdata, vif->rxlen);

    return 0;
}

/*
 * Structures to export the Wireless Handlers
 */
static const struct iw_priv_args ecrnx_wext_private_args[] = {
#ifdef CONFIG_ECRNX_WIFO_CAIL
	{IOCTL_IWPRIV_AMT, IW_PRIV_TYPE_CHAR | 2000, IW_PRIV_TYPE_CHAR | 2000, "amt"},
#endif
    {IOCTL_IWPRIV_WD, IW_PRIV_TYPE_CHAR | 2000, IW_PRIV_TYPE_CHAR | 2000, "wd"},
};

const iw_handler ecrnx_wext_private_handler[] = {
#ifdef CONFIG_ECRNX_WIFO_CAIL
    [IOCTL_IWPRIV_AMT - SIOCIWFIRSTPRIV] = priv_amt,
#endif
    [IOCTL_IWPRIV_WD - SIOCIWFIRSTPRIV] = priv_wd,
};

#endif

/*------------------------------------------------------------------*/
/*
* Commit handler : called after a bunch of SET operations
*/
static int ecrnx_wext_config_commit(struct net_device *dev,
               struct iw_request_info *info, /* NULL */
               void *zwrq,           /* NULL */
               char *extra)          /* NULL */
{
    return 1;
}

static int ecrnx_wext_get_name(struct net_device *dev,
        struct iw_request_info *info,
        IN union iwreq_data *prIwReqData,
        char *extra)
{
    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    struct ecrnx_sta *sta = NULL;
    struct mac_rateset *rate_set;
    uint8_t bss_mode = 0;
    ecrnx_printk_wext("%s\n", __func__);
    if(ecrnx_vif->sta.ap != NULL)
    {
        sta = ecrnx_vif->sta.ap;
        rate_set = &sta->rate_set;
        bss_mode = ecrnx_get_bss_mode(sta->bss_cap, rate_set);
        ecrnx_printk_wext("%s sta=%d\n", __func__, bss_mode);
        switch(bss_mode)
        {
            case 0:
                strcpy(prIwReqData->name, "802.11b");
                break;
            case 1:
                strcpy(prIwReqData->name, "802.11bg");
                break;
            case 2:
                strcpy(prIwReqData->name, "802.11bgn");
                break;
            case 3:
                strcpy(prIwReqData->name, "802.11bgnax");
                break;
            case 4:
                strcpy(prIwReqData->name, "802.11ax");
                break;
            case 5:
                strcpy(prIwReqData->name, "802.11n");
                break;
            default :
                strcpy(prIwReqData->name, "unassociated");
        }
    }
    else
    {
        strcpy(prIwReqData->name, "unassociated");
    }
    return 0;
}

/*------------------------------------------------------------------*/
/*
 * Wireless Handler : set frequency
 */
static int ecrnx_wext_set_freq(struct net_device *dev,
             struct iw_request_info *info,
             struct iw_freq *fwrq,
             char *extra)
{
    int rc = -EINPROGRESS;      /* Call commit handler */
    ecrnx_printk_wext("fwrq->e:%d, fwrq->m:%d \n", fwrq->e, fwrq->m);
    return rc;
}

/*------------------------------------------------------------------*/
/*
 * Wireless Handler : get frequency
 */
static int ecrnx_wext_get_freq(struct net_device *dev,
             struct iw_request_info *info,
             struct iw_freq *fwrq,
             char *extra)
{
    ecrnx_printk_wext("%s\n", __func__);
    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    struct ecrnx_sta *sta = NULL;
    if(ecrnx_vif->sta.ap != NULL)
    {
        sta = ecrnx_vif->sta.ap;
        fwrq->m = 100000 * sta->center_freq;
    }
    else
    {
        fwrq->m = 100000 * 2412;
    }

    fwrq->e = 1;
    return 0;
}

/*------------------------------------------------------------------*/
/*
 * Wireless Handler : set Mode of Operation
 */
static int ecrnx_wext_set_mode(struct net_device *dev,
             struct iw_request_info *info,
             __u32 *uwrq,
             char *extra)
{
    ecrnx_printk_wext("*uwrq:%d \n", *uwrq);
    return -EINPROGRESS;        /* Call commit handler */
}

/*------------------------------------------------------------------*/
/*
 * Wireless Handler : get Mode of Operation
 */
static int ecrnx_wext_get_mode(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{
    ecrnx_printk_wext("%s\n", __func__);

    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    prIwReqData->mode = IW_MODE_INFRA;
    return 0;
}

static int ecrnx_wext_get_essid(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{

    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    ecrnx_printk_wext("%s\n", __func__);
    if(ecrnx_vif->sta.ap != NULL)
    {
        prIwReqData->essid.length = ecrnx_vif->ssidLength;
        memcpy(extra, ecrnx_vif->ssid, ecrnx_vif->ssidLength);
        prIwReqData->essid.flags = 1;
        return 0;
    }
    else
    {
        return -1;
    }

}

static int ecrnx_wext_get_nick(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{
	if (extra) {
		prIwReqData->data.length = 12;
		prIwReqData->data.flags = 1;
		memcpy(extra, "<WIFI@ESWIN>", 12);
	}
	return 0;
}

static int ecrnx_wext_set_rate(struct net_device *dev,
             struct iw_request_info *info,
             __u32 *uwrq,
             char *extra)
{
   *uwrq = 0xFFEE;
    return 0;
}

uint8_t get_rssi_to_max_rate(uint8_t rate[], int rssi)
{
    if(rssi > -35)
    {
        return rate[0];
    }
    else if(rssi <= -35 && rssi > -50)
    {
        return rate[1];
    }
    else if(rssi <= -50 && rssi > -60)
    {
        return rate[2];
    }
    else if(rssi <= -60 && rssi > -70)
    {
        return rate[3];
    }
    else
    {
        return rate[4];
    }
}

static int ecrnx_wext_get_rate(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{
    uint8_t max_rate = 0, bss_mode = 0;
    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    struct mac_rateset *rate_set;

    ecrnx_printk_wext("%s\n", __func__);
    struct ecrnx_sta *sta = NULL;
    if(ecrnx_vif->sta.ap != NULL)
    {
        sta = ecrnx_vif->sta.ap;
        rate_set = &sta->rate_set;
        bss_mode = ecrnx_get_bss_mode(sta->bss_cap, rate_set);
        switch(bss_mode)
        {
            case 2:
            case 5:
                if(sta->center_freq == sta->center_freq1)
                {
                    max_rate=get_rssi_to_max_rate(rate_table[1], sta->rssi);
                }
                else
                {
                    max_rate=get_rssi_to_max_rate(rate_table[0], sta->rssi);
                }
                break;
            case 3:
            case 4:
                    max_rate=get_rssi_to_max_rate(rate_table[2], sta->rssi);
                break;
            default:
                    max_rate=get_rssi_to_max_rate(rate_table[3], sta->rssi);
                break;
        }
    }

    prIwReqData->bitrate.fixed = 0;
    prIwReqData->bitrate.value = max_rate * 1000000;
    return 0;
}

static int ecrnx_wext_get_wap(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{
    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    struct ecrnx_sta *sta = NULL;
    ecrnx_printk_wext("%s\n", __func__);

    prIwReqData->ap_addr.sa_family = ARPHRD_ETHER;
    memset(prIwReqData->ap_addr.sa_data, 0, ETH_ALEN);
    if(ecrnx_vif->sta.ap != NULL)
    {
        sta = ecrnx_vif->sta.ap;
        memcpy(prIwReqData->ap_addr.sa_data, sta->mac_addr, ETH_ALEN);
    }

    return 0;
}

static int ecrnx_wext_get_range(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{
    struct iw_range *range = (struct iw_range *)extra;
    u16 val = 0;
    int i;
    prIwReqData->data.length = sizeof(*range);
    memset(range, 0, sizeof(*range));

    range->throughput = 5 * 1000 * 1000;
    range->max_qual.qual = 100;

    /* percent values between 0 and 100. */
    range->max_qual.level = 100;
    range->max_qual.noise = 100;
    range->max_qual.updated = IW_QUAL_ALL_UPDATED; /* Updated all three */

    range->avg_qual.qual = 92; /* > 8% missed beacons is 'bad' */

    range->avg_qual.level = 30;
    range->avg_qual.noise = 100;
    range->avg_qual.updated = IW_QUAL_ALL_UPDATED; /* Updated all three */

    range->num_bitrates = 4;

    for (i = 0; i < 4 && i < IW_MAX_BITRATES; i++)
        range->bitrate[i] = rates[i];

    range->min_frag = MIN_FRAG_THRESHOLD;
    range->max_frag = MAX_FRAG_THRESHOLD;

    range->pm_capa = 0;

    range->we_version_compiled = WIRELESS_EXT;
    range->we_version_source = 16;

    range->num_channels = val;
    range->num_frequency = val;

#if WIRELESS_EXT > 17
    range->enc_capa = IW_ENC_CAPA_WPA | IW_ENC_CAPA_WPA2 |
                    IW_ENC_CAPA_CIPHER_TKIP | IW_ENC_CAPA_CIPHER_CCMP;
#endif

#ifdef IW_SCAN_CAPA_ESSID /* WIRELESS_EXT > 21 */
    range->scan_capa = IW_SCAN_CAPA_ESSID | IW_SCAN_CAPA_TYPE | IW_SCAN_CAPA_BSSID |
                    IW_SCAN_CAPA_CHANNEL | IW_SCAN_CAPA_MODE | IW_SCAN_CAPA_RATE;
#endif

    return 0;
}

static inline char *iw_stream_mac_addr_proess(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{
    /*  AP MAC address */
    iwe->cmd = SIOCGIWAP;
    iwe->u.ap_addr.sa_family = ARPHRD_ETHER;

    memcpy(iwe->u.ap_addr.sa_data, pnetwork->bssid, ETH_ALEN);
    start = iwe_stream_add_event(info, start, stop, iwe, IW_EV_ADDR_LEN);
    return start;
}

static inline char *iw_stream_essid_proess(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{

    /* Add the ESSID */
    iwe->cmd = SIOCGIWESSID;
    iwe->u.data.flags = 1;
    iwe->u.data.length = pnetwork->ssid_len;
    start = iwe_stream_add_point(info, start, stop, iwe, pnetwork->ssid);
    return start;
}

static inline char *iw_stream_chan_proess(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{

    iwe->cmd = SIOCGIWFREQ;
    iwe->u.freq.m =  100000 * chtofreq(pnetwork->ch);
    iwe->u.freq.e = 1;
    iwe->u.freq.i = pnetwork->ch;
    start = iwe_stream_add_event(info, start, stop, iwe, IW_EV_FREQ_LEN);
    return start;
}

static inline char *iw_stream_encryption_process(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{
    iwe->cmd = SIOCGIWENCODE;
    if (pnetwork->cap & BIT(4))
        iwe->u.data.flags = IW_ENCODE_ENABLED | IW_ENCODE_NOKEY;
    else
        iwe->u.data.flags = IW_ENCODE_DISABLED;
    iwe->u.data.length = 0;
    start = iwe_stream_add_point(info, start, stop, iwe, pnetwork->ssid);
    return start;
}

static inline char *iw_stream_rate_process(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{
    uint8_t max_rate = 0;

    if (pnetwork->bss_protol & BIT(0)) {
        if(pnetwork->ht_cap & 0x0002)
        {
            max_rate = get_rssi_to_max_rate(rate_table[0], pnetwork->rssi);
        }
        else
        {
            max_rate = get_rssi_to_max_rate(rate_table[1], pnetwork->rssi);
        }
    }
    else if(pnetwork->bss_protol & BIT(1))
    {
        max_rate = get_rssi_to_max_rate(rate_table[1], pnetwork->rssi);
    }
    else if(pnetwork->bss_protol & (BIT(2)|BIT(3)))
    {
        max_rate = get_rssi_to_max_rate(rate_table[2], pnetwork->rssi);
    }
    else
    {
        max_rate = get_rssi_to_max_rate(rate_table[3], pnetwork->rssi);
    }

    iwe->cmd = SIOCGIWRATE;
    iwe->u.bitrate.fixed = iwe->u.bitrate.disabled = 0;
    iwe->u.bitrate.value = max_rate * 1000000;
    start = iwe_stream_add_event(info, start, stop, iwe, IW_EV_PARAM_LEN);
    return start;
}

static inline char *iw_stream_mode_process(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{
    if (pnetwork->cap & (BIT(0) | BIT(1))) {
        iwe->cmd = SIOCGIWMODE;
        if (pnetwork->cap & BIT(0))
            iwe->u.mode = IW_MODE_MASTER;
        else
            iwe->u.mode = IW_MODE_ADHOC;

        start = iwe_stream_add_event(info, start, stop, iwe, IW_EV_UINT_LEN);
    }
    return start;
}

static inline char *iw_stream_protocol_process(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{

    iwe->cmd = SIOCGIWNAME;
    if (pnetwork->bss_protol & BIT(0)) {
        snprintf(iwe->u.name, IFNAMSIZ, "802.11bgn");
    }
    else if(pnetwork->bss_protol & BIT(1))
    {
        snprintf(iwe->u.name, IFNAMSIZ, "802.11bg");
    }
    else if(pnetwork->bss_protol & BIT(2))
    {
        snprintf(iwe->u.name, IFNAMSIZ, "802.11bgnax");
    }
    else if(pnetwork->bss_protol & BIT(3))
    {
        snprintf(iwe->u.name, IFNAMSIZ, "802.11ax");
    }
    else
    {
        snprintf(iwe->u.name, IFNAMSIZ, "802.11b");
    }
    start = iwe_stream_add_event(info, start, stop, iwe, IW_EV_CHAR_LEN);
    return start;
}

static inline char *iw_stream_rssi_process(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{
    iwe->cmd = IWEVQUAL;
    iwe->u.qual.updated = 0x1 | 0x2 | 0x40;
    iwe->u.qual.level = -(pnetwork->rssi);
    if(iwe->u.qual.level < 35)
    {
        iwe->u.qual.qual = 100;
    }
    else if(iwe->u.qual.level < 50 && iwe->u.qual.level >= 35)
    {
        iwe->u.qual.qual = 75;
    }
    else if(iwe->u.qual.level < 65 && iwe->u.qual.level >= 50)
    {
        iwe->u.qual.qual = 55;
    }
    else if(iwe->u.qual.level < 80 && iwe->u.qual.level >= 65)
    {
        iwe->u.qual.qual = 20;
    }
    else
    {
        iwe->u.qual.qual = 0;
    }

    iwe->u.qual.noise = 0;
    start = iwe_stream_add_event(info, start, stop, iwe, IW_EV_QUAL_LEN);
    return start;
}

static inline char *iw_stream_wpa_wpa2_process(struct iw_request_info *info,
        struct wlan_network *pnetwork,
        char *start, char *stop, struct iw_event *iwe)
{
    u8 *pbuf = kzalloc(256, GFP_KERNEL);
    u8 wpa_len = 0, rsn_len = 0, i;
    u8 *p;
    if (pbuf && (pnetwork->cap & BIT(4)))
    {
        wpa_len = pnetwork->wpa_ie[1] + 2;
        rsn_len = pnetwork->rsn_ie[1] + 2;
        p = pbuf;

        if (pnetwork->wpa_ie[1] > 0) {
            p += sprintf(p, "wpa_ie=");
            for (i = 0; i < wpa_len; i++)
                p += sprintf(p, "%02x", pnetwork->wpa_ie[i]);

            if (wpa_len > 100) {
                printk("-----------------Len %d----------------\n", wpa_len);
                for (i = 0; i < wpa_len; i++)
                    printk("%02x ", pnetwork->wpa_ie[i]);
                printk("\n");
                printk("-----------------Len %d----------------\n", wpa_len);
            }

            memset(iwe, 0, sizeof(*iwe));
            iwe->cmd = IWEVCUSTOM;
            iwe->u.data.length = strlen(pbuf);
            start = iwe_stream_add_point(info, start, stop, iwe, pbuf);

            memset(iwe, 0, sizeof(*iwe));
            iwe->cmd = IWEVGENIE;
            iwe->u.data.length = wpa_len;
            start = iwe_stream_add_point(info, start, stop, iwe, pnetwork->wpa_ie);
        }

        if (pnetwork->rsn_ie[1] > 0) {

            memset(pbuf, 0, 256);
            p += sprintf(p, "rsn_ie=");
            for (i = 0; i < rsn_len; i++)
                p += sprintf(p, "%02x", pnetwork->rsn_ie[i]);
            memset(iwe, 0, sizeof(*iwe));
            iwe->cmd = IWEVCUSTOM;
            iwe->u.data.length = strlen(pbuf);
            start = iwe_stream_add_point(info, start, stop, iwe, pbuf);

            memset(iwe, 0, sizeof(*iwe));
            iwe->cmd = IWEVGENIE;
            iwe->u.data.length = rsn_len;
            start = iwe_stream_add_point(info, start, stop, iwe, pnetwork->rsn_ie);
        }
    }
    kfree(pbuf);
    return start;
}

static char *translate_scan(struct iw_request_info *info, struct wlan_network *pnetwork,
		char *start, char *stop)
{
    struct iw_event iwe;
    memset(&iwe, 0, sizeof(iwe));

    start = iw_stream_mac_addr_proess(info, pnetwork, start, stop, &iwe);
    start = iw_stream_essid_proess(info, pnetwork, start, stop, &iwe);
    start = iw_stream_protocol_process(info, pnetwork, start, stop, &iwe);

    start = iw_stream_mode_process(info, pnetwork, start, stop, &iwe);
    start = iw_stream_chan_proess(info, pnetwork, start, stop, &iwe);
    start = iw_stream_encryption_process(info, pnetwork, start, stop, &iwe);
    start = iw_stream_rate_process(info, pnetwork, start, stop, &iwe);
    start = iw_stream_wpa_wpa2_process(info, pnetwork, start, stop, &iwe);
    start = iw_stream_rssi_process(info, pnetwork, start, stop, &iwe);

    return start;
}

static int ecrnx_wext_get_scan(struct net_device *dev,
             struct iw_request_info *info,
             IN union iwreq_data *prIwReqData,
             char *extra)
{
    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    struct ecrnx_hw *ecrnx_hw = ecrnx_vif->ecrnx_hw;
    struct wlan_network *entry;
    char *ev = extra;
    char *stop = ev + prIwReqData->data.length;
    u32 wait_for_surveydone;
    u32 ret = 0;

    struct wireless_dev *wdev;
    wdev = &ecrnx_vif->wdev;

    ecrnx_printk_wext("%s\n", __func__);
    if(strncmp(wdev->netdev->name, "wlan0", 5))
    {
        ecrnx_printk_wext("no support interface %s.\n", wdev->netdev->name);
        return -1;
    }

    list_for_each_entry(entry, &ecrnx_hw->scan_list, list) {
        if ((stop - ev) < SCAN_ITEM_SIZE) {
            if(prIwReqData->data.length == MAX_SCAN_BUFFER_LEN){ /*max buffer len defined by iwlist*/
                ret = 0;
                break;
            }
            ret = -E2BIG;
            break;
        }
        ev = translate_scan(info, entry, ev, stop);
    }

    prIwReqData->data.length = ev - extra;
    prIwReqData->data.flags = 0;
    return ret;
}

#if WIRELESS_EXT >= 17
static struct iw_statistics *ecrnx_get_wireless_stats(struct net_device *dev)
{
    struct ecrnx_vif *ecrnx_vif = netdev_priv(dev);
    struct iw_statistics *iwstats = &ecrnx_vif->iwstats;
    struct ecrnx_sta *sta = NULL;
    int tmp_level = 0;
    int tmp_qual = 0;
    int tmp_noise = 0;

    ecrnx_printk_wext("%s\n", __func__);
    if(ecrnx_vif->sta.ap != NULL)
    {
        sta = ecrnx_vif->sta.ap;
        iwstats->qual.level = -(sta->rssi);
        if(iwstats->qual.level < 35)
            iwstats->qual.qual = 100;
        else if(iwstats->qual.level < 50 && iwstats->qual.level >= 35)
            iwstats->qual.qual = 75;
        else if(iwstats->qual.level < 65 && iwstats->qual.level >= 50)
            iwstats->qual.qual = 55;
        else if(iwstats->qual.level < 80 && iwstats->qual.level >= 65)
            iwstats->qual.qual = 20;
        else
            iwstats->qual.qual = 0;

        iwstats->qual.noise = 0;
    }
    return &ecrnx_vif->iwstats;
}
#endif
static int dummy(struct net_device *dev,
             struct iw_request_info *info,
             __u32 *uwrq,
             char *extra)
{
	return -1;
}

static const iw_handler     ecrnx_wext_handler[] =
{
	(iw_handler)ecrnx_wext_config_commit,    /* SIOCSIWCOMMIT */
	(iw_handler)ecrnx_wext_get_name,		/* SIOCGIWNAME */
	(iw_handler)dummy,					/* SIOCSIWNWID */
	(iw_handler)dummy,					/* SIOCGIWNWID */
	(iw_handler)ecrnx_wext_set_freq,		/* SIOCSIWFREQ */
	(iw_handler)ecrnx_wext_get_freq,		/* SIOCGIWFREQ */
	(iw_handler)ecrnx_wext_set_mode,		/* SIOCSIWMODE */
	(iw_handler)ecrnx_wext_get_mode,		/* SIOCGIWMODE */
	(iw_handler)dummy,					/* SIOCSIWSENS */
	NULL,//ecrnx_wext_get_sens,		/* SIOCGIWSENS */
	NULL,					/* SIOCSIWRANGE */
	(iw_handler)ecrnx_wext_get_range,		/* SIOCGIWRANGE */
	NULL,//ecrnx_wext_set_priv,		/* SIOCSIWPRIV */
	NULL,					/* SIOCGIWPRIV */
	NULL,					/* SIOCSIWSTATS */
	NULL,					/* SIOCGIWSTATS */
	(iw_handler)dummy,					/* SIOCSIWSPY */
	(iw_handler)dummy,					/* SIOCGIWSPY */
	NULL,					/* SIOCGIWTHRSPY */
	NULL,					/* SIOCWIWTHRSPY */
	NULL,//ecrnx_wext_set_wap,		/* SIOCSIWAP */
	(iw_handler)ecrnx_wext_get_wap,		/* SIOCGIWAP */
	NULL,//ecrnx_wext_set_mlme,		/* request MLME operation; uses struct iw_mlme */
	(iw_handler)dummy,					/* SIOCGIWAPLIST -- depricated */
	NULL,//ecrnx_wext_set_scan,		/* SIOCSIWSCAN */
	(iw_handler)ecrnx_wext_get_scan,		/* SIOCGIWSCAN */
	NULL,//ecrnx_wext_set_essid,		/* SIOCSIWESSID */
	(iw_handler)ecrnx_wext_get_essid,		/* SIOCGIWESSID */
	(iw_handler)dummy,					/* SIOCSIWNICKN */
	(iw_handler)ecrnx_wext_get_nick,		/* SIOCGIWNICKN */
	NULL,					/* -- hole -- */
	NULL,					/* -- hole -- */
	(iw_handler)ecrnx_wext_set_rate,		/* SIOCSIWRATE */
	(iw_handler)ecrnx_wext_get_rate,		/* SIOCGIWRATE */
	NULL,//ecrnx_wext_set_rts,			/* SIOCSIWRTS */
	NULL,//ecrnx_wext_get_rts,			/* SIOCGIWRTS */
	NULL,//ecrnx_wext_set_frag,		/* SIOCSIWFRAG */
	NULL,//ecrnx_wext_get_frag,		/* SIOCGIWFRAG */
	(iw_handler)dummy,					/* SIOCSIWTXPOW */
	(iw_handler)dummy,					/* SIOCGIWTXPOW */
	(iw_handler)dummy,					/* SIOCSIWRETRY */
	NULL,//ecrnx_wext_get_retry,		/* SIOCGIWRETRY */
	NULL,//ecrnx_wext_set_enc,			/* SIOCSIWENCODE */
	NULL,//ecrnx_wext_get_enc,			/* SIOCGIWENCODE */
	(iw_handler)dummy,					/* SIOCSIWPOWER */
	NULL,//ecrnx_wext_get_power,		/* SIOCGIWPOWER */
	NULL,					/*---hole---*/
	NULL,					/*---hole---*/
	NULL,//ecrnx_wext_set_gen_ie,		/* SIOCSIWGENIE */
	NULL,					/* SIOCGWGENIE */
	NULL,//ecrnx_wext_set_auth,		/* SIOCSIWAUTH */
	NULL,					/* SIOCGIWAUTH */
	NULL,//ecrnx_wext_set_enc_ext,		/* SIOCSIWENCODEEXT */
	NULL,					/* SIOCGIWENCODEEXT */
	NULL,//ecrnx_wext_set_pmkid,		/* SIOCSIWPMKSA */
	NULL,					/*---hole---*/
};

const struct iw_handler_def  ecrnx_wext_handler_def =
{
    .num_standard   = ARRAY_SIZE(ecrnx_wext_handler),
    .standard   = ecrnx_wext_handler,
#ifdef CONFIG_WEXT_PRIV
    .num_private    = ARRAY_SIZE(ecrnx_wext_private_handler),
    .num_private_args = ARRAY_SIZE(ecrnx_wext_private_args),
    .private    = ecrnx_wext_private_handler,
    .private_args   = ecrnx_wext_private_args,
#endif
#if WIRELESS_EXT >= 17
	.get_wireless_stats = ecrnx_get_wireless_stats,
#endif

};
#endif

/**
 ****************************************************************************************
 *
 * @file ecrnx_debug.h
 *
 * @brief ecrnx driver debug structure declarations
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ****************************************************************************************
 */

#ifndef ECRNX_DEBUG_H_
#define ECRNX_DEBUG_H_

#define FW_STR  "fmac"
#define ECRNX_FN_ENTRY_STR "%s() enter, line:%d\n", __func__, __LINE__
#define DBG_PREFIX "[ecrnx] "
#define DBG_PREFIX_IW_CFM "[ecrnx] iwpriv cfm:"
#define DBG_PREFIX_PAT "[ecrnx] pattern error:"
#define DBG_PREFIX_CRC_CHECK "[ecrnx] crc check:"
#define DBG_PREFIX_SDIO_RX "[ecrnx] sdio rx:"
#define DBG_PREFIX_SDIO_TX "[ecrnx] sdio tx:"

typedef struct {
    u32 level;
    u32 dir;
} LOG_CTL_ST;

enum
{
    ECRNX_DBG_BIT_ERR,
    ECRNX_DBG_BIT_WARN,
    ECRNX_DBG_BIT_INIT,
    ECRNX_DBG_BIT_EXIT,
    ECRNX_DBG_BIT_TRANS,
    ECRNX_DBG_BIT_SCAN,
    ECRNX_DBG_BIT_P2P,
    ECRNX_DBG_BIT_MGMT,
    ECRNX_DBG_BIT_AGG,
    ECRNX_DBG_BIT_AP,
    ECRNX_DBG_BIT_STA,
    ECRNX_DBG_BIT_TX,
    ECRNX_DBG_BIT_RX,
    ECRNX_DBG_BIT_BH,
    ECRNX_DBG_BIT_MSG,
    ECRNX_DBG_BIT_CFG80211,
    ECRNX_DBG_BIT_WEXT,
    ECRNX_DBG_BIT_PM,
    ECRNX_DBG_BIT_PLATFROM,
    ECRNX_DBG_BIT_DEBUGFFS,
    ECRNX_DBG_BIT_FW_DOWNLOAD,
    ECRNX_DBG_BIT_AMT,
    ECRNX_DBG_BIT_DEBUG
};


#define ECRNX_PRINTK_MASK_ERR			BIT(ECRNX_DBG_BIT_ERR)
#define ECRNX_PRINTK_MASK_WARN			BIT(ECRNX_DBG_BIT_WARN)
#define ECRNX_PRINTK_MASK_INIT			BIT(ECRNX_DBG_BIT_INIT)
#define ECRNX_PRINTK_MASK_EXIT			BIT(ECRNX_DBG_BIT_EXIT)
#define ECRNX_PRINTK_MASK_TRANS			BIT(ECRNX_DBG_BIT_TRANS)
#define ECRNX_PRINTK_MASK_SCAN			BIT(ECRNX_DBG_BIT_SCAN)
#define ECRNX_PRINTK_MASK_P2P			BIT(ECRNX_DBG_BIT_P2P)
#define ECRNX_PRINTK_MASK_MGMT			BIT(ECRNX_DBG_BIT_MGMT)
#define ECRNX_PRINTK_MASK_AGG			BIT(ECRNX_DBG_BIT_AGG)
#define ECRNX_PRINTK_MASK_AP			BIT(ECRNX_DBG_BIT_AP)
#define ECRNX_PRINTK_MASK_STA			BIT(ECRNX_DBG_BIT_STA)
#define ECRNX_PRINTK_MASK_TX			BIT(ECRNX_DBG_BIT_TX)
#define ECRNX_PRINTK_MASK_RX			BIT(ECRNX_DBG_BIT_RX)
#define ECRNX_PRINTK_MASK_BH			BIT(ECRNX_DBG_BIT_BH)
#define ECRNX_PRINTK_MASK_MSG			BIT(ECRNX_DBG_BIT_MSG)
#define ECRNX_PRINTK_MASK_CFG80211		BIT(ECRNX_DBG_BIT_CFG80211)
#define ECRNX_PRINTK_MASK_WEXT			BIT(ECRNX_DBG_BIT_WEXT)
#define ECRNX_PRINTK_MASK_PM			BIT(ECRNX_DBG_BIT_PM)
#define ECRNX_PRINTK_MASK_PLATFROM		BIT(ECRNX_DBG_BIT_PLATFROM)
#define ECRNX_PRINTK_MASK_DEBUGFS     	BIT(ECRNX_DBG_BIT_DEBUGFFS)
#define ECRNX_PRINTK_MASK_FW_DOWNLOAD	BIT(ECRNX_DBG_BIT_FW_DOWNLOAD)
#define ECRNX_PRINTK_MASK_AMT			BIT(ECRNX_DBG_BIT_AMT)
#define ECRNX_PRINTK_MASK_DEBUG			BIT(ECRNX_DBG_BIT_DEBUG)


#define ECRNX_PRINTK_DEFAULT_MASK	(ECRNX_PRINTK_MASK_ERR|ECRNX_PRINTK_MASK_WARN|ECRNX_PRINTK_MASK_INIT| \
									ECRNX_PRINTK_MASK_EXIT|ECRNX_PRINTK_MASK_CFG80211|ECRNX_PRINTK_MASK_FW_DOWNLOAD)

#define ECRNX_PRINTK_ALL ((u32)(-1))
#define ECRNX_PRINTK_CLEAR		(0)

#ifdef CONFIG_ECRNX_DBG
#define ecrnx_printk(_level,fmt,arg...)     do {if(ecrnx_printk_mask&(_level)) printk(KERN_ERR "%s" fmt,ecrnx_log,##arg);}while(0)
#else
#define ecrnx_printk(_level,fmt,arg...)     do {} while(0)
#endif

/*
*ecrnx printk
*/
#define ecrnx_printk_err(...) 		ecrnx_printk(ECRNX_PRINTK_MASK_ERR,__VA_ARGS__)
#define ecrnx_printk_warn(...)		ecrnx_printk(ECRNX_PRINTK_MASK_WARN,__VA_ARGS__)
#define ecrnx_printk_init(...)		ecrnx_printk(ECRNX_PRINTK_MASK_INIT,__VA_ARGS__)
#define ecrnx_printk_exit(...)		ecrnx_printk(ECRNX_PRINTK_MASK_EXIT,__VA_ARGS__)
#define ecrnx_printk_trans(...)		ecrnx_printk(ECRNX_PRINTK_MASK_TRANS,__VA_ARGS__)
#define ecrnx_printk_scan(...)		ecrnx_printk(ECRNX_PRINTK_MASK_SCAN,__VA_ARGS__)
#define ecrnx_printk_p2p(...)		ecrnx_printk(ECRNX_PRINTK_MASK_P2P,__VA_ARGS__)
#define ecrnx_printk_mgmt(...)		ecrnx_printk(ECRNX_PRINTK_MASK_MGMT,__VA_ARGS__)
#define ecrnx_printk_agg(...)		ecrnx_printk(ECRNX_PRINTK_MASK_AGG,__VA_ARGS__)
#define ecrnx_printk_ap(...)		ecrnx_printk(ECRNX_PRINTK_MASK_AP,__VA_ARGS__)
#define ecrnx_printk_sta(...)		ecrnx_printk(ECRNX_PRINTK_MASK_STA,__VA_ARGS__)
#define ecrnx_printk_tx(...)		ecrnx_printk(ECRNX_PRINTK_MASK_TX,__VA_ARGS__)
#define ecrnx_printk_rx(...)		ecrnx_printk(ECRNX_PRINTK_MASK_RX,__VA_ARGS__)
#define ecrnx_printk_bh(...)		ecrnx_printk(ECRNX_PRINTK_MASK_BH,__VA_ARGS__)
#define ecrnx_printk_msg(...)		ecrnx_printk(ECRNX_PRINTK_MASK_MSG,__VA_ARGS__)
#define ecrnx_printk_cfg(...)		ecrnx_printk(ECRNX_PRINTK_MASK_CFG80211,__VA_ARGS__)
#define ecrnx_printk_wext(...)		ecrnx_printk(ECRNX_PRINTK_MASK_WEXT,__VA_ARGS__)
#define ecrnx_printk_pm(...)		ecrnx_printk(ECRNX_PRINTK_MASK_PM,__VA_ARGS__)
#define ecrnx_printk_platform(...)	ecrnx_printk(ECRNX_PRINTK_MASK_PLATFROM,__VA_ARGS__)
#define ecrnx_printk_debugfs(...)	ecrnx_printk(ECRNX_PRINTK_MASK_DEBUGFS,__VA_ARGS__)
#define ecrnx_printk_fw_dl(...)	    ecrnx_printk(ECRNX_PRINTK_MASK_FW_DOWNLOAD,__VA_ARGS__)
#define ecrnx_printk_amt(...)	    ecrnx_printk(ECRNX_PRINTK_MASK_AMT,__VA_ARGS__)
#define ecrnx_printk_debug(...)		ecrnx_printk(ECRNX_PRINTK_MASK_DEBUG,__VA_ARGS__)

#ifdef CONFIG_ECRNX_DBG
#define ecrnx_printk_always(fmt,arg...)     printk(KERN_ERR "%s" fmt,ecrnx_log,##arg)
#else
#define ecrnx_printk_always(fmt,arg...)     do {} while(0)
#endif

extern u32 ecrnx_printk_mask;
extern const char *ecrnx_log;
extern int ecrnx_dbg_level;
extern LOG_CTL_ST log_ctl;

#ifndef CONFIG_ECRNX_DEBUGFS_CUSTOM
int ecrnx_fw_log_level_set(u32 level, u32 dir);
#endif

void ecrnx_dbg_mask_dump(u32 mask);

#endif /* ECRNX_DEBUG_H_ */

/**
 ****************************************************************************************
 *
 * @file ecrnx_debug.c
 *
 * @brief ecrnx driver debug functions;
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ****************************************************************************************
 */
#include <linux/init.h>
#include "ecrnx_defs.h"
#include "eswin_utils.h"

#ifdef CONFIG_ECRNX_DBG_MASK
int ecrnx_dbg_level = CONFIG_ECRNX_DBG_MASK; 
u32 ecrnx_printk_mask = CONFIG_ECRNX_DBG_MASK;//defined in the 6600u_feature file
#else
int ecrnx_dbg_level = DRV_DBG_TYPE_NONE;
u32 ecrnx_printk_mask = ECRNX_PRINTK_DEFAULT_MASK;
#endif

const char *ecrnx_log = DBG_PREFIX;

LOG_CTL_ST log_ctl={
    .level = 2,
    .dir = 0,
};

#ifndef CONFIG_ECRNX_DEBUGFS_CUSTOM
int ecrnx_fw_log_level_set(u32 level, u32 dir)
{
    uint32_t dbg_info[3] = {0};

    dbg_info[0] = 0x01; //SLAVE_LOG_LEVEL
    dbg_info[1] = level;
    dbg_info[2] = dir;

    ecrnx_printk_always("%s: fstype:%d, level:%d, dir:%d \n", __func__, dbg_info[0], dbg_info[1], dbg_info[2]);
    ecrnx_printk_always("info_len:%d \n", sizeof(dbg_info));
    return host_send(dbg_info, sizeof(dbg_info), TX_FLAG_MSG_DEBUG_IE);
}
#endif

void ecrnx_dbg_mask_dump(u32 mask)
{
    if(mask & ECRNX_PRINTK_MASK_ERR) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_ERR is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_WARN) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_WARN is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_INIT) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_INIT is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_EXIT) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_EXIT is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_TRANS) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_TRANS is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_SCAN) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_SCAN is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_P2P) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_P2P is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_MGMT) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_MGMT is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_AGG) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_AGG is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_AP) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_AP is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_STA) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_STA is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_TX) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_TX is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_RX) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_RX is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_BH) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_BH is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_MSG) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_MSG is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_CFG80211) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_CFG80211 is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_WEXT) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_WEXT is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_PM) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_PM is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_PLATFROM) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_PLATFROM is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_DEBUGFS) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_DEBUGFS is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_FW_DOWNLOAD) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_FW_DOWNLOAD is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_AMT) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_AMT is set; \n");
    }if(mask & ECRNX_PRINTK_MASK_DEBUG) {
        ecrnx_printk_always("ECRNX_PRINTK_MASK_DEBUG is set; \n");
    }
}

// #endif



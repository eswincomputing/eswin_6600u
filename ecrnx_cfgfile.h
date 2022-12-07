/**
 ****************************************************************************************
 *
 * @file ecrnx_cfgfile.h
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ****************************************************************************************
 */

#ifndef _ECRNX_CFGFILE_H_
#define _ECRNX_CFGFILE_H_

/*
 * Structure used to retrieve information from the Config file used at Initialization time
 */
struct ecrnx_conf_file {
    u8 mac_addr[ETH_ALEN];
    u8 fw_log_level;
    u8 fw_log_type;
};

/*
 * Structure used to retrieve information from the PHY Config file used at Initialization time
 */
struct ecrnx_phy_conf_file {
    struct phy_trd_cfg_tag trd;
    struct phy_karst_cfg_tag karst;
    struct phy_cataxia_cfg_tag cataxia;
};

/*
 * Structure used to retrieve information from the AMT Config file used at Initialization time
 */
#include "ecrnx_calibration_data.h"
struct ecrnx_amt_conf_file {
    uint8_t   gain[CHAN_LEVEL_MAX][CAL_FORMAT_CLASS];
    cfo_cal_t     cfo_cal;
    uint32_t      freqOffset;
    uint8_t mac_addr[ETH_ALEN];
    uint8_t delta_gain_flag;
    uint8_t cfo_flag;
    uint8_t mac_flag;
};
extern struct ecrnx_amt_conf_file amt_conf_param;

int ecrnx_parse_configfile(struct ecrnx_hw *ecrnx_hw, const char *filename, bool *mac_flag);
int ecrnx_parse_phy_configfile(struct ecrnx_hw *ecrnx_hw, const char *filename,
                              struct ecrnx_phy_conf_file *config, int path);
int ecrnx_parse_amt_configfile(struct device *dev, const char *filename);

#endif /* _ECRNX_CFGFILE_H_ */

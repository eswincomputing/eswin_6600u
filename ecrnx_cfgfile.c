/**
 ****************************************************************************************
 *
 * @file ecrnx_configparse.c
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ****************************************************************************************
 */
#include <linux/firmware.h>
#include <linux/if_ether.h>

#include "ecrnx_defs.h"
#include "ecrnx_cfgfile.h"
#include "ecrnx_debug.h"
#include "ecrnx_debugfs_func.h"

/**
 *
 */
static const char *ecrnx_find_tag(const u8 *file_data, unsigned int file_size,
                                 const char *tag_name, unsigned int tag_len)
{
    unsigned int curr, line_start = 0, line_size;

    ecrnx_printk_debugfs(ECRNX_FN_ENTRY_STR);

    /* Walk through all the lines of the configuration file */
    while (line_start < file_size) {
        /* Search the end of the current line (or the end of the file) */
        for (curr = line_start; curr < file_size; curr++)
            if (file_data[curr] == '\n')
                break;

        /* Compute the line size */
        line_size = curr - line_start;

        /* Check if this line contains the expected tag */
        if ((line_size >= (strlen(tag_name) + tag_len)) &&
            (!strncmp(&file_data[line_start], tag_name, strlen(tag_name))))
            return (&file_data[line_start + strlen(tag_name)]);

        /* Move to next line */
        line_start = curr + 1;
    }

    /* Tag not found */
    return NULL;
}

#ifdef CONFIG_ECRNX_DBG
/**
 * Parse the Config file used at init time
 */
int ecrnx_parse_configfile(struct ecrnx_hw *ecrnx_hw, const char *filename,bool *mac_flag)
{
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
        firmware_file *config_fw;
#else
        const struct firmware *config_fw;
#endif
    int ret = -1;
    const u8 *tag_ptr;
    bool  dbg_level_flag = false, fw_log_lv_flag = false, fw_log_type_flag = false;

    ecrnx_printk_debugfs(ECRNX_FN_ENTRY_STR);
    int status;
    char *config_path = NULL;
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
    config_path = kmalloc(strlen(CONFIG_FW_PATH) + strlen(filename) + 1,GFP_KERNEL);
    memset(config_path, 0, strlen(CONFIG_FW_PATH) + strlen(filename) + 1);
    memcpy(config_path, CONFIG_FW_PATH, strlen(CONFIG_FW_PATH));
    memcpy(config_path + strlen(CONFIG_FW_PATH), filename, strlen(filename));
    ecrnx_printk_always("cfg path:%s\n",config_path);
    if (eswin_fw_isFileReadable(config_path, NULL) == false)
    {
        ecrnx_printk_warn("%s cfg file not exist:%s\n", __func__, config_path);
        kfree(config_path);
        return 0;
    }

    eswin_fw_alloc(&config_fw);

    status = eswin_fw_retriveFromFile(config_path, config_fw->data, 1024*1024);
    config_fw->size = status;
    if (status <= 0)
    {
        kfree(config_path);
        ret = -1;
    }
    else
        ret = 0;
#else
#if defined(CONFIG_FW_LOADER) || (defined(CONFIG_FW_LOADER_MODULE) && defined(MODULE))
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    ret = firmware_request_nowarn(&config_fw, filename, ecrnx_hw->dev); //avoid the files not exit error
#else
    ret = request_firmware(&config_fw, filename, ecrnx_hw->dev);
#endif
#else
    return 0;
#endif
#endif
    if (ret == 0) {
        /* Get MAC Address */
        tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size, "MAC_ADDR=", strlen("00:00:00:00:00:00"));
        if (tag_ptr != NULL) {
            u8 *addr = ecrnx_hw->conf_param.mac_addr;
            if ((sscanf(tag_ptr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        addr + 0, addr + 1, addr + 2,
                        addr + 3, addr + 4, addr + 5) == ETH_ALEN)) {
                if ((addr[0] & 0x01) == 0)
                *mac_flag = true;
                else
                {
                   printk("CFG FILE MAC ADDR is invalid,systeme will use efuse mac if it's valid\n");
                   *mac_flag = false;
                }
            }
            else
              *mac_flag = false;
        }

        tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size, "DRIVER_LOG_LEVEL=", strlen("000"));
        if (tag_ptr != NULL){
#if 0
            if(sscanf(tag_ptr, "%hhx", &ecrnx_hw->conf_param.host_driver_log_level) == 1){
                ecrnx_dbg_level = ecrnx_hw->conf_param.host_driver_log_level;
                dbg_level_flag = true;
            }
#else
            if(sscanf(tag_ptr, "%x", &ecrnx_printk_mask) == 1){
                //ecrnx_dbg_level = ecrnx_hw->conf_param.host_driver_log_level;
                dbg_level_flag = true;
            }
#endif
        }

        tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size, "FW_LOG_LEVEL=", strlen("0"));
        if (tag_ptr != NULL){
            if(sscanf(tag_ptr, "%hhx", &ecrnx_hw->conf_param.fw_log_level) == 1){
                fw_log_lv_flag = true;
            }
        }

        tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size, "FW_LOG_TYPE=", strlen("0"));
        if (tag_ptr != NULL){
            if(sscanf(tag_ptr, "%hhx", &ecrnx_hw->conf_param.fw_log_type) == 1){
                fw_log_type_flag = true;
            }
        }

        /* Release the configuration file */
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
        kfree(config_path);
        eswin_fw_release(config_fw);
#else
        release_firmware(config_fw);
#endif

    }

    if(!fw_log_lv_flag){
        ecrnx_hw->conf_param.fw_log_level = log_ctl.level;
    }

    if(!fw_log_type_flag){
        ecrnx_hw->conf_param.fw_log_type = log_ctl.dir;
    }

    ecrnx_printk_always("MAC Address is:%pM\n", ecrnx_hw->conf_param.mac_addr);
    //ecrnx_printk_always("host driver log level is:%d \n", ecrnx_hw->conf_param.host_driver_log_level);
    ecrnx_printk_always("host driver log ecrnx_printk_mask is:0x%x \n", ecrnx_printk_mask);
    ecrnx_dbg_mask_dump(ecrnx_printk_mask);
    ecrnx_printk_always("firmware log level is:%d \n", ecrnx_hw->conf_param.fw_log_level);

    if(0 == ecrnx_hw->conf_param.fw_log_type){
        ecrnx_printk_always("firmware log level type:%d (print to chip's uart) \n", ecrnx_hw->conf_param.fw_log_type);
    }else if(1 == ecrnx_hw->conf_param.fw_log_type){
        ecrnx_printk_always("firmware log level type:%d (print to host ) \n", ecrnx_hw->conf_param.fw_log_type);
    }else if(2 == ecrnx_hw->conf_param.fw_log_type){
        ecrnx_printk_always("firmware log level type:%d (both print to host and chip's uart) \n", ecrnx_hw->conf_param.fw_log_type);
    }else{
        ecrnx_printk_err("firmware log level type error;\n");
    }
    return 0;
}

/**
 * Parse the Config file used at init time
 */
int ecrnx_parse_phy_configfile(struct ecrnx_hw *ecrnx_hw, const char *filename,
                              struct ecrnx_phy_conf_file *config, int path)
{
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
        firmware_file *config_fw;
#else
        const struct firmware *config_fw;
#endif
    int ret;
    const u8 *tag_ptr;

    ecrnx_printk_debugfs(ECRNX_FN_ENTRY_STR);
    int status;
    char *config_path = NULL;
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
    config_path = kmalloc(strlen(CONFIG_FW_PATH) + strlen(filename) + 1,GFP_KERNEL);
    memset(config_path, 0, strlen(CONFIG_FW_PATH) + strlen(filename) + 1);
    memcpy(config_path, CONFIG_FW_PATH, strlen(CONFIG_FW_PATH));
    memcpy(config_path + strlen(CONFIG_FW_PATH), filename, strlen(filename));
    ecrnx_printk_always("cfg path:%s\n",config_path);
    if (eswin_fw_isFileReadable(config_path, NULL) == false)
    {
        ecrnx_printk_err("%s acquire cfg from file:%s\n", __func__, config_path);
        kfree(config_path);
        return -1;
    }

    eswin_fw_alloc(&config_fw);

    status = eswin_fw_retriveFromFile(config_path, config_fw->data, 1024*1024);
    config_fw->size = status;
    if (status <= 0)
    {
        kfree(config_path);
        ret = -1;
    }
    else
        ret = 0;
#else
#if defined(CONFIG_FW_LOADER) || (defined(CONFIG_FW_LOADER_MODULE) && defined(MODULE))
    if ((ret = request_firmware(&config_fw, filename, ecrnx_hw->dev))) {
        ecrnx_printk_err(KERN_CRIT "%s: Failed to get %s (%d)\n", __func__, filename, ret);
        return ret;
    }
#else
    return 0;
#endif
#endif
    /* Get Trident path mapping */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "TRD_PATH_MAPPING=", strlen("00"));
    if (tag_ptr != NULL) {
        u8 val;
        if (sscanf(tag_ptr, "%hhx", &val) == 1)
            config->trd.path_mapping = val;
        else
            config->trd.path_mapping = path;
    } else
        config->trd.path_mapping = path;

    ecrnx_printk_debugfs("Trident path mapping is: %d\n", config->trd.path_mapping);

    /* Get DC offset compensation */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "TX_DC_OFF_COMP=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->trd.tx_dc_off_comp) != 1)
            config->trd.tx_dc_off_comp = 0;
    } else
        config->trd.tx_dc_off_comp = 0;

    ecrnx_printk_debugfs("TX DC offset compensation is: %08X\n", config->trd.tx_dc_off_comp);

    /* Get Karst TX IQ compensation value for path0 on 2.4GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_TX_IQ_COMP_2_4G_PATH_0=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.tx_iq_comp_2_4G[0]) != 1)
            config->karst.tx_iq_comp_2_4G[0] = 0x01000000;
    } else
        config->karst.tx_iq_comp_2_4G[0] = 0x01000000;

    ecrnx_printk_debugfs("Karst TX IQ compensation for path 0 on 2.4GHz is: %08X\n", config->karst.tx_iq_comp_2_4G[0]);

    /* Get Karst TX IQ compensation value for path1 on 2.4GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_TX_IQ_COMP_2_4G_PATH_1=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.tx_iq_comp_2_4G[1]) != 1)
            config->karst.tx_iq_comp_2_4G[1] = 0x01000000;
    } else
        config->karst.tx_iq_comp_2_4G[1] = 0x01000000;

    ecrnx_printk_debugfs("Karst TX IQ compensation for path 1 on 2.4GHz is: %08X\n", config->karst.tx_iq_comp_2_4G[1]);

    /* Get Karst RX IQ compensation value for path0 on 2.4GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_RX_IQ_COMP_2_4G_PATH_0=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.rx_iq_comp_2_4G[0]) != 1)
            config->karst.rx_iq_comp_2_4G[0] = 0x01000000;
    } else
        config->karst.rx_iq_comp_2_4G[0] = 0x01000000;

    ecrnx_printk_debugfs("Karst RX IQ compensation for path 0 on 2.4GHz is: %08X\n", config->karst.rx_iq_comp_2_4G[0]);

    /* Get Karst RX IQ compensation value for path1 on 2.4GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_RX_IQ_COMP_2_4G_PATH_1=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.rx_iq_comp_2_4G[1]) != 1)
            config->karst.rx_iq_comp_2_4G[1] = 0x01000000;
    } else
        config->karst.rx_iq_comp_2_4G[1] = 0x01000000;

    ecrnx_printk_debugfs("Karst RX IQ compensation for path 1 on 2.4GHz is: %08X\n", config->karst.rx_iq_comp_2_4G[1]);

    /* Get Karst TX IQ compensation value for path0 on 5GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_TX_IQ_COMP_5G_PATH_0=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.tx_iq_comp_5G[0]) != 1)
            config->karst.tx_iq_comp_5G[0] = 0x01000000;
    } else
        config->karst.tx_iq_comp_5G[0] = 0x01000000;

    ecrnx_printk_debugfs("Karst TX IQ compensation for path 0 on 5GHz is: %08X\n", config->karst.tx_iq_comp_5G[0]);

    /* Get Karst TX IQ compensation value for path1 on 5GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_TX_IQ_COMP_5G_PATH_1=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.tx_iq_comp_5G[1]) != 1)
            config->karst.tx_iq_comp_5G[1] = 0x01000000;
    } else
        config->karst.tx_iq_comp_5G[1] = 0x01000000;

    ecrnx_printk_debugfs("Karst TX IQ compensation for path 1 on 5GHz is: %08X\n", config->karst.tx_iq_comp_5G[1]);

    /* Get Karst RX IQ compensation value for path0 on 5GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_RX_IQ_COMP_5G_PATH_0=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.rx_iq_comp_5G[0]) != 1)
            config->karst.rx_iq_comp_5G[0] = 0x01000000;
    } else
        config->karst.rx_iq_comp_5G[0] = 0x01000000;

    ecrnx_printk_debugfs("Karst RX IQ compensation for path 0 on 5GHz is: %08X\n", config->karst.rx_iq_comp_5G[0]);

    /* Get Karst RX IQ compensation value for path1 on 5GHz */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_RX_IQ_COMP_5G_PATH_1=", strlen("00000000"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%08x", &config->karst.rx_iq_comp_5G[1]) != 1)
            config->karst.rx_iq_comp_5G[1] = 0x01000000;
    } else
        config->karst.rx_iq_comp_5G[1] = 0x01000000;

    ecrnx_printk_debugfs("Karst RX IQ compensation for path 1 on 5GHz is: %08X\n", config->karst.rx_iq_comp_5G[1]);

    /* Get Karst default path */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "KARST_DEFAULT_PATH=", strlen("00"));
    if (tag_ptr != NULL) {
        u8 val;
        if (sscanf(tag_ptr, "%hhx", &val) == 1)
            config->karst.path_used = val;
        else
            config->karst.path_used = path;
    } else
        config->karst.path_used = path;

    ecrnx_printk_debugfs("Karst default path is: %d\n", config->karst.path_used);

    /* Release the configuration file */
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
        kfree(config_path);
        eswin_fw_release(config_fw);
#else
        release_firmware(config_fw);
#endif


    return 0;
}
#endif

struct ecrnx_amt_conf_file amt_conf_param;
int ecrnx_parse_amt_configfile(struct device *dev, const char *filename)
{
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
    firmware_file *config_fw;
#else
    const struct firmware *config_fw;
#endif
    
    int ret;
    const u8 *tag_ptr;
    bool delta_11b_flag = false,  delta_11n_flag = false, delta_11n_40m_flag = false;
    bool swl_flag = false,  fine_flag = false,  coarse_flag = false;
    bool mac_flag = false;

    ecrnx_printk_debugfs(ECRNX_FN_ENTRY_STR);

#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
    int status;
    char *amt_config_path = NULL;
    amt_config_path = kmalloc(strlen(CONFIG_FW_PATH) + strlen(filename) + 1,GFP_KERNEL);
    memset(amt_config_path, 0, strlen(CONFIG_FW_PATH) + strlen(filename) + 1);
    memcpy(amt_config_path, CONFIG_FW_PATH, strlen(CONFIG_FW_PATH));
    memcpy(amt_config_path + strlen(CONFIG_FW_PATH), filename, strlen(filename));
    ecrnx_printk_always("amt.cfg path:%s\n",amt_config_path);

    if (eswin_fw_isFileReadable(amt_config_path, NULL) == false)    
    {        
        ecrnx_printk_err("%s acquire amt_config from file:%s\n", __func__, amt_config_path);        
        return -1;    
    }

    eswin_fw_alloc(&config_fw);

    status = eswin_fw_retriveFromFile(amt_config_path, config_fw->data, 1024*1024);
    config_fw->size = status;
    if (status <= 0)
        ret = -1;
    else
        ret = 0;
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
    ret = firmware_request_nowarn(&config_fw, filename, dev); //avoid the files not exit error
#else
    ret = request_firmware(&config_fw, filename, dev);
#endif
#endif

    if (ret != 0) {
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
        kfree(amt_config_path);
        eswin_fw_release(config_fw);
#endif
        return ret;
    }

    memset(&amt_conf_param, 0, sizeof(amt_conf_param));

    /* Get AMT gain delta for calibration tx power */
    int gain_code, delta_low, delta_high;
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "AMT_GAIN_DELTA_11B=", strlen("65535,07,07"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%5d,%2d,%2d", 
                        &gain_code, &delta_low, &delta_high) == CHAN_LEVEL_MAX) {

        gain_code = ((gain_code & 0xff00) >> 8);
        gain_code &= DIG_GAIN_MAX;

        if (delta_low < -7 || delta_low > 7) {
        	ecrnx_printk_always("11b gain delta delta_low error\n");
        }
        if (delta_high < -7 || delta_high > 7) {
        	ecrnx_printk_always("11b gain delta delta_high error\n");
        }
	
        amt_conf_param.gain[CHAN_LEVEL_LOW][0] = delta_low > 0 ? (delta_low & 0x7) | 0x8 : (delta_low * -1) & 0x7;
        amt_conf_param.gain[CHAN_LEVEL_MID][0] = gain_code;
        amt_conf_param.gain[CHAN_LEVEL_HIGH][0] = delta_high > 0 ? (delta_high & 0x7) | 0x8 : (delta_high * -1) & 0x7;

        delta_11b_flag = true;
        }
    }
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                        "AMT_GAIN_DELTA_11N=", strlen("65535,07,07"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%5d,%2d,%2d", 
                        &gain_code, &delta_low, &delta_high) == CHAN_LEVEL_MAX) {
	
        gain_code = ((gain_code & 0xff00) >> 8);
        gain_code &= DIG_GAIN_MAX;

        if (delta_low < -7 || delta_low > 7) {
        	ecrnx_printk_always("11n gain delta delta_low error\n");
        }
        if (delta_high < -7 || delta_high > 7) {
        	ecrnx_printk_always("11n gain delta delta_high error\n");
        }
        
        amt_conf_param.gain[CHAN_LEVEL_LOW][1] = delta_low > 0 ? (delta_low & 0x7) | 0x8 : (delta_low * -1) & 0x7;
        amt_conf_param.gain[CHAN_LEVEL_MID][1] = gain_code;
        amt_conf_param.gain[CHAN_LEVEL_HIGH][1] = delta_high > 0 ? (delta_high & 0x7) | 0x8 : (delta_high * -1) & 0x7;

        delta_11n_flag = true;
        }
    }

    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size,
                            "AMT_GAIN_DELTA_11N_40M=", strlen("65535,07,07"));
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%5d,%2d,%2d", 
                        &gain_code, &delta_low, &delta_high) == CHAN_LEVEL_MAX) {
	
        gain_code = ((gain_code & 0xff00) >> 8);
        gain_code &= DIG_GAIN_MAX;

        if (delta_low < -7 || delta_low > 7) {
        	ecrnx_printk_always("11n40 gain delta delta_low error\n");
        }
        if (delta_high < -7 || delta_high > 7) {
        	ecrnx_printk_always("11n40 gain delta delta_high error\n");
        }
        
        amt_conf_param.gain[CHAN_LEVEL_LOW][2] = delta_low > 0 ? (delta_low & 0x7) | 0x8 : (delta_low * -1) & 0x7;
        amt_conf_param.gain[CHAN_LEVEL_MID][2] = gain_code;
        amt_conf_param.gain[CHAN_LEVEL_HIGH][2] = delta_high > 0 ? (delta_high & 0x7) | 0x8 : (delta_high * -1) & 0x7;  
        
        delta_11n_40m_flag = true;
        }
    }

    if (delta_11b_flag && delta_11n_flag && delta_11n_40m_flag)
        amt_conf_param.delta_gain_flag = true;

    /* Get AMT CFO */
    tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size, "AMT_CFO=", strlen("13,05,07"));
    int fine, coarse, swl;
    if (tag_ptr != NULL) {
        if (sscanf(tag_ptr, "%2d,%2d,%2d", 
                    &swl, &coarse, &fine) == CHAN_LEVEL_MAX){
        amt_conf_param.cfo_cal.swl = swl;
        amt_conf_param.cfo_cal.coarse = coarse;
        amt_conf_param.cfo_cal.fine = fine;
        amt_conf_param.freqOffset =  (0x000FFFFF & (swl << 8)) | fine << 16 | fine << 12 | coarse << 4 | coarse;
        amt_conf_param.cfo_flag = true;
        }
    }
	
    /* Get MAC Address */
   tag_ptr = ecrnx_find_tag(config_fw->data, config_fw->size, "AMT_MAC=", strlen("00:00:00:00:00:00"));
    if (tag_ptr != NULL) {
        u8 *addr = amt_conf_param.mac_addr;
        if (sscanf(tag_ptr,
                        "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                        addr + 0, addr + 1, addr + 2,
                        addr + 3, addr + 4, addr + 5) == ETH_ALEN){
        amt_conf_param.mac_flag = true;
        }
    }    

    /* Release the configuration file */
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
        kfree(amt_config_path);
        eswin_fw_release(config_fw);
#else
        release_firmware(config_fw);
#endif

    return 0;
}


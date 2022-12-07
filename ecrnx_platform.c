/**
 ******************************************************************************
 *
 * @file ecrnx_platform.c
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ******************************************************************************
 */

#include <linux/module.h>
#include <linux/firmware.h>
#include <linux/delay.h>

#include "ecrnx_platform.h"
#include "reg_access.h"
#include "hal_desc.h"
#include "ecrnx_main.h"

#if defined(CONFIG_ECRNX_ESWIN_SDIO)
#include "sdio.h"
#include "ecrnx_sdio.h"
#elif defined(CONFIG_ECRNX_ESWIN_USB)
#include "usb.h"
#include "ecrnx_usb.h"
#endif
#ifdef CONFIG_ECRNX_WIFO_CAIL
#include "core.h"
#include "ecrnx_amt.h"
#endif

#ifdef CONFIG_ECRNX_TL4
/**
 * ecrnx_plat_tl4_fw_upload() - Load the requested FW into embedded side.
 *
 * @ecrnx_plat: pointer to platform structure
 * @fw_addr: Virtual address where the fw must be loaded
 * @filename: Name of the fw.
 *
 * Load a fw, stored as a hex file, into the specified address
 */
static int ecrnx_plat_tl4_fw_upload(struct ecrnx_plat *ecrnx_plat, u8* fw_addr,
                                   char *filename)
{
    struct device *dev = ecrnx_platform_get_dev(ecrnx_plat);
    const struct firmware *fw;
    int err = 0;
    u32 *dst;
    u8 const *file_data;
    char typ0, typ1;
    u32 addr0, addr1;
    u32 dat0, dat1;
    int remain;

    err = request_firmware(&fw, filename, dev);
    if (err) {
        return err;
    }
    file_data = fw->data;
    remain = fw->size;

    /* Copy the file on the Embedded side */
    dev_dbg(dev, "\n### Now copy %s firmware, @ = %p\n", filename, fw_addr);

    /* Walk through all the lines of the configuration file */
    while (remain >= 16) {
        u32 data, offset;

        if (sscanf(file_data, "%c:%08X %04X", &typ0, &addr0, &dat0) != 3)
            break;
        if ((addr0 & 0x01) != 0) {
            addr0 = addr0 - 1;
            dat0 = 0;
        } else {
            file_data += 16;
            remain -= 16;
        }
        if ((remain < 16) ||
            (sscanf(file_data, "%c:%08X %04X", &typ1, &addr1, &dat1) != 3) ||
            (typ1 != typ0) || (addr1 != (addr0 + 1))) {
            typ1 = typ0;
            addr1 = addr0 + 1;
            dat1 = 0;
        } else {
            file_data += 16;
            remain -= 16;
        }

        if (typ0 == 'C') {
            offset = 0x00200000;
            if ((addr1 % 4) == 3)
                offset += 2*(addr1 - 3);
            else
                offset += 2*(addr1 + 1);

            data = dat1 | (dat0 << 16);
        } else {
            offset = 2*(addr1 - 1);
            data = dat0 | (dat1 << 16);
        }
        dst = (u32 *)(fw_addr + offset);
        *dst = data;
    }

    release_firmware(fw);

    return err;
}
#endif

#ifndef CONFIG_ECRNX_TL4
#define IHEX_REC_DATA           0
#define IHEX_REC_EOF            1
#define IHEX_REC_EXT_SEG_ADD    2
#define IHEX_REC_START_SEG_ADD  3
#define IHEX_REC_EXT_LIN_ADD    4
#define IHEX_REC_START_LIN_ADD  5

#endif

/**
 * ecrnx_platform_on() - Start the platform
 *
 * @ecrnx_hw: Main driver data
 * @config: Config to restore (NULL if nothing to restore)
 *
 * It starts the platform :
 * - load fw and ucodes
 * - initialize IPC
 * - boot the fw
 * - enable link communication/IRQ
 *
 * Called by 802.11 part
 */
int ecrnx_platform_on(struct ecrnx_hw *ecrnx_hw, void *config)
{
    u8 *shared_ram;
    int ret;
    
    ecrnx_printk_platform("%s entry!!", __func__);
    shared_ram = kzalloc(sizeof(struct ipc_shared_env_tag), GFP_KERNEL);
    if (!shared_ram)
        return -ENOMEM;

    if ((ret = ecrnx_ipc_init(ecrnx_hw, shared_ram)))
       return ret;

    ecrnx_printk_platform("%s exit!!", __func__);
    return 0;
}

/**
 * ecrnx_platform_off() - Stop the platform
 *
 * @ecrnx_hw: Main driver data
 * @config: Updated with pointer to config, to be able to restore it with
 * ecrnx_platform_on(). It's up to the caller to free the config. Set to NULL
 * if configuration is not needed.
 *
 * Called by 802.11 part
 */
void ecrnx_platform_off(struct ecrnx_hw *ecrnx_hw, void **config)
{
    ecrnx_printk_platform("%s entry!!", __func__);
    ecrnx_ipc_deinit(ecrnx_hw);
#if defined(CONFIG_ECRNX_ESWIN_SDIO)
     ecrnx_sdio_deinit(ecrnx_hw);
#elif defined(CONFIG_ECRNX_ESWIN_USB)
    ecrnx_usb_deinit(ecrnx_hw);
#else
   #error "config error drv";
#endif
}

/**
 * ecrnx_platform_init() - Initialize the platform
 *
 * @ecrnx_plat: platform data (already updated by platform driver)
 * @platform_data: Pointer to store the main driver data pointer (aka ecrnx_hw)
 *                That will be set as driver data for the platform driver
 * Return: 0 on success, < 0 otherwise
 *
 * Called by the platform driver after it has been probed
 */
int ecrnx_platform_init(void *ecrnx_plat, void **platform_data)
{
    ecrnx_printk_platform(ECRNX_FN_ENTRY_STR);
#if defined CONFIG_ECRNX_FULLMAC
#ifdef CONFIG_ECRNX_WIFO_CAIL
	if (amt_mode == true) {
		return ecrnx_amt_init(ecrnx_plat);
	}
	else
#endif
    return ecrnx_cfg80211_init(ecrnx_plat, platform_data);
#elif defined CONFIG_ECRNX_FHOST
    return ecrnx_fhost_init(ecrnx_plat, platform_data);
#endif
}

/**
 * ecrnx_platform_deinit() - Deinitialize the platform
 *
 * @ecrnx_hw: main driver data
 *
 * Called by the platform driver after it is removed
 */
void ecrnx_platform_deinit(struct ecrnx_hw *ecrnx_hw)
{
    ecrnx_printk_platform(ECRNX_FN_ENTRY_STR);

#if defined CONFIG_ECRNX_FULLMAC
#ifdef CONFIG_ECRNX_WIFO_CAIL
	if (amt_mode == true) {
		ecrnx_amt_deinit();
	}
	else
#endif
    ecrnx_cfg80211_deinit(ecrnx_hw);
#elif defined CONFIG_ECRNX_FHOST
    ecrnx_fhost_deinit(ecrnx_hw);
#endif
}


/**
 * ecrnx_platform_register_drv() - Register all possible platform drivers
 */
int ecrnx_platform_register_drv(void)
{
#if defined(CONFIG_ECRNX_ESWIN_SDIO)
    return ecrnx_sdio_register_drv();
#elif defined(CONFIG_ECRNX_ESWIN_USB)
    return ecrnx_usb_register_drv();
#else
    #error "config error drv"
#endif
}


/**
 * ecrnx_platform_unregister_drv() - Unegister all platform drivers
 */
void ecrnx_platform_unregister_drv(void)
{
#if defined(CONFIG_ECRNX_ESWIN_SDIO)
    return ecrnx_sdio_unregister_drv();
#elif defined(CONFIG_ECRNX_ESWIN_USB)
    return ecrnx_usb_unregister_drv();
#else
    #error "config error drv"
#endif
}


#ifndef CONFIG_ECRNX_SDM
MODULE_FIRMWARE(ECRNX_AGC_FW_NAME);
MODULE_FIRMWARE(ECRNX_FCU_FW_NAME);
MODULE_FIRMWARE(ECRNX_LDPC_RAM_NAME);
#endif
MODULE_FIRMWARE(ECRNX_MAC_FW_NAME);
#ifndef CONFIG_ECRNX_TL4
MODULE_FIRMWARE(ECRNX_MAC_FW_NAME2);
#endif

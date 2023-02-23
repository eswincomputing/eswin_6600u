/**
******************************************************************************
*
* @file fw.c
*
* @brief ecrnx sdio firmware download functions
*
* Copyright (C) ESWIN 2015-2020
*
******************************************************************************
*/

#include <linux/firmware.h>
#include "core.h"
#include "sdio.h"
#include "fw_head_check.h"

extern char *fw_name;


void eswin_fw_file_download(struct eswin *tr)
{
	int ret;
	unsigned int length_all;
	unsigned char length_str[9]={0};
	unsigned int lengthLeft, lengthSend, offset = HEAD_SIZE;
	const u8 * dataAddr;
	struct sk_buff *skb;
	int file_num = 0;
	unsigned int file_load_addr[3] = {0x10000U, 0x60800U, 0x80000U};  // ilm addr; dlm addr offset 0x800 for bootrom log; iram0 addr

	char str_sync[4] = {0x63, 0x6E, 0x79, 0x73};		
	char str_cfg[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00};  // default for sync

	skb = dev_alloc_skb(1024);

	ecrnx_printk_fw_dl("%s entry!!", __func__);

#if 0
	/* 1 sync */
	memcpy(skb->data, str_sync, 4);
	tr->ops->write(tr, skb->data, 4);
	ret = tr->ops->wait_ack(tr);
	ecrnx_printk_fw_dl("dl-fw >> sync, ret: %d\n", ret);
#endif
	
	dataAddr = tr->fw->data;
	length_all = tr->fw->size - offset;
	
	while(length_all)
	{
		memcpy(length_str, dataAddr + offset, 8);
		ecrnx_printk_fw_dl("-------------------------------------%s\n", length_str);
		offset+=8; 
		length_all-=8;
		ret = kstrtol(length_str, 10, (long*)&lengthLeft);
		if(ret==0 && lengthLeft)
		{
			length_all-=lengthLeft;

			/* 2 cfg addr and length */
			str_cfg[4] = (char)((file_load_addr[file_num]) & 0xFF);
			str_cfg[5] = (char)(((file_load_addr[file_num])>>8) & 0xFF);
			str_cfg[6] = (char)(((file_load_addr[file_num])>>16) & 0xFF);
			str_cfg[7] = (char)(((file_load_addr[file_num])>>24) & 0xFF);
			str_cfg[8] = (char)((lengthLeft) & 0xFF);
			str_cfg[9] = (char)(((lengthLeft)>>8) & 0xFF);
			str_cfg[10] = (char)(((lengthLeft)>>16) & 0xFF);
			str_cfg[11] = (char)(((lengthLeft)>>24) & 0xFF);


			memcpy(skb->data, &str_cfg[0], 12);
			tr->ops->write(tr, skb->data, 12);
			ret = tr->ops->wait_ack(tr);


			/* 3 load fw */
			do {
				lengthSend = (lengthLeft >= 1024) ? 1024 : lengthLeft; //ECO3 supprot 64K buff
				if(lengthLeft%512==0)
				{
					memcpy(skb->data, dataAddr + offset, lengthSend);
					tr->ops->write(tr, skb->data, lengthSend);
					ret = tr->ops->wait_ack(tr);
				}
				else
				{	
					memcpy(skb->data, dataAddr + offset, lengthSend&0xFFFFFE00U);
					tr->ops->write(tr, skb->data, lengthSend&0xFFFFFE00U);
					ret = tr->ops->wait_ack(tr);
					
					memcpy(skb->data, dataAddr + offset + (int)(lengthLeft&0xFFFFFE00U), lengthSend&0x1FFU);
					tr->ops->write(tr, skb->data, lengthSend&0x1FFU);
					ret = tr->ops->wait_ack(tr);
				}

				offset += lengthSend;	
				lengthLeft -= lengthSend;
			} while(lengthLeft);	
		}
		file_num++;
	}

	/* 4 start up */
	memset(skb->data, 0, 12);
	tr->ops->write(tr, skb->data, 12);
	tr->ops->wait_ack(tr);

	dev_kfree_skb(skb);
}





bool eswin_fw_file_chech(struct eswin *tr)
{
	int status;
    char *fw_path = NULL;
	if (fw_name == NULL)
		goto err_fw;

	if (tr->fw)
		return true;


#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
    fw_path = kmalloc(strlen(CONFIG_FW_PATH) + strlen(fw_name) + 1,GFP_KERNEL);
    memset(fw_path, 0, strlen(CONFIG_FW_PATH) + strlen(fw_name) + 1);
    memcpy(fw_path, CONFIG_FW_PATH, strlen(CONFIG_FW_PATH));
    memcpy(fw_path + strlen(CONFIG_FW_PATH), fw_name, strlen(fw_name));

    ecrnx_printk_fw_dl("%s,custom fw download, Checking firmware... (%s)\n",  __func__, fw_path);
    eswin_fw_alloc(&tr->fw);

    ecrnx_printk_fw_dl("%s, Checking firmware... (%s)\n",	__func__, fw_path);

    if (eswin_fw_isFileReadable(fw_path, NULL) == false)
    {
        ecrnx_printk_err("%s acquire FW from file:%s\n", __func__, fw_path);
        goto err_fw;
    }

    status = eswin_fw_retriveFromFile(fw_path, tr->fw->data, 1024*1024);
    if (status <= 0) {
        ecrnx_printk_err("%s, error status = %d\n",	__func__, status);
        goto err_fw;
    }
    tr->fw->size = status;
#else
#if defined(CONFIG_FW_LOADER) || (defined(CONFIG_FW_LOADER_MODULE) && defined(MODULE))
    ecrnx_printk_fw_dl("%s, Checking firmware... (%s)\n",  __func__, fw_name);
    
    status = request_firmware((const struct firmware **)&tr->fw, fw_name, tr->dev);
    if (status != 0) {
        ecrnx_printk_err("%s, error status = %d\n",  __func__, status);
		tr->fw = NULL;
        goto err_fw;
    }
#endif
#endif
    ecrnx_printk_fw_dl("%s, request fw OK and size is %d\n", __func__, tr->fw->size);

    if(fw_check_head(tr) == false)
    {
        goto err_fw;
    }
    return true;


err_fw:
#ifdef CONFIG_CUSTOM_FIRMWARE_DOWNLOAD
    if(fw_path != NULL)
    {
        kfree(fw_path);
        fw_path = NULL;
    }
#endif
    return false;
}

bool eswin_system_running(struct eswin *tr)
{
    int ret;
    struct sk_buff *skb;
    char str_sync[4] = {0x63, 0x6E, 0x79, 0x73};
    skb = dev_alloc_skb(10);
    memcpy(skb->data, str_sync, 4);
    ret = tr->ops->write(tr, skb->data, 4);

    printk("eswin_system_running, ret: %d\n", ret);
    dev_kfree_skb(skb);
    if(ret == 0)
    {
        msleep(100);
    }
    return ret;
}




/**
******************************************************************************
*
* @file fw_load.h
*
* @brief ecrnx usb firmware load functions
*
* Copyright (C) ESWIN 2015-2020
*
******************************************************************************
*/

#ifndef _FW_LOAD_H_
#define _FW_LOAD_H_

#include "ecrnx_defs.h"

#define HEAD_SIZE  (64)
#define INFO_SIZE  (48)

typedef struct _firmware_file {
    char* data;
    unsigned int size;
}firmware_file;

int eswin_fw_isFileReadable(const char *path, u32 *sz);
int eswin_fw_retriveFromFile(const char *path, u8 *buf, u32 sz);
int eswin_fw_alloc(firmware_file **pFw);
int eswin_fw_release(firmware_file *fw);

#endif


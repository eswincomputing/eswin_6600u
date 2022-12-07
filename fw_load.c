#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/uaccess.h>
#include <asm/uaccess.h>
#include "fw_load.h"


static int openFile(struct file **fpp, const char *path, int flag, int mode)
{
    struct file *fp;

    fp = filp_open(path, flag, mode);
    if (IS_ERR(fp)) {
        *fpp = NULL;
        return PTR_ERR(fp);
    } else {
        *fpp = fp;
        return 0;
    }
}

static int closeFile(struct file *fp)
{
    filp_close(fp, NULL);
    return 0;
}


static int readFile(struct file *fp, char *buf, int len)
{
    int rlen = 0, sum = 0;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
    if (!(fp->f_mode & FMODE_CAN_READ))
#else
    if (!fp->f_op || !fp->f_op->read)
#endif
        return -EPERM;

    while (sum < len) {
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0))
        rlen = kernel_read(fp, buf + sum, len - sum, &fp->f_pos);
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 1, 0))
        rlen = __vfs_read(fp, buf + sum, len - sum, &fp->f_pos);
#else
        rlen = fp->f_op->read(fp, buf + sum, len - sum, &fp->f_pos);
#endif
        if (rlen > 0)
            sum += rlen;
        else if (0 != rlen)
            return rlen;
        else
            break;
    }

    return  sum;

}

int eswin_fw_isFileReadable(const char *path, u32 *sz)
{
    struct file *fp;
    int ret = 0;
    mm_segment_t oldfs;
    char buf;

    fp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(fp))
        ret = PTR_ERR(fp);
    else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
        oldfs = get_fs();
        set_fs( get_ds() );
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
        oldfs = get_fs();
        set_fs( KERNEL_DS );
#else
        oldfs = force_uaccess_begin();
#endif

        if (1 != readFile(fp, &buf, 1))
            ret = PTR_ERR(fp);

        if (ret == 0 && sz) {
            #if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0))
            *sz = i_size_read(fp->f_path.dentry->d_inode);
            #else
            *sz = i_size_read(fp->f_dentry->d_inode);
            #endif
        }
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
            set_fs(oldfs);
#else
            force_uaccess_end(oldfs);
#endif
        filp_close(fp, NULL);
    }
    if (ret == 0)
        return true;
    else
        return false;
}

int eswin_fw_retriveFromFile(const char *path, u8 *buf, u32 sz)
{
    int ret = -1;
    mm_segment_t oldfs;
    struct file *fp;

    if (path && buf) {
        ret = openFile(&fp, path, O_RDONLY, 0);
        if (0 == ret) {
            //RTW_INFO("%s openFile path:%s fp=%p\n", __FUNCTION__, path , fp);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,0,0)
            oldfs = get_fs();
            set_fs( get_ds() );
#elif LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
            oldfs = get_fs();
            set_fs( KERNEL_DS );
#else
            oldfs = force_uaccess_begin();
#endif
            ret = readFile(fp, buf, sz);
#if LINUX_VERSION_CODE < KERNEL_VERSION(5,10,0)
            set_fs(oldfs);
#else
            force_uaccess_end(oldfs);
#endif
            closeFile(fp);

            ecrnx_printk_fw_dl("%s readFile, ret:%d\n", __FUNCTION__, ret);

        }
        else
        {
            ecrnx_printk_err("%s openFile path:%s Fail, ret:%d\n", __FUNCTION__, path, ret);
        }
    } else {
        ecrnx_printk_err("%s NULL pointer\n", __FUNCTION__);
        ret =  -EINVAL;
    }
    return ret;
}

int eswin_fw_alloc(firmware_file **pFw)
{
    firmware_file *fw;
    *pFw = kmalloc(sizeof(firmware_file),GFP_KERNEL);
    fw = *pFw;
    fw->data = kmalloc(1024*1024,GFP_KERNEL);
    return true;
}

int eswin_fw_release(firmware_file *fw)
{
    if(fw->data != NULL)
    {
        kfree(fw->data);
    }

    if(fw != NULL)
    {
        kfree(fw);
    }
    return true;
}


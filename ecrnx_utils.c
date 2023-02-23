/**
 * ecrnx_utils.c
 *
 * IPC utility function definitions
 *
 * Copyright (C) ESWIN 2015-2020
 */
#include "ecrnx_utils.h"
#include "ecrnx_defs.h"
#include "ecrnx_rx.h"
#include "ecrnx_tx.h"
#include "ecrnx_msg_rx.h"
#include "ecrnx_debugfs.h"
#include "ecrnx_prof.h"
#include "ipc_host.h"

#ifdef CONFIG_ECRNX_ESWIN_SDIO
#include "eswin_utils.h"
#include "ecrnx_sdio.h"
#include "sdio.h"
#elif defined(CONFIG_ECRNX_ESWIN_USB)
#include "eswin_utils.h"
#include "ecrnx_usb.h"
#include "usb.h"
#endif

#if defined(CONFIG_ECRNX_DEBUGFS_CUSTOM)
#include "ecrnx_debugfs_func.h"
#endif

/**
 * ecrnx_ipc_elem_var_allocs - Alloc a single ipc buffer and push it to fw
 *
 * @ecrnx_hw: Main driver structure
 * @elem: Element to allocate
 * @elem_size: Size of the element to allcoate
 * @dir: DMA direction
 * @buf: If not NULL, used this buffer instead of allocating a new one. It must
 * be @elem_size long and be allocated by kmalloc as kfree will be called.
 * @init: Pointer to initial data to write in buffer before DMA sync. Needed
 * only if direction is DMA_TO_DEVICE. If set it is assume that its size is
 * @elem_size.
 * @push: Function to push the element to fw. May be set to NULL.
 *
 * It allocates a buffer (or use the one provided with @buf), initializes it if
 * @init is set, map buffer for DMA transfer, initializes @elem and push buffer
 * to FW if @push is seet.
 *
 * Return: 0 on success and <0 upon error. If error is returned any allocated
 * memory has been freed (including @buf if set).
 */
int ecrnx_ipc_elem_var_allocs(struct ecrnx_hw *ecrnx_hw,
                             struct ecrnx_ipc_elem_var *elem, size_t elem_size,
                             enum dma_data_direction dir,
                             void *buf, const void *init,
                             void (*push)(struct ipc_host_env_tag *, uint32_t))
{
    if (buf) {
        elem->addr = buf;
    } else {
        elem->addr = kmalloc(elem_size, GFP_KERNEL);
        if (!elem->addr) {
            dev_err(ecrnx_hw->dev, "Allocation of ipc buffer failed\n");
            return -ENOMEM;
        }
    }
    elem->size = elem_size;

    if ((dir == DMA_TO_DEVICE) && init) {
        memcpy(elem->addr, init, elem_size);
    }

    elem->dma_addr = (ptr_addr)elem->addr;
    return 0;
}

/**
 * ecrnx_ipc_elem_var_deallocs() - Free memory allocated for a single ipc buffer
 *
 * @ecrnx_hw: Main driver structure
 * @elem: Element to free
 */
void ecrnx_ipc_elem_var_deallocs(struct ecrnx_hw *ecrnx_hw,
                                struct ecrnx_ipc_elem_var *elem)
{
    if (!elem->addr)
        return;
    kfree(elem->addr);
    elem->addr = NULL;
}

/**
 * ecrnx_ipc_skb_elem_allocs() - Allocate and push a skb buffer for the FW
 *
 * @ecrnx_hw: Main driver data
 * @elem: Pointer to the skb elem that will contain the address of the buffer
 */
int ecrnx_ipc_skb_elem_allocs(struct ecrnx_hw *ecrnx_hw,
                                 struct ecrnx_ipc_skb_elem *elem, size_t skb_size,
                                 enum dma_data_direction dir,
                                 int (*push)(struct ipc_host_env_tag *,
                                             void *, uint32_t))
{
    elem->skb = dev_alloc_skb(skb_size);
    if (unlikely(!elem->skb)) {
        dev_err(ecrnx_hw->dev, "Allocation of ipc skb failed\n");
        return -ENOMEM;
    }

    elem->dma_addr = dma_map_single(ecrnx_hw->dev, elem->skb->data, skb_size, dir);
    if (unlikely(dma_mapping_error(ecrnx_hw->dev, elem->dma_addr))) {
        dev_err(ecrnx_hw->dev, "DMA mapping failed\n");
        dev_kfree_skb(elem->skb);
        elem->skb = NULL;
        return -EIO;
    }

    if (push){
        push(ecrnx_hw->ipc_env, elem, elem->dma_addr);
    }
    return 0;
}

/**
 * ecrnx_elems_allocs() - Allocate IPC storage elements.
 * @ecrnx_hw: Main driver data
 *
 * This function allocates all the elements required for communications with
 * LMAC, such as Rx Data elements, MSGs elements, ...
 * This function should be called in correspondence with the deallocation function.
 */
static int ecrnx_elems_allocs(struct ecrnx_hw *ecrnx_hw)
{
    ecrnx_printk_debug(ECRNX_FN_ENTRY_STR);
    return 0;

}

void ecrnx_set_ipc_env_msg_flag(struct ecrnx_hw *ecrnx_hw)
{
    ecrnx_hw->ipc_env->msga2e_hostid = NULL;
}

void dump_cmd_mgr_queue(struct ecrnx_cmd_mgr *cmd_mgr);
/**
 * ecrnx_ipc_msg_push() - Push a msg to IPC queue
 *
 * @ecrnx_hw: Main driver data
 * @msg_buf: Pointer to message
 * @len: Size, in bytes, of message
 */
void ecrnx_ipc_msg_push(struct ecrnx_hw *ecrnx_hw, void *msg_buf, uint16_t len)
{
    ecrnx_hw->msg_tx++;
    struct ecrnx_cmd *cmd = (struct ecrnx_cmd *)msg_buf;
    ecrnx_printk_msg("%s:msg_tx:%d, id:0x%x, reqid:0x%x, flags:0x%x, hostid:%p \n", __func__, ecrnx_hw->msg_tx, cmd->id, cmd->reqid, cmd->flags, ecrnx_hw->ipc_env->msga2e_hostid);

    if (ecrnx_hw->ipc_env->msga2e_hostid) {
        dump_cmd_mgr_queue(&ecrnx_hw->cmd_mgr);
    }
    ipc_host_msg_push(ecrnx_hw->ipc_env, msg_buf, len);
}

/**
 * ecrnx_ipc_txdesc_push() - Push a txdesc to FW
 *
 * @ecrnx_hw: Main driver data
 * @tx_desc: Pointer on &struct txdesc_api to push to FW
 * @hostid: Pointer save in ipc env to retrieve tx buffer upon confirmation.
 * @hw_queue: Hw queue to push txdesc to
 * @user: User position to push the txdesc to. It must be set to 0 if  MU-MIMMO
 * is not used.
 */
void ecrnx_ipc_txdesc_push(struct ecrnx_hw *ecrnx_hw, void *tx_desc,
                          void *hostid, int hw_queue, int user)
{
    ecrnx_frame_send(ecrnx_hw, tx_desc, hostid, hw_queue, user);
}

/**
 * ecrnx_ipc_fw_trace_desc_get() - Return pointer to the start of trace
 * description in IPC environment
 *
 * @ecrnx_hw: Main driver data
 */
void *ecrnx_ipc_fw_trace_desc_get(struct ecrnx_hw *ecrnx_hw)
{
    return NULL;
}

/**
 * ecrnx_ipc_sta_buffer - Update counter of bufferred data for a given sta
 *
 * @ecrnx_hw: Main driver data
 * @sta: Managed station
 * @tid: TID on which data has been added or removed
 * @size: Size of data to add (or remove if < 0) to STA buffer.
 */
void ecrnx_ipc_sta_buffer(struct ecrnx_hw *ecrnx_hw, struct ecrnx_sta *sta, int tid, int size)
{
}

/**
 * ecrnx_msgind() - IRQ handler callback for %IPC_IRQ_E2A_MSG
 *
 * @pthis: Pointer to main driver data
 * @hostid: Pointer to IPC elem from e2amsgs_pool
 */
static u8 ecrnx_msgind(void *pthis, void *hostid)
{
    struct ecrnx_hw *ecrnx_hw = pthis;
	u8 ret = 0;

    struct ipc_e2a_msg *msg = NULL;

    ecrnx_hw->msg_rx++;

    if(!pthis || !hostid){
        ecrnx_printk_err(" %s input param error!! \n", __func__);
        return ret;
    }
    msg = hostid;

    ecrnx_printk_msg("%s: msg_id:0x%x, dest_id:0x%x, src_id:0x%x!!\n", __func__, msg->id, msg->dummy_dest_id, msg->dummy_src_id);
    /* Relay further actions to the msg parser */
    ecrnx_rx_handle_msg(ecrnx_hw, msg);
    return ret;
}

/**
 * ecrnx_msgackind() - IRQ handler callback for %IPC_IRQ_E2A_MSG_ACK
 *
 * @pthis: Pointer to main driver data
 * @hostid: Pointer to command acknoledged
 */
static u8 ecrnx_msgackind(void *pthis, void *hostid)
{
    struct ecrnx_hw *ecrnx_hw = (struct ecrnx_hw *)pthis;

    //ecrnx_printk_tx("%s");
    ecrnx_hw->msg_tx_done++;
    ecrnx_hw->cmd_mgr.llind(&ecrnx_hw->cmd_mgr, (struct ecrnx_cmd *)hostid);
    return -1;
}

/**
 * ecrnx_radarind() - IRQ handler callback for %IPC_IRQ_E2A_RADAR
 *
 * @pthis: Pointer to main driver data
 * @hostid: Pointer to IPC elem from e2aradars_pool
 */
static u8 ecrnx_radarind(void *pthis, void *hostid)
{
#ifdef CONFIG_ECRNX_RADAR
    struct ecrnx_hw *ecrnx_hw = pthis;
    struct ecrnx_ipc_elem *elem = hostid;
    struct radar_pulse_array_desc *pulses = elem->addr;
    u8 ret = 0;
    int i;

    /* Look for pulse count meaning that this hostbuf contains RADAR pulses */
    if (pulses->cnt == 0) {
        ret = -1;
        goto radar_no_push;
    }

    if (ecrnx_radar_detection_is_enable(&ecrnx_hw->radar, pulses->idx)) {
        /* Save the received pulses only if radar detection is enabled */
        for (i = 0; i < pulses->cnt; i++) {
            struct ecrnx_radar_pulses *p = &ecrnx_hw->radar.pulses[pulses->idx];

            p->buffer[p->index] = pulses->pulse[i];
            p->index = (p->index + 1) % ECRNX_RADAR_PULSE_MAX;
            if (p->count < ECRNX_RADAR_PULSE_MAX)
                p->count++;
        }

        /* Defer pulse processing in separate work */
        if (! work_pending(&ecrnx_hw->radar.detection_work))
            schedule_work(&ecrnx_hw->radar.detection_work);
    }

    /* Reset the radar element and re-use it */
    pulses->cnt = 0;
radar_no_push:
    return ret;
#else
    return -1;
#endif
}

/**
 * ecrnx_prim_tbtt_ind() - IRQ handler callback for %IPC_IRQ_E2A_TBTT_PRIM
 *
 * @pthis: Pointer to main driver data
 */
static void ecrnx_prim_tbtt_ind(void *pthis)
{
}

/**
 * ecrnx_sec_tbtt_ind() - IRQ handler callback for %IPC_IRQ_E2A_TBTT_SEC
 *
 * @pthis: Pointer to main driver data
 */
static void ecrnx_sec_tbtt_ind(void *pthis)
{
}

/**
 * ecrnx_dbgind() - IRQ handler callback for %IPC_IRQ_E2A_DBG
 *
 * @pthis: Pointer to main driver data
 * @hostid: Pointer to IPC elem from dbgmsgs_pool
 */
 
#ifdef CONFIG_ECRNX_ESWIN_USB
 extern void usb_dbg_printf(void * data, int len);
#endif
static u8 ecrnx_dbgind(void *pthis, void *hostid)
{
    u8 ret = 0;

    struct sk_buff *skb = (struct sk_buff *)hostid;
#ifdef CONFIG_ECRNX_ESWIN_USB
    usb_dbg_printf(skb->data, skb->len);
#else
    uint8_t string[IPC_DBG_PARAM_SIZE] = {0}; 
    if(skb->len < IPC_DBG_PARAM_SIZE)
    {
        memcpy(string, skb->data, skb->len);
    }
    else
    {
        ecrnx_printk_err("waring: string buff no enough \n");
        memcpy(string, skb->data, IPC_DBG_PARAM_SIZE-1);
    }
    ecrnx_printk_always("%s %s", (char *)FW_STR, (char *)string);
#endif

    return ret;
}

void ecrnx_release_list(struct ecrnx_hw *ecrnx_hw, bool is_exit)
{
#ifdef CONFIG_WIRELESS_EXT
    struct wlan_network *entry, *next;
#endif

#if defined(CONFIG_ECRNX_DEBUGFS_CUSTOM)
    struct ecrnx_debugfs_survey_info_tbl *note, *tmp;
#endif

#ifdef CONFIG_WIRELESS_EXT
    list_for_each_entry_safe(entry, next, &ecrnx_hw->scan_list, list) {
        list_del(&entry->list);
        kfree(entry);
    }
#endif

#if defined(CONFIG_ECRNX_DEBUGFS_CUSTOM)
    if(is_exit)
    {
        list_for_each_entry_safe(note, tmp, &ecrnx_hw->debugfs_survey_info_tbl_ptr, list)
        {
            list_del(&note->list);
            kfree(note);
        }
    }
#endif
}

/**
 * ecrnx_ipc_init() - Initialize IPC interface.
 *
 * @ecrnx_hw: Main driver data
 * @shared_ram: Pointer to shared memory that contains IPC shared struct
 *
 * This function initializes IPC interface by registering callbacks, setting
 * shared memory area and calling IPC Init function.
 * It should be called only once during driver's lifetime.
 */
int ecrnx_ipc_init(struct ecrnx_hw *ecrnx_hw, u8 *shared_ram)
{
    struct ipc_host_cb_tag cb;
    int res;

    ecrnx_printk_init(ECRNX_FN_ENTRY_STR);

    /* initialize the API interface */
    cb.recv_data_ind   = ecrnx_rxdataind;
    cb.recv_radar_ind  = ecrnx_radarind;
    cb.recv_msg_ind    = ecrnx_msgind;
    cb.recv_msgack_ind = ecrnx_msgackind;
    cb.recv_dbg_ind    = ecrnx_dbgind;
    cb.send_data_cfm   = ecrnx_txdatacfm;
    cb.handle_data_cfm   = ecrnx_handle_tx_datacfm;

    cb.prim_tbtt_ind   = ecrnx_prim_tbtt_ind;
    cb.sec_tbtt_ind    = ecrnx_sec_tbtt_ind;
    cb.recv_unsup_rx_vec_ind = ecrnx_unsup_rx_vec_ind;

    /* set the IPC environment */
    ecrnx_hw->ipc_env = (struct ipc_host_env_tag *)
                       kzalloc(sizeof(struct ipc_host_env_tag), GFP_KERNEL);

    if (!ecrnx_hw->ipc_env)
        return -ENOMEM;

    /* call the initialization of the IPC */
    ipc_host_init(ecrnx_hw->ipc_env, &cb,
                  (struct ipc_shared_env_tag *)shared_ram, ecrnx_hw);

    ecrnx_cmd_mgr_init(&ecrnx_hw->cmd_mgr);

#ifdef CONFIG_WIRELESS_EXT
    INIT_LIST_HEAD(&ecrnx_hw->scan_list);
#endif

    ecrnx_rx_reord_init(ecrnx_hw);
#ifdef CONFIG_ECRNX_ESWIN_SDIO
    ecrnx_sdio_init(ecrnx_hw);
#elif defined(CONFIG_ECRNX_ESWIN_USB)
    ecrnx_usb_init(ecrnx_hw);
#endif

    res = ecrnx_elems_allocs(ecrnx_hw);
    if (res) {

        kfree(ecrnx_hw->ipc_env);
        ecrnx_hw->ipc_env = NULL;
    }

    return res;
}

/**
 * ecrnx_ipc_deinit() - Release IPC interface
 *
 * @ecrnx_hw: Main driver data
 */
void ecrnx_ipc_deinit(struct ecrnx_hw *ecrnx_hw)
{
    ecrnx_printk_exit(ECRNX_FN_ENTRY_STR);

    ecrnx_ipc_tx_drain(ecrnx_hw);
    ecrnx_cmd_mgr_deinit(&ecrnx_hw->cmd_mgr);

    ecrnx_rx_reord_deinit(ecrnx_hw);
    ecrnx_release_list(ecrnx_hw, true);

    if(ecrnx_hw->sw_txhdr_cache)
        kmem_cache_destroy(ecrnx_hw->sw_txhdr_cache);

    if (ecrnx_hw->ipc_env->shared) {
        kfree(ecrnx_hw->ipc_env->shared);
        ecrnx_hw->ipc_env->shared = NULL;
    }
    if (ecrnx_hw->ipc_env) {
        kfree(ecrnx_hw->ipc_env);
        ecrnx_hw->ipc_env = NULL;
    }

}

/**
 * ecrnx_ipc_start() - Start IPC interface
 *
 * @ecrnx_hw: Main driver data
 */
void ecrnx_ipc_start(struct ecrnx_hw *ecrnx_hw)
{
    ipc_host_enable_irq(ecrnx_hw->ipc_env, IPC_IRQ_E2A_ALL);
}

/**
 * ecrnx_ipc_stop() - Stop IPC interface
 *
 * @ecrnx_hw: Main driver data
 */
void ecrnx_ipc_stop(struct ecrnx_hw *ecrnx_hw)
{
    ipc_host_disable_irq(ecrnx_hw->ipc_env, IPC_IRQ_E2A_ALL);
}

/**
 * ecrnx_ipc_tx_drain() - Flush IPC TX buffers
 *
 * @ecrnx_hw: Main driver data
 *
 * This assumes LMAC is still (tx wise) and there's no TX race until LMAC is up
 * tx wise.
 * This also lets both IPC sides remain in sync before resetting the LMAC,
 * e.g with ecrnx_send_reset.
 */
void ecrnx_ipc_tx_drain(struct ecrnx_hw *ecrnx_hw)
{
    int i, j;

    ecrnx_printk_tx(ECRNX_FN_ENTRY_STR);

    if (!ecrnx_hw->ipc_env) {
        printk(KERN_CRIT "%s: bypassing (restart must have failed)\n", __func__);
        return;
    }

    for (i = 0; i < ECRNX_HWQ_NB; i++) {
        for (j = 0; j < nx_txuser_cnt[i]; j++) {
            struct sk_buff *skb;
            while ((skb = (struct sk_buff *)ipc_host_tx_flush(ecrnx_hw->ipc_env, i, j))) {
                struct ecrnx_sw_txhdr *sw_txhdr =
                    ((struct ecrnx_txhdr *)skb->data)->sw_hdr;
                skb_pull(skb, sw_txhdr->headroom);
                dev_kfree_skb_any(skb);
            }
        }
    }
}

/**
 * ecrnx_ipc_tx_pending() - Check if TX pframes are pending at FW level
 *
 * @ecrnx_hw: Main driver data
 */
bool ecrnx_ipc_tx_pending(struct ecrnx_hw *ecrnx_hw)
{
    return ipc_host_tx_frames_pending(ecrnx_hw->ipc_env);
}

/**
 * ecrnx_error_ind() - %DBG_ERROR_IND message callback
 *
 * @ecrnx_hw: Main driver data
 *
 * This function triggers the UMH script call that will indicate to the user
 * space the error that occurred and stored the debug dump. Once the UMH script
 * is executed, the ecrnx_umh_done() function has to be called.
 */
void ecrnx_error_ind(struct ecrnx_hw *ecrnx_hw)
{
    struct ecrnx_ipc_elem_var *elem = &ecrnx_hw->dbgdump_elem.buf;
    struct dbg_debug_dump_tag *dump = elem->addr;

    dma_sync_single_for_device(ecrnx_hw->dev, elem->dma_addr, elem->size,
                               DMA_FROM_DEVICE);
    dev_err(ecrnx_hw->dev, "(type %d): dump received\n",
            dump->dbg_info.error_type);

#ifdef CONFIG_ECRNX_DEBUGFS
    ecrnx_hw->debugfs.trace_prst = true;
    ecrnx_trigger_um_helper(&ecrnx_hw->debugfs);
#endif
}

/**
 * ecrnx_umh_done() - Indicate User Mode helper finished
 *
 * @ecrnx_hw: Main driver data
 *
 */
void ecrnx_umh_done(struct ecrnx_hw *ecrnx_hw)
{
    if (!test_bit(ECRNX_DEV_STARTED, &ecrnx_hw->flags))
        return;

    /* this assumes error_ind won't trigger before ipc_host_dbginfobuf_push
       is called and so does not irq protect (TODO) against error_ind */
#ifdef CONFIG_ECRNX_DEBUGFS
    ecrnx_hw->debugfs.trace_prst = false;
#endif
}

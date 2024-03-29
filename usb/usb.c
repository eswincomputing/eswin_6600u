/**
 ******************************************************************************
 *
 * @file usb.c
 *
 * @brief usb driver function definitions
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ******************************************************************************
 */
#include <linux/version.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/gpio.h>
#include <linux/timer.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <uapi/linux/sched/types.h>
#endif
//#include <linux/usb.h>
#include "usb.h"

#include "core.h"
//#include "debug.h"
#include "ecrnx_usb.h"

#include "usb_host_interface.h"
#include "ecrnx_compat.h"
#include "fw_head_check.h"
#include "slave_log_buf.h"

#define USB_RX_TIMER_TIMEOUT_US          (200)
//TCP PKG MAX LEN:1594; UDP PKG MAX LEN:1582
#define USB_RX_LENGTH_THD                (1594)
#define USB_RX_UPLOAD_THD                (12)
#define USB_RX_FRAG_MAX_CNT              (6)

static struct eswin_usb * g_usb;
static unsigned int rx_packets =0;
static unsigned int rx_packets_len =0;
static struct timer_list usb_rx_timer = {0};

static void usb_refill_recv_transfer(struct usb_infac_pipe * pipe);


#define USB_LOG_MEM_SIZE	(512*8)//(512*16)
#define USB_LOG_MAX_SIZE	512

struct ring_buffer buf_handle = {0};

#if defined(CONFIG_ECRNX_DEBUGFS_CUSTOM)
struct ring_buffer *usb_dbg_buf_get(void)
{
    if(buf_handle.init == false)
    {
        ring_buffer_init(&buf_handle, USB_LOG_MEM_SIZE);
    }
    return &buf_handle;
}
#endif

void usb_dbg_printf(void * data, int len)
{
    if(buf_handle.init == false)
    {
        ring_buffer_init(&buf_handle, USB_LOG_MEM_SIZE);
    }
    ring_buffer_put(&buf_handle, data, len);
}


static struct usb_urb_context *
usb_alloc_urb_from_pipe(struct usb_infac_pipe *pipe)
{
	struct usb_urb_context *urb_context = NULL;
	unsigned long flags;

	spin_lock_irqsave(&g_usb->cs_lock, flags);
	if (!list_empty(&pipe->urb_list_head)) {
		urb_context = list_first_entry(&pipe->urb_list_head,
					       struct usb_urb_context, link);
		list_del(&urb_context->link);
		pipe->urb_cnt--;
	}
	spin_unlock_irqrestore(&g_usb->cs_lock, flags);

	return urb_context;
}



static void usb_free_urb_to_infac(struct usb_infac_pipe * pipe,
					struct usb_urb_context *urb_context)
{
	unsigned long flags;

	spin_lock_irqsave(&g_usb->cs_lock, flags);
	pipe->urb_cnt++;
	list_add(&urb_context->link, &pipe->urb_list_head);
    if(urb_context->urb)
    {
        usb_unanchor_urb(urb_context->urb);
        usb_free_urb(urb_context->urb);
        urb_context->urb = NULL;
    }
	spin_unlock_irqrestore(&g_usb->cs_lock, flags);
}

static void usb_cleanup_recv_urb(struct usb_urb_context *urb_context)
{
	dev_kfree_skb(urb_context->skb);
	urb_context->skb = NULL;

	usb_free_urb_to_infac(urb_context->pipe, urb_context);
}

static void usb_free_pipe_resources(struct usb_infac_pipe *pipe)
{
	struct usb_urb_context *urb_context;
    unsigned long flags;
       for (;;) {
        urb_context = NULL;
        if (!list_empty(&pipe->urb_stack_list_head)) {
            urb_context = list_first_entry(&pipe->urb_stack_list_head,
                               struct usb_urb_context, total_link);
            list_del(&urb_context->total_link);
        }


        if (!urb_context)
               break;
        if(urb_context->skb)
        {
            dev_kfree_skb(urb_context->skb);
            urb_context->skb = NULL;
        }

        if(urb_context->urb)
        {
            usb_unanchor_urb(urb_context->urb);
            usb_free_urb(urb_context->urb);
            urb_context->urb = NULL;
        }
        kfree(urb_context);
       }

}

static void usb_transmit_complete(struct urb *urb)
{
	struct usb_urb_context *urb_context = urb->context;
	struct usb_infac_pipe *pipe = urb_context->pipe;
	struct sk_buff *skb;
	struct txdesc_api *tx_desc;
	u32_l flag = 0;

	ecrnx_printk_trans("%s, urb:0x%x, skb:0x%x, dir:%d; \n", __func__, urb, urb_context->skb, pipe->dir);

	if (urb->status != 0) {
        pipe->err_count++;
        if(pipe->err_count%100 == 1)
        {
            ecrnx_printk_err( "pipe-dir: %d, failed:%d\n",
			pipe->dir, urb->status);
        }
        if((pipe->err_status != urb->status)||(pipe->err_count == 10000))
        {
            pipe->err_status = urb->status;
            pipe->err_count = 0;
        }
	}

	skb = urb_context->skb;
	urb_context->skb = NULL;
	usb_free_urb_to_infac(urb_context->pipe, urb_context);

	flag = *(u32_l *)skb->data;
	if((u8_l)(flag & FLAG_MSG_TYPE_MASK) == TX_FLAG_TX_DESC)
	{
		tx_desc = (struct txdesc_api *)((u32_l *)skb->data + 1);
		if (tx_desc->host.flags & TXU_CNTRL_MGMT)
		{
			return;
		}
	}

	skb_queue_tail(&pipe->io_comp_queue, skb);
#ifdef CONFIG_ECRNX_KTHREAD
	wake_up_interruptible(&g_usb->wait_tx_comp);
#endif
#ifdef CONFIG_ECRNX_WORKQUEUE
	schedule_work(&pipe->io_complete_work);
#endif
#ifdef CONFIG_ECRNX_TASKLET
	tasklet_schedule(&pipe->tx_tasklet);
#endif
}


void usb_rx_timer_handle(struct timer_list *time)
{
    if (rx_packets)
    {
        rx_packets = 0;
        rx_packets_len = 0;
        #ifdef CONFIG_ECRNX_KTHREAD
	    wake_up_interruptible(&g_usb->wait_rx_comp);
        #endif
        #ifdef CONFIG_ECRNX_WORKQUEUE
	    schedule_work(&g_usb->infac_data.pipe_rx.io_complete_work);
        #endif
        #ifdef CONFIG_ECRNX_TASKLET
	    tasklet_schedule(&g_usb->infac_data.pipe_rx.rx_tasklet);
        #endif
    }
}

static struct sk_buff * last_skb[USB_RX_FRAG_MAX_CNT] = {0};
static u16_l last_idx = 0;
static u16_l frag_cnt = 0;
static u16_l total_len = 0;
static inline void *usb_skb_put_data(struct sk_buff *skb, const void *data,
				 unsigned int len)
{
	void *tmp = skb_put(skb, len);

	memcpy(tmp, data, len);

	return tmp;
}

static void usb_recv_complete(struct urb *urb)
{
	struct usb_urb_context *urb_context = urb->context;
	struct usb_infac_pipe *pipe = urb_context->pipe;
	struct sk_buff *skb;
	int status = 0;
    u16_l i;

	//ECRNX_PRINT(" %s entry, dir: %d!!", __func__, pipe->dir);


	//ECRNX_PRINT( " usb recv pipe-dir %d stat %d len %d urb 0x%pK\n",
	//	   pipe->dir, urb->status, urb->actual_length,
	//	   urb);

	if (urb->status != 0) {
		status = -EIO;
		switch (urb->status) {
		case -ECONNRESET:
		case -ENOENT:
		case -ESHUTDOWN:
			/* no need to spew these errors when device
			 * removed or urb killed due to driver shutdown
			 */
			status = -ECANCELED;
			break;
		default:
            pipe->err_count++;
            if(pipe->err_count%100 == 1)
            {
			    ecrnx_printk_err("usb redcv pipe-dir %d  failed: %d\n",
				   pipe->dir, urb->status);
            }
            if((pipe->err_status != status)||(pipe->err_count == 10000))
            {
                pipe->err_status = status;
                pipe->err_count = 0;
            }
			break;
		}
		goto cleanup_recv_urb;
	}

	if (urb->actual_length == 0)
		goto cleanup_recv_urb;

	skb = urb_context->skb;

	/* we are going to pass it up */
	urb_context->skb = NULL;
	skb_put(skb, urb->actual_length);

    struct rxu_stat_mm *rxu_state = (struct rxu_stat_mm*)skb->data;
    //printk("skb->len:%d %d %d\n", skb->len, urb->actual_length,rxu_state->is_usb_frag);
    if (urb->actual_length == USB_RX_MAX_BUF_SIZE && rxu_state->is_amsdu == 1 && rxu_state->is_usb_frag >=1 && !frag_cnt && !last_idx) {
        last_skb[last_idx++] = skb;
        frag_cnt = rxu_state->is_usb_frag;
        total_len = skb->len;
        goto free_urb;
    } else if (last_idx && frag_cnt) {
        frag_cnt = frag_cnt - 1;
        if (last_idx < USB_RX_FRAG_MAX_CNT) {   
            last_skb[last_idx++] = skb;
        } else {
            for(i = 0; i < last_idx; i++) {
                dev_kfree_skb(last_skb[i]);
            }
            last_idx = frag_cnt = total_len = 0;
            goto free_urb;
        }
        total_len += skb->len;
        if (frag_cnt) {
            goto free_urb;
        }
    }

    if(last_idx && !frag_cnt) {
        struct sk_buff *total;

        //printk("total_len=%d last_idx=%d\n", total_len, last_idx);
        total = dev_alloc_skb(total_len);
        if (!total) {
            for(i = 0; i < last_idx; i++) {
                dev_kfree_skb(last_skb[i]);
            }
            last_idx = total_len = 0;
            goto free_urb;
        }

        for(i = 0; i < last_idx; i++) {
            usb_skb_put_data(total, last_skb[i]->data, last_skb[i]->len);
            dev_kfree_skb(last_skb[i]);
        }
        skb = total;
    }

    last_idx = frag_cnt = total_len = 0;
	skb_queue_tail(&pipe->io_comp_queue, skb);

#if 0
    usb_rx_cnt++;
    //printk("skb->len:%d %d %d\n", skb->len, usb_rx_cnt, urb->actual_length);
    if (skb->len < 1500 ||usb_rx_cnt > 12)
	{
	    usb_rx_cnt = 0;
	    schedule_work(&pipe->io_complete_work);
    }
#else

    rx_packets++;
    rx_packets_len +=skb->len;

    if (skb->len < USB_RX_LENGTH_THD || rx_packets > USB_RX_UPLOAD_THD || rx_packets_len > USB_RX_LENGTH_THD * USB_RX_UPLOAD_THD)
    {
        rx_packets = 0;
        rx_packets_len = 0;
        #ifdef CONFIG_ECRNX_KTHREAD
        wake_up_interruptible(&g_usb->wait_rx_comp);
        #endif
        #ifdef CONFIG_ECRNX_WORKQUEUE
        schedule_work(&pipe->io_complete_work);
        #endif
        #ifdef CONFIG_ECRNX_TASKLET
        tasklet_schedule(&pipe->rx_tasklet);
        #endif
    }
    else
    {
        mod_timer(&usb_rx_timer, jiffies + usecs_to_jiffies(USB_RX_TIMER_TIMEOUT_US));
    }
#endif

	//ECRNX_DBG(" entry %s, len: %d\n", __func__, urb->actual_length);	
	//print_hex_dump(KERN_INFO, "READ:", DUMP_PREFIX_ADDRESS, 32, 1, skb->data, urb->actual_length, false);
free_urb:
	/* note: queue implements a lock */
	usb_free_urb_to_infac(pipe, urb_context);

	usb_refill_recv_transfer(pipe);
	return;

cleanup_recv_urb:
	usb_cleanup_recv_urb(urb_context);
}

#ifdef CONFIG_ECRNX_WORKQUEUE
static void usb_tx_comp_work(struct work_struct *work)
#elif defined(CONFIG_ECRNX_TASKLET)
static void usb_tx_comp_work(unsigned long data)
#elif defined(CONFIG_ECRNX_KTHREAD)
static void usb_tx_comp_work(struct usb_infac_pipe* infac_pipe)
#endif
{
    struct usb_infac_pipe *pipe = NULL;
#ifdef CONFIG_ECRNX_WORKQUEUE
    pipe = container_of(work, struct usb_infac_pipe, io_complete_work);
#elif defined(CONFIG_ECRNX_TASKLET)
    pipe = (struct usb_infac_pipe *)data;
#elif defined(CONFIG_ECRNX_KTHREAD)
    pipe = infac_pipe;
#endif

    struct sk_buff *skb;
    struct txdesc_api *tx_desc;
    u32_l flag = 0;

    while ((skb = skb_dequeue(&pipe->io_comp_queue))) {
        //ECRNX_DBG(" %s skb dequeue, skb:0x%08x, skb len: %d!!", __func__, skb, skb->len);

        flag = *(u32_l *)skb->data;
        if((u8_l)(flag & FLAG_MSG_TYPE_MASK) != TX_FLAG_TX_DESC)
        {
            dev_kfree_skb(skb);
            continue;
        }
        tx_desc = (struct txdesc_api *)((u32_l *)skb->data + 1);
        if (g_usb->p_eswin->data_cfm_callback && ((u8_l)(flag & FLAG_MSG_TYPE_MASK) == TX_FLAG_TX_DESC) && !(tx_desc->host.flags & TXU_CNTRL_MGMT))
        {
#if (__SIZEOF_POINTER__ == 8)
            ptr_addr host_id;
            memcpy(&host_id, tx_desc->host.packet_addr, sizeof(ptr_addr));
            g_usb->p_eswin->data_cfm_callback(g_usb->p_eswin->umac_priv, (void*)host_id);
#else
            g_usb->p_eswin->data_cfm_callback(g_usb->p_eswin->umac_priv, (void*)(*(u32_l*)(tx_desc->host.packet_addr)));
#endif
        }
    }
}

#ifdef CONFIG_ECRNX_WORKQUEUE
static void usb_rx_comp_work(struct work_struct *work)
#elif defined(CONFIG_ECRNX_TASKLET)
static void usb_rx_comp_work(unsigned long data)
#elif defined(CONFIG_ECRNX_KTHREAD)
static void usb_rx_comp_work(struct usb_infac_pipe* infac_pipe)
#endif
{
   struct usb_infac_pipe *pipe = NULL;
#ifdef CONFIG_ECRNX_WORKQUEUE
    pipe = container_of(work, struct usb_infac_pipe, io_complete_work);
#elif defined(CONFIG_ECRNX_TASKLET)
    pipe = (struct usb_infac_pipe *)data;
#elif defined(CONFIG_ECRNX_KTHREAD)
    pipe = infac_pipe;
#endif

    struct sk_buff *skb;

    while ((skb = skb_dequeue(&pipe->io_comp_queue))) {
        if (g_usb->p_eswin->rx_callback) {
            g_usb->p_eswin->rx_callback(g_usb->p_eswin->umac_priv, skb, usb_pipeendpoint(pipe->usb_pipe_handle));
        }
        else {
            if (skb) { // free the skb
                ecrnx_printk_trans("%s, skb free: 0x%x !! \n",__func__);
                dev_kfree_skb(skb);
            }
        }
    }
}

#ifdef CONFIG_ECRNX_KTHREAD
static int eswin_tx_comp_thread(void *data)
{
    struct eswin_usb * p_usb = (struct eswin_usb *)data;
    int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    struct sched_param param = { .sched_priority = 1 };
    param.sched_priority = 56;
    sched_setscheduler(get_current(), SCHED_FIFO, &param);
#else
    sched_set_fifo(get_current());
#endif
    ecrnx_printk_trans("eswin_tx_comp_thread entry\n");

    while (!kthread_should_stop())
    {
        ret = wait_event_interruptible(p_usb->wait_tx_comp, skb_queue_len(&g_usb->infac_data.pipe_tx.io_comp_queue) != 0 ||
                skb_queue_len(&g_usb->infac_msg.pipe_tx.io_comp_queue) != 0 || kthread_should_stop());
        if (ret < 0)
        {
            ecrnx_printk_err("usb tx pkg thread error!\n");
            return 0;
        }
        if(kthread_should_stop())
        {
            continue;
        }

        usb_tx_comp_work(&g_usb->infac_msg.pipe_tx);
        usb_tx_comp_work(&g_usb->infac_data.pipe_tx);
    }
    ecrnx_printk_trans("tx pkg thread exit\n");
    return 0;
}

static int eswin_rx_comp_thread(void *data)
{
    struct eswin_usb * p_usb = (struct eswin_usb *)data;
    int ret;

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
    struct sched_param param = { .sched_priority = 1 };
    param.sched_priority = 56;
    sched_setscheduler(get_current(), SCHED_FIFO, &param);
#else
    sched_set_fifo(get_current());
#endif
    ecrnx_printk_trans("eswin_rx_comp_thread entry\n");

    while (!kthread_should_stop())
    {
        ret = wait_event_interruptible(p_usb->wait_rx_comp, skb_queue_len(&g_usb->infac_data.pipe_rx.io_comp_queue) != 0 ||
                skb_queue_len(&g_usb->infac_msg.pipe_rx.io_comp_queue) != 0|| kthread_should_stop());

        if (ret < 0)
        {
            ecrnx_printk_err("usb tx pkg thread error!\n");
            return 0;
        }
        if(kthread_should_stop())
        {
            continue;
        }
        usb_rx_comp_work(&g_usb->infac_msg.pipe_rx);
        usb_rx_comp_work(&g_usb->infac_data.pipe_rx);
    }
    ecrnx_printk_trans("rx pkg thread exit\n");
    return 0;
}
#endif

static void usb_flush_pipe(struct usb_infac_pipe * pipe)
{
	usb_kill_anchored_urbs(&pipe->urb_submitted);
    if (pipe->dir == USB_DIR_TX) {
        #ifdef CONFIG_ECRNX_KTHREAD
        if(g_usb->kthread_tx_comp)
        {
            kthread_stop(g_usb->kthread_tx_comp);
            wake_up_interruptible(&g_usb->wait_tx_comp);
            g_usb->kthread_tx_comp = NULL;
        }
        #endif
        #ifdef CONFIG_ECRNX_TASKLET
        tasklet_kill(&pipe->tx_tasklet);
        #endif
        #ifdef CONFIG_ECRNX_WORKQUEUE
        cancel_work_sync(&pipe->io_complete_work);
        #endif
    } else {
        #ifdef CONFIG_ECRNX_KTHREAD
        if(g_usb->kthread_rx_comp)
        {
            kthread_stop(g_usb->kthread_rx_comp);
            wake_up_interruptible(&g_usb->wait_rx_comp);
            g_usb->kthread_rx_comp = NULL;
        }
        #endif
        #ifdef CONFIG_ECRNX_TASKLET
        tasklet_kill(&pipe->rx_tasklet);
        #endif
        #ifdef CONFIG_ECRNX_WORKQUEUE
        cancel_work_sync(&pipe->io_complete_work);
        #endif
    }
}
#ifdef CONFIG_PM
static void usb_flush_all(struct eswin_usb * p_usb)
{
	usb_flush_pipe(&p_usb->infac_data.pipe_rx);
	usb_flush_pipe(&p_usb->infac_data.pipe_tx);
	usb_flush_pipe(&p_usb->infac_msg.pipe_rx);
	usb_flush_pipe(&p_usb->infac_msg.pipe_tx);
}
#endif
struct timer_list data_time_st;
struct timer_list msg_time_st;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
void data_timer_handle(struct timer_list *timer)
#else
void data_timer_handle(unsigned long data)
#endif
{
    usb_refill_recv_transfer(&g_usb->infac_data.pipe_rx);
}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 15, 0)
void msg_timer_handle(struct timer_list *timer)
#else
void msg_timer_handle(unsigned long data)
#endif
{
    usb_refill_recv_transfer(&g_usb->infac_msg.pipe_rx);
}


static void usb_refill_recv_transfer(struct usb_infac_pipe * pipe)
{
	struct usb_urb_context *urb_context;
	struct urb *urb;
	int usb_status;

	for ( ;; )  {
		urb_context = usb_alloc_urb_from_pipe(pipe);
		if (!urb_context)
			break;
		
		urb_context->skb = dev_alloc_skb(USB_RX_MAX_BUF_SIZE);
		if (!urb_context->skb)
			goto err;

		urb = usb_alloc_urb(0, GFP_ATOMIC);
		if (!urb)
			goto err;
        urb_context->urb = urb;

		usb_fill_bulk_urb(urb,
				  pipe->infac->udev,
				  pipe->usb_pipe_handle,
				  urb_context->skb->data,
				  USB_RX_MAX_BUF_SIZE,
				  usb_recv_complete, urb_context);

		usb_anchor_urb(urb, &pipe->urb_submitted);
		usb_status = usb_submit_urb(urb, GFP_ATOMIC);

		if (usb_status) {
			ecrnx_printk_err("usb_refill_recv_transfer, usb bulk recv failed: %d\n", 
				usb_status);
			//usb_unanchor_urb(urb);
			//usb_free_urb(urb);
			goto err;
		}
		//usb_free_urb(urb);
	}
		
	return;

err:
	usb_cleanup_recv_urb(urb_context);
    if(&g_usb->infac_data.pipe_rx == pipe)
    {
        if(pipe->urb_cnt >= USB_DATA_URB_NUM)
        {
            data_time_st.function = data_timer_handle;
            data_time_st.expires = jiffies + usecs_to_jiffies(10);

            add_timer(&data_time_st);
            ecrnx_printk_err("[%s:%d]:data urb submission failed!\n", __func__,  __LINE__);
        }
    }
    else
    {
        if(pipe->urb_cnt >= USB_MSG_URB_NUM)
        {
            msg_time_st.function = msg_timer_handle;
            msg_time_st.expires = jiffies + usecs_to_jiffies(10);

            add_timer(&msg_time_st);
            ecrnx_printk_err("[%s:%d]:msg urb submission failed!\n", __func__,  __LINE__);
        }
    }
}



static int usb_hif_start(struct eswin *tr)
{
	struct eswin_usb * p_usb =  (struct eswin_usb *)tr->drv_priv;

	ecrnx_printk_trans("%s entry!!", __func__);

	usb_refill_recv_transfer(&p_usb->infac_data.pipe_rx);
	usb_refill_recv_transfer(&p_usb->infac_msg.pipe_rx);
	timer_setup(&usb_rx_timer, usb_rx_timer_handle, 0);

	return 0;
}


int usb_hif_xmit(struct eswin *tr, struct sk_buff *skb)
{

    unsigned int req_type = TX_FLAG_MAX;
	struct eswin_usb * p_usb =  (struct eswin_usb *)tr->drv_priv;
	struct usb_infac_data_t * infac_data = NULL;
	struct usb_infac_pipe * pipe = NULL;
	struct usb_urb_context *urb_context;
	struct urb *urb;
    int ret = -1;

    req_type = *((unsigned int*)(skb->data));
    if((req_type & FLAG_MSG_TYPE_MASK) == TX_FLAG_TX_DESC)
    {
        infac_data = &p_usb->infac_data;
        pipe = &infac_data->pipe_tx;
    }
    else
    {
        infac_data = &p_usb->infac_msg;
        pipe = &infac_data->pipe_tx;
    }

	urb_context = usb_alloc_urb_from_pipe(pipe);
	if (!urb_context) {
		ret = -ENOMEM;
		ecrnx_printk_err("no urb_context memory; \n");
		goto err;
	}
	
	urb_context->skb = skb;

	urb = usb_alloc_urb(0, GFP_ATOMIC);
	if (!urb) {
		ret = -ENOMEM;
		ecrnx_printk_err("no urb memory; \n");
		goto err_free_urb_to_pipe;
	}

    urb_context->urb = urb;

    ecrnx_printk_trans("%s:%s, urb:0x%x, skb:0x%x; \n", __func__, ((req_type & FLAG_MSG_TYPE_MASK) == TX_FLAG_TX_DESC)?"data":"msg", urb, skb);
	usb_fill_bulk_urb(urb,
			  infac_data->udev,
			  pipe->usb_pipe_handle,
			  skb->data,
			  skb->len,
			  usb_transmit_complete, urb_context);

	if (!(skb->len % infac_data->max_packet_size)) {
		/* hit a max packet boundary on this pipe */
		urb->transfer_flags |= URB_ZERO_PACKET;
	}

	usb_anchor_urb(urb, &pipe->urb_submitted);
	ret = usb_submit_urb(urb, GFP_ATOMIC);
	if (ret) {
		ecrnx_printk_err("usb_hif_xmit, usb bulk transmit failed: %d\n", ret);
		//usb_unanchor_urb(urb);
		ret = -EINVAL;
		goto err_free_urb_to_pipe;
	}

	//usb_free_urb(urb);

	return 0;

err_free_urb_to_pipe:
	usb_free_urb_to_infac(urb_context->pipe, urb_context);
err:
	ecrnx_printk_err("usb_hif_xmit, pkg miss due to urb, ret:%d.\n", ret);
	skb_queue_tail(&pipe->io_comp_queue, skb);
	#ifdef CONFIG_ECRNX_KTHREAD
	wake_up_interruptible(&g_usb->wait_tx_comp);
	#endif
	#ifdef CONFIG_ECRNX_WORKQUEUE
	schedule_work(&pipe->io_complete_work);
	#endif
	#ifdef CONFIG_ECRNX_TASKLET
	tasklet_schedule(&pipe->tx_tasklet);
	#endif
	return ret;
}

static int usb_hif_write_raw(struct eswin *tr, const void* data, const u32 len)
{
	struct eswin_usb * p_usb =  (struct eswin_usb *)tr->drv_priv;
	struct usb_infac_data_t * infac_data = &p_usb->infac_data;
	struct usb_infac_pipe * pipe = &infac_data->pipe_tx;

	return usb_bulk_msg(infac_data->udev, pipe->usb_pipe_handle, (void*)data, len, NULL, 20000);
}

static int usb_hif_wait_ack(struct eswin *tr, void* data, const u32 len)
{
	struct eswin_usb * p_usb =  (struct eswin_usb *)tr->drv_priv;
	struct usb_infac_data_t * infac_data = &p_usb->infac_data;
	struct usb_infac_pipe * pipe = &infac_data->pipe_rx;

	return usb_bulk_msg(infac_data->udev, pipe->usb_pipe_handle, data, len, NULL, 1000);
}

#ifdef CONFIG_PM
static int usb_hif_suspend(struct eswin *tr)
{
	return -EOPNOTSUPP;
}

static int usb_hif_resume(struct eswin *tr)
{
	return -EOPNOTSUPP;
}
#endif

static struct usb_ops eswin_usb_hif_ops = {
	.xmit			= usb_hif_xmit,
	.start			= usb_hif_start,
	.write			= usb_hif_write_raw,
	.wait_ack			= usb_hif_wait_ack,
#ifdef CONFIG_PM
	.suspend		= usb_hif_suspend,
	.resume		= usb_hif_resume,
#endif
};

static int usb_create_pipe(struct usb_infac_pipe * pipe, int dir, bool flag)
{
	int i;
	struct usb_urb_context *urb_context;
	ecrnx_printk_trans("%s entry, dir: %d!!", __func__, dir);

	pipe->dir = dir;
    pipe->err_count = 0;
	init_usb_anchor(&pipe->urb_submitted);
	INIT_LIST_HEAD(&pipe->urb_list_head);
    INIT_LIST_HEAD(&pipe->urb_stack_list_head);
	for (i = 0; i < (flag ? USB_MSG_URB_NUM : USB_DATA_URB_NUM); i++) {
		urb_context = kzalloc(sizeof(*urb_context), GFP_KERNEL);
		if (!urb_context)
			return -ENOMEM;

		urb_context->pipe = pipe;
		//pipe->urb_cnt++;
		
		usb_free_urb_to_infac(pipe, urb_context);
        list_add(&urb_context->total_link, &pipe->urb_stack_list_head);
	}

	if (dir) {
		#ifdef CONFIG_ECRNX_WORKQUEUE
		INIT_WORK(&pipe->io_complete_work,  usb_tx_comp_work);
		#endif
		#ifdef CONFIG_ECRNX_TASKLET
		tasklet_init(&pipe->tx_tasklet, usb_tx_comp_work, (unsigned long) pipe);
		#endif
	} else {
		#ifdef CONFIG_ECRNX_WORKQUEUE
		INIT_WORK(&pipe->io_complete_work,  usb_rx_comp_work);
		#endif
		#ifdef CONFIG_ECRNX_TASKLET
		tasklet_init(&pipe->rx_tasklet, usb_rx_comp_work, (unsigned long) pipe);
		#endif
	}

	skb_queue_head_init(&pipe->io_comp_queue);
	return 0;
}

static int usb_create_infac(struct usb_interface *interface, struct usb_infac_data_t  * p_infac, bool flag)
{
	struct usb_device *dev = interface_to_usbdev(interface);
	struct usb_host_interface *iface_desc = interface->cur_altsetting;
	struct usb_endpoint_descriptor *endpoint = NULL;

	int i;
	ecrnx_printk_trans("%s entry %d!!", __func__, iface_desc->desc.bNumEndpoints);

	usb_get_dev(dev);
	usb_set_intfdata(interface, p_infac);

	p_infac->udev = dev;
	p_infac->interface = interface;

	for (i = 0; i < iface_desc->desc.bNumEndpoints; ++i) {
		endpoint = &iface_desc->endpoint[i].desc;
		if (endpoint->bEndpointAddress & USB_DIR_MASK) {
			p_infac->pipe_rx.usb_pipe_handle = usb_rcvbulkpipe(dev, endpoint->bEndpointAddress);
			p_infac->pipe_rx.infac = p_infac;
			usb_create_pipe(&p_infac->pipe_rx, USB_DIR_RX, flag);
		} else {
			p_infac->pipe_tx.usb_pipe_handle = usb_sndbulkpipe(dev, endpoint->bEndpointAddress);
			p_infac->pipe_tx.infac = p_infac;
			usb_create_pipe(&p_infac->pipe_tx, USB_DIR_TX, flag);
		}
	}
	p_infac->max_packet_size = le16_to_cpu(endpoint->wMaxPacketSize);;

	return 0;
}

extern bool usb_status;
extern struct eswin *pEswin;
static int eswin_usb_probe(struct usb_interface *interface,
			    const struct usb_device_id *id)
{
	int ret;
	struct eswin_usb * p_usb;
	struct eswin* p_eswin;
	struct usb_host_interface *iface_desc = interface->cur_altsetting;
    struct usb_device *dev = interface_to_usbdev(interface);

     if((usb_status == false) && dl_fw)
     {
        ecrnx_printk_trans("%s entry, reset slave !!", __func__);
        ret = usb_control_msg(dev,
            usb_sndctrlpipe(dev, 0),
            0x2,
            USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
            0,
            0,
            NULL, 0,10);
        if(ret == 0)
        {
            ecrnx_printk_trans("Wait for slave restart !!");
            msleep(200);
        }
     }

	ecrnx_printk_trans("%s entry, func: %d, g_usb: %p !!", __func__, iface_desc->desc.bInterfaceNumber, g_usb);

	if (iface_desc->desc.bInterfaceNumber == USB_INFAC_DATA) {
		if (g_usb) {
			p_usb = g_usb;
            pEswin->dev = &interface->dev;
		} else {
			p_eswin = eswin_core_create(sizeof(struct eswin_usb), &interface->dev, &eswin_usb_hif_ops);
			if(!p_eswin) {
				dev_err(&interface->dev, "failed to allocate core\n");
				return -ENOMEM;
			}

			p_usb = (struct eswin_usb *)p_eswin->drv_priv;
			p_usb->p_eswin = p_eswin;
			g_usb = p_usb;
			spin_lock_init(&p_usb->cs_lock);
		}

		p_usb->dev = &interface->dev;

		usb_create_infac(interface, &p_usb->infac_data, 0);
	} else {
		usb_create_infac(interface, &g_usb->infac_msg, 1);
		//usb_hif_start(g_usb->p_eswin);

		if (!g_usb->usb_enum_already) {
			ret = eswin_core_register(g_usb->p_eswin);
			if(ret) {
				ecrnx_printk_err("failed to register core\n");
				return ret;
			}
		} else {
			g_usb->usb_enum_already = 1;
		}
		return 0;
	}

	#ifdef CONFIG_ECRNX_KTHREAD
	if(iface_desc->desc.bInterfaceNumber == USB_INFAC_DATA)
	{
		init_waitqueue_head(&g_usb->wait_tx_comp);
		init_waitqueue_head(&g_usb->wait_rx_comp);

		g_usb->kthread_tx_comp = kthread_run(eswin_tx_comp_thread, g_usb, "tx_comp");
		g_usb->kthread_rx_comp = kthread_run(eswin_rx_comp_thread, g_usb, "rx_comp");

		if (IS_ERR(g_usb->kthread_tx_comp)) {
			g_usb->kthread_tx_comp = NULL;
			ecrnx_printk_err("kthread_tx_comp run fail\n");
		}

		if (IS_ERR(g_usb->kthread_rx_comp)) {
			g_usb->kthread_rx_comp = NULL;
			ecrnx_printk_err("kthread_rx_comp run fail\n");
		}
		ecrnx_printk_trans("%s kthread_run success.", __func__);
	}
	#endif
	ecrnx_printk_trans("%s exit!!", __func__);
	return 0;
}

static void eswin_usb_remove(struct usb_interface *interface)
{
	struct usb_infac_data_t  * p_infac;
	struct usb_host_interface *iface_desc = interface->cur_altsetting;

	ecrnx_printk_trans("%s entry!!", __func__);

	p_infac = usb_get_intfdata(interface);

	if (!p_infac) {
		ecrnx_printk_err("%s, p_infa is null!!", __func__);
		return;
	}

	if (iface_desc->desc.bInterfaceNumber == USB_INFAC_DATA) {
		eswin_core_unregister(g_usb->p_eswin);
	} 

	del_timer(&usb_rx_timer);
    if(timer_pending(&data_time_st) == true)
    {
        del_timer(&data_time_st);
    }
    if(timer_pending(&msg_time_st) == true)
    {
        del_timer(&msg_time_st);
    }

	usb_flush_pipe(&p_infac->pipe_rx);
	usb_flush_pipe(&p_infac->pipe_tx);
	usb_free_pipe_resources(&p_infac->pipe_rx);
	usb_free_pipe_resources(&p_infac->pipe_tx);

	usb_set_intfdata(interface, NULL);
	usb_put_dev(interface_to_usbdev(interface));
	dl_fw = true;
	offset = 0;
}


#ifdef CONFIG_PM
static int eswin_usb_pm_suspend(struct usb_interface *interface,	pm_message_t message)
{
	ecrnx_printk_trans("entry %s\n", __func__);
	usb_flush_all(g_usb);
	return 0;
}

static int eswin_usb_pm_resume(struct usb_interface *interface)
{
	ecrnx_printk_trans("entry %s\n", __func__);
	usb_refill_recv_transfer(&g_usb->infac_data.pipe_rx);
	usb_refill_recv_transfer(&g_usb->infac_msg.pipe_rx);
	return 0;
}

#else
#define eswin_usb_pm_suspend NULL
#define eswin_usb_pm_resume NULL
#endif

/* table of devices that work with this driver */
static struct usb_device_id eswin_usb_ids[] = {
	{USB_DEVICE(0x3452, 0x6600)},
	{ /* Terminating entry */ },
};

MODULE_DEVICE_TABLE(usb, eswin_usb_ids);
static struct usb_driver eswin_usb_driver = {
	.name = "eswin_usb",
	.probe = eswin_usb_probe,
	.suspend = eswin_usb_pm_suspend,
	.resume = eswin_usb_pm_resume,
	.disconnect = eswin_usb_remove,
	.id_table = eswin_usb_ids,
	.supports_autosuspend = true,
};

static int __init eswin_usb_init(void)
{
	int ret;

	#ifdef CONFIG_POWERKEY_GPIO
	int pk_gpio = 4;
	pk_gpio = CONFIG_POWERKEY_GPIO;
	gpio_direction_output(pk_gpio,0);
	msleep(1000);
	gpio_direction_output(pk_gpio,1);
	#endif

	ecrnx_printk_trans("%s entry !!\n", __func__);
	ret = usb_register(&eswin_usb_driver);
	if (ret)
		ecrnx_printk_err("usb driver registration failed: %d\n", ret);

	ecrnx_printk_trans("%s exit !!\n", __func__);
	return ret;
}

static void __exit eswin_usb_exit(void)
{
	ecrnx_printk_trans("%s entry !!\n", __func__);
	usb_deregister(&eswin_usb_driver);
	ecrnx_printk_trans("%s exit !!\n", __func__);
}

void ecrnx_usb_reset_sync_fw(void)
{
    usb_control_msg(g_usb->infac_msg.udev,
        usb_sndctrlpipe(g_usb->infac_msg.udev, 0),
        0x2,
        USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
        0,
        0,
        NULL, 0,10);
}

int ecrnx_usb_register_drv(void)
{
    return eswin_usb_init();
}

void ecrnx_usb_unregister_drv(void)
{
    eswin_core_unregister(g_usb->p_eswin);
    ecrnx_usb_reset_sync_fw();
    return eswin_usb_exit();
}

struct device *eswin_usb_get_dev(void *plat)
{
    struct eswin* tr = (struct eswin*)plat;
    
    return tr->dev;
}


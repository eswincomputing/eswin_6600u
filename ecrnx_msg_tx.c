/**
 ******************************************************************************
 *
 * @file ecrnx_msg_tx.c
 *
 * @brief TX function definitions
 *
 * Copyright (C) ESWIN 2015-2020
 *
 ******************************************************************************
 */

#include "ecrnx_msg_tx.h"
#include "ecrnx_mod_params.h"
#include "reg_access.h"
#ifdef CONFIG_ECRNX_BFMER
#include "ecrnx_bfmer.h"
#endif //(CONFIG_ECRNX_BFMER)
#include "ecrnx_compat.h"
#include "ecrnx_defs.h"
#include "ecrnx_calibration_data.h"
#include "eswin_utils.h"
#include "core.h"

const struct mac_addr mac_addr_bcst = {{0xFFFF, 0xFFFF, 0xFFFF}};

/* Default MAC Rx filters that can be changed by mac80211
 * (via the configure_filter() callback) */
#define ECRNX_MAC80211_CHANGEABLE        (                                       \
                                         NXMAC_ACCEPT_BA_BIT                  | \
                                         NXMAC_ACCEPT_BAR_BIT                 | \
                                         NXMAC_ACCEPT_OTHER_DATA_FRAMES_BIT   | \
                                         NXMAC_ACCEPT_PROBE_REQ_BIT           | \
                                         NXMAC_ACCEPT_PS_POLL_BIT               \
                                        )

/* Default MAC Rx filters that cannot be changed by mac80211 */
#define ECRNX_MAC80211_NOT_CHANGEABLE    (                                       \
                                         NXMAC_ACCEPT_QO_S_NULL_BIT           | \
                                         NXMAC_ACCEPT_Q_DATA_BIT              | \
                                         NXMAC_ACCEPT_DATA_BIT                | \
                                         NXMAC_ACCEPT_OTHER_MGMT_FRAMES_BIT   | \
                                         NXMAC_ACCEPT_MY_UNICAST_BIT          | \
                                         NXMAC_ACCEPT_BROADCAST_BIT           | \
                                         NXMAC_ACCEPT_BEACON_BIT              | \
                                         NXMAC_ACCEPT_PROBE_RESP_BIT            \
                                        )

/* Default MAC Rx filter */
#define ECRNX_DEFAULT_RX_FILTER  (ECRNX_MAC80211_CHANGEABLE | ECRNX_MAC80211_NOT_CHANGEABLE)

const int bw2chnl[] = {
    [NL80211_CHAN_WIDTH_20_NOHT] = PHY_CHNL_BW_20,
    [NL80211_CHAN_WIDTH_20]      = PHY_CHNL_BW_20,
    [NL80211_CHAN_WIDTH_40]      = PHY_CHNL_BW_40,
    [NL80211_CHAN_WIDTH_80]      = PHY_CHNL_BW_80,
    [NL80211_CHAN_WIDTH_160]     = PHY_CHNL_BW_160,
    [NL80211_CHAN_WIDTH_80P80]   = PHY_CHNL_BW_80P80,
};

const int chnl2bw[] = {
    [PHY_CHNL_BW_20]      = NL80211_CHAN_WIDTH_20,
    [PHY_CHNL_BW_40]      = NL80211_CHAN_WIDTH_40,
    [PHY_CHNL_BW_80]      = NL80211_CHAN_WIDTH_80,
    [PHY_CHNL_BW_160]     = NL80211_CHAN_WIDTH_160,
    [PHY_CHNL_BW_80P80]   = NL80211_CHAN_WIDTH_80P80,
};

/*****************************************************************************/
/*
 * Parse the ampdu density to retrieve the value in usec, according to the
 * values defined in ieee80211.h
 */
static inline u8 ecrnx_ampdudensity2usec(u8 ampdudensity)
{
    switch (ampdudensity) {
    case IEEE80211_HT_MPDU_DENSITY_NONE:
        return 0;
        /* 1 microsecond is our granularity */
    case IEEE80211_HT_MPDU_DENSITY_0_25:
    case IEEE80211_HT_MPDU_DENSITY_0_5:
    case IEEE80211_HT_MPDU_DENSITY_1:
        return 1;
    case IEEE80211_HT_MPDU_DENSITY_2:
        return 2;
    case IEEE80211_HT_MPDU_DENSITY_4:
        return 4;
    case IEEE80211_HT_MPDU_DENSITY_8:
        return 8;
    case IEEE80211_HT_MPDU_DENSITY_16:
        return 16;
    default:
        return 0;
    }
}

static inline bool use_pairwise_key(struct cfg80211_crypto_settings *crypto)
{
    if ((crypto->cipher_group ==  WLAN_CIPHER_SUITE_WEP40) ||
        (crypto->cipher_group ==  WLAN_CIPHER_SUITE_WEP104))
        return false;

    return true;
}

static inline bool is_non_blocking_msg(int id)
{
    return ((id == MM_TIM_UPDATE_REQ) || (id == ME_RC_SET_RATE_REQ) ||
            (id == MM_BFMER_ENABLE_REQ) || (id == ME_TRAFFIC_IND_REQ) ||
            (id == TDLS_PEER_TRAFFIC_IND_REQ) ||
            (id == MESH_PATH_CREATE_REQ) || (id == MESH_PROXY_ADD_REQ) ||
            (id == SM_EXTERNAL_AUTH_REQUIRED_RSP));
}

/**
 * copy_connect_ies -- Copy Association Elements in the the request buffer
 * send to the firmware
 *
 * @vif: Vif that received the connection request
 * @req: Connection request to send to the firmware
 * @sme: Connection info
 *
 * For driver that do not use userspace SME (like this one) the host connection
 * request doesn't explicitly mentions that the connection can use FT over the
 * air. if FT is possible, send the FT elements (as received in update_ft_ies callback)
 * to the firmware
 *
 * In all other cases simply copy the list povided by the user space in the
 * request buffer
 */
static void copy_connect_ies(struct ecrnx_vif *vif, struct sm_connect_req *req,
                            struct cfg80211_connect_params *sme)
{
    if ((sme->auth_type == NL80211_AUTHTYPE_FT) && !(vif->sta.flags & ECRNX_STA_FT_OVER_DS))
    {
        const struct ecrnx_element *rsne, *fte, *mde;
        uint8_t *pos;
        rsne = cfg80211_find_ecrnx_elem(WLAN_EID_RSN, vif->sta.ft_assoc_ies,
                                    vif->sta.ft_assoc_ies_len);
        fte = cfg80211_find_ecrnx_elem(WLAN_EID_FAST_BSS_TRANSITION, vif->sta.ft_assoc_ies,
                                    vif->sta.ft_assoc_ies_len);
        mde = cfg80211_find_ecrnx_elem(WLAN_EID_MOBILITY_DOMAIN,
                                         vif->sta.ft_assoc_ies, vif->sta.ft_assoc_ies_len);
        pos = (uint8_t *)req->ie_buf;

        // We can use FT over the air
        memcpy(&vif->sta.ft_target_ap, sme->bssid, ETH_ALEN);

        if (rsne) {
            memcpy(pos, rsne, sizeof(struct ecrnx_element) + rsne->datalen);
            pos += sizeof(struct ecrnx_element) + rsne->datalen;
        }
        memcpy(pos, mde, sizeof(struct ecrnx_element) + mde->datalen);
        pos += sizeof(struct ecrnx_element) + mde->datalen;
        if (fte) {
            memcpy(pos, fte, sizeof(struct ecrnx_element) + fte->datalen);
            pos += sizeof(struct ecrnx_element) + fte->datalen;
        }

        req->ie_len = pos - (uint8_t *)req->ie_buf;
    }
    else
    {
        memcpy(req->ie_buf, sme->ie, sme->ie_len);
        req->ie_len = sme->ie_len;
    }
}

/**
 * update_connect_req -- Return the length of the association request IEs
 *
 * @vif: Vif that received the connection request
 * @sme: Connection info
 *
 * Return the ft_ie_len in case of FT.
 * FT over the air is possible if:
 * - auth_type = AUTOMATIC (if already set to FT then it means FT over DS)
 * - already associated to a FT BSS
 * - Target Mobility domain is the same as the curent one
 *
 * If FT is not possible return ie length of the connection info
 */
static int update_connect_req(struct ecrnx_vif *vif, struct cfg80211_connect_params *sme)
{
    if ((vif->sta.ap) &&
        (vif->sta.ft_assoc_ies) &&
        (sme->auth_type == NL80211_AUTHTYPE_AUTOMATIC))
    {
        const struct ecrnx_element *rsne, *fte, *mde, *mde_req;
        int ft_ie_len = 0;

        mde_req = cfg80211_find_ecrnx_elem(WLAN_EID_MOBILITY_DOMAIN,
                                     sme->ie, sme->ie_len);
        mde = cfg80211_find_ecrnx_elem(WLAN_EID_MOBILITY_DOMAIN,
                                 vif->sta.ft_assoc_ies, vif->sta.ft_assoc_ies_len);
        if (!mde || !mde_req ||
            memcmp(mde, mde_req, sizeof(struct ecrnx_element) + mde->datalen))
        {
            return sme->ie_len;
        }

        ft_ie_len += sizeof(struct ecrnx_element) + mde->datalen;

        rsne = cfg80211_find_ecrnx_elem(WLAN_EID_RSN, vif->sta.ft_assoc_ies,
                                    vif->sta.ft_assoc_ies_len);
        fte = cfg80211_find_ecrnx_elem(WLAN_EID_FAST_BSS_TRANSITION, vif->sta.ft_assoc_ies,
                                    vif->sta.ft_assoc_ies_len);

        if (rsne && fte)
        {
            ft_ie_len += 2 * sizeof(struct ecrnx_element) + rsne->datalen + fte->datalen;
            sme->auth_type = NL80211_AUTHTYPE_FT;
            return ft_ie_len;
        }
        else if (rsne || fte)
        {
            netdev_warn(vif->ndev, "Missing RSNE or FTE element, skip FT over air");
        }
        else
        {
            sme->auth_type = NL80211_AUTHTYPE_FT;
            return ft_ie_len;
        }
    }
    return sme->ie_len;
}

static inline u8_l get_chan_flags(uint32_t flags)
{
    u8_l chan_flags = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0)
    if (flags & IEEE80211_CHAN_PASSIVE_SCAN)
#else
    if (flags & IEEE80211_CHAN_NO_IR)
        chan_flags |= CHAN_NO_IR;
    if (flags & IEEE80211_CHAN_RADAR)
        chan_flags |= CHAN_RADAR;
#endif
    return chan_flags;
}

static inline s8_l chan_to_fw_pwr(int power)
{
    return power > 127 ? 127 : (s8_l)power;
}

static void cfg80211_to_ecrnx_chan(const struct cfg80211_chan_def *chandef,
                                  struct mac_chan_op *chan)
{
    if(chandef && chandef->chan){
        chan->band = chandef->chan->band;
        chan->type = bw2chnl[chandef->width];
        chan->prim20_freq = chandef->chan->center_freq;
        chan->center1_freq = chandef->center_freq1;
        chan->center2_freq = chandef->center_freq2;
        chan->flags = get_chan_flags(chandef->chan->flags);
        chan->tx_power = chan_to_fw_pwr(chandef->chan->max_power);
    }
}

static inline void limit_chan_bw(u8_l *bw, u16_l primary, u16_l *center1)
{
    int oft, new_oft = 10;

    if (*bw <= PHY_CHNL_BW_40)
        return;

    oft = *center1 - primary;
    *bw = PHY_CHNL_BW_40;

    if (oft < 0)
        new_oft = new_oft * -1;
    if (abs(oft) == 10 || abs(oft) == 50)
        new_oft = new_oft * -1;

    *center1 = primary + new_oft;
}

/**
 ******************************************************************************
 * @brief Allocate memory for a message
 *
 * This primitive allocates memory for a message that has to be sent. The memory
 * is allocated dynamically on the heap and the length of the variable parameter
 * structure has to be provided in order to allocate the correct size.
 *
 * Several additional parameters are provided which will be preset in the message
 * and which may be used internally to choose the kind of memory to allocate.
 *
 * The memory allocated will be automatically freed by the kernel, after the
 * pointer has been sent to ke_msg_send(). If the message is not sent, it must
 * be freed explicitly with ke_msg_free().
 *
 * Allocation failure is considered critical and should not happen.
 *
 * @param[in] id        Message identifier
 * @param[in] dest_id   Destination Task Identifier
 * @param[in] src_id    Source Task Identifier
 * @param[in] param_len Size of the message parameters to be allocated
 *
 * @return Pointer to the parameter member of the ke_msg. If the parameter
 *         structure is empty, the pointer will point to the end of the message
 *         and should not be used (except to retrieve the message pointer or to
 *         send the message)
 ******************************************************************************
 */
static inline void *ecrnx_msg_zalloc(lmac_msg_id_t const id,
                                    lmac_task_id_t const dest_id,
                                    lmac_task_id_t const src_id,
                                    uint16_t const param_len)
{
    struct lmac_msg *msg;
    gfp_t flags;

    if (is_non_blocking_msg(id) && in_atomic())
        flags = GFP_ATOMIC;
    else
        flags = GFP_KERNEL;

    msg = (struct lmac_msg *)kzalloc(sizeof(struct lmac_msg) + param_len,
                                     flags);
    if (msg == NULL) {
        ecrnx_printk_err(KERN_CRIT "%s: msg allocation failed\n", __func__);
        return NULL;
    }

    ecrnx_printk_msg("%s msg:0x%p, param:0x%p, id:0x%x, src_id:0x%x, dst_id:0x%x \n", __func__, msg, msg->param, id, src_id, dest_id);
    msg->id = id;
    msg->dest_id = dest_id;
    msg->src_id = src_id;
    msg->param_len = param_len;

    return msg->param;
}

static void ecrnx_msg_free(struct ecrnx_hw *ecrnx_hw, const void *msg_params)
{
    struct lmac_msg *msg = container_of((void *)msg_params,
                                        struct lmac_msg, param);

    ecrnx_printk_msg("%s msg:%p \n", __func__, msg);

    /* Free the message */
    kfree(msg);
}

static int ecrnx_send_msg(struct ecrnx_hw *ecrnx_hw, const void *msg_params,
                         int reqcfm, lmac_msg_id_t reqid, void *cfm)
{
    struct lmac_msg *msg;
    struct ecrnx_cmd *cmd;
    bool nonblock;
    int ret;

    //ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    msg = container_of((void *)msg_params, struct lmac_msg, param);

    if (!test_bit(ECRNX_DEV_STARTED, &ecrnx_hw->flags) &&
        reqid != MM_RESET_CFM && reqid != MM_VERSION_CFM &&
        reqid != MM_START_CFM && reqid != MM_SET_IDLE_CFM &&
        reqid != ME_CONFIG_CFM && reqid != MM_SET_PS_MODE_CFM &&
        reqid != ME_CHAN_CONFIG_CFM && reqid != MM_SET_GAIN_DELTA_CFM &&
        reqid != MM_GET_CAL_RESULT_CFM && reqid != MM_SET_MACADRR_CFM) {
        ecrnx_printk_err(KERN_CRIT "%s: bypassing (ECRNX_DEV_RESTARTING set) 0x%02x\n",
               __func__, reqid);
        kfree(msg);
        return -EBUSY;
    } else if (!ecrnx_hw->ipc_env) {
        ecrnx_printk_err(KERN_CRIT "%s: bypassing (restart must have failed)\n", __func__);
        kfree(msg);
        return -EBUSY;
    }

    nonblock = is_non_blocking_msg(msg->id);
    
#if defined(CONFIG_ECRNX_ESWIN_USB)
    if(register_status == false){
        ecrnx_printk_err(KERN_CRIT "%s: register_status is false; \n", __func__);
        kfree(msg);
        return -ENODEV;
    }
#endif

    cmd = kzalloc(sizeof(struct ecrnx_cmd), nonblock ? GFP_ATOMIC : GFP_KERNEL);

    if(!cmd) {
        ecrnx_printk_err("no memory!\n");
        return -ENOMEM;
    }
    cmd->result  = -EINTR;
    cmd->id      = msg->id;
    cmd->reqid   = reqid;
    cmd->a2e_msg = msg;
    cmd->e2a_msg = cfm;
    if (nonblock)
        cmd->flags = ECRNX_CMD_FLAG_NONBLOCK;
    if (reqcfm)
        cmd->flags |= ECRNX_CMD_FLAG_REQ_CFM;
    if(ecrnx_hw->wiphy != NULL)
    {
        ecrnx_printk_msg("%s inqueue, cmd:0x%p, cmd_flag:0x%x, msg:0x%p \n", __func__, cmd, cmd->flags, cmd->a2e_msg);
        ret = ecrnx_hw->cmd_mgr.queue(&ecrnx_hw->cmd_mgr, cmd);
    }

    if (!ret)
        ret = cmd->result;
        
    if (!nonblock)
        kfree(cmd);

    ecrnx_printk_msg("%s ret:%d \n", __func__, ret);
    return ret;
}

/******************************************************************************
 *    Control messages handling functions (SOFTMAC and  FULLMAC)
 *****************************************************************************/
int ecrnx_send_reset(struct ecrnx_hw *ecrnx_hw)
{
    void *void_param;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* RESET REQ has no parameter */
    void_param = ecrnx_msg_zalloc(MM_RESET_REQ, TASK_MM, DRV_TASK_ID, 0);
    if (!void_param)
        return -ENOMEM;

    return ecrnx_send_msg(ecrnx_hw, void_param, 1, MM_RESET_CFM, NULL);
}

int ecrnx_send_start(struct ecrnx_hw *ecrnx_hw)
{
    struct mm_start_req *start_req_param;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the START REQ message */
    start_req_param = ecrnx_msg_zalloc(MM_START_REQ, TASK_MM, DRV_TASK_ID,
                                      sizeof(struct mm_start_req));
    if (!start_req_param)
        return -ENOMEM;

    /* Set parameters for the START message */
    memcpy(&start_req_param->phy_cfg, &ecrnx_hw->phy.cfg, sizeof(ecrnx_hw->phy.cfg));
    start_req_param->uapsd_timeout = (u32_l)ecrnx_hw->mod_params->uapsd_timeout;
    start_req_param->lp_clk_accuracy = (u16_l)ecrnx_hw->mod_params->lp_clk_ppm;
    start_req_param->tx_timeout[AC_BK] = (u16_l)ecrnx_hw->mod_params->tx_to_bk;
    start_req_param->tx_timeout[AC_BE] = (u16_l)ecrnx_hw->mod_params->tx_to_be;
    start_req_param->tx_timeout[AC_VI] = (u16_l)ecrnx_hw->mod_params->tx_to_vi;
    start_req_param->tx_timeout[AC_VO] = (u16_l)ecrnx_hw->mod_params->tx_to_vo;

    /* Send the START REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, start_req_param, 1, MM_START_CFM, NULL);
}

int ecrnx_send_version_req(struct ecrnx_hw *ecrnx_hw, struct mm_version_cfm *cfm)
{
    void *void_param;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);
    /* VERSION REQ has no parameter */
    void_param = ecrnx_msg_zalloc(MM_VERSION_REQ, TASK_MM, DRV_TASK_ID, 0);
    if (!void_param)
        return -ENOMEM;

    return ecrnx_send_msg(ecrnx_hw, void_param, 1, MM_VERSION_CFM, cfm);
}

int ecrnx_send_add_if(struct ecrnx_hw *ecrnx_hw, const unsigned char *mac,
                     enum nl80211_iftype iftype, bool p2p, struct mm_add_if_cfm *cfm)
{
    struct mm_add_if_req *add_if_req_param;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ADD_IF_REQ message */
    add_if_req_param = ecrnx_msg_zalloc(MM_ADD_IF_REQ, TASK_MM, DRV_TASK_ID,
                                       sizeof(struct mm_add_if_req));
    if (!add_if_req_param)
        return -ENOMEM;

    /* Set parameters for the ADD_IF_REQ message */
    memcpy(&(add_if_req_param->addr.array[0]), mac, ETH_ALEN);
    switch (iftype) {
    case NL80211_IFTYPE_P2P_CLIENT:
        add_if_req_param->p2p = true;
        add_if_req_param->type = MM_STA;
        break;
    case NL80211_IFTYPE_STATION:
        add_if_req_param->type = MM_STA;
        break;

    case NL80211_IFTYPE_ADHOC:
        add_if_req_param->type = MM_IBSS;
        break;
    case NL80211_IFTYPE_P2P_GO:
        add_if_req_param->p2p = true;
        add_if_req_param->type = MM_AP;
        break;
    case NL80211_IFTYPE_AP:
        add_if_req_param->type = MM_AP;
        break;
    case NL80211_IFTYPE_MESH_POINT:
        add_if_req_param->type = MM_MESH_POINT;
        break;
    case NL80211_IFTYPE_AP_VLAN:
        return -1;
    case NL80211_IFTYPE_MONITOR:
        add_if_req_param->type = MM_MONITOR;
        break;
    default:
        add_if_req_param->type = MM_STA;
        break;
    }

    /* Send the ADD_IF_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, add_if_req_param, 1, MM_ADD_IF_CFM, cfm);
}

int ecrnx_send_remove_if(struct ecrnx_hw *ecrnx_hw, u8 vif_index)
{
    struct mm_remove_if_req *remove_if_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_REMOVE_IF_REQ message */
    remove_if_req = ecrnx_msg_zalloc(MM_REMOVE_IF_REQ, TASK_MM, DRV_TASK_ID,
                                    sizeof(struct mm_remove_if_req));
    if (!remove_if_req)
        return -ENOMEM;

    /* Set parameters for the MM_REMOVE_IF_REQ message */
    remove_if_req->inst_nbr = vif_index;

    /* Send the MM_REMOVE_IF_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, remove_if_req, 1, MM_REMOVE_IF_CFM, NULL);
}

int ecrnx_send_set_channel(struct ecrnx_hw *ecrnx_hw, int phy_idx,
                          struct mm_set_channel_cfm *cfm)
{
    struct mm_set_channel_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);
    if (phy_idx >= ecrnx_hw->phy.cnt)
        return -ENOTSUPP;

    req = ecrnx_msg_zalloc(MM_SET_CHANNEL_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_set_channel_req));
    if (!req)
        return -ENOMEM;

    if (phy_idx == 0) {
        /* On FULLMAC only setting channel of secondary chain */
        wiphy_err(ecrnx_hw->wiphy, "Trying to set channel of primary chain");
        return 0;
    } else {
        req->chan = ecrnx_hw->phy.sec_chan;
    }

    req->index = phy_idx;

    if (ecrnx_hw->phy.limit_bw)
        limit_chan_bw(&req->chan.type, req->chan.prim20_freq, &req->chan.center1_freq);

    /*ecrnx_printk_cfg("mac80211:   freq=%d(c1:%d - c2:%d)/width=%d - band=%d\n"
             "   hw(%d): prim20=%d(c1:%d - c2:%d)/ type=%d - band=%d\n",
             center_freq, center_freq1, center_freq2, width, band,
             phy_idx, req->chan.prim20_freq, req->chan.center1_freq,
             req->chan.center2_freq, req->chan.type, req->chan.band);*/

    /* Send the MM_SET_CHANNEL_REQ REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MM_SET_CHANNEL_CFM, cfm);
}


int ecrnx_send_key_add(struct ecrnx_hw *ecrnx_hw, u8 vif_idx, u8 sta_idx, bool pairwise,
                      u8 *key, u8 key_len, u8 key_idx, u8 cipher_suite,
                      struct mm_key_add_cfm *cfm)
{
    struct mm_key_add_req *key_add_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_KEY_ADD_REQ message */
    key_add_req = ecrnx_msg_zalloc(MM_KEY_ADD_REQ, TASK_MM, DRV_TASK_ID,
                                  sizeof(struct mm_key_add_req));
    if (!key_add_req)
        return -ENOMEM;

    /* Set parameters for the MM_KEY_ADD_REQ message */
    if (sta_idx != 0xFF) {
        /* Pairwise key */
        key_add_req->sta_idx = sta_idx;
    } else {
        /* Default key */
        key_add_req->sta_idx = sta_idx;
        key_add_req->key_idx = (u8_l)key_idx; /* only useful for default keys */
    }
    key_add_req->pairwise = pairwise;
    key_add_req->inst_nbr = vif_idx;
    key_add_req->key.length = key_len;
    memcpy(&(key_add_req->key.array[0]), key, key_len);

    key_add_req->cipher_suite = cipher_suite;

    ecrnx_printk_msg("%s: sta_idx:%d key_idx:%d inst_nbr:%d cipher:%d key_len:%d\n", __func__,
             key_add_req->sta_idx, key_add_req->key_idx, key_add_req->inst_nbr,
             key_add_req->cipher_suite, key_add_req->key.length);
#if defined(CONFIG_ECRNX_DBG) || defined(CONFIG_DYNAMIC_DEBUG)
    print_hex_dump_bytes("key: ", DUMP_PREFIX_OFFSET, key_add_req->key.array, key_add_req->key.length);
#endif

    /* Send the MM_KEY_ADD_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, key_add_req, 1, MM_KEY_ADD_CFM, cfm);
}

int ecrnx_send_key_del(struct ecrnx_hw *ecrnx_hw, uint8_t hw_key_idx)
{
    struct mm_key_del_req *key_del_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_KEY_DEL_REQ message */
    key_del_req = ecrnx_msg_zalloc(MM_KEY_DEL_REQ, TASK_MM, DRV_TASK_ID,
                                  sizeof(struct mm_key_del_req));
    if (!key_del_req)
        return -ENOMEM;

    /* Set parameters for the MM_KEY_DEL_REQ message */
    key_del_req->hw_key_idx = hw_key_idx;

    /* Send the MM_KEY_DEL_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, key_del_req, 1, MM_KEY_DEL_CFM, NULL);
}

int ecrnx_send_bcn_change(struct ecrnx_hw *ecrnx_hw, u8 vif_idx, dma_addr_t bcn_addr,
                         u16 bcn_len, u16 tim_oft, u16 tim_len, u16 *csa_oft)
{
    struct mm_bcn_change_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_BCN_CHANGE_REQ message */
    req = ecrnx_msg_zalloc(MM_BCN_CHANGE_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_bcn_change_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_BCN_CHANGE_REQ message */
    req->bcn_ptr = bcn_addr;
    req->bcn_len = bcn_len;
    req->tim_oft = tim_oft;
    req->tim_len = tim_len;
    req->inst_nbr = vif_idx;

    if (csa_oft) {
        int i;
        for (i = 0; i < BCN_MAX_CSA_CPT; i++) {
            req->csa_oft[i] = csa_oft[i];
        }
    }

    /* Send the MM_BCN_CHANGE_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MM_BCN_CHANGE_CFM, NULL);
}

int ecrnx_send_roc(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                  struct ieee80211_channel *chan, unsigned  int duration)
{
    struct mm_remain_on_channel_req *req;
    struct cfg80211_chan_def chandef;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Create channel definition structure */
    cfg80211_chandef_create(&chandef, chan, NL80211_CHAN_NO_HT);

    /* Build the MM_REMAIN_ON_CHANNEL_REQ message */
    req = ecrnx_msg_zalloc(MM_REMAIN_ON_CHANNEL_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_remain_on_channel_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_REMAIN_ON_CHANNEL_REQ message */
    req->op_code      = MM_ROC_OP_START;
    req->vif_index    = vif->vif_index;
    req->duration_ms  = duration;
    cfg80211_to_ecrnx_chan(&chandef, &req->chan);

    /* Send the MM_REMAIN_ON_CHANNEL_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MM_REMAIN_ON_CHANNEL_CFM, NULL);
}

int ecrnx_send_cancel_roc(struct ecrnx_hw *ecrnx_hw)
{
    struct mm_remain_on_channel_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_REMAIN_ON_CHANNEL_REQ message */
    req = ecrnx_msg_zalloc(MM_REMAIN_ON_CHANNEL_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_remain_on_channel_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_REMAIN_ON_CHANNEL_REQ message */
    req->op_code = MM_ROC_OP_CANCEL;

    /* Send the MM_REMAIN_ON_CHANNEL_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MM_REMAIN_ON_CHANNEL_CFM, NULL);
}

int ecrnx_send_set_power(struct ecrnx_hw *ecrnx_hw, u8 vif_idx, s8 pwr,
                        struct mm_set_power_cfm *cfm)
{
    struct mm_set_power_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_SET_POWER_REQ message */
    req = ecrnx_msg_zalloc(MM_SET_POWER_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_set_power_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_SET_POWER_REQ message */
    req->inst_nbr = vif_idx;
    req->power = pwr;

    /* Send the MM_SET_POWER_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MM_SET_POWER_CFM, cfm);
}

int ecrnx_send_set_edca(struct ecrnx_hw *ecrnx_hw, u8 hw_queue, u32 param,
                       bool uapsd, u8 inst_nbr)
{
    struct mm_set_edca_req *set_edca_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_SET_EDCA_REQ message */
    set_edca_req = ecrnx_msg_zalloc(MM_SET_EDCA_REQ, TASK_MM, DRV_TASK_ID,
                                   sizeof(struct mm_set_edca_req));
    if (!set_edca_req)
        return -ENOMEM;

    /* Set parameters for the MM_SET_EDCA_REQ message */
    set_edca_req->ac_param = param;
    set_edca_req->uapsd = uapsd;
    set_edca_req->hw_queue = hw_queue;
    set_edca_req->inst_nbr = inst_nbr;

    /* Send the MM_SET_EDCA_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, set_edca_req, 1, MM_SET_EDCA_CFM, NULL);
}

#ifdef CONFIG_ECRNX_P2P_DEBUGFS
int ecrnx_send_p2p_oppps_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif,
                            u8 ctw, struct mm_set_p2p_oppps_cfm *cfm)
{
    struct mm_set_p2p_oppps_req *p2p_oppps_req;
    int error;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_SET_P2P_OPPPS_REQ message */
    p2p_oppps_req = ecrnx_msg_zalloc(MM_SET_P2P_OPPPS_REQ, TASK_MM, DRV_TASK_ID,
                                    sizeof(struct mm_set_p2p_oppps_req));

    if (!p2p_oppps_req) {
        return -ENOMEM;
    }

    /* Fill the message parameters */
    p2p_oppps_req->vif_index = ecrnx_vif->vif_index;
    p2p_oppps_req->ctwindow = ctw;

    /* Send the MM_P2P_OPPPS_REQ message to LMAC FW */
    error = ecrnx_send_msg(ecrnx_hw, p2p_oppps_req, 1, MM_SET_P2P_OPPPS_CFM, cfm);

    return (error);
}

int ecrnx_send_p2p_noa_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif,
                          int count, int interval, int duration, bool dyn_noa,
                          struct mm_set_p2p_noa_cfm *cfm)
{
    struct mm_set_p2p_noa_req *p2p_noa_req;
    int error;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Param check */
    if (count > 255)
        count = 255;

    if (duration >= interval) {
        dev_err(ecrnx_hw->dev, "Invalid p2p NOA config: interval=%d <= duration=%d\n",
                interval, duration);
        return -EINVAL;
    }

    /* Build the MM_SET_P2P_NOA_REQ message */
    p2p_noa_req = ecrnx_msg_zalloc(MM_SET_P2P_NOA_REQ, TASK_MM, DRV_TASK_ID,
                                  sizeof(struct mm_set_p2p_noa_req));

    if (!p2p_noa_req) {
        return -ENOMEM;
    }

    /* Fill the message parameters */
    p2p_noa_req->vif_index = ecrnx_vif->vif_index;
    p2p_noa_req->noa_inst_nb = 0;
    p2p_noa_req->count = count;

    if (count) {
        p2p_noa_req->duration_us = duration * 1024;
        p2p_noa_req->interval_us = interval * 1024;
        p2p_noa_req->start_offset = (interval - duration - 10) * 1024;
        p2p_noa_req->dyn_noa = dyn_noa;
    }

    /* Send the MM_SET_2P_NOA_REQ message to LMAC FW */
    error = ecrnx_send_msg(ecrnx_hw, p2p_noa_req, 1, MM_SET_P2P_NOA_CFM, cfm);

    return (error);
}
#endif /* CONFIG_ECRNX_P2P_DEBUGFS */

/******************************************************************************
 *    Control messages handling functions (FULLMAC only)
 *****************************************************************************/
#ifdef CONFIG_ECRNX_FULLMAC

int ecrnx_send_me_config_req(struct ecrnx_hw *ecrnx_hw)
{
    struct me_config_req *req;
    struct wiphy *wiphy = ecrnx_hw->wiphy;
#ifdef CONFIG_ECRNX_5G
    struct ieee80211_sta_ht_cap *ht_cap = &wiphy->bands[NL80211_BAND_5GHZ]->ht_cap;
    struct ieee80211_sta_vht_cap *vht_cap = &wiphy->bands[NL80211_BAND_5GHZ]->vht_cap;
#else
	struct ieee80211_sta_ht_cap *ht_cap = &wiphy->bands[NL80211_BAND_2GHZ]->ht_cap;
	struct ieee80211_sta_vht_cap *vht_cap = &wiphy->bands[NL80211_BAND_2GHZ]->vht_cap;
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)  && defined(CONFIG_ECRNX_HE)
    struct ieee80211_sta_he_cap const *he_cap;
#endif
    uint8_t *ht_mcs = (uint8_t *)&ht_cap->mcs;
    int i;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_CONFIG_REQ message */
    req = ecrnx_msg_zalloc(ME_CONFIG_REQ, TASK_ME, DRV_TASK_ID,
                                   sizeof(struct me_config_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the ME_CONFIG_REQ message */
    req->ht_supp = ht_cap->ht_supported;
    req->vht_supp = vht_cap->vht_supported;
    req->ht_cap.ht_capa_info = cpu_to_le16(ht_cap->cap);
    req->ht_cap.a_mpdu_param = ht_cap->ampdu_factor |
                                     (ht_cap->ampdu_density <<
                                         IEEE80211_HT_AMPDU_PARM_DENSITY_SHIFT);
    for (i = 0; i < sizeof(ht_cap->mcs); i++)
        req->ht_cap.mcs_rate[i] = ht_mcs[i];
    req->ht_cap.ht_extended_capa = 0;
    req->ht_cap.tx_beamforming_capa = 0;
    req->ht_cap.asel_capa = 0;

    req->vht_cap.vht_capa_info = cpu_to_le32(vht_cap->cap);
    req->vht_cap.rx_highest = cpu_to_le16(vht_cap->vht_mcs.rx_highest);
    req->vht_cap.rx_mcs_map = cpu_to_le16(vht_cap->vht_mcs.rx_mcs_map);
    req->vht_cap.tx_highest = cpu_to_le16(vht_cap->vht_mcs.tx_highest);
    req->vht_cap.tx_mcs_map = cpu_to_le16(vht_cap->vht_mcs.tx_mcs_map);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0) && defined(CONFIG_ECRNX_HE)
#ifdef CONFIG_ECRNX_5G
    if (wiphy->bands[NL80211_BAND_5GHZ]->iftype_data != NULL) {
        he_cap = &wiphy->bands[NL80211_BAND_5GHZ]->iftype_data->he_cap;
#else
	if (wiphy->bands[NL80211_BAND_2GHZ]->iftype_data != NULL) {
		he_cap = &wiphy->bands[NL80211_BAND_2GHZ]->iftype_data->he_cap;
#endif

        req->he_supp = he_cap->has_he;
        for (i = 0; i < ARRAY_SIZE(he_cap->he_cap_elem.mac_cap_info); i++) {
            req->he_cap.mac_cap_info[i] = he_cap->he_cap_elem.mac_cap_info[i];
        }
        for (i = 0; i < ARRAY_SIZE(he_cap->he_cap_elem.phy_cap_info); i++) {
            req->he_cap.phy_cap_info[i] = he_cap->he_cap_elem.phy_cap_info[i];
        }
        req->he_cap.mcs_supp.rx_mcs_80 = cpu_to_le16(he_cap->he_mcs_nss_supp.rx_mcs_80);
        req->he_cap.mcs_supp.tx_mcs_80 = cpu_to_le16(he_cap->he_mcs_nss_supp.tx_mcs_80);
        req->he_cap.mcs_supp.rx_mcs_160 = cpu_to_le16(he_cap->he_mcs_nss_supp.rx_mcs_160);
        req->he_cap.mcs_supp.tx_mcs_160 = cpu_to_le16(he_cap->he_mcs_nss_supp.tx_mcs_160);
        req->he_cap.mcs_supp.rx_mcs_80p80 = cpu_to_le16(he_cap->he_mcs_nss_supp.rx_mcs_80p80);
        req->he_cap.mcs_supp.tx_mcs_80p80 = cpu_to_le16(he_cap->he_mcs_nss_supp.tx_mcs_80p80);
        for (i = 0; i < MAC_HE_PPE_THRES_MAX_LEN; i++) {
            req->he_cap.ppe_thres[i] = he_cap->ppe_thres[i];
        }
        req->he_ul_on = ecrnx_hw->mod_params->he_ul_on;
    }
#else
    req->he_ul_on = false;

    req->he_supp = ecrnx_he_cap.has_he;
    for (i = 0; i < ARRAY_SIZE(ecrnx_he_cap.he_cap_elem.mac_cap_info); i++) {
        req->he_cap.mac_cap_info[i] = ecrnx_he_cap.he_cap_elem.mac_cap_info[i];
    }
    for (i = 0; i < ARRAY_SIZE(ecrnx_he_cap.he_cap_elem.phy_cap_info); i++) {
        req->he_cap.phy_cap_info[i] = ecrnx_he_cap.he_cap_elem.phy_cap_info[i];
    }
    req->he_cap.mcs_supp.rx_mcs_80 = cpu_to_le16(ecrnx_he_cap.he_mcs_nss_supp.rx_mcs_80);
    req->he_cap.mcs_supp.tx_mcs_80 = cpu_to_le16(ecrnx_he_cap.he_mcs_nss_supp.tx_mcs_80);
    req->he_cap.mcs_supp.rx_mcs_160 = cpu_to_le16(ecrnx_he_cap.he_mcs_nss_supp.rx_mcs_160);
    req->he_cap.mcs_supp.tx_mcs_160 = cpu_to_le16(ecrnx_he_cap.he_mcs_nss_supp.tx_mcs_160);
    req->he_cap.mcs_supp.rx_mcs_80p80 = cpu_to_le16(ecrnx_he_cap.he_mcs_nss_supp.rx_mcs_80p80);
    req->he_cap.mcs_supp.tx_mcs_80p80 = cpu_to_le16(ecrnx_he_cap.he_mcs_nss_supp.tx_mcs_80p80);
    for (i = 0; i < MAC_HE_PPE_THRES_MAX_LEN; i++) {
        req->he_cap.ppe_thres[i] = ecrnx_he_cap.ppe_thres[i];
    }
#endif

    req->ps_on = ecrnx_hw->mod_params->ps_on;
    req->dpsm = ecrnx_hw->mod_params->dpsm;
    /**
     * set sleep_flag for sdio slave.
     * bit0: MODEM_SLEEP
     * bit1: WFI_SLEEP
     * bit2: LIGHT_SLEEP
     * bit3: DEEP_SLEEP
     */
    req->sleep_flag = 0x5;
    req->tx_lft = ecrnx_hw->mod_params->tx_lft;
    req->ant_div_on = ecrnx_hw->mod_params->ant_div;
    if (ecrnx_hw->mod_params->use_80)
        req->phy_bw_max = PHY_CHNL_BW_80;
    else if (ecrnx_hw->mod_params->use_2040)
        req->phy_bw_max = PHY_CHNL_BW_40;
    else
        req->phy_bw_max = PHY_CHNL_BW_20;

    req->custom_macrule = ecrnx_hw->mod_params->custom_macrule;

    wiphy_info(wiphy, "HT supp %d, VHT supp %d, HE supp %d\n", req->ht_supp,
                                                               req->vht_supp,
                                                               req->he_supp);

    /* Send the ME_CONFIG_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_CONFIG_CFM, NULL);
}

int ecrnx_send_me_chan_config_req(struct ecrnx_hw *ecrnx_hw)
{
    struct me_chan_config_req *req;
    struct wiphy *wiphy = ecrnx_hw->wiphy;
    int i;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_CHAN_CONFIG_REQ message */
    req = ecrnx_msg_zalloc(ME_CHAN_CONFIG_REQ, TASK_ME, DRV_TASK_ID,
                                            sizeof(struct me_chan_config_req));
    if (!req)
        return -ENOMEM;

    req->chan2G4_cnt=  0;
    if (wiphy->bands[NL80211_BAND_2GHZ] != NULL) {
        struct ieee80211_supported_band *b = wiphy->bands[NL80211_BAND_2GHZ];
        for (i = 0; i < b->n_channels; i++) {
            req->chan2G4[req->chan2G4_cnt].flags = 0;
            if (b->channels[i].flags & IEEE80211_CHAN_DISABLED)
                req->chan2G4[req->chan2G4_cnt].flags |= CHAN_DISABLED;
            req->chan2G4[req->chan2G4_cnt].flags |= get_chan_flags(b->channels[i].flags);
            req->chan2G4[req->chan2G4_cnt].band = NL80211_BAND_2GHZ;
            req->chan2G4[req->chan2G4_cnt].freq = b->channels[i].center_freq;
            req->chan2G4[req->chan2G4_cnt].tx_power = chan_to_fw_pwr(b->channels[i].max_power);
            req->chan2G4_cnt++;
            if (req->chan2G4_cnt == MAC_DOMAINCHANNEL_24G_MAX)
                break;
        }
    }

    req->chan5G_cnt = 0;
#ifdef CONFIG_ECRNX_5G
    if (wiphy->bands[NL80211_BAND_5GHZ] != NULL) {
        struct ieee80211_supported_band *b = wiphy->bands[NL80211_BAND_5GHZ];
        for (i = 0; i < b->n_channels; i++) {
            req->chan5G[req->chan5G_cnt].flags = 0;
            if (b->channels[i].flags & IEEE80211_CHAN_DISABLED)
                req->chan5G[req->chan5G_cnt].flags |= CHAN_DISABLED;
            req->chan5G[req->chan5G_cnt].flags |= get_chan_flags(b->channels[i].flags);
            req->chan5G[req->chan5G_cnt].band = NL80211_BAND_5GHZ;
            req->chan5G[req->chan5G_cnt].freq = b->channels[i].center_freq;
            req->chan5G[req->chan5G_cnt].tx_power = chan_to_fw_pwr(b->channels[i].max_power);
            req->chan5G_cnt++;
            if (req->chan5G_cnt == MAC_DOMAINCHANNEL_5G_MAX)
                break;
        }
    }
#endif
    /* Send the ME_CHAN_CONFIG_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_CHAN_CONFIG_CFM, NULL);
}

int ecrnx_send_me_set_control_port_req(struct ecrnx_hw *ecrnx_hw, bool opened, u8 sta_idx)
{
    struct me_set_control_port_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_SET_CONTROL_PORT_REQ message */
    req = ecrnx_msg_zalloc(ME_SET_CONTROL_PORT_REQ, TASK_ME, DRV_TASK_ID,
                                   sizeof(struct me_set_control_port_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the ME_SET_CONTROL_PORT_REQ message */
    req->sta_idx = sta_idx;
    req->control_port_open = opened;

    /* Send the ME_SET_CONTROL_PORT_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_SET_CONTROL_PORT_CFM, NULL);
}

int ecrnx_send_me_sta_add(struct ecrnx_hw *ecrnx_hw, struct station_parameters *params,
                         const u8 *mac, u8 inst_nbr, struct me_sta_add_cfm *cfm)
{
    struct me_sta_add_req *req;
    u8 *ht_mcs = (u8 *)&params->ht_capa->mcs;
    int i;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_STA_ADD_REQ message */
    req = ecrnx_msg_zalloc(ME_STA_ADD_REQ, TASK_ME, DRV_TASK_ID,
                                  sizeof(struct me_sta_add_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_STA_ADD_REQ message */
    memcpy(&(req->mac_addr.array[0]), mac, ETH_ALEN);

    req->rate_set.length = params->supported_rates_len;
    for (i = 0; i < params->supported_rates_len; i++)
        req->rate_set.array[i] = params->supported_rates[i];

    req->flags = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (params->capability & WLAN_CAPABILITY_SHORT_PREAMBLE){
        req->flags |= STA_SHORT_PREAMBLE_CAPA;
    }
#endif

    if (params->ht_capa) {
        const struct ieee80211_ht_cap *ht_capa = params->ht_capa;

        req->flags |= STA_HT_CAPA;
        req->ht_cap.ht_capa_info = cpu_to_le16(ht_capa->cap_info);
        req->ht_cap.a_mpdu_param = ht_capa->ampdu_params_info;
        for (i = 0; i < sizeof(ht_capa->mcs); i++)
            req->ht_cap.mcs_rate[i] = ht_mcs[i];
        req->ht_cap.ht_extended_capa = cpu_to_le16(ht_capa->extended_ht_cap_info);
        req->ht_cap.tx_beamforming_capa = cpu_to_le32(ht_capa->tx_BF_cap_info);
        req->ht_cap.asel_capa = ht_capa->antenna_selection_info;
    }

    if (params->vht_capa) {
        const struct ieee80211_vht_cap *vht_capa = params->vht_capa;

        req->flags |= STA_VHT_CAPA;
        req->vht_cap.vht_capa_info = cpu_to_le32(vht_capa->vht_cap_info);
        req->vht_cap.rx_highest = cpu_to_le16(vht_capa->supp_mcs.rx_highest);
        req->vht_cap.rx_mcs_map = cpu_to_le16(vht_capa->supp_mcs.rx_mcs_map);
        req->vht_cap.tx_highest = cpu_to_le16(vht_capa->supp_mcs.tx_highest);
        req->vht_cap.tx_mcs_map = cpu_to_le16(vht_capa->supp_mcs.tx_mcs_map);
    }

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)) && defined(CONFIG_ECRNX_HE)
    if (params->he_capa) {
        const struct ieee80211_he_cap_elem *he_capa = params->he_capa;
        struct ieee80211_he_mcs_nss_supp *mcs_nss_supp =
                                (struct ieee80211_he_mcs_nss_supp *)(he_capa + 1);

        req->flags |= STA_HE_CAPA;
        for (i = 0; i < ARRAY_SIZE(he_capa->mac_cap_info); i++) {
            req->he_cap.mac_cap_info[i] = he_capa->mac_cap_info[i];
        }
        for (i = 0; i < ARRAY_SIZE(he_capa->phy_cap_info); i++) {
            req->he_cap.phy_cap_info[i] = he_capa->phy_cap_info[i];
        }
        req->he_cap.mcs_supp.rx_mcs_80 = mcs_nss_supp->rx_mcs_80;
        req->he_cap.mcs_supp.tx_mcs_80 = mcs_nss_supp->tx_mcs_80;
        req->he_cap.mcs_supp.rx_mcs_160 = mcs_nss_supp->rx_mcs_160;
        req->he_cap.mcs_supp.tx_mcs_160 = mcs_nss_supp->tx_mcs_160;
        req->he_cap.mcs_supp.rx_mcs_80p80 = mcs_nss_supp->rx_mcs_80p80;
        req->he_cap.mcs_supp.tx_mcs_80p80 = mcs_nss_supp->tx_mcs_80p80;
    }

#endif

    if (params->sta_flags_set & BIT(NL80211_STA_FLAG_WME))
        req->flags |= STA_QOS_CAPA;

    if (params->sta_flags_set & BIT(NL80211_STA_FLAG_MFP)) //  if (sme->mfp == NL80211_MFP_REQUIRED || sme->mfp ==NL80211_MFP_OPTIONAL) //wfa must used  NL80211_MFP_REQUIRED and NL80211_MFP_OPTIONAL
        req->flags |= STA_MFP_CAPA;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    if (params->opmode_notif_used) {
        req->flags |= STA_OPMOD_NOTIF;
        req->opmode = params->opmode_notif;
    }
#endif

    req->aid = cpu_to_le16(params->aid);
    req->uapsd_queues = params->uapsd_queues;
    req->max_sp_len = params->max_sp * 2;
    req->vif_idx = inst_nbr;

    if (params->sta_flags_set & BIT(NL80211_STA_FLAG_TDLS_PEER)) {
        struct ecrnx_vif *ecrnx_vif = ecrnx_hw->vif_table[inst_nbr];
        req->tdls_sta = true;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
        if ((params->ext_capab[3] & WLAN_EXT_CAPA4_TDLS_CHAN_SWITCH) &&
            !ecrnx_vif->tdls_chsw_prohibited)
            req->tdls_chsw_allowed = true;
#endif
        if (ecrnx_vif->tdls_status == TDLS_SETUP_RSP_TX)
            req->tdls_sta_initiator = true;
    }

    /* Send the ME_STA_ADD_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_STA_ADD_CFM, cfm);
}

int ecrnx_send_me_sta_del(struct ecrnx_hw *ecrnx_hw, u8 sta_idx, bool tdls_sta)
{
    struct me_sta_del_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_STA_DEL_REQ message */
    req = ecrnx_msg_zalloc(ME_STA_DEL_REQ, TASK_ME, DRV_TASK_ID,
                          sizeof(struct me_sta_del_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_STA_DEL_REQ message */
    req->sta_idx = sta_idx;
    req->tdls_sta = tdls_sta;

    /* Send the ME_STA_DEL_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_STA_DEL_CFM, NULL);
}

int ecrnx_send_me_traffic_ind(struct ecrnx_hw *ecrnx_hw, u8 sta_idx, bool uapsd, u8 tx_status)
{
    struct me_traffic_ind_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_UTRAFFIC_IND_REQ message */
    req = ecrnx_msg_zalloc(ME_TRAFFIC_IND_REQ, TASK_ME, DRV_TASK_ID,
                          sizeof(struct me_traffic_ind_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the ME_TRAFFIC_IND_REQ message */
    req->sta_idx = sta_idx;
    req->tx_avail = tx_status;
    req->uapsd = uapsd;

    /* Send the ME_TRAFFIC_IND_REQ to UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_TRAFFIC_IND_CFM, NULL);
}

int ecrnx_send_twt_request(struct ecrnx_hw *ecrnx_hw,
                          u8 setup_type, u8 vif_idx,
                          struct twt_conf_tag *conf,
                          struct twt_setup_cfm *cfm)
{
    struct twt_setup_req *req;

    ecrnx_printk_pm(ECRNX_FN_ENTRY_STR);

    /* Build the TWT_SETUP_REQ message */
    req = ecrnx_msg_zalloc(TWT_SETUP_REQ, TASK_TWT, DRV_TASK_ID,
                          sizeof(struct twt_setup_req));
    if (!req)
        return -ENOMEM;

    memcpy(&req->conf, conf, sizeof(req->conf));
    req->setup_type = setup_type;
    req->vif_idx = vif_idx;

    /* Send the TWT_SETUP_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, TWT_SETUP_CFM, cfm);
}

int ecrnx_send_twt_teardown(struct ecrnx_hw *ecrnx_hw,
                           struct twt_teardown_req *twt_teardown,
                           struct twt_teardown_cfm *cfm)
{
    struct twt_teardown_req *req;

    ecrnx_printk_pm(ECRNX_FN_ENTRY_STR);

    /* Build the TWT_TEARDOWN_REQ message */
    req = ecrnx_msg_zalloc(TWT_TEARDOWN_REQ, TASK_TWT, DRV_TASK_ID,
                          sizeof(struct twt_teardown_req));
    if (!req)
        return -ENOMEM;

    memcpy(req, twt_teardown, sizeof(struct twt_teardown_req));

    /* Send the TWT_TEARDOWN_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, TWT_TEARDOWN_CFM, cfm);
}
int ecrnx_send_me_rc_stats(struct ecrnx_hw *ecrnx_hw,
                          u8 sta_idx,
                          struct me_rc_stats_cfm *cfm)
{
    struct me_rc_stats_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_RC_STATS_REQ message */
    req = ecrnx_msg_zalloc(ME_RC_STATS_REQ, TASK_ME, DRV_TASK_ID,
                                  sizeof(struct me_rc_stats_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the ME_RC_STATS_REQ message */
    req->sta_idx = sta_idx;

    /* Send the ME_RC_STATS_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_RC_STATS_CFM, cfm);
}

int ecrnx_send_me_rc_set_rate(struct ecrnx_hw *ecrnx_hw,
                             u8 sta_idx,
                             u16 rate_cfg)
{
    struct me_rc_set_rate_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_RC_SET_RATE_REQ message */
    req = ecrnx_msg_zalloc(ME_RC_SET_RATE_REQ, TASK_ME, DRV_TASK_ID,
                          sizeof(struct me_rc_set_rate_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the ME_RC_SET_RATE_REQ message */
    req->sta_idx = sta_idx;
    req->fixed_rate_cfg = rate_cfg;

    /* Send the ME_RC_SET_RATE_REQ message to FW */
    return ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
}

int ecrnx_send_me_set_ps_mode(struct ecrnx_hw *ecrnx_hw, u8 ps_mode)
{
    struct me_set_ps_mode_req *req;

    ecrnx_printk_pm(ECRNX_FN_ENTRY_STR);

    /* Build the ME_SET_PS_MODE_REQ message */
    req = ecrnx_msg_zalloc(ME_SET_PS_MODE_REQ, TASK_ME, DRV_TASK_ID,
                          sizeof(struct me_set_ps_mode_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the ME_SET_PS_MODE_REQ message */
    req->ps_state = ps_mode;

    /* Send the ME_SET_PS_MODE_REQ message to FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_SET_PS_MODE_CFM, NULL);
}

int ecrnx_send_sm_connect_req(struct ecrnx_hw *ecrnx_hw,
                             struct ecrnx_vif *ecrnx_vif,
                             struct cfg80211_connect_params *sme,
                             struct sm_connect_cfm *cfm)
{
    struct sm_connect_req *req;
    int i, ie_len;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    ie_len = update_connect_req(ecrnx_vif, sme);
    /* Build the SM_CONNECT_REQ message */
    req = ecrnx_msg_zalloc(SM_CONNECT_REQ, TASK_SM, DRV_TASK_ID,
                     (sizeof(struct sm_connect_req) + ie_len));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the SM_CONNECT_REQ message */
    if (sme->crypto.n_ciphers_pairwise &&
        ((sme->crypto.ciphers_pairwise[0] == WLAN_CIPHER_SUITE_WEP40) ||
         (sme->crypto.ciphers_pairwise[0] == WLAN_CIPHER_SUITE_TKIP) ||
         (sme->crypto.ciphers_pairwise[0] == WLAN_CIPHER_SUITE_WEP104)))
        req->flags |= DISABLE_HT;

    if (sme->crypto.control_port)
        req->flags |= CONTROL_PORT_HOST;

    if (sme->crypto.control_port_no_encrypt)
        req->flags |= CONTROL_PORT_NO_ENC;

    if (use_pairwise_key(&sme->crypto))
        req->flags |= WPA_WPA2_IN_USE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (sme->mfp == NL80211_MFP_REQUIRED)
        req->flags |= MFP_IN_USE;
#endif

    req->ctrl_port_ethertype = sme->crypto.control_port_ethertype;

    if (sme->bssid)
        memcpy(&req->bssid, sme->bssid, ETH_ALEN);
    else
        req->bssid = mac_addr_bcst;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 7, 0)
    if (sme->prev_bssid)
        req->flags |= REASSOCIATION;
#else
    if (ecrnx_vif->sta.ap)
        req->flags |= REASSOCIATION;
#endif
    if ((sme->auth_type == NL80211_AUTHTYPE_FT) && (ecrnx_vif->sta.flags & ECRNX_STA_FT_OVER_DS))
        req->flags |= (REASSOCIATION | FT_OVER_DS);
    req->vif_idx = ecrnx_vif->vif_index;
    if (sme->channel) {
        req->chan.band = sme->channel->band;
        req->chan.freq = sme->channel->center_freq;
        req->chan.flags = get_chan_flags(sme->channel->flags);
    } else {
        req->chan.freq = (u16_l)-1;
    }
    memset(ecrnx_vif->ssid, 0, 32);
    for (i = 0; i < sme->ssid_len; i++){
        req->ssid.array[i] = sme->ssid[i];
        ecrnx_vif->ssid[i] = sme->ssid[i];
    }
    ecrnx_vif->ssidLength = sme->ssid_len;
    req->ssid.length = sme->ssid_len;

    req->listen_interval = ecrnx_mod_params.listen_itv;
    req->dont_wait_bcmc = !ecrnx_mod_params.listen_bcmc;

    /* Set auth_type */
    if (sme->auth_type == NL80211_AUTHTYPE_AUTOMATIC)
        req->auth_type = WLAN_AUTH_OPEN;
    else if (sme->auth_type == NL80211_AUTHTYPE_OPEN_SYSTEM)
        req->auth_type = WLAN_AUTH_OPEN;
    else if (sme->auth_type == NL80211_AUTHTYPE_SHARED_KEY)
        req->auth_type = WLAN_AUTH_SHARED_KEY;
    else if (sme->auth_type == NL80211_AUTHTYPE_FT)
        req->auth_type = WLAN_AUTH_FT;
    else if (sme->auth_type == NL80211_AUTHTYPE_SAE)
        req->auth_type = WLAN_AUTH_SAE;
    else
        goto invalid_param;
    copy_connect_ies(ecrnx_vif, req, sme);

    /* Set UAPSD queues */
    req->uapsd_queues = ecrnx_mod_params.uapsd_queues;

    /* Send the SM_CONNECT_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, SM_CONNECT_CFM, cfm);

invalid_param:
    ecrnx_msg_free(ecrnx_hw, req);
    return -EINVAL;
}

int ecrnx_send_sm_disconnect_req(struct ecrnx_hw *ecrnx_hw,
                                struct ecrnx_vif *ecrnx_vif,
                                u16 reason)
{
    struct sm_disconnect_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the SM_DISCONNECT_REQ message */
    req = ecrnx_msg_zalloc(SM_DISCONNECT_REQ, TASK_SM, DRV_TASK_ID,
                                   sizeof(struct sm_disconnect_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the SM_DISCONNECT_REQ message */
    req->reason_code = reason;
    req->vif_idx = ecrnx_vif->vif_index;

    /* Send the SM_DISCONNECT_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, SM_DISCONNECT_CFM, NULL);
}

int ecrnx_send_disconnect_local(struct ecrnx_hw *ecrnx_hw,
                                struct ecrnx_vif *ecrnx_vif,
                                u16 reason)
{
    ecrnx_vif->local_disconn = 1;
    return ecrnx_send_sm_disconnect_req(ecrnx_hw, ecrnx_vif, reason);
}

int ecrnx_send_sm_external_auth_required_rsp(struct ecrnx_hw *ecrnx_hw,
                                            struct ecrnx_vif *ecrnx_vif,
                                            u16 status)
{
    struct sm_external_auth_required_rsp *rsp;

    /* Build the SM_EXTERNAL_AUTH_CFM message */
    rsp = ecrnx_msg_zalloc(SM_EXTERNAL_AUTH_REQUIRED_RSP, TASK_SM, DRV_TASK_ID,
                          sizeof(struct sm_external_auth_required_rsp));
    if (!rsp)
        return -ENOMEM;

    rsp->status = status;
    rsp->vif_idx = ecrnx_vif->vif_index;

    /* send the SM_EXTERNAL_AUTH_REQUIRED_RSP message UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, rsp, 0, 0, NULL);
}
int ecrnx_send_sm_ft_auth_rsp(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif,
                             uint8_t *ie, int ie_len)
{
    struct sm_connect_req *rsp;
    rsp = ecrnx_msg_zalloc(SM_FT_AUTH_RSP, TASK_SM, DRV_TASK_ID,
                         (sizeof(struct sm_connect_req) + ie_len));
    if (!rsp)
        return -ENOMEM;
    rsp->vif_idx = ecrnx_vif->vif_index;
    rsp->ie_len = ie_len;
    memcpy(rsp->ie_buf, ie, rsp->ie_len);
    return ecrnx_send_msg(ecrnx_hw, rsp, 0, 0, NULL);
}

int ecrnx_send_apm_start_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                            struct cfg80211_ap_settings *settings,
                            struct apm_start_cfm *cfm,
                            struct ecrnx_ipc_elem_var *elem)
{
    struct apm_start_req *req;
    struct ecrnx_bcn *bcn = &vif->ap.bcn;
    u8 *buf;
    u32 flags = 0;
    const u8 *rate_ie;
    u8 rate_len = 0;
    int var_offset = offsetof(struct ieee80211_mgmt, u.beacon.variable);
    const u8 *var_pos;
    int len, i, error;

    ecrnx_printk_ap(ECRNX_FN_ENTRY_STR);

    /* Build the APM_START_REQ message */
    req = ecrnx_msg_zalloc(APM_START_REQ, TASK_APM, DRV_TASK_ID,
                                   sizeof(struct apm_start_req));
    if (!req)
        return -ENOMEM;

    // Build the beacon
    bcn->dtim = (u8)settings->dtim_period;
    buf = ecrnx_build_bcn(bcn, &settings->beacon);
    if (!buf) {
        ecrnx_msg_free(ecrnx_hw, req);
        return -ENOMEM;
    }

    // Retrieve the basic rate set from the beacon buffer
    len = bcn->len - var_offset;
    var_pos = buf + var_offset;

// Assume that rate higher that 54 Mbps are BSS membership
#define IS_BASIC_RATE(r) (r & 0x80) && ((r & ~0x80) <= (54 * 2))

    rate_ie = cfg80211_find_ie(WLAN_EID_SUPP_RATES, var_pos, len);
    if (rate_ie) {
        const u8 *rates = rate_ie + 2;
        for (i = 0; (i < rate_ie[1]) && (rate_len < MAC_RATESET_LEN); i++) {
            if (IS_BASIC_RATE(rates[i]))
                req->basic_rates.array[rate_len++] = rates[i];
        }
    }
    rate_ie = cfg80211_find_ie(WLAN_EID_EXT_SUPP_RATES, var_pos, len);
    if (rate_ie) {
        const u8 *rates = rate_ie + 2;
        for (i = 0; (i < rate_ie[1]) && (rate_len < MAC_RATESET_LEN); i++) {
            if (IS_BASIC_RATE(rates[i]))
                req->basic_rates.array[rate_len++] = rates[i];
        }
    }
    req->basic_rates.length = rate_len;
#undef IS_BASIC_RATE

    // Sync buffer for FW
    if ((error = ecrnx_ipc_elem_var_allocs(ecrnx_hw, elem, bcn->len,
                                          DMA_TO_DEVICE, buf, NULL, NULL))) {
        return error;
    }

    /* Set parameters for the APM_START_REQ message */
    req->vif_idx = vif->vif_index;
    req->bcn_addr = elem->dma_addr;
    req->bcn_len = bcn->len;
    req->tim_oft = bcn->head_len;
    req->tim_len = bcn->tim_len;
    cfg80211_to_ecrnx_chan(&settings->chandef, &req->chan);
    req->bcn_int = settings->beacon_interval;
    if (settings->crypto.control_port)
        flags |= CONTROL_PORT_HOST;

    if (settings->crypto.control_port_no_encrypt)
        flags |= CONTROL_PORT_NO_ENC;

    if (use_pairwise_key(&settings->crypto))
        flags |= WPA_WPA2_IN_USE;

    if (settings->crypto.control_port_ethertype)
        req->ctrl_port_ethertype = settings->crypto.control_port_ethertype;
    else
        req->ctrl_port_ethertype = ETH_P_PAE;
    req->flags = flags;

    /* Send the APM_START_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, APM_START_CFM, cfm);
}

int ecrnx_send_apm_stop_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif)
{
    struct apm_stop_req *req;

    ecrnx_printk_ap(ECRNX_FN_ENTRY_STR);

    /* Build the APM_STOP_REQ message */
    req = ecrnx_msg_zalloc(APM_STOP_REQ, TASK_APM, DRV_TASK_ID,
                                   sizeof(struct apm_stop_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the APM_STOP_REQ message */
    req->vif_idx = vif->vif_index;

    /* Send the APM_STOP_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, APM_STOP_CFM, NULL);
}

int ecrnx_send_apm_probe_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                            struct ecrnx_sta *sta, struct apm_probe_client_cfm *cfm)
{
    struct apm_probe_client_req *req;

    ecrnx_printk_ap(ECRNX_FN_ENTRY_STR);

    req = ecrnx_msg_zalloc(APM_PROBE_CLIENT_REQ, TASK_APM, DRV_TASK_ID,
                          sizeof(struct apm_probe_client_req));
    if (!req)
        return -ENOMEM;

    req->vif_idx = vif->vif_index;
    req->sta_idx = sta->sta_idx;

    /* Send the APM_PROBE_CLIENT_REQ message to UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, APM_PROBE_CLIENT_CFM, cfm);
}
#ifdef CONFIG_WIRELESS_EXT
extern void ecrnx_release_list(struct ecrnx_hw *ecrnx_hw, bool is_exit);
#endif
int ecrnx_send_scanu_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif,
                        struct cfg80211_scan_request *param)
{
    struct scanu_start_req *req;
    int i, chan_num = 0;
    uint8_t chan_flags = 0;

    ecrnx_printk_scan(ECRNX_FN_ENTRY_STR);

    /* Build the SCANU_START_REQ message */
    req = ecrnx_msg_zalloc(SCANU_START_REQ, TASK_SCANU, DRV_TASK_ID,
                          sizeof(struct scanu_start_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters */
    req->vif_idx = ecrnx_vif->vif_index;
    req->chan_cnt = (u8)min_t(int, SCAN_CHANNEL_MAX, param->n_channels);
    req->ssid_cnt = (u8)min_t(int, SCAN_SSID_MAX, param->n_ssids);
    req->bssid = mac_addr_bcst;
    req->no_cck = param->no_cck;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 8, 0)
    if (param->duration_mandatory)
        req->duration = ieee80211_tu_to_usec(param->duration);
#endif

    if(param->n_ssids>1){
        ecrnx_printk_scan("%s:n_ssids: %d \n", __func__, param->n_ssids);
        for (i = 0; i < param->n_ssids; i++){
            print_hex_dump_bytes("[ecrnx]scan_req: ", DUMP_PREFIX_NONE, &param->ssids[i], param->ssids[i].ssid_len);
            ecrnx_printk_scan("i:%d, ssid_len:%d \n", i, param->ssids[i].ssid_len);
        }
    }

    if (req->ssid_cnt == 0)
        chan_flags |= CHAN_NO_IR;
    for (i = 0; i < req->ssid_cnt; i++) {
        int j;
        for (j = 0; j < param->ssids[i].ssid_len; j++)
            req->ssid[i].array[j] = param->ssids[i].ssid[j];
        req->ssid[i].length = param->ssids[i].ssid_len;
    }

    if(req->ssid_cnt == 1 && param->ssids[0].ssid_len > 0)
    {
        if (strcmp(req->ssid[0].array, "DIRECT-"))
        {
            req->ssid_cnt = 2;
            req->ssid[1].length = 0;
        }
    }

    if (param->ie) {

        if (ecrnx_ipc_elem_var_allocs(ecrnx_hw, &ecrnx_hw->scan_ie,
                                     param->ie_len, DMA_TO_DEVICE,
                                     NULL, param->ie, NULL))
            goto error;
        req->add_ie_len = param->ie_len;
        req->add_ies = ecrnx_hw->scan_ie.dma_addr;
    } else {
        req->add_ie_len = 0;
        req->add_ies = 0;
    }

    for (i = 0; i < req->chan_cnt; i++) {
        struct ieee80211_channel *chan = param->channels[i];

		if(chan->band){
			continue;
		}
        req->chan[chan_num].band = chan->band;
        req->chan[chan_num].freq = chan->center_freq;
        req->chan[chan_num].flags = chan_flags | get_chan_flags(chan->flags);
        req->chan[chan_num].tx_power = chan_to_fw_pwr(chan->max_reg_power);
		chan_num++;
		ecrnx_printk_scan("--%d set ch, %d,%d,%d,%d\n", i, req->chan[i].band, req->chan[i].freq, req->chan[i].flags, req->chan[i].tx_power);
    }
#ifdef CONFIG_WIRELESS_EXT
	ecrnx_release_list(ecrnx_hw, false);
#endif
	req->chan_cnt = chan_num;
    /* Send the SCANU_START_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
error:
    if (req != NULL)
        ecrnx_msg_free(ecrnx_hw, req);
    return -ENOMEM;
}

int ecrnx_send_scanu_cancel_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif)
{
    struct scanu_cancel_req *req = NULL;

    /* Build the SCANU_START_REQ message */
    req = ecrnx_msg_zalloc(SCANU_CANCEL_REQ, TASK_SCANU, DRV_TASK_ID,
                          sizeof(struct scanu_cancel_req));
    if (!req){
        return -ENOMEM;
    }

    req->vif_idx = ecrnx_vif->vif_index;
    ecrnx_printk_scan("%s: vif_idx:%d; \n", __func__, req->vif_idx);
    return ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
}

int ecrnx_send_apm_start_cac_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                                struct cfg80211_chan_def *chandef,
                                struct apm_start_cac_cfm *cfm)
{
    struct apm_start_cac_req *req;

    ecrnx_printk_ap(ECRNX_FN_ENTRY_STR);

    /* Build the APM_START_CAC_REQ message */
    req = ecrnx_msg_zalloc(APM_START_CAC_REQ, TASK_APM, DRV_TASK_ID,
                          sizeof(struct apm_start_cac_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the APM_START_CAC_REQ message */
    req->vif_idx = vif->vif_index;
    cfg80211_to_ecrnx_chan(chandef, &req->chan);

    /* Send the APM_START_CAC_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, APM_START_CAC_CFM, cfm);
}

int ecrnx_send_apm_stop_cac_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif)
{
    struct apm_stop_cac_req *req;

    ecrnx_printk_ap(ECRNX_FN_ENTRY_STR);

    /* Build the APM_STOP_CAC_REQ message */
    req = ecrnx_msg_zalloc(APM_STOP_CAC_REQ, TASK_APM, DRV_TASK_ID,
                          sizeof(struct apm_stop_cac_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the APM_STOP_CAC_REQ message */
    req->vif_idx = vif->vif_index;

    /* Send the APM_STOP_CAC_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, APM_STOP_CAC_CFM, NULL);
}

int ecrnx_send_mesh_start_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                             const struct mesh_config *conf, const struct mesh_setup *setup,
                             struct mesh_start_cfm *cfm)
{
    // Message to send
    struct mesh_start_req *req;
    // Supported basic rates
    struct ieee80211_supported_band *band = ecrnx_hw->wiphy->bands[setup->chandef.chan->band];
    /* Counter */
    int i;
    /* Return status */
    int status;
    /* DMA Address to be unmapped after confirmation reception */
    u32 dma_addr = 0;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MESH_START_REQ message */
    req = ecrnx_msg_zalloc(MESH_START_REQ, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_start_req));
    if (!req) {
        return -ENOMEM;
    }

    req->vif_index = vif->vif_index;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    req->bcn_int = setup->beacon_interval;
    req->dtim_period = setup->dtim_period;
#endif
    req->mesh_id_len = setup->mesh_id_len;

    for (i = 0; i < setup->mesh_id_len; i++) {
        req->mesh_id[i] = *(setup->mesh_id + i);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    req->user_mpm = setup->user_mpm;
#endif
    req->is_auth = setup->is_authenticated;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
    req->auth_id = setup->auth_id;
#endif
    req->ie_len = setup->ie_len;

    if (setup->ie_len) {
        /*
         * Need to provide a Virtual Address to the MAC so that it can download the
         * additional information elements.
         */
        req->ie_addr = dma_map_single(ecrnx_hw->dev, (void *)setup->ie,
                                      setup->ie_len, DMA_FROM_DEVICE);

        /* Check DMA mapping result */
        if (dma_mapping_error(ecrnx_hw->dev, req->ie_addr)) {
            ecrnx_printk_err(KERN_CRIT "%s - DMA Mapping error on additional IEs\n", __func__);

            /* Consider there is no Additional IEs */
            req->ie_len = 0;
        } else {
            /* Store DMA Address so that we can unmap the memory section once MESH_START_CFM is received */
            dma_addr = req->ie_addr;
        }
    }

    /* Provide rate information */
    req->basic_rates.length = 0;
    for (i = 0; i < band->n_bitrates; i++) {
        u16 rate = band->bitrates[i].bitrate;

        /* Read value is in in units of 100 Kbps, provided value is in units
         * of 1Mbps, and multiplied by 2 so that 5.5 becomes 11 */
        rate = (rate << 1) / 10;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
        if (setup->basic_rates & CO_BIT(i)) {
            rate |= 0x80;
        }
#endif

        req->basic_rates.array[i] = (u8)rate;
        req->basic_rates.length++;
    }

    /* Provide channel information */
    cfg80211_to_ecrnx_chan(&setup->chandef, &req->chan);

    /* Send the MESH_START_REQ message to UMAC FW */
    status = ecrnx_send_msg(ecrnx_hw, req, 1, MESH_START_CFM, cfm);

    /* Unmap DMA area */
    if (setup->ie_len) {
        dma_unmap_single(ecrnx_hw->dev, dma_addr, setup->ie_len, DMA_TO_DEVICE);
    }

    /* Return the status */
    return (status);
}

int ecrnx_send_mesh_stop_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                            struct mesh_stop_cfm *cfm)
{
    // Message to send
    struct mesh_stop_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MESH_STOP_REQ message */
    req = ecrnx_msg_zalloc(MESH_STOP_REQ, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_stop_req));
    if (!req) {
        return -ENOMEM;
    }

    req->vif_idx = vif->vif_index;

    /* Send the MESH_STOP_REQ message to UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MESH_STOP_CFM, cfm);
}

int ecrnx_send_mesh_update_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                              u32 mask, const struct mesh_config *p_mconf, struct mesh_update_cfm *cfm)
{
    // Message to send
    struct mesh_update_req *req;
    // Keep only bit for fields which can be updated
    u32 supp_mask = (mask << 1) & (CO_BIT(NL80211_MESHCONF_GATE_ANNOUNCEMENTS)
                                   | CO_BIT(NL80211_MESHCONF_HWMP_ROOTMODE)
                                   | CO_BIT(NL80211_MESHCONF_FORWARDING)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
                                   | CO_BIT(NL80211_MESHCONF_POWER_MODE)
#endif
                                   );


    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    if (!supp_mask) {
        return -ENOENT;
    }

    /* Build the MESH_UPDATE_REQ message */
    req = ecrnx_msg_zalloc(MESH_UPDATE_REQ, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_update_req));

    if (!req) {
        return -ENOMEM;
    }

    req->vif_idx = vif->vif_index;

    if (supp_mask & CO_BIT(NL80211_MESHCONF_GATE_ANNOUNCEMENTS))
    {
        req->flags |= CO_BIT(MESH_UPDATE_FLAGS_GATE_MODE_BIT);
        req->gate_announ = p_mconf->dot11MeshGateAnnouncementProtocol;
    }

    if (supp_mask & CO_BIT(NL80211_MESHCONF_HWMP_ROOTMODE))
    {
        req->flags |= CO_BIT(MESH_UPDATE_FLAGS_ROOT_MODE_BIT);
        req->root_mode = p_mconf->dot11MeshHWMPRootMode;
    }

    if (supp_mask & CO_BIT(NL80211_MESHCONF_FORWARDING))
    {
        req->flags |= CO_BIT(MESH_UPDATE_FLAGS_MESH_FWD_BIT);
        req->mesh_forward = p_mconf->dot11MeshForwarding;
    }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
    if (supp_mask & CO_BIT(NL80211_MESHCONF_POWER_MODE))
    {
        req->flags |= CO_BIT(MESH_UPDATE_FLAGS_LOCAL_PSM_BIT);
        req->local_ps_mode = p_mconf->power_mode;
    }
#endif
    /* Send the MESH_UPDATE_REQ message to UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MESH_UPDATE_CFM, cfm);
}

int ecrnx_send_mesh_peer_info_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                                 u8 sta_idx, struct mesh_peer_info_cfm *cfm)
{
    // Message to send
    struct mesh_peer_info_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MESH_PEER_INFO_REQ message */
    req = ecrnx_msg_zalloc(MESH_PEER_INFO_REQ, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_peer_info_req));
    if (!req) {
        return -ENOMEM;
    }

    req->sta_idx = sta_idx;

    /* Send the MESH_PEER_INFO_REQ message to UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MESH_PEER_INFO_CFM, cfm);
}

void ecrnx_send_mesh_peer_update_ntf(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif,
                                    u8 sta_idx, u8 mlink_state)
{
    // Message to send
    struct mesh_peer_update_ntf *ntf;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MESH_PEER_UPDATE_NTF message */
    ntf = ecrnx_msg_zalloc(MESH_PEER_UPDATE_NTF, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_peer_update_ntf));

    if (ntf) {
        ntf->vif_idx = vif->vif_index;
        ntf->sta_idx = sta_idx;
        ntf->state = mlink_state;

        /* Send the MESH_PEER_INFO_REQ message to UMAC FW */
        ecrnx_send_msg(ecrnx_hw, ntf, 0, 0, NULL);
    }
}

void ecrnx_send_mesh_path_create_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif, u8 *tgt_addr)
{
    struct mesh_path_create_req *req;
    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Check if we are already waiting for a confirmation */
    if (vif->ap.flags & ECRNX_AP_CREATE_MESH_PATH)
        return;

        /* Build the MESH_PATH_CREATE_REQ message */
    req = ecrnx_msg_zalloc(MESH_PATH_CREATE_REQ, TASK_MESH, DRV_TASK_ID,
                              sizeof(struct mesh_path_create_req));
    if (!req)
        return;

    req->vif_idx = vif->vif_index;
    memcpy(&req->tgt_mac_addr, tgt_addr, ETH_ALEN);

    vif->ap.flags |= ECRNX_AP_CREATE_MESH_PATH;

    /* Send the MESH_PATH_CREATE_REQ message to UMAC FW */
    ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
}

int ecrnx_send_mesh_path_update_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif, const u8 *tgt_addr,
                                   const u8 *p_nhop_addr, struct mesh_path_update_cfm *cfm)
{
    // Message to send
    struct mesh_path_update_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MESH_PATH_UPDATE_REQ message */
    req = ecrnx_msg_zalloc(MESH_PATH_UPDATE_REQ, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_path_update_req));
    if (!req) {
        return -ENOMEM;
    }

    req->delete = (p_nhop_addr == NULL);
    req->vif_idx = vif->vif_index;
    memcpy(&req->tgt_mac_addr, tgt_addr, ETH_ALEN);

    if (p_nhop_addr) {
        memcpy(&req->nhop_mac_addr, p_nhop_addr, ETH_ALEN);
    }

    /* Send the MESH_PATH_UPDATE_REQ message to UMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MESH_PATH_UPDATE_CFM, cfm);
}

void ecrnx_send_mesh_proxy_add_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *vif, u8 *ext_addr)
{
    // Message to send
    struct mesh_proxy_add_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MESH_PROXY_ADD_REQ message */
    req = ecrnx_msg_zalloc(MESH_PROXY_ADD_REQ, TASK_MESH, DRV_TASK_ID,
                          sizeof(struct mesh_proxy_add_req));

    if (req) {
        req->vif_idx = vif->vif_index;
        memcpy(&req->ext_sta_addr, ext_addr, ETH_ALEN);

        /* Send the MESH_PROXY_ADD_REQ message to UMAC FW */
        ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
    }
}

int ecrnx_send_tdls_peer_traffic_ind_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif)
{
    struct tdls_peer_traffic_ind_req *tdls_peer_traffic_ind_req;

    if (!ecrnx_vif->sta.tdls_sta)
        return -ENOLINK;

    /* Build the TDLS_PEER_TRAFFIC_IND_REQ message */
    tdls_peer_traffic_ind_req = ecrnx_msg_zalloc(TDLS_PEER_TRAFFIC_IND_REQ, TASK_TDLS, DRV_TASK_ID,
                                           sizeof(struct tdls_peer_traffic_ind_req));

    if (!tdls_peer_traffic_ind_req)
        return -ENOMEM;

    /* Set parameters for the TDLS_PEER_TRAFFIC_IND_REQ message */
    tdls_peer_traffic_ind_req->vif_index = ecrnx_vif->vif_index;
    tdls_peer_traffic_ind_req->sta_idx = ecrnx_vif->sta.tdls_sta->sta_idx;
    memcpy(&(tdls_peer_traffic_ind_req->peer_mac_addr.array[0]),
           ecrnx_vif->sta.tdls_sta->mac_addr, ETH_ALEN);
    tdls_peer_traffic_ind_req->dialog_token = 0; // check dialog token value
    tdls_peer_traffic_ind_req->last_tid = ecrnx_vif->sta.tdls_sta->tdls.last_tid;
    tdls_peer_traffic_ind_req->last_sn = ecrnx_vif->sta.tdls_sta->tdls.last_sn;

    /* Send the TDLS_PEER_TRAFFIC_IND_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, tdls_peer_traffic_ind_req, 0, 0, NULL);
}

int ecrnx_send_config_monitor_req(struct ecrnx_hw *ecrnx_hw,
                                 struct cfg80211_chan_def *chandef,
                                 struct me_config_monitor_cfm *cfm)
{
    struct me_config_monitor_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the ME_CONFIG_MONITOR_REQ message */
    req = ecrnx_msg_zalloc(ME_CONFIG_MONITOR_REQ, TASK_ME, DRV_TASK_ID,
                                   sizeof(struct me_config_monitor_req));
    if (!req)
        return -ENOMEM;

    if (chandef) {
        req->chan_set = true;
        cfg80211_to_ecrnx_chan(chandef, &req->chan);

        if (ecrnx_hw->phy.limit_bw)
            limit_chan_bw(&req->chan.type, req->chan.prim20_freq, &req->chan.center1_freq);
    } else {
         req->chan_set = false;
    }

    req->uf = ecrnx_hw->mod_params->uf;

    /* Send the ME_CONFIG_MONITOR_REQ message to FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, ME_CONFIG_MONITOR_CFM, cfm);
}
#endif /* CONFIG_ECRNX_FULLMAC */

#ifdef CONFIG_ECRNX_P2P
int ecrnx_send_p2p_start_listen_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif, unsigned int duration)
{
	struct p2p_listen_start_req *req;
	struct ecrnx_p2p_listen *p2p_listen = &ecrnx_hw->p2p_listen;
	int rc;
	
	ecrnx_printk_p2p(ECRNX_FN_ENTRY_STR);

	if(p2p_listen->listen_started)
	{
		ecrnx_printk_err("P2P listen already ongoing\n");
		return -EBUSY;
	}

	p2p_listen->ecrnx_vif = ecrnx_vif;
	p2p_listen->listen_duration = duration;
	
	if(ecrnx_hw->scan_request)
	{
		ecrnx_printk_err("Delaying p2p listen until scan done\n");
		return 0;
	}
	
	/* Build the P2P_LISTEN_START_REQ message */
    req = ecrnx_msg_zalloc(P2P_LISTEN_START_REQ, TASK_P2P_LISTEN, DRV_TASK_ID,
    							sizeof(struct p2p_listen_start_req));
    if (!req)
        return -ENOMEM;

    req->vif_idx = ecrnx_vif->vif_index;

    rc = ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
    if(rc)
 	return rc;

    p2p_listen->listen_started = 1;

    return rc;
}

int ecrnx_send_p2p_cancel_listen_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif)
{
    struct p2p_cancel_listen_req *req;
    struct ecrnx_p2p_listen *p2p_listen = &ecrnx_hw->p2p_listen;
	
    ecrnx_printk_p2p(ECRNX_FN_ENTRY_STR);

	/* Build the P2P_CANCEL_LISTEN_REQ message */
    req = ecrnx_msg_zalloc(P2P_CANCEL_LISTEN_REQ, TASK_P2P_LISTEN, DRV_TASK_ID,
    							sizeof(struct p2p_cancel_listen_req));
    if (!req)
        return -ENOMEM;

    req->vif_idx = ecrnx_vif->vif_index;
    p2p_listen->listen_started = 0;
    //return rwnx_send_msg(rwnx_hw, req, 1, P2P_CANCEL_LISTEN_CFM, NULL);
    ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);

    return 0;

}
#endif

int ecrnx_send_tdls_chan_switch_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_vif *ecrnx_vif,
                                   struct ecrnx_sta *ecrnx_sta, bool sta_initiator,
                                   u8 oper_class, struct cfg80211_chan_def *chandef,
                                   struct tdls_chan_switch_cfm *cfm)
{
    struct tdls_chan_switch_req *tdls_chan_switch_req;

    /* Build the TDLS_CHAN_SWITCH_REQ message */
    tdls_chan_switch_req = ecrnx_msg_zalloc(TDLS_CHAN_SWITCH_REQ, TASK_TDLS, DRV_TASK_ID,
                                           sizeof(struct tdls_chan_switch_req));

    if (!tdls_chan_switch_req)
        return -ENOMEM;

    /* Set parameters for the TDLS_CHAN_SWITCH_REQ message */
    tdls_chan_switch_req->vif_index = ecrnx_vif->vif_index;
    tdls_chan_switch_req->sta_idx = ecrnx_sta->sta_idx;
    memcpy(&(tdls_chan_switch_req->peer_mac_addr.array[0]),
           ecrnx_sta_addr(ecrnx_sta), ETH_ALEN);
    tdls_chan_switch_req->initiator = sta_initiator;
    cfg80211_to_ecrnx_chan(chandef, &tdls_chan_switch_req->chan);
    tdls_chan_switch_req->op_class = oper_class;

    /* Send the TDLS_CHAN_SWITCH_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, tdls_chan_switch_req, 1, TDLS_CHAN_SWITCH_CFM, cfm);
}

int ecrnx_send_tdls_cancel_chan_switch_req(struct ecrnx_hw *ecrnx_hw,
                                          struct ecrnx_vif *ecrnx_vif,
                                          struct ecrnx_sta *ecrnx_sta,
                                          struct tdls_cancel_chan_switch_cfm *cfm)
{
    struct tdls_cancel_chan_switch_req *tdls_cancel_chan_switch_req;

    /* Build the TDLS_CHAN_SWITCH_REQ message */
    tdls_cancel_chan_switch_req = ecrnx_msg_zalloc(TDLS_CANCEL_CHAN_SWITCH_REQ, TASK_TDLS, DRV_TASK_ID,
                                           sizeof(struct tdls_cancel_chan_switch_req));
    if (!tdls_cancel_chan_switch_req)
        return -ENOMEM;

    /* Set parameters for the TDLS_CHAN_SWITCH_REQ message */
    tdls_cancel_chan_switch_req->vif_index = ecrnx_vif->vif_index;
    tdls_cancel_chan_switch_req->sta_idx = ecrnx_sta->sta_idx;
    memcpy(&(tdls_cancel_chan_switch_req->peer_mac_addr.array[0]),
           ecrnx_sta_addr(ecrnx_sta), ETH_ALEN);

    /* Send the TDLS_CHAN_SWITCH_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, tdls_cancel_chan_switch_req, 1, TDLS_CANCEL_CHAN_SWITCH_CFM, cfm);
}

#ifdef CONFIG_ECRNX_BFMER
void ecrnx_send_bfmer_enable(struct ecrnx_hw *ecrnx_hw, struct ecrnx_sta *ecrnx_sta,
                            const struct ieee80211_vht_cap *vht_cap)
{
    struct mm_bfmer_enable_req *bfmer_en_req;
    __le32 vht_capability;
    u8 rx_nss = 0;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);
    if (!vht_cap) {
        goto end;
    }

    vht_capability = vht_cap->vht_cap_info;
    if (!(vht_capability & IEEE80211_VHT_CAP_SU_BEAMFORMEE_CAPABLE)) {
        goto end;
    }

    rx_nss = ecrnx_bfmer_get_rx_nss(vht_cap);

    /* Allocate a structure that will contain the beamforming report */
    if (ecrnx_bfmer_report_add(ecrnx_hw, ecrnx_sta, ECRNX_BFMER_REPORT_SPACE_SIZE))
    {
        goto end;
    }

    /* Build the MM_BFMER_ENABLE_REQ message */
    bfmer_en_req = ecrnx_msg_zalloc(MM_BFMER_ENABLE_REQ, TASK_MM, DRV_TASK_ID,
                                   sizeof(struct mm_bfmer_enable_req));

    /* Check message allocation */
    if (!bfmer_en_req) {
        /* Free memory allocated for the report */
        ecrnx_bfmer_report_del(ecrnx_hw, ecrnx_sta);

        /* Do not use beamforming */
        goto end;
    }

    /* Provide DMA address to the MAC */
    bfmer_en_req->host_bfr_addr = ecrnx_sta->bfm_report->dma_addr;
    bfmer_en_req->host_bfr_size = ECRNX_BFMER_REPORT_SPACE_SIZE;
    bfmer_en_req->sta_idx = ecrnx_sta->sta_idx;
    bfmer_en_req->aid = ecrnx_sta->aid;
    bfmer_en_req->rx_nss = rx_nss

    if (vht_capability & IEEE80211_VHT_CAP_MU_BEAMFORMEE_CAPABLE) {
        bfmer_en_req->vht_mu_bfmee = true;
    } else {
        bfmer_en_req->vht_mu_bfmee = false;
    }

    /* Send the MM_BFMER_EN_REQ message to LMAC FW */
    ecrnx_send_msg(ecrnx_hw, bfmer_en_req, 0, 0, NULL);

end:
    return;
}

#ifdef CONFIG_ECRNX_MUMIMO_TX
int ecrnx_send_mu_group_update_req(struct ecrnx_hw *ecrnx_hw, struct ecrnx_sta *ecrnx_sta)
{
    struct mm_mu_group_update_req *req;
    int group_id, i = 0;
    u64 map;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_MU_GROUP_UPDATE_REQ message */
    req = ecrnx_msg_zalloc(MM_MU_GROUP_UPDATE_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_mu_group_update_req) +
                          ecrnx_sta->group_info.cnt * sizeof(req->groups[0]));

    /* Check message allocation */
    if (!req)
        return -ENOMEM;

    /* Go through the groups the STA belongs to */
    group_sta_for_each(ecrnx_sta, group_id, map) {
        int user_pos = ecrnx_mu_group_sta_get_pos(ecrnx_hw, ecrnx_sta, group_id);

        if (WARN((i >= ecrnx_sta->group_info.cnt),
                 "STA%d: Too much group (%d)\n",
                 ecrnx_sta->sta_idx, i + 1))
            break;

        req->groups[i].group_id = group_id;
        req->groups[i].user_pos = user_pos;

        i++;
    }

    req->group_cnt = ecrnx_sta->group_info.cnt;
    req->sta_idx = ecrnx_sta->sta_idx;

    /* Send the MM_MU_GROUP_UPDATE_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, MM_MU_GROUP_UPDATE_CFM, NULL);
}
#endif /* CONFIG_ECRNX_MUMIMO_TX */
#endif /* CONFIG_ECRNX_BFMER */

/**********************************************************************
 *    Debug Messages
 *********************************************************************/
int ecrnx_send_dbg_trigger_req(struct ecrnx_hw *ecrnx_hw, char *msg)
{
    struct mm_dbg_trigger_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_DBG_TRIGGER_REQ message */
    req = ecrnx_msg_zalloc(MM_DBG_TRIGGER_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_dbg_trigger_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_DBG_TRIGGER_REQ message */
    strncpy(req->error, msg, sizeof(req->error));

    /* Send the MM_DBG_TRIGGER_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 0, -1, NULL);
}

int ecrnx_send_dbg_mem_read_req(struct ecrnx_hw *ecrnx_hw, u32 mem_addr,
                               struct dbg_mem_read_cfm *cfm)
{
    struct dbg_mem_read_req *mem_read_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the DBG_MEM_READ_REQ message */
    mem_read_req = ecrnx_msg_zalloc(DBG_MEM_READ_REQ, TASK_DBG, DRV_TASK_ID,
                                   sizeof(struct dbg_mem_read_req));
    if (!mem_read_req)
        return -ENOMEM;

    /* Set parameters for the DBG_MEM_READ_REQ message */
    mem_read_req->memaddr = mem_addr;

    /* Send the DBG_MEM_READ_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, mem_read_req, 1, DBG_MEM_READ_CFM, cfm);
}

int ecrnx_send_dbg_mem_write_req(struct ecrnx_hw *ecrnx_hw, u32 mem_addr,
                                u32 mem_data)
{
    struct dbg_mem_write_req *mem_write_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the DBG_MEM_WRITE_REQ message */
    mem_write_req = ecrnx_msg_zalloc(DBG_MEM_WRITE_REQ, TASK_DBG, DRV_TASK_ID,
                                    sizeof(struct dbg_mem_write_req));
    if (!mem_write_req)
        return -ENOMEM;

    /* Set parameters for the DBG_MEM_WRITE_REQ message */
    mem_write_req->memaddr = mem_addr;
    mem_write_req->memdata = mem_data;

    /* Send the DBG_MEM_WRITE_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, mem_write_req, 1, DBG_MEM_WRITE_CFM, NULL);
}

int ecrnx_send_dbg_set_mod_filter_req(struct ecrnx_hw *ecrnx_hw, u32 filter)
{
    struct dbg_set_mod_filter_req *set_mod_filter_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the DBG_SET_MOD_FILTER_REQ message */
    set_mod_filter_req =
        ecrnx_msg_zalloc(DBG_SET_MOD_FILTER_REQ, TASK_DBG, DRV_TASK_ID,
                        sizeof(struct dbg_set_mod_filter_req));
    if (!set_mod_filter_req)
        return -ENOMEM;

    /* Set parameters for the DBG_SET_MOD_FILTER_REQ message */
    set_mod_filter_req->mod_filter = filter;

    /* Send the DBG_SET_MOD_FILTER_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, set_mod_filter_req, 1, DBG_SET_MOD_FILTER_CFM, NULL);
}

int ecrnx_send_dbg_set_sev_filter_req(struct ecrnx_hw *ecrnx_hw, u32 filter)
{
    struct dbg_set_sev_filter_req *set_sev_filter_req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the DBG_SET_SEV_FILTER_REQ message */
    set_sev_filter_req =
        ecrnx_msg_zalloc(DBG_SET_SEV_FILTER_REQ, TASK_DBG, DRV_TASK_ID,
                        sizeof(struct dbg_set_sev_filter_req));
    if (!set_sev_filter_req)
        return -ENOMEM;

    /* Set parameters for the DBG_SET_SEV_FILTER_REQ message */
    set_sev_filter_req->sev_filter = filter;

    /* Send the DBG_SET_SEV_FILTER_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, set_sev_filter_req, 1, DBG_SET_SEV_FILTER_CFM, NULL);
}

int ecrnx_send_dbg_get_sys_stat_req(struct ecrnx_hw *ecrnx_hw,
                                   struct dbg_get_sys_stat_cfm *cfm)
{
    void *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Allocate the message */
    req = ecrnx_msg_zalloc(DBG_GET_SYS_STAT_REQ, TASK_DBG, DRV_TASK_ID, 0);
    if (!req)
        return -ENOMEM;

    /* Send the DBG_MEM_READ_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 1, DBG_GET_SYS_STAT_CFM, cfm);
}

int ecrnx_send_cfg_rssi_req(struct ecrnx_hw *ecrnx_hw, u8 vif_index, int rssi_thold, u32 rssi_hyst)
{
    struct mm_cfg_rssi_req *req;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_CFG_RSSI_REQ message */
    req = ecrnx_msg_zalloc(MM_CFG_RSSI_REQ, TASK_MM, DRV_TASK_ID,
                          sizeof(struct mm_cfg_rssi_req));
    if (!req)
        return -ENOMEM;

    /* Set parameters for the MM_CFG_RSSI_REQ message */
    req->vif_index = vif_index;
    req->rssi_thold = (s8)rssi_thold;
    req->rssi_hyst = (u8)rssi_hyst;

    /* Send the MM_CFG_RSSI_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, req, 0, 0, NULL);
}

extern bool set_gain;
int ecrnx_send_set_gain_delta_req(struct ecrnx_hw *ecrnx_hw)
{
	s8_l *delta;

    if (set_gain != true)
        return -ENOMEM;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);

    /* Build the MM_SET_GAIN_DELTA_REQ message */
    delta = ecrnx_msg_zalloc(MM_SET_GAIN_DELTA_REQ, TASK_MM, DRV_TASK_ID,
                          GAIN_DELTA_CFG_BUF_SIZE);
    if (!delta)
        return -ENOMEM;

    /* Set parameters for the MM_SET_GAIN_DELTA_REQ message */
    memset(delta, 0, GAIN_DELTA_CFG_BUF_SIZE);
    memcpy(delta, gain_delta, GAIN_DELTA_CFG_BUF_SIZE);

    /* Send the MM_SET_GAIN_DELTA_REQ message to LMAC FW */
    return ecrnx_send_msg(ecrnx_hw, delta, 0, MM_SET_GAIN_DELTA_CFM, NULL);
}

int ecrnx_send_cal_result_get_req(struct ecrnx_hw *ecrnx_hw, void *cfm)
{
    void *void_param;

	ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);
    /* calibration result get REQ has no parameter */
    void_param = ecrnx_msg_zalloc(MM_GET_CAL_RESULT_REQ, TASK_MM, DRV_TASK_ID, 0);
    if (!void_param)
        return -ENOMEM;

    return ecrnx_send_msg(ecrnx_hw, void_param, 1, MM_GET_CAL_RESULT_CFM, cfm);
}

int ecrnx_send_set_macaddr_req(struct ecrnx_hw *ecrnx_hw, u8_l *addr)
{
    struct mm_set_macddr_req *param;

    ecrnx_printk_msg(ECRNX_FN_ENTRY_STR);
    /* calibration result get REQ has no parameter */
    param = ecrnx_msg_zalloc(MM_SET_MACADRR_REQ, TASK_MM, DRV_TASK_ID, sizeof(struct mm_set_macddr_req));
    if (!param)
        return -ENOMEM;

    memcpy(param->addr.array, addr, MAC_ADDR_LEN);

    return ecrnx_send_msg(ecrnx_hw, param, 1, MM_SET_MACADRR_CFM, NULL);
}



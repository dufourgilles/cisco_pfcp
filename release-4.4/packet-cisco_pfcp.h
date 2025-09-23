
#ifndef _PACKET_CISCO_PFCP_H_
#define _PACKET_CISCO_PFCP_H_

typedef struct pfcp_session_args {
    wmem_list_t *seid_list;
    wmem_list_t *ip_list;
    guint64 last_seid;
    address last_ip;
    guint8 last_cause;
} pfcp_session_args_t;

static int ett_pfcp = -1;
static expert_field ei_pfcp_ie_data_not_decoded = EI_INIT;

#define PFCP_GET_VERSION(msg)                   ((msg & 0xE0) >> 5)
#define PFCP_GET_SEID_FLAG(msg)                 (msg & 0x01)
#define PFCP_GET_MP_FLAG(msg)                   ((msg & 0x02) >> 1)
#define PFCP_VERSION                            0x1
#define PFCP_GET_MSG_PRIO(msg)                  (msg >> 4)
#define PFCP_GET_INTERFACE_TYPE(msg)            (msg & 0x07)
#define PFCP_GET_COMPRESSION_ENABLED(msg)       ((msg & 0x08) >> 3)


#endif
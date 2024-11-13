

#ifndef _PACKET_PFCP_TLV_CONTENT_H_
#define _PACKET_PFCP_TLV_CONTENT_H_

typedef enum {
  PFD_SX_RULE_DEF = 1,
  PFD_SX_RB_ACTION_PRIORITY,
  PFD_SX_CHARGING_ACTION,
  PFD_SX_GROUP_OF_RULEDEFS,
  PFD_SX_RDEF_IN_GOR,
  PFD_SX_QOS_GROUP_OF_RULEDEFS,
  PFD_SX_RDEF_IN_QOS_GOR,
  PFD_SX_SERVICE_CHAIN,
  PFD_SX_NSH_FORMAT,
  PFD_SX_NSH_FIELD,
  PFD_SX_TRAFFIC_STEER_APP,
  PFD_SX_RB_L3_L4_L7_INFO,
  PFD_SX_ACS_LEVEL_INFO,
  PFD_SX_RB_RULE_N_ROUTE,
  PFD_SX_APN_INFO,
  PFD_SX_EDR_FORMAT,
  PFD_SX_LI_CONFIG,
  PFD_SX_DCCA_CONFIG,
  PFD_SX_RB_PP_RULE_N_ACTION,
  PFD_SX_PLUGIN_VERSION,
  PFD_SX_PKT_FILTER,
  PFD_SX_CA_PKTF,
  PFD_SX_TRIGGER_ACTION,
  PFD_SX_TRIGGER_CONDITION,
  PFD_SX_SUBSCRIBER_CLASS,
  PFD_SX_SERVICE_SCHEME,
  PFD_SX_SERVICE_SCHEME_TRIGGER,
  PFD_SX_SERVICE_SCHEME_TRIGGER_ACTION_N_CONDITION,
  PFD_SX_SUBSCRIBER_BASE,
  PFD_SX_SUBSCRIBER_BASE_EVENT_LINE,
  PFD_SX_P2P_ADS_GROUP,
  PFD_SX_BANDWIDTH_POLICY,
  PFD_SX_BANDWIDTH_POLICY_ID,
  PFD_SX_BANDWIDTH_POLICY_GROUP_LIMIT,
  PFD_SX_CC_PROFILE,
  PFD_SX_GTPP_GROUP,
  PFD_SX_AAA_GROUP,
  PFD_SX_XHEADER,
  PFD_SX_CF_POLICY,
  PFD_SX_CRP_IN_CF_POLICY,
  PFD_SX_SFW_GLOBAL_POLICY,
  PFD_SX_SFW_NAT_POLICY,
  PFD_SX_SFW_NAT_POLICY_RULE_N_ACTION,
  PFD_SX_TIMEDEF,
  PFD_SX_GRP_OF_PREFIXED_URLS,
  PFD_SX_RB_URL_PREPROCESSING,
  PFD_SX_ACL_INFO,
  PFD_SX_ACS_LEVEL_NAT_INFO,
  PFD_SX_TRAFFIC_OPTIMIZATION_PROFILE,
  PFD_SX_TRAFFIC_OPTIMIZATION_POLICY,
  PFD_SX_MON_KEY_URR_ID_INFO,
  PFD_SX_URL_SNI_POOL,
  PFD_SX_TRAFFIC_OPTIMIZATION_POLICY_2123,
  PFD_SX_DCCA_CONFIG_TAC,
  PFD_SX_CHARGING_ACTION_2124, /* 55 */
  PFD_SX_SERVER_LIST,
  PFD_SX_IP_ADDR_IN_SERVER_LIST,
  PFD_SX_APN_INFO_COMP,
  PFD_SX_DCCA_CONFIG_2124,
  /*config end should be last config push type*/
  PFD_SX_CONFIG_END = 60,
  PFD_SX_TRIGGER_ACTION_2125,
  PFD_SX_TRIGGER_CONDITION_2125,
  PFD_SX_EDNS_FIELDS,
  PFD_SX_EDNS_HEADER,
  PFD_SX_EDNS_SPROFILE,
  PFD_SX_CHARGING_ACTION_2125,
  PFD_SX_TRAFFIC_OPTIMIZATION_PROFILE_2125, /* Keeping thi above profile wrt changes done for CSCvz76372 N+-3 */
  PFD_SX_TRAFFIC_OPTIMIZATION_POLICY_2026,
  PFD_SX_ACS_LEVEL_INFO_NEW,
  PFD_SX_GTPP_GROUP_2123 = 70,
  PFD_SX_LI_CONFIG_2126,
  PFD_SX_GTPP_GROUP_2122 = 72,
  PFD_SX_GTPP_GROUP_2127,
  PFD_SX_GTPP_GROUP_2120 = 74,
  PFD_SX_HOSTPOOL,
  PFD_SX_PORTMAP,
  PFD_SX_IMSIPOOL,
  /*Keep all the newly introduced TAGS above this*/
  PFD_SX_TLV_MAX = 80, //If exhausted, increase this in multiple of 8.
  PFD_SX_DONE = 240,
  PFD_SX_NODE_REPORT = 250,
  PFD_REDUNDANCY_INFO_SX_ASSOCIATION_UPDATE = 251,
  PFD_SX_ASSOCIATION_SETUP = 252,
  PFD_SX_ASSOCIATION_UPDATE = 253,
  PFD_SX_ASSOCIATION_RELEASE = 254,
  PFD_SX_INVALID = 255
} pfcp_trans_node_type_t;

#define MAX_CSS_SERVICE_NAME_SIZE 16
#define ACSCTRL_RULE_NAMELEN 64
#define ACS_P2P_CDP_NAME_MAX_LEN 20
#define ACS_MAX_RULELINES_PER_RDEF 32
#define ACSCTRL_RULE_DESCLEN 64
#define ACS_MAX_XHEADER_NAME_LEN 32
#define ACS_MAX_STRING_LEN 128


typedef enum {
  IPPOOL_INFO_TYPE =1,
  IPPOOL_OPERATION_TYPE =2,
  IPPOOL_CHUNK_V4_TYPE =3,
  IPPOOL_CHUNK_V6_TYPE =4,
  IPPOOL_POOL_ID_TYPE = 5,
  IPPOOL_CONTEXT_NAME_TYPE =6,
  IPPOOL_CHUNK_SIZE = 7,
  IPPOOL_VRF_ID_TYPE = 8,
  IPPOOL_VRF_NAME_TYPE = 9,
  IPPOOL_INVALID_TYPE
} ippool_mgmt_ie_type_t;


typedef struct sn_ip_addr_ {
    uint8_t         ip_ver;
    union {
        uint32_t    ipv4;
        uint32_t    ipv6[4];
    } sn_ip_addr_t_u;
} sn_ip_addr_t;

typedef int bool_t;

struct acs_sct_rule_line {
        bool_t valid;
        bool_t case_sens;
        bool_t group_of_objects_present;
        guint proto;
        guint field;
        guint field2;
        guint field3;
        guint rule_type;
        guint oper;
        guint int_val;
        guint int_val2;
        guint group_of_objects_id;
        int hex_signature_len;
        sn_ip_addr_t ip_addr;
        sn_ip_addr_t ip_addr2;
        sn_ip_addr_t ip_mask;
        char xheader_name[ACS_MAX_XHEADER_NAME_LEN];
        char disp_str[ACS_MAX_STRING_LEN];
        char lowercase_str[ACS_MAX_STRING_LEN];
        guint str_len;
};
typedef struct acs_sct_rule_line acs_sct_rule_line;
typedef acs_sct_rule_line acs_sct_rule_line_t;

struct mgmt_acsctrl_config_cc_group_default_group
{
  bool_t valid;
  bool_t value;
};

typedef struct mgmt_acsctrl_config_cc_group_default_group MGMTACTRConfigDefCCGroup;
extern int ett_pfcp_cisco_content_tlv;

void
dissect_pfcp_cisco_content_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_);
#endif

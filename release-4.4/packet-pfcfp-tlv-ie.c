#include "packet-pfcfp-tlv-ie.h"

// enum IPPoolOperationType
static const value_string pfcfp_ip_pool_op_type[] =  {
    {0, ""},
    {1, "IP_POOL_ADD"},
    {2, "IP_POOL_REMOVE"},
    {3, "IP_POOL_UP_DEREG_BEGIN" },
    {4, "IP_POOL_UP_DEREG_END" },
    {5, "IP_POOL_ADD_TRANSIENT"},
    {6, "IP_POOL_REMOVE_TRANSIENT"},
    {7, "IP_POOL_AUDIT"},
    {8, "IP_POOL_CLEAN_UP_LOCAL_VPN_DB"},
    {9, "IP_POOL_RCM_UP_FLUSH_COMPLETE"},
};

/*
packages/boxer/sess/sx/sxmgr/include/sxmgr_main.h
    252   PFD_SX_RULE_DEF = 1,
    253   PFD_SX_RB_ACTION_PRIORITY,
    254   PFD_SX_CHARGING_ACTION,
    255   PFD_SX_GROUP_OF_RULEDEFS,

    ... PFD_SX_ASSOCIATION_UPDATE 253
  */
static const value_string pfcp_content_tlv_vals[] = {
    {0, ""},
    {1, "RULE_DEF"},
    {2, "RB_ACTION_PRIORITY"},
    {3, "CHARGING_ACTION"},
    {4, "GROUP_OF_RULEDEFS"},
    {5, "RDEF_IN_GOR"},
    {6, "QOS_GROUP_OF_RULEDEFS"},
    {7, "RDEF_IN_QOS_GOR"},
    {8, "SERVICE_CHAIN"},
    {9, "NSH_FORMAT"},
    {10, "NSH_FIELD}"},
    {11, "TRAFFIC_STEER_APP"},
    {12, "RB_L3_L4_L7_INFO"},
    {13, "ACS_LEVEL_INFO"},
    {14, "RB_RULE_N_ROUTE"},
    {15, "APN_INFO"},
    {16, "EDR_FORMAT"},
    {17, "LI_CONFIG"},
    {18, "CREDIT_CONTROL_GROUP"},
    {19, "RB_PP_RULE_N_ACTION"},
    {20, "PLUGIN_VER"},
    {21, "PKT_FILTER"},
    {22, "CA PKTF"},
    {23, "TRIGGER ACTION"},
    {24, "TRIGGER CONDITION"},
    {25, "SUBSCRIBER CLASS"},
    {26, "SERVICE SCHEME"},
    {27, "SERVICE SCHEME TRIGGER"},
    {28, "SERVICE SCHEME TRIGGER CONDITION AND ACTION"},
    {29, "SUBSCRIBER BASE"},
    {30, "SUBSCRIBER BASE SCLASS AND SCHEME"},
    {31, "P2P_ADS_GROUP"},
    {32, "BANDWIDTH POLICY"},
    {33, "BANDWIDTH POLICY ID"},
    {34, "BANDWIDTH POLICY GROUP LIMIT"},
    {35, "ACCOUNTING POLICY"},
    {36, "GTPP GROUP"},
    {37, "AAA GROUP"},
    {38, "XHEADER"},
    {39, "CF_POLICY"},
    {40, "CRP_IN_CF_POLICY"},
    {41, "NAT_GLOBAL_CONFIG"},
    {42, "NAT_POLICY"},
    {43, "NAT_POLICY_RULE_N_ACTION"},
    {44, "TIMEDEF"},
    {45, "GROUP_OF_PREFIXED_URLS"},
    {46, "RB_URL_PREPROCESSING"},
    {47, "ACL_INFO"},
    {48, "ACS_LEVEL_NAT_INFO"},
    {49, "TRAFFIC OPTIMIZATION PROFILE"},
    {50, "TRAFFIC OPTIMIZATION POLICY"},
    {51, "MON_KEY_URR_ID_PREFIX"},
    {52, "URL_SNI_POOL"},
    {53, "TRAFFIC OPTIMIZATION POLICY_2123"},
    {54, "CREDIT_CONTROL_GROUP_TAC"},
    {56, "SERVER_LIST"},
    {57, "SERVER_LIST_IPADDR"},
    {58, "APN_INFO_COMP"},
    {59, "DCCA_CONFIG_2124"},
    {60, "PFD CONFIG END"},
    {61, "TRIGGER_ACTION_2125"},
    {62, "PFD_SX_EDNS_FIELDS"},
    {63, "PFD_SX_EDNS_HEADER"},
    {64, "PFD_SX_EDNS_SPROFILE"},
    {70, "PFD_SX_GTPP_GROUP_2123"},
    {72, "PFD TLV MAX"},
    {240, "DONE"},
    {251, "REDUNDANCY_INFO"},
    {253, "IP_POOL_INFO"},
    {255, "INVALID"},
};

static dissector_handle_t cisco_pfcp_tlv_handle;

// subtree
int ett_pfcp_cisco_content_tlv = -1;
static int hf_pfcp_cisco_tlv_content_type = -1;
static int hf_pfcp_cisco_tlv_content_action = -1;
static int hf_pfcp_cisco_tlv_content_numtlv = -1;
static int hf_pfcp_cisco_tlv_content_len = -1;
static int hf_pfcp_cisco_tlv_content_data = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_service = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_name = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_id = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_description = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_type = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_tethering = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_urlpool = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_p2p_id = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_p2p_name = -1;
static int hf_pfcp_cisco_tlv_content_ruledef_num_rules = -1;
static int hf_pfcp_cisco_tlv_content_compress_len = -1;
static int hf_pfcp_cisco_tlv_content_ruleline_valid = -1;
static int hf_pfcp_cisco_tlv_content_ruleline_proto = -1;
static int hf_pfcp_cisco_tlv_content_ruleline_ipv4 = -1;
static int hf_pfcp_cisco_tlv_content_ruleline_xheader = -1;
static int hf_pfcp_cisco_tlv_content_ruleline_disp = -1;
static int hf_pfcp_cisco_tlv_content_ruleline_lowercase = -1;
static int hf_pfcp_cisco_tlv_content_ippool_type = -1;
static int hf_pfcp_cisco_tlv_content_ippool_ctxt_name = -1;
static int hf_pfcp_cisco_tlv_content_ippool_idtype = -1;
static int hf_pfcp_cisco_tlv_content_ippool_id = -1;
static int hf_pfcp_cisco_tlv_content_ippool_vrf_name = -1;
static int hf_pfcp_cisco_tlv_content_ippool_chunk_size = -1;
static int hf_pfcp_cisco_tlv_content_ippool_optype = -1; 
static int hf_pfcp_cisco_tlv_content_ippool_chunk_id = -1;
static int hf_pfcp_cisco_tlv_content_ippool_chunk_ipv4 = -1;
static int hf_pfcp_cisco_tlv_content_ippool_chunk_ipv6 = -1;

static void dissect_pfcp_tlv_ruledef(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length);
static void dissect_pfcp_content_rule(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length, proto_item *rule_item);
static void dissect_pfcp_content_rule_line(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length);
static void dissect_pfcp_content_ip_pool(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length);


#define include_cisco_tlv_hf()                                                      \
        {&hf_pfcp_cisco_tlv_content_type,                                           \
            {"Content Type", "cisco_pfcp.cisco.contenttlv.type",                    \
            FT_UINT8, BASE_DEC, VALS(pfcp_content_tlv_vals), 0x0,                   \
            NULL, HFILL}},                                                          \
        {&hf_pfcp_cisco_tlv_content_action,                                         \
         {"Content Action", "cisco_pfcp.cisco.contenttlv.action",                   \
          FT_UINT8, BASE_DEC, NULL, 0x0,                                            \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_numtlv,                                         \
         {"Content Num TLV", "cisco_pfcp.cisco.contenttlv.numtlv",                  \
          FT_UINT8, BASE_DEC, NULL, 0x0,                                            \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_len,                                            \
         {"ContentTLV Length", "cisco_pfcp.cisco.contenttlv.tlv_len",               \
          FT_UINT16, BASE_DEC, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_data,                                           \
         {"ContentTLV Data", "cisco_pfcp.cisco.contenttlv.data",                    \
          FT_BYTES, BASE_NONE, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_service,                                \
         {"Ruledef Service", "cisco_pfcp.cisco.contenttlv.ruledef.service",         \
          FT_STRING, BASE_NONE, NULL, 0x0,                                          \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_name,                                   \
         {"Ruledef Name", "cisco_pfcp.cisco.contenttlv.ruledef.name",               \
          FT_STRING, BASE_NONE, NULL, 0x0,                                          \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_id,                                     \
         {"Ruledef ID", "cisco_pfcp.cisco.contenttlv.ruledef.id",                   \
          FT_UINT32, BASE_DEC, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_description,                            \
         {"Ruledef Description", "cisco_pfcp.cisco.contenttlv.ruledef.description", \
          FT_STRING, BASE_NONE, NULL, 0x0,                                          \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_num_rules,                              \
         {"Ruledef Num Rules", "cisco_pfcp.cisco.contenttlv.ruledef.num_rules",     \
          FT_UINT8, BASE_DEC, NULL, 0x0,                                            \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_type,                                   \
         {"Ruledef Type", "cisco_pfcp.cisco.contenttlv.ruledef.type",               \
          FT_UINT16, BASE_HEX, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_tethering,                              \
         {"Ruledef Type", "cisco_pfcp.cisco.contenttlv.ruledef.tethering",          \
          FT_BYTES, BASE_NONE, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_urlpool,                                \
         {"Ruledef URL Pool", "cisco_pfcp.cisco.contenttlv.ruledef.urlpool",        \
          FT_STRING, BASE_NONE, NULL, 0x0,                                          \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_compress_len,                                   \
         {"Compress Length", "cisco_pfcp.cisco.contenttlv.comporess_len",           \
          FT_UINT16, BASE_DEC, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruledef_p2p_id,                                 \
         {"Ruledef P2P ID", "cisco_pfcp.cisco.contenttlv.ruledef.p2p.id",           \
          FT_UINT32, BASE_DEC, NULL, 0x0,                                           \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruleline_valid,                                 \
         {"Ruledef Rule Line Valid", "cisco_pfcp.cisco.contenttlv.ruleline.valid",  \
          FT_BOOLEAN, BASE_NONE, NULL, 0x0,                                         \
          NULL, HFILL}},                                                            \
        {&hf_pfcp_cisco_tlv_content_ruleline_proto,                                 \
         {"RuleLine Proto", "cisco_pfcp.cisco.contenttlv.ruleline.proto",           \
          FT_UINT8, BASE_DEC, NULL, 0x0,                                            \
          NULL, HFILL}},                                                            \
        { &hf_pfcp_cisco_tlv_content_ruleline_ipv4,                                 \
        { "RuleLine IP v4", "cisco_pfcp.cisco.contenttlv.ruleline.ipv4",            \
            FT_IPv4, BASE_NONE,  NULL, 0,                                           \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ruleline_xheader,                              \
        { "Rule XHeader", "cisco_pfcp.cisco.contenttlv.ruleline.xheader",           \
            FT_STRING, BASE_NONE,  NULL, 0,                                         \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ruleline_disp,                                 \
        { "Rule Disp", "cisco_pfcp.cisco.contenttlv.ruleline.disp",                 \
            FT_STRING, BASE_NONE,  NULL, 0,                                         \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ruleline_lowercase,                            \
        { "Rule Lower Case", "cisco_pfcp.cisco.contenttlv.ruleline.lowercase",      \
            FT_STRING, BASE_NONE,  NULL, 0,                                         \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_type,                                   \
        { "IP Pool Type", "cisco_pfcp.cisco.contenttlv.ippool.type",                \
            FT_UINT8, BASE_HEX,  NULL, 0,                                           \
            NULL, HFILL }                                                           \
        },                                                                          \
        {&hf_pfcp_cisco_tlv_content_ippool_optype,                                  \
        {"IP Pool OP Type", "cisco_pfcp.cisco.contenttlv.ippol.optype",             \
        FT_UINT8, BASE_DEC, VALS(pfcfp_ip_pool_op_type), 0x0,                       \
        NULL, HFILL}},                                                              \
        { &hf_pfcp_cisco_tlv_content_ippool_ctxt_name,                              \
        { "IP Pool Context", "cisco_pfcp.cisco.contenttlv.ipool.context",           \
            FT_STRING, BASE_NONE,  NULL, 0,                                         \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_idtype,                                 \
        { "IP Pool ID Type", "cisco_pfcp.cisco.contenttlv.ipool.idtype",            \
            FT_UINT8, BASE_HEX,  NULL, 0,                                           \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_id,                                     \
        { "IP Pool ID", "cisco_pfcp.cisco.contenttlv.ipool.id",                     \
            FT_UINT16, BASE_HEX,  NULL, 0,                                          \
            NULL, HFILL }                                                           \
        },                                                                          \
         { &hf_pfcp_cisco_tlv_content_ippool_vrf_name,                              \
        { "IP Pool VRF", "cisco_pfcp.cisco.contenttlv.ipool.vrfname",               \
            FT_STRING, BASE_NONE,  NULL, 0,                                         \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_chunk_size,                             \
        { "IP Pool Chunk size", "cisco_pfcp.cisco.contenttlv.ippool.chunk.size",    \
            FT_UINT32, BASE_DEC,  NULL, 0,                                          \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_chunk_id,                               \
        { "IP Pool Chunk ID", "cisco_pfcp.cisco.contenttlv.ippool.chunk.id",        \
            FT_UINT32, BASE_HEX,  NULL, 0,                                          \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_chunk_ipv4,                             \
        { "Chunk IPv4", "cisco_pfcp.cisco.contenttlv.ippool.chunk.ipv4",            \
            FT_IPv4, BASE_NONE, NULL, 0x0,                                          \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ippool_chunk_ipv6,                             \
        { "Chunk IPv6", "cisco_pfcp.cisco.contenttlv.ippool.chunk.ipv6",            \
            FT_IPv6, BASE_NONE, NULL, 0x0,                                          \
            NULL, HFILL }                                                           \
        },                                                                          \
        { &hf_pfcp_cisco_tlv_content_ruledef_p2p_name,                              \
        { "Ruledef P2P Name", "cisco_pfcp.cisco.contenttlv.ruledef.p2p.name",       \
            FT_STRING, BASE_NONE, NULL, 0x0,                                        \
            NULL, HFILL  }                                                           \
        }                                                                           

// packages/boxer/sess/sx/sxc/parser/pfcp_dec_ie.c

void
dissect_pfcp_cisco_content_tlv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *item _U_, guint16 length, guint8 message_type _U_, pfcp_session_args_t *args _U_)
{
    // todo dissect TLV
    guint32 type;
    guint32 tlv_len;

    gint offset = 0;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_cisco_tlv_content_type, tvb, offset, 1, ENC_BIG_ENDIAN, &type);
    offset++;
    proto_item_append_text(item, "%s", val_to_str_const(type, pfcp_content_tlv_vals, "Unknown"));

    proto_tree_add_item_ret_uint(tree, hf_pfcp_cisco_tlv_content_len, tvb, offset, 2, ENC_BIG_ENDIAN, &tlv_len);
    offset += 2;

    //   proto_tree_add_item_ret_uint(tree, hf_pfcp_cisco_tlv_content_action, tvb, offset, 1, ENC_BIG_ENDIAN, &action);
    //   offset++;

    switch (type)
    {
        case PFD_SX_RULE_DEF:
            dissect_pfcp_tlv_ruledef(tvb, pinfo, tree, offset, length);
            break;
        case PFD_SX_ASSOCIATION_UPDATE:
            dissect_pfcp_content_ip_pool(tvb, pinfo, tree, offset, length);
            break;
    }
    if (offset < length)
    {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

/*
    111 typedef struct actrl_send_rule_config sn_uplane_ruledef_t;


      13924 struct actrl_send_rule_config {
  13925         char service_name[MAX_CSS_SERVICE_NAME_SIZE];
  13926         char rule_name[ACSCTRL_RULE_NAMELEN];
  13927         guint ruledef_id;
  13928         acs_sct_rule_line_t rule_def[ACS_MAX_RULELINES_PER_RDEF];
  13929         char rdef_description[ACSCTRL_RULE_DESCLEN];
  13930         ACSRuleAppType rule_application;
  13931         ACSConfigTethering tethered_flow;
  13932         u_char is_ruledef_contains_urlpool;
  13933         u_char is_ruledef_contains_sni;
  13934         char attached_urlpool[ACSCTRL_RULE_NAMELEN];
  13935         ACSConfigBool dump_pkt_in_log;
  13936         acs_rule_oper_t rule_operator;
  13937         ACSSFWRuleEnableLogging sfw_rule_logging;
  13938         guint p2p_cdp_id;
  13939         char p2p_cdp_name[ACS_P2P_CDP_NAME_MAX_LEN];
  13940         bool_t config_changed;
  13941 };


*/

static void
dissect_pfcp_tlv_ruledef(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length)
{
    guint32 num_rules, iter = 0;
    guint16 compress_len = 0;
    tvbuff_t *next_tvb;
    proto_tree *rule_tree;
    proto_item *rule_item;

    proto_tree_add_item_ret_uint(tree, hf_pfcp_cisco_tlv_content_ruledef_num_rules, tvb, offset, 1, ENC_BIG_ENDIAN, &num_rules);
    offset++;

    while(iter < num_rules) {
        compress_len = tvb_get_ntohs(tvb, offset);
        rule_tree = proto_tree_add_subtree_format(tree, tvb, offset, compress_len, ett_pfcp_cisco_content_tlv, &rule_item, "Rule %u: ", iter);
        proto_tree_add_item(rule_tree, hf_pfcp_cisco_tlv_content_compress_len, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        next_tvb = tvb_uncompress_zlib(tvb, offset, compress_len);        
        if (next_tvb)
        {
            add_new_data_source(pinfo, next_tvb, "gunziped content tlv");            
            dissect_pfcp_content_rule(next_tvb, pinfo, rule_tree, 0, tvb_reported_length(next_tvb), rule_item);
        }
        offset += compress_len;
        iter++;
    }
     if (offset < length)
    {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}


static void
dissect_pfcp_content_rule(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length, proto_item *item)
{
        int i;
        proto_tree *rule_tree;
        proto_item *rule_item;
        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_service, tvb, offset, MAX_CSS_SERVICE_NAME_SIZE, ENC_BIG_ENDIAN);
        offset += MAX_CSS_SERVICE_NAME_SIZE;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_name, tvb, offset, ACSCTRL_RULE_NAMELEN, ENC_BIG_ENDIAN);
        proto_item_append_text(item, "%s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, ACSCTRL_RULE_NAMELEN, ENC_ASCII));
        offset += ACSCTRL_RULE_NAMELEN;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_id, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset += 4;

        // rule_def
        for (i = 0; i < ACS_MAX_RULELINES_PER_RDEF; i++)
        {
            rule_tree = proto_tree_add_subtree_format(tree, tvb, offset, 386, ett_pfcp_cisco_content_tlv, &rule_item, "Line %u: ", i);
            dissect_pfcp_content_rule_line(tvb, pinfo, rule_tree, offset, length);
            offset += sizeof(acs_sct_rule_line_t);
        }

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_description, tvb, offset, ACSCTRL_RULE_DESCLEN, ENC_BIG_ENDIAN);
        offset += ACSCTRL_RULE_DESCLEN;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_tethering, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 7;

        // skip 2 is_ruledef_contains_urlpool + is_ruledef_contains_sni
        offset += 2;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_urlpool, tvb, offset, ACSCTRL_RULE_NAMELEN, ENC_BIG_ENDIAN);
        offset += ACSCTRL_RULE_NAMELEN;

        // skip 2 ACSConfigBool dump_pkt_in_log
        offset += 2;

        // skip 2 acs_rule_oper_t
        offset += 2;

        // skip 2 ACSSFWRuleEnableLogging
        offset += 2;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_p2p_id, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruledef_p2p_name, tvb, offset, ACS_P2P_CDP_NAME_MAX_LEN, ENC_BIG_ENDIAN);
        offset += ACS_P2P_CDP_NAME_MAX_LEN;

        // skip bool_t config_changed;
        offset++;
        if (offset < length)
        {
            proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
        }
    }


/*

    111 typedef struct sn_ip_addr_ {
    112     uint8_t         ip_ver;
    113     union {
    114         uint32_t    ipv4;
    115         uint32_t    ipv6[4];
    116     } sn_ip_addr_t_u;
    117 } sn_ip_addr_t;


              13851 struct acs_sct_rule_line {
              13852         bool_t valid;
              13853         bool_t case_sens;
              13854         bool_t group_of_objects_present;
              13855         guint proto;
              13856         guint field;
              13857         guint field2;
              13858         guint field3;
              13859         guint rule_type;
              13860         guint oper;
              13861         guint int_val;
              13862         guint int_val2;
              13863         guint group_of_objects_id;
              13864         int hex_signature_len; 43
              13865         sn_ip_addr_t ip_addr;
              13866         sn_ip_addr_t ip_addr2;
              13867         sn_ip_addr_t ip_mask; 51
              13868         char xheader_name[ACS_MAX_XHEADER_NAME_LEN]; 32
              13869         char disp_str[ACS_MAX_STRING_LEN]; 128
              13870         char lowercase_str[ACS_MAX_STRING_LEN];
              13871         guint str_len;
              13872 };
*/
static void
dissect_pfcp_content_rule_line(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length) {
    int i;
    unsigned char ipVer;
    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruleline_valid, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    // skip case_sens  group_of_objects_present
    offset += 8;
    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruleline_proto, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    // skip 
    offset += 36;

    i = 0;
    while(i < 3) {
        ipVer = tvb_get_uint8(tvb, offset);
        offset++;
        if (ipVer == 4) {
            proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruleline_ipv4, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
        } else {
            offset += 16;
        }
        i++;
    }
    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruleline_xheader, tvb, offset, ACS_MAX_XHEADER_NAME_LEN, ENC_LITTLE_ENDIAN);
    offset+=ACS_MAX_XHEADER_NAME_LEN;
    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruleline_disp, tvb, offset, ACS_MAX_STRING_LEN, ENC_LITTLE_ENDIAN);
    offset+=ACS_MAX_STRING_LEN;
    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ruleline_lowercase, tvb, offset, ACS_MAX_STRING_LEN, ENC_LITTLE_ENDIAN);
    offset+=ACS_MAX_STRING_LEN;
    offset+= 4;
    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}


// sxmgr_ippool_encode_ip_chunk_info_params

static void
dissect_pfcp_content_ip_pool(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint16 length) {
    guint8 len = 0;
    guint type;

    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // sxmgr_ippool_encode_operation_type_params
    offset++;
    proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_optype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    // sxmgr_ippool_encode_context_name_params
    offset++;
    len = tvb_get_uint8(tvb, offset);
    offset++;
    if (len) {
        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_ctxt_name, tvb, offset, len, ENC_LITTLE_ENDIAN);
        offset += len;
    }
    
    // skip type IPPOOL_POOL_ID_TYPE
    offset += 1;

    while(offset < length) {
        // sxmgr_ippool_encode_pool_params

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_id, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        
        // sxmgr_ippool_encode_vrf_name_param - optional
        type = tvb_get_uint8(tvb, offset);
        offset++;
        if (type == IPPOOL_VRF_NAME_TYPE) {
            len = tvb_get_uint8(tvb, offset);
            offset++;

            if (len) {
                proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_vrf_name, tvb, offset, len, ENC_BIG_ENDIAN);
                offset += len;
            }
            // skip next type
            offset++;
        }

        proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_chunk_size, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        while(offset < length) {
            // sxmgr_ippool_encode_ipv4_chunk_params
            type = tvb_get_uint8(tvb, offset);
            offset++;
            if (type == IPPOOL_CHUNK_V4_TYPE) {
                proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_chunk_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_chunk_ipv4, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            } else if (type == IPPOOL_CHUNK_V6_TYPE) {
                proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_chunk_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
                proto_tree_add_item(tree, hf_pfcp_cisco_tlv_content_ippool_chunk_ipv6, tvb, offset, 16, ENC_BIG_ENDIAN);
                offset += 16;
            } else {
                break;
            }
        }
    }

    if (offset < length) {
        proto_tree_add_expert(tree, pinfo, &ei_pfcp_ie_data_not_decoded, tvb, offset, -1);
    }
}

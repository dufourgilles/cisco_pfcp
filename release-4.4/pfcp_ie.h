/*
 * Copyright (c) 2017 by cisco Systems, Inc.
 * All rights reserved.
 */
/*
 * =====================================================================================
 *
 *    Filename: pfcp_ie.h 
 *
 *    Description:  PFCP IEs and Sx messages definitions 
 *
 *    Copyright (c) 2008 by STARENT NETWORKS, Inc. All rights reserved
 *    No part of this document may be reproduced in any way, or by any means,
 *    without the prior written permission of STARENT NETWORKS, Incorporated
 *
 * =====================================================================================
 */

#ifndef __PFCP_IE_H__
#define __PFCP_IE_H__


#define P2P_MODULE_VERS_SIZE       16
#define P2P_MODULE_MAX_VERSION (P2P_MODULE_VERS_SIZE+1)

#define  PFCP_STANDARD_PORT               8805
#define  PFCP_ENC_PORT                    8810 

/* For Private Ext */
#define  CISCO_ENT_ID                     8165

#define PFCP_GR_VERSION_2000 2000
#define PFCP_GR_VERSION_2100 2100
#define PFCP_GR_VERSION_2200 2200
#define PFCP_GR_VERSION_2300 2300
#define PFCP_GR_VERSION_2400 2400
#define PFCP_GR_VERSION_2500 2500 // 21.27 CSCwa31955
#define PFCP_GR_VERSION_2600 2600 // 21.28 CSCwc01433
/* Add new PFCP GR VERSION above this line and update the macro below 
  * incraese it by 100 every time*/
#define PFCP_GR_VERSION_CURRENT  PFCP_GR_VERSION_2600


#define PFCP_MAX_MSG_SIZE            5120
#define PFCP_MAX_ENABLED_PROTOCOL    512
#define PFCP_MONSUB_MAX_PROTOCOL_ID  128
#define PFCP_MAX_PDRS                     176
#define PFCP_MIN_SGW_PDRS                 4 // RA+RS+2 pdr for default bearer 
#define PFCP_MIN_SGW_URRS                 8
#define PFCP_MIN_PGW_URRS                 8
#define PFCP_MAX_FARS                     PFCP_MAX_PDRS
#define PFCP_MAX_BEARERS                  11
#define PFCP_MAX_SX_SESSIONS              11
#define PFCP_MAX_CREATE_PDR               PFCP_MAX_PDRS
#define PFCP_MAX_CREATE_FAR               PFCP_MAX_PDRS
#define PFCP_MAX_UPDATE_PDR               PFCP_MAX_PDRS
#define PFCP_MAX_REMOVE_PDR               PFCP_MAX_PDRS
#define PFCP_MAX_UPDATE_FAR               PFCP_MAX_PDRS
#define PFCP_MAX_REMOVE_FAR               PFCP_MAX_PDRS
#define PFCP_MAX_CREATED_PDR              PFCP_MAX_PDRS
#define PFCP_MAX_UPDATE_QER               PFCP_MAX_PDRS
#define PFCP_MAX_REMOVE_URR               PFCP_MAX_PDRS
#define PFCP_MAX_REMOVE_QER               PFCP_MAX_PDRS
#define PFCP_MAX_PDI                      1
#define PFCP_MAX_FORW_PARAMS              1
#define PFCP_MAX_DUPL_PARAMS              2
#define PFCP_MAX_APP_DETECT_INFO_PER_PDR  1
#define PFCP_MAX_UPDATE_FORW_PARAMS       1
#define PFCP_MAX_UPDATE_DUPL_PARAMS       2
#define PFCP_MAX_UPDATE_ADDNL_FORW_PARAMS 1
#define PFCP_MAX_URR                      (PFCP_MAX_PDRS+32) /*We are supporting 2 interfaces per pdr */
#define PFCP_MAX_LINKED_URR               4 /* Must be same as SESS_UPLANE_MAX_LINKED_URR defined in sess_common.x */
#define PFCP_MAX_QER_PER_PDR              2   /* Per PDR we can have one QER for uplink and one QER for Downlink*/
#define PFCP_MAX_QER                      ((PFCP_MAX_PDRS/2)+16)
#define PFCP_MAX_USAGE_REPORT             (PFCP_MAX_PDRS+32) /* 2*PFCP_MAX_URR is to take care of each URR's monitoring time snapshot of data*/
#define PFCP_MAX_TRAFFIC_ENDPTS           ((PFCP_MAX_BEARERS*3) + 2) /* 2 CTE per bearer for SGW + 1 CTE per bearer for PGW + 2 RA/RS CTEs */ 
#define PFCP_MAX_CREATE_BLI               64

#define PFCP_MAX_PDN_INSTANCE_LEN         100
#define PFCP_MAX_APN_LEN                  100
#define PFCP_MAX_CONTEXT_LEN              100
#define PFCP_MAX_APP_ID_LEN               64 /* The Maximum length of the ruledef on boxer, TODO: for non-Cisco, have to discusss */
#define PFCP_MAX_REDIRECT_INFO_LEN        1024 /*TODO: Find and update max value*/
#define PFCP_MAX_FLOW_DESCR_LEN           256 /*TODO: Find and update max value*/
#define PFCF_MAX_FLOW_DES_PER_PDR         8 /*TODO ACS_MAX_OPTIONS_PER_RULE is 20 for GiLAN but earlier it was 16*/
#define PFCP_MAX_FORW_POLICY_ID_LEN       255
#define PFCP_MAX_URR_IN_PDR               16 /*TODO: When multiple interfaces supported, we might have to change this value*/
#define PFCP_MAX_PREDEF_RULE_LEN         128
#define PFCP_MAX_RBASE_NAME_LEN           64
#define PFCP_MAX_QGR_NAME_LEN           64
#define PFCP_MAX_IMEI_LEN                 16
#define PFCP_MAX_MSISDN_LEN               16
#define PFCP_MAX_IMSI_LEN                 16
#define PFCP_MAX_QUERY_URR                1
#define PFCP_MAX_INTERCEPT_ID_LEN  25
#define PFCP_MAX_CHARGING_ID_LEN       255
#define PFCP_MAX_RULE_NAME_LEN         64
#define PFCP_MAX_VRF_NAME_LEN          64
#define PFCP_MAX_RATTYPE_LEN                 8
#define PFCP_MAX_CALL_STATION_ID         65 
#define PFCP_MAX_ULI_LEN                 44
#define PFCP_MAX_TRIGGER_ACTION          20

#define ACS_MAX_DCCA_GROUP_NAME_LEN 64
#define PFCP_MAX_IE_SUPPORTED   1024
#define PFCP_MAX_UNSUPPORTED_IE 20

#define PFCP_MAX_CHRG_CHARS_LEN            2
#define PFCP_MAX_MCC_MNC_LEN               7
#define PFCP_MAX_CUST_ID_LEN             256
#define PFCP_MAX_USR_NAME_LEN            128
#define PFCP_MAX_TRANSPARENT_DATA_LEN    128
#define PFCP_MAX_SESS_ID_LEN             128
#define PFCP_MAX_MS_TIMEZONE_LEN         2
#define PFCP_MAX_USER_PROFILE_LEN        16
#define PFCP_MAX_XHDR_HASH_VAL_LEN       81
#define PFCP_MAX_TRSTERRING_PROFILE_LEN  64
#define PFCP_MAX_TRSTERRING_SUBSCRIPTION_SCHEME_LEN  64
#define PFCP_STAROS_VERSION_MAX    128

#define LI_XID_LEN 16  //NOTE: should be same as XID_LEN in sess_common.x
/*
 * Gx alias IE max length = 69 (min length = 1+4+2 = 7)
 * 1 (flag) + 4 (start pdr and end pdr id) + gx alias group name max len
 *                     ACSCTRL_GRP_OF_RDEFS_NAMELEN (64) = 69
 */
#define PFCP_GX_ALIAS_WITHOUT_NAME        5
#define PFCP_MIN_GX_ALIAS_LEN             7
#define PFCP_MAX_GX_ALIAS_LEN             69
#define PFCP_MIN_GX_ALIAS_NAME_LEN    (PFCP_MIN_GX_ALIAS_LEN - PFCP_GX_ALIAS_WITHOUT_NAME)
#define PFCP_MAX_GX_ALIAS_NAME_LEN    (PFCP_MAX_GX_ALIAS_LEN - PFCP_GX_ALIAS_WITHOUT_NAME)
/*
 * maximum number of PDRs sent in GxAlias GoR groups list.
 * maximum ruledefs allowed across gx-alias GoRs = 512,
 * so maximum PDR allowed for GxAlias group list = 1024 (1 each for UL and DL)
 */
#define PFCP_MAX_GX_ALIAS_GROUP_LIST_RULEDEF   512
#define PFCP_MAX_GX_ALIAS_GROUP_LIST_PDR       1024

/*
 * maximum number of GxAlias GoR groups
 * Though maximum configured GxAlias GoRs = ACS_MAX_GRP_OF_RDEFS = 384,
 * we can't use all these in a single Sx msg (limited size for Sx message(2K)).
 * So we are setting a reasonable number of GoRs we can communicate in a single Sx.
 */
#define PFCP_MAX_GX_ALIAS_GROUPS 64

/* -----------------------
 * Maximum IE lengths
 * ----------------------- */

#define  PFCP_MAX_SEID_LEN                64
#define  PFCP_MAX_IPV6_LEN                16
#define  PFCP_MAX_IPV6_PREFIX_LEN         8
#define  PFCP_MAX_DEF_IPV6_PREFIX_LEN     64
#define  PFCP_MAX_PVT_EXTN_LEN            256
#define  PFCP_MAX_OFFEND_IE_LEN           256 /*TODO: Not defined yet*/
/* USed to push Stats from UP to CP*/
#define  PFCP_MAX_CONTENT_LENGTH          (PFCP_MAX_MSG_SIZE-50)
/* Used to push PFD Config from CP to UP*/
#define  PFCP_MAX_PFD_CONTENT_LENGTH      6000
#define  PFCP_MAX_MSG_LENGTH              4000
#define  PFCP_MAX_HDR_LENGTH              150 /*IP (40) + UDP (8) + VPP MEH Hdr (54) + PFCP HDR (16) + PFD MSG IE (20) + buffer*/
#define  PFCP_MAX_MISSING_PARTS_LEN       100
#define  PFCP_MAX_STATS_REQUEST           1
#define  PFCP_MAX_ENTITY_NAME_LEN         101
#define  PFCP_MAX_RSP_PARTS               256
#define PFCP_MAX_PORT_CHUNK_INFO          100

/* -----------------------
 *  Sx Message types
 * ----------------------- */

#define  SX_MSG_RESERVED                                    0
#define  SX_MSG_HEARTBEAT_REQUEST                           1
#define  SX_MSG_HEARTBEAT_RESPONSE                          2
#define  SX_MSG_PFD_MANAGEMENT_REQUEST                      3
#define  SX_MSG_PFD_MANAGEMENT_RESPONSE                     4
#define  SX_MSG_ASSOCIATION_SETUP_REQUEST                   5
#define  SX_MSG_ASSOCIATION_SETUP_RESPONSE                  6
#define  SX_MSG_ASSOCIATION_UPDATE_REQUEST                  7
#define  SX_MSG_ASSOCIATION_UPDATE_RESPONSE                 8
#define  SX_MSG_ASSOCIATION_RELEASE_REQUEST                 9
#define  SX_MSG_ASSOCIATION_RELEASE_RESPONSE               10
#define  SX_MSG_VERSION_NOT_SUPPORTED_RESPONSE             11
#define  SX_MSG_NODE_REPORT_REQUEST                        12
#define  SX_MSG_NODE_REPORT_RESPONSE                       13
#define  SX_MSG_PRIME_STATS_QUERY_REQUEST                  44
#define  SX_MSG_PRIME_STATS_QUERY_RESPONSE                 45
#define  SX_MSG_PRIME_STATS_QUERY_ACK                      46
#define  SX_MSG_PRIME_PFD_MANAGEMENT_REQUEST               47
#define  SX_MSG_PRIME_PFD_MANAGEMENT_RESPONSE              48
#define  SX_MSG_MAX_NODE_RELATED_MSG                       49
#define  SX_MSG_SESSION_ESTABLISHMENT_REQUEST              50
#define  SX_MSG_SESSION_ESTABLISHMENT_RESPONSE             51
#define  SX_MSG_SESSION_MODIFICATION_REQUEST               52
#define  SX_MSG_SESSION_MODIFICATION_RESPONSE              53
#define  SX_MSG_SESSION_DELETION_REQUEST                   54
#define  SX_MSG_SESSION_DELETION_RESPONSE                  55
#define  SX_MSG_SESSION_REPORT_REQUEST                     56
#define  SX_MSG_SESSION_REPORT_RESPONSE                    57
#define  SX_MSG_MAX_SESSION_RELATED_MSG                    99


/* ----------------
 *   PFCP IEs
 * ---------------- */

#define PFCP_IE_CREATE_PDR                1
#define PFCP_IE_PDI                       2
#define PFCP_IE_CREATE_FAR                3
#define PFCP_IE_FORW_PARAMS               4
#define PFCP_IE_DUPL_PARAMS               5
#define PFCP_IE_CREATE_URR                6
#define PFCP_IE_CREATE_QER                7
#define PFCP_IE_CREATED_PDR               8
#define PFCP_IE_UPDATE_PDR                9
#define PFCP_IE_UPDATE_FAR                10
#define PFCP_IE_UPDATE_FORW_PARAMS        11
#define PFCP_IE_UPDATE_BAR_SESS_REP_RSP   12
#define PFCP_IE_UPDATE_URR                13
#define PFCP_IE_UPDATE_QER                14
#define PFCP_IE_REMOVE_PDR                15
#define PFCP_IE_REMOVE_FAR                16
#define PFCP_IE_REMOVE_URR                17
#define PFCP_IE_REMOVE_QER                18
#define PFCP_IE_CAUSE                     19
#define PFCP_IE_SRC_IFACE                 20
#define PFCP_IE_FTEID                     21
#define PFCP_IE_PDN_INSTANCE              22
#define PFCP_IE_SDF_FILTER                23
#define PFCP_IE_APP_ID                    24
#define PFCP_IE_GATE_STATUS               25
#define PFCP_IE_MBR                       26
#define PFCP_IE_GBR                       27
#define PFCP_IE_QER_CORRELATION_ID        28
#define PFCP_IE_PRECEDENCE                29
#define PFCP_IE_TRANSPORT_LEVEL_MARKING   30
#define PFCP_IE_VOLUME_THRESHOLD          31
#define PFCP_IE_TIME_THRESHOLD            32
#define PFCP_IE_MONITORING_TIME           33
#define PFCP_IE_SUBSEQUENT_VOLUME_THRESHOLD 34
#define PFCP_IE_SUBSEQUENT_TIME_THRESHOLD 35
#define PFCP_IE_INACTIVITY_DETECTION_TIME 36
#define PFCP_IE_REPORTING_TRIGGERS        37
#define PFCP_IE_REDIRECT_INFO             38
#define PFCP_IE_REPORT_TYPE               39
#define PFCP_IE_OFFENDING_IE              40
#define PFCP_IE_FORW_POLICY               41
#define PFCP_IE_DEST_IFACE                42
#define PFCP_IE_UP_FUNC_FEATURE           43
#define PFCP_IE_APPLY_ACTION              44
#define PFCP_IE_DOWNLINK_DATA_SERVICE_INFORMATION 45
#define PFCP_IE_DOWNLINK_DATA_NOTIFICATION_DELAY 46
#define PFCP_IE_DL_BUFFERING_DURATION     47
#define PFCP_IE_DL_BUFFERING_SUGGESTED_PACKET_COUNT 48
#define PFCP_IE_SX_SMREQ_FLAGS            49
#define PFCP_IE_LOAD_CTRL_INFO            51
#define PFCP_IE_SEQUENCE_NUMBER           52
#define PFCP_IE_METRIC                    53
#define PFCP_IE_OVERLOAD_CTRL_INFO        54
#define PFCP_IE_TIMER        		  55
#define PFCP_IE_PDR_ID                    56
#define PFCP_IE_FSEID                     57
#define PFCP_IE_NODE_ID                   60
#define PFCP_IE_MEASUREMENT_METHOD        62
#define PFCP_IE_USAGE_REPORT_TRIGGER      63
#define PFCP_IE_MEASUREMENT_PERIOD        64
#define PFCP_IE_VOLUME_MEASUREMENT        66
#define PFCP_IE_DURATION_MEASUREMENT      67
#define PFCP_IE_APP_DETECTION_INFO        68
#define PFCP_IE_TIME_OF_FIRST_PACKET      69
#define PFCP_IE_TIME_OF_LAST_PACKET       70
#define PFCP_IE_QUOTA_HOLDING_TIME        71
#define PFCP_IE_DROPPED_DL_TRAFFIC_THRESHOLD  72
#define PFCP_IE_TIME_QUOTA                74
#define PFCP_IE_START_TIME                75
#define PFCP_IE_END_TIME                  76
#define PFCP_IE_QUERY_URR                 77
#define PFCP_IE_VOLUME_QUOTA              73
#define PFCP_IE_USAGE_REPORT_SESS_MOD_RSP 78
#define PFCP_IE_USAGE_REPORT_SESS_DEL_RSP 79
#define PFCP_IE_USAGE_REPORT_SESS_REP_REQ 80
#define PFCP_IE_URR_ID                    81
#define PFCP_IE_LINKED_URR_ID             82
#define PFCP_IE_DOWNLINK_DATA_REPORT_SESS_REP_REQ 83
#define PFCP_IE_OUTER_HEADER_CREATION     84
#define PFCP_IE_CREATE_BAR                85
#define PFCP_IE_UPDATE_BAR                86
#define PFCP_IE_REMOVE_BAR                87
#define PFCP_IE_BAR_ID                    88
#define PFCP_IE_CP_FUNC_FEATURE           89
#define PFCP_IE_USAGE_INFORMATION         90
#define PFCP_IE_APPLICATION_INSTANCE_ID   91
#define PFCP_IE_FLOW_INFORMATION          92
#define PFCP_IE_UE_IP_ADDRESS             93
#define PFCP_IE_PACKET_RATE               94
#define PFCP_IE_OUTER_HEADER_REMOVAL      95
#define PFCP_IE_RECOVERY_TIME_STAMP       96
#define PFCP_IE_DL_FLOW_LEVEL_MARKING     97
#define PFCP_IE_ERROR_INDICATION_REPORT   99
#define PFCP_IE_MEASUREMENT_INFORMATION   100
#define PFCP_IE_NODE_REPORT_TYPE          101
#define PFCP_IE_UP_PATH_FAILURE_REPORT    102
#define PFCP_IE_REMOTE_GTPU_PEER          103
#define PFCP_IE_UR_SEQN                   104
#define PFCP_IE_UPDATE_DUPL_PARAMS        105
#define PFCP_IE_ACTIVATE_PREDEF_RULE      106
#define PFCP_IE_DEACTIVATE_PREDEF_RULE    107
#define PFCP_IE_FAR_ID                    108
#define PFCP_IE_OCI_FLAGS                 110
#define PFCP_IE_SX_ASSOCIATION_RELEASE_REQUEST 111
#define PFCP_IE_FAILED_RULE_ID            114
#define PFCP_IE_USER_INACTIVITY           117
#define PFCP_IE_QFI                       124
#define PFCP_IE_SUGGESTED_BUFFERING_PACKETS_COUNT 140
#define PFCP_IE_USER_ID                   141
#define PFCP_IE_AVERAGING_WINDOW          157
#define PFCP_IE_PAGING_POLICY_IND         158
/*TODO: PFCP_IE_UPDATE_ADDNL_FORW_PARAMS not defined in spec. 29244-110, IE Tag may change */
#define PFCP_IE_QER_BURST_SIZE            176
#define PFCP_IE_QER_CONFORM_ACTION        177
#define PFCP_IE_QER_EXCEED_ACTION         178
#define PFCP_IE_SRCIP                     192
#define PFCP_IE_EXTENDED_INTR_INFO        198
#define PFCP_IE_SECONDARY_PDR_ID          199
#define PFCP_IE_EXTENDED_APPLY_ACTIONS    200
#define PFCP_IE_UPDATE_ADDNL_FORW_PARAMS  201
#define PFCP_IE_CONFIG_ACTION             202
#define PFCP_IE_CORRELATION_ID            203
#define PFCP_IE_SUB_PART_NUMBER           204
#define PFCP_IE_SUB_PART_INDEX            205
#define PFCP_IE_CONTENT_TLV               206
#define PFCP_IE_RBASE_NAME                207
#define PFCP_IE_NSH_INFO                  208
#define PFCP_IE_STATS_REQUEST             209
#define PFCP_IE_QUERY_PARAMS              210
#define PFCP_IE_CLASSIFIER_PARAMS         211
#define PFCP_IE_STATS_RESPONSE            212
#define PFCP_IE_STATS_ACK                 213
#define PFCP_IE_PACKET_MEASUREMENT        214
#define PFCP_IE_EXTENDED_MEASUREMENT_METHOD        215
#define PFCP_IE_RECALCULATE_MEASUREMENT   216
#define PFCP_IE_SUB_INFO                  217
#define PFCP_IE_INTR_INFO                 218
#define PFCP_IE_NODE_CAPABILITY           219
#define PFCP_IE_INNER_PACKET_MARKING      220
#define PFCP_IE_TRANSPORT_LEVEL_MARKING_OPTIONS     221
#define PFCP_IE_PDHIR_OUTER_HEADER_CREATION 222
#define PFCP_IE_CHARGING_PARAMS           223
#define PFCP_IE_GY_OFFLINE_CHARGE         224
#define PFCP_IE_BEARER_INFO               225
#define PFCP_IE_SUB_PARAMS                226
#define PFCP_IE_RULE_NAME                 227 
#define PFCP_IE_LAYER2_MARKING            228
#define PFCP_IE_MONITOR_SUBSCRIBER_INFO   229
#define PFCP_IE_MON_SUB_REPORT_SESS_REP_REQ 230
#define PFCP_IE_CREATE_BLI                231
#define PFCP_IE_BLI_ID                    232
#define PFCP_IE_QCI                       233
#define PFCP_IE_5QI                       234
#define PFCP_IE_ARP                       235
#define PFCP_IE_CHARGING_ID               236
#define PFCP_IE_RATING_GRP                237
#define PFCP_MAX_QGR_IN_PDR               20

#define PFCP_IE_NEXTHOP                   238
#define PFCP_IE_NEXTHOP_ID                239
#define PFCP_IE_NEXTHOP_IP                240

#define PFCP_IE_QGR_INFO                  241
#define PFCP_IE_UE_IP_VRF                 242
#define PFCP_IE_SERVICE_ID                243
#define PFCP_IE_USER_PLANE_ID             244
#define PFCP_IE_PEER_VERSION              245
/* Gx Alias IE for processing group name and convert to PDRs */
#define PFCP_IE_GX_ALIAS                  246
#define PFCP_IE_QUERY_INTERFACE           253

#define PFCP_IE_NBR_INFO_SESS_REP_REQ     247
#define PFCP_IE_NAT_IP                    248
#define PFCP_IE_PORT_CHUNK_INFO           249
#define PFCP_IE_ALLOCATION_FLAG           250
#define PFCP_IE_NAPT_NUM_USERS_PER_USER   251
#define PFCP_IE_RELEASE_TIMER             252
#define PFCP_IE_QUERY_INTERFACE           253
#define PFCP_IE_BUSY_OUT_INACTIVITY_TIMEOUT    254


#define PFCP_IE_QUERY_INTERFACE           253

#define PFCP_IE_PRIVATE_EXTENSION         255
#define PFCP_IE_TRIGGER_ACTION_REPORT     256

#define PFCP_IE_QER_ID                    109
#define PFCP_IE_CREATE_TRAFFIC_ENDPOINT   127
#define PFCP_IE_CREATED_TRAFFIC_ENDPOINT  128
#define PFCP_IE_UPDATE_TRAFFIC_ENDPOINT   129
#define PFCP_IE_REMOVE_TRAFFIC_ENDPOINT   130
#define PFCP_IE_TRAFFIC_ENDPOINT_ID       131
#define PFCP_IE_SOURCE_VIOLATION          265

/* ----------------------
 * PFCP cause values
 * ---------------------- */

#define  PFCP_CAUSE_REQUEST_UNKNOWN                             0
#define  PFCP_CAUSE_REQUEST_ACCEPTED                            1
#define  PFCP_CAUSE_REQUEST_REJECTED                           64
#define  PFCP_CAUSE_CONTEXT_NOT_FOUND                          65
#define  PFCP_CAUSE_MANDATORY_IE_MISSING                       66
#define  PFCP_CAUSE_CONDITIONAL_IE_MISSING                     67
#define  PFCP_CAUSE_INVALID_LENGTH                             68
#define  PFCP_CAUSE_MANDATORY_IE_INCORRECT                     69
#define  PFCP_CAUSE_INVALID_FORWARDING_POLICY                  70
#define  PFCP_CAUSE_INVALID_FTEID_ALLOCATION_OPTION            71
#define  PFCP_CAUSE_NO_ESTABLISHED_SX_ASSOCIATION              72
#define  PFCP_CAUSE_CONDITIONAL_IE_INCORRECT                   PFCP_CAUSE_MANDATORY_IE_INCORRECT
#define  PFCP_CAUSE_RULE_CREATION_MODIFICATION_FAILURE         73
#define  PFCP_CAUSE_PFCP_ENTITY_IN_CONGESTION                  74
#define  PFCP_CAUSE_NO_RESOURCE_AVAILABLE                      75
#define  PFCP_CAUSE_SERVICE_NOT_SUPPORTED                      76
#define  PFCP_CAUSE_SYSTEM_FAILURE                             77


/* Internal cause - set specifically for the errorneous response messages */
#define PFCP_CAUSE_SN_MALFORMED_MSG                           255



/* IP Addr Types */
#define  PFCP_IP_ADDR_TYPE_IPV4          1
#define  PFCP_IP_ADDR_TYPE_IPV6          2


typedef struct {
  int ip_ver;
  union {
    guint32 ipv4;
    guint32 ipv6[4];
  } snx_ip_addr_t_u;
} snx_ip_addr_t;

/*  PFCP  Private Extension Definitions */

/* Private Extension IE for CISCO Type */

typedef struct
{
  guint8 valid;
  guint8 remove;              /*If this is set, value should not be encoded/decoded */
  guint8 l2markingtype:2;     /* 0 - No Marking, 1 - DSCP-to-L2 Marking, 2 - QCI-QoS Mapping 3-None Priority: Range 0x0 to 0x3 */
  guint8 internal_priority:6; /* Internal Priority - from [QCI-Table / DSCPTable] : Range 0x0 - 0x7, 0x8 is invalid
                                                   - in case of DSCPtoL2 marking, send dscp vlaue 0x0 to 0x3F */
} PfcpLayer2Marking;

/*  PFCP Private Extension Definition for _cust_ */

/* End of Private Extension Definitions */

/* Max filename length for cause */
#define PFCP_MAX_ERR_FILENAME_LEN 30


typedef enum
{
  SX_GTP_ULI_LOC_TYPE_CGI = 1,
  SX_GTP_ULI_LOC_TYPE_SAI = 2,
  SX_GTP_ULI_LOC_TYPE_RAI = 4,
  SX_GTP_ULI_LOC_TYPE_CGI_RAI = 5,
  SX_GTP_ULI_LOC_TYPE_SAI_RAI = 6,
  SX_GTP_ULI_LOC_TYPE_TAI = 8,
  SX_GTP_ULI_LOC_TYPE_ECGI = 16,
  SX_GTP_ULI_LOC_TYPE_TAI_ECGI = 24,
  SX_ULI_LOC_TYPE_NRTAI = 28,
  SX_ULI_LOC_TYPE_NCGI = 30,
  SX_ULI_LOC_TYPE_NRTAI_NCGI = 31
}sx_gtp_uli_loc_type;

/* ----------------------
 *  PFCP Enums
 * ---------------------- */

/*
 *  NOTE: PLEASE ENSURE THAT ALL FOLLOWING ENUMS
 *  IS IN SYNC WITH ENUMS defined in sess_common.x.
 */ 
typedef enum 
{   
  PFCP_INTERFACE_SXA,
  PFCP_INTERFACE_SXB,
  PFCP_INTERFACE_SXAB,
  PFCP_INTERFACE_SXC,
  PFCP_INTERFACE_N4,
  PFCP_INTERFACE_INVALID,
  PFCP_INTERFACE_MAX           //Keep this as last entry
}pfcp_interface_type_e;

#define SNX_PFCP_INTERFACE_SXB_OR_N4(_intf_type) \
 (_intf_type == PFCP_INTERFACE_SXB || _intf_type == PFCP_INTERFACE_N4)

#define SNX_PFCP_INTERFACE_N4(_intf_type) \
 (_intf_type == PFCP_INTERFACE_N4)

typedef enum
{
  PFCP_SRC_IFACE_TYPE_ACCESS = 0,
  PFCP_SRC_IFACE_TYPE_CORE,
  PFCP_SRC_IFACE_TYPE_SGI_LAN,
  PFCP_SRC_IFACE_TYPE_CP_FUNCTION,
  PFCP_SRC_IFACE_TYPE_MAX
}PfcpSrcIfaceType;

typedef enum
{
  PFCP_DST_IFACE_TYPE_ACCESS = 0,
  PFCP_DST_IFACE_TYPE_CORE,
  PFCP_DST_IFACE_TYPE_SGI_LAN,
  PFCP_DST_IFACE_TYPE_CP_FUNCTION,
  PFCP_DST_IFACE_TYPE_LI_FUNCTION,
  PFCP_DST_IFACE_TYPE_MAX
}PfcpDstIfaceType;

typedef enum
{
  PFCP_APPLY_ACTION_TYPE_DROP                       = 0x01,
  PFCP_APPLY_ACTION_TYPE_FORWARD                    = 0x02,
  PFCP_APPLY_ACTION_TYPE_BUFF_REQUEST               = 0x04,
  PFCP_APPLY_ACTION_TYPE_NOTIFY_CP                  = 0x08,
  PFCP_APPLY_ACTION_TYPE_FORW_DUPLICATE             = 0x10,
  PFCP_APPLY_ACTION_TYPE_MAX                        = 0x20
}PfcpApplyActionType;

typedef enum
{
  PFCP_EXTENDED_APPLY_ACTION_TYPE_UL_DROP           = 0x01,
  PFCP_EXTENDED_APPLY_ACTION_TYPE_DL_DROP           = 0x02,
  PFCP_EXTENDED_APPLY_ACTION_TYPE_KILL_FLOW         = 0x04,
  PFCP_EXTENDED_APPLY_ACTION_TYPE_ALLOW             = 0x08,
  PFCP_EXTENDED_APPLY_ACTION_TYPE_MAX               = 0x20
}PfcpExtendedApplyActionType;

typedef enum
{
  PFCP_QGR_APPLY_ACTION_FORWARD                     = 0x01,
  PFCP_QGR_APPLY_ACTION_DROP                        = 0x02,
  PFCP_QGR_APPLY_ACTION_MARK_DSCP                   = 0x04,
  PFCP_QGR_APPLY_ACTION_MAX                         = 0x08,
} PfcpQGRApplyActions;

typedef enum 
{
  PFCP_OHR_GTPU_UDP_IPv4 = 0,
  PFCP_OHR_GTPU_UDP_IPv6,
  PFCP_OHR_UDP_IPV4,
  PFCP_OHR_UDP_IPv6,
  PFCP_OHR_GTPU_UDP_IPv4v6 = 6, //PFCP_OHR_GTPU_UDP_IP
  PFCP_OHR_MAX
}PfcpOutHdrRemovalDescription;

#define PFCP_OHR_GTPU_UDP_IP PFCP_OHR_GTPU_UDP_IPv4v6 

typedef enum 
{
  //6th Octet as per spec 29.244 version 16
  PFCP_OHC_N19 = (1<<0),
  PFCP_OHC_N6 = (1<<1),
  // Custom Values for LI. This supports needs to be implemented in spec for LI TCP
  PFCP_OHC_TCP_IPV4 = (1<<4), 
  PFCP_OHC_TCP_IPV6 = (1<<3),
  //This is special case using free enum octects for IPV4V6 handling
  PFCP_OHC_GTPU_UDP_IPv4v6 = (3<<8), 

  //5th Octet  as per spec 29.244 version 16
  PFCP_OHC_GTPU_UDP_IPv4 = (1<<8),
  PFCP_OHC_GTPU_UDP_IPv6 = (1<<9),
  PFCP_OHC_UDP_IPv4 = (1<<10),
  PFCP_OHC_UDP_IPv6 = (1<<11),
  PFCP_OHC_IPv4 = (1<<12),
  PFCP_OHC_IPv6 = (1<<13),
  PFCP_OHFC_CTAG = (1<<14),
  PFCP_OHFC_STAG = (1<<15),
  PFCP_OHC_MAX = (1<<15) + 1
}PfcpOutHdrCreationDescription;

typedef enum
{
  PFCP_OHC_GTPU_UDP_IPv4_LEGACY = 0,
  PFCP_OHC_GTPU_UDP_IPv6_LEGACY,
  PFCP_OHC_UDP_IPv4_LEGACY,
  PFCP_OHC_UDP_IPv6_LEGACY,
  // Custom Values for LI. This supports needs to be implemented in spec for LI TCP
  PFCP_OHC_TCP_IPV4_LEGACY,
  PFCP_OHC_TCP_IPV6_LEGACY,
  PFCP_OHC_LEGACY_MAX
}PfcpOutHdrCreationDescriptionLegacy;

/* 29.244, 8.2.80 */
typedef enum
{
    PFCP_RULE_ID_TYPE_PDR = 0,
    PFCP_RULE_ID_TYPE_FAR = 1,
    PFCP_RULE_ID_TYPE_QER = 2,
    PFCP_RULE_ID_TYPE_URR = 3,
    PFCP_RULE_ID_TYPE_BAR = 4
    /* Values 5-31 SHOULD be interpreted as the value 1*/
} PfcpRuleIdType;
typedef enum
{
  PFCP_GATE_STATUS_OPEN = 0,
  PFCP_GATE_STATUS_CLOSE = 1,
}PfcpGateStatusValues;

typedef enum
{
  PFCP_NODE_ID_TYPE_IPV4 = 0,
  PFCP_NODE_ID_TYPE_IPV6 = 1,
  PFCP_NODE_ID_TYPE_FQDN = 2,
  PFCP_NODE_ID_TYPE_MAX = 3,
  PFCP_NODE_ID_TYPE_UNKNOWN = 4,
}PfcpNodeIdType;

typedef enum
{
  PFCP_REDIRECT_ADDRESS_TYPE_IPV4 = 0,
  PFCP_REDIRECT_ADDRESS_TYPE_IPV6 = 1,
  PFCP_REDIRECT_ADDRESS_TYPE_URL = 2,
  PFCP_REDIRECT_ADDRESS_TYPE_SIP_URI = 3,
}PfcpRedirectAddressType;

/* ----------------------
 *  PFCP IE structures
 * ---------------------- */

typedef struct
{ 
  guint8       valid;
  snx_ip_addr_t addr;
}PfcpIpAddr;

typedef struct
{
  guint8    valid;
  guint16   type;
  guint16   len;
  guint8    val[PFCP_MAX_OFFEND_IE_LEN];
}PfcpOffendingIe;

typedef struct
{
  guint8            valid;
  guint8            val; 
  char              fileName[PFCP_MAX_ERR_FILENAME_LEN+1];
  int               lineNo;
}PfcpCause;

typedef struct
{
  const char  *erroneous_ie;
  const char  *erroneous_token;
  PfcpCause    err_cause;
  PfcpOffendingIe   offendIe;
}PfcpIeErr;

typedef struct
{
  guint8     valid;
  guint16    len;
  char context[PFCP_MAX_CONTEXT_LEN];
}PfcpLiContext;


typedef struct
{
  guint8            valid;
  unsigned int      intercept_id;
}PfcpIntercept_Id;

typedef struct
{
  guint8     valid;
  guint16    len;
  char intercept_key[PFCP_MAX_INTERCEPT_ID_LEN];
}PfcpIntercept_Key;

typedef struct
{
  guint8            valid;
  unsigned int      callid;
}PfcpCall_Id;

typedef struct
{
  guint8            valid;
  unsigned int      charging_id;
}PfcpCharging_Id;

typedef struct
{
  guint8            valid;
  unsigned int      poi_id;
}PfcpPoi_Id;

typedef struct
{
  guint8            valid;
  guint8            value[LI_XID_LEN];
}PfcpXid;

typedef struct
{
  guint8            valid;
  guint8            bearer_id;
}PfcpBearer_Id;

typedef struct
{
  guint8            valid;
  guint8            s8hr_bearer_id;
}PfcpS8hrBearer_Id;

typedef struct
{
  guint8     valid;
  guint16    len;
  char msisdn[PFCP_MAX_MSISDN_LEN];
  guint8 msisdn_tbcd[PFCP_MAX_MSISDN_LEN/2];
}PfcpMsisdn;

typedef struct
{
  guint8     valid;
  guint16    len;
  char imsi[PFCP_MAX_IMSI_LEN];
  guint8 imsi_tbcd[PFCP_MAX_IMSI_LEN/2];
}PfcpImsi;

typedef struct
{
  guint8     valid;
  guint16    len;
  char imei[PFCP_MAX_IMEI_LEN];
  guint8 imei_tbcd[PFCP_MAX_IMEI_LEN/2];
}PfcpImei;

typedef struct
{
  guint8    valid;
  guint16   len;
  char      called_st_id[PFCP_MAX_CALL_STATION_ID]; 
}PfcpCalledStationId;

typedef struct
{
  guint8    valid;
  guint16   len;
  char      calling_st_id[PFCP_MAX_CALL_STATION_ID];
}PfcpCallingStationId;

typedef struct
{
  guint8     valid;
  PfcpMsisdn msisdn;
  PfcpImsi imsi;
}PfcpNshInfo;

typedef struct
{
  guint8     valid;
  PfcpMsisdn msisdn;
  PfcpImsi imsi;
  PfcpImei imei;
  PfcpCall_Id callid;
  PfcpBearer_Id bearer_id;
}PfcpSubInfo;

typedef struct
{
  guint8     valid;
  PfcpImsi imsi;
  PfcpImei imei;
  PfcpMsisdn msisdn;
}PfcpUserID;

typedef struct
{
  guint8     valid;
  guint16    len;
  char apn_name[PFCP_MAX_APN_LEN];
}PfcpApnName;

typedef struct
{
  guint8     valid;
  guint8     value[PFCP_MAX_CHRG_CHARS_LEN];
}PfcpChrgChars;

typedef struct
{
  guint8     valid;
  char value;
}PfcpRat;

typedef struct
{
  guint8     valid;
  guint16    len;
  char value[PFCP_MAX_MCC_MNC_LEN];
}PfcpMccMnc;

typedef struct
{
  guint8     valid;
  PfcpIpAddr value;
}PfcpSGSNAddress;

typedef struct
{
  guint8     valid;
  unsigned int value; 
}PfcpCongestionLevel;

typedef struct
{
  guint8     valid;
  guint16    len;
  char value[PFCP_MAX_CUST_ID_LEN];
}PfcpCustomerId;

typedef struct
{
  guint8     valid;
  PfcpIpAddr value;
}PfcpGGSNAddress;

typedef struct
{
  guint8     valid;
  guint16    len;
  char value[PFCP_MAX_USR_NAME_LEN]; 
}PfcpUserName;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_TRANSPARENT_DATA_LEN];
}PfcpRadiusString;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_SESS_ID_LEN];
}PfcpSessionId;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_MS_TIMEZONE_LEN];
}PfcpMSTimeZone;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_USER_PROFILE_LEN];
}PfcpUserProfile;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_XHDR_HASH_VAL_LEN];
}PfcpXhdrHashVal;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_ULI_LEN];
}PfcpULI;

typedef struct
{
  guint8 valid;
  unsigned int value;
}PfcpCFID;

typedef struct
{
  guint8 valid;
  guint8 value;
}PfcpTPID;

typedef struct
{
  guint8     valid;
  guint8     value;
}PfcpChargingDisabled;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_TRSTERRING_PROFILE_LEN];
}PfcpTrSteeringProfile;

typedef struct
{
  guint8     valid;
  guint16    len;
  char       value[PFCP_MAX_TRSTERRING_SUBSCRIPTION_SCHEME_LEN];
}PfcpTrSteeringSubscriptionScheme;

typedef struct
{
  guint8     valid;
  PfcpChrgChars       chrg_chars;
  PfcpRat         rat_type; 
  PfcpCFID         cf_plcy_id;
  PfcpCFID         consolidated_cf_plcy_id;
  PfcpTPID         traffic_opt_policy_id;
  PfcpMccMnc          mcc_mnc;
  PfcpSGSNAddress     sgsn_addr;
  PfcpULI             uli;
  PfcpCongestionLevel  congstn_level;
  PfcpCustomerId       cust_id;
  PfcpGGSNAddress      ggsn_addr;
  PfcpUserName         user_name;
  PfcpRadiusString     radius_string;
  PfcpSessionId        sess_id;
  PfcpMSTimeZone       ms_tz;
  PfcpUserProfile      user_profile;
  PfcpXhdrHashVal          hash_val;
  PfcpCalledStationId  called_st_id;
  PfcpCallingStationId calling_st_id;
  PfcpChargingDisabled  charging_disabled;
  PfcpTrSteeringProfile  ts_profile;
  PfcpTrSteeringSubscriptionScheme  ts_subscription_scheme;
}PfcpSubParams;

typedef struct
{
  guint8               valid;
  guint8               remove; /*If this is set, value should not be encoded/decoded */
  guint16              value;
}PfcpInnerPacketMarking;

typedef struct
{
  guint8 valid;
  guint8 copy_inner:1;
  guint8 copy_outer:1;
}PfcpTransportLevelMarkingOptions;

typedef struct
{
  guint8     valid;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpNetElemID;

typedef struct
{
  guint8     valid;
  PfcpIntercept_Id  intercept_id;
  PfcpIntercept_Key intercept_key;
  PfcpCharging_Id   charging_id;
  PfcpBearer_Id     bearer_id;
  PfcpLiContext     context;
  PfcpNetElemID     network_elem_id;
  PfcpS8hrBearer_Id s8hr_bearer_id;
  guint32           s8hr_gtpc_teid;
  guint8    s8hr_ims_media_flag; 
}PfcpIntrInfo;

typedef struct
{
  guint8             valid;
  PfcpPoi_Id         poi_id;
  PfcpXid            xid;
}PfcpExtendedIntrInfo;

typedef struct
{
  guint8     valid;
  guint64    seid;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpFseid;

typedef guint16 pdr_id_t;
typedef guint32 urr_id_t;
typedef guint32 far_id_t;
typedef guint32 qer_id_t;
typedef guint16 bar_id_t; 
typedef guint8  traffic_endpt_id_t;
typedef guint8  bli_id_t;

#define PFCP_MAX_TRAFFIC_END_POINT_ID_VAL 64

typedef struct
{
  guint8  valid;
  pdr_id_t rule_id;
}PfcpPdrId;

typedef struct
{
  guint8  valid;
  pdr_id_t value;
}PfcpSecondaryPdrId;

typedef struct
{
  guint8  valid;
  guint16 length;
  guint8  rule_name[PFCP_MAX_RULE_NAME_LEN];
}PfcpRuleName;

/*Note: FAR ID is not defined in the spec
 * Adding far id IE with ie type 100 and
 * 16 bit far id value*/


typedef struct
{
  guint8  valid;
  far_id_t val;
}PfcpFarId;


/* This shall be used for both IE 106 (Activate) and 107 (DeActivate) Predefined rules */
typedef struct
{
  guint8  valid;
  guint16 length;
  guint8  predefined_rule_name[PFCP_MAX_PREDEF_RULE_LEN];
}PfcpPredefRule;

/* IE 114 It shall identify the Rule which failed to be created or modified. */
typedef struct
{
  guint8  valid;
  guint16 length;
  guint8  spare:3;
  guint8  rule_id_type:5;
  guint64  rule_id_value;
  /* reserve octets not defined yet */
}PfcpFailedRuleId;

typedef struct
{
  guint8  valid;
  guint8  spare:7;
  guint8  aoci:1;
}PfcpOciFlags;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpPrecedence;

typedef struct
{
  guint8  valid;
  guint8 spare:4;
  guint8 iface_val:4;
}PfcpSrcIface;

typedef guint8 choose_id_t;

typedef struct
{
  guint8     valid;
  guint8     ch:1;
  guint8     chid:1;
  choose_id_t choose_id;
  guint32    teid;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpFteid;

typedef struct
{
  guint8     valid;
  guint8     s_d:1;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpUeIpAddress;

typedef struct
{
  guint8     valid;
  //guint8     s_d:1;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpNextHopIp;

typedef struct
{
  guint8 valid;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpRemoteGtpuPeer;

typedef struct
{ 
  guint8     valid;
  guint8     description;
}PfcpOuterHeaderRemoval;



typedef struct
{ 
  guint8     valid;
  guint16    description;
  guint16    port_num;
  guint32    teid;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
}PfcpOuterHeaderCreation;

typedef struct
{ 
  guint8     valid;
  guint8     remove; /*If this is set, value should not be encoded/decoded */
  guint16    value;
}PfcpTransportLevelMarking;

typedef struct
{ 
  guint8  valid;
  guint16 pdn_instance_len;
  guint8  pdn_instance[PFCP_MAX_PDN_INSTANCE_LEN];
}PfcpPdnInstance;

typedef struct
{ 
  guint8  valid;
  guint16 app_id_len;
  guint8  app_id[PFCP_MAX_APP_ID_LEN];
}PfcpAppId;

typedef struct 
{
  guint8 valid;
  guint16 app_inst_id_len;
  gint8  app_inst_id[PFCP_MAX_FLOW_DESCR_LEN + 1];
} PfcpAppInstId;

typedef struct
{
  guint8 valid;
  guint8 spare:5;
  guint8 direction:3;     /* 0 - Unspecified, 1 - Downlink, 2 - Uplink, 3 - Bi-Directional */
  guint16 fl_descr_len;
  guint8 fl_descr[PFCP_MAX_FLOW_DESCR_LEN + 1];
} PfcpFlowDescription;

typedef struct 
{
  guint8              valid;
  PfcpAppId           app_id;
  PfcpAppInstId       app_inst_id;
  PfcpFlowDescription flow_descr;
} PfcpAppDetectInfo;

typedef struct
{
  guint8 valid;
  guint8 valid_fl:1;
  guint8 valid_spi:1;
  guint8 valid_ttc:1;
  guint8 valid_fd:1;
  guint16 fl_descr_len;
  guint8 fl_descr[PFCP_MAX_FLOW_DESCR_LEN + 1];
  guint8 tos_traffic_class[2];
  guint8 flow_label[3];
  guint32 spi;
}PfcpSdfFilter;

typedef struct
{
  guint8  valid;
  guint8  numSdfFilter;
  PfcpSdfFilter SdfFilter[PFCF_MAX_FLOW_DES_PER_PDR];
}PfcpSdfFilterList;

typedef struct
 {
  guint8            valid;
  guint8            val;
}PfcpQfi;

typedef struct
 {
  guint8            valid;
  guint32           avgWin;
}PfcpAvgWindow;

typedef struct
 {
  guint8            valid;
  guint8            ppi;
}PfcpPpi;

typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpTrafficEndptId;

typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpNextHopId;

typedef struct
{
  guint8     valid;
  PfcpSrcIface src_iface;
  PfcpFteid fteid;
  PfcpPdnInstance pdn_instance;
  PfcpUeIpAddress ue_ip_address;
  PfcpSdfFilterList sdf_filter_list;
  PfcpAppId app_id;
  PfcpQfi qfi;
  PfcpTrafficEndptId trafficEndptId;
}PfcpPdi;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpContentId;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpUrrId;

typedef struct
{
  guint8  valid;
  guint8  numUrr;
  PfcpUrrId urr_id_list[PFCP_MAX_URR_IN_PDR];
}PfcpUrrIdList;

typedef struct
{
  guint8  valid;
  guint8  numUrr;
  PfcpUrrId urr_id_list[PFCP_MAX_URR];
}PfcpQueryUrrIdList;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpLinkedUrrId;

typedef struct
{
  guint8  valid;
  guint8  numLinkedUrrId;
  PfcpLinkedUrrId linked_urr_id_list[PFCP_MAX_LINKED_URR];
}PfcpLinkedUrrIdList;

typedef struct
{
  guint8 valid;
  guint16 len;
  char name[PFCP_MAX_RBASE_NAME_LEN];
}PfcpRulebase;

typedef struct
{
  guint8           valid;
  guint32          qer_id;
}PfcpQerId;

typedef struct
{
  guint8  valid;
  guint8  numQer;
  PfcpQerId qer_id[PFCP_MAX_QER_PER_PDR];
}PfcpQerIdList;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpStartTime;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpEndTime;

typedef struct
{
  guint8            valid;
  guint8            qci;
  guint8            arp;
  guint32           charging_id;
}PfcpBearerInfo;

typedef struct
{
  guint8     valid;
  PfcpTrafficEndptId trafficEndptId;
  PfcpFteid fteid;
}PfcpCreatedTrafficEndpt;

typedef struct
{
  guint8     valid;
  PfcpTrafficEndptId trafficEndptId;
}PfcpRemoveTrafficEndpt;

typedef struct
{
  guint8     valid;
  PfcpTrafficEndptId trafficEndptId;
  PfcpFteid fteid;
  PfcpPdnInstance pdn_instance;
  PfcpUeIpAddress ue_ip_address;
  PfcpBearerInfo bearer_info;
}PfcpTrafficEndpt;

typedef struct
{
  guint8     valid;
  PfcpNextHopId NextHopId;
  PfcpNextHopIp nexthop_ip;
}PfcpNextHopIpAddr;

typedef struct
{
  guint8        valid;
  guint8        numTrafficEndptId;
  PfcpTrafficEndptId  trafficEndptId[PFCP_MAX_TRAFFIC_ENDPTS];
}PfcpTrafficEndpIdtList;

typedef struct
{
  guint8        valid;
  guint8        numTrafficEndpt;
  PfcpTrafficEndpt  trafficEndpt[PFCP_MAX_TRAFFIC_ENDPTS];
}PfcpTrafficEndptList;

typedef PfcpTrafficEndptList  PfcpCreateTrafficEndptList;
typedef PfcpTrafficEndptList  PfcpUpdateTrafficEndptList;

typedef struct
{
  guint8        valid;
  guint8        numTrafficEndpt;
  PfcpCreatedTrafficEndpt  trafficEndpt[PFCP_MAX_TRAFFIC_ENDPTS];
}PfcpCreatedTrafficEndptList;

typedef struct
{
  guint8        valid;
  guint8        numTrafficEndpt;
  PfcpRemoveTrafficEndpt  trafficEndpt[PFCP_MAX_TRAFFIC_ENDPTS];
}PfcpRemoveTrafficEndptList;

typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpBliId;

typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpQci;

typedef struct
{
  guint8 valid;
  guint8 val;
}Pfcp5qi;

typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpArp;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpChargingId;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpRatingGrp;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpServiceId;

typedef struct
{
  guint8 valid;
  PfcpBliId bli_id;
  PfcpQci qci;
  Pfcp5qi _5qi;
  PfcpArp arp;
  PfcpChargingId charging_id;
}PfcpCreateBli;

typedef struct
{
  guint8  valid;
  guint16 length;
  guint8  vrf_name[PFCP_MAX_VRF_NAME_LEN];
}PfcpVrfName;

typedef struct
{
  guint8 valid;
  guint8 spare:7;
  guint8 iden_vrf:1;
  union {
    PfcpVrfName ip;
    struct {
       PfcpVrfName ipv4;
       PfcpVrfName ipv6;
    }sep;
  }u;
}PfcpUeIpVrf;

typedef struct
{ 
  guint8          valid;
  guint8          numCreateBli;
  PfcpCreateBli   createBli[PFCP_MAX_CREATE_BLI];
}PfcpCreateBliList;

typedef struct
{
  guint8 valid;
  guint16 len;
  char name[PFCP_MAX_QGR_NAME_LEN];
}PfcpQGRName;

typedef enum
{
  QGR_ADD = 0,
  QGR_MODIFY,
  QGR_REMOVE 
}PfcpQGROperation;

enum trigger_action_t
{
   SMGR_SS_ACTION_INVALID,
   SMGR_SS_ACTION_ACTIVATE_RULE,
   SMGR_SS_ACTION_MAX
};

typedef struct
{
  guint8     valid;
  guint8     operation:2;
  PfcpPrecedence priority;
  PfcpQGRName name;
  PfcpFarId far_id;
  PfcpQerId qer_id;
  PfcpUrrId urr_id;
}PfcpQGRInfo;

typedef struct
{
  guint8  valid;
  guint8  numQGR;
  PfcpQGRInfo qgr_info[PFCP_MAX_QGR_IN_PDR];
}PfcpQGRInfoList;

/* GxAlias IE data struct: used for IE type 246  */
typedef struct
{
  guint8  valid;
  /* min val = PFCP_MIN_GX_ALIAS_LEN */
  guint16 length;
  /* 1 => add, 0 => delete PDRs in this group */
  guint8  flags;
  /* for rules audit between CP and UP */
  guint16 start_pdr_id;
  guint16 end_pdr_id;
  /* -5 for excluding Add/Del flag and start and end pdr ids info */
  char  gx_alias_name[PFCP_MAX_GX_ALIAS_NAME_LEN];
}PfcpGxAlias;

/* List of GxAlias groups. sent as sequence of GxAlias IEs in Sx Sess Est Req/Mod msg */
typedef struct
{
  guint8        valid;
  guint8        numGxAlias;
  PfcpGxAlias   gxAlias[PFCP_MAX_GX_ALIAS_GROUPS];
}PfcpGxAliasList;

typedef struct
{
  guint8                  valid;
  guint8                  local_pdr_record;
  PfcpPdrId               pdr_id;
  PfcpRuleName            rule_name;
  PfcpPrecedence          precedence;
  PfcpPdi                 pdi;
  PfcpOuterHeaderRemoval  outer_header_removal;
  PfcpFarId               far_id;
  PfcpBliId               bli_id;
  PfcpUrrIdList           pdr_urr_id_list;
  PfcpPredefRule          activate_predef_rule;
  PfcpRulebase            rulebase;
  PfcpQerIdList           qer_id_list;
  PfcpStartTime           start_time;
  PfcpEndTime             end_time;
  PfcpSecondaryPdrId      secondary_pdr_id;
}PfcpCreatePdr;

typedef struct
{
 guint8  valid;
 guint8 spare:5;
 guint8 event:1;
 guint8 volume:1;
 guint8 duration:1;
}PfcpMeasurementMethod;

typedef struct
{
 guint8  valid;
 guint8 spare:7;
 guint8 volume_pkt:1;
}PfcpExtendedMeasurementMethod;

typedef struct
{
 guint8 valid;
 guint8 liusa:1;
 guint8 droth:1;
 guint8 stop:1;
 guint8 start:1;
 guint8 qht:1;
 guint8 timth:1;
 guint8 volth:1;
 guint8 perio:1;
 guint8 spare:5;
 guint8 envcl:1;
 guint8 timqu:1;
 guint8 volqu:1;
}PfcpReportingTriggers;

typedef struct
{
 guint8 valid;
 guint32 val;
}PfcpMeasurementPeriod;

typedef struct
{
 guint8 valid;
 guint32 val;
}PfcpIdleTimeout;

typedef struct
{
  guint8 valid;
  guint8 spare:5;
  guint8 dlvol_valid:1;
  guint8 ulvol_valid:1;
  guint8 tovol_valid:1;
  guint64 tot_vol;
  guint64 ul_vol;
  guint64 dl_vol;
}PfcpVolumeThreshold;

typedef struct
{
  guint8 valid;
  guint8 spare:5;
  guint8 dlvol_valid:1;
  guint8 ulvol_valid:1;
  guint8 tovol_valid:1;
  guint64 tot_vol;
  guint64 ul_vol;
  guint64 dl_vol;
}PfcpVolumeQuota;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpTimeThreshold;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpTimeQuota;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpQuotaHoldingTime;

typedef struct
{
  guint8 valid;
  guint8 spare:7;
  guint8 dlpa_bits:1;
  guint64 val;
}PfcpDroppedDlTrafficThreshold;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpMonitoringTime;

typedef struct
{
  guint8 valid;
  guint8 spare:5;
  guint8 dlvol_valid:1;
  guint8 ulvol_valid:1;
  guint8 tovol_valid:1;
  guint64 tot_vol;
  guint64 ul_vol;
  guint64 dl_vol;
}PfcpSubsequentVolumeThreshold;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpSubsequentTimeThreshold;

typedef struct
{
  guint8 valid;
  guint32 val;
}PfcpInactivityDetectionTime;

typedef struct
{
  guint8 valid;
  guint32 inactivity_timeout;
}PfcpUplaneBusyOut;

typedef struct
{
 guint8 valid;
 guint8 spare:5;
 guint8 radi:1;
 guint8 inam_bits:1;
 guint8 mbqe_bits:1;
}PfcpMeasurementInformation;

typedef struct
{
  guint8  valid;
  guint8  spare:6;
  guint8  rcvol:1;
  guint8  rcdur:1;
}PfcpRecalculateMeasurement;

typedef struct
{
  guint8              valid;
  PfcpUrrIdList       urr_id;
  PfcpMeasurementMethod measurment_method;
  PfcpExtendedMeasurementMethod extended_measurement_method;
  PfcpReportingTriggers reporting_triggers;
  PfcpMeasurementPeriod measurement_period;
  PfcpVolumeThreshold   volume_threshold;
  PfcpVolumeQuota       volume_quota;
  PfcpTimeThreshold     time_threshold;
  PfcpTimeQuota         time_quota;
  PfcpQuotaHoldingTime  quota_holding_time;
  PfcpDroppedDlTrafficThreshold dropped_dl_traffic_threshold;
  PfcpMonitoringTime    monitoring_time;
  PfcpSubsequentVolumeThreshold subsequent_volume_threshold;
  PfcpSubsequentTimeThreshold subsequent_time_threshold;
  PfcpInactivityDetectionTime  inactivity_detection_time;
  PfcpLinkedUrrIdList          linked_urr_id_list;
  PfcpMeasurementInformation   measurement_information;
  PfcpRecalculateMeasurement   recalculateMeasurement;
  PfcpFarId                    far_id_quota_action;
  PfcpRatingGrp                rating_grp;
}PfcpUrr;

typedef struct
{
  guint8 valid;
  guint8 spare:4;
  guint8 iface_val:4;
}PfcpDestIface;

typedef struct
{
  guint8 valid;
  guint8 forw_policy_id_len;
  guint8 forw_policy_id[PFCP_MAX_FORW_POLICY_ID_LEN];
}PfcpForwPolicy;

typedef struct
{ 
  guint8  valid;
  PfcpDestIface dest_iface;
  PfcpOuterHeaderCreation outer_header_creation;
  PfcpForwPolicy forw_policy;
}PfcpUpdateAddnlForwParams;

typedef struct
{ 
  guint8        valid;
  guint8        numCreatePdr;
  PfcpCreatePdr CreatePdr[PFCP_MAX_CREATE_PDR];
}PfcpCreatePdrList;

typedef struct
{ 
  guint8        valid;
  guint8        numUrr;
  PfcpUrr       Urr[PFCP_MAX_URR];
}PfcpUrrList;

//ms: begin
typedef struct
{
    guint8    valid;
    PfcpFarId far_id;
}PfcpRemoveFar;

typedef struct
{
    guint8    valid;
    PfcpUrrId urr_id;
}PfcpRemoveUrr;

typedef struct
{
    guint8    valid;
    PfcpQerId qer_id;
}PfcpRemoveQer;

typedef struct
{ 
  guint8        valid;
  guint8        numFar;
  PfcpRemoveFar Far[PFCP_MAX_FARS];
}PfcpRemoveFarList;

typedef struct
{ 
  guint8        valid;
  guint8        numUrr;
  PfcpRemoveUrr Urr[PFCP_MAX_URR];
}PfcpRemoveUrrList;

typedef struct
{ 
  guint8        valid;
  guint8        numQer;
  PfcpRemoveQer Qer[PFCP_MAX_QER];
}PfcpRemoveQerList;
//ms: end

typedef struct
{
  guint8           valid;
  guint32          co_relation_id;
}PfcpQerCorrelationId;

typedef struct
{
  guint8           valid;
  guint8           ulGate:2;
  guint8           dlGate:2;
}PfcpGateStatus;

typedef struct
{
  guint8           valid;
  guint64          ul_mbr;
  guint64          dl_mbr;
}PfcpMbr;

typedef struct
{
  guint8           valid;
  guint64          ul_gbr;
  guint64          dl_gbr;
}PfcpGbr;

typedef struct
{
  guint8           valid;
  guint32          ul_burst;
  guint32          dl_burst;
}PfcpBurst;

typedef struct
{
  guint8           valid;
  guint8           dlpr:1 ;
  guint8           ulpr:1 ;
  guint8           uplinkTimeUnit:3 ;
  guint8           downlinkTimeUnit:3 ;
  guint16          maxUlPacketRate ;
  guint16          maxDlPacketRate ;
}PfcpPacketRate;

typedef struct
{
  guint8           valid;
  guint8           ttc:1 ;
  guint8           sci:1 ;
  guint8           tosTrafficCalss ;
  guint8           svcClassInd ;
}PfcpDlFlowLevelMarking;

typedef struct
{ 
  guint8  valid;
  guint8  spare:3;
  guint8  val:5;
}PfcpApplyAction;

typedef struct
{ 
  guint8                 valid;
  PfcpApplyAction        ul_action;
  PfcpApplyAction        dl_action;
  guint8                 ul_dscp_val;
  guint8                 dl_dscp_val;
} PfcpQGRAction;

typedef struct
{
  guint8                  valid;
  PfcpQerIdList           qer_id;
  PfcpQerCorrelationId    qerCorrelationId;
  PfcpGateStatus          gateStatus;
  PfcpMbr                 mbr;
  PfcpGbr                 gbr;
  PfcpBurst               burst;
  PfcpPacketRate          pktRate;
  PfcpDlFlowLevelMarking  dlLevelFlowLevelMarking;
  PfcpQfi                 qfi;
  PfcpQGRAction           conform_action;
  PfcpQGRAction           exceed_action;
  PfcpAvgWindow           avgWindow;
  PfcpPpi                 ppi;
}PfcpQer;

typedef struct
{ 
  guint8        valid;
  guint8        numQer;
  PfcpQer       Qer[PFCP_MAX_QER];
}PfcpCreateQerList ;

typedef struct
{
  guint8  valid;
  guint8  val;
}PfcpExtendedApplyAction;

typedef struct
{
  guint8  valid;
  guint8  spare:4;
  guint8  addr_type:4;
  guint16 addr_len;
  guint8  addr[PFCP_MAX_REDIRECT_INFO_LEN];
}PfcpRedirectInfo; /*Note: Should not use as a stack variable to avoid stack overflow*/

typedef struct
{
  guint8  valid;
  PfcpDestIface dest_iface;
  PfcpPdnInstance pdn_instance;
  PfcpRedirectInfo redirect_info;
  PfcpOuterHeaderCreation outer_header_creation;
  PfcpTransportLevelMarking  transport_level_marking;
  PfcpForwPolicy forw_policy;
  PfcpInnerPacketMarking inner_packet_marking;
  PfcpTransportLevelMarkingOptions transport_level_marking_options;
  PfcpTrafficEndptId linkedTrafficEndptId;
  PfcpNextHopId NextHopId;
  PfcpLayer2Marking  layer2_marking;
}PfcpForwParams;

typedef struct
{
  guint8  valid;
  PfcpDestIface dest_iface;
  PfcpOuterHeaderCreation outer_header_creation;
  PfcpOuterHeaderCreation pdhir_outer_header_creation;
  PfcpIntrInfo intr_info;
  PfcpExtendedIntrInfo extended_intr_info;
}PfcpDuplParams;

typedef struct
{
 guint8      valid;
 guint8      numDuplParams;
 PfcpDuplParams  dupl_param[PFCP_MAX_DUPL_PARAMS];
}PfcpDuplParamsList;

typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpBarId;

typedef struct
{
  guint8  valid;
  PfcpFarId far_id;
  PfcpApplyAction apply_action;
  PfcpExtendedApplyAction ext_apply_action;
  PfcpForwParams  forw_params;
  PfcpDuplParams  dupl_params;
  PfcpDuplParamsList dupl_params_multi;
  PfcpBarId bar_id;
}PfcpCreateFar;

typedef struct
{ 
  guint8      valid;
  guint8      numCreateFar;
  PfcpCreateFar CreateFar[PFCP_MAX_CREATE_FAR];
}PfcpCreateFarList;

typedef struct
{
  guint8 valid;
  guint8 spare:5;
  guint8 qaurr:1;
  guint8 sndem:1;
  guint8 drobu:1;
}PfcpSxSmReqFlags;

typedef struct
{
  guint8  valid;
  PfcpPdrId pdr_id;
  PfcpOuterHeaderRemoval  outer_header_removal;
  PfcpPrecedence precedence;
  PfcpPdi pdi;
  PfcpFarId far_id;
  PfcpBliId bli_id;
  PfcpUrrIdList           pdr_urr_id_list;
  PfcpRuleName            rule_name;
  PfcpPredefRule  activate_predef_rule;
  PfcpPredefRule  deactivate_predef_rule;
  PfcpQerIdList           qer_id_list;
  PfcpStartTime           start_time;
  PfcpEndTime             end_time;
  PfcpSecondaryPdrId      secondary_pdr_id;
}PfcpUpdatePdr;

typedef struct
{
  guint8      valid;
  guint8      numUpdatePdr;
  PfcpUpdatePdr UpdatePdr[PFCP_MAX_UPDATE_PDR];
}PfcpUpdatePdrList;

typedef struct
{
  guint8  valid;
  PfcpPdrId pdr_id;
  PfcpSecondaryPdrId secondary_pdr_id;
}PfcpRemovePdr;

typedef struct
{
  guint8      valid;
  guint8      numRemovePdr;
  PfcpRemovePdr RemovePdr[PFCP_MAX_REMOVE_PDR];
}PfcpRemovePdrList;


typedef struct
{
  guint8  valid;
  PfcpDestIface dest_iface;
  PfcpPdnInstance pdn_instance;
  PfcpRedirectInfo redirect_info;
  PfcpOuterHeaderCreation outer_header_creation;
  PfcpTransportLevelMarking  transport_level_marking;
  PfcpForwPolicy forw_policy;
  PfcpSxSmReqFlags sx_smreq_flags;
  PfcpInnerPacketMarking inner_packet_marking;
  PfcpTransportLevelMarkingOptions transport_level_marking_options;
  PfcpTrafficEndptId linkedTrafficEndptId;
  PfcpLayer2Marking  layer2_marking;
}PfcpUpdateForwParams;

typedef struct
{
  guint8  valid;
  PfcpDestIface dest_iface;
  PfcpOuterHeaderCreation outer_header_creation;
  PfcpOuterHeaderCreation pdhir_outer_header_creation;
  PfcpIntrInfo intr_info;
  PfcpExtendedIntrInfo extended_intr_info;
}PfcpUpdateDuplParams;

typedef struct
{
 guint8      valid;
 guint8      numDuplParams;
 PfcpUpdateDuplParams  update_dupl_param[PFCP_MAX_DUPL_PARAMS];
}PfcpUpdateDuplParamsList;

typedef struct
{
  guint8  valid;
  PfcpFarId far_id;
  PfcpApplyAction apply_action;
  PfcpExtendedApplyAction ext_apply_action;
  PfcpUpdateForwParams update_forw_params;
  PfcpUpdateDuplParams update_dupl_params;
  PfcpUpdateDuplParamsList  update_dupl_params_multi;
  PfcpUpdateAddnlForwParams update_addnl_forw_params;
  PfcpBarId bar_id;
}PfcpUpdateFar;

typedef struct
{
  guint8      valid;
  guint8      numUpdateFar;
  PfcpUpdateFar UpdateFar[PFCP_MAX_UPDATE_FAR];
}PfcpUpdateFarList;


typedef struct
{
  guint8  valid;
  PfcpQerIdList qer_id;
  PfcpQerCorrelationId    qerCorrelationId;
  PfcpGateStatus          gateStatus;
  PfcpMbr                 mbr;
  PfcpGbr                 gbr;
  PfcpQfi                 qfi;
  PfcpBurst               burst;
  PfcpQGRAction           conform_action;
  PfcpQGRAction           exceed_action;
  PfcpAvgWindow           avgWindow;
  PfcpPpi                 ppi;
}PfcpUpdateQer;

typedef struct
{
  guint8      valid;
  guint8      numUpdateQer;
  PfcpUpdateQer UpdateQer[PFCP_MAX_UPDATE_QER];
}PfcpUpdateQerList;

typedef PfcpUrrList PfcpUpdateUrrList ;

typedef struct
{
  guint8  valid;
  PfcpPdrId pdr_id;
  PfcpFteid fteid;
}PfcpCreatedPdr;

typedef struct
{
  guint8      valid;
  guint8      numCreatedPdr;
  PfcpCreatedPdr CreatedPdr[PFCP_MAX_CREATED_PDR];
}PfcpCreatedPdrList;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpUrSeqn;

typedef struct
{
  guint8  valid;
  
  /*First octect*/
  guint8  immer:1;
  guint8  droth:1;
  guint8  stopt:1;
  guint8  start:1;
  guint8  quhti:1;
  guint8  timth:1;
  guint8  volth:1;
  guint8  perio:1;

  /*Second octect*/
  guint8  spare:2;
  guint8  envcl:1;
  guint8  monit:1;
  guint8  termr:1;
  guint8  liusa:1;
  guint8  timqu:1;
  guint8  volqu:1;
}PfcpUsageReportTrigger;

typedef struct
{
  guint8  valid;
  guint8  spare:5;
  guint8  dlvol:1;
  guint8  ulvol:1;
  guint8  tovol:1;
  guint64 total_volume;
  guint64 uplink_volume;
  guint64 downlink_volume;
}PfcpVolumeMeasurement;

typedef struct
{
  guint8  valid;
  guint8  spare:5;
  guint8  dlvol:1;
  guint8  ulvol:1;
  guint8  tovol:1;
  guint64 total_packet;
  guint64 uplink_packet;
  guint64 downlink_packet;
}PfcpPacketMeasurement;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpDurationMeasurement;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpTimeOfFirstPacket;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpTimeOfLastPacket;

typedef struct
{
  guint8  valid;
  guint8  spare:4;
  guint8  ube:1;
  guint8  uae:1;
  guint8  aft:1;
  guint8  bef:1;
}PfcpUsageInformation;

typedef struct
{
  guint8                  valid;
  PfcpUrrIdList           urr_id;
  PfcpUrSeqn              ur_seqn;
  PfcpUsageReportTrigger  usage_report_trigger;
  PfcpStartTime           start_time;
  PfcpEndTime             end_time;
  PfcpVolumeMeasurement   volume_measurement;
  PfcpPacketMeasurement   packet_measurement;
  PfcpDurationMeasurement duration_measurement;
  PfcpTimeOfFirstPacket   time_of_first_packet;
  PfcpTimeOfLastPacket    time_of_last_packet;
  PfcpUsageInformation    usage_information;
  PfcpAppDetectInfo       app_detect_info;
  PfcpRatingGrp           rating_grp;
  PfcpServiceId           service_id;
}PfcpUsageReport;

typedef struct
{
  guint8      valid;
  guint8      numUsageReport;
  PfcpUsageReport UsageReport[PFCP_MAX_USAGE_REPORT];
}PfcpUsageReportList;

typedef struct
{
  guint8 valid;
  guint8 spare:6;
  guint8 qfi_valid:1;
  guint8 ppi_valid:1;
  guint8 ppi_value;
  guint8 qfi_value;
}DlDataServiceInfo;

typedef struct
{
  guint8      valid;
  PfcpPdrId   pdr_id;
  DlDataServiceInfo dl_service_info;
}PfcpDnlkDataReport;

typedef struct
{
  guint8      valid;
  PfcpFteid   fteid;
}PfcpErrorIndReport;

typedef struct
{
  guint8      valid;
  guint8      gter:1;
  guint8      srir:1;
  guint8      spare:2;
  guint8      upir:1;
  guint8      erir:1;
  guint8      usar:1;
  guint8      dldr:1;
  guint8      msur:1;
  guint8      spter:1;
  guint8      uprr:1;
  guint8      nbur:1;
  guint8      tar:1;
  guint8      spare1:4;
}PfcpReportType;

typedef struct
{
  guint8                  valid;
  PfcpQueryUrrIdList      query_urr_id_list;
}PfcpQueryUrr;

typedef struct
{
  guint8 valid;
  guint8 spare:3;
  guint8 offline_urr:1;
  guint8 online_urr:1;
  guint8 radius_urr:1;
  guint8 bearer_urr:1;
  guint8 sess_urr:1;
}PfcpQueryInterface;

#define PFCP_ACS_MAX_GTPP_GROUP_NAME_LEN 64
#define PFCP_SESS_MAX_SERVICE_NAME_LEN 64 /* max service name len */
#define PFCP_MAX_VPN_CONTEXT_NAME_SIZE 80
#define PFCP_SESS_MAX_RADIUS_GROUP_NAME_LEN 64

typedef struct 
{
  guint8 valid;
  guint8         charging_chars[2];

  guint8         gtpp_group_name_len;
  guint8         gtpp_group_name[PFCP_ACS_MAX_GTPP_GROUP_NAME_LEN];
  guint32        gtpp_group_context_id ;

  guint8         cc_profile_name_len;
  guint8         cc_profile_name[PFCP_SESS_MAX_SERVICE_NAME_LEN];
  guint32        cc_profile_srv_type ;
  guint32        diam_acct_interim_interval ;

  guint8         aaa_group_name_len ;
  guint8         aaa_group_name[PFCP_SESS_MAX_RADIUS_GROUP_NAME_LEN];
  guint32        aaa_group_context_id ;
  guint32        rad_interim_interval;

  guint8         gy_offline_charging_enabled ;
  guint8         gtpp_dict ;

  guint8         cc_group_name_len;
  guint8         cc_group_name[ACS_MAX_DCCA_GROUP_NAME_LEN];

}PfcpChargingParams ;

typedef struct
{
  guint8 valid;
  guint8 value;

}PfcpSuggestedBuffPktCount;

typedef struct
{
  guint8 valid;
  guint16 value;

}PfcpDLBuffSuggestedPktCount;

typedef struct
{
  guint8 valid;
  guint8 value;

}PfcpDLDataNotificationDelay;

typedef struct
{
  guint8 valid;
  guint8 value;

}PfcpDLBuffDuration;

typedef struct
{
  guint8 valid;
  PfcpBarId bar_id;
  PfcpSuggestedBuffPktCount buff_pkt_count;

}PfcpCreateBar;

typedef struct
{
  guint8 valid;
  PfcpBarId bar_id;
  PfcpSuggestedBuffPktCount buff_pkt_count;
  PfcpDLDataNotificationDelay dl_data_notif_delay;

}PfcpUpdateBar;

typedef struct
{
  guint8 valid;
  PfcpBarId bar_id;

}PfcpRemoveBar;

typedef struct
{
  guint8 valid;
  PfcpBarId bar_id;
  PfcpDLDataNotificationDelay dl_data_notif_delay;
  PfcpDLBuffDuration dl_buffer_duration;
  PfcpDLBuffSuggestedPktCount dl_buff_pkt_count;
  PfcpSuggestedBuffPktCount buff_pkt_count;

}PfcpUpdateBarSessRepRsp;

typedef struct
{
  guint8 valid;
  guint32 seq_num;
}PfcpSeqNumber;

typedef struct
{
  guint8 valid;
  guint8 metric;
}PfcpMetric;

typedef struct
{
  guint8  valid;
  guint8  timer_value:5;
  guint8  timer_unit:3;

}PfcpValidityTime;

typedef struct
{
  guint8 valid;
  PfcpSeqNumber load_ctrl_seq_num;
  PfcpMetric    load_metric;
}PfcpLoadCntrlInfo;

typedef struct
{
  guint8 valid;
  PfcpSeqNumber overload_ctrl_seqNum;
  PfcpMetric red_metric;
  PfcpValidityTime timer;
  PfcpOciFlags            ociFlags;
}PfcpOverLoadCntrlInfo;

typedef struct
{
  guint8 valid;
  guint8 action;
  guint8 enable_vpptrace;
  guint8 pkt_cap_flag;
  guint8 pan_priority_flag;
  guint8 pan_meh_cap_flag;
  guint8 meh_header;
  guint8 priority;
  guint16 pkt_cap_size;
  guint8 display_control_info;
  guint8 display_data_info;
  char data_or_control_change;
  guint32 cli_instance_id;
  guint8 enabled_protocols[PFCP_MAX_ENABLED_PROTOCOL];
  guint8 enabled_protocols_id[PFCP_MONSUB_MAX_PROTOCOL_ID];
}PfcpMonitorSubscriber;


/*********************NBU Changes ******************/

typedef struct
{
  guint8 valid;
  PfcpIpAddr ipv4;
}PfcpNatIPAddress;

typedef struct
{
  guint8 valid;
  guint16 startPort;
  guint16 endPort;
}PfcpPortChunkInfo;

typedef struct
{
  guint8 valid;
  guint8 numPortChunkInfo;
  PfcpPortChunkInfo portChunkInfo[PFCP_MAX_PORT_CHUNK_INFO];
}PfcpPortChunkInfoList;


typedef struct
{
  guint8 valid;
  guint8 val;
}PfcpAllocationFlag;

typedef struct
{
  guint8 valid;
  guint16 val;
}PfcpNAPTNumUsersPerIP;

typedef struct
{
  guint8 valid;
  guint16 val;
}PfcpReleaseTimer;


typedef struct
{
  guint8 valid;
  PfcpNatIPAddress natIPAddress;
  PfcpPortChunkInfoList portChunkInfoList;
  PfcpAllocationFlag allocationFlag;
  PfcpNAPTNumUsersPerIP naptNumUsersPerIP;
  PfcpReleaseTimer releaseTimer;
}PfcpNBRInfo;

typedef struct {
  PfcpRuleName act_rule;
}PfcpActivateRule;

typedef struct
{
  guint8 valid;
  guint8 trigger_type;
  union {
      PfcpActivateRule activate_rule;
  }u;
}PfcpTriggerAction;

typedef struct
{
  guint8 valid;
  guint16 num_of_trigger_action;
  PfcpTriggerAction  trigger_action[PFCP_MAX_TRIGGER_ACTION];
}PfcpTriggerActionReport;


/*************************************************/

/* ------------------------------
 *  PFCP message definitions
 * ------------------------------ */

/* Session Establishment Request */
typedef struct
{
  PfcpFseid               fseid;
  PfcpCreatePdrList       createPdrList;
  PfcpCreateFarList       createFarList;
  PfcpUrrList             createUrrList;
  PfcpNshInfo             nsh_info;
  PfcpQGRInfoList         qgr_info_list;
  PfcpSubInfo             sub_info;
  PfcpUserID              user_id;
  PfcpSubParams           sub_params;
  PfcpCreateQerList       createQerList;
  PfcpCreateBar           createBar;
  PfcpIdleTimeout         IdleTimeout;
  PfcpChargingParams      charging_params;
  PfcpCreateTrafficEndptList createTrafficEndptList;
  PfcpNextHopIpAddr       createNextHopIpAddr;
  PfcpMonitorSubscriber   monitorSubscriber;
  PfcpCreateBliList       createBliList;
  PfcpUeIpVrf             ue_ip_vrf;
  PfcpGxAliasList         gxAliasList;
  /***********Warning**************
   * These members will not be memset to zero. 
   * Use proper Valid flag and Initialize to FALSE
   *******************************/
}PfcpSessEstabReq;


/* Session Establishment Response */
typedef struct
{
  PfcpCause               cause;
  PfcpOffendingIe         offendingIe;
  PfcpFseid               upFseid;
  PfcpCreatedPdrList      createdPdrList;
  PfcpLoadCntrlInfo       LCI;
  PfcpOverLoadCntrlInfo   OCI;
  PfcpFailedRuleId        failedRuleId;
  PfcpCreatedTrafficEndptList createdTrafficEndptList;
}PfcpSessEstabRsp;

typedef struct 
{
  guint8 valid;
  guint8 value;
}PfcpGyOfflineCharge;


/* Session Modification Request */
typedef struct
{
  PfcpFseid               cpFseid;
  
  PfcpRemovePdrList       removePdrList;
  PfcpRemoveFarList       removeFarList;
  PfcpRemoveUrrList       removeUrrList;
  PfcpRemoveQerList       removeQerList;
  PfcpRemoveBar           removeBar;
  PfcpCreatePdrList       createPdrList;
  PfcpCreateFarList       createFarList;
  PfcpUrrList             createUrrList;
  PfcpCreateQerList       createQerList;
  PfcpCreateBar           createBar;
  PfcpUpdatePdrList       updatePdrList;
  PfcpUpdateFarList       updateFarList;
  PfcpUpdateQerList       updateQerList;
  PfcpUpdateUrrList       updateUrrList;
  PfcpUpdateBar           updateBar;
  PfcpSxSmReqFlags        sxSmReqFlags;
  PfcpSubInfo             sub_info;
  PfcpSubParams           sub_params;
  PfcpQueryUrr            queryUrr;
  PfcpQueryInterface      queryIface;
  PfcpFailedRuleId        failedRuleId;
  PfcpGyOfflineCharge       gy_status;
  PfcpIdleTimeout         IdleTimeout;
  PfcpCreateBliList       createBliList;

  PfcpCreateTrafficEndptList createTrafficEndptList;
  PfcpUpdateTrafficEndptList updateTrafficEndptList;
  PfcpRemoveTrafficEndptList removeTrafficEndptList;
  PfcpMonitorSubscriber  monitorSubscriber;
  PfcpQGRInfoList             qgr_info_list;
  /* covers both addition/deletion of PDRs in GxAlias GoR */
  PfcpGxAliasList         gxAliasList;
  /***********Warning**************
   * These members will not be memset to zero. 
   * Use proper Valid flag and Initialize to FALSE
   *******************************/
}PfcpSessModReq;



/* Session Modification Response */
typedef struct
{
  PfcpCause               cause;
  PfcpOffendingIe         offendingIe;
  PfcpCreatedPdrList      createdPdrList;
  PfcpLoadCntrlInfo       LCI;
  PfcpOverLoadCntrlInfo   OCI;
  PfcpUsageReportList     usageReportList;
  PfcpFailedRuleId        failedRuleId;
  PfcpCreatedTrafficEndptList createdUpdatedTrafficEndptList;
}PfcpSessModRsp;


/* Session Deletion Response */
typedef struct
{
  PfcpCause               cause;
  PfcpOffendingIe         offendingIe;
  PfcpUsageReportList     usageReportList;
  PfcpLoadCntrlInfo       LCI;
  PfcpOverLoadCntrlInfo   OCI;
}PfcpSessDelRsp;

typedef struct
{
  guint8  cong_short_term;
  guint8  cong_longer_term;
  guint8  flag_throttle;
  guint32 count_accepted;
  guint32 count_rejected;
  guint32 disk_io_rate;
}PfcpMonSubStats;

/*Monitor Subscriber Report */
typedef struct
{
  guint8          valid;
  guint8          exit_code;
  guint32         cli_instance_id;
  PfcpMonSubStats stats;
}PfcpMonSubReport;

/* Session Report Request */
typedef struct
{
  PfcpReportType          reportType;
  PfcpUsageReportList     usageReportList;
  PfcpDnlkDataReport      dnlkDataReport;
  PfcpErrorIndReport      errorIndReport;
  PfcpLoadCntrlInfo       LCI;
  PfcpOverLoadCntrlInfo   OCI;
  PfcpMonSubReport        monsubReport;
  PfcpNBRInfo             NBRInfo;
  PfcpTriggerActionReport tarInfo;
}PfcpSessReportReq;


/* Session Report Response */
typedef struct
{
  PfcpCause               cause;
  PfcpOffendingIe         offendingIe;
  PfcpUpdateUrrList       updateUrrList;
  PfcpUpdateBarSessRepRsp updateBar;
#if 0
  PfcpSxSrRspFlags        sxSrRspFlags;
  PfcpCreatePdr           createPdr;
  PfcpLoadCntrlInfo       LCI;
  PfcpOverLoadCntrlInfo   OCI;
  PfcpUsageReport         usageReport;
#endif
}PfcpSessReportRsp;

typedef struct
{
  guint8 valid;
  guint8 Type;
  guint16 Length;
  guint8 Value[PFCP_MAX_PFD_CONTENT_LENGTH];
}PfcpContentTLV;


typedef struct
{
  guint8     valid;
  guint8     nodeid_type:4;
  PfcpIpAddr ipaddr;
}PfcpNodeId;

typedef struct
{ 
  guint8     valid;
  guint32    value;
}PfcpNodeCapability;

typedef struct
{
  guint8    valid;
  guint32   value;
}PfcpRecovTimeStamp;

typedef struct
{
  guint8    valid;
  guint32   peerVersion;
  guint32   starosGrVersion;
  gint8     len;
  char      star_os_version[PFCP_STAROS_VERSION_MAX];
}PfcpPeerVersion;

typedef struct
{
  guint8     valid;
  guint8     is_v6:1;
  guint8     is_v4:1;
  guint8     is_mpl:1;
  PfcpIpAddr ipv4;
  PfcpIpAddr ipv6;
  guint8     mpl;
}PfcpSrcIp;

typedef struct
{
  guint8     valid;
  guint8     sarr:1;
}PfcpSxAssociationReleaseRequest;

typedef struct
{
  guint8    valid;
  guint8    BUCP:1;
  guint8    DDND:1;
  guint8    DLBD:1;
  guint8    TRST:1;
  guint8    FTUP:1;
  guint8    PFDM:1;
  guint8    HEEU:1;
  guint8    TREU:1;
  guint8    EMPU:1;
  guint8    PDIU:1;
  guint8    UDBC:1;
  guint8    QUOAC:1;
  guint8    TRACE:1;
  guint8    FRRT:1;
}PfcpUpFuncFeature;

typedef struct
{
  guint8    valid;
  guint8    LOAD:1;
  guint8    OVRL:1;
}PfcpCpFuncFeature;

typedef struct
{
  guint8    valid;
  guint8    UPFR:1;
}PfcpNodeReportType;

typedef struct
{
  guint8  valid;
  guint32 val;
}PfcpUserPlaneId;


typedef struct
{
  PfcpNodeId          nodeId;
  PfcpRecovTimeStamp  recov_ts;
  PfcpNodeCapability  nodeCapability;
  PfcpUpFuncFeature   up_feature;
  PfcpCpFuncFeature   cp_feature;
  PfcpUserPlaneId     user_plane_id;
  PfcpPeerVersion     peer_version;
}PfcpAssociationSetupReq;

typedef struct
{
  PfcpNodeId       nodeId;
  PfcpCause        cause;
  PfcpRecovTimeStamp recov_ts;
  PfcpUpFuncFeature  up_feature;
  PfcpCpFuncFeature  cp_feature;
  PfcpPeerVersion    peer_version;
}PfcpAssociationSetupRsp;

typedef struct
{
  PfcpNodeId       nodeId;
  PfcpContentTLV   contentTLV;
  PfcpUplaneBusyOut  uplane_busy_out;
  PfcpSxAssociationReleaseRequest sxAssocRelReq;
  PfcpUpFuncFeature  up_feature;
  PfcpCpFuncFeature  cp_feature;
}PfcpAssociationUpdateReq;

typedef struct
{
  PfcpNodeId       nodeId;
  PfcpCause        cause;
  PfcpUpFuncFeature  up_feature;
  PfcpCpFuncFeature  cp_feature;
}PfcpAssociationUpdateRsp;

typedef struct
{
  PfcpNodeId       nodeId;
}PfcpAssociationReleaseReq;

typedef struct
{
  guint8 valid;
  PfcpRemoteGtpuPeer remoteGtpuPeer;
}PfcpUpPathFailReport;

typedef struct
{
  PfcpNodeId       nodeId;
  PfcpCause        cause;
}PfcpAssociationReleaseRsp;

typedef struct
{
  PfcpNodeId           nodeId;
  PfcpNodeReportType   repType;
  PfcpUpPathFailReport userPlanePathFailReport;
}PfcpNodeReportReq;

typedef struct
{
  PfcpNodeId       nodeId;
  PfcpCause        cause;
  PfcpOffendingIe  offendIe;
}PfcpNodeReportRsp;

typedef struct 
{
  guint8 valid;
  guint8 value;
}PfcpConfigAction;

typedef struct 
{
  guint8 valid;
  guint16 value;
}PfcpCorrelationId;

typedef struct
{
  guint8 valid;
  guint8 value;
}PfcpSubPartNumber;

typedef struct
{
  guint8 valid;
  guint8 value;
}PfcpSubPartIndex;

/*Prime PFD Management Request*/
typedef struct
{
  PfcpConfigAction         configAction;
  PfcpCorrelationId        correlationId;
  PfcpSubPartNumber        subPartNumber;
  PfcpSubPartIndex         subPartIndex;
  PfcpContentTLV           contentTLV;
}PfcpPrimePfdMgmtReq;

/*Prime PFD Management Response*/
typedef struct
{
  PfcpCause                cause;
  PfcpCorrelationId        correlationId;
  PfcpSubPartIndex        subPartIndex;
}PfcpPrimePfdMgmtRsp;


typedef struct
{
  guint8 valid;
  guint8 entity_type;
  guint8 spare:6;
  guint8 q_type:1;
  guint8 q_all:1;
  guint16 entity_name_len;
  guint8 entity_name[PFCP_MAX_ENTITY_NAME_LEN] ; //160b long entity_name
}PfcpQueryParams;

typedef struct
{
  guint8 valid;
  guint8 spare:6;
  guint8 num_classifier_valid:1;
  guint8 string_classifier_valid:1;
  guint16 classifier_type;
  guint32 num_classifier;
  guint16 string_classifier_len;
  guint8 string_classifier[PFCP_MAX_ENTITY_NAME_LEN] ; //160b long entity_name
}PfcpClassifierParams;

typedef struct
{
  guint8 valid;
  PfcpQueryParams query_params;
  PfcpClassifierParams classifier_params;
}PfcpNodeStatsRequest;

typedef struct
{
  guint8      valid;
  guint8      numStatsRequest;
  PfcpNodeStatsRequest StatsRequest[PFCP_MAX_STATS_REQUEST];
}PfcpNodeStatsRequestList;

typedef struct
{
  guint8 valid;
  guint8 entity_type;
  guint8 part_number;
  guint8 total_parts;
  guint16 data_len;
  guint8 data[PFCP_MAX_CONTENT_LENGTH];
}PfcpStatsResponse;

typedef struct
{
  guint8 valid;
  guint8 response_type;
  guint8 part_number;
  guint16 missing_parts_len;
  guint8 missing_parts[PFCP_MAX_CONTENT_LENGTH];
}PfcpStatsResponseAck;

typedef struct
{
  PfcpCorrelationId        correlationId;
  PfcpNodeStatsRequestList nodeStatsRequest;
}PfcpPrimeStatsQueryReq;

typedef struct
{
  PfcpCause                cause;
  PfcpOffendingIe          offendingIe;
  PfcpCorrelationId        correlationId;
  PfcpStatsResponse        statsResponse;
}PfcpPrimeStatsQueryRsp;

typedef struct
{
  PfcpCorrelationId        correlationId;
  PfcpStatsResponseAck     statsResponseAck;
}PfcpPrimeStatsQueryAck;

typedef struct
{
  PfcpRecovTimeStamp recoveryTimeStamp;
  PfcpPeerVersion    peer_version;
  PfcpSrcIp          srcip;
}PfcpHeartBeatReq;

typedef struct
{
  PfcpRecovTimeStamp recoveryTimeStamp;
}PfcpHeartBeatRsp;

typedef struct
{
    guint8  valid:1;
    guint16 len; 
    char    module_version[P2P_MODULE_MAX_VERSION]; 
}PfcpPluginVer;

typedef struct
{	
	PfcpPluginVer	pluginVersion;
}PfcpPluginVersionReq;

/* 
 * PFCP PDU stucture
 */
typedef struct
{
  guint8                        msgType;
  guint8                        is_encrypted;        
  union
  {
    PfcpSessEstabReq            sessEstabReq;         /* Session Establishment Request     */
    PfcpSessEstabRsp            sessEstabRsp;         /* Session Establishment Response    */
    PfcpSessModReq              sessModReq;           /* Session Modification Request      */
    PfcpSessModRsp              sessModRsp;           /* Session Modification Response     */
    //PfcpSessDelReq              sessDelReq;           /* Session Deletion Request          */
    PfcpSessDelRsp              sessDelRsp;           /* Session Deletion Response         */
    PfcpSessReportReq           sessReportReq;        /* Session Report Request            */
    PfcpSessReportRsp           sessReportRsp;        /* Session Report Response           */
    PfcpPrimePfdMgmtReq         primePfdMgmtReq;      /* Prime PFD Management Request      */
    PfcpPrimePfdMgmtRsp         primePfdMgmtRsp;      /* Prime PFD Management Response     */
    PfcpPrimeStatsQueryReq      primeStatsQueryReq;   /* Proprietary Stats Query Request   */
    PfcpPrimeStatsQueryRsp      primeStatsQueryRsp;   /* Proprietary Stats Query Response  */
    PfcpPrimeStatsQueryAck      primeStatsQueryAck;   /* Proprietary Stats Query Acknowledgement */
    PfcpAssociationSetupReq     associationSetupReq;  /* Sx Association Setup Request   */
    PfcpAssociationSetupRsp     associationSetupRsp;  /* Sx Association Setup Response  */
    PfcpAssociationUpdateReq    associationUpdateReq; /* Sx Association Update Request  */
    PfcpAssociationUpdateRsp    associationUpdateRsp; /* Sx Association Update Response */
    PfcpAssociationReleaseReq   associationReleaseReq; /*Sx Association Release Request */
    PfcpAssociationReleaseRsp   associationReleaseRsp; /*Sx Association Release Request */
    PfcpNodeReportReq           nodeReportReq;         /*Sx Node Report Request */
    PfcpNodeReportRsp           nodeReportRsp;         /*Sx Node Report Response */
    PfcpHeartBeatReq            heartBeatReq;         /* HeartBeat Request                 */
    PfcpHeartBeatRsp            heartBeatRsp;         /* HeartBeat Response                */
	PfcpPluginVersionReq		pluginVersionReq;	  /* Plugin version load request from CP to UP */
	/* To do: define this type for the response from UP to CP*/
	/*PfcpPluginVersionRsp		pluginVersionRsp*/	  /* Status response and plugin version loaded on UP*/
  }u;
}PfcpAllPdus;




/* ---------------------------
 *  PFCP header structure
 * --------------------------- */

typedef struct
{
  guint8     seid_valid:1;
  guint8     mp_valid:1;
  guint8     spare:3;
  guint8     version:3;
  guint8     interface_type:3;
  guint8     compression:1;
  guint8     msg_prio;
  guint8     msg_type;
  guint16    msg_length;
  guint16    hdr_length;
  guint32    seq_num;
  guint64    seid;
}PfcpHdr;

/* ---------------------------------------
 * Macros to memset individual fields of
 * PfcpAllPdus structure
 * --------------------------------------- */
void smc_sx_reset_sess_pdu(void *req, int mgs_type);
void smc_sx_reset_sess_modifreq_pdu(PfcpSessModReq *req);
void smc_sx_reset_sess_remove_traffic_endpoint_list(PfcpRemoveTrafficEndptList * ptr);

void
pfcp_reset_sx_sess_estab_req_msg(PfcpSessEstabReq *req, void *msg_ie_info);
void 
pfcp_reset_sx_sess_estab_rsp_msg(PfcpSessEstabRsp *rsp, void *msg_ie_info);
void
pfcp_sx_reset_sess_mod_req(PfcpSessModReq *sess_mod_req, void *ie_info);
void
pfcp_sx_reset_sess_mod_rsp(PfcpSessModRsp *sess_mod_rsp, void *ie_info);
void
pfcp_sx_reset_sess_report_req(PfcpSessReportReq *req, void *ie_info);
void
pfcp_sx_reset_sess_report_rsp(PfcpSessReportRsp *rsp, void *ie_info);
#endif  /* #ifndef __PFCP_IE_H__ */

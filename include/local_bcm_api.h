
#ifndef __LOCAL_BCM_API_H__
#define __LOCAL_BCM_API_H__ 1

/* Stat Group Mode Flags */
#define BCM_STAT_GROUP_MODE_INGRESS         0x00000001 /* Stat Group Mode
                                                          Ingress */
#define BCM_STAT_GROUP_MODE_EGRESS          0x00000002 /* Stat Group Mode Egress */

#define OPENNSL_STAT_GROUP_MODE_INGRESS BCM_STAT_GROUP_MODE_INGRESS
#define OPENNSL_STAT_GROUP_MODE_EGRESS BCM_STAT_GROUP_MODE_EGRESS

/* Counter Statistics Values */
typedef struct bcm_stat_value_s {
    uint32 packets;     /* packets value */
    uint64 bytes;       /* bytes value */
    uint64 packets64;   /* 64-bit accumulated packets value */
} bcm_stat_value_t;

/* Types of counters per L3 object. */
typedef enum bcm_l3_stat_e {
    bcmL3StatOutPackets = 0,
    bcmL3StatOutBytes = 1,
    bcmL3StatDropPackets = 2,
    bcmL3StatDropBytes = 3,
    bcmL3StatInPackets = 4,
    bcmL3StatInBytes = 5
} bcm_l3_stat_t;

#define opennsl_stat_value_t bcm_stat_value_t

#define opennslL3StatOutPackets bcmL3StatOutPackets
#define opennslL3StatOutBytes bcmL3StatOutBytes
#define opennslL3StatInPackets bcmL3StatInPackets
#define opennslL3StatInBytes bcmL3StatInBytes
#define opennslL3StatDropPackets bcmL3StatDropPackets
#define opennslL3StatDropBytes bcmL3StatDropBytes

typedef int bcm_if_t;

/* Get the specified counter statistic for a L3 egress interface */
extern int bcm_l3_egress_stat_counter_get(
    int unit,
    bcm_if_t intf_id,
    bcm_l3_stat_t stat,
    uint32 num_entries,
    uint32 *counter_indexes,
    bcm_stat_value_t *counter_values);

/* Get the specified counter statistic for a L3 ingress interface */
extern int bcm_l3_ingress_stat_counter_get(
    int unit,
    bcm_if_t intf_id,
    bcm_l3_stat_t stat,
    uint32 num_entries,
    uint32 *counter_indexes,
    bcm_stat_value_t *counter_values);

extern void bcm_stat_value_t_init(bcm_stat_value_t *stat_value);

#define opennsl_stat_value_t_init bcm_stat_value_t_init
#define opennsl_l3_ingress_stat_counter_get bcm_l3_ingress_stat_counter_get
#define opennsl_l3_egress_stat_counter_get bcm_l3_egress_stat_counter_get

/* Statistics Group Modes */
typedef enum bcm_stat_group_mode_e {
    bcmStatGroupModeSingle = 0,         /* A single counter used for all traffic
                                           types */
    bcmStatGroupModeTrafficType = 1,    /* A dedicated counter per traffic type
                                           Unicast, multicast, broadcast */
    bcmStatGroupModeDlfAll = 2,         /* A pair of counters where the base
                                           counter is used for dlf and the other
                                           counter is used for all traffic types */
    bcmStatGroupModeDlfIntPri = 3,      /* N+1 counters where the base counter
                                           is used for dlf and next N are used
                                           per Cos */
    bcmStatGroupModeTyped = 4,          /* A dedicated counter for unknown
                                           unicast, known unicast, multicast,
                                           broadcast */
    bcmStatGroupModeTypedAll = 5,       /* A dedicated counter for unknown
                                           unicast, known unicast, multicast,
                                           broadcast and one for all traffic(not
                                           already counted) */
    bcmStatGroupModeTypedIntPri = 6,    /* A dedicated counter for unknown
                                           unicast, known unicast,
                                           multicast,broadcast and N internal
                                           priority counters for traffic (not
                                           already counted) */
    bcmStatGroupModeSingleWithControl = 7, /* A single counter used for all traffic
                                           types with an additional counter for
                                           control traffic */
    bcmStatGroupModeTrafficTypeWithControl = 8, /* A dedicated counter per traffic type
                                           unicast, multicast, broadcast with an
                                           additional counter for control
                                           traffic */
    bcmStatGroupModeDlfAllWithControl = 9, /* A pair of counters where the base
                                           counter is used for control, the next
                                           one for dlf and the other counter is
                                           used for all traffic types */
    bcmStatGroupModeDlfIntPriWithControl = 10, /* N+2 counters where the base counter
                                           is used for control, the next one for
                                           dlf and next N are used per Cos */
    bcmStatGroupModeTypedWithControl = 11, /* A dedicated counter for control,
                                           unknown unicast, known unicast,
                                           multicast, broadcast */
    bcmStatGroupModeTypedAllWithControl = 12, /* A dedicated counter for control,
                                           unknown unicast, known
                                           unicast,multicast, broadcast and one
                                           for all traffic (not already counted) */
    bcmStatGroupModeTypedIntPriWithControl = 13, /* A dedicated counter for control,
                                           unknown unicast, known unicast,
                                           multicast, broadcast and N internal
                                           priority counters for traffic (not
                                           already counted) */
    bcmStatGroupModeDot1P = 14,         /* A set of 8(2^3) counters selected
                                           based on Vlan priority */
    bcmStatGroupModeIntPri = 15,        /* A set of 16(2^4) counters based on
                                           internal priority */
    bcmStatGroupModeIntPriCng = 16,     /* A set of 64 counters(2^(4+2)) based
                                           on Internal priority+CNG */
    bcmStatGroupModeSvpType = 17,       /* A set of 2 counters(2^1) based on SVP
                                           type */
    bcmStatGroupModeDscp = 18,          /* A set of 64 counters(2^6) based on
                                           DSCP bits */
    bcmStatGroupModeDvpType = 19,       /* A set of 2 counters(2^1) based on DVP
                                           type */
    bcmStatGroupModeCng = 20,           /* A set of 4 counters based on Pre IFP
                                           packet color bits */
    bcmStatGroupModeCount = 21          /* This should be the maximum value
                                           defined for the enum */
} bcm_stat_group_mode_t;

#define opennslStatGroupModeSingle bcmStatGroupModeSingle
#define opennslStatGroupModeTrafficType bcmStatGroupModeTrafficType

/* Ingress and Egress Statistics Accounting Objects */
typedef enum bcm_stat_object_e {
    bcmStatObjectIngPort = 0,           /* Ingress Port Object */
    bcmStatObjectIngVlan = 1,           /* Ingress Vlan Object */
    bcmStatObjectIngVlanXlate = 2,      /* Ingress Vlan Translate Object */
    bcmStatObjectIngVfi = 3,            /* Ingress VFI Object */
    bcmStatObjectIngL3Intf = 4,         /* Ingress L3 Interface Object */
    bcmStatObjectIngVrf = 5,            /* Ingress VRF Object */
    bcmStatObjectIngPolicy = 6,         /* Ingress Policy Object */
    bcmStatObjectIngFieldStageLookup = 6, /* Ingress VFP Object */
    bcmStatObjectIngMplsVcLabel = 7,    /* Ingress MPLS VC Label Object */
    bcmStatObjectIngMplsSwitchLabel = 8, /* Ingress MPLS Switch Label Object */
    bcmStatObjectIngMplsFrrLabel = 14,  /* Ingress MPLS Fast Reroute Label
                                           Object */
    bcmStatObjectIngL3Host = 15,        /* L3 Host without L3 Egress Object */
    bcmStatObjectIngTrill = 16,         /* Ingress Trill Object */
    bcmStatObjectIngMimLookupId = 17,   /* Ingress MiM I-SID Object */
    bcmStatObjectIngL2Gre = 18,         /* Ingress L2 GRE Object */
    bcmStatObjectIngEXTPolicy = 19,     /* Ingress external FP Object */
    bcmStatObjectIngFieldStageExternal = 19, /* Ingress external FP Object */
    bcmStatObjectIngVxlan = 24,         /* Ingress Vxlan Object */
    bcmStatObjectIngVsan = 25,          /* Ingress FCOE VSAN Object */
    bcmStatObjectIngFcoe = 26,          /* Ingress FCOE Object */
    bcmStatObjectIngL3Route = 27,       /* Ingress L2 Route Defip Object */
    bcmStatObjectIngNiv = 30,           /* Ingress Niv Object */
    bcmStatObjectIngIpmc = 32,          /* Ingress IPMC Object */
    bcmStatObjectEgrPort = 9,           /* Egress Port Object */
    bcmStatObjectEgrVlan = 10,          /* Egress Vlan Object */
    bcmStatObjectEgrVlanXlate = 11,     /* Egress Vlan Translate Object */
    bcmStatObjectEgrVfi = 12,           /* Egress VFI Object */
    bcmStatObjectEgrL3Intf = 13,        /* Egress L3 Interface Object */
    bcmStatObjectEgrWlan = 20,          /* Egress WLAN Object */
    bcmStatObjectEgrMim = 21,           /* Egress MiM Object */
    bcmStatObjectEgrMimLookupId = 22,   /* Egress MiM I-SID Object */
    bcmStatObjectEgrL2Gre = 23,         /* Egress L2 GRE Object */
    bcmStatObjectEgrVxlan = 28,         /* Egress Vxlan Object */
    bcmStatObjectEgrL3Nat = 29,         /* Egress L3 NAT Object */
    bcmStatObjectEgrNiv = 31,           /* Egress Niv Object */
    bcmStatObjectIngVxlanDip = 33,      /* Ingress Vxlan Dip Object */
    bcmStatObjectIngFieldStageIngress = 34, /* Ingress FP Object */
    bcmStatObjectEgrFieldStageEgress = 35, /* Egress FP Object */
    bcmStatObjectEgrMplsTunnelLabel = 36, /* Egress MPLS Tunnel Label */
    bcmStatObjectMaxValue = 37          /* This should be the maximum value
                                           defined in this enum */
} bcm_stat_object_t;

/* Packet type related flex attributes values */
typedef enum bcm_stat_group_mode_attr_pkt_type_e {
    bcmStatGroupModeAttrPktTypeAll = 1, /* All Packet Types */
    bcmStatGroupModeAttrPktTypeUnknown = 2, /* Unknown Packet */
    bcmStatGroupModeAttrPktTypeControl = 3, /* Control Packet */
    bcmStatGroupModeAttrPktTypeOAM = 4, /* OAM Packet */
    bcmStatGroupModeAttrPktTypeBFD = 5, /* BFD Packet */
    bcmStatGroupModeAttrPktTypeBPDU = 6, /* BPDU Packet */
    bcmStatGroupModeAttrPktTypeICNM = 7, /* ICNM Packet */
    bcmStatGroupModeAttrPktType1588 = 8, /* 1588 Packet */
    bcmStatGroupModeAttrPktTypeKnownL2UC = 9, /* Known L2 Unicast Packet */
    bcmStatGroupModeAttrPktTypeUnknownL2UC = 10, /* Unknown L2 Unicast Packet */
    bcmStatGroupModeAttrPktTypeL2BC = 11, /* L2 Broadcast Packet */
    bcmStatGroupModeAttrPktTypeKnownL2MC = 12, /* Known L2 Multicast Packet */
    bcmStatGroupModeAttrPktTypeUnknownL2MC = 13, /* Unknown L2 Multicast Packet */
    bcmStatGroupModeAttrPktTypeKnownL3UC = 14, /* Known L3 Unicast Packet */
    bcmStatGroupModeAttrPktTypeUnknownL3UC = 15, /* Unknown L3 Unicast Packet */
    bcmStatGroupModeAttrPktTypeKnownIPMC = 16, /* Known IPMC Packet */
    bcmStatGroupModeAttrPktTypeUnknownIPMC = 17, /* Unknown IPMC Packet */
    bcmStatGroupModeAttrPktTypeKnownMplsL2 = 18, /* Known MPLS L2 Packet */
    bcmStatGroupModeAttrPktTypeKnownMplsL3 = 19, /* Known MPLS L3 Packet */
    bcmStatGroupModeAttrPktTypeKnownMpls = 20, /* Known MPLS Packet */
    bcmStatGroupModeAttrPktTypeUnknownMpls = 21, /* Unknown MPLS Packet */
    bcmStatGroupModeAttrPktTypeKnownMplsMulticast = 22, /* Known MPLS Multicast Packet */
    bcmStatGroupModeAttrPktTypeKnownMim = 23, /* Known MiM Packet */
    bcmStatGroupModeAttrPktTypeUnknownMim = 24, /* Unknown MiM Packet */
    bcmStatGroupModeAttrPktTypeKnownTrill = 25, /* Known TRILL Packet */
    bcmStatGroupModeAttrPktTypeUnknownTrill = 26, /* Unknown TRILL Packet */
    bcmStatGroupModeAttrPktTypeKnownNiv = 27, /* Known  NIV Packet */
    bcmStatGroupModeAttrPktTypeUnknownNiv = 28 /* Unknown  NIV Packet */
} bcm_stat_group_mode_attr_pkt_type_t;

#define opennslStatGroupModeAttrPktTypeKnownL3UC bcmStatGroupModeAttrPktTypeKnownL3UC
#define opennslStatGroupModeAttrPktTypeUnknownL3UC bcmStatGroupModeAttrPktTypeUnknownL3UC
#define opennslStatGroupModeAttrPktTypeKnownIPMC bcmStatGroupModeAttrPktTypeKnownIPMC
#define opennslStatGroupModeAttrPktTypeUnknownIPMC bcmStatGroupModeAttrPktTypeUnknownIPMC

/* Stat Group Mode Attribute Selectors */
typedef enum bcm_stat_group_mode_attr_e {
    bcmStatGroupModeAttrColor = 1,      /* Color Selector: Possible
                                           Value:bcmColorGreen|Yellow|REd or
                                           oxFFFFFFFF */
    bcmStatGroupModeAttrFieldIngressColor = 2, /* Field Ingress Color Selector:
                                           Possible
                                           Values:bcmColorGreen|Yellow|REd or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrIntPri = 3,     /* Internal Priority Selector: Possible
                                           Values: 0 to 15 or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrVlan = 4,       /* Vlan Type Selector: Possible Values:
                                           bcmStatGroupModeVlanAttr */
    bcmStatGroupModeAttrOuterPri = 5,   /* Outer Vlan Priority Selector:
                                           Possible Values: 0 to 7 or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrInnerPri = 6,   /* Inner Vlan Priority Selector:
                                           Possible Values: 0 to 7 or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrPort = 7,       /* Logical Port Selector: Possible
                                           Values:<MaxLogicalPort> or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrTosDscp = 8,    /* Type Of Service Selector(DSCP :
                                           Differentiated services Code Point):
                                           Possible Values:<6b:TOS Val> or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrTosEcn = 9,     /* Type Of Service Selector(ECN:
                                           Explicit Congestion Notification):
                                           Possible Values:<2b:TOS Val> or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrPktType = 10,   /* Packet Type Selector: Possible
                                           Values:<bcmStatGroupModeAttrPktType*> */
    bcmStatGroupModeAttrIngNetworkGroup = 11, /* Ingress Network Group Selector:
                                           Possible Values:<Value> or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrEgrNetworkGroup = 12, /* Egress Network Group Selector:
                                           Possible Values:<Value> or
                                           STAT_GROUP_MODE_ATTR_ALL_VALUES for
                                           all */
    bcmStatGroupModeAttrDrop = 13,      /* Drop Selector: Possible Values:<0 or
                                           1> */
    bcmStatGroupModeAttrPacketTypeIp = 14 /* Ip Packet Selector: Possible
                                           Values:<0 or 1> */
} bcm_stat_group_mode_attr_t;

/* Stat Flex Group Attribute Selector */
typedef struct bcm_stat_group_mode_attr_selector_s {
    uint32 counter_offset;              /* Counter Offset */
    bcm_stat_group_mode_attr_t attr;    /* Attribute Selector */
    uint32 attr_value;                  /* Attribute Values */
} bcm_stat_group_mode_attr_selector_t;

#define opennslStatObjectEgrL3Intf bcmStatObjectEgrL3Intf
#define opennslStatObjectIngL3Intf bcmStatObjectIngL3Intf
#define opennslStatGroupModeAttrPktType bcmStatGroupModeAttrPktType
#define opennsl_stat_group_mode_attr_selector_t bcm_stat_group_mode_attr_selector_t

/* bcm_if_t */
typedef int bcm_if_t;

extern int bcm_stat_group_create(
    int unit,
    bcm_stat_object_t object,
    bcm_stat_group_mode_t group_mode,
    uint32 *stat_counter_id,
    uint32 *num_entries);

/* Attach counters entries to the given L3 Egress interface */
extern int bcm_l3_egress_stat_attach(
    int unit,
    bcm_if_t intf_id,
    uint32 stat_counter_id);

extern int bcm_l3_ingress_stat_attach(
    int unit,
    bcm_if_t intf_id,
    uint32 stat_counter_id);

/* Initialize an attribute selector of Stat Flex Group Mode */
extern void bcm_stat_group_mode_attr_selector_t_init(
    bcm_stat_group_mode_attr_selector_t *attr_selector);

/* Create Customized Stat Group mode for given Counter Attributes */
extern int bcm_stat_group_mode_id_create(
    int unit,
    uint32 flags,
    uint32 total_counters,
    uint32 num_selectors,
    bcm_stat_group_mode_attr_selector_t *attr_selectors,
    uint32 *mode_id);

/* Associate an accounting object to customized group mode */
extern int bcm_stat_custom_group_create(
    int unit,
    uint32 mode_id,
    bcm_stat_object_t object,
    uint32 *stat_counter_id,
    uint32 *num_entries);

#define opennsl_stat_group_create bcm_stat_group_create
#define opennsl_l3_egress_stat_attach bcm_l3_egress_stat_attach
#define opennsl_l3_ingress_stat_attach bcm_l3_ingress_stat_attach
#define opennsl_stat_group_mode_attr_selector_t_init bcm_stat_group_mode_attr_selector_t_init
#define opennsl_stat_group_mode_id_create bcm_stat_group_mode_id_create
#define opennsl_stat_custom_group_create bcm_stat_custom_group_create

#endif /* __LOCAL_BCM_API_H__ */

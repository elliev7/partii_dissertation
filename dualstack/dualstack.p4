/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_ARP      = 0x0806;
const bit<16> TYPE_IPV4     = 0x0800;
const bit<16> TYPE_IPV6     = 0x86DD;
const bit<8>  TYPE_ICMPv4   = 0x01;
const bit<8>  TYPE_ICMPV6   = 0x3A;
const bit<8>  TYPE_UDP      = 0x11;
const bit<8>  TYPE_TCP      = 0x06;

const bit<16> ARP_HTYPE     = 0x0001;
const bit<16> ARP_PTYPE     = TYPE_IPV4;
const bit<8>  ARP_HLEN      = 0x06;
const bit<8>  ARP_PLEN      = 0x04;
const bit<16> ARP_REQ       = 0x0001;
const bit<16> ARP_REPLY     = 0x0002;

const bit<8>  TYPE_ECHO_REP_V4  = 0x00;
const bit<8>  TYPE_DEST_UNR_V4  = 0x03;
const bit<8>  TYPE_REDIR_V4     = 0x05;
const bit<8>  TYPE_ECHO_REQ_V4  = 0x08;
const bit<8>  TYPE_ROU_ADV_V4   = 0x09;
const bit<8>  TYPE_ROU_SOL_V4   = 0x0A;
const bit<8>  TYPE_TIME_EXC_V4  = 0x0B;

const bit<8>  TYPE_DEST_UNR_V6  = 0x01;
const bit<8>  TYPE_PACK_BIG_V6  = 0x02;
const bit<8>  TYPE_TIME_EXC_V6  = 0x03;
const bit<8>  TYPE_PAR_PROB_V6  = 0x04;
const bit<8>  TYPE_ECHO_REQ_V6  = 0x80;
const bit<8>  TYPE_ECHO_REP_V6  = 0x81;
const bit<8>  TYPE_INFO_QUE_V6  = 0x8B;
const bit<8>  TYPE_INFO_RES_V6  = 0x8C;

const bit<8>  TYPE_MC_REP_V6    = 0x83;
const bit<8>  TYPE_MC_DONE_V6   = 0x84;
const bit<8>  TYPE_ROU_SOL_V6   = 0x85;
const bit<8>  TYPE_ROU_ADV_V6   = 0x86;
const bit<8>  TYPE_NEI_SOL_V6   = 0x87;
const bit<8>  TYPE_NEI_ADV_V6   = 0x88;
const bit<8>  TYPE_REDIR_V6     = 0x89;

typedef bit<9>   ingressSpec_t;
typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;
typedef bit<128> ip6Addr_t;

const ip6Addr_t IPV6r1  = 0xfe80000000000000a2cec8fffea20000;
const ip4Addr_t IPV4r1  = 0xa9fe0900;
const macAddr_t MACr1 = 0xa0cec8a26d15;
const ip6Addr_t IPV6r2  = 0xfe8000000000000002249bfffe800000;
const ip4Addr_t IPV4r2  = 0xa9febc00;
const macAddr_t MACr2 = 0x00249b807838;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
}

header arp_t {
    bit<16>     h_type;
    bit<16>     p_type;
    bit<8>      h_len;
    bit<8>      p_len;
    bit<16>     op_code;
    macAddr_t   src_mac;
    ip4Addr_t   src_ip;
    macAddr_t   dst_mac;
    ip4Addr_t   dst_ip;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     totalLen;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     fragOffset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdrChecksum;
    ip4Addr_t   srcAddr;
    ip4Addr_t   dstAddr;
}

header ipv6_t {
    bit<4>      version;
    bit<8>      trafficClass;
    bit<20>     flowLabel;
    bit<16>     payloadLen;
    bit<8>      nextHeader;
    bit<8>      hopLimit;
    ip6Addr_t   srcAddr;
    ip6Addr_t   dstAddr;
}

header_union ip_t {
    ipv4_t      ipv4;
    ipv6_t      ipv6;
}

header icmp_t {
    bit<8>      type;
    bit<8>      code;
    bit<16>     checksum;
}

header echo_t {
    bit<16>     identifier;
    bit<16>     seqNum;
    bit<448>    data;
}

header ndp_t {
    bit<1>      rFlag;
    bit<1>      sFlag;
    bit<1>      oFlag;
    bit<29>     reserved;
    bit<128>    trgAddr;
    bit<8>      optType;
    bit<8>      optLen;
    macAddr_t   llAddr;
}

header_union message_t {
    echo_t  echo;
    ndp_t   ndp;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t  ethernet;
    arp_t       arp;
    ip_t        ip;
    icmp_t      icmp;
    message_t   message;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.op_code) {
            TYPE_ARP_REQ: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ip.ipv4);
        transition select(hdr.ip.ipv4.protocol) {
            TYPE_ICMPV4: parse_icmpv4;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ip.ipv6);
        transition select(hdr.ip.ipv6.nextHeader) {
            TYPE_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_icmpv4 {
        packet.extract(hdr.icmp);
        transition select(hdr.icmp.type) {
            TYPE_ECHO_REQ_V4: parse_echo;
            default: accept;
        }
    }

    state parse_icmpv6 {
        packet.extract(hdr.icmp);
        transition select(hdr.icmp.type) {
            TYPE_ECHO_REQ_V6: parse_echo;
            TYPE_NEI_SOL: parse_ndp;
            default: accept;
        }
    }

    state parse_echo {
        packet.extract(hdr.message.echo);
        transition accept;
    }

    state parse_ndp {
        packet.extract(hdr.message.ndp);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { 
        verify_checksum(
            hdr.ip.ipv4.isValid(),
            { 
                hdr.ip.ipv4.version,
                hdr.ip.ipv4.ihl,
                hdr.ip.ipv4.diffserv,
                hdr.ip.ipv4.totalLen,
                hdr.ip.ipv4.identification,
                hdr.ip.ipv4.flags,
                hdr.ip.ipv4.fragOffset,
                hdr.ip.ipv4.ttl,
                hdr.ip.ipv4.protocol,
                hdr.ip.ipv4.srcAddr,
                hdr.ip.ipv4.dstAddr 
            },
            hdr.ip.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        verify_checksum(
            (hdr.ip.ipv4.isValid() && hdr.icmp.isValid() && hdr.message.echo.isValid()),
            {
                hdr.icmp.type,
                hdr.icmp.code,
                16w0,
                hdr.message.echo.identifier,
                hdr.message.echo.seqNum,
                hdr.message.echo.data
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );
        verify_checksum(
            (hdr.ip.ipv6.isValid() && hdr.icmp.isValid() && hdr.message.echo.isValid()),
            {
                hdr.ip.ipv6.srcAddr,
                hdr.ip.ipv6.dstAddr,
                hdr.ip.ipv6.payloadLen,
                24w0,
                hdr.ip.ipv6.nextHeader,
                hdr.icmp.type,
                hdr.icmp.code,
                hdr.message.echo.identifier,
                hdr.message.echo.seqNum,
                hdr.message.echo.data
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );
        verify_checksum(
            (hdr.ip.ipv6.isValid() && hdr.icmp.isValid() && hdr.message.ndp.isValid()),
            {
                hdr.ip.ipv6.srcAddr,
                hdr.ip.ipv6.dstAddr,
                hdr.ip.ipv6.payloadLen,
                24w0,
                hdr.ip.ipv6.nextHeader,
                hdr.icmp.type,
                hdr.icmp.code,
                hdr.message.ndp.rFlag,
                hdr.message.ndp.sFlag,
                hdr.message.ndp.oFlag,
                hdr.message.ndp.reserved,
                hdr.message.ndp.trgAddr,
                hdr.message.ndp.optType,
                hdr.message.ndp.optLen,
                hdr.message.ndp.llAddr
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action arp_reply(macAddr_t request_mac) {
        hdr.arp.op_code = TYPE_ARP_REP;
        hdr.arp.dst_mac = hdr.arp.src_mac;
        hdr.arp.src_mac = request_mac;
        
        bit<32> tmp_ip = hdr.arp.src_ip;
        hdr.arp.src_ip = hdr.arp.dst_ip;
        hdr.arp.dst_ip = tmp_ip;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = request_mac;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        if(hdr.ethernet.etherType == TYPE_IPV4){
            hdr.ip.ipv4.ttl = hdr.ip.ipv4.ttl - 1;
        }
        else {
            hdr.ip.ipv6.hopLimit = hdr.ip.ipv6.hopLimit - 1;
        }

        standard_metadata.egress_spec = port;
    }

    action echo_reply() {
        if(hdr.ethernet.etherType == TYPE_IPV4) {
            hdr.icmp.type = TYPE_ECHO_REP_V4;  
            bit<32> tmp_ip = hdr.ip.ipv4.srcAddr;
            hdr.ip.ipv4.srcAddr = hdr.ip.ipv4.dstAddr;
            hdr.ip.ipv4.dstAddr = tmp_ip;
            hdr.ip.ipv4.ttl = 255;
        }
        else {
            hdr.icmp.type = TYPE_ECHO_REP_V6;
            bit<128> tmp_ip = hdr.ip.ipv6.srcAddr;
            hdr.ip.ipv6.srcAddr = hdr.ip.ipv6.dstAddr;
            hdr.ip.ipv6.dstAddr = tmp_ip;
            hdr.ip.ipv6.hopLimit = 255;
        }

        hdr.icmp.checksum = 0;
        bit<48> tmp_mac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    
    action destination_unreachable(ingressSpec_t src) {
        bit<320> ipv6_datagram = hdr.ipv6.version ++ hdr.ipv6.trafficClass ++ hdr.ipv6.flowLabel 
                                ++ hdr.ipv6.payloadLen ++ hdr.ipv6.nextHeader ++ hdr.ipv6.hopLimit 
                                ++ hdr.ipv6.srcAddr ++ hdr.ipv6.dstAddr;
        bit<32> icmpv6_datagram = hdr.icmpv6.type ++ hdr.icmpv6.code ++ hdr.icmpv6.checksum;
        bit<480> echo_datagram = hdr.echo.identifier ++ hdr.echo.seqNum ++ hdr.echo.data;

        hdr.icmpv6.type = TYPE_DEST_UNR;
        hdr.icmpv6.checksum = 0;
        hdr.echo.identifier = 0;
        hdr.echo.seqNum = 0;
        hdr.echo.data = ipv6_datagram ++ icmpv6_datagram ++ echo_datagram[479:384];

        hdr.ipv6.dstAddr = hdr.ipv6.srcAddr;
        hdr.ipv6.hopLimit = 255;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;

        if (hdr.ipv6.srcAddr[127:16] == IPr2[127:16]){
            src == 2;
        }

        if(src == 1){
            hdr.ipv6.srcAddr = IPr1;
            hdr.ethernet.srcAddr = MACr1;
        }
        else {
            hdr.ipv6.srcAddr = IPr2;
            hdr.ethernet.srcAddr = MACr2;
        }

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action time_exceeded(ingressSpec_t src) {
        bit<320> ipv6_datagram = hdr.ip.ipv6.version ++ hdr.ip.ipv6.trafficClass ++ hdr.ip.ipv6.flowLabel 
                                ++ hdr.ip.ipv6.payloadLen ++ hdr.ip.ipv6.nextHeader ++ hdr.ip.ipv6.hopLimit 
                                ++ hdr.ip.ipv6.srcAddr ++ hdr.ip.ipv6.dstAddr;
        bit<32>  icmp_datagram = hdr.icmp.type ++ hdr.icmp.code ++ hdr.icmp.checksum;
        bit<480> echo_datagram = hdr.message.echo.identifier ++ hdr.message.echo.seqNum ++ hdr.message.echo.data;

        hdr.icmp.type = TYPE_TIME_EXC_V6;
        hdr.icmp.checksum = 0;
        hdr.message.echo.identifier = 0;
        hdr.message.echo.seqNum = 0;
        hdr.message.echo.data = ipv6_datagram ++ icmp_datagram ++ echo_datagram[479:384];

        hdr.ip.ipv6.dstAddr = hdr.ip.ipv6.srcAddr;
        hdr.ip.ipv6.hopLimit = 255;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;

        if(src == 1){
            hdr.ip.ipv6.srcAddr = IPV6r1;
            hdr.ethernet.srcAddr = MACr1;
        }
        else {
            hdr.ip.ipv6.srcAddr = IPV6r2;
            hdr.ethernet.srcAddr = MACr2;
        }

        standard_metadata.egress_spec = standard_metadata.ingress_port; 
    }

    action nei_adv(macAddr_t llAddr, ingressSpec_t src) {
        hdr.icmp.type = TYPE_NEI_ADV;
        hdr.icmp.checksum = 0;
        hdr.message.ndp.rFlag = 1;
        hdr.message.ndp.sFlag = 1;
        hdr.message.ndp.oFlag = 1;
        hdr.message.ndp.optType = 0x02;
        hdr.message.ndp.llAddr = llAddr;

        hdr.ip.ipv6.dstAddr = hdr.ip.ipv6.srcAddr;
        hdr.ip.ipv6.hopLimit = 255;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;

        if(src == 1){
            hdr.ip.ipv6.srcAddr = IPV6r1;
            hdr.ethernet.srcAddr = MACr1;
        }
        else {
            hdr.ip.ipv6.srcAddr = IPV6r2;
            hdr.ethernet.srcAddr = MACr2;
        }

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_responder {
        key = {
            hdr.arp.dst_ip: exact;
        }
        actions = {
            arp_reply;
            drop;
        }
        default_action = drop;
    }

    table ipv4_lpm {
        key = {
            hdr.ip.ipv4.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
    }

    table ipv6_lpm {
        key = {
            hdr.ip.ipv6.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = destination_unreachable(1);
    }

    table echo_responder_v4 {
        key = {
            hdr.ethernet.dstAddr: exact;
            hdr.ip.ipv4.dstAddr: exact;
        }
        actions = {
            echo_reply;
            drop;
        }
        default_action = drop();

        const entries = {
            (MACr1, IPV4r1): echo_reply;
            (MACr2, IPV4r2): echo_reply;
        }
    }

    table echo_responder_v6 {
        key = {
            hdr.ethernet.dstAddr: exact;
            hdr.ip.ipv6.dstAddr: exact;
        }
        actions = {
            echo_reply;
            drop;
        }
        default_action = drop();

        const entries = {
            (MACr1, IPV6r1): echo_reply;
            (MACr2, IPV6r2): echo_reply;
        }
    }

    table destination_unreachable_responder {
        key = {
            hdr.ipv6.srcAddr[127:16]: lpm;
        }
        actions = {
            time_exceeded;
            drop;
        }
        default_action = destination_unreachable(1);

        const entries = {
            IPr1[127:16]: destination_unreachable(1);
            IPr2[127:16]: destination_unreachable(2);
        }
    }

    table time_exceeded_responder {
        key = {
            hdr.ip.ipv6.srcAddr[127:16]: lpm;
        }
        actions = {
            time_exceeded;
            drop;
        }
        default_action = time_exceeded(1);

        const entries = {
            IPV6r1[127:16]: time_exceeded(1);
            IPV6r2[127:16]: time_exceeded(2);
        }
    }

    table nei_responder {
        key = {
            hdr.message.ndp.trgAddr: exact;
        }
        actions = {
            nei_adv;
            drop;
        }
        default_action = drop();
    }
    
    apply {
        if(hdr.arp.isValid()){
            arp_responder.apply();
        }
        else if(hdr.ip.ipv4.isValid()) {
            if(hdr.ip.ipv4.ttl > 1) {
                if(hdr.ip.ipv4.protocol == TYPE_ICMPV4) {
                    if(hdr.icmp.isValid()) {
                        if(hdr.icmp.type == TYPE_ECHO_REQ_V4) {
                            if(hdr.ip.ipv4.dstAddr == IPV4r1) {
                                echo_responder_v4.apply();
                            }
                            else if(hdr.ip.ipv4.dstAddr == IPV4r2) {
                                echo_responder_v4.apply();
                            }
                            else {
                                ipv4_lpm.apply();
                            }
                        }
                        else {
                            ipv4_lpm.apply();
                        }
                    }
                    else {
                        ipv4_lpm.apply();
                    }
                }
                else {
                    ipv4_lpm.apply();
                }
            }
            else {
                drop();
            }
        }
        else if(hdr.ip.ipv6.isValid()) {
            if(hdr.ip.ipv6.hopLimit > 1) {
                if (hdr.ipv6.nextHeader == TYPE_ICMPV6) {
                    if(hdr.icmp.isValid()) {
                        if (hdr.icmp.type == TYPE_ECHO_REQ_V6) {
                            if(hdr.ipv6.dstAddr == IPV6r1) {
                                echo_responder_v6.apply();
                            }
                            else if(hdr.ipv6.dstAddr == IPV6r2) {
                                echo_responder_v6.apply();
                            }
                            else {
                                ipv6_lpm.apply();
                            }
                        }
                        else if (hdr.icmp.type == TYPE_NEI_SOL) {
                            nei_responder.apply();
                        }
                        else {
                            ipv6_lpm.apply();
                        }
                    }
                    else {
                        ip6_lpm.apply();
                    }
                }
                else {
                    ipv6_lpm.apply();
                }
            }
            else {
                time_exceeded_responder.apply();
            }
        }
        else {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, 
                          inout metadata meta) {
     apply { 
        update_checksum(
            hdr.ip.ipv4.isValid(),
            { 
                hdr.ip.ipv4.version,
                hdr.ip.ipv4.ihl,
                hdr.ip.ipv4.diffserv,
                hdr.ip.ipv4.totalLen,
                hdr.ip.ipv4.identification,
                hdr.ip.ipv4.flags,
                hdr.ip.ipv4.fragOffset,
                hdr.ip.ipv4.ttl,
                hdr.ip.ipv4.protocol,
                hdr.ip.ipv4.srcAddr,
                hdr.ip.ipv4.dstAddr 
            },
            hdr.ip.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );
        update_checksum(
            (hdr.ip.ipv4.isValid() && hdr.icmp.isValid() && hdr.message.echo.isValid()),
            {
                hdr.icmp.type,
                hdr.icmp.code,
                16w0,
                hdr.message.echo.identifier,
                hdr.message.echo.seqNum,
                hdr.message.echo.data
            },
                hdr.icmp.checksum,
                HashAlgorithm.csum16
        );
        update_checksum(
            (hdr.ip.ipv6.isValid() && hdr.icmp.isValid() && hdr.message.echo.isValid()),
            {
                hdr.ip.ipv6.srcAddr,
                hdr.ip.ipv6.dstAddr,
                hdr.ip.ipv6.payloadLen,
                24w0,
                hdr.ip.ipv6.nextHeader,
                hdr.icmp.type,
                hdr.icmp.code,
                hdr.message.echo.identifier,
                hdr.message.echo.seqNum,
                hdr.message.echo.data
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );
        update_checksum(
            (hdr.ip.ipv6.isValid() && hdr.icmp.isValid() && hdr.message.ndp.isValid()),
            {
                hdr.ip.ipv6.srcAddr,
                hdr.ip.ipv6.dstAddr,
                hdr.ip.ipv6.payloadLen,
                24w0,
                hdr.ip.ipv6.nextHeader,
                hdr.icmp.type,
                hdr.icmp.code,
                hdr.message.ndp.rFlag,
                hdr.message.ndp.sFlag,
                hdr.message.ndp.oFlag,
                hdr.message.ndp.reserved,
                hdr.message.ndp.trgAddr,
                hdr.message.ndp.optType,
                hdr.message.ndp.optLen,
                hdr.message.ndp.llAddr
            },
            hdr.icmp.checksum,
            HashAlgorithm.csum16
        );
     }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, 
                   in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ip);
        packet.emit(hdr.icmp);
        packet.emit(hdr.message);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
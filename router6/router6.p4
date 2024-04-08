/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6     = 0x86DD;
const bit<8>  TYPE_ICMPV6   = 0x3A;
const bit<8>  TYPE_ECHO_REQ = 0x80;
const bit<8>  TYPE_ECHO_REP = 0x81;
const bit<8>  TYPE_TIME_EXC = 0x3;
const bit<8>  TYPE_NDP_SOL  = 0x87;
const bit<8>  TYPE_NDP_ADV  = 0x88;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<128> ip6Addr_t;

const ip6Addr_t IPr  = 0x00010000000000000002000300040005;
const macAddr_t MACr = 0xaa00aa00aa00;

header ethernet_t {
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
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

header icmpv6_t {
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
    ndp_t ndp;
}


struct metadata {
    /* empty */
}

struct headers {
    ethernet_t  ethernet;
    ipv6_t      ipv6;
    icmpv6_t    icmpv6;
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
          TYPE_IPV6: parse_ipv6;
        }
        
    }

    state parse_ipv6 {
      packet.extract(hdr.ipv6);
      transition select(hdr.ipv6.nextHeader) {
        TYPE_ICMPV6: parse_icmpv6;
        default: accept;
      }
    }

    state parse_icmpv6 {
      packet.extract(hdr.icmpv6);
      transition select(hdr.icmpv6.type) {
        TYPE_ECHO_REQ: parse_echo;
        TYPE_NDP_SOL: parse_ndp;
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
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.message.echo.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.message.echo.identifier,
                hdr.message.echo.seqNum,
                hdr.message.echo.data
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );

        verify_checksum(
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.message.ndp.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.message.ndp.rFlag,
                hdr.message.ndp.sFlag,
                hdr.message.ndp.oFlag,
                hdr.message.ndp.reserved,
                hdr.message.ndp.trgAddr,
                hdr.message.ndp.optType,
                hdr.message.ndp.optLen,
                hdr.message.ndp.llAddr
            },
            hdr.icmpv6.checksum,
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

    action forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit - 1;

        standard_metadata.egress_spec = port;
    }

    action echo_reply() {
        hdr.icmpv6.type = TYPE_ECHO_REP;
        hdr.icmpv6.checksum = 0;

	    bit<128> tmp_ip = hdr.ipv6.srcAddr;
        hdr.ipv6.srcAddr = hdr.ipv6.dstAddr;
        hdr.ipv6.dstAddr = tmp_ip;
        hdr.ipv6.hopLimit = 255;

        bit<48> tmp_mac = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = tmp_mac;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action time_exceeded() {
        bit<320> ipv6_datagram = hdr.ipv6.version ++ hdr.ipv6.trafficClass ++ hdr.ipv6.flowLabel ++ hdr.ipv6.payloadLen ++ hdr.ipv6.nextHeader ++ hdr.ipv6.hopLimit ++ hdr.ipv6.srcAddr ++ hdr.ipv6.dstAddr;
        bit<32>  icmpv6_datagram = hdr.icmpv6.type ++ hdr.icmpv6.code ++ hdr.icmpv6.checksum;
        bit<480> echo_datagram = hdr.message.echo.identifier ++ hdr.message.echo.seqNum ++ hdr.message.echo.data;

        hdr.icmpv6.type = TYPE_TIME_EXC;
        hdr.icmpv6.checksum = 0;
        hdr.message.echo.identifier = 0;
        hdr.message.echo.seqNum = 0;
        hdr.message.echo.data = ipv6_datagram ++ icmpv6_datagram ++ echo_datagram[479:384];

        hdr.ipv6.dstAddr = hdr.ipv6.srcAddr;
        hdr.ipv6.srcAddr = IPr;
        hdr.ipv6.hopLimit = 255;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = MACr;

        standard_metadata.egress_spec = standard_metadata.ingress_port; 
    }

    action ndp_adv(macAddr_t llAddr) {
        hdr.icmpv6.type = TYPE_NDP_ADV;
        hdr.icmpv6.checksum = 0;
        hdr.message.ndp.rFlag = 1;
        hdr.message.ndp.sFlag = 1;
        hdr.message.ndp.oFlag = 1;
        hdr.message.ndp.optType = 0x02;
        hdr.message.ndp.llAddr = llAddr;

        hdr.ipv6.dstAddr = hdr.ipv6.srcAddr;
        hdr.ipv6.srcAddr = IPr;
        hdr.ipv6.hopLimit = 255;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = MACr;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ipv6_lpm {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            forward;
            drop;
        }
        default_action = drop();
    }
    
    table echo_responder {
        key = {
            hdr.ethernet.dstAddr: exact;
            hdr.ipv6.dstAddr: exact;
        }
        actions = {
            echo_reply;
            drop;
        }
        default_action = drop();

        const entries = {
            (MACr, IPr): echo_reply;
        }
    }

    table ndp_responder {
        key = {
            hdr.message.ndp.trgAddr: exact;
        }
        actions = {
            ndp_adv;
            drop;
        }
        default_action = drop();
    }

    apply {
        if (hdr.ipv6.isValid()) {
            if(hdr.ipv6.hopLimit > 1) {
                if (hdr.ipv6.nextHeader == TYPE_ICMPV6 && hdr.icmpv6.isValid()) {
                    if (hdr.icmpv6.type == TYPE_ECHO_REQ && hdr.ipv6.dstAddr == IPr) {
                        echo_responder.apply();
                    }
                    else if (hdr.icmpv6.type == TYPE_NDP_SOL) {
                        ndp_responder.apply();
                    }
                    else {
                        ipv6_lpm.apply();
                    }
                }
                else {
                    ipv6_lpm.apply();
                }
            }
            else {
                time_exceeded();
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

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {  
        update_checksum(
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.message.echo.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.message.echo.identifier,
                hdr.message.echo.seqNum,
                hdr.message.echo.data
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );

        update_checksum(
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.message.ndp.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.message.ndp.rFlag,
                hdr.message.ndp.sFlag,
                hdr.message.ndp.oFlag,
                hdr.message.ndp.reserved,
                hdr.message.ndp.trgAddr,
                hdr.message.ndp.optType,
                hdr.message.ndp.optLen,
                hdr.message.ndp.llAddr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
     }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.icmpv6);
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
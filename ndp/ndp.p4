/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6 = 0x86DD;
const bit<8>  TYPE_ICMPV6 = 0x3A;
const bit<8>  TYPE_NDP_SOL = 0x87;
const bit<8>  TYPE_NDP_ADV = 0x88;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<128> ip6Addr_t;

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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t  ethernet;
    ipv6_t      ipv6;
    icmpv6_t    icmpv6;
    ndp_t       ndp;
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
      }
    }

    state parse_icmpv6 {
      packet.extract(hdr.icmpv6);
      transition select(hdr.icmpv6.type) {
        TYPE_NDP_SOL: parse_ndp;
      }
    }

    state parse_ndp {
      packet.extract(hdr.ndp);
      transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  
        verify_checksum(
            hdr.icmpv6.isValid(),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.rFlag,
                hdr.ndp.sFlag,
                hdr.ndp.oFlag,
                hdr.ndp.reserved,
                hdr.ndp.trgAddr,
                hdr.ndp.optType,
                hdr.ndp.optLen,
                hdr.ndp.llAddr
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
    

    action ndp_adv(macAddr_t llAddr) {
        hdr.icmpv6.type = TYPE_NDP_ADV;
        hdr.icmpv6.checksum = 0;
        hdr.ndp.rFlag = 1;
        hdr.ndp.sFlag = 1;
        hdr.ndp.oFlag = 1;
        hdr.ndp.optType = 0x02;
        hdr.ndp.llAddr = llAddr;

        hdr.ipv6.dstAddr = hdr.ipv6.srcAddr;
        hdr.ipv6.srcAddr = 0x00010000000000000002000300040005;
        hdr.ipv6.hopLimit = 255;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = 0xaa00aa00aa00;

        standard_metadata.egress_port = standard_metadata.ingress_port;
    }
    
    table ndp_responder {
        key = {
            hdr.ndp.trgAddr: exact;
        }
        actions = {
            ndp_adv;
            drop;
            NoAction;
        }
        default_action = drop();
    }

    apply {
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.hopLimit > 1) {            
                if (hdr.icmpv6.isValid()) {
                    if (hdr.icmpv6.type == TYPE_NDP_SOL) {
                        ndp_responder.apply();
                    }
                    else {
                        drop();
                    }
                }
                else {
                    drop();
                }
            }
            else {
                drop();
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
            hdr.icmpv6.isValid(),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.ndp.rFlag,
                hdr.ndp.sFlag,
                hdr.ndp.oFlag,
                hdr.ndp.reserved,
                hdr.ndp.trgAddr,
                hdr.ndp.optType,
                hdr.ndp.optLen,
                hdr.ndp.llAddr
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
        packet.emit(hdr.ndp);
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
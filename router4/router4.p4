/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4     = 0x0800;
const bit<16> TYPE_ARP      = 0x0806;
const bit<16> TYPE_ARP_REQ  = 0x0001;
const bit<16> TYPE_ARP_REP  = 0x0002;
const bit<8>  TYPE_ICMP     = 0x01;
const bit<8>  TYPE_ECHO_REQ = 0x08;
const bit<8>  TYPE_ECHO_REP = 0x00;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>   egressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<32>  ip4Addr_t;

const ip4Addr_t IPr  = 0x0102032d;
const macAddr_t MACr = 0xaa00aa00aa00;

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

header icmp_t {
    bit<8>      type;
    bit<8>      code;
    bit<16>     checksum;
    bit<16>     identifier;
    bit<16>     seqNum;
    bit<448>    data;
}

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t   ethernet;
    arp_t        arp;
    ipv4_t       ipv4;
    icmp_t       icmp;
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
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition select(hdr.arp.op_code) {
            TYPE_ARP_REQ: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        verify_checksum(
            hdr.icmp.isValid(),
            {
                hdr.icmp.type,
                hdr.icmp.code,
                16w0,
                hdr.icmp.identifier,
                hdr.icmp.seqNum,
                hdr.icmp.data
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
        hdr.arp.src_ip = hdr.arp.dst_ip;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = request_mac;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;

        standard_metadata.egress_spec = port;
    }

    action echo_reply() {
        hdr.icmp.type = TYPE_ECHO_REP;
        hdr.icmp.checksum = 0;

	    bit<32> tmp_ip = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = tmp_ip;
        hdr.ipv4.ttl = 255;

        bit<48> tmp_mac = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp_mac;

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
            hdr.ipv4.dstAddr: lpm;
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
            hdr.ipv4.dstAddr: exact;
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

    apply {
        if(hdr.arp.isValid()){
            arp_responder.apply();
        }
        else if (hdr.ipv4.isValid() && hdr.ipv4.ttl > 1) {
                if (hdr.icmp.isValid() && hdr.icmp.type == TYPE_ECHO_REQ && hdr.ipv4.dstAddr == IPr){
                    echo_responder.apply();
                }
                else {
                    ipv4_lpm.apply();
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

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { 
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr 
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum(
            hdr.icmp.isValid(),
            {
                hdr.icmp.type,
                hdr.icmp.code,
                16w0,
                hdr.icmp.identifier,
                hdr.icmp.seqNum,
                hdr.icmp.data
            },
                hdr.icmp.checksum,
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
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
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
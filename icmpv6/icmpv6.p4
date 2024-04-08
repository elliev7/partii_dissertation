/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6     = 0x86DD;
const bit<8>  TYPE_ICMPV6   = 0x3A;
const bit<8>  TYPE_ECHO_REQ = 0x80;
const bit<8>  TYPE_ECHO_REP = 0x81;
const bit<8>  TYPE_TIME_EXC = 0x3;

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

struct metadata {
    /* empty */
}

struct headers {
    ethernet_t  ethernet;
    ipv6_t      ipv6;
    icmpv6_t    icmpv6;
    echo_t      echo;
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
            TYPE_ECHO_REQ: parse_echo;
        }
    }

    state parse_echo {
        packet.extract(hdr.echo);
        transition accept;
    }
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  
        verify_checksum(
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.echo.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.echo.identifier,
                hdr.echo.seqNum,
                hdr.echo.data
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

    action time_exceeded() {
        bit<320> ipv6_datagram = hdr.ipv6.version ++ hdr.ipv6.trafficClass ++ hdr.ipv6.flowLabel ++ hdr.ipv6.payloadLen ++ hdr.ipv6.nextHeader ++ hdr.ipv6.hopLimit ++ hdr.ipv6.srcAddr ++ hdr.ipv6.dstAddr;
        bit<32> icmpv6_datagram = hdr.icmpv6.type ++ hdr.icmpv6.code ++ hdr.icmpv6.checksum;
        bit<480> echo_datagram = hdr.echo.identifier ++ hdr.echo.seqNum ++ hdr.echo.data;

        hdr.icmpv6.type = TYPE_TIME_EXC;
        hdr.icmpv6.checksum = 0;
        hdr.echo.identifier = 0;
        hdr.echo.seqNum = 0;
        hdr.echo.data = ipv6_datagram ++ icmpv6_datagram ++ echo_datagram[479:384];

        hdr.ipv6.dstAddr = hdr.ipv6.srcAddr;
        hdr.ipv6.srcAddr = IPr;
        hdr.ipv6.hopLimit = 255;

        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = MACr;

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    apply {
        if (hdr.ipv6.isValid()) {
            if (hdr.ipv6.hopLimit > 1) {            
                if (hdr.icmpv6.isValid() && hdr.icmpv6.type == TYPE_ECHO_REQ) {
                    echo_responder.apply();
                }
                else {
                    drop();
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
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.echo.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.echo.identifier,
                hdr.echo.seqNum,
                hdr.echo.data
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
        packet.emit(hdr.echo);
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
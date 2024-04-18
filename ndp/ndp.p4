/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV6    = 0x86DD;
const bit<8>  TYPE_ICMPV6  = 0x3A;
const bit<8>  TYPE_UDP     = 0x11;
const bit<8>  TYPE_TCP     = 0x06;

const bit<8>  TYPE_MC_REP  = 0x83;
const bit<8>  TYPE_MC_DONE = 0x84;
const bit<8>  TYPE_ROU_SOL = 0x85;
const bit<8>  TYPE_ROU_ADV = 0x86;
const bit<8>  TYPE_NEI_SOL = 0x87;
const bit<8>  TYPE_NEI_ADV = 0x88;
const bit<8>  TYPE_REDIR   = 0x89;

typedef bit<9>   ingressSpec_t;
typedef bit<48>  macAddr_t;
typedef bit<128> ip6Addr_t;

const ip6Addr_t IPr1  = 0xfe80000000000000a2cec8fffea20000;
const macAddr_t MACr1 = 0xa0cec8a26d15;
const ip6Addr_t IPr2  = 0xfe8000000000000002249bfffe800000;
const macAddr_t MACr2 = 0x00249b807838;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header ethernet_t 
{
    macAddr_t   dstAddr;
    macAddr_t   srcAddr;
    bit<16>     etherType;
}

header ipv6_t 
{
    bit<4>      version;
    bit<8>      trafficClass;
    bit<20>     flowLabel;
    bit<16>     payloadLen;
    bit<8>      nextHeader;
    bit<8>      hopLimit;
    ip6Addr_t   srcAddr;
    ip6Addr_t   dstAddr;
}

header icmpv6_t 
{
    bit<8>      type;
    bit<8>      code;
    bit<16>     checksum;
}

header nei_t 
{
    bit<1>      rFlag;
    bit<1>      sFlag;
    bit<1>      oFlag;
    bit<29>     reserved;
    bit<128>    trgAddr;
    bit<8>      optType;
    bit<8>      optLen;
    macAddr_t   llAddr;
}

struct metadata 
{
    /* empty */
}

struct headers 
{
    ethernet_t  ethernet;
    ipv6_t      ipv6;
    icmpv6_t    icmpv6;
    nei_t       nei;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) 
{
    state start 
    {
        transition parse_ethernet;
    }

    state parse_ethernet 
    {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) 
        {
            TYPE_IPV6: parse_ipv6;
        }
    }

    state parse_ipv6 
    {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHeader) 
        {
            TYPE_ICMPV6: parse_icmpv6;
        }
    }

    state parse_icmpv6 
    {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type) 
        {
            TYPE_NEI_SOL: parse_nei;
        }
    }

    state parse_nei 
    {
        packet.extract(hdr.nei);
        transition accept;
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) 
{
    apply 
    {  
        verify_checksum(
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.nei.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.nei.rFlag,
                hdr.nei.sFlag,
                hdr.nei.oFlag,
                hdr.nei.reserved,
                hdr.nei.trgAddr,
                hdr.nei.optType,
                hdr.nei.optLen,
                hdr.nei.llAddr
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
                  inout standard_metadata_t standard_metadata) 
{
    action drop() 
    {
        mark_to_drop(standard_metadata);
    }  

    action nei_adv(macAddr_t llAddr, ingressSpec_t src) 
    {
        hdr.icmpv6.type = TYPE_NEI_ADV;
        hdr.icmpv6.checksum = 0;
        hdr.nei.rFlag = 1;
        hdr.nei.sFlag = 1;
        hdr.nei.oFlag = 1;
        hdr.nei.optType = 0x02;
        hdr.nei.llAddr = llAddr;

        hdr.ipv6.dstAddr = hdr.ipv6.srcAddr;
        hdr.ipv6.hopLimit = 255;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;

        if(src == 1)
        {
            hdr.ipv6.srcAddr = IPr1;
            hdr.ethernet.srcAddr = MACr1;
        }
        else 
        {
            hdr.ipv6.srcAddr = IPr2;
            hdr.ethernet.srcAddr = MACr2;
        }

        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }
    
    table nei_responder 
    {
        key = {
            hdr.nei.trgAddr: exact;
        }
        actions = {
            nei_adv;
            drop;
        }
        default_action = drop();
    }

    apply 
    {
        if(hdr.ipv6.isValid()) 
        {
            if(hdr.ipv6.hopLimit > 1) 
            {
                if(hdr.icmpv6.isValid() && hdr.icmpv6.type == TYPE_NEI_SOL) 
                {
                    nei_responder.apply();
                }
                else 
                {
                    drop();
                }
            }
            else 
            {
                drop();
            }
        }
        else 
        {
            drop();
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) 
{
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) 
{
     apply 
     {
        update_checksum(
            (hdr.ipv6.isValid() && hdr.icmpv6.isValid() && hdr.nei.isValid()),
            {
                hdr.ipv6.srcAddr,
                hdr.ipv6.dstAddr,
                hdr.ipv6.payloadLen,
                24w0,
                hdr.ipv6.nextHeader,
                hdr.icmpv6.type,
                hdr.icmpv6.code,
                hdr.nei.rFlag,
                hdr.nei.sFlag,
                hdr.nei.oFlag,
                hdr.nei.reserved,
                hdr.nei.trgAddr,
                hdr.nei.optType,
                hdr.nei.optLen,
                hdr.nei.llAddr
            },
            hdr.icmpv6.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) 
{
    apply 
    {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.icmpv6);
        packet.emit(hdr.nei);
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
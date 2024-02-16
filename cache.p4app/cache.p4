/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8> TYPE_UDP = 0x11; 
//This is 0d1234 in hex 
const bit<16> REQ_PORT = 0x4D2; 
struct metadata { }

typedef bit<9>  egressSpec_t;
typedef bit<16> portAddr_t; 
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header req_t {
    bit<8> key; 
}

header resp_t {
    bit<8> key; 
    bit<8> valid_resp; 
    bit<32> value; 
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t{
    portAddr_t srcPort; 
    portAddr_t dstPort; 
    bit<16>    len; 
    bit<16>    checkSum; 
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    udp_t        udp; 
    req_t        req; 
    resp_t       resp; 
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start { transition parse_ethernet; }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp; 
            default: accept; 
        }
    }
    state parse_udp{
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
           REQ_PORT: parse_req;  
           default: parse_resp_option; 
        }
    }  
    state parse_req{
        packet.extract(hdr.req); 
        transition accept; 
    }
    state parse_resp_option{
        transition select(hdr.udp.srcPort) {
           REQ_PORT: parse_resp;  
           default: accept; 
        }
    }
    state parse_resp{
        packet.extract(hdr.resp); 
        transition accept; 
    }

}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply { }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    register<bit<40>>(256) reg_cache; 
    action cache_hit(bit<8> valid_val, bit<32> val){
        //Swap the IP Addresses + Mac addresses. Set UDP check sum to 0? update Value to be 0 chance req --> resp header  
        ip4Addr_t temp = hdr.ipv4.dstAddr; 
        hdr.ipv4.dstAddr = hdr.ipv4.srcAddr;  
        hdr.ipv4.srcAddr = temp; 
        hdr.udp.dstPort = hdr.udp.srcPort; 
        hdr.udp.srcPort = 1234; //This makes it a response header?  
        hdr.udp.len = hdr.udp.len + 5; 
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 5; 
        hdr.udp.checkSum = 0; 
        hdr.resp.setValid(); 
        hdr.resp.key = hdr.req.key; 
        hdr.resp.valid_resp = valid_val; 
        hdr.resp.value = val; 
        hdr.req.setInvalid(); 
        log_msg("cache hit {}, udp Len: {}, IP Len: {} \n", {val, hdr.udp.len, hdr.ipv4.totalLen}); 
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }
    table key_cache{
        key = {
            hdr.req.key: exact; 
       }
        actions = {
        cache_hit; 
        NoAction; 
       }   
        size = 1024; 
        default_action = NoAction; 
       }
    apply {
        if(hdr.resp.isValid()){
            log_msg("Valid resp header = key: {}, valid: {}, value: {}, UDP len: {}, IP len: {}\n", {hdr.resp.key, hdr.resp.valid_resp, hdr.resp.value,hdr.udp.len, hdr.ipv4.totalLen}); 
            //Write it into the register cache 
           bit<40> temp = (((bit<40>)hdr.resp.value << 8) | (bit<40>)hdr.resp.valid_resp); 
           reg_cache.write((bit<32>) hdr.resp.key,temp);  
        }
        else if(hdr.req.isValid()){
            //Check table cache 
            key_cache.apply(); 
            //Check Register cache 
            bit<40> temp; 
            reg_cache.read(temp,(bit<32>) hdr.req.key); 
            bit<8> valid_val =(bit<8>) (temp & 0xFF); 
            bit<32> val = (bit<32>)(temp >> 8);  
            log_msg("Valid req header = {} , UDP len: {}, IP len: {}\n", {val, hdr.udp.len, hdr.ipv4.totalLen}); 
            if(valid_val != 0){
                cache_hit(valid_val, val); 
            }
        } 
        if (hdr.ipv4.isValid()) {
            log_msg("Valid IP msg src= {}, dst = {}",{hdr.ipv4.srcAddr,hdr.ipv4.dstAddr} ); 
            ipv4_lpm.apply();
        }
        
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp); 
        packet.emit(hdr.resp); 
        packet.emit(hdr.req); 
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

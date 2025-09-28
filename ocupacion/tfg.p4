#include <core.p4>
#include <v1model.p4>

// ==================== CONSTANTES ====================
const bit<16> TYPE_IPV4     = 0x800;    // EtherType para IPv4
const bit<5>  IPV4_OPTION_MRI = 31;

#define MAX_HOPS 9

// ==================== TIPOS BÁSICOS =================
typedef bit<9>  egressSpec_t;   // Puerto de salida (BMv2 usa 9 bits)
typedef bit<48> macAddr_t;      // Dirección MAC
typedef bit<32> ip4Addr_t;      // Dirección IPv4
typedef bit<32> switchID_t;     // ID Switch
typedef bit<32> qdepth_t;       // Ocupacion de la cola

// ==================== CABECERAS =====================
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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

header ipv4_option_t { //para poder empaquetar bien cuando usemos mri y swtraces
    bit<1> copyFlag;
    bit<2> optClass;
    bit<5> option;
    bit<8> optionLength;
}

header mri_t {
    bit<16> count; //cuantas entradas de switch_t lleva el paquete
}

header switch_t {
    switchID_t swid;  //ID del switch
    qdepth_t   qdepth;  //Ocupacion de la cola en un switch
}

struct ingress_metadata_t {
    bit<16>  count;
 }

struct parser_metadata_t {
    bit<16>  remaining;
}

struct metadata {
    ingress_metadata_t  ingress_metadata;
    parser_metadata_t   parser_metadata;
}

struct headers {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    ipv4_option_t ipv4_option;
    mri_t         mri;
    switch_t[MAX_HOPS] swtraces;
}

error { IPHeaderTooShort }

// ==================== PARSER ========================
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata){

    state start { transition parse_ethernet; }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default  : accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.ihl) {
            5       : accept;
            default : parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        packet.extract(hdr.ipv4_option);
        transition select(hdr.ipv4_option.option) {
            IPV4_OPTION_MRI: parse_mri;
            default        : accept;
        }
    }

    state parse_mri {
        packet.extract(hdr.mri);
        meta.parser_metadata.remaining = hdr.mri.count;
        transition select(meta.parser_metadata.remaining) {
            0       : accept;
            default : parse_swtrace;
        }
    }

    state parse_swtrace {
        packet.extract(hdr.swtraces.next);
        meta.parser_metadata.remaining = meta.parser_metadata.remaining - 1;
        transition select(meta.parser_metadata.remaining) {
            0       : accept;
            default : parse_swtrace;
        }
    }
}

//===================== CHECKSUM ======================
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

// ==================== INGRESS =======================
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    action drop() { mark_to_drop(standard_metadata); }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1; // decrementa TTL
    }

    action ipv4_clone(macAddr_t dstAddr, egressSpec_t port) {
	hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        standard_metadata.egress_spec = port;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1; // decrementa TTL
	clone(CloneType.I2E, 99);
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { ipv4_forward; ipv4_clone; drop; NoAction; }
        size = 1024;
        default_action = NoAction();
    }



    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

// ==================== EGRESS ========================
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata){

    action add_swtrace(switchID_t swid) {
        hdr.mri.count = hdr.mri.count + 1;             // incrementa el contador
        hdr.swtraces.push_front(1);                    // reserva hueco para 1 hop
        hdr.swtraces[0].setValid();                    // marca válido el nuevo hop
        hdr.swtraces[0].swid   = swid;                 // id del switch actual
        hdr.swtraces[0].qdepth = (qdepth_t)standard_metadata.deq_qdepth; // ocupación
        // ajusta longitudes (8B por hop = 2 palabras de 32b)
        hdr.ipv4.ihl                 = hdr.ipv4.ihl + 2;
        hdr.ipv4_option.optionLength = hdr.ipv4_option.optionLength + 8;
        hdr.ipv4.totalLen            = hdr.ipv4.totalLen + 8;
    }

    
    // Elimina toda la cabecera MRI + trazas y ajusta IPv4
    action strip_mri_all() {
        if (hdr.mri.isValid()) {
            bit<16> hops = hdr.mri.count;
            bit<16> bytes_to_remove = (hops * 8) + 4;         // total
            bit<8>  words_to_remove = (bit<8>)(2 * hops + 1); // palabra de 32

            if (hops > 0) { hdr.swtraces[0].setInvalid(); }
            if (hops > 1) { hdr.swtraces[1].setInvalid(); }
            if (hops > 2) { hdr.swtraces[2].setInvalid(); }
            if (hops > 3) { hdr.swtraces[3].setInvalid(); }
            if (hops > 4) { hdr.swtraces[4].setInvalid(); }
            if (hops > 5) { hdr.swtraces[5].setInvalid(); }
            if (hops > 6) { hdr.swtraces[6].setInvalid(); }
            if (hops > 7) { hdr.swtraces[7].setInvalid(); }
            if (hops > 8) { hdr.swtraces[8].setInvalid(); }

            hdr.mri.setInvalid();
            hdr.ipv4_option.setInvalid();

            hdr.ipv4.ihl      = hdr.ipv4.ihl - (bit<4>)words_to_remove;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen - bytes_to_remove;
        }
    }

    table swtrace {
        actions = { add_swtrace; NoAction; }
        size = 16;                                 
        default_action = NoAction();
    }

    apply {
        if (hdr.mri.isValid()) {
            swtrace.apply();
        }

            if (standard_metadata.egress_port == 1) {
            strip_mri_all();
        }
    }
}

// ==================== CHECKSUM (post) ===============
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

// ==================== DEPARSE =======================
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4_option);
        packet.emit(hdr.mri);
        packet.emit(hdr.swtraces);
    }
}

// ==================== SWITCH ========================
V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

	

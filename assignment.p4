/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header h265_nal_header_t {
    bit<1> forbidden_zero_bit;
    bit<6> nal_unit_type;
    bit<6> nuh_layer_id;
    bit<3> nuh_temporal_id_plus1;
}

header rtp_t {
    bit<2>  version;
    bit<1>  padding;
    bit<1>  extension;
    bit<4>  csrcCount;
    bit<1>  marker;
    bit<7>  payloadType;
    bit<16> sequenceNumber;
    bit<32> timestamp;
    bit<32> ssrc;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header telemetry_t {  /* CUSTOM STUFF - COULD BE CHANGED */
    bit<32> switch_id;
    bit<32> ingress_port;
    bit<32> egress_port;
    bit<32> queue_depth;
    bit<32> timestamp;
	bit<32> i_frame_rate;
	bit<32> p_frame_rate;
	bit<32> i_frame_size; // IT'S MORE COMPLICATE TO COMPUTE, BUT FOR NOW I USE JUST THE PACKET SIZES
	bit<32> p_frame_size;
	bit<32> inter_frame_gaps;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    rtp_t rtp;
    h265_nal_header_t h265_nal_header;
}

struct metadata { // ALSO CUSTOM - USING FOR INFO SHARING BETWEEN PACKETS
    bit<32> ingress_port;
    bit<32> egress_port;
	bit<32> packet_p_count; // initially set to zero if I'm right
	bit<32> packet_i_count;
	bit<64> last_p_arrival_time;
	bit<64> last_i_arrival_time;
}


/************************************************************************
************************ P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x0800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x11: parse_udp;  // UDP protocol number is 17 (0x11)
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_rtp;
    }

    state parse_rtp {
        packet.extract(hdr.rtp);
        transition parse_h265;
    }

    state parse_h265 {
        packet.extract(hdr.h265_nal_header);
        transition accept;
    }
}


/************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
			      packet_in packet,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
				  
				  
	/*************************************************************
	*************************  ACTIONS   *************************
	**************************************************************/

	action forward_with_telemetry(inout headers hdr, inout metadata meta) {  
		apply {
			meta.ingress_port = standard_metadata.ingress_port;
			meta.egress_port = standard_metadata.egress_port;
			bit<16> header_sizes = 56; // sum of header sizes / 8
			
			if(header.nal_unit_type == 0b000101){ // binary 5 is I frame
			    telemetry_t telemetry;
				bit<64> elapsed_time_i = local_time() - meta.last_i_arrival_time;
				
				if (elapsed_i_time > 0 && meta.packet_i_count > 1) {
					bit<32> i_rate = (meta.packet_i_count * 1000000) / elapsed_time;  // Packets per second
					telemetry.i_frame_rate = i_rate;
				}
				telemetry.i_frame_size = packet.length - header_sizes;
				telemetry.switch_id = 1;  // example switch ID
				telemetry.ingress_port = meta.ingress_port;
				telemetry.egress_port = meta.egress_port;
				telemetry.timestamp = local_time();
				//telemetry.inter_frame_gaps
				
				meta.last_i_arrival_time = local_time();
				meta.packet_i_count = meta.packet_i_count + 1;
			}
			
			
			if(header.nal_unit_type == 0b000001 ){ // binary 1 is P frame
			    telemetry_t telemetry;
				bit<64> elapsed_time_p = local_time() - meta.last_p_arrival_time;
				
				if (elapsed_p_time > 0 && meta.packet_p_count > 1) {
					bit<32> p_rate = (meta.packet_p_count * 1000000) / elapsed_time_p;  // Packets per second
					telemetry.p_frame_rate = i_rate;
				}
				telemetry.p_frame_size = packet.length - header_sizes;
				telemetry.switch_id = 1;  // example switch ID
				telemetry.ingress_port = meta.ingress_port;
				telemetry.egress_port = meta.egress_port;
				telemetry.timestamp = local_time();
				//telemetry.inter_frame_gaps
				
				meta.last_p_arrival_time = local_time();
				meta.packet_p_count = meta.packet_p_count + 1;
			}
			

			send_to_collector(telemetry); // NOT YET IMPLEMENTED

			apply_action(forward(hdr, meta));
		}
	}

	action forward(inout headers hdr, inout metadata meta) {
		apply {
			standard_metadata.egress_spec = get_egress_port(hdr.ipv4.dstAddr);
		}
	}

	action drop() {
		mark_to_drop();
	}


	/************************************************************
	*************************  TABLES   *************************
	*************************************************************/

	table forward_table {
		key = {
			hdr.ethernet.dstAddr: exact;
		}
		actions = {
			forward_with_telemetry;
			drop;
		}
		size = 1024;
		default_action = forward_with_telemetry();
	}		  
				  
				  
	/********************
	******* APPLY *******
	*********************/

    apply(
		forward_table
    );
}





/************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {


    apply {  }
}


/************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

/************************************************************************
*************************  S W I T C H  *********************************
*************************************************************************/


V1Switch(
	MyParser(),
	MyIngress(),
	MyEgress(),
	MyDeparser()
) main;

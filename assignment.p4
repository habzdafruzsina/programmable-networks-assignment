/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

header h265_slice_header_t { // NOT SURE OF THE STRUCTURE, SIENCE THE ISO DOCS ARE NOT FREE.........
    bit<1>  first_slice_segment_in_pic_flag;
    bit<1>  no_output_of_prior_pics_flag;
    bit<6>  slice_type; // (0 = P slice, 1 = B slice, 2 = I slice)
    bit<1>  pic_output_flag;
    bit<3>  colour_plane_id;
    bit<4>  slice_pic_order_cnt_lsb; // picture order count for the slice (can be used to derive the frame ID)
    bit<1>  short_term_ref_pic_set_sps_flag;
}

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
    bit<8> frame_type;
	bit<32> frame_rate;
	bit<32> frame_size; // IT'S MORE COMPLICATE TO COMPUTE, BUT FOR NOW I USE JUST THE PACKET SIZES
	bit<32> inter_frame_gaps;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t ipv4;
    udp_t udp;
    rtp_t rtp;
    h265_nal_header_t h265_nal_header;
    h265_slice_header_t h265_slice_header;
}

// USED FOR INFO SHARING BETWEEN 'STAGES'
struct metadata { 
    bit<32> ingress_port;
    bit<32> egress_port;
}

// ALSO CUSTOM - USING FOR INFO SHARING BETWEEN PACKETS
register<bit<32>>(1) packet_p_count; // initially set to zero if I'm right
register<bit<32>>(1) packet_i_count;
register<bit<32>>(1) last_p_arrival_time;
register<bit<32>>(1) last_i_arrival_time;


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
        transition parse_h265_nal_hdr;
    }

    state parse_h265_nal_hdr {
        packet.extract(hdr.h265_nal_header);
        transition accept;
        //transition parse_h265_slice_hdr;
    }

    // SHOULD BE PARSED, CAUSE IT CONTAINS DATA TO IDENTIFY THE FRAMES AND SLICES
    /*state parse_h265_slice_hdr {
        packet.extract(hdr.h265_slice_header);
        transition accept;
    }*/
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

    action determine_frame_type(bit<6> nal_unit_type) {
        if (nal_unit_type == 19 || nal_unit_type == 20 || nal_unit_type == 21) {
            meta.frame_type = 1;  // I-frame
        } else if (nal_unit_type == 0 || nal_unit_type == 1 || nal_unit_type == 8 || nal_unit_type == 9) {
            meta.frame_type = 2;  // P-frame (? - not sure)
        } else {
            meta.frame_type = 0;
        }
    }

	action forward_with_telemetry(inout headers hdr, inout metadata meta) {
        meta.ingress_port = standard_metadata.ingress_port;
        meta.egress_port = standard_metadata.egress_port;
        bit<16> header_sizes = 57; // sum of header sizes / 8
        bit<32> packet_count;
        bit<32> last_arrival_time;
        telemetry_t telemetry;
        
        if(hdr.h265_nal_header.nal_unit_type == 19 || 
          hdr.h265_nal_header.nal_unit_type == 20 || 
          hdr.h265_nal_header.nal_unit_type == 21){ // I frame

            // READING REGISTERS
            packet_i_count.read(packet_count, 0);
            last_i_arrival_time.read(last_arrival_time, 0);
            
            // SETTING REGISTERS
            packet_i_count.write(0, packet_count + 1);
            last_i_arrival_time.write(0, local_time());
        }

        if(hdr.h265_nal_header.nal_unit_type == 0 || 
          hdr.h265_nal_header.nal_unit_type == 1 || 
          hdr.h265_nal_header.nal_unit_type == 8 || 
          hdr.h265_nal_header.nal_unit_type == 9){ // P frame

            // READING REGISTERS
            packet_p_count.read(packet_count, 0);
            last_p_arrival_time.read(last_arrival_time, 0);
            
            // SETTING REGISTERS
            packet_p_count.write(0, packet_count + 1);
            last_p_arrival_time.write(0, local_time());
        }

        bit<64> elapsed_time = local_time() - last_arrival_time;
        
        if (elapsed_time > 0 && packet_count > 1) {
            bit<32> rate = (packet_count * 1000000) / elapsed_time;  // Packets per second
            telemetry.frame_rate = rate;
        }
        telemetry.frame_type = hdr.nal_unit_type;
        telemetry.frame_size = packet.length - header_sizes; // not entirely correct
        telemetry.switch_id = 1;  // example switch ID
        telemetry.ingress_port = meta.ingress_port;
        telemetry.egress_port = meta.egress_port;
        telemetry.timestamp = local_time();
        //telemetry.inter_frame_gaps

        send_to_collector(telemetry);

        apply_action(forward(hdr, meta));
	}


    action send_to_collector(packet_out packet,
                            in headers hdr,
                            in telemetry_t telemetry,
                            inout metadata meta,
                            inout standard_metadata_t standard_metadata) {
        headers new_hdr;
        //new_hdr.ethernet.dstAddr = /* Collector MAC address */;
        new_hdr.ethernet.srcAddr = hdr.ethernet.srcAddr;
        new_hdr.ethernet.etherType = hdr.ethernet.etherType;

        new_hdr.ipv4.version = hdr.ipv4.version;
        new_hdr.ipv4.ihl = hdr.ipv4.ihl;
        new_hdr.ipv4.diffserv = hdr.ipv4.diffserv;
        new_hdr.ipv4.totalLen = hdr.ipv4.totalLen;
        new_hdr.ipv4.identification = hdr.ipv4.identification;
        new_hdr.ipv4.flags = hdr.ipv4.flags;
        new_hdr.ipv4.fragOffset = hdr.ipv4.fragOffset;
        new_hdr.ipv4.ttl = hdr.ipv4.ttl;
        new_hdr.ipv4.protocol = hdr.ipv4.protocol;
        new_hdr.ipv4.hdrChecksum = hdr.ipv4.hdrChecksum;
        new_hdr.ipv4.srcAddr = hdr.ipv4.srcAddr;
        //new_hdr.ipv4.dstAddr = /* Collector IP address */;

        new_hdr.udp.srcPort = hdr.udp.srcPort;
        //new_hdr.udp.dstPort = /* Collector UDP port */;
        new_hdr.udp.length = hdr.udp.length;
        new_hdr.udp.checksum = hdr.udp.checksum;

        packet.emit(new_hdr.ethernet);
        packet.emit(new_hdr.ipv4);
        packet.emit(new_hdr.udp);
        packet.emit(telemetry);
        packet.send(standard_metadata.egress_spec);
    }


	action forward(inout headers hdr, inout metadata meta) {
		standard_metadata.egress_spec = get_egress_port(hdr.ipv4.dstAddr);
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

    apply{
		forward_table.apply();
    }
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

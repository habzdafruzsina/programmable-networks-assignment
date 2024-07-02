import sys
import os

from scapy.all import sniff, get_if_list, Ether, get_if_hwaddr, IP, Raw
from scapy.fields import BitField, IntField, ByteField

# Define a custom Telemetry header
class Telemetry(Packet):
    name = "Telemetry"
    fields_desc = [
        IntField("switch_id", 0),
        IntField("ingress_port", 0),
        IntField("egress_port", 0),
        IntField("queue_depth", 0),
        IntField("timestamp", 0),
        ByteField("frame_type", 0),
        IntField("frame_rate", 0),
        IntField("frame_size", 0),
        IntField("inter_frame_gaps", 0)
    ]

# Bind the custom header to UDP (not sure about that...)
bind_layers(UDP, Telemetry)

def packet_handler(packet):
    print("Packet Received:")

    if packet.haslayer(Telemetry):
        telemetry = packet[Telemetry]

        # Extract telemetry data
        switch_id = telemetry.switch_id
        ingress_port = telemetry.ingress_port
        egress_port = telemetry.egress_port
        queue_depth = telemetry.queue_depth
        timestamp = telemetry.timestamp
        frame_type = telemetry.frame_type
        frame_rate = telemetry.frame_rate
        frame_size = telemetry.frame_size
        inter_frame_gaps = telemetry.inter_frame_gaps

        # Example: Store telemetry data in a file
        with open("telemetry.log", "a") as f:
        f.write(f"Telemetry Data - Switch ID: {switch_id}, Ingress Port: {ingress_port}, "
                f"Egress Port: {egress_port}, Timestamp: {timestamp}, "
                f"Frame Type: {frame_type}, Frame Rate: {frame_rate}, Frame Size: {frame_size}, "
                f"Inter Frame Gaps: {inter_frame_gaps}\n")

        print(f"Telemetry Data - Switch ID: {switch_id}, Ingress Port: {ingress_port}, "
              f"Egress Port: {egress_port}")


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    # Example: Capture ICMP packets on the default interface ( could be TCP or UDP too )
    # sniff(filter="icmp", iface="eth0", prn=packet_handler)
    sniff(filter="udp", iface = iface, prn = lambda x: packet_handler(x))

if __name__ == '__main__':
    main()
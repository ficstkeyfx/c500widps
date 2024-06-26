# Initialize dictionaries and lists for packet analysis.
packets_brief = {}
forward_packets = {}
backward_packets = {}
protocols = []
protocol_counts = {}

def processing_packet_conversion(packet):
    # Clone the packet for processing without modifying the original.
    packet_2 = packet

    while packet_2:
        # Extract and count protocol layers in the packet.
        layer = packet_2[0]
        if layer.name not in protocol_counts:
            protocol_counts[layer.name] = 0
        else:
            protocol_counts[layer.name] += 1
        protocols.append(layer.name)

        # Break if there are no more payload layers.
        if not layer.payload:
            break
        packet_2 = layer.payload

    # Extract relevant information for feature creation.
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    src_port = packet.sport
    dst_port = packet.dport
    ip_length = len(packet[IP])
    ip_ttl = packet[IP].ttl
    ip_tos = packet[IP].tos
    tcp_data_offset = packet[TCP].dataofs
    tcp_flags = packet[TCP].flags

    # Process payload content and create a feature string.
    payload_bytes = bytes(packet.payload)
    payload_length = len(payload_bytes)
    payload_content = payload_bytes.decode('utf-8', 'replace')
    payload_decimal = ' '.join(str(byte) for byte in payload_bytes)
    final_data = "0" + " " + "0" + " " + "195" + " " + "-1" + " " + str(src_port) + " " + str(dst_port) + " " + str(ip_length) + " " + str(payload_length) + " " + str(ip_ttl) + " " + str(ip_tos) + " " + str(tcp_data_offset) + " " + str(int(tcp_flags)) + " " + "-1" + " " + str(payload_decimal)
    return final_data
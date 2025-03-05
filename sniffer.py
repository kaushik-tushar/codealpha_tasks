from scapy.all import sniff, wrpcap

captured_packets = []

def process_packet(packet):
    """Processes and stores captured packets."""
    print(packet.summary())  # Print packet details
    captured_packets.append(packet)  # Store packet in list

def main():
    print("Starting packet capture...")
    try:
        # Capturing 10 packets (Change count=0 for continuous capture)
        sniff(prn=process_packet, count=10)
    except KeyboardInterrupt:
        print("\nPacket capture interrupted by user.")
    except Exception as e:
        print(f"An error occurred during packet capture: {e}")
    finally:
        if captured_packets:
            try:
                wrpcap('captured_packets.pcap', captured_packets)
                print("Captured packets saved to 'captured_packets.pcap'.")
            except Exception as e:
                print(f"Failed to save packets: {e}")
        else:
            print("No packets were captured.")

if __name__ == "__main__":
    main()

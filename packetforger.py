import random
import time
from contextlib import redirect_stdout
from scapy.all import send, sr1, sniff, fragment, IP, TCP, UDP, ICMP, Raw
from scapy.packet import Packet

def SendPacket(packet, listen_response=True):
    log_file = "packetresponse.log"
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

    def log_packet_info(pkt, response=None, rtt=None, note=""):
        with open(log_file, "a") as f:
            f.write(f"\n\n--- Logged at {timestamp} ---\n")
            if note:
                f.write(note + "\n")
            if rtt is not None:
                f.write(f"RTT: {rtt*1000:.2f} ms\n")
            elif listen_response:
                f.write("RTT: > timeout (12 seconds)\n")
            else:
                f.write("Response Not Expected.\n")
            with redirect_stdout(f):
                print("Sent Packet:\n")
                pkt.show()
                if response:
                    print("Received Packet:\n")
                    response.show()

    # Fragmented packets case
    if isinstance(packet, list):
        print("Sending Fragmented Packets...")
        for i, pkt in enumerate(packet):
            print(f"Fragment {i + 1}/{len(packet)}:")
            pkt.show()
            send(pkt)

        if listen_response:
            print("All fragments sent. Listening for response...")
            start = time.time()
            resp = sniff(filter="tcp or icmp or udp", timeout=12, count=1)
            rtt = time.time() - start
            print(f"Ping: {rtt*1000:.2f} ms \n")
            if resp:
                print("Received Response:")
                resp[0].show()
                log_packet_info(packet[0], response=resp[0], rtt=rtt, note="Response after all fragments sent.")
            else:
                print("No Response Received.")
                log_packet_info(packet[0], note="No response after all fragments sent.")
        else:
            log_packet_info(packet[0], note="Sent packet fragments. Response not expected.")
        return

    # Standard packet case
    elif isinstance(packet, Packet):
        print("Packet Constructed:")
        packet.show()

        # Automatically disable response listening for UDP
        if packet.haslayer(UDP):
            print("UDP Packet: No response expected.")
            listen_response = False
            note = "UDP: No response expected."
        else:
            note = ""

        if listen_response:
            print("Sending and Listening for Response...")
            start = time.time()
            resp = sr1(packet, timeout=12, verbose=False)
            rtt = time.time() - start
            print(f"Ping: {rtt*1000:.2f} ms \n")
            if resp:
                print("Received Response:")
                resp.show()
                log_packet_info(packet, response=resp, rtt=rtt)
            else:
                print("No Response Received.")
                log_packet_info(packet, note="No response received (timeout).")
        else:
            print("Sending Packet (No Response Expected)...")
            send(packet)
            log_packet_info(packet, note=note or "Response not expected.")
        return

    else:
        print("Invalid packet object")



def FragmentedTCP(DestIP, SrcPort, DstPort, Flags, TTL, mss, winsize, chunk_count, disorder, overlap, payload):
    tcp = TCP(
        sport=SrcPort,
        dport=DstPort,
        flags=Flags,
        seq=random.randint(0, 4294967295),
        options=[('MSS', mss), ('Timestamp', (12345678, 0)), ('WScale', winsize)]
    )
    
    pkt = IP(dst=DestIP, id=random.randint(0, 65535), ttl=TTL) / tcp / payload
    frags = fragment(pkt, fragsize=int(len(payload) / chunk_count))

    if disorder:
        random.shuffle(frags)
    if overlap:
        frags += [frags[0].copy()]  # Simple overlap for demo

    return frags



def BuildPacket():
    DestIP = input("Destination IP: ").strip()
    Proto = input("1=TCP, 2=UDP, 3=ICMP, 4=FragTCP: ").strip()
    TTL = int(input("TTL: (64)Linux, (128)Windows, (255)Cisco): ").strip())

    if Proto not in ['1', '2', '3', '4']:
        print("Invalid Option")
        return

    SrcPort = DstPort = None
    if Proto in ['1', '2', '4']:
        DstPort = int(input("Destination Port (1-65535): ").strip())
        SrcPort = int(input("Source Port (1-65535): ").strip())
        print('Payload #1: b"A" * 512')
        print('Payload #2: HTTP Get')
        print('Payload #3: Custom Payload')      
        payloadc = input('Select Payload (1), (2) or (3): ').strip()
            
        if payloadc == '1':
            payload = b"A" * 512
            
        elif payloadc == '2':
            targethttpget = input("Enter Website URL httpbin.org: ").strip()
            payload = Raw(load=f"GET / HTTP/1.1\r\nHost: {targethttpget}\r\n\r\n".encode())
        
        elif payloadc == '3':
            payload = input('Enter your custom payload').encode()
        
        else:
            print("ERROR: Incorrect Payload Selection!")
            return
        
        
    if Proto in ['1', '4']:
        Flags = input("TCP Flags: S(SYN), A(ACK), SA(SYN-ACK), F(FIN), R(RST), U(URG), P(PSH), E(ECE), C(CWR), N(NS), FA(FIN-ACK), PA(PSH-ACK), RA(RST-ACK), FPU(FIN-PSH-URG), SEC(SYN-ECE-CWR):  ").strip()
        mss = int(input("MSS: (1460)Linux or (1380)Windows: ").strip())
        winsize = int(input("Window Scale: 7(8192WinSize=Linux=1MB Effective.Win) OR 8(64240WinSize=Windows=15.7MB Effective.Win) OR 0(64240WinSize=62.7KB Effective.Win -NO Scale): ").strip())

    if Proto == '4':
        chunk_count = int(input("# Fragmentation Chunks [8,16,24,32,64]:  ").strip())
        disorder = input("Out of Order? (y/n): ").strip().lower() == 'y'
        overlap = input("Overlapping Fragments? (y/n): ").strip().lower() == 'y'
        return FragmentedTCP(DestIP, SrcPort, DstPort, Flags, TTL, mss, winsize, chunk_count, disorder, overlap, payload)

    elif Proto == '3':
       # ICMP Type Selection
       Type = input("0=EchoRep, 3=DstUnreachable, 4=SrcQuench, 5=Redirect, 8=EchoReq, 9=RouterAdvertise, 10=RouterSoliciting, 11=TimeExceeded, 12=ParamProb, 13=TimestmpReq, 14=TimestmpRep, 15=InfReq, 16=InfRep, 17=AddrMaskReq, 18=AddrMaskRep, 30=Tracert, 42=ExtndEchoReq, 43=ExtndEchoRep: ").strip()
          
       # ICMP Code Selection Dependent on Type
       if Type == '3':
           Code = input("0=NetUnreach, 1=HostUnreach, 2=ProtocolUnreach, 3=PortUnreach, 4=FragNeeded, 5=SrcRouteFail, 6=DestNetUnknown, 7=DestHostUnknown, 8=SrcHostIsolated, 9=NetAdminProhib, 10=HostAdminProhib, 11=NetTOSUnreach, 12=HostTOSUnreach, 13=AdminProhibited, 14=HostPrecViolation, 15=PrecCutoff").strip()
       elif Type == '5':
           Code = input("0=Redirect for Net, 1=Redirect for Host, 2=Redirect for TOS and Net, 3=Redirect for TOS and Host").strip()
       elif Type == '9':
           Code = input("0=Normal Adv, 16=Does Not Route Common Traffic").strip()
       elif Type == '11':
           Code = input("0=TTL Exceeded, 1=Frag Reassembly Time Exceeded").strip()
       elif Type == '12':
           Code = input("0=Pointer Error, 1=Missing Option, 2=Bad Length").strip()
       elif Type == '40':
           Code = input("0=Bad SPI, 1=Auth Failed, 2=Decompress Failed, 3=Decrypt Failed, 4=Need Auth, 5=Need Authz").strip()
       elif Type in ['42', '43']:
           Code = input("0=No Error, 1=Malformed Query, 2=No Interface, 3=No Table Entry, 4=Multiple Interfaces").strip()
       else:
           Code = input("Enter code (default = 0): ").strip()


       # ICMP ID Generation
       IDmethod = input("ID: 0(Linux/Windows) | 1(Windows) | 2(Random 0-65535): ").strip()
       if IDmethod == '0':
           ID = '0'  
       elif IDmethod == '1':
           ID = '1'        
       elif IDmethod == '2':
           ID = random.randint(0, 65535)
       else:
           print("Invalid option.")
       
       
       # ICMP SEQ Generation
       Seqmethod = input("Seq: 0(Linux/Windows) | 1(Windows) | 2(Random 0-65535): ").strip()
       if Seqmethod == '0':
           Seq = '0'  
       elif Seqmethod == '1':
           Seq = '1'        
       elif Seqmethod == '2':
           Seq = random.randint(0, 65535)
       else:
           print("Invalid option.")
           
           
       return IP(dst=DestIP,id=random.randint(0, 65535),ttl=TTL) / ICMP(type=int(Type),code=int(Code),id=int(ID),seq=int(Seq))
    
    
    
    elif Proto == '2':
        return IP(dst=DestIP, id=random.randint(0, 65535),ttl=TTL) / UDP(sport=SrcPort, dport=DstPort) / payload

    elif Proto == '1':
        return IP(dst=DestIP,id=random.randint(0, 65535),ttl=TTL) / TCP(
            sport=SrcPort,
            dport=DstPort,
            flags=Flags,
            seq=random.randint(0, 4294967295),
            options=[('MSS', mss), ('Timestamp', (12345678, 0)), ('WScale', winsize)]) / payload

if __name__ == "__main__":
    packet = BuildPacket()
    if packet:
        SendPacket(packet, listen_response=True)

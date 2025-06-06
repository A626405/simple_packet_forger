import random
import time
import scapy.all as scapy
from contextlib import redirect_stdout


def fragmentfunc(packet, chunk_count, overlap, order, payload):
    frags = scapy.fragment(packet, fragsize=int(len(payload) / chunk_count))
    if order:
        random.shuffle(frags)
    if overlap:
        frags += [frags[0].copy()]  # Simple overlap for demo

    return frags
    


def SendPacket(packet, listen_response=True):
    log_file = "packetresponse.log"
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

    def log_packet_info(packet, response=None, rtt=None, note=""):
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
                packet.show()
                if response:
                    print("Received Packet:\n")
                    response.show()

    # Fragmented packets case
    if isinstance(packet, list):
        print("Sending Fragmented Packets...")
        for i, packet in enumerate(packet):
            print(f"Fragment {i + 1}/{len(packet)}:")
            packet.show()
            scapy.send(packet)

        if listen_response:
            print("All fragments sent. Listening for response...")
            start = time.time()
            resp = scapy.sniff(filter="tcp or icmp or udp", timeout=12, count=1)
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
    elif isinstance(packet, scapy.Packet):
        print("Packet Constructed:")
        packet.show()

        # Automatically disable response listening for UDP
        if packet.haslayer(scapy.UDP):
            print("UDP Packet: No response expected.")
            listen_response = False
            note = "UDP: No response expected."
        else:
            note = ""

        if listen_response:
            print("Sending and Listening for Response...")
            start = time.time()
            resp = scapy.sr1(packet, timeout=12, verbose=False)
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
            scapy.send(packet)
            log_packet_info(packet, note=note or "Response not expected.")
        return

    else:
        print("Invalid packet object")




def BuildPacket():

    targethost = input("Target IP Address: ").strip()
    selectprotocol = input("Packet Protocol: (1)TCP, (2)UDP, (3)ICMP: ").strip()
    TTL = int(input("TTL: (64)Linux, (128)Windows, (255)Cisco): ").strip())
    IPid = random.randint(0, 65535)


    if selectprotocol == '3':
        #ICMP Type Selection
        Type = input("0=EchoRep, 3=DstUnreachable, 4=SrcQuench, 5=Redirect, 8=EchoReq, 9=RouterAdvertise, 10=RouterSoliciting, 11=TimeExceeded, 12=ParamProb, 13=TimestmpReq, 14=TimestmpRep, 15=InfReq, 16=InfRep, 17=AddrMaskReq, 18=AddrMaskRep, 30=Tracert, 42=ExtndEchoReq, 43=ExtndEchoRep: ").strip()
          
        #ICMP Code Selection Dependent on Type
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


        #ICMP ID Generation
        IDmethod = input("ID: 0(Linux/Windows) | 1(Windows) | 2(Random 0-65535): ").strip()
        if IDmethod == '0':
            ID = 0  
        elif IDmethod == '1':
            ID = 1        
        elif IDmethod == '2':
            ID = random.randint(0, 65535)
        else:
            print("Invalid option.")
       
        
       #ICMP SEQ Generation
        Seqmethod = input("Seq: 0(Linux/Windows) | 1(Windows) | 2(Random 0-65535): ").strip()
        if Seqmethod == '0':
            Seq = 0  
        elif Seqmethod == '1':
            Seq = 1       
        elif Seqmethod == '2':
            Seq = random.randint(0, 65535)
        else:
            print("Invalid option.")
        
        
        
        #ICMP Packet
        IP = scapy.IP(dst=targethost, id=IPid, ttl=TTL)
        L3 = scapy.ICMP(type=int(Type),code=int(Code),id=ID,seq=Seq)    
        packet = IP/L3
        return packet

    #L4 Setup
    if selectprotocol in ['1','2']:
        dstport = int(input("Destination Port (1-65535): ").strip())
        srcport = int(input("Source Port (1-65535): ").strip())
    
        print('Payload #1: b"A" * 512')
        print('Payload #2: HTTP Get')
        print('Payload #3: Custom Payload')      
        payloadc = input('Select Payload (1), (2) or (3): ').strip()
            
        if payloadc == '1':
            payload = b"A" * 512
            
        elif payloadc == '2':
            targethttpget = input("Enter Website URL httpbin.org: \n").strip()
            payload = scapy.Raw(load=f"GET / HTTP/1.1\r\nHost: {targethttpget}\r\n\r\n".encode())
        
        elif payloadc == '3':
            payload = input('Enter your custom payload').encode()
        
        else:
            print("ERROR: Incorrect Payload Selection!")
    
    

    TCPorUDP = input("(0)TCP or (1)UDP: \n").strip()
    fragpacket = input("L3 Frag Packet: (0)No or (1)Yes: \n").strip()

    if TCPorUDP == "0" and fragpacket == "0":
        Flags = input("TCP Flags: S(SYN), A(ACK), SA(SYN-ACK), F(FIN), R(RST), U(URG), P(PSH), E(ECE), C(CWR), N(NS), FA(FIN-ACK), PA(PSH-ACK), RA(RST-ACK), FPU(FIN-PSH-URG), SEC(SYN-ECE-CWR):  ").strip()
        mss = int(input("MSS: (1460)Linux or (1380)Windows: ").strip())
        winsize = int(input("Window Scale: 7(8192WinSize=Linux=1MB Effective.Win) OR 8(64240WinSize=Windows=15.7MB Effective.Win) OR 0(64240WinSize=62.7KB Effective.Win -NO Scale): ").strip())

        IP = scapy.IP(dst=targethost, id=IPid, ttl=TTL)
        L4 = scapy.TCP(sport=srcport,dport=dstport,flags=Flags,seq=random.randint(0, 4294967295),options=[('MSS', mss), ('Timestamp', (12345678, 0)), ('WScale', winsize)]) 
        packet = IP/L4/payload
        return packet
        

    elif TCPorUDP == "1" and fragpacket == "0":
        IP = scapy.IP(dst=targethost, id=IPid, ttl=TTL)
        L4 = scapy.UDP(sport=srcport,dport=dstport)
        packet = IP/L4/payload
        return packet
        
    
    elif TCPorUDP == "0" and fragpacket == "1":
        Flags = input("TCP Flags: S(SYN), A(ACK), SA(SYN-ACK), F(FIN), R(RST), U(URG), P(PSH), E(ECE), C(CWR), N(NS), FA(FIN-ACK), PA(PSH-ACK), RA(RST-ACK), FPU(FIN-PSH-URG), SEC(SYN-ECE-CWR):  ").strip()
        mss = int(input("MSS: (1460)Linux or (1380)Windows: ").strip())
        winsize = int(input("Window Scale: 7(8192WinSize=Linux=1MB Effective.Win) OR 8(64240WinSize=Windows=15.7MB Effective.Win) OR 0(64240WinSize=62.7KB Effective.Win -NO Scale): ").strip())

        IP = scapy.IP(dst=targethost, id=IPid, ttl=TTL)
        L4 = scapy.TCP(sport=srcport,dport=dstport,flags=Flags,seq=random.randint(0, 4294967295),options=[('MSS', mss), ('Timestamp', (12345678, 0)), ('WScale', winsize)]) 
        packet = IP/L4/payload
    
        chunk_count = int(input("# Fragmentation Chunks [8,16,24,32,64]:  ").strip())
        order = input("(n)InOrder or (y)Out-Of-Order: \n").strip().lower() == 'y'
        overlap = input("(n)NoOverlap or (y)Overlapping Packets: \n").strip().lower() == 'y'
        return fragmentfunc(packet, chunk_count, overlap, order, payload)

    
    elif TCPorUDP == "1" and fragpacket == "1":
        IP = scapy.IP(dst=targethost, id=IPid, ttl=TTL)
        L4 = scapy.UDP(sport=srcport,dport=dstport)
        packet = IP/L4/payload
    
        chunk_count = int(input("# Fragmentation Chunks [8,16,24,32,64]:  ").strip())
        order = input("(n)InOrder or (y)Out-Of-Order: \n").strip().lower() == 'y'
        overlap = input("(n)NoOverlap or (y)Overlapping Packets: \n").strip().lower() == 'y'
        return fragmentfunc(packet, chunk_count, overlap, order, payload)




if __name__ == "__main__":
    packet = BuildPacket()
    if packet:
        SendPacket(packet, listen_response=True)

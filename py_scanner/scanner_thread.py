from scapy.all import *
import threading
class ScannerThread(threading.Thread):
    def __init__(self, dest_ip="127.0.0.1", ports={"from":1, "to":2}, thread_num=0):
        threading.Thread.__init__(self)

        self.thread_num = thread_num
        self.dest_ip = dest_ip
        self.ports = ports
        self.ReturnObject=[] # there we will put {'port': port, 'res': res}
  
        self.SYNACK = 0x12 # Set flag values for later reference
        self.RSTACK = 0x14
    
    def run(self):
        for port in range(self.ports["from"], self.ports["to"]):
            res = self.SYNscan(ip_addr=self.dest_ip, port=port)
            print("thread: " + str(self.thread_num) + " running port: " + str(port) + "SYNres: " + str(res))
            #res = self.FINscan(ip_addr=self.dest_ip, port=port)
            print("thread: " + str(self.thread_num) + " running port: " + str(port) + "FINres: " + str(res))
            
            self.ReturnObject.append({'port': port, 'res': res})
        

    def SYNscan(self, ip_addr, port): # Function to scan a given port
        try:
            srcport = RandShort() # Generate Port Number
            conf.verb = 0 # Hide output
            SYNACKpkt = sr1(IP(dst = ip_addr)/TCP(sport = srcport, dport = port, flags = "S")) # Send SYN and recieve RST-ACK or SYN-ACK
            pktflags = SYNACKpkt.getlayer(TCP).flags # Extract flags of recived packet
            if pktflags == self.SYNACK: # Cross reference Flags
                return True # If open, return true
            else:
                return False # If closed, return false
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Construct RST packet
            send(RSTpkt) # Send RST packet

        except KeyboardInterrupt: # In case the user needs to quit
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
            send(RSTpkt) # Send RST packet to whatever port is currently being scanned
            print("\n[*] User Requested Shutdown...")
            print("[*] Exiting...")
            sys.exit(1)


    def FINscan(self, ip_addr, port): # Function to scan a given port
        try:
            srcport = RandShort() # Generate Port Number
            conf.verb = 0 # Hide output
     
            fin_scan_resp = sr1(IP(dst=ip_addr)/TCP(dport=port,flags="F"))
            print(fin_scan_resp)
            if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
                print("Open|Filtered")
            elif(fin_scan_resp.haslayer(TCP)):
                if(fin_scan_resp.getlayer(TCP).flags == 0x14):
                    print("Closed")
                elif(fin_scan_resp.haslayer(ICMP)):
                    if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        print("Filtered")
            return 'ok'
        except KeyboardInterrupt: # In case the user needs to quit
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
            send(RSTpkt) # Send RST packet to whatever port is currently being scanned
            print("\n[*] User Requested Shutdown...")
            print("[*] Exiting...")
            sys.exit(1)



    def NULLscan(self, ip_addr, port): # Function to scan a given port
        try:
            srcport = RandShort() # Generate Port Number
            conf.verb = 0 # Hide output
                
            null_scan_resp = sr1(IP(dst=dst_ip)/TCP(dport=dst_port,flags=""),timeout=10)
            if (str(type(null_scan_resp))=="<type 'NoneType'>"):
                print("Open|Filtered")
            elif(null_scan_resp.haslayer(TCP)):
                if(null_scan_resp.getlayer(TCP).flags == 0x14):
                    print ("Closed")
                elif(null_scan_resp.haslayer(ICMP)):
                    if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                        print("Filtered")
        except KeyboardInterrupt: # In case the user needs to quit
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
            send(RSTpkt) # Send RST packet to whatever port is currently being scanned
            print("\n[*] User Requested Shutdown...")
            print("[*] Exiting...")
            sys.exit(1)

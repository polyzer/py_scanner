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
            print("thread: " + str(self.thread_num) + " running port: " + str(port))
            res = self.scanport(ip_addr=self.dest_ip, port=port)
            self.ReturnObject.append({'port': port, 'res': res})
        

    def scanport(self, ip_addr, port): # Function to scan a given port
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


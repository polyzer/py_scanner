import threading
import socket
from scapy.all import *

class ScannerThread(threading.Thread):
    def __init__(self, dest_ip="127.0.0.1", ports={"from":1, "to":2}, thread_num=0, scan_type="S"):
        self._stopevent = threading.Event(  )
        self._sleepperiod = 1.0

        threading.Thread.__init__(self)

        self.scanning_type = scan_type
        self.thread_num = thread_num
        self.dest_ip = dest_ip
        self.ports = ports
        self.ReturnObject=[] # there we will put {'port': port, 'res': res}
  
        self.SYNACK = 0x12 # Set flag values for later reference
        self.RSTACK = 0x14
    
    def incoming(self, host, port):
        # """Open specified port and return file-like object"""
        # sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # # set SOL_SOCKET.SO_REUSEADDR=1 to reuse the socket if
        # # needed later without waiting for timeout (after it is
        # # closed, for example)
        # sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # sock.bind((host, port))
        # sock.listen(0)   # do not queue connections
        # conn, addr = sock.accept()
        # with conn:
        #     print('Connected by', addr)
        #     sock.sendall("GET / HTTP/1.1\r\n\r\n")
        #     while True:
        #         data = conn.recv(1024)
        #         if not data:
        #             break
        #         print(data)
        #         #conn.sendall(data)
        # sock.close()

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(b'GET / HTTP/1.1\r\n\r\n')
            data = s.recv(1024)
            print(data)
            s.close()
        # /-- network ---

    def run(self):
        if self.scanning_type == "S":
            for port in range(self.ports["from"], self.ports["to"]):
                res = self.SYNscan(ip_addr=self.dest_ip, port=port)
                print("thread: " + str(self.thread_num) + " running port: " + str(port) + "SYNres: " + str(res))
        if self.scanning_type == "F":
               for port in range(self.ports["from"], self.ports["to"]):
                res = self.FINscan(ip_addr=self.dest_ip, port=port)
                print("thread: " + str(self.thread_num) + " running port: " + str(port) + "FINres: " + str(res))
        if self.scanning_type == "N":
           for port in range(self.ports["from"], self.ports["to"]):
                res = self.NULLscan(ip_addr=self.dest_ip, port=port)
                print("thread: " + str(self.thread_num) + " running port: " + str(port) + "NULLres: " + str(res))
        exit()
    def join(self, timeout=None):
        """ Stop the thread. """
        self._stopevent.set(  )
        threading.Thread.join(self, timeout)

    def SYNscan(self, ip_addr, port): # Function to scan a given port
        try:
            #srcport = RandShort() # Generate Port Number
            SYNACKpkt = sr1(IP(dst = ip_addr)/TCP( dport = port, flags = "S")) # Send SYN and recieve RST-ACK or SYN-ACK
            pktflags = SYNACKpkt.getlayer(TCP).flags # Extract flags of recived packet
            if pktflags == self.SYNACK: # Cross reference Flags
                self.incoming(ip_addr, port)
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
            fin_scan_resp = sr1(IP(dst=ip_addr)/TCP(dport=port,flags="F"))
            #print(fin_scan_resp)
            if (str(type(fin_scan_resp))=="<type 'NoneType'>"):
                #print("Open|Filtered")
                self.incoming(ip_addr, port)
                return "Open|Filtered"
            if(fin_scan_resp.getlayer(TCP).flags == 0x14):
               # print("Closed")
                return "Closed"
            elif(fin_scan_resp.haslayer(ICMP)):
                if(int(fin_scan_resp.getlayer(ICMP).type)==3 and int(fin_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                   # print("Filtered")
                    return "Filtered"
        except KeyboardInterrupt: # In case the user needs to quit
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
            send(RSTpkt) # Send RST packet to whatever port is currently being scanned
            print("\n[*] User Requested Shutdown...")
            print("[*] Exiting...")
            sys.exit(1)



    def NULLscan(self, ip_addr, port): # Function to scan a given port
        try:
            srcport = RandShort() # Generate Port Number
                
            null_scan_resp = sr1(IP(dst=ip_addr)/TCP(dport=port,flags=""),timeout=2)
            if (str(type(null_scan_resp))=="<type 'NoneType'>"):
                self.incoming(ip_addr, port)
                print("Open|Filtered")
            if(null_scan_resp.getlayer(TCP).flags == 0x14):
               # print("Closed")
                return "Closed"
            elif(null_scan_resp.haslayer(ICMP)):
                if(int(null_scan_resp.getlayer(ICMP).type)==3 and int(null_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                    print("Filtered")
        except KeyboardInterrupt: # In case the user needs to quit
            RSTpkt = IP(dst = target)/TCP(sport = srcport, dport = port, flags = "R") # Built RST packet
            send(RSTpkt) # Send RST packet to whatever port is currently being scanned
            print("\n[*] User Requested Shutdown...")
            print("[*] Exiting...")
            sys.exit(1)

    def FINscanAll(self, ip_addr, ports):
        ip_p = IP(dst=ip_addr)
        tcp_p = TCP(dport=(ports['from'],ports['to']),flags='F')
        packets = ip_p/tcp_p
        resp, non_resp = sr(packets,timeout=0.5)
        for item in non_resp :
            print('[-]Port:',item.sport,'closed')
        for sent,recv in resp: # I DO NOt get any recv packets
            if recv[1].flags == 4 : # 4 == RST packet
                print('[+]Port:',sent[1].dport,'closed, but !port service on!')
            if recv[1].flags != 4 :
                print('[+]Port:',sent[1].dport,'opened')
                print(recv[1].flags) 


    def NULLscanAll(self, ip_addr, ports):
        ip_p = IP(dst=ip_addr)
        tcp_p = TCP(dport=(ports['from'],ports['to']),flags='')
        packets = ip_p/tcp_p
        resp, non_resp = sr(packets,timeout=0.5)
        for item in non_resp :
            print('[-]Port:',item.sport,'closed')
        for sent,recv in resp: # I DO NOt get any recv packets
            if recv[1].flags == 4 : # 4 == RST packet
                print('[+]Port:',sent[1].dport,'closed, but !port service on!')
            if recv[1].flags != 4 :
                print('[+]Port:',sent[1].dport,'opened')
                print(recv[1].flags) 
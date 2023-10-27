import datetime
from time import sleep, time
from modTransmit import send_segments
from client import Webclient
from noise import NoiseClient
import scapy.all as scapy
from scapy.sendrecv import AsyncSniffer 
import logging
import sys

INTERFACE_SCRIPT = ""
INTERFACE_CLIENT = ""
WITH_CLIENT = True

SERVER_INFORMATION= ('192.168.1.6',8080 ,'34:17:eb:cb:d4:14')
SERVER2_INFORMATION= ('10.100.0.1',8080 ,'a0:36:9f:28:15:34')

# The Queues must match, otherwise the evaluation is wrong!
# QUEUE 1
IC_PROBE_INFO= ('10.1.0.2',62599,'a0:36:9f:28:15:7c')
IC_SPOOF_INFO= ('192.168.1.21',58671,'a0:36:9f:28:15:7c')

# QUEUE 0
OOC_PROBE_INFO= ('10.1.0.2',53883,'a0:36:9f:28:15:7c')
OOC_SPOOF_INFO= ('192.168.1.21',64651,'a0:36:9f:28:15:7c')

# QUEUE 1
OOC2_PROBE_INFO= ('10.1.0.2',49771,'a0:36:9f:28:15:7c')
OOC2_SPOOF_INFO= ('192.168.1.21',53059,'a0:36:9f:28:15:7c')

NOISE_CLIENT='10.1.0.2'
NOISE_PORTS = [59250,64728,57500,64709]

SEQ = 0
ACK = 0

# Variables needed to evaluate the order
FIRST = None
CON = 0
NOCON = 0

ISIC = True

def set_seq(packet):
    global SEQ
    global ACK
    if packet.sprintf('%TCP.flags%')=='A':
        SEQ = packet.ack
        ACK = packet.seq

def eval_order(packet):
    global FIRST
    global CON
    global NOCON
    global ISIC
    if packet.sprintf('%TCP.flags%')=='R':
        if ISIC:
            spoofPort = IC_PROBE_INFO[1]
        else:
            spoofPort = OOC2_PROBE_INFO[1]
        port = packet.sprintf('%TCP.dport%')
        if port == FIRST:
            return
        if FIRST is None:
            FIRST = port
            return
        if port == f"{spoofPort}" and FIRST is not None:
            NOCON+=1
            FIRST = None
            return
        if port == f"{OOC_PROBE_INFO[1]}" and FIRST is not None:
            CON+=1
            FIRST = None
            return

def run():
    global SEQ
    global ACK
    global CON
    global NOCON
    global FIRST
    global ISIC
    try:
        sniffer = AsyncSniffer(iface=INTERFACE_CLIENT,prn=set_seq,filter=f"tcp and dst port {IC_SPOOF_INFO[1]}")
        orderSniffer = AsyncSniffer(iface=INTERFACE_CLIENT,prn=eval_order,filter=f"dst port {IC_PROBE_INFO[1]} or dst port {OOC_PROBE_INFO[1]} or dst port {OOC2_PROBE_INFO[1]}")

        sniffer.start()
        orderSniffer.start()
        if WITH_CLIENT:
            www = Webclient((SERVER_INFORMATION[0],SERVER_INFORMATION[1]),(IC_SPOOF_INFO[0],IC_SPOOF_INFO[1]))
            www.start()
            sleep(0.5)
            if www.FINISHED:
                raise Exception("Client did not run")
            logging.info(f"[+] Client started")

        for port in NOISE_PORTS:
            nc = NoiseClient((SERVER2_INFORMATION[0],SERVER2_INFORMATION[1]),(NOISE_CLIENT,port),12,1)
            nc.start()
            sleep(0.5)
            if nc.FINISHED:
                raise Exception("NoiseClient did not run")
            logging.info(f"[+] Noise Client started")

        delay = 0.1
        startTime = time()
        finish_time = datetime.datetime.now() + datetime.timedelta(hours=1)
        while datetime.datetime.now() < finish_time:
            for i in range (1,3):
                for i in range(1,101):      
                    # Lower letter: IC
                    # Capital letter: OOC
                    pattern = f"SsSsSsSsSsSsSsSsSsSsPp"          
                    payload = "ET /"
                    FIRST = None
                    if ISIC:
                        if send_segments(INTERFACE_SCRIPT, str(SEQ), str(ACK), IC_PROBE_INFO[1], OOC_PROBE_INFO[1], IC_SPOOF_INFO[1], OOC_SPOOF_INFO[1], 8080, pattern,payload,payload) != 1:
                            raise Exception(f"Segments could not be send")
                    else:
                        #CON = IW, NOCON = OOW
                        if send_segments(INTERFACE_SCRIPT, str(SEQ), str(ACK), OOC2_PROBE_INFO[1], OOC_PROBE_INFO[1], OOC2_SPOOF_INFO[1], OOC_SPOOF_INFO[1], 8080, pattern,payload,payload) != 1:
                            raise Exception(f"Segments could not be send")
                    currentTime = str(datetime.timedelta(seconds=round(time()-startTime)))
                    print(f"[{i}] IC: {ISIC}  | CON: {CON}; NOCON {NOCON} in {currentTime} with {round(delay,1)}s delay",end="\r")
                    sleep(delay)
                print(f"\n[{i}] IC: {ISIC} | CON: {CON}; NOCON {NOCON} in {currentTime} with {round(delay,1)}s delay",end="\r")
                logging.info(f"IC: {ISIC} | CON: {CON}; NOCON: {NOCON} in {currentTime} with {round(delay,1)}s delay")
                CON = 0
                NOCON = 0
                ISIC ^= True

    except Exception as e:
        logging.error(f"[!] Error: {e}")
        sys.exit(-1)
    finally:
        sniffer.stop()
        orderSniffer.stop()
        if WITH_CLIENT:
            www.abort_webserver()
            www.join()
            for i in range(10):
                if www.FINISHED:
                    break
                sleep(0.2)
        nc.abort_noiseclient()
        nc.join()
        for i in range(10):
            if nc.FINISHED:
               break
            sleep(0.2)
        endTime = time()
        print("\n")
        logging.info(f"[+] Finished in {str(datetime.timedelta(seconds=round(endTime-startTime)))}")
    return 1

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("[?] Usage: python3 run.py <amount> <script interface> <client interface>")
    
    amount = int(sys.argv[1])
    INTERFACE_SCRIPT = sys.argv[2]
    INTERFACE_CLIENT = sys.argv[3]
    if len(sys.argv) == 5:
        print(f"[+] Webclient: {(sys.argv[4] == 'True')}")
        WITH_CLIENT = sys.argv[4] == 'True'
    logging.basicConfig(filename="../logs/run.log",level=logging.INFO,format="%(asctime)s %(message)s")

    run()

import subprocess
from random import choice
import logging

# Uses https://github.com/stackpath/rxtxcpu, run in folder /contrib/rss

probeTuple = ('10.100.0.2','10.100.0.1')
spoofTuple = ('192.168.1.6','192.168.1.7')
destPort = '8080'

#port 49152 - 65535
portsProbe1 = [i for i in range (49152,65535)]
portsProbe2 = [i for i in range (49152,65535)]
portsSpoof1 = [i for i in range (49152,65535)]
portsSpoof2 = [i for i in range (49152,65535)]

logging.basicConfig(filename='results.log', level=logging.INFO,format="%(message)s")

total = len(portsProbe1)

while True:
    pPort1 = choice(portsProbe1)
    pPort2 = choice(portsProbe2)
    sPort1 = choice(portsSpoof1)
    sPort2 = choice(portsSpoof2)
    portsProbe1.remove(pPort1)
    portsProbe2.remove(pPort2)
    portsSpoof1.remove(sPort1)
    portsSpoof2.remove(sPort2)

    # Probe, in-connection
    ps = subprocess.Popen(['ethtool','-x','enp1s0f0'],stdout=subprocess.PIPE)
    res1 = str(subprocess.check_output(['./rss.sh',probeTuple[0],str(pPort1),probeTuple[1],destPort],stdin=ps.stdout))
    # Probe, out-of-connection
    ps = subprocess.Popen(['ethtool','-x','enp1s0f0'],stdout=subprocess.PIPE)
    res2 = str(subprocess.check_output(['./rss.sh',probeTuple[0],str(pPort2),probeTuple[1],destPort],stdin=ps.stdout))
    # Spoofed, in-connection
    ps = subprocess.Popen(['ethtool','-x','enp1s0f0'],stdout=subprocess.PIPE)
    res3 = str(subprocess.check_output(['./rss.sh',spoofTuple[0],str(sPort1),spoofTuple[1],destPort],stdin=ps.stdout))
    # Spoofed, out-of-connection
    ps = subprocess.Popen(['ethtool','-x','enp1s0f0'],stdout=subprocess.PIPE)
    res4 = str(subprocess.check_output(['./rss.sh',spoofTuple[0],str(sPort2),spoofTuple[1],destPort],stdin=ps.stdout))

    probeIC = res1.split('\\')
    probeOOC = res2.split('\\')
    spoofIC = res3.split('\\')
    spoofOOC = res4.split('\\')

        #IC probe and spoofed on same queue + con/nocon probes on different queues + con/nocon spoofed on different queues + OOC probe and spoofed on same queue
    if probeIC[2] == spoofIC[2] and probeIC[2] != probeOOC[2] and spoofIC[2] != spoofOOC[2] and probeOOC[2] == spoofOOC[2]:
        logging.info('------------------------------------------------------')
        logging.info(f'IC Probes: {probeTuple[0]}:{pPort1} -> {probeTuple[1]}:{destPort}')
        logging.info(f'IC Spoofed: {spoofTuple[0]}:{sPort1} -> {spoofTuple[1]}:{destPort}')
        logging.info(f'''Probe; in-connection:
        {probeIC[0]}
        {probeIC[1]}
        {probeIC[2]} \nSpoofed; in-connection:
        {spoofIC[0]}
        {spoofIC[1]}
        {spoofIC[2]}
        ''')
        logging.info(f'OOC Probes: {probeTuple[0]}:{pPort2} -> {probeTuple[1]}:{destPort}')
        logging.info(f'OOC Spoofed: {spoofTuple[0]}:{sPort2} -> {spoofTuple[1]}:{destPort}')
        logging.info(f'''Probe; out-of-connection:
        {probeOOC[0]}
        {probeOOC[1]}
        {probeOOC[2]} \nSpoofed; out-of-connection:
        {spoofOOC[0]}
        {spoofOOC[1]}
        {spoofOOC[2]}
        ''')
    print(f'Progess: {round((total-len(portsProbe1))/total*100,2)}%',end='\r')

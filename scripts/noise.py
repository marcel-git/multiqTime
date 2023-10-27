from http import client
from time import sleep, time
from threading import Thread
import datetime
import pycurl
from io import BytesIO

class NoiseClient(Thread):

    DO_ABORT = False
    FINISHED = False

    def __init__(self, server, client, max_scale, time_hours):   
        super(NoiseClient, self).__init__()    
        self.SERVER_ADDRESS=server
        self.CLIENT_ADDRESS=client
        self.TIME_INTERVAL=(time_hours*60)/max_scale

    def abort_noiseclient(self):
        NoiseClient.DO_ABORT = True

    def run(self):
        try: 
            #conn = client.HTTPConnection(
            #        host=self.SERVER_ADDRESS[0], port=self.SERVER_ADDRESS[1], source_address=self.CLIENT_ADDRESS)
            pc = pycurl.Curl()
            buffer = BytesIO()
            pc.setopt(pycurl.URL, self.SERVER_ADDRESS[0])
            pc.setopt(pycurl.PORT,  self.SERVER_ADDRESS[1])
            pc.setopt(pycurl.LOCALPORT, self.CLIENT_ADDRESS[1])
            pc.setopt(pycurl.INTERFACE, "enp1s0f0")
            pc.setopt(pycurl.WRITEDATA, buffer)
            print(f"[+] NoiseClient connecting to {self.SERVER_ADDRESS[0]}:{self.SERVER_ADDRESS[1]} with {self.CLIENT_ADDRESS[0]}:{self.CLIENT_ADDRESS[1]}")
            #conn.connect()
            # currenlty starting at 1 because the connection will clsoe otherwise and result in an error
            interval = 1

            finish_time = datetime.datetime.now() + datetime.timedelta(minutes=self.TIME_INTERVAL)
            while not NoiseClient.DO_ABORT:
                pps = NoiseClient.calculate_pps(interval)
                for i in range(0, pps):
                    #conn.request("GET", "/")
                    #resp = conn.getresponse()
                    #resp.read()
                    pc.perform()
                    body = buffer.getvalue()
                    buffer.flush()
                if datetime.datetime.now() > finish_time:
                    finish_time = datetime.datetime.now() + datetime.timedelta(minutes=self.TIME_INTERVAL)
                    interval += 1
                sleep(1)
                
            pc.close()
            #conn.close()
        except Exception as e:
            print(f"[!] Error in noise.py: {e}")
            raise e

        NoiseClient.FINISHED = True
    
    def calculate_pps(n):
        if n == 0:
            return 0
        return 2 ** (n - 1)
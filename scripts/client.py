from http import client
from time import sleep
from threading import Thread


class Webclient(Thread):

    DO_ABORT = False
    CON_INITING = True
    FINISHED = False

    def __init__(self, server, client):   
        super(Webclient, self).__init__()    
        self.SERVER_ADDRESS=server
        self.CLIENT_ADDRESS=client

    def abort_webserver(self):
        Webclient.DO_ABORT = True

    def run(self):
        try: 
            conn = client.HTTPConnection(
                    host=self.SERVER_ADDRESS[0], port=self.SERVER_ADDRESS[1], source_address=self.CLIENT_ADDRESS)
            print(f"[+] Client connecting to {self.SERVER_ADDRESS[0]}:{self.SERVER_ADDRESS[1]} with {self.CLIENT_ADDRESS[0]}:{self.CLIENT_ADDRESS[1]}")
            conn.connect()
            
            while not Webclient.DO_ABORT:
                Webclient.CON_INITING = True

                sleep(0.05) # ensure that probe messages finish before reconnect

                conn.request("GET", "/")
                resp = conn.getresponse()
                resp.read()

                Webclient.CON_INITING = False
                sleep(0.95)

            conn.close()
            sleep(0.2)
        except Exception as e:
            print(f"[!] Error in client.py: {e}")
            raise e;

        Webclient.FINISHED = True
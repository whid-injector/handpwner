#!/usr/bin/python3
import pyfiglet
import sys
import socket
from datetime import datetime
import time, codecs, binascii, re
import crcmod.predefined
from binascii import unhexlify
import argparse
import logging

### ONELINER TO USE:
### for line in $(cat IPs.txt);do python3 handscan_mini.py -m single -s $line ;done >> results_IPs_Scan.txt
### TO R#EMOVE NUL chars from results file:
### tr -d '\000' < results.txt > CLEANED_results.txt

def crcCalc(payload):
    s = unhexlify(payload)
    crc16 = crcmod.predefined.Crc('xmodem')
    crc16.update(s)
    hex=crc16.hexdigest()
    hexbyte1 = hex[0] + hex[1]
    hexbyte2 = hex[2] + hex[3]
    newhex = hexbyte2 + hexbyte1
    packet='ff0a'+payload+newhex+'ff'
    return packet

def scanRange(network,port):
    """ Starts a TCP scan on a given IP address range """
    print('[*] Starting TCP port scan on network %s.0' % network)
    # Iterate over a range of host IP addresses and scan each target
    for host in range(1, 255):
        ip = network + '.' + str(host)
        tcp_scan(ip,port)
    print('[*] TCP scan on network %s.0 complete' % network)


def scan_from_file(filename,port):
    file = open(filename, 'r')
    for line in file:
        print('Line is: '+line)
        print('Port is: '+ str(port))
        query_model(str(line),port)
    
    
def query_model(ip,port):
    """ Creates a TCP socket and attempts to connect via supplied ports """    
    socket.setdefaulttimeout(1.5)
    tcp = socket.socket()
    tcp.connect((ip, port))
    #logging.debug('[+] Address to be scanned: '+address)
    pktz=bytes.fromhex('ff0a00440008c1ff')
    logging.debug('[+] Wake-Up Packet to be sent: ff0a00440008c1ff')
    tcp.send(pktz)
    dataz = tcp.recv(1024)
    dataz.hex()
    tcp.close()
    time.sleep(1)
    #This is the packet that queries for the specific model name
	#echo -n -e "\xff\x0a\x00\x73\x00\x0a\x5d\xff" | nc -q1 192.168.2.212 3001
    socket.setdefaulttimeout(1.5)
    tcp = socket.socket()
    tcp.connect((ip, port))
    pkt=bytes.fromhex('ff0a0073000a5dff')
    tcp.send(pkt)
    data = tcp.recv(1024)
    data.hex()
   # print ('[!] RESPONSE: ' + data.hex())
    resp = data.hex()[10:]
    model = resp[0:2]
    print('<@> IP Addres: '+ ip)
    if model == '00':
        print('<#> Found a HP-1000/HP-2000 model')
        found = 1
        time.sleep(2)
    elif model == '01':
        print('<#> Found a HP-3000 model')
        found = 1
        time.sleep(2)            
    elif model == '02':
        print('<#> Found a HP-4000 model')
        found = 1
        time.sleep(2)
    elif model == '03':
        print('<#> Found a HP-CR model')
        found = 1
        time.sleep(2)
    elif model == '04':
        print('<#> Found a HK-2 model')
        found = 1
        time.sleep(2)
    else :
        print('<#> UKNOWN MODEL!')
        found = 1
        time.sleep(2)
    resp = data.hex()[54:]
    modelname = resp[0:34]
    respz = data.hex()[106:]
    field = respz[0:4]
#    print ('Field is: ' + field)
#    st = respz[0:2]
#    nd = respz[2:4]
#    swapped = nd + st
#    users = int(swapped, 16)
#    print ('nd: '+nd)
#    print ('st: '+st)
    users = int(respz[2:4]+respz[0:2], 16)
    print ('[!] Users Enrolled: ' + str(users))
    print ('[!] Model Name: ' + bytearray.fromhex(modelname).decode())
    tcp.close()


def tcp_scan(ip,port):
    """ Creates a TCP socket and attempts to connect via supplied ports """
    try:
        socket.setdefaulttimeout(0.01)
        # Create a new socket
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Print if the port is open
        if not tcp.connect_ex((ip, port)):
            print('[!] %s:%d/TCP Open' % (ip, port))
            tcp.close()
            time.sleep(1)
            found = 0
	    #This loop is here because the target device has 1byte called "address" that can be in a range 0~254. Therefore for each of these integers we need to generate a packet with valid CRC.
            for x in range(0,254):
                try:
                    if found==0:
		        #This is the Wake-Up Packet (This must be sent to wake up the target BEFORE sending the next CMDs!!!): ff 0a 00 44 00 08 c1 ff
		        #This is the reply from the target device: ff 0a ff 30 03 00 92 1f  da 5e
		        #Quick test: echo -n -e "\xff\x0a\x00\x44\x00\x08\xc1\xff" | nc -q1 192.168.2.212 3001
                        socket.setdefaulttimeout(1.5)
                        tcp = socket.socket()
                        tcp.connect((ip, port))
                        address = format(x, '#04x')[2:]
                        logging.debug('[+] Address to be scanned: '+address)
                        pktz=bytes.fromhex(crcCalc(address+'4400'))#.lower()
                        logging.debug('[+] Wake-Up Packet to be sent: '+crcCalc(address+'4400').lower())
                        tcp.send(pktz)
                        dataz = tcp.recv(1024)
                        dataz.hex()
                        tcp.close()
                        time.sleep(1)
		        #This is the packet that queries for the specific model name
		        #echo -n -e "\xff\x0a\x00\x73\x00\x0a\x5d\xff" | nc -q1 192.168.2.212 3001
                        socket.setdefaulttimeout(1.5)
                        tcp = socket.socket()
                        tcp.connect((ip, port))
                        address = format(x, '#04x')[2:]
                        logging.debug('[+] Address to be scanned: '+address)
                        pkt=bytes.fromhex(crcCalc(address+'7300'))
                        logging.debug('[+] Final Packet to be sent: '+crcCalc(address+'7300').lower())
                        tcp.send(pkt)
                        data = tcp.recv(1024)
                        data.hex()
                        resp = data.hex()[10:]
                        model = resp[0:2]
                        if model == '00':
                            print('<#> Found a HP-1000/HP-2000 model')
                            found = 1
                            time.sleep(2)
                        elif model == '01':
                            print('<#> Found a HP-3000 model')
                            found = 1
                            time.sleep(2)            
                        elif model == '02':
                            print('<#> Found a HP-4000 model')
                            found = 1
                            time.sleep(2)
                        elif model == '03':
                            print('<#> Found a HP-CR model')
                            found = 1
                            time.sleep(2)
                        elif model == '04':
                            print('<#> Found a HK-2 model')
                            found = 1
                            time.sleep(2)
                        else :
                            print('<#> UKNOWN MODEL!')
                            found = 1
                            time.sleep(2)
                        resp = data.hex()[54:]
                        modelname = resp[0:34]
                        print ('[!] Model Name: ' + bytearray.fromhex(modelname).decode())
                        print('[!] Handpunch Address: '+ address +'\n')
                        tcp.close()
                except socket.error:
                    address = format(x, '#04x')[2:]
                    logging.debug('[!] No device with address: ' + address)
                    tcp.close()                 

    except KeyboardInterrupt:
        print("[[!] User Interruption")
        sys.exit()
    except socket.gaierror:
        print("[!] Hostname Could Not Be Resolved")
        sys.exit()
    except socket.error:
        print("[!] Server not responding")
        sys.exit()


if __name__ == '__main__':
    #print(pyfiglet.figlet_format("HANDSCAN", font = "smkeyboard" ))
    #print('Copyright© 2021 - Luca Bongiorni - www.whid.ninja\n\n')
    parser = argparse.ArgumentParser()
    #parser.add_argument('-r', type=str, required=True, help="IP Range. Example: 192.168.2")
    parser.add_argument('-r', type=str, help="IP Range. Example: 192.168.2")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    parser.add_argument('-p', type=int, default=3001, help="Port (default 3001)")
    parser.add_argument('-s', "--single", type=str, help="Single Host IP to scan. Example 10.1.2.3")
    parser.add_argument('-l', "--hostsfile", type=str, help="File containing IPs list. Example IPs_to_scan.txt")
    parser.add_argument('-m', '--mode', required=True, dest='mode', choices=['range', 'single', 'hostsfile'], help="Select scan mode: {single, range, hostsfile}")
    args = parser.parse_args()
    network=args.r
    port=args.p
    ip=args.single
    filename = args.hostsfile
    mode = args.mode
    
    
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
        
    if mode == 'range':
        scanRange(network,port)
    elif mode == 'single':
        query_model(ip,port)
    elif mode == 'hostsfile':
        scan_from_file(filename,port)
    

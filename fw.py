from scapy.all import *
from netfilterqueue import NetfilterQueue
from scapy.layers.inet import IP , TCP , UDP , ICMP 
import logging  
# from firewall import firewall
import time
import json
try:
    logging.basicConfig(
        filename="app.log",
        encoding="utf-8",
        filemode="a",
        format="{asctime} - {levelname} - {message}",
        style="{",
        datefmt="%Y-%m-%d %H:%M",
    )

    f = open("firewallrules.json","r")
    rules = json.load(f)
    f.close()
    DictOfPackets = {}
    ShadowBAN = {}
    if("ListOfBannedIpAddr" in rules):
        if(type(rules["ListOfBannedIpAddr"])==list):
            ListOfBannedIpAddr = rules["ListOfBannedIpAddr"]
        else:
            print("Invalid ListOfBannedIpAddr in rule file. Defaulting to []")
            ListOfBannedIpAddr = []
    else:
        print("ListOfBannedIpAddr missing in rule file. Defaulting to []")
        ListOfBannedIpAddr = []
            
    if("ListOfBannedPorts" in rules):
        if(type(rules["ListOfBannedPorts"])==list):
            ListOfBannedPorts = rules["ListOfBannedPorts"]
        else:
            print("Invalid ListOfBannedPorts in rule file. Defaulting to []")
            ListOfBannedPorts = []
    else:
        print("ListOfBannedPorts missing in rule file. Defaulting to []")
        ListOfBannedPorts = []
            
    if("ListOfBannedPrefixes" in rules):
        if(type(rules["ListOfBannedPrefixes"])==list):
            ListOfBannedPrefixes = rules["ListOfBannedPrefixes"]
        else:
            print("Invalid ListOfBannedPrefixes in rule file. Defaulting to []")
            ListOfBannedPrefixes = []
    else:
        print("ListOfBannedPrefixes missing in rule file. Defaulting to []")
        ListOfBannedPrefixes = []

    if("TimeThreshold" in rules):
        if(type(rules["TimeThreshold"])==int):
            TimeThreshold = rules["TimeThreshold"]
        else:
            print("Invalid TimeThreshold in rule file. Defaulting to 10")
            TimeThreshold = 10
    else:
        print("TimeThreshold missing in rule file. Defaulting to 10")
        TimeThreshold = 10

    if("PacketThreshold" in rules):
        if(type(rules["PacketThreshold"])==int):
            PacketThreshold = rules["PacketThreshold"]
        else:
            print("Invalid PacketThreshold in rule file. Defaulting to 100")
            PacketThreshold = 100
    else:
        print("PacketThreshold missing in rule file. Defaulting to 100")
        PacketThreshold = 100

    if("BlockDOS" in rules):
        if(rules["BlockDOS"]=="True" or rules["BlockDOS"]=="False"):
            BlockDOS = eval(rules["BlockDOS"])
        else:
            print("Invalid BlockDOS in rule file. Defaulting to True")
            BlockDOS = True
    else:
        print("BlockDOS missing in rule file. Defaulting to True")
        BlockDOS = True

except FileNotFoundError:
    print("Rule file (firewallrules.json) not found, setting default values")
    ListOfBannedIpAddr = [] 
    ListOfBannedPorts = []
    ListOfBannedPrefixes = []
    TimeThreshold = 10 #sec
    PacketThreshold = 100    
    BlockDOS = True

def firewall(pkt):
    print('IN FIREWALL')
    sca = IP(pkt.get_payload())

    if(sca.src in ShadowBAN):
        if(time.time() - ShadowBAN[sca.src] <= rules["ShadowBanDuration"]):
            logging.warning("Banned Access : %s"%(sca.src));
            pkt.drop();
            return;
        else:
            logging.warning("Ban lifted : %s"%(sca.src));
            ShadowBAN.pop(sca.src)
    if(sca.src in ListOfBannedIpAddr):
        logging.warning(sca.src, "is a incoming IP address that is banned by the firewall.")
        pkt.drop()
        return 
    
    if(BlockDOS): #attempt at preventing hping3
        # print(sca);
        if(sca.src in DictOfPackets):
            temptime = list(DictOfPackets[sca.src])
            if(len(DictOfPackets[sca.src]) >= PacketThreshold):
                if(time.time()-DictOfPackets[sca.src][0] <= TimeThreshold):
                    logging.warning("Ping by %s blocked by the firewall (too many requests in short span of time)." %(sca.src))
                    ShadowBAN[sca.src] = time.time();
                    logging.warning("Shadow banned : %s"%(sca.src))
                    pkt.drop()
                    return
                else:
                    DictOfPackets[sca.src].pop(0)
                    DictOfPackets[sca.src].append(time.time())
            else:
                DictOfPackets[sca.src].append(time.time())
        else:
            DictOfPackets[sca.src] = [time.time()]
        
        # print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src))		
        # pkt.accept()
        # return 



    if(sca.haslayer(ICMP)):
        t = sca.getlayer(TCP)
        if(t.dport in ListOfBannedPorts):
            logging.warning(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return 

    if(sca.haslayer(TCP)):
        t = sca.getlayer(TCP)
        if(t.dport in ListOfBannedPorts):
            logging.warning(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return 

    if(sca.haslayer(UDP)):
        t = sca.getlayer(UDP)
        if(t.dport in ListOfBannedPorts):
            logging.warning(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return 

    if(True in [sca.src.find(suff)==0 for suff in ListOfBannedPrefixes]):
        logging.warning("Prefix of " + sca.src + " is banned by the firewall.")
        pkt.drop()
        return



    print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src)) 
    pkt.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(1,firewall)
try:
    nfqueue.run()
    print('START')
except KeyboardInterrupt:
	pass

nfqueue.unbind()

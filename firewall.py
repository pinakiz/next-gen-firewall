from scapy.layers.inet import IP , TCP , UDP , ICMP 
import time
ListOfBannedIpAddr = []
ListOfBannedPorts = []
ListOfBannedPrefixes = []
BlockPingAttacks = []
PacketThreshold = 100
TimeThreshold = 10
DictOfPackets = {}

def firewall(pkt):
    sca = IP(pkt.get_payload())

    if(sca.src in ListOfBannedIpAddr):
        print(sca.src, "is a incoming IP address that is banned by the firewall.")
        pkt.drop()
        return 

    if(sca.haslayer(TCP)):
        t = sca.getlayer(TCP)
        if(t.dport in ListOfBannedPorts):
            print(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return 

    if(sca.haslayer(UDP)):
        t = sca.getlayer(UDP)
        if(t.dport in ListOfBannedPorts):
            print(t.dport, "is a destination port that is blocked by the firewall.")
            pkt.drop()
            return 

    if(True in [sca.src.find(suff)==0 for suff in ListOfBannedPrefixes]):
        print("Prefix of " + sca.src + " is banned by the firewall.")
        pkt.drop()
        return

    if(BlockPingAttacks): #attempt at preventing hping3
        t = sca.getlayer(ICMP)
        if(t.code==0):
            if(sca.src in DictOfPackets):
                temptime = list(DictOfPackets[sca.src])
                if(len(DictOfPackets[sca.src]) >= PacketThreshold):
                    if(time.time()-DictOfPackets[sca.src][0] <= TimeThreshold):
                        print("Ping by %s blocked by the firewall (too many requests in short span of time)." %(sca.src))
                        pkt.drop()
                        return
                    else:
                        DictOfPackets[sca.src].pop(0)
                        DictOfPackets[sca.src].append(time.time())
                else:
                    DictOfPackets[sca.src].append(time.time())
            else:
                DictOfPackets[sca.src] = [time.time()]

        print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src))		
        pkt.accept()
        return 

    print("Packet from %s accepted and forwarded to IPTABLES" %(sca.src)) #commented coz its annoying
    pkt.accept()

if __name__ == '__main__':
    print("JUST AN HELPER FUNCTION")
from scapy.all import *
import sqlite3



conn = sqlite3.connect('security.db')
c = conn.cursor()

def createtable():

    c.execute('''CREATE TABLE  IF NOT EXISTS Packets
                (SourceIP text, DestinationIP text, DestPort text, SourPort text,IPType Text)''')
    conn.commit()
createtable()

def insertdata(srcip,dstip,dstport,srcport,type):


    c.execute("INSERT INTO Packets VALUES(?,?,?,?,?)",(srcip,dstip,dstport,srcport,type))
    conn.commit()


def packetsniffing(pkt):
    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
    if TCP in pkt:
        tcp_sport = pkt[TCP].sport
        tcp_dport = pkt[TCP].dport



        if(ip_src=="172.217.31.46"or ip_dst=="172.217.31.46"):
            c.execute("INSERT INTO Packets VALUES(?,?,?,?,?)",(ip_src,ip_dst,tcp_sport,tcp_dport,"Virus"))
            conn.commit()
        else:
            insertdata(ip_src, ip_dst, tcp_dport, tcp_sport," ")



        print( " IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))

        print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))





sniff(prn=packetsniffing, filter="tcp", store=0)
conn.close()

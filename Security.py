from scapy.all import *
import sqlite3
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton,QMainWindow
from PyQt5.QtCore import pyqtSlot
from PyQt5 import QtWidgets
import threading


conn = sqlite3.connect('security.db')
c = conn.cursor()

class App(QMainWindow):

    def __init__(self):
        super().__init__()
        self.title = 'Sniffing'
        self.left = 10
        self.top = 10
        self.width = 520
        self.height = 500
        self.setFixedSize(300,180)
        self.initUI()
    def LoadData(self):
        self.table = QWidget.QTableView(self)  # SELECTING THE VIEW
        self.table.setGeometry(0, 0, 575, 575)
        self.model = QWidget.QStandardItemModel(self)  # SELECTING THE MODEL - FRAMEWORK THAT HANDLES QUERIES AND EDITS
        self.table.setModel(self.model)  # SETTING THE MODEL
        self.table.setEditTriggers(QWidget.QAbstractItemView.NoEditTriggers)
        self.populate()


    def initUI(self):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        button = QPushButton('Sniff', self)
        button.setToolTip('This is an example button')
        button.move(0, 0)
        button.resize(300,180)
        button.clicked.connect(self.on_click)

        self.show()

    @pyqtSlot()
    def on_click(self):
        capture()





def createtable():

    c.execute('''CREATE TABLE  IF NOT EXISTS Packets
                (SourceIP text, DestinationIP text, DestPort text, SourPort text,IPType Text)''')
    conn.commit()
createtable()

def insertdata(srcip,dstip,dstport,srcport,type):


    c.execute("INSERT INTO Packets VALUES(?,?,?,?,?)",(srcip,dstip,dstport,srcport,type))
    conn.commit()

def readdatabase():
    c.execute("SELECT *FROM Packets ")
    conn.commit()
    satırlar = c.fetchall()
def packetsniffing(pkt):

    if IP in pkt:
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        if TCP in pkt:
            tcp_sport = pkt[TCP].sport
            tcp_dport = pkt[TCP].dport



            if(ip_src=="172.217.31.46" or ip_dst=="172.217.31.46"):
                c.execute("INSERT INTO Packets VALUES(?,?,?,?,?)",(ip_src,ip_dst,tcp_sport,tcp_dport,"Virus"))
                conn.commit()
            else:
                insertdata(ip_src, ip_dst, tcp_dport, tcp_sport," ")



        print( " IP src " + str(ip_src) + " TCP sport " + str(tcp_sport))

        print(" IP dst " + str(ip_dst) + " TCP dport " + str(tcp_dport))



def capture():
    sniff(prn=packetsniffing, filter="tcp", store=0,count=50)




app = QApplication(sys.argv)
window=App()
window.show()
app.exec_()
conn.close()

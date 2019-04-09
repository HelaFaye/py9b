#!python2-32
from py9b.link.base import LinkOpenException, LinkTimeoutException
from py9b.link.tcp import TCPLink
#from py9b.link.ble import BLELink
from py9b.link.serial import SerialLink
from py9b.transport.base import BaseTransport as BT
from py9b.transport.packet import BasePacket as PKT
#from py9b.transport.xiaomi import XiaomiTransport
from py9b.transport.ninebot import NinebotTransport
from py9b.command.regio import ReadRegs, WriteRegs

#link = SerialLink(dump=True)
link = TCPLink()
#link = BLELink()

with link:
	print "Scanning..."
	ports = link.scan()
	print ports

	#tran = XiaomiTransport(link)
	tran = NinebotTransport(link)

	link.open(("127.0.0.20:6000"))
#	link.open(ports[0][1])
	print "Connected"

	print 'Reading passwd...'
	pwd = tran.execute(ReadRegs(BT.ESC, 0x17, "6s")) 
	print "Passwd:", pwd

	link.close()

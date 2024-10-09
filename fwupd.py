from __future__ import print_function
from sys import argv, exit
import os
import argparse
from progressbar import ProgressBar

from py9b.link.base import LinkOpenException, LinkTimeoutException
from py9b.transport.base import BaseTransport as BT
from py9b.transport.xiaomi import XiaomiTransport
from py9b.transport.ninebot import NinebotTransport
from py9b.command.regio import ReadRegs, WriteRegs
from py9b.command.update import *

PING_RETRIES = 20


def checksum(s, data):
    for c in data:
        s += c
    return s & 0xFFFFFFFF


def UpdateFirmware(link, tran, dev, fwfile):
    fwfile.seek(0, os.SEEK_END)
    fw_size = fwfile.tell()
    fwfile.seek(0)
    fw_page_size = 0x80

    print("Pinging...", end="")
    for retry in range(PING_RETRIES):
        print(".", end="")
        try:
            if dev == BT.BLE:
                tran.execute(ReadRegs(dev, 0, "13s"))
            else:
                tran.execute(ReadRegs(dev, 0x10, "14s"))
        except LinkTimeoutException:
            continue
        break
    else:
        print("Timed out!")
        return False
    print("OK")

    if args.interface != "blefleet":
        print("Locking...")
        tran.execute(WriteRegs(BT.ESC, 0x70, "<H", 0x0001))
    else:
        print("Not Locking...")

    print("Starting...")
    tran.execute(StartUpdate(dev, fw_size))

    print("Writing...")
    total_pages = fw_size // fw_page_size + (1 if fw_size % fw_page_size else 0)
    pb = ProgressBar(maxval=total_pages).start()
    page = 0
    chk = 0

    while fw_size > 0:
        chunk_sz = min(fw_size, fw_page_size)
        data = fwfile.read(chunk_sz)
        chk = checksum(chk, data)
        
        # Send the WriteUpdate command
        tran.execute(WriteUpdate(dev, page, data + b"\x00" * (fw_page_size - chunk_sz)))
        
        page += 1
        fw_size -= chunk_sz
        
        # Update the progress bar
        pb.update(page)

    pb.finish()

    print("Finalizing...")
    tran.execute(FinishUpdate(dev, chk ^ 0xFFFFFFFF))

    print("Rebooting...")
    tran.execute(RebootUpdate(dev))
    print("Done")
    return True


# The rest of your script remains unchanged
##########################################################################################

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description="Xiaomi/Ninebot firmware flasher",
    epilog="Example 1:  %(prog)s ble ble_patched.bin  - flash ble_patched.bin to BLE using default communication parameters"
    "\nExample 2:  %(prog)s -i tcp -a 127.0.1.10:6000 bms bms115.bin  - flash bms115.bin to BMS over TCP-BLE bridge at 127.0.1.10:6000"
    "\nExample 3:  %(prog)s -i serial -a COM2 esc CFW.bin  - flash CFW.bin to ESC via COM2"
    "\nExample 4:  %(prog)s -i ble -a 12:34:56:78:9A:BC -p ninebot extbms bms107.bin  - flash bms107.bin to Ninebot's external BMS via BLE, use specified BLE address",
)

devices = {"ble": BT.BLE, "esc": BT.ESC, "bms": BT.BMS, "extbms": BT.EXTBMS}
parser.add_argument("device", help="target device", type=str.lower, choices=devices)

parser.add_argument("file", type=argparse.FileType("rb"), help="firmware file")

parser.add_argument(
    "-i",
    "--interface",
    help="communication interface, default: %(default)s",
    type=str.lower,
    choices=("ble", "serial", "tcp", "blefleet", "bleak"),
    default="ble",
)

parser.add_argument(
    "-a",
    "--address",
    help="communication address (ble: BDADDR, serial: port, tcp: host:port), default: first available",
)

protocols = {"xiaomi": XiaomiTransport, "ninebot": NinebotTransport}
parser.add_argument(
    "-p",
    "--protocol",
    help="communication protocol, default: %(default)s",
    type=str.lower,
    choices=protocols,
    default="xiaomi",
)

if len(argv) == 1:
    parser.print_usage()
    exit()
args = parser.parse_args()

if args.device == "extbms" and args.protocol != "ninebot":
    exit("Only Ninebot supports External BMS!")

dev = devices.get(args.device)

if args.interface == "ble":
    try:
        from py9b.link.ble import BLELink
    except ImportError:
        exit("BLE is not supported on your system!")
    link = BLELink()
elif args.interface == "tcp":
    from py9b.link.tcp import TCPLink
    link = TCPLink()
elif args.interface == "serial":
    from py9b.link.serial import SerialLink
    link = SerialLink()
elif args.interface == "blefleet":
    try:
        from py9b.link.blefleet import BLELink
    except ImportError:
        exit("BLE is not supported on your system!")
    link = BLELink()
elif args.interface == "bleak":
    try:
        from py9b.link.bleak import BleakLink
    except ImportError:
        exit("BLE is not supported on your system!")
    link = BleakLink()
else:
    exit("!!! BUG !!! Unknown interface selected: " + args.interface)

with link:
    tran = protocols.get(args.protocol)(link)

    if args.address:
        addr = args.address
    else:
        print("Scanning...")
        ports = link.scan()
        if not ports:
            exit("No interfaces found!")
        print("Connecting to", ports[0][0])
        addr = ports[0][1]

    link.open(addr)
    print("Connected")
    try:
        UpdateFirmware(link, tran, dev, args.file)
    except Exception as e:
        print("Error:", e)
        raise

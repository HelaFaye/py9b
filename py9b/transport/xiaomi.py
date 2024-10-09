from struct import pack, unpack
from .base import checksum, BaseTransport as BT
from .packet import BasePacket
from .ninebot_crypto import NinebotCrypto  # Import the NinebotCrypto library

class XiaomiTransport(BT):
    MASTER2ESC = 0x20
    ESC2MASTER = 0x23
    MASTER2BLE = 0x21
    BLE2MASTER = 0x24
    MASTER2BMS = 0x22
    BMS2MASTER = 0x25
    MOTOR = 0x01
    DEVFF = 0xFF

    _SaDa2Addr = {
        BT.HOST: {
            BT.MOTOR: MOTOR,
            BT.ESC: MASTER2ESC,
            BT.BLE: MASTER2BLE,
            BT.BMS: MASTER2BMS,
        },
        BT.ESC: {
            BT.HOST: ESC2MASTER,
            BT.BLE: MASTER2BLE,
            BT.BMS: MASTER2BMS,
            BT.MOTOR: MOTOR,
        },
        BT.BMS: {BT.HOST: BMS2MASTER, BT.ESC: BMS2MASTER, BT.MOTOR: MOTOR},
        BT.MOTOR: {BT.HOST: MOTOR, BT.ESC: MOTOR, BT.BMS: MOTOR},
    }

    _BleAddr2SaDa = {
        MASTER2ESC: (BT.HOST, BT.ESC),
        ESC2MASTER: (BT.ESC, BT.HOST),
        MASTER2BMS: (BT.HOST, BT.BMS),
        BMS2MASTER: (BT.BMS, BT.HOST),
        MASTER2BLE: (BT.HOST, BT.BLE),
        BLE2MASTER: (BT.BLE, BT.HOST),
        MOTOR: (BT.MOTOR, BT.HOST),
    }

    def __init__(self, link, device=BT.HOST):
        super(XiaomiTransport, self).__init__(link)
        self.device = device
        self.keys = []  # Initialize keys as an empty list
        self.MsgCrypto = NinebotCrypto()  # Create a NinebotCrypto object

    def _make_addr(self, src, dst):
        return XiaomiTransport._SaDa2Addr[src][dst]

    def _split_addr(self, addr):
        if self.device == BT.BMS:
            return XiaomiTransport._BmsAddr2SaDa[addr]
        else:
            return XiaomiTransport._BleAddr2SaDa[addr]

    def _wait_pre(self):
        while self.link.read(1) != b"\x55":
            pass  # Wait for 0x55

        while True:
            c = self.link.read(1)
            if c in (b"\xaa", b"\xab"):
                return c
            elif c != b"\x55":
                break  # Restart waiting for 0x55

    def recv(self):
        ver = self._wait_pre()
        pkt = self.link.read(1)

        # Check if packet is empty
        if not pkt:
            raise ValueError("Received empty packet.")

        l = ord(pkt) + 3 + (4 if ver == b"\xab" else 0)
        pkt.extend(self.link.read(l))

        ck_calc = checksum(pkt[0:-2])
        ck_pkt = unpack("<H", pkt[-2:])[0]
        if ck_pkt != ck_calc:
            raise ValueError("Checksum mismatch!")

        if ver == b"\xab":
            try:
                pkt[1:] = self.MsgCrypto.decrypt(pkt[1:])[:-4]
            except Exception as e:
                raise ValueError(f"Decryption failed: {str(e)}")

        sa, da = self._split_addr(pkt[1])
        return BasePacket(sa, da, pkt[2], pkt[3], pkt[4:-2])  # sa, da, cmd, arg, data

    def send(self, packet):
        dev = self._make_addr(packet.src, packet.dst)
        try:
            if self.keys:
                pkt = pack("<B", len(packet.data) + 2)
                # Use MsgCrypto to encrypt the outgoing message
                pkt += self.MsgCrypto.encrypt(
                    pack("<BBB", dev, packet.cmd, packet.arg) + packet.data + (b"\x00" * 4)
                )
                pkt = b"\x55\xab" + pkt + pack("<H", checksum(pkt))
            else:
                pkt = (
                    pack("<BBBB", len(packet.data) + 2, dev, packet.cmd, packet.arg)
                    + packet.data
                )
                pkt = b"\x55\xaa" + pkt + pack("<H", checksum(pkt))
            self.link.write(pkt)
        except Exception as e:
            raise ValueError(f"Error sending packet: {str(e)}")

    def initiate_pairing(self):
        # Step 1: Send pairing initiation command (0x5B)
        init_packet = BasePacket(src=BT.HOST, dst=BT.BLE, cmd=0x5B, arg=0, data=bytearray())
        self.send(init_packet)

        # Step 2: Parse reply
        reply = self.recv()
        if reply and reply.cmd == 0x5B and reply.arg in [0, 1]:
            serial_number = reply.data[16:30]  # Extract S/N from the reply
            self.pair_with_scooter(serial_number)
        else:
            raise ValueError("Failed to initiate pairing. Check reply.")

    def pair_with_scooter(self, serial_number):
        # Step 3: Send new communication key (0x5C) every second
        new_key = bytearray(16)  # Your new key here (ensure it's constant)
        print("Press the power button to pair with the scooter...")
        while True:
            new_key_packet = BasePacket(src=BT.HOST, dst=BT.BLE, cmd=0x5C, arg=0, data=new_key)
            self.send(new_key_packet)

            # Step 4: Wait for the power button press response (0x5C)
            reply = self.recv()
            if reply and reply.cmd == 0x5C and reply.arg == 1:
                break  # Power button pressed

        # Step 5: Send S/N to complete pairing (0x5D)
        sn_packet = BasePacket(src=BT.HOST, dst=BT.BLE, cmd=0x5D, arg=0, data=serial_number)
        self.send(sn_packet)

        # Step 6: Wait for pairing confirmation
        reply = self.recv()
        if reply and reply.cmd == 0x5D and reply.arg == 1:
            print("Successfully paired with the scooter!")
        else:
            raise ValueError("Pairing failed. Check the response.")

    def recover_keys(self):
        req = BasePacket(src=BT.HOST, dst=BT.BMS, cmd=0x01, arg=0x50, data=bytearray([0x20]))
        self.send(req)
        resp = self.recv()

        # Ensure response is valid before appending
        if resp and resp.data:
            self.keys += resp.data[9:]
        else:
            raise ValueError("Failed to recover keys.")

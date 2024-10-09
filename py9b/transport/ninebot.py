"""Ninebot packet transport"""
from struct import pack, unpack
from .base import checksum, BaseTransport as BT
from .packet import BasePacket
from .ninebot_crypto import NinebotCrypto  # Import your NinebotCrypto class
import os  # For generating random data


class NinebotTransport(BT):
    def __init__(self, link, device=BT.HOST):
        super(NinebotTransport, self).__init__(link)
        self.device = device
        self.use_encryption = False
        self.crypto = NinebotCrypto()  # Persistent NinebotCrypto object

    def _wait_pre(self):
        while self.link.read(1) != b"\x5A":
            pass  # Wait for 5A

        while True:
            c = self.link.read(1)
            if c == b"\xA5":
                return True
            elif c != b"\x5A":
                break  # Restart waiting for 5A

    def recv(self):
        self._wait_pre()
        pkt = self.link.read(1)

        # Check if packet is empty
        if not pkt:
            raise ValueError("Received empty packet.")

        l = ord(pkt) + 6
        for i in range(l):
            pkt += self.link.read(1)

        ck_calc = checksum(pkt[0:-2])
        ck_pkt = unpack("<H", pkt[-2:])[0]
        if ck_pkt != ck_calc:
            raise ValueError("Checksum mismatch!")

        # Decrypt incoming messages using the NinebotCrypto
        data = self.crypto.decrypt(pkt[5:-2]) if self.use_encryption else pkt[5:-2]

        return BasePacket(
            pkt[1], pkt[2], pkt[3], pkt[4], data
        )  # sa, da, cmd, arg, data

    def send(self, packet):
        # Encrypt outgoing messages using the NinebotCrypto
        try:
            data_to_send = self.crypto.encrypt(packet.data) if self.use_encryption else packet.data
        except Exception as e:
            raise ValueError(f"Encryption failed: {str(e)}")

        pkt = (
            pack(
                "<BBBBB",
                len(packet.data),
                packet.src,
                packet.dst,
                packet.cmd,
                packet.arg,
            )
            + data_to_send
        )
        pkt = b"\x5A\xA5" + pkt + pack("<H", checksum(pkt))
        self.link.write(pkt)

    def check_protocol(self):
        # Send initial 0x5B message to check if the device supports encryption
        initial_packet = BasePacket(src=0, dst=0, cmd=0x5B, arg=0, data=b'')
        self.send(initial_packet)

        # Wait for the reply and process it
        reply = self.recv()  # Read the response
        if reply and reply.cmd == 0x5B and reply.arg in (0x00, 0x01):
            # Extract serial number if needed and process the reply
            serial_number = reply.data[16:30]  # Assuming 14-byte serial number at offset 16
            self.pair_with_device(serial_number)
        else:
            raise ValueError("Failed to check protocol or unsupported encryption.")

    def pair_with_device(self, serial_number):
        # Send the 0x5C command with a fixed random data for the communication key
        self.communication_key = os.urandom(16)  # Generate 16 bytes of random data once
        pairing_packet = BasePacket(src=0, dst=0, cmd=0x5C, arg=0, data=self.communication_key)

        while True:
            self.send(pairing_packet)
            reply = self.recv()  # Read the response

            if reply and reply.cmd == 0x5C and reply.arg == 0x01:  # Power button pressed
                break
            # You can add further handling for other reply types if needed

        # Send the 0x5D command with the serial number
        serial_packet = BasePacket(src=0, dst=0, cmd=0x5D, arg=0, data=serial_number)
        
        # Implement retries for sending the 0x5D packet
        for _ in range(3):  # Retry up to 3 times
            self.send(serial_packet)
            final_reply = self.recv()  # Read the final reply
            if final_reply and final_reply.cmd == 0x5D and final_reply.arg == 0x01:
                self.use_encryption = True  # Enable encryption
                print("Successfully paired with the scooter!")
                break
        else:
            raise ValueError("Failed to pair with the scooter after 3 attempts.")

__all__ = ["NinebotTransport"]

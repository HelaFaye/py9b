# py9b
Ninebot/Xiaomi electric scooter communication library and tools.

This fork adds custom UUID support for use with scooters acquired via impound auction or other means.
DO NOT USE THIS ON SCOOTERS THAT DON'T BELONG TO YOU!!!

## Tools
* fwupd.py - firmware flasher capable of flashing BLE/ESC/BMS
* readregs.py - ESC/BMS register file dumper
Other tools are highly experimental.

## Requirements
* Python 3 [www.python.org]
* ProgressBar [pip install progressbar2]
* PySerial [pip install pyserial] - for direct serial UART backend
* PyGatt [pip install pygatt] - for BLED112 dongle backend
* Bleak [pip install bleak] - for Bleak cross-platform BLE backend
* ABLE [https://github.com/b3b/able] - for deprecated Android BLE backend
* usb4a [pip install usb4a] and usbserial4a [pip install usbserial4a] - for Android USB serial implementation
* threading [pip install threading] - for multithreading
* nRFUARTBridge [https://github.com/flowswitch/nRFUARTBridge] - for Android BLE-TCP backend

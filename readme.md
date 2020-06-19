# SmartRF Packet Capture Wireshark Disector

Used with CC2531 USB dongle - flashed with capture Firmware
Tested for zigbee sniffing.

Install TI Smart RF Packet Sniffer ( original version )

in Settings/Packet Broadcast - set the Address to 127.0.0.1, enabled, and probably Broadcast only.

copy tisniffer.lua to \progra~1\Wireshark\3.x

Start wireshark, capture loopback, Filter "udp port 5000"


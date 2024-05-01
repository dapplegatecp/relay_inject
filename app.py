from scapy.all import *
import os

import logging
logger = logging.getLogger("option82_inject")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

app_agent_ip = os.getenv("APP_AGENT_IP", "192.168.27.2")
app_agent_port = os.getenv("APP_AGENT_PORT", 67)
app_curciutid = os.getenv("APP_CIRCUIT_ID")
app_remoteid = os.getenv("APP_REMOTE_ID")

myip = get_if_addr("eth0")
logger.info(f"relay agent: {app_agent_ip} option82: {app_curciutid},{app_remoteid} bind ip: {myip}:{app_agent_port}")
# Create a socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
    # Bind the socket to an interface and port
    local = (myip, int(app_agent_port))
    sock.bind(local)
    # Receive a packet
    logger.info(f"waiting to receive {local}")
    total_packets = 0
    while True:
        packet = sock.recvfrom(65535)
        logger.debug(f"incoming raw {packet}")

        # Parse the packet
        p = BOOTP(packet[0])

        # Print the packet summary
        logger.info(f"new packet: {p.summary()}")
        if p.haslayer(DHCP):
            logger.debug(p.show(dump=True))
        else:
            logger.error("Not a DHCP packet")

        circuitid = app_curciutid
        remoteid = app_remoteid

        option82 = b''

        if circuitid:
            circuitid_hex = circuitid.encode("ascii")
            circuid_len = len(circuitid_hex)
            option82 += bytes([0x01, circuid_len]) + circuitid_hex
        if remoteid:
            remoteid_hex = bytes.fromhex(remoteid)
            remoteid_len = len(remoteid_hex)
            option82 +=  bytes([0x02, remoteid_len]) + remoteid_hex
        else:
            remoteid_hex = p.chaddr[0:6].hex(":").upper().encode("ascii")
            remoteid_len = len(remoteid_hex)
            option82 +=  bytes([0x02, remoteid_len]) + remoteid_hex

        if option82:
            logger.debug(f"option82 raw: {option82}")
            oi = p[DHCP].options.index('end')
            p[DHCP].options.insert(oi, ('relay_agent_information', option82))

        logger.debug(f"outgoing raw: {bytes(p)}")

        # Send the packet
        server_address = (app_agent_ip, 67)
        sock.sendto(bytes(p), server_address)

        total_packets += 1
        logger.info(f"Total packets handled: {total_packets}")
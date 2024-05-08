from scapy.all import *
import hashlib
import os

import threading, queue

import logging
logger = logging.getLogger("option82_inject")
logger.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)

app_curciutid = os.getenv("APP_CIRCUIT_ID")
app_remoteid = os.getenv("APP_REMOTE_ID")

q = queue.Queue()

logger.info(f"option82: {app_curciutid},{app_remoteid}")

def recv_handler(q):
    total_packets = 0
    last_packet_hash = None
    while True:
        iface, p = q.get()
        packet_hash = hashlib.sha256(bytes(p)).digest()
        if packet_hash == last_packet_hash:
            last_packet_hash = None
            logger.debug(f"packet hash matches previous: {packet_hash}, ignoring")
            continue
        logger.info(f"interface: {iface} new packet: {p.summary()}")
        logger.debug(f"interface: {iface} hash: {packet_hash} incoming raw: {bytes(p)}")
        if p.haslayer(DHCP):
            logger.debug(p.show(dump=True))
        else:
            logger.error("Not a DHCP packet")
            continue

        # only modify packet when outgoing is gt0 (which means incoming is eth0) AND if it's dhcp discover or request
        if iface == "eth0" and (p[DHCP].options[0][1] == 1 or p[DHCP].options[0][1] == 3):
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

            # Recalculate the len/chksum
            del p[IP].len
            del p[IP].chksum
            del p[UDP].len
            del p[UDP].chksum
            p= p.__class__(bytes(p))
            packet_hash = hashlib.sha256(bytes(p)).digest()
            total_packets += 1
            logger.info(f"Total packets handled: {total_packets}")

        oiface = "eth0" if iface == "gt0" else "gt0"
        logger.debug(f"hash {packet_hash} oiface: {oiface} outgoing raw: {bytes(p)}")
        last_packet_hash = packet_hash
        sendp(p, iface=oiface)

def recv_thread(iface, q):
    sniff(iface=iface, filter="udp and (port 67 or port 68)", prn=lambda p: q.put((iface,p)))

for i in ("eth0", "gt0"):
    t = threading.Thread(target=recv_thread, args=(i, q))
    t.start()

recv_handler(q)

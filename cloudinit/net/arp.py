import os
import queue
import random
import socket
import struct
import sys
import threading
import time
from array import array
from ipaddress import IPv4Address
from typing import Iterator

# NOTE:
# Per [1] RFC 3927 is rejected, so this POC is not expected to outlive its
# infancy
#
# [1] https://www.rfc-editor.org/errata/rfc3927
# https://datatracker.ietf.org/doc/html/rfc3927#section-2.1

# https://tuprints.ulb.tu-darmstadt.de/6243/1/TR-18.pdf
# https://github.com/secdev/scapy/blob/master/scapy/layers/l2.py
#
# man packet
# man socket
# man raw
# man ip

#
# Commands for verification:
#
# arping -A -i eth0 10.0.0.1
# sudo tcpdump -lni  wlp2s0 arp
# ip neigh show

# Assumes L2 supports arp
# fmt: off
PROBE_WAIT          =  1 # second   (initial random delay)
PROBE_NUM           =  3 #          (number of probe packets)
PROBE_MIN           =  1 # second   (minimum delay till repeated probe)
PROBE_MAX           =  2 # seconds  (maximum delay till repeated probe)
ANNOUNCE_WAIT       =  2 # seconds  (delay before announcing)
ANNOUNCE_NUM        =  2 #          (number of announcement packets)
ANNOUNCE_INTERVAL   =  2 # seconds  (time between announcement packets)
MAX_CONFLICTS       = 10 #          (max conflicts before rate limiting)
RATE_LIMIT_INTERVAL = 60 # seconds  (delay between successive attempts)
DEFEND_INTERVAL     = 10 # seconds  (minimum interval between defensive ARPs).
ETH_BROADCAST       = [0xFFFF, 0xFFFF, 0xFFFF]
ETH_TYPE_ARP        = 0x0806
OP_REQUEST          = 1
OP_REPLY            = 2
# fmt: on


def get_pseudo_random_ip(mac) -> Iterator[IPv4Address]:
    """169.254.1.0 to 169.254.254.255"""

    # mac might be identical from copied images, time might be identical from
    # simultaneous launch, hopefully /dev/random is smarter than we are
    # TODO: improve this
    random.seed(
        "".join(
            [
                mac,
                str(time.time()),
                str((f := open("/dev/random", "rb")).read(32)),
            ]
        )
    )
    f.close()

    while True:
        yield IPv4Address(
            "169.254.{}.{}".format(
                random.randint(1, 254),
                random.randint(0, 255),
            )
        )


def get_ips(_) -> Iterator[IPv4Address]:
    for i in range(1, 255):
        for j in range(0, 256):
            yield IPv4Address("169.254.{}.{}".format(i, j))


def gratuitous_arp(ip, mac, socket):
    sender_hardware_address = mac
    sender_ip_address = 0
    target_hardware_address = 0
    # TODO: continue here
    raise NotImplemented()

def arp_listen(socket):
    return socket.recv(4096)


def listening_thread(queue, event, socket):
    while not event.is_set():
        try:
            if val := arp_listen(socket):
                queue.put(val)
        except TimeoutError:
            pass
        except Exception as e:
            print(e)
            os._exit(1)


def gather_arps(socket):
    """Start thread that listens for arps, queue them"""
    q = queue.Queue()
    e = threading.Event()
    t = threading.Thread(
        name="arp listener",
        target=listening_thread,
        args=(q, e, socket),
    )
    t.start()
    return (q, e, t)


def arp_matches_mac(mac, ret) -> bool:
    raise NotImplemented


def is_ip_in_use(ip: IPv4Address, mac, queue, socket) -> bool:
    t_init = time.time()
    t_max = t_init + PROBE_WAIT

    def time_left():
        return t if (t := t_max - time.time()) >= 0 else 0

    gratuitous_arp(ip, mac, socket)
    while True:
        try:
            val = queue.get(block=True, timeout=time_left)
            if arp_matches_mac(mac, val):
                print("arp matches!")
                print(val)
                return True
            else:
                print("received arp:")
                print(val)
        except queue.Empty:
            break
    return False
    print("Timeout out")


def select_link_local_ipv4_address(mac, socket, scan=False):
    ip = None
    get_ip = get_pseudo_random_ip if not scan else get_ips
    queue, event, thread = gather_arps(socket)
    for ip in get_ip(mac):
        # Use first free address
        if response := is_ip_in_use(ip, mac, queue, socket):
            print(f"Address {ip} is in use: {response}")
        else:
            print(f"Address selected: {ip}")
            if not scan:
                return ip
    print("No address available")
    event.set()
    thread.join()


def discover_interace(iface):
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        s.bind((iface, ETH_TYPE_ARP))
        s.settimeout(0.5)
        mac = s.getsockname()[4]
    except OSError as e:
        print(e)
        raise
    return (s, mac)


def get_hw_addr(addr: bytes) -> str:
    return ":".join("{:02x}".format(i) for i in addr)


def get_src_hw(frame: bytes) -> str:
    return get_hw_addr(frame[0:6])


def get_dst_hw(frame: bytes) -> str:
    return get_hw_addr(frame[6:12])


def get_ipv4_addr(addr: bytes) -> IPv4Address:
    return IPv4Address(".".join(str(int(i)) for i in addr))


def get_src_ipv4(frame: bytes) -> IPv4Address:
    return get_ipv4_addr(frame[28:32])


def get_dst_ipv4(frame: bytes) -> IPv4Address:
    return get_ipv4_addr(frame[38:42])


def get_op(frame: bytes) -> int:
    return int(frame[21:22][0])


def get_op_name(frame: bytes) -> str:
    op = get_op(frame)
    if op == OP_REQUEST:
        return "Request"
    elif op == OP_REPLY:
        return "Reply"
    else:
        raise ValueError(
            f"Invalid op: {op} is not in set({OP_REQUEST}, {OP_REPLY})"
        )

def arp_dump(iface, debug=False):
    """Implementation doesn't use promiscuous mode. Only arps directed to
    the specified iface or broadcast will be observed.
    """
    socket, _ = discover_interace(iface)
    queue, event, thread = gather_arps(socket)
    try:
        while True:
            frame = queue.get()
            print(
                "op: {}\nsrc mac: {} src ip: {}\ndst mac: {} src ip: {}".format(
                    get_op_name(frame),
                    get_src_hw(frame),
                    get_src_ipv4(frame),
                    get_dst_hw(frame),
                    get_dst_ipv4(frame),
                )
            )
            if debug:
                print(frame)
    except KeyboardInterrupt:
        print("Done!")

    event.set()
    thread.join()
    socket.close()

def to_network_byte_order(packet: array):
    length = len(packet)
    format_str = f'!{length}H'
    out = array("H",
        struct.unpack(format_str, packet)
    )
    return out

def pretty_print(packet: array):
    """perhaps only in the eye of the beholder"""
    print("\n".join("{:04x}".format(short) for short in packet))

def arp_probe(iface, probe_ip: IPv4Address):
    socket, mac = discover_interace(iface)

    # Broadcast frame in network byte order
    # each list element is 2 bytes in the header

    arp_probe_payload = [
            0x0001,  # Ethernet
            0x0800,  # IPv4
            0x0604,  # mac address is 6 bytes, IPv4 address is 4
            0x0001,  # operation:  1 is request, 2 is reply
            int.from_bytes(mac[0:2], byteorder=sys.byteorder),
            int.from_bytes(mac[2:4], byteorder=sys.byteorder),
            int.from_bytes(mac[4:6], byteorder=sys.byteorder),
            0x0000,  # SPA:
            0x0000,  # THA:
            int.from_bytes(probe_ip.packed[0:2], byteorder=sys.byteorder),
            int.from_bytes(probe_ip.packed[2:4], byteorder=sys.byteorder),
    ]
    ether_frame = array("H", [
        # Destination address:
        *ETH_BROADCAST,
        # Source address:
        int.from_bytes(mac[0:2], byteorder=sys.byteorder),
        int.from_bytes(mac[2:4], byteorder=sys.byteorder),
        int.from_bytes(mac[4:6], byteorder=sys.byteorder),
        # Protocol
        ETH_TYPE_ARP,
        # Data
        *arp_probe_payload,
    ])
    nbo_packet = to_network_byte_order(ether_frame)

    # currently packets are malformed after the opcode
    # TODO: Investigate
    # print("mac:")
    # print(int.from_bytes(mac[0:2], byteorder=sys.byteorder))
    print("sending packet:")
    pretty_print(nbo_packet)
    socket.send(nbo_packet)
    socket.close()

def arping(iface):
    socket, mac = discover_interace(iface)
    select_link_local_ipv4_address(mac, socket, scan=False)
    socket.close()


if "__main__" == __name__:
    try:
        arp_probe(sys.argv[1], IPv4Address(sys.argv[2]))
        # arping(sys.argv[1])
        # arp_dump(sys.argv[1])
    except PermissionError:
        print("Command requires root")

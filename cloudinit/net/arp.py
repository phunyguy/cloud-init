from ipaddress import IPv4Address
import random
import time
import sys
import os
import typing
import queue
import threading
import socket
import struct
# https://datatracker.ietf.org/doc/html/rfc3927#section-2.4
#
# Commands for verification:
#
# arping -A -i eth0 10.0.0.1
# sudo tcpdump -lni  wlp2s0 arp
# ip neigh show

# Assumes L2 supports arp
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

ETH_BROADCAST = 'ff:ff:ff:ff:ff:ff'
ETH_TYPE_ARP = 0x0806


# Note: section 1.6 says not to use dhcp in 169.254/16, but cloud-init does


def get_pseudo_random_ip(
        mac) -> typing.Iterator[IPv4Address]:
    """169.254.1.0 to 169.254.254.255"""

    # mac might be identical from copied images, time might be identical from
    # simultaneous launch, hopefully /dev/random is smarter than we are
    # TODO: improve this
    random.seed(
            "".join([
                    mac,
                    str(time.time()),
                    str((f := open("/dev/random", "rb")).read(32))
                ])
    )
    f.close()

    while True:
        yield IPv4Address("169.254.{}.{}".format(
                random.randint(1, 254),
                random.randint(0, 255),
            )
        )

def get_ips(_) -> typing.Iterator[IPv4Address]:
    for i in range(1, 255):
        for j in range(0, 256):
            yield IPv4Address("169.254.{}.{}".format(i, j))


# https://github.com/secdev/scapy/blob/master/scapy/layers/l2.py
# https://jrydberg-blog.tumblr.com/post/10518729490/sending-a-gratuitous-arp-with-python
# https://datatracker.ietf.org/doc/html/rfc3927#section-2.1
def gratuitous_arp(ip, mac, socket):
    sender_hardware_address = mac
    sender_ip_address = 0
    target_hardware_address = 0
    # TODO: continue here
    raise NotImplemented()

    # Broadcast frame in network byte order
    struct.iter_unpack(
        "!h",
        [
            0x0001,  # Ethernet
            0x0800,  # IPv4
            0x0604,  # mac address is 6 bytes, IPv4 address is 4
            0x0002,  # operation:  1 is request, 2 is reply
            hex(mac[0:2]),
            hex(mac[2:4]),
            hex(mac[4:6]),
        ])
    gratuitous_arp = [
        # HTYPE
        struct.pack("!h", 1),
        # PTYPE (IPv4)
        struct.pack("!h", 0x0800),
        # HLEN
        struct.pack("!B", 6),
        # PLEN
        struct.pack("!B", 4),
        # OPER (reply)
        struct.pack("!h", 2),
        # SHA
        ether_addr,
        # SPA
        socket.inet_aton(address),
        # THA
        ether_addr,
        # TPA
        socket.inet_aton(address)
        ]
    ether_frame = [
        # Destination address:
        ether_aton(ETH_BROADCAST),
        # Source address:
        mac,
        # Protocol
        struct.pack("!h", ETH_TYPE_ARP),
        # Data
        ''.join(gratuitous_arp)
        ]
    socket.send(''.join(ether_frame))
    socket.close()

def arp_listen(socket):
    """Needs to timeout every second or so for event checking & cleanup"""
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

def gather_arps(mac, socket):
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

def arp_matches_mac(mac, ret):
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
    queue, event, thread = gather_arps(mac, socket)
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
        s.settimeout(0.1)
        mac = s.getsockname()[4]
    except OSError as e:
        print(e)
        raise
    return (s, mac)

def get_src_hw(frame: bytes) -> str:
    return get_hw_addr(frame[0:6])

def get_dst_hw(frame: bytes) -> str:
    return get_hw_addr(frame[6:12])

def get_hw_addr(addr: bytes) -> str:
    return ':'.join('%02x'%i for i in addr)


def arpdump(iface):
    socket, mac = discover_interace(iface)
    queue, event, thread = gather_arps(mac, socket)
    try:
        while True:
            frame = queue.get()
            print("src: {}\ndst: {}".format(
                get_src_hw(frame),
                get_dst_hw(frame),
            ))
            print(frame)
    except KeyboardInterrupt:
        print("Done!")

    event.set()
    thread.join()

def arping(iface):
    s, mac = discover_interace(iface)
    select_link_local_ipv4_address(mac, s, scan=False)

if "__main__" == __name__:
    try:
        #arping(sys.argv[1])
        arpdump(sys.argv[1])
    except PermissionError:
        print("Command requires root")

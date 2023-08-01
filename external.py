from scapy.all import *
import pandas as pd
import multiprocessing

packetRow = []
new_rows_count = 0
# ftp_dest_IP = ''
# ftp_src_IP = ''
# ftp_packet_len = ''

# ssh_dest_IP = ''
# ssh_src_IP = ''
# ssh_packet_len = ''

# tcp_dest_IP = ''
# tcp_src_IP = ''
# tcp_packet_len = ''


def ftp(packet):
    # getting the destination ( IP address from header)
    # global ftp_dest_IP
    # global ftp_src_IP
    # global ftp_packet_len
    ftp_dest_IP = packet.getlayer(IP).dst
    ftp_src_IP = packet.getlayer(IP).src
    ftp_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    raw = raw + "FTP"
    packetRow.append([ftp_src_IP, ftp_dest_IP, ftp_packet_len, raw])
    global new_rows_count
    new_rows_count += 1
    print(packetRow)


def ftp_sniffer(iface = 'enp0s3'):
    conf.iface = iface
    try:
        # sniffing FTP (port 21) - the ftp function will process the packets
        sniff(filter='tcp port 21', prn=ftp)

    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)


def ssh(packet):
    global ssh_dest_IP
    # global ssh_src_IP
    # global ssh_packet_len
    # getting the destination ( IP address from header)
    ssh_dest_IP = packet.getlayer(IP).dst
    ssh_src_IP = packet.getlayer(IP).src
    ssh_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    raw = raw + "SSH"
    packetRow.append([ssh_src_IP, ssh_dest_IP, ssh_packet_len, raw])
    global new_rows_count
    new_rows_count += 1
    # return ssh_dest_IP, ssh_src_IP, ssh_packet_len, raw

def ssh_sniffer(iface = 'enp0s3'):
    conf.iface = iface
    try:
        # sniffing SSH (port 22) - the ssh function will process the packets
        sniff(filter='tcp port 22', prn=ssh)
    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)


def tcp(packet):
    # global tcp_dest_IP
    # global tcp_src_IP
    # global tcp_packet_len
    # # getting the destination ( IP address from header)
    tcp_dest_IP = packet.getlayer(IP).dst
    src_port = packet.getlayer(TCP).sport
    tcp_src_IP = packet.getlayer(IP).src
    tcp_packet_len = packet.getlayer(IP).len
    # getting raw packet load data
    raw = packet.sprintf('%Raw.load%')
    raw = raw + "TCP"
    if (src_port != 21):
        if (src_port != 22):
            packetRow.append([tcp_src_IP, tcp_dest_IP, tcp_packet_len, raw])
            global new_rows_count
            new_rows_count += 1

def tcp_sniffer(iface = 'enp0s3'):
    conf.iface = iface
    try:
        sniff(filter='tcp', prn=tcp)
    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)
        
        
def http(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_len = packet[IP].len
        method = packet[HTTPRequest].Method.decode()
        raw = f"{method}{RESET} + {url}"
        if packet.haslayer(Raw) and method == "POST":
            raw = f"{method}{RESET} + {url} + {packet[Raw].load}{RESET}"
        raw = raw + "TCP"
        packetRow.append([src_IP, dest_IP, packet_len, raw])
        global new_rows_count
        new_rows_count += 1
        
def http_sniffer(iface = 'enp0s3'):
    conf.iface = iface
    try:
        sniff(filter='port 80', prn=http)
    except KeyboardInterrupt as e:
        print("[-] Closing function")
        exit(0)

def packetSniff():
    try:
        t1 = multiprocessing.Process(target = ftp_sniffer)
        t2 = multiprocessing.Process(target = ssh_sniffer)
        t3 = multiprocessing.Process(target = tcp_sniffer)
        t1.start()
        t2.start()
        t3.start()
        # ftp_sniffer('enp0s3')
        # ssh_sniffer('enp0s3')
        # tcp_sniffer('enp0s3')
        # print(packetRow)
        # http_sniffer('enp0s3')
        # df = df.append(pd.DataFrame(packetRow,
        #            columns=[ 'src_IP', 'dest_IP', 'packet_len', 'data']),
        #            ignore_index = True)
        # display(df)
    except KeyboardInterrupt as e:
        # print(packetRow)
        exit(0)
        # df = df.append(pd.DataFrame(packetRow,
        #            columns=[ 'src_IP', 'dest_IP', 'packet_len', 'data']),
        #            ignore_index = True)
       
packetSniff()
# ftp_sniffer('lo')

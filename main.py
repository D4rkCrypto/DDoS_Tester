#coding:utf-8

import core
from myparser import myparser

class bcolors:
    """terminal colors"""
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    SKY = '\033[36m'
    WHITE = '\033[37m'
    ENDC = '\033[0m'

def main():
    LOGO = r'''
 ____  ____   ___  ____    _____         _
|  _ \|  _ \ / _ \/ ___|  |_   _|__  ___| |_ ___ _ __
| | | | | | | | | \___ \    | |/ _ \/ __| __/ _ \ '__|
| |_| | |_| | |_| |___) |   | |  __/\__ \ ||  __/ |
|____/|____/ \___/|____/    |_|\___||___/\__\___|_|
    '''
    print(bcolors.BLUE+LOGO+bcolors.ENDC)
    args = myparser()
    attack = core.attack(args)
    {
        1: attack.UDP_Flood,
        2: attack.ICMP_Flood,
        3: attack.NTP_Amplification,
        4: attack.SNMP_Amplification,
        5: attack.SSDP_Amplification,
        6: attack.DNS_Amplification
    }[args.type]()

if __name__ == '__main__':
    main()

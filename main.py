import core
from myparser import my_parser


class COLORS:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    PURPLE = '\033[35m'
    SKY = '\033[36;1m'
    WHITE = '\033[37m'
    END = '\033[0m'


def main():
    logo = r'''
             ____  ____   ___  ____    _____         _
            |  _ \|  _ \ / _ \/ ___|  |_   _|__  ___| |_ ___ _ __
            | | | | | | | | | \___ \    | |/ _ \/ __| __/ _ \ '__|
            | |_| | |_| | |_| |___) |   | |  __/\__ \ ||  __/ |
            |____/|____/ \___/|____/    |_|\___||___/\__\___|_|
    '''
    print(COLORS.SKY + logo + COLORS.END)
    print(' ' * 29 + COLORS.BLUE + 'Written by D4rk7r4c3r' + COLORS.END)
    print('\n' + ' ' * 25 + 'Press Ctrl+C to stop attack')
    args = my_parser()
    core.ATTACK(args)


if __name__ == '__main__':
    main()

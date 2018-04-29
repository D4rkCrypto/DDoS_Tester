import sys
import argparse

def myparser():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("target",
                        help="Specify target ip")
    parser.add_argument("-p", "--port",
                        type=int,
                        help="Specify target port")
    parser.add_argument("-t", "--type",
                        type=int,
                        required=True,
                        help="Specify attack type")
    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        sys.exit(1)
    return parser.parse_args()

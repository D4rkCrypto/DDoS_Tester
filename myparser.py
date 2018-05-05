import sys
import argparse


def my_parser():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument("target_ip",
                        type=str,
                        help="Specify target ip")

    parser.add_argument("--type", required=True,
                        type=int,
                        help="Specify attack type")

    parser.add_argument("--threads",
                        type=int,
                        help="Specify target port")

    parser.add_argument("--target_port",
                        type=int,
                        help="Specify target port")

    parser.add_argument("--file",
                        type=str,
                        help="Specify DRDoS server list file")

    if len(sys.argv) == 1:
        parser.print_usage(sys.stderr)
        sys.exit(1)
    return parser.parse_args()

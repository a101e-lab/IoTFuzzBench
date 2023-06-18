#!/usr/bin/python3
# -*- coding: UTF-8 -*-

from util.generator import *
from util.captor import *
import argparse


def print_logo():
    logo = """
 ___    _____ _____               ____
|_ _|__|_   _|  ___|   _ ________/ ___| ___ _ __
 | |/ _ \| | | |_ | | | |_  /_  / |  _ / _ \ '_ \\
 | | (_) | | |  _|| |_| |/ / / /| |_| |  __/ | | |
|___\___/|_| |_|   \__,_/___/___|\____|\___|_| |_|
    """
    print(logo)


if __name__ == "__main__":

    print_logo()
    parser = argparse.ArgumentParser(description="Automatically generate fuzzers")
    # group = parser.add_mutually_exclusive_group()
    # group.add_argument("-c", "--capture", action="store_true", help="the network interface")
    # group.add_argument("-g", "--generate", action="store_true", help="generate fuzzers")
    parser.add_argument("action", choices=["capture", "generate_by_pcap","generate_by_seed"], help="the action")
    parser.add_argument("-i", "--interface", help="the network interface")
    parser.add_argument("-ip", help="the target ip")
    parser.add_argument("-port", help="the target port")
    parser.add_argument("-policy", choices=["boo_default", "boo_byte","boo_reversal","pdfuzzergen"], help="the action")
    parser.add_argument("file", help="the input file")
    args = parser.parse_args()

    if args.action == "capture" and args.file and args.interface:
        network_interface = args.interface
        output_pcap_file = args.file
        traffic_monitoring(network_interface, output_pcap_file)
    elif args.action == "generate_by_pcap" and args.file:
        start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        input_pcap_file = args.file
        fuzz_template_generation_by_pcap(input_pcap_file, start_time)
    elif args.action == "generate_by_seed" and args.file:
        # start_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        start_time = '1'
        input_seed_file = args.file
        target_ip = args.ip
        target_port = int(args.port)
        fuzz_policy = args.policy
        fuzz_template_generation_by_seed(input_seed_file,target_ip,target_port, fuzz_policy, start_time)
    else:
        parser.print_help()

#!/usr/bin/env python3
# This file is part of cloud-init. See LICENSE file for license information.

"""Arping tool"""
import argparse

import cloudinit.net.arp as arp

NAME = "arp"


def get_parser(parser=None):
    """Build or extend and arg parser for arp utility.

    @param parser: Optional existing ArgumentParser instance.

    @returns: ArgumentParser with proper argument configuration.
    """
    if not parser:
        parser = argparse.ArgumentParser(prog=NAME, description=__doc__)
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        type=str,
        help="Network interface to use",
    )

    parser.add_argument(
        "-p",
        "--ping",
        type=bool,
        help="Arping",
    )

    parser.add_argument(
        "-d",
        "--dump",
        type=bool,
        help="Dump arp info (kill with ctrl-c)",
    )



def handle_args(_, args):
    if args.dump:
        arp.arpdump(args.interface)
    elif args.ping:
        arp.arping(args.interface)
    else:
        raise NotImplementedError("nope")

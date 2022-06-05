#!/usr/bin/env python3
# This file is part of cloud-init. See LICENSE file for license information.

"""Arping tool"""
import argparse

import cloudinit.net.arp as arp

NAME = "arp"


def get_parser(parser=None):
    """Build or extend and arg parser for arp utility.

    @param parser: Optional existing ArgumentParser instance representing the
        subcommand which will be extended to support the args of this utility.

    @returns: ArgumentParser with proper argument configuration.
    """
    if not parser:
        parser = argparse.ArgumentParser(prog=NAME, description=__doc__)
    parser.add_argument(
        "-i",
        "--interface",
        required=True,
        type=str,
        help="Network interface to ping from",
    )


def handle_args(_, args):
    arp.arpdump(args.interface)

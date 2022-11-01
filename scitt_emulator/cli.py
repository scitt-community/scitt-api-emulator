# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse

from scitt_emulator import client, server


def cli(fn):
    parser = fn(description="SCITT emulator")
    sub = parser.add_subparsers(dest="cmd", help="Command to execute", required=True)

    client.cli(lambda *args, **kw: sub.add_parser("client", *args, **kw))
    server.cli(lambda *args, **kw: sub.add_parser("server", *args, **kw))

    return parser


def main(argv=None):
    parser = cli(argparse.ArgumentParser)
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3

from argparse import ArgumentParser
from analyzer import Analyzer
from debugger import Debugger


def get_parameters() -> object:
    """
    gets all program parameters using argparse
    """
    parser = ArgumentParser(description="Timeless Debugger")
    parser.add_argument("binary", type=str, help="Binary file to debug")
    parser.add_argument("--output-file", type=str, help="Specifies an output file for logs")
    return parser.parse_args()


def check_elf(binary_infos: dict) -> None:
    """
    exits if given infos don't correspond to an ELF binary
    """
    if binary_infos.get("magic_number") != 0x7f or binary_infos.get("format") != "ELF":
        name = binary_infos.get("name") if binary_infos.get("name") else "Given file"
        print(f"[-] {name} is not an ELF binary")
        exit(1)


def run() -> None:
    """
    launches all tasks for debugger
    """
    parameters = get_parameters()
    analyzer = Analyzer(parameters.binary, logs=vars(parameters).get("output-file"))
    analyzer.run()
    binary_infos = analyzer.get()
    check_elf(binary_infos)
    debugger = Debugger(binary_infos)
    debugger.run()

if __name__ == "__main__":
    run()

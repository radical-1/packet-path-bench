"""Summarize paired count-minus-pass runtimes from benchmark CSV files."""

import argparse
import csv
from math import isfinite
from pathlib import Path
from statistics import median


def paired_deltas(rows, count_mode, pass_mode):
    trials = {}
    for row in rows:
        mode = row["mode"]
        if mode not in (count_mode, pass_mode):
            continue
        repeat = int(row["repeat"])
        runtime = float(row["bpf_ns_per_run"])
        if not isfinite(runtime) or runtime < 0:
            raise ValueError(f"repeat {repeat}: invalid {mode} runtime")
        modes = trials.setdefault(repeat, {})
        if mode in modes:
            raise ValueError(f"repeat {repeat}: duplicate {mode} trial")
        modes[mode] = runtime

    if not trials:
        raise ValueError(f"no trials for {count_mode} or {pass_mode}")
    deltas = []
    for repeat, modes in sorted(trials.items()):
        for mode in (count_mode, pass_mode):
            if mode not in modes:
                raise ValueError(f"repeat {repeat}: missing {mode} trial")
        deltas.append(modes[count_mode] - modes[pass_mode])
    return deltas


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv_paths", nargs="+", type=Path)
    args = parser.parse_args()

    for path in args.csv_paths:
        try:
            with path.open(newline="") as file:
                rows = list(csv.DictReader(file))
            print(path)
            for label, count, control in (
                ("Generic XDP", "xdp-generic", "xdp-pass"),
                ("TC ingress", "tc", "tc-pass"),
            ):
                deltas = paired_deltas(rows, count, control)
                positive = sum(delta > 0 for delta in deltas)
                print(f"  {label}: median {median(deltas):+.2f} ns, "
                      f"range {min(deltas):+.2f} to {max(deltas):+.2f} ns, "
                      f"count slower in {positive}/{len(deltas)} pairs")
        except (OSError, ValueError, KeyError, TypeError) as error:
            parser.error(f"{path}: {error}")


if __name__ == "__main__":
    main()

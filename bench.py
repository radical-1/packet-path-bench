"""Compare ingress counters on a private veth link."""
import argparse
import csv
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
from uuid import uuid4

MODES = ("baseline", "xdp-generic", "tc")
OBJECT = Path(__file__).with_name("ingress.bpf.o").resolve()
PASS_OBJECT = OBJECT.with_name("pass.bpf.o")
DESTINATION = "192.0.2.2"


def run(*command, **kwargs):
    return subprocess.run(command, check=True, text=True, **kwargs)


def bpf_programs(*selector):
    return json.loads(run("bpftool", "-j", "prog", "show", *selector,
                          capture_output=True).stdout)


def attached_program_id(namespace, mode):
    if mode.startswith("xdp"):
        output = run("ip", "-j", "-n", namespace, "link", "show", "dev", "rx0",
                     capture_output=True)
        link, = json.loads(output.stdout)
        xdp = link.get("xdp", {})
        # XDP_ATTACHED_SKB (2) identifies generic XDP in iproute2 JSON.
        programs = [entry.get("prog", {}) for entry in xdp.get("attached", [xdp])
                    if entry.get("mode") == 2]
    else:
        output = run("ip", "netns", "exec", namespace, "tc", "-j", "filter",
                     "show", "dev", "rx0", "ingress", capture_output=True)
        programs = [entry.get("options", {}).get("prog", {})
                    for entry in json.loads(output.stdout) if entry.get("kind") == "bpf"]
    ids = [program["id"] for program in programs if program.get("id")]
    if len(ids) != 1:
        raise RuntimeError(f"Expected one {mode} program on {namespace}/rx0, got {ids}")
    return str(ids[0])


def trial(mode, args):
    token = uuid4().hex[:8]
    tx, rx = f"ppb-tx-{token}", f"ppb-rx-{token}"
    namespaces = []
    server = None
    try:
        for namespace in (tx, rx):
            run("ip", "netns", "add", namespace)
            namespaces.append(namespace)
        run("ip", "-n", tx, "link", "add", "tx0", "type", "veth", "peer",
            "name", "rx0", "netns", rx)
        for namespace, dev, address in ((tx, "tx0", "192.0.2.1"), (rx, "rx0", DESTINATION)):
            run("ip", "-n", namespace, "addr", "add", f"{address}/24", "dev", dev)
            run("ip", "-n", namespace, "link", "set", dev, "up")
        obj = PASS_OBJECT if mode.endswith("-pass") else OBJECT
        measure_bpf = args.bpf_runtime and mode != "baseline"
        if mode in ("xdp-generic", "xdp-pass"):
            run("ip", "-n", rx, "link", "set", "dev", "rx0", "xdpgeneric",
                "obj", str(obj), "sec", "xdp")
        if mode in ("tc", "tc-pass"):
            run("ip", "netns", "exec", rx, "tc", "qdisc", "add", "dev", "rx0", "clsact")
            run("ip", "netns", "exec", rx, "tc", "filter", "add", "dev", "rx0",
                "ingress", "bpf", "da", "obj", str(obj), "sec", "classifier")
        if measure_bpf:
            program_id = attached_program_id(rx, mode)

        server = subprocess.Popen(
            ["ip", "netns", "exec", rx, "iperf3", "-s", "-1", "-B", DESTINATION],
            stdout=subprocess.DEVNULL,
        )
        for _ in range(50):
            if server.poll() is not None:
                raise RuntimeError("iperf3 server exited before listening")
            sockets = run("ip", "netns", "exec", rx, "ss", "-H", "-ltn",
                          "sport", "=", ":5201", capture_output=True)
            if sockets.stdout.strip():
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("iperf3 server did not start")
        result = run("ip", "netns", "exec", tx, "iperf3", "-c", DESTINATION,
                     "-u", "-b", args.rate, "-l", str(args.payload), "-t", str(args.seconds),
                     "-O", "1", "-J", stdout=subprocess.PIPE, timeout=args.seconds + 15)
        data = json.loads(result.stdout)
        if "error" in data:
            raise RuntimeError(data["error"])
        server.wait(timeout=5)
        if measure_bpf:
            program = bpf_programs("id", program_id)
            if isinstance(program, list):
                program = program[0]
            count = program.get("run_cnt", 0)
            if count <= 0 or "run_time_ns" not in program:
                raise RuntimeError(f"No runtime statistics for BPF program {program_id}")
            data["bpf_program"] = program
        return data
    finally:
        if server is not None and server.poll() is None:
            server.kill()
            server.wait()
        for namespace in reversed(namespaces):
            subprocess.run(("ip", "netns", "del", namespace), check=False)


def metrics(data):
    end = data["end"]
    received = end["sum_received"]
    # iperf3 UDP packet count includes datagrams reported lost.
    packets = received["packets"] - received["lost_packets"]
    cpu = end["cpu_utilization_percent"]
    return {
        "tx_mbps": end["sum_sent"]["bits_per_second"] / 1_000_000,
        "rx_pps": packets / received["seconds"],
        "rx_mbps": received["bits_per_second"] / 1_000_000,
        "loss_pct": received["lost_percent"],
        "sender_cpu_pct": cpu["host_total"],
        "receiver_cpu_pct": cpu["remote_total"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rate", default="100M", help="iperf3 target bit rate")
    parser.add_argument("--payload", type=int, default=256, help="UDP payload bytes")
    parser.add_argument("--seconds", type=int, default=5, help="measured seconds per trial")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--pass-only-controls", action="store_true",
                        help="include pass-only XDP and TC alongside the counters")
    parser.add_argument("--bpf-runtime", action="store_true",
                        help="record kernel BPF runtime statistics with bpftool")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid():
        parser.error("run as root to create namespaces and attach eBPF programs")
    if not OBJECT.is_file():
        parser.error("run make to build ingress.bpf.o")
    if args.pass_only_controls and not PASS_OBJECT.is_file():
        parser.error("run make to build pass.bpf.o")
    if args.bpf_runtime:
        setting = Path("/proc/sys/kernel/bpf_stats_enabled")
        if not setting.is_file() or setting.read_text().strip() != "1":
            parser.error("--bpf-runtime requires kernel.bpf_stats_enabled=1")
    if not 16 <= args.payload <= 1472 or min(args.seconds, args.repeats) < 1:
        parser.error("payload must be 16–1472 bytes and seconds and repeats must be positive")
    args.output.mkdir(parents=True)
    config = vars(args) | {"output": str(args.output), "kernel": os.uname().release}
    (args.output / "config.json").write_text(json.dumps(config, indent=2) + "\n")
    results = []
    modes = MODES + ("xdp-pass", "tc-pass") if args.pass_only_controls else MODES
    for repeat in range(args.repeats):
        offset = repeat % len(modes)
        for mode in modes[offset:] + modes[:offset]:
            print(f"Repeat {repeat + 1}: {mode}", flush=True)
            data = trial(mode, args)
            (args.output / f"{repeat + 1}-{mode}.json").write_text(json.dumps(data, indent=2) + "\n")
            row = {"repeat": repeat + 1, "mode": mode, **metrics(data)}
            if args.bpf_runtime:
                program = data.get("bpf_program")
                row["bpf_runs"] = program["run_cnt"] if program else None
                row["bpf_ns_per_run"] = (program["run_time_ns"] / program["run_cnt"]
                                         if program else None)
            results.append(row)

    with (args.output / "trials.csv").open("w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=list(results[0]))
        writer.writeheader()
        writer.writerows(results)
    for mode in modes:
        rows = [row for row in results if row["mode"] == mode]
        values = ", ".join(f"{key}={statistics.median(row[key] for row in rows):.2f}"
                           for key in rows[0] if key not in {"repeat", "mode"}
                           and rows[0][key] is not None)
        print(f"{mode} (medians): {values}")


if __name__ == "__main__":
    main()

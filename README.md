# Packet Path Bench

Compare three receiver configurations with the same UDP traffic over a private
Linux veth link.

## Progress report

- **Goal.** Measure how packet rate and payload size affect throughput, loss,
  and CPU use with baseline, generic XDP, and TC ingress.
- **Done.** Built equivalent pass-through eBPF counters and a runner that saves
  iperf3 logs and trial metrics. Ran a rate sweep and six paired comparisons of
  256-byte and 512-byte payloads at the same packet rate.
- **Confirmed.** At an 800 Mb/s target with 256-byte payloads, the sender used
  nearly one full CPU and sent about 749 Mb/s with generic XDP and 767 Mb/s with
  TC. The receiver kept up with zero reported loss. At 512 bytes, all three
  modes reached the target. Across 36 trials at about 195,300 packets/s, doubling
  the payload raised median paired sender CPU utilization by 0.70–1.45
  percentage points, depending on the mode.
- **Open and next.** The current figures measure iperf3 process CPU use. The
  cost of each ingress hook remains unmeasured. A follow-up would rotate mode
  order and measure CPU cost per packet at a fixed rate below saturation.

| Mode | Receiver configuration |
| --- | --- |
| baseline | No eBPF program on ingress |
| xdp-generic | Generic XDP counts packets and passes them |
| tc | TC ingress counts packets and passes them |

Both programs increment a per-CPU counter. Each trial creates fresh namespaces
and attaches only the selected program. The runner rotates the order across
repeats and omits the first second of traffic. It cleans up the namespaces when
the trial finishes.

## First run

You need Linux, Python 3.9 or later, Clang with the BPF target, make, a C compiler,
Linux UAPI and libbpf headers, iproute2 with BPF support, and iperf3. Running
the benchmark requires root privileges and kernel support for veth, network
namespaces, generic XDP and TC BPF.

```sh
make
sudo python3 bench.py --output runs/first --rate 100M --payload 256 --seconds 5 --repeats 3
```

Use a new output directory for every run. It contains the run configuration,
the original iperf3 JSON for each trial, and a CSV with received packets per
second, sender and receiver throughput, loss, and endpoint CPU utilization. The terminal shows the
median of each metric by mode.

## Reading the results

The CSV uses iperf3's UDP receive statistics. The BPF counter provides the same
work at both hooks and counts all ingress packets, including control traffic.
Its map is not used as the source of the benchmark metrics.

The default load is paced. Similar throughput with low loss means all three modes
handled that offered load. To explore capacity, repeat the experiment at higher
rates with the same payload size and look for where loss rises across repeated
trials. Vary the load in a separate run so the comparison stays consistent.

The CPU columns report the iperf3 processes' utilization, not total machine
CPU or time spent in each BPF program. The results describe generic XDP and TC on
veth on this machine. Driver-mode XDP on a physical NIC is a separate experiment.

## First measurements

At 100 and 400 Mb/s with 256-byte payloads, all three modes reached the target
with zero reported loss. The table compares three UDP payload sizes at the same
800 Mb/s target. Each row shows medians across three 5-second trials.

| UDP payload | Mode | Sent (Mb/s) | Received (Mb/s) | Received packets/s | Sender CPU (%) |
| ---: | --- | ---: | ---: | ---: | ---: |
| 256 B | Baseline | 799.77 | 799.75 | 390,505 | 97.90 |
| 256 B | Generic XDP | 748.80 | 748.79 | 365,621 | 99.96 |
| 256 B | TC ingress | 767.00 | 766.99 | 374,505 | 99.97 |
| 512 B | Baseline | 799.96 | 799.94 | 195,298 | 67.57 |
| 512 B | Generic XDP | 799.96 | 799.95 | 195,300 | 76.76 |
| 512 B | TC ingress | 799.95 | 799.95 | 195,301 | 70.83 |
| 1,024 B | Baseline | 799.96 | 799.95 | 97,651 | 35.80 |
| 1,024 B | Generic XDP | 799.96 | 799.95 | 97,651 | 43.31 |
| 1,024 B | TC ingress | 799.97 | 799.95 | 97,651 | 37.28 |

All configurations reported zero loss. At 256 bytes, the sender used about one
full CPU in both BPF modes and generated less than the target rate. At 512 and
1,024 bytes, all three modes reached the target. Sender CPU utilization fell as
packets per second fell, which supports packet rate as a factor in the sender
limit for this setup. The endpoint CPU figures cannot isolate the cost of either
ingress hook.

### Matched packet rate

Six pairs compared 256-byte payloads at 400 Mb/s with 512-byte payloads at
800 Mb/s. The payload order alternated between pairs. All 36 trials delivered
between 195,301 and 195,307 packets/s, rounded to the nearest packet per second,
with zero reported loss.

| Mode | Median paired increase in sender CPU (percentage points) | Sender CPU higher at 512 B | Median paired increase in receiver CPU (percentage points) |
| --- | ---: | ---: | ---: |
| Baseline | +1.39 | 5/6 | +0.78 |
| Generic XDP | +1.45 | 6/6 | +1.00 |
| TC ingress | +0.70 | 5/6 | +0.50 |

Larger payloads generally used more endpoint CPU at the same packet rate. The
paired differences were smaller than the gaps between the earlier standalone
runs. The mode order was fixed within each payload run, so these pairs are best
used to compare payload sizes within a mode.

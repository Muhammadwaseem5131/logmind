# LogMind evaluation

Measured accuracy of the ten detectors, reproducible with:

```bash
python evaluate.py
```

## Method

`evaluate.py` generates a labelled corpus from 21 scenario generators
(11 attack, 10 benign), 5 randomised runs each. Every attack scenario declares
which detector **must** fire (`expected`) and which detectors **may** fire
without penalty (`allowed`) - a brute-force log really does contain a volume
spike, so counting that as an error would be wrong. Benign scenarios allow
nothing: any finding at all is a false positive.

The benign half is deliberately adversarial - these are the cases a naive
detector alarms on:

| Benign scenario | Why it is a trap |
|---|---|
| Forgetful user | 2-4 failures then success, from one IP - just under every threshold |
| Monitoring bot | 120 requests, high total volume but a flat rate |
| Maintenance window | Many `sudo` commands, all of them routine |
| Night batch host | All activity at 02:00, with no daytime baseline to compare against |
| CI deploy | 25 successful logins from a single IP |
| Helpdesk morning | Several users each failing once, from different IPs |
| Normal day | Ordinary logins, cron, health checks |
| NAT gateway | A whole office behind one address - structurally identical to one IP probing many accounts |
| Password rotation | 7 failures then success, because the user kept typing the old password |
| Load test | A planned one-minute flood |

## Results

```
Corpus: 105 logs (55 attack, 50 benign), 3,366 log lines

Per-detector
detector                 TP   FP   FN   prec    rec     F1
account_probing           5    5    0   0.50   1.00   0.67
brute_force_success       5   10    0   0.33   1.00   0.50
distributed_attack        5    0    0   1.00   1.00   1.00
failed_burst              5    0    0   1.00   1.00   1.00
log_gap                   5    0    0   1.00   1.00   1.00
log_tampering             5    0    0   1.00   1.00   1.00
off_hours                 5    0    0   1.00   1.00   1.00
sensitive_command         5    0    0   1.00   1.00   1.00
user_enumeration          5    0    0   1.00   1.00   1.00
volume_spike              5    5    0   0.50   1.00   0.67
web_attack                5    0    0   1.00   1.00   1.00
macro average                           0.85   1.00   0.89

Alert decision (did the log get flagged at all?)
  attack logs flagged     55/55  (recall 1.00)
  benign logs flagged     15/50  (false alarm rate 0.30)
  precision 0.79   F1 0.88

Failures:
  FP    b_nat_gateway: unexpected brute_force_success
  FP    b_nat_gateway: unexpected account_probing
  FP    b_nat_gateway: unexpected brute_force_success
  FP    b_nat_gateway: unexpected account_probing
  FP    b_nat_gateway: unexpected brute_force_success
  FP    b_nat_gateway: unexpected account_probing
  FP    b_nat_gateway: unexpected brute_force_success
  FP    b_nat_gateway: unexpected account_probing
  FP    b_nat_gateway: unexpected brute_force_success
  FP    b_nat_gateway: unexpected account_probing
  FP    b_password_rotation: unexpected brute_force_success
  FP    b_password_rotation: unexpected brute_force_success
  FP    b_password_rotation: unexpected brute_force_success
  FP    b_password_rotation: unexpected brute_force_success
  FP    b_password_rotation: unexpected brute_force_success
  FP    b_load_test: unexpected volume_spike
  FP    b_load_test: unexpected volume_spike
  FP    b_load_test: unexpected volume_spike
  FP    b_load_test: unexpected volume_spike
  FP    b_load_test: unexpected volume_spike
```

## Known false positives

The last three benign scenarios are the ones LogMind gets wrong, and they are
kept in the corpus deliberately - a benchmark everything passes measures
nothing.

| Case | Fires as | Why it cannot be fixed from the log alone | What would fix it |
|---|---|---|---|
| Office NAT gateway | `account_probing`, `brute_force_success` | Many users behind one IP is byte-for-byte the same shape as one attacker trying many accounts | A NAT / asset inventory marking that address as shared |
| Password rotation day | `brute_force_success` | Repeated failures then a success is the definition of the pattern; intent is not in the log | A change calendar, or correlating with the password-change event |
| Scheduled load test | `volume_spike` | A planned flood and an unplanned one look identical | A maintenance window feed |

Each needs context that lives outside the log file. Reporting them is more
useful than tuning them away, because suppressing these shapes would also
suppress the real attacks they resemble.

## Reading this honestly

The corpus is **synthetic**: the same author wrote the attacks and the
detectors, so recall here is an upper bound, not a field measurement. What the
numbers do establish is that (a) every detector fires on the pattern it claims
to cover, (b) seven realistic near-miss benign shapes produce zero alerts, and
(c) the three ambiguous cases above are understood rather than accidental.

The benchmark has already paid for itself once: it caught `log_gap` firing on
35 of 85 logs, because any log with an idle overnight stretch looked like a
deletion. The rule now requires a dense log *and* a gap that is a lone
outlier.

Validation against a public labelled dataset of real traffic is the next step
and has not been done.

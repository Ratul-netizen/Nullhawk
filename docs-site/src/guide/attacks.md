# Intruder, fuzz, race & sequencer

The tools that send one request many ways. Unlike the scanner, these **conclude nothing on
their own** — what a difference means is the judgment of whoever chose the payloads. They
group responses so the outlier is obvious.

## Fuzz / intruder

Send one request many times, once per payload, and compare what came back. Responses are
grouped by `(status, length)` so the crowd is one line and the outlier is a short row below it
— and outliers are measured against the **majority**, not the baseline (in two hundred
usernames, the unchanged request is just one more wrong answer).

```bash
nullhawk fuzz ./engagement <request-id> ...    # payload positions and lists
```

The unthrottled intruder is **Pro**; a throttled run is available free. It files nothing into
the findings store — it's an instrument, not a detector. (It will replay a `POST` where the
scanner refuses to, and says the method and count first.)

## Race

Send one captured request many times **at once**, to find a race condition — single-use codes,
balance/redeem flows, coupon double-spend:

```bash
nullhawk race ./engagement <request-id> ...
```

## Sequencer

Measure how unpredictable a token is — session IDs, CSRF tokens, password-reset tokens:

```bash
nullhawk sequencer ./engagement ...
```

A predictable token is a finding in itself; the sequencer gives you the evidence (the sampled
values and the analysis) to back the claim.

## When to reach for which

- **Fuzz** — enumerate a parameter (usernames, ids, files) and spot the anomaly. It found a
  real local-file-inclusion on a public test target in twelve requests.
- **Race** — any "this should only work once" flow.
- **Sequencer** — anything whose security rests on a value being unguessable.

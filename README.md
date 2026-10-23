# CS6008 Assignment 2 — DNS Security — Working Notes

Deadline: 23 Oct 2026. Built under time pressure — prioritize Phase 1 → 2 → 3 → 4 → 6 → 5 → 7.
Everything here is a **starting skeleton**, not a tested final submission. Build it, run it,
fix what breaks, capture evidence as you go (you need captures for the report regardless).

---

## Why this assignment is structured this way (read this before typing anything)

Plain DNS has no authentication: a resolver accepts whichever reply arrives first and looks
syntactically right, matching the query ID and ports. Anyone who can see the query (on-path)
can race the real answer and win. That's Phase 1–2. DNSSEC fixes *integrity* of the DNS
record itself (Phase 3) — but only as far as the resolver; the stub↔resolver hop is still
plaintext and unauthenticated (Phase 6), and an attacker who can't forge signatures can still
try to make the resolver *think* the zone isn't signed at all (Phase 4 downgrade). Phase 5 is
a side effect of how "this name doesn't exist" has to be provable *in advance* — it leaks
zone contents. Phase 7 finally encrypts+authenticates the last mile, closing Phase 6, but
doesn't touch anything upstream of the resolver. Treat the report as answering one running
question per phase: "what does this layer protect, and what does it still not protect?"

---

## Phase 1 — Topology (do first, budget ~45–60 min)

**What you're proving:** a working iterative DNS hierarchy (root → com → example.com) with
no direct inter-subnet links except through the two routers you control.

1. `cd phase1 && docker compose up -d --build`
2. Install routes (containers don't get them automatically — see `setup-routes.sh`):
   `./setup-routes.sh`
3. Verify:
   ```
   docker exec client dig @172.16.2.10 example.com +short        # -> 172.16.1.20
   docker exec client curl http://example.com                     # via webserver's A record only if client resolves via browser; for curl test:
   docker exec client curl --resolve example.com:80:172.16.1.20 http://example.com
   docker exec client dig @172.16.3.10 example.com                # should NOT answer — not reachable without router route, remove the auth-subnet route temporarily to actually demonstrate isolation, or just show client has no route to 172.16.3.0/24 at all (we only gave the resolver that route, by design)
   ```
4. Capture on core-router: `docker exec core-router tcpdump -i any -w /tmp/p1.pcap udp port 53`
   then run the dig above in another shell, stop capture, pull file with `docker cp`.

**Report tip:** your isolation proof is simply that `client` never got a route to
172.16.3.0/24 (only `resolver` did) — show `ip route` on client and note the missing route.

---

## Phase 2 — On-path forgery (budget ~90–120 min, this is the hard one)

**What you're proving:** an attacker who can see the resolver's queries (because core-router
diverts response traffic through it) can win the race against the real authoritative answer.

1. Edit `core-router`'s routes so that return traffic from the authoritative subnet to the
   resolver passes via the attacker first (`phase2/divert-routes.sh`). The clean way: give
   the attacker an IP on the resolver subnet, and add a **more specific route on core-router**
   for traffic destined to `resolver` (172.16.2.10/32) via the attacker's resolver-subnet IP,
   with the attacker configured to forward packets it doesn't forge (IP forwarding on, or your
   own relay loop in the interceptor).
2. Build: `cd phase2 && make` (needs `libpcap-dev`, already in the attacker Dockerfile).
3. Run relay-only first (`./interceptor -i eth0` with forging disabled) and re-verify Phase 1's
   `dig` still works — this is your "transparent relay" evidence.
4. Flip forging on (`-f` flag — see source), flush resolver cache
   (`docker exec resolver rndc flush`), repeat the client lookup: `example.com` should now
   resolve to `172.16.1.30` (rogue-web) while `www.example.com` still resolves correctly.

**The interceptor skeleton (`phase2/interceptor.c`) gives you:**
- raw capture + injection scaffolding via libpcap (`pcap_open_live`, `pcap_inject`/`pcap_sendpacket`)
- Ethernet/IP/UDP header parsing stubs
- a DNS message parser stub (you need to finish QNAME parsing — it's length-prefixed labels)
- a forge-response builder stub (you need to fill in RR count, TTL, RDATA = rogue-web IP)
- checksum helpers (IP header checksum is simple; UDP checksum needs the pseudo-header —
  both are stubbed with the correct formula, fill in the loop)

This same binary, with `--strip` and a `--validate-aware` style flag added, becomes your
Phase 4 tool. For Phase 6 you just rerun it with `-i` pointed at the client-subnet interface
and rogue A record logic unchanged.

---

## Phase 3 — DNSSEC (budget ~60–90 min, config-heavy not code-heavy)

Your Phase 2 binary doesn't change. What changes is the zones:

```
cd phase1
dnssec-keygen -a ECDSAP256SHA256 -n ZONE example.com      # repeat per zone (root, com, example.com)
dnssec-keygen -a ECDSAP256SHA256 -n ZONE -f KSK example.com
dnssec-signzone -A -3 $(head -c 16 /dev/urandom | xxd -p) -N INCREMENT \
  -o example.com -t domain-ns/zones/example.com.zone
```
Then take the DS record BIND prints (or regenerate with `dnssec-dsfromkey`) and paste it into
the **parent** zone (com's zone file on tld-ns), re-sign that zone, repeat up to root. Put the
root KSK's public key into resolver's `named.conf` as `trust-anchors { "." initial-key ... };`
and flip `dnssec-validation yes;`. Verify with `dig +dnssec` (look for `ad` flag + RRSIG) and
`delv -a <root.key> example.com` before re-running the exact Phase 2 attack — same commands.

**Don't commit private keys** (the `.private` key files) — the report question asks this
directly; the answer is no, and your `.gitignore` should exclude them.

---

## Phase 4 — Strip/downgrade (budget ~45 min on top of Phase 3)

Run A: extend the interceptor to delete RRSIG/DNSKEY/DS records from the wire response before
forwarding, then inject your forged A. Run B: don't touch the wire at all — just remove the DS
record from the **com** zone on tld-ns (re-sign com without it) so example.com has no secure
delegation from its parent, even though domain-ns still signs it. The resolver can't build a
chain of trust to it, treats it as a "provably insecure" island, and accepts your plain forged
answer. Run B is the more interesting result for the report: the operator mistake is "signed
the child, forgot to publish DS in the parent."

---

## Phase 6 — Last-mile forgery (budget ~45 min, mostly reuse)

Same interceptor, moved to the client subnet (`-i` on the client-net interface, attacker IP
172.16.1.100), diversion route added on **edge-router** instead of core-router. Forge the
resolver→client response. Test against plain `curl`/OS resolver (should get owned) and a
validating stub like `delv` with its own root key (should correctly reject, because the `ad`
flag only means something to a client that *checked* it was set by someone it trusts — an
on-path attacker can just set `ad` on a forged UDP packet, a non-validating stub has no way
to tell).

---

## Phase 5 — Zone walking (skip if out of time; needs NSEC3, not NSEC)

Plain NSEC denial-of-existence proves "nothing exists between A and B" by *naming* the next
real record — walk the zone by repeatedly querying names just past what you were told doesn't
exist, and you enumerate everything in ~N+2 queries. The fix is NSEC3 (hashed owner names) —
switch `dnssec-policy` or sign with `-3 <salt>` and the walk now returns hash chains you can't
reverse cheaply (not "none" — you can still see the record *count* and structure, that's the
report's "what can an enumerator still learn" answer).

## Phase 7 — DoT/DoH (skip first if time is short; heaviest setup for the marks)

`openssl req -x509 ...` for a private CA, issue resolver.cs6008.local's cert from it (DNS SAN
only, no IP SAN), BIND `tls` block + `listen-on tls` on 853, client points `stunnel`/`kdig +tls`
at the hostname with the CA installed as trusted. Three attacks × two client policies = 6
cells in a table; the two that should land are the ones where the client *permits cleartext
fallback* and you block 853/443 — that's the one encryption-alone can't fix.

---

## Submission hygiene (don't lose free marks)

- `phaseN/` dirs each need their own compose + configs + attack source + build command + README
- Don't commit compiled binaries, signed zones, or built images — your scripts regenerate them
- Commit incrementally — even now, `git init && git add -A && git commit -m "phase1 skeleton"`
  immediately, then commit again every time something works
- Add the GenAI appendix to report.pdf: what you asked, what you changed, how you verified it

# What to Say to the Judges — Plain-English Script

For explaining Diode Watch to **non-technical judges**. No jargon, no acronyms.
Read the lines in quotes out loud, or paraphrase them. Analogy first, then the
real thing. Sections are in the order you'll likely be asked.

---

## 1. The 60-second opening (say this first, word for word)

> "Imagine a **security camera in a bank vault**. The camera can watch
> everything that happens, but it is behind **one-way glass** — it can see in,
> but nothing can ever get back out to it, and it can't talk back or touch
> anything. That's what a **data diode** is: a network copy that can only
> receive traffic, never send anything back.
>
> We built a system that **watches that network footage and automatically
> spots when something bad is happening** — a cyberattack in progress. It works
> only from what it can *see*; it never opens the 'packages' going past (it
> can't read encrypted data), and it can never be hacked into attacking the
> network it protects, because the glass only goes one way.
>
> To prove it works, we **simulated a fake network** with fake users and fake
> attackers, and our system caught the attacks, raised alarms on a live
> dashboard, and even **texted the security team's chat app automatically** —
> all by itself, with no human looking at the screen."

---

## 2. "What is a data diode?" (the one-word glass answer)

> "Think of a **letterbox that only lets mail come in, never go out** — not even
> the postman can push a letter back. Companies use this for their most
> protected networks: it lets them *see* everything on the wire, but guarantees
> that even a hacked monitoring device can never be used to attack the real
> network. The whole challenge of our project is: **do great security with only
> the ability to look, never to touch.**"

---

## 3. "What's actually running here?" (the 3 parts)

> "Three things:
>
> **1. The Simulator** — this is our 'movie set'. It generates a realistic
> fake network — normal people checking email, browsing, plus a few 'villains'
> doing bad things like flooding a server, or malware phoning home. We run it
> in **fast-forward** (4× speed) so a whole day's worth of traffic fits into a
> few minutes.
>
> **2. The Brain (engine)** — a program that reads every single conversation
> as it happens, checks it against 'what normal looks like', and decides if
> it's suspicious. It can read about **2,000 conversations every second**.
>
> **3. The Dashboard** — the screen you see, like a control-room monitor. When
> the brain finds something, it appears here instantly, along with a record
> saved to a database and a message sent to the team's chat (Slack)."

---

## 4. Walking them through the Dashboard — Live Feed tab

> "This is the alarm screen. Every row is **one alarm we raised**. Let me read
> one row for you:
>
> **`HIGH · C2_BEACON · 10.0.1.50 → 198.51.100.10 · 87% · ×3`**
>
> - **HIGH** — that's the **seriousness** of the alarm, like red/amber/green.
>   HIGH means 'look now'; CRITICAL means 'drop everything'.
> - **C2_BEACON** — that's the **type of attack**. This one means a computer
>   inside the network is 'phoning home' to a hacker's server, on a regular
>   beat — like a spy checking in every minute. We catch that rhythm.
> - **10.0.1.50 → 198.51.100.10** — the **from→to** address: which computer did
>   it, and where it was talking to. The `10.x` addresses are inside the
>   company; the `198.x` ones are 'the internet'.
> - **87%** — that's **how sure** we are. 87% = pretty confident. It's our
>   honesty rating, not a guarantee.
> - **×3** — this alarm has fired **3 times** already. Instead of spamming us
>   with 3 identical rows, we **group them into one** and just count them. So
>   `×3` means 'this same thing happened 3 times'.
> - The time on the right is the **clock inside the simulation** (fast-forwarded
>   time), not real wall-clock time.
>
> If you click a row, it opens a little 'receipt' showing **exactly what
> evidence** made us suspicious — we never ask anyone to trust us blindly;
> every alarm comes with its proof."

**If they ask what "TCP" or "UDP" means:**
> "Those are just the two 'delivery methods' of the internet. TCP is like a
> **registered letter** — guaranteed to arrive. UDP is like a **postcard** —
> sent quickly, but it can get lost. Knowing which one is used helps us spot
> attacks, because some attacks misuse one or the other."

---

## 5. Overview tab — the numbers

> "The top cards are the health meters:
>
> - **Throughput** — how fast the brain is reading: about **2,000 conversations
>   per second**. That's our design target.
> - **Flows processed** — the **total odometer** since the program started.
>   Because it reads 2,000 a second, this adds up to millions over an hour.
>   It's a running total, like a car's mileage — not a 'current' number.
> - **Alert sessions** — how many alarm groups we currently have.
> - **Alerts/sec** — how fast new alarms are coming in right now.
>
> The **bar chart and pie chart** just summarize the alarms by attack type and
> by seriousness — so you can see at a glance 'we've had mostly X, and most are
> HIGH'.
>
> The **line graph** is the heartbeat: it shows how fast the brain is working
> over the last few minutes. **The bottom axis is the simulation clock** — the
> fast-forwarded time. So `56:00` means '56 minutes into the simulated day',
> which took about 14 real minutes to play."

---

## 6. Evaluation tab — "how do we know it works?"

> "This is the part we're most proud of. Anyone can *claim* their security tool
> works. We **prove** it, live, in front of you.
>
> When we made the fake network, we secretly **labeled every attack** — we know
> the ground truth, exactly which 'actors' were the bad guys. Crucially, the
> brain is **never allowed to see those labels** — it has to figure things out
> blind, exactly like in real life.
>
> A separate little program **grades the brain's alarms against the truth**:
>
> - When the brain raised an alarm and there really was an attack → a **hit**.
> - When the brain raised an alarm but nothing was actually there → a **false
>   alarm**.
> - When an attack happened and the brain stayed silent → a **miss**.
>
> **Precision** = of everything we alarmed on, how much was real. **Recall** =
> of all the real attacks, how many we caught. **F1** = the combined score.
> The table shows this for every attack type. Right now you can watch these
> numbers update in real time as the simulation runs."

---

## 7. The Slack message & n8n — "how does the team get told?"

> "When an alarm is **HIGH or CRITICAL**, the system doesn't just show it on a
> screen someone might not be watching. It automatically sends a **message to
> the security team's chat app (Slack)**, like this:
>
> > `DIODE-WATCH [HIGH] C2_BEACON — 10.0.1.50 -> 198.51.100.10 (conf 0.87). <explanation>`
>
> The orchestration tool (called n8n) is the 'office manager' of the system —
> it decides where each alarm goes. It also runs **two background helpers**:
>
> 1. **The self-healing check** — every hour it checks whether the 'normal
>    traffic' has changed so much that our model is out of date (we measure
>    this with a number called drift, like a temperature gauge). If it has, the
>    system **retrains itself** automatically — like refreshing its memory of
>    what normal looks like.
> 2. **The weekly refresh** — once a week, on schedule, it retrains the domain
>    detector just to be safe.
>
> The point: **the system keeps itself updated with no human and no outside
> help** — which is the whole promise of a one-way glass network."

---

## 8. "Why do I see '5 million flows' or a big number?"

> "That's the running total — the **odometer**. Our brain reads ~2,000
> conversations per second, so over the hours the demo has been running, that
> total climbs into the millions. It starts at zero every time the program is
> restarted. It's not '5 million happening right now' — it's '5 million seen
> since we turned it on'."

---

## 9. "Why does the graph say 56:00?"

> "Because we run the simulation in **fast-forward (4× real time)** — that's
> the whole trick to demoing a full day of attacks in minutes. The graph's
> bottom axis shows **simulation time**: `56:00` means '56 minutes into the
> simulated day'. If it were real clock time, it would say the time of day
> (like 4:30 PM). We intentionally show the simulated clock because that's what
> the attack timeline is measured in."

---

## 10. If they ask "is this real traffic?"

> "No — it's a **realistic simulation**, like a flight simulator for pilots. We
> use made-up IP addresses, but the traffic patterns are shaped like real ones,
> and the *detection brain* is the exact same code that would sit on a real
> network's one-way tap. We simulate so we can (a) know the ground truth to
> grade ourselves honestly, and (b) show a whole attack timeline without
> waiting days."

---

## 11. If they ask "what's the one thing that makes this special?"

> "Three things, in order:
>
> 1. **It respects the hardest security constraint** — it works on a network
>    where it can only watch and never touch. Most tools assume they can act;
>    ours assumes it can't, and still catches attacks.
> 2. **It never decrypts anything** — it reads only the 'envelope', not the
>    'letter' (TLS metadata, not contents), so it works even on fully encrypted
>    traffic.
> 3. **It proves its own accuracy** — a live scorecard of how often it's right,
>    computed against hidden ground truth."

---

## 12. One-line glossary (tech → plain English)

| You hear | It means |
|---|---|
| data diode | one-way glass; can see in, nothing gets out |
| passive | only watching, never sending/touching |
| flow | one internet conversation between two computers |
| flow record / metadata | the envelope: who→who, size, when, protocol — not the contents |
| Redis stream | a live conveyor belt of these conversations |
| detector / model | a checklist or pattern-spotter that flags suspicious behavior |
| warmup | the brain quietly watching normal traffic first, to learn 'normal' |
| IsolationForest | an 'unusual-pattern' spotter trained only on normal traffic |
| DGA / domain | a fake domain name made by malware (the brain flags these) |
| JA3 | a 'fingerprint' of a computer's TLS handshake; known-bad ones are flagged |
| confidence 87% | how sure we are (not a guarantee) |
| severity HIGH/CRITICAL | seriousness / urgency |
| occurrences ×3 | same alarm fired 3 times, grouped into one |
| TimescaleDB | the filing cabinet where alarms are saved |
| n8n | the office manager / automation tool routing alarms + retrains |
| Slack | the team's chat app; gets an automatic message for HIGH/CRITICAL |
| drift (PSI) | a gauge of 'has normal changed so much we're out of date?' |
| precision / recall / F1 | how often right / how much we caught / combined score |
| simulator clock (56:00) | fast-forwarded time inside the simulation |

---

## 13. Demo flow if the judges want to see it live

1. Point at **Live Feed**: "these alarms are firing right now — click one, here's
   the proof behind it."
2. Point at **Evaluation**: "watch these numbers — this is us being graded by
   hidden truth, updating live."
3. Show the **Overview**: "2,000 conversations/sec; the graph is our heartbeat."
4. Open **Slack**: "here's the automatic message that just went out — no human
   touched it."
5. End on the **one-way glass** idea — it's the story they'll remember.
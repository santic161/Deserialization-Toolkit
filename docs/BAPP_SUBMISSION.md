# BApp Store submission — Deserialization Toolkit

Open a **New extension submission** issue at
<https://github.com/PortSwigger/extension-portal> and paste the fields below.
(Field labels follow the live issue form; adjust to match exactly.)

---

**Extension URL (GitHub repository)**
https://github.com/santic161/Insecure-Deserialization-Scanner

**Version number**
2.0.0

**Compatible products**
- [x] Burp Suite Community Edition
- [x] Burp Suite Professional
- [ ] Burp Suite DAST / Enterprise
- [ ] Burp AI

> Passive cookie scanning and time-based detection work in Community.
> DNS/out-of-band detection uses Burp Collaborator (Professional only) and degrades gracefully.

**Author**
- Display name: santic161
- Contact email: santi.c161@gmail.com
- Discord: `<your-discord-username>`

---

**Extension overview**

Deserialization Toolkit finds and exploits Java deserialization vulnerabilities without the usual
friction. You type a plaintext OS command (e.g. `rm -rf /home/carlos/morale.txt`), pick a ysoserial
gadget chain and an encoding, and the extension builds the payload, injects it into the request
(cookie, header, body or a `{PAYLOAD}` marker), sends it, and shows the response — all in one tab.
A passive check flags cookies that carry serialized Java objects (naming the transport encoding) and
cookies with weak `Secure`/`HttpOnly`/`SameSite` flags. Confirmed chains are remembered per host and
used to rank the gadget list, so the most likely chain is pre-selected next time.

It is a modern, from-scratch rewrite on the **Montoya API** of the concepts in Federico Dotta's
original *Java Deserialization Scanner* (MIT, credited), and differs substantially: an in-process
ysoserial engine (no `java` subprocess, no JVM cold-start), automatic JPMS module opening so it works
on a stock Burp with **no `vmoptions` edits**, passive insecure-cookie detection, a per-host gadget
recommender, flexible insertion points, and one-click hand-off from a confirmed finding to a
ready-to-fire exploit.

**Key features**
- Payload Builder: plaintext command → gadget → encoding → insert → send → response, one screen.
- Flexible insertion points: cookie, `{PAYLOAD}` marker, or "mark selection" (overwrites the selected
  bytes). Refuses payloads with CR/LF/NUL and fixes `Content-Length` so the request never breaks.
- Passive scan: serialized Java object in cookie (High, with detected encoding) + weak cookie flags (Low).
- Active detection: time-based (sleep) and out-of-band via Collaborator, run concurrently; vulnerable
  rows highlighted, sendable to the Payload Builder as an exploit in one click.
- In-process ysoserial engine with payload cache; zero JVM-flag setup (runtime module opening).
- Per-host gadget recommender fed by passive findings and confirmed hits.
- 7 output encodings; context-menu integration from Proxy/Repeater; persistent settings.

**How it works / setup**
- Build: `mvn clean package` → `target/deserialization-toolkit.jar`. Load via Extensions ▸ Add ▸ Java.
- A `ysoserial-all.jar` (fat build) is loaded in-process. It is bundled in the extension jar (under
  `resources/ysoserial/`); a newer fork can be pointed to from the Settings tab.
- On Java 17+, ysoserial needs several JDK-internal packages opened for reflection. Rather than
  requiring the user to edit `vmoptions`, the extension opens them itself at load time via the JDK's
  trusted lookup (the technique used by ByteBuddy/Lombok); it falls back to documented `--add-opens`
  flags only if a future JDK blocks that. No network calls are made at load; nothing phones home.
- All HTTP goes through Burp's own `api.http()`; `passiveAudit()` performs no network I/O; background
  work runs off the Swing EDT; the ysoserial classloader and thread pool are released on unload.

**Usage**
1. Browse the target through Burp — insecure/serialized cookies appear under Dashboard/Issues.
2. Right-click a request ▸ *Deserialization Toolkit: Send to Payload Builder*.
3. Type the command, keep the recommended gadget, click *Generate + Insert + Send*, read the response.
4. For blind cases, use the Scanner sub-tab (time-based or Collaborator); double-click a red
   VULNERABLE row to open it as an exploit.

---

**Confirmations**
- [ ] I have permission from all relevant persons to submit this extension to the BApp Store for
      public use, under the terms and conditions of the EULA.
- [ ] I have read and understood the BApp Store submission requirements.

---

## Pre-submission checklist (do before opening the issue)

- [ ] Drop `ysoserial-all.jar` into `src/main/resources/ysoserial/` so the built jar is self-contained
      (one-click install — required for acceptance).
- [ ] Tag a GitHub release (e.g. `v2.0.0`) so there is a stable source snapshot.
- [ ] Confirm the built jar loads on a **stock** Burp (no vmoptions) and CommonsCollections6 generates.
- [ ] Add real screenshots to `docs/` and reference them in the README.
- [ ] Re-check the name does not collide with an existing BApp entry.

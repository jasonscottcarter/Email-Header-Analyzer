# Email Header Analyzer

A local Node.js web app that takes apart an email's headers and shows whether the message is what it claims to be. Paste a header block, or drag and drop a `.eml` or Outlook `.msg` file. Everything runs on your machine, and no API keys are needed.

## Features

- **Verdict and red flags:** an overall rating (Suspicious / Review carefully / No red flags found) and a ranked list of issues in plain language, for example a display name showing a different address, a Reply-To pointing elsewhere, or forged Authentication-Results.
- **Authentication, two ways:**
  - **Reported by the receiving server:** the SPF, DKIM, DMARC, ARC and Microsoft `compauth` results that the server recorded on arrival.
  - **Re-checked now:** the tool fetches DKIM keys and verifies each signature cryptographically, re-evaluates SPF for the real sending IP, and evaluates DMARC itself.
- **DMARC compliance grid:** SPF authenticated, SPF aligned, DKIM authenticated and DKIM aligned, which together explain *why* DMARC passed or failed.
- **BIMI:** the sending domain's brand-logo record, whether the domain qualifies (DMARC enforcement), the referenced VMC/CMC certificate, and the logo itself. A logo the receiving server already validated (`BIMI-Indicator` header) is shown as well.
- **Delivery path:** every Received hop, oldest first, with timestamps, delay bars, HELO name, reverse DNS, IP, protocol, TLS and blocklist status. The hop that delivered to the recipient's mail system is highlighted.
- **Sender IP:** reverse DNS, forward confirmation, and public blocklists.
- **Spam filter verdicts decoded:** Microsoft 365 (SFV, CAT, SCL, BCL, IPV, country), SpamAssassin, Proofpoint, Mimecast and Barracuda.
- **All headers:** the complete header list, decoded and filterable.

## Prerequisites

- [Node.js](https://nodejs.org) v22 or later (LTS). Verify with `node --version`
- [Git](https://git-scm.com). Verify with `git --version`

## Installation

```bash
git clone https://github.com/jasonscottcarter/Email-Header-Analyzer.git
cd Email-Header-Analyzer
npm install
npm start
```

You should see `Email Header Analyzer running at http://localhost:3002`. Open that address in your browser. Press `Ctrl+C` in the terminal to stop the server.

It uses port 3002, so it can run alongside Email Domain Inspector and Threat Intel Dashboard (both on 3000). To use a different port, start it with `PORT=3005 npm start` (PowerShell: `$env:PORT=3005; npm start`).

## Usage

1. Get the headers:

   | Mail client | Where to find the headers |
   | --- | --- |
   | Outlook (desktop) | Open the message > **File** > **Properties** > copy **Internet headers**. Or drag the message from Outlook to your desktop to save a `.msg` file. |
   | Outlook on the web | Open the message > **⋯** > **View** > **View message source** |
   | Gmail | Open the message > **⋮** > **Show original** > **Download original** (`.eml`) or copy the text |
   | Apple Mail | **View** > **Message** > **All Headers**, or **File** > **Save As** (Raw Message Source) |
   | Thunderbird | Open the message > **More** > **View Source**, or **File** > **Save As** (`.eml`) |

2. Paste the headers into the box, or drag a `.eml` / `.msg` file onto it (or use **Choose file…**).
3. Click **Analyze** (or press **Ctrl+Enter**).

Leave **Live DNS checks** on to verify DKIM, SPF, DMARC and BIMI and to check blocklists. Turn it off to analyze completely offline. See the security notes before checking suspicious mail.

### What you can verify with each input

| Input | DKIM verification |
| --- | --- |
| Full `.eml` file | Signature **and** body hash (detects edits to the message body) |
| Pasted headers or `.msg` file | Signature only. The body hash can't be checked without the original body, so the result shows **pass-headers**. |

## What each check tells you

| Check | What it shows |
| --- | --- |
| SPF | Whether the IP that delivered the message is allowed to send for the envelope (Return-Path) domain. |
| DKIM | Whether a domain's cryptographic signature over the headers (and body) is valid, meaning those parts weren't changed after signing. |
| DMARC | Whether SPF or DKIM passed **for the domain shown in From**. This is what stops spoofing. |
| BIMI | The brand logo the From domain publishes. Mail clients only show it when DMARC passes, so a logo here is **not** proof the message is genuine. |
| ARC | A chain of signatures added by forwarders and mailing lists so later servers can trust earlier authentication results. |
| Delivery path | The route the message took. Large delays, backwards timestamps and hops without TLS are worth a look. |
| Blocklists | Whether the sending or relay IPs appear on public DNS blocklists. |

## Project structure

```
email-header-analyzer/
├── lib/
│   ├── analyze.js     # Builds the report and red flags
│   ├── dkim.js        # DKIM signature verification
│   ├── live.js        # SPF, DMARC, BIMI, reverse DNS and blocklist checks
│   ├── msg.js         # Reads internet headers out of Outlook .msg files
│   ├── parse.js       # Header, address, Received and Authentication-Results parsing
│   └── vendors.js     # Decodes spam filter headers (Microsoft, SpamAssassin, ...)
├── public/
│   ├── app.js         # Frontend logic
│   └── index.html     # Frontend page and styles
├── test/              # Tests (node --test), with fixtures
├── server.js          # Express server
└── package.json
```

## Tests

```bash
npm test
```

The tests use a fake DNS resolver, so they run offline. DKIM tests sign messages with mailauth's signer, which is independent of the verifier, and then confirm that tampered headers and bodies are detected.

## Limitations

- **Live checks use today's DNS.** If a domain has rotated its DKIM key or changed its SPF record since the message was sent, a re-check can fail even though the message was genuine on arrival. Compare with the "Reported by receiving server" results.
- **Headers from mail clients may be re-wrapped.** DKIM signatures using `simple` header canonicalization can fail on pasted headers whose lines were re-folded. Use the original `.eml` file when you can.
- **`.msg` files have no original body**, so DKIM body hashes can't be checked. Drafts and sent items have no internet headers at all.
- **Spotting forged trace headers is heuristic.** The tool finds the hop where the message entered the recipient's mail system and ignores any Received-SPF, Authentication-Results or Microsoft CIP that claims a sender IP the receiving servers didn't record, or that sits where only the sender could have written it. A server that introduces itself (HELO) with a name in the recipient's own domain is only treated as internal if that name resolves to its IP (live checks) or its IP is in Microsoft 365's published mail ranges, whose internal relay names don't resolve publicly. Otherwise it's flagged as impersonating the recipient's servers. When the message arrived straight from the sender's server, a forged Authentication-Results header that makes no IP claim can't be told apart by position. The re-check still catches it, and a "Receiving server and re-check disagree" warning is raised.
- **BIMI certificates (VMC/CMC) are not validated.** The tool shows the certificate URL but doesn't check the certificate chain.
- **Blocklist results need care.** Spamhaus refuses queries sent through public DNS resolvers such as 8.8.8.8 or 1.1.1.1; the tool shows these as **Refused**, not clean. Only IPv4 addresses are checked, and at most 8 relay IPs per message.
- **Red flags are heuristics.** "No red flags found" is not a guarantee. Always check links and attachments separately.

## Security notes

- **Local only.** The server listens on `127.0.0.1` (this computer only). It rejects requests addressed to any other host name, which blocks DNS-rebinding attacks, and requests sent from other websites' pages. File uploads must use `application/octet-stream`, so browsers can't send them across sites without a CORS check that fails.
- **Header content is untrusted.** Everything taken from an email is escaped before display, and the Content-Security-Policy only allows the page's own script file (no inline scripts), so even a missed escape couldn't run code.
- **Live checks are visible to the sender.** DKIM key and BIMI lookups go to the sending domain's DNS servers, and the BIMI logo is downloaded from the URL it publishes. A targeted attacker could notice that their message is being examined. Turn **Live DNS checks** off for sensitive investigations.
- **BIMI logos are fetched by the server, not your browser.** Only HTTPS URLs on public addresses are fetched, logos are limited to 64 KB of SVG, and they're displayed as images, where SVG scripts can't run.

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `Cannot find module 'express'` | Run `npm install` from inside the project folder. |
| Port 3002 already in use | Start on another port: `PORT=3005 npm start` (PowerShell: `$env:PORT=3005; npm start`). |
| "No email headers found" | Paste the complete header block, starting from the first `Received:` or `Delivered-To:` line, not just the visible From/To/Subject. |
| "This .msg file has no internet headers" | The message is a draft or one you sent. Open a message you received instead. |
| DKIM shows `temperror` | The DKIM key lookup timed out. Check your network and try again. |
| Every Spamhaus result says Refused | Your DNS resolver is a public one. Use your ISP's or a local resolver to query Spamhaus. |

## Built with

Node.js, Express, [mailauth](https://github.com/postalsys/mailauth) (SPF evaluation), [@kenjiuno/msgreader](https://github.com/HiraokaHyperTools/msgreader) (Outlook `.msg` files), [tldts](https://github.com/remusao/tldts) (organizational domains), and vanilla JavaScript.

## License

MIT. See [LICENSE](LICENSE).

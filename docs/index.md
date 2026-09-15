---
title: EasyDC, Samba Active Directory from the browser
hide:
  - navigation
  - toc
---

<div class="es-home">
<header class="es-band es-nav">
<div class="es-wrap es-nav-inner">
<a href="." class="es-brand">
<img src="assets/logo.svg" alt="EasyDC" />
<span class="es-brand-name">Easy<span>DC</span></span>
</a>
<nav class="es-nav-links" aria-label="Page sections">
<a href="#manage">Manage</a>
<a href="#health">Health check</a>
<a href="#architecture">Architecture</a>
<a href="#install">Install</a>
<a href="install/">Docs</a>
</nav>
<div class="es-nav-actions">
<a class="es-btn es-btn--secondary" href="https://github.com/easysysio/EasyDC" target="_blank" rel="noopener noreferrer">
<svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor" aria-hidden="true"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"></path></svg>
GitHub
</a>
<a class="es-btn es-btn--primary" href="#install">Get started</a>
</div>
</div>
</header>
<section class="es-band es-hero">
<div class="es-wrap es-hero-grid">
<div class="es-hero-copy es-rise">
<div class="es-eyebrow"><span class="es-eyebrow-dot"></span>Samba AD management · part of EasySYS</div>
<h1 class="es-h1">Run your Samba domain from the browser.</h1>
<p class="es-lead">EasyDC connects to your Samba Active Directory domain controllers over LDAP and gives you users, groups, computers, DNS, Group Policy and OUs in one web console, with an audit log of every change and a health check for the domain. One binary, and nothing installed on the DC.</p>
<div class="es-actions">
<a class="es-btn es-btn--primary es-btn--lg" href="#install">
Get started
<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 5v14M6 13l6 6 6-6"></path></svg>
</a>
<a class="es-btn es-btn--ghost es-btn--lg" href="install/">Read the docs</a>
</div>
<div class="es-pills">
<span class="es-pill"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="6" y="6" width="12" height="12" rx="2"></rect><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4"></path></svg>Rust core</span>
<span class="es-pill"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 8l-9-5-9 5v8l9 5 9-5V8z"></path><path d="M3 8l9 5 9-5M12 13v8"></path></svg>Single binary</span>
<span class="es-pill"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 018 0v4"></path></svg>LDAPS</span>
<span class="es-pill"><svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M14 3H6a1 1 0 00-1 1v16a1 1 0 001 1h12a1 1 0 001-1V8l-5-5z"></path><path d="M14 3v5h5M8 13h8M8 17h6"></path></svg>Audit log</span>
</div>
</div>
<div class="es-terminal-wrap es-rise es-rise--late">
<div class="es-terminal">
<div class="es-terminal-accent"></div>
<div class="es-terminal-bar">
<div class="es-dots"><span></span><span></span><span></span></div>
<span class="es-mono">admin@mgmt-01 — bash</span>
<span style="width: 47px;"></span>
</div>
<div class="es-term-body es-mono"><span class="t-c"># 1 — download the binary and run it</span>
<span class="t-p">$</span> curl -fLo easydc https://github.com/easysysio/EasyDC/\
    releases/latest/download/easydc-linux-x86_64
<span class="t-p">$</span> chmod +x easydc &amp;&amp; ./easydc
EasyDC running on http://0.0.0.0:3000
<span class="t-c"># 2 — create the admin, then add your DC</span>
<span class="t-ok">→</span> http://mgmt-01:3000/setup</div>
<div class="es-term-meta">
<div><div class="es-term-meta-label">Web UI</div><div class="es-term-meta-value es-mono">:3000</div></div>
<div><div class="es-term-meta-label">Directory</div><div class="es-term-meta-value es-mono">LDAP · LDAPS</div></div>
<div><div class="es-term-meta-label">Arch</div><div class="es-term-meta-value es-mono">x86_64 · arm64</div></div>
</div>
</div>
</div>
</div>
<div class="es-strip">
<div class="es-wrap es-strip-inner">
<span class="es-strip-label">Works with</span>
<div class="es-strip-items">
<span>Samba AD domain controllers</span>
<span>Several DCs, one dashboard</span>
<span>systemd</span>
<span class="es-mono">x86_64 · arm64</span>
</div>
</div>
</div>
</section>
<section id="manage" class="es-band es-section">
<div class="es-wrap">
<div class="es-head">
<div>
<span class="es-kicker-lg">What you manage</span>
<h2 class="es-h2">The everyday work of a domain, without samba-tool.</h2>
</div>
<p class="es-desc">Each area reads and writes the directory directly over LDAP. Every change lands in the audit log with the EasyDC user who made it, and failures keep the error the server returned.</p>
</div>
<div class="ed-areas">
<div class="es-card ed-area">
<div class="ed-area-top">
<div class="es-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2"></path><circle cx="9" cy="7" r="4"></circle><path d="M22 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"></path></svg></div>
<span class="es-tag es-mono">/users</span>
</div>
<span class="es-kicker">Users</span>
<h3 class="es-h3">Accounts and passwords</h3>
<p class="es-product-text">Create, edit, enable, disable and delete accounts. Reset a password with must-change-at-next-logon, and unlock an account the moment you see its Locked badge.</p>
<div class="es-tags"><span class="es-tag">Reset password</span><span class="es-tag">Unlock</span></div>
</div>
<div class="es-card ed-area">
<div class="ed-area-top">
<div class="es-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="2" width="6" height="6" rx="1"></rect><rect x="2" y="16" width="6" height="6" rx="1"></rect><rect x="16" y="16" width="6" height="6" rx="1"></rect><path d="M12 8v4M5 16v-2h14v2"></path></svg></div>
<span class="es-tag es-mono">/groups</span>
</div>
<span class="es-kicker">Groups</span>
<h3 class="es-h3">Security and distribution</h3>
<p class="es-product-text">Create and edit groups of either type, see who is in them, and add or remove members from the group's own page.</p>
<div class="es-tags"><span class="es-tag">Membership</span></div>
</div>
<div class="es-card ed-area">
<div class="ed-area-top">
<div class="es-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"></rect><path d="M8 21h8M12 17v4"></path></svg></div>
<span class="es-tag es-mono">/computers</span>
</div>
<span class="es-kicker">Computers</span>
<h3 class="es-h3">Machine accounts</h3>
<p class="es-product-text">List the computers joined to the domain, disable one that should not authenticate, and delete the accounts of machines that are gone.</p>
<div class="es-tags"><span class="es-tag">Enable / disable</span></div>
</div>
<div class="es-card ed-area">
<div class="ed-area-top">
<div class="es-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"></path></svg></div>
<span class="es-tag es-mono">/dns</span>
</div>
<span class="es-kicker">DNS</span>
<h3 class="es-h3">AD-integrated zones</h3>
<p class="es-product-text">Browse the zones stored in the domain's DNS partition and add or delete records, written in the format Samba actually serves.</p>
<div class="es-tags"><span class="es-tag">A · AAAA</span><span class="es-tag">CNAME · MX</span><span class="es-tag">TXT · NS · PTR</span></div>
</div>
<div class="es-card ed-area">
<div class="ed-area-top">
<div class="es-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6l8-3z"></path><path d="M9 12l2 2 4-4"></path></svg></div>
<span class="es-tag es-mono">/gpo</span>
</div>
<span class="es-kicker">Group Policy</span>
<h3 class="es-h3">GPOs and their links</h3>
<p class="es-product-text">Create Group Policy Objects, set their status, and link or unlink them to OUs. Policy settings stay in SYSVOL on the DC.</p>
<div class="es-tags"><span class="es-tag">Link to OU</span></div>
</div>
<div class="es-card ed-area">
<div class="ed-area-top">
<div class="es-icon"><svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"></path></svg></div>
<span class="es-tag es-mono">/ous</span>
</div>
<span class="es-kicker">Organizational Units</span>
<h3 class="es-h3">The OU tree</h3>
<p class="es-product-text">Browse the tree, create, rename and delete OUs, and move users, groups and computers into the OU where they belong.</p>
<div class="es-tags"><span class="es-tag">Move objects</span></div>
</div>
</div>
</div>
</section>
<section id="health" class="es-band es-section es-subtle">
<div class="es-wrap">
<div class="es-head--stack">
<span class="es-kicker-lg">Health check</span>
<h2 class="es-h2">Find what is quietly broken before it breaks logons.</h2>
<p class="es-desc">One click runs thirteen read-only checks against the domain and reports each as passed, warning, failed or skipped, with what to do about it. Everything runs over LDAP, and nothing is written.</p>
</div>
<div class="ed-checks">
<div class="es-card ed-check">
<div class="ed-check-head">
<div class="es-icon es-icon--sm"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 7v5l3 2"></path></svg></div>
<h3 class="ed-check-title">Time</h3>
</div>
<ul class="ed-check-list">
<li>Clock skew against the DC, warning at 60 s and failing at the 300 s Kerberos limit</li>
</ul>
</div>
<div class="es-card ed-check">
<div class="ed-check-head">
<div class="es-icon es-icon--sm"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="4" width="18" height="7" rx="2"></rect><rect x="3" y="13" width="18" height="7" rx="2"></rect><path d="M7 7.5h.01M7 16.5h.01"></path></svg></div>
<h3 class="ed-check-title">Domain</h3>
</div>
<ul class="ed-check-list">
<li>Domain controllers and sites</li>
<li>All five FSMO holders still exist</li>
<li>Domain and forest functional levels</li>
</ul>
</div>
<div class="es-card ed-check">
<div class="ed-check-head">
<div class="es-icon es-icon--sm"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17 1l4 4-4 4"></path><path d="M3 11V9a4 4 0 014-4h14M7 23l-4-4 4-4"></path><path d="M21 13v2a4 4 0 01-4 4H3"></path></svg></div>
<h3 class="ed-check-title">Replication</h3>
</div>
<ul class="ed-check-list">
<li>Inbound partners on the domain, configuration and schema partitions</li>
</ul>
</div>
<div class="es-card ed-check">
<div class="ed-check-head">
<div class="es-icon es-icon--sm"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M3 12h18M12 3a14 14 0 010 18M12 3a14 14 0 000 18"></path></svg></div>
<h3 class="ed-check-title">DNS</h3>
</div>
<ul class="ed-check-list">
<li>The <code>_ldap</code>, <code>_kerberos</code>, <code>_kpasswd</code> and <code>_gc</code> SRV records clients use to find a DC</li>
<li>Each DC's host record and <code>_msdcs</code> alias</li>
</ul>
</div>
<div class="es-card ed-check">
<div class="ed-check-head">
<div class="es-icon es-icon--sm"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="11" width="16" height="10" rx="2"></rect><path d="M8 11V7a4 4 0 018 0v4"></path></svg></div>
<h3 class="ed-check-title">Security</h3>
</div>
<ul class="ed-check-list">
<li>LDAPS reachability and certificate expiry</li>
<li>Machine account quota and anonymous LDAP access</li>
<li>Unconstrained delegation, and disabled accounts in privileged groups</li>
</ul>
</div>
<div class="es-card ed-check">
<div class="ed-check-head">
<div class="es-icon es-icon--sm"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2M6 6l1 14h10l1-14"></path></svg></div>
<h3 class="ed-check-title">Hygiene</h3>
</div>
<ul class="ed-check-list">
<li>Computers with no logon for 90 days</li>
<li>Accounts whose password is not required, or never expires</li>
</ul>
</div>
</div>
<p class="ed-note">Some things are only visible from a shell on the DC, such as <code>samba-tool dbcheck</code> and SYSVOL replication; the <a href="health-check/">health check guide</a> lists what is and is not covered.</p>
</div>
</section>
<section id="architecture" class="es-band es-section">
<div class="es-wrap">
<div class="es-head--stack">
<span class="es-kicker-lg">Architecture</span>
<h2 class="es-h2">A console beside your domain, not a change to it</h2>
<p class="es-desc">EasyDC is a web console and an LDAP client in one binary. It binds to each domain controller as the account you give it and works on the directory directly, so there is no agent to install and nothing to change on the DCs.</p>
</div>
<div class="es-diagram">
<div class="es-diagram-scroll">
<svg viewBox="0 0 1120 360" role="img" aria-label="Diagram: administrators use the EasyDC web console over HTTP; EasyDC keeps logins, servers and the audit log in SQLite and reads and writes Samba AD domain controllers over LDAP or LDAPS, with nothing installed on them.">
<defs>
<marker id="ed-ah" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="a-head" d="M0 0L10 5L0 10z"></path></marker>
<marker id="ed-ahb" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path class="a-head a-head--es" d="M0 0L10 5L0 10z"></path></marker>
</defs>
<text class="a-lane" x="0" y="14">YOU</text>
<text class="a-lane" x="300" y="14">EASYDC</text>
<text class="a-lane" x="880" y="14">YOUR DOMAIN</text>
<g class="a-ext"><rect x="0" y="122" width="220" height="76" rx="10"></rect><text class="a-title" x="20" y="154">Administrators</text><text class="a-sub" x="20" y="178">any browser</text></g>
<g class="a-es"><rect x="300" y="30" width="500" height="310" rx="14"></rect><text class="a-title" x="324" y="66">EasyDC</text><text class="a-sub" x="324" y="90">one binary</text></g>
<g class="a-box"><rect x="324" y="120" width="210" height="80" rx="10"></rect><text class="a-title" x="340" y="152">Web console</text><text class="a-sub" x="340" y="176">:3000 · health check</text></g>
<g class="a-box"><rect x="566" y="120" width="210" height="80" rx="10"></rect><text class="a-title" x="582" y="152">LDAP client</text><text class="a-sub" x="582" y="176">one bind per server</text></g>
<g class="a-box"><rect x="324" y="240" width="452" height="76" rx="10"></rect><text class="a-title" x="340" y="272">SQLite</text><text class="a-sub" x="340" y="296">logins · servers · audit log</text></g>
<g class="a-ext"><rect x="880" y="50" width="240" height="84" rx="10"></rect><text class="a-title" x="900" y="84">Samba AD DC</text><text class="a-sub" x="900" y="110">nothing installed</text></g>
<g class="a-ext"><rect x="880" y="186" width="240" height="84" rx="10"></rect><text class="a-title" x="900" y="220">Samba AD DC</text><text class="a-sub" x="900" y="246">nothing installed</text></g>
<line class="a-line" x1="220" y1="160" x2="322" y2="160" marker-end="url(#ed-ah)"></line>
<text class="a-label" x="271" y="150" text-anchor="middle">HTTP</text>
<line class="a-line a-line--es" x1="534" y1="160" x2="564" y2="160" marker-end="url(#ed-ahb)"></line>
<line class="a-line a-line--es" x1="429" y1="200" x2="429" y2="238" marker-end="url(#ed-ahb)"></line>
<text class="a-label a-label--es" x="441" y="224">audit</text>
<path class="a-line a-line--es" fill="none" d="M776 160 H828 V92 H878" marker-end="url(#ed-ahb)"></path>
<path class="a-line a-line--es" fill="none" d="M776 160 H828 V228 H878" marker-end="url(#ed-ahb)"></path>
<text class="a-label a-label--es" x="836" y="156">LDAPS</text>
</svg>
</div>
<div class="es-legend">
<span><span class="es-swatch"></span>EasySYS service</span>
<span><span class="es-swatch es-swatch--ext"></span>Your existing infrastructure</span>
<span class="es-legend-note">Add as many domain controllers as you like; each keeps its own bind account.</span>
</div>
</div>
</div>
</section>
<section id="install" class="es-band es-section es-subtle">
<div class="es-wrap es-install">
<div>
<span class="es-kicker-lg">Deploy</span>
<h2 class="es-h2">Running in minutes, on any Linux host.</h2>
<p class="es-desc">EasyDC is one binary for x86_64 or arm64. Run it in place to try it, or install it as a systemd service under its own user. The <a href="install/">installation guide</a> has the details.</p>
<div class="es-steps">
<div class="es-step"><span class="es-step-num es-mono">1</span><div><div class="es-step-title">Download the binary</div><div class="es-step-text">From the GitHub releases, for x86_64 or arm64.</div></div></div>
<div class="es-step"><span class="es-step-num es-mono">2</span><div><div class="es-step-title">Run it, or enable the service</div><div class="es-step-text">It listens on port 3000 and keeps its state in one SQLite file.</div></div></div>
<div class="es-step"><span class="es-step-num es-mono">3</span><div><div class="es-step-title">Create your admin, add a DC</div><div class="es-step-text">Point it at a domain controller with an ldaps:// URL and a bind account.</div></div></div>
</div>
</div>
<div class="es-terminal es-code">
<input class="es-os-radio" type="radio" name="es-os" id="es-os-deb" checked />
<input class="es-os-radio" type="radio" name="es-os" id="es-os-rpm" />
<div class="es-tabs">
<label for="es-os-deb">Try it</label>
<label for="es-os-rpm">systemd service</label>
</div>
<div class="es-panel es-panel--deb"><div class="es-term-body es-mono"><span class="t-c"># 1 — download for your architecture</span>
<span class="t-p">$</span> curl -fLo easydc https://github.com/easysysio/EasyDC/\
    releases/latest/download/easydc-linux-x86_64
<span class="t-p">$</span> chmod +x easydc
<span class="t-c"># 2 — run it in place</span>
<span class="t-p">$</span> ./easydc
<span class="t-c"># 3 — create your admin</span>
<span class="t-ok">→</span> http://&lt;host&gt;:3000/setup</div></div>
<div class="es-panel es-panel--rpm"><div class="es-term-body es-mono"><span class="t-c"># 1 — install the binary under its own user</span>
<span class="t-p">$</span> sudo cp easydc /usr/local/bin/easydc
<span class="t-p">$</span> sudo useradd -r -s /bin/false easydc
<span class="t-p">$</span> sudo install -d -o easydc -g easydc /var/lib/easydc
<span class="t-c"># 2 — add the unit from the guide, then start it</span>
<span class="t-p">$</span> sudo systemctl enable --now easydc
<span class="t-c"># 3 — create your admin</span>
<span class="t-ok">→</span> http://&lt;host&gt;:3000/setup</div></div>
</div>
</div>
</section>
<section class="es-band es-cta">
<div class="es-wrap">
<div class="es-cta-box">
<svg class="es-cta-hex" viewBox="0 0 512 512" aria-hidden="true"><polygon points="86,256 171,109 341,109 426,256 341,403 171,403" fill="none" stroke="#ffffff" stroke-width="34" stroke-linejoin="round"></polygon></svg>
<div class="es-cta-copy">
<h2 class="es-h2">Start with one domain controller.</h2>
<p class="es-cta-text">Add a single DC, run the health check, and see what your domain looks like from the browser. MIT licensed and developed in the open.</p>
</div>
<div class="es-cta-actions">
<a class="es-btn es-btn--primary es-btn--lg" href="install/">Read the docs</a>
<a class="es-btn es-btn--on-dark es-btn--lg" href="https://github.com/easysysio/EasyDC" target="_blank" rel="noopener noreferrer">GitHub</a>
</div>
</div>
</div>
</section>
<footer class="es-band es-footer">
<div class="es-wrap es-footer-grid">
<div>
<a href="." class="es-brand"><img src="assets/logo.svg" alt="EasyDC" /><span class="es-brand-name">Easy<span>DC</span></span></a>
<p class="ed-small">Samba Active Directory from the browser. Part of the <a href="https://easysys.io">EasySYS</a> suite.</p>
</div>
<div class="es-footer-col">
<span class="es-footer-title">Documentation</span>
<a href="install/">Installation</a>
<a href="getting-started/">Getting started</a>
<a href="managing/">Managing the domain</a>
<a href="health-check/">Health check</a>
<a href="reference/">Reference</a>
</div>
<div class="es-footer-col">
<span class="es-footer-title">EasySYS</span>
<a href="https://easysys.io">easysys.io</a>
<a href="https://easylog.easysys.io">EasyLog</a>
<a href="https://easywaf.easysys.io">EasyWAF</a>
<a href="https://easyvault.easysys.io">EasyVault</a>
<a href="https://www.easynas.org">EasyNAS</a>
</div>
<div class="es-footer-col">
<span class="es-footer-title">Community</span>
<a href="https://github.com/easysysio/EasyDC">GitHub</a>
<a href="https://github.com/easysysio/EasyDC/releases">Releases</a>
<a href="https://discord.gg/easysys">Discord</a>
</div>
</div>
<div class="es-wrap">
<div class="es-footer-bottom">
<span>© 2026 EasySYS · MIT licensed</span>
<span class="es-mono">easydc.easysys.io</span>
</div>
</div>
</footer>
</div>

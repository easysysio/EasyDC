// The parts of the page around the content: the sidebar, the light and dark
// switch, the server switcher, and search (Ctrl-K or ⌘K).
(function () {
    'use strict';

    const shell = document.querySelector('.app-shell');
    if (!shell) return;
    const serverId = shell.dataset.server || '';

    // ── which page we are on ─────────────────────────────────────────────────
    const links = Array.from(document.querySelectorAll('.app-nav-link[href]'));
    const here = location.pathname.replace(/\/$/, '') || '/';
    const best = links
        .filter(a => {
            const path = a.getAttribute('href');
            return here === path || (path !== '/' && here.startsWith(path + '/') && a.dataset.exact === undefined);
        })
        .sort((a, b) => b.getAttribute('href').length - a.getAttribute('href').length)[0];
    if (best) best.setAttribute('aria-current', 'page');

    // ── light and dark ───────────────────────────────────────────────────────
    const themeButton = document.getElementById('themeToggle');
    const system = window.matchMedia('(prefers-color-scheme: dark)');
    function chosen() {
        try { return localStorage.getItem('easydc.theme'); } catch (e) { return null; }
    }
    function apply(theme) {
        document.documentElement.dataset.bsTheme = theme;
        const dark = theme === 'dark';
        themeButton.querySelector('i').className = 'bi ' + (dark ? 'bi-sun' : 'bi-moon');
        const label = dark ? 'Switch to light mode' : 'Switch to dark mode';
        themeButton.title = label;
        themeButton.setAttribute('aria-label', label);
    }
    apply(document.documentElement.dataset.bsTheme || 'light');
    themeButton.addEventListener('click', function () {
        const next = document.documentElement.dataset.bsTheme === 'dark' ? 'light' : 'dark';
        try {
            // Back on the system's own choice, follow it again.
            if (next === (system.matches ? 'dark' : 'light')) localStorage.removeItem('easydc.theme');
            else localStorage.setItem('easydc.theme', next);
        } catch (e) { /* storage blocked: this page only */ }
        apply(next);
    });
    system.addEventListener('change', function () {
        if (!chosen()) apply(system.matches ? 'dark' : 'light');
    });

    // ── functional level, read after the page so a DC that is down cannot hold it up ──
    document.querySelectorAll('.js-server-level').forEach(function (el) {
        fetch(el.dataset.url, { headers: { Accept: 'application/json' } })
            .then(r => r.ok ? r.json() : Promise.reject())
            .then(l => {
                el.textContent = el.dataset.short !== undefined ? l.text.replace('Functional level', 'Level') : l.text;
                el.title = l.title;
            })
            .catch(() => {
                el.textContent = el.dataset.short !== undefined ? 'Level unknown' : 'Functional level unknown';
                el.title = 'EasyDC could not read the level from this server.';
            });
    });

    // ── the server switcher: stays on the same kind of page ──────────────────
    const switcher = document.getElementById('serverMenu');
    if (switcher) {
        let loaded = false;
        const section = (location.pathname.split('/')[3] || '');
        switcher.parentElement.addEventListener('show.bs.dropdown', function () {
            if (loaded) return;
            loaded = true;
            fetch('/servers/switcher', { headers: { Accept: 'application/json' } })
                .then(r => r.ok ? r.json() : Promise.reject())
                .then(function (servers) {
                    const items = servers.map(function (s) {
                        const li = document.createElement('li');
                        const a = document.createElement('a');
                        a.className = 'dropdown-item' + (String(s.id) === serverId ? ' active' : '');
                        a.href = '/servers/' + s.id + (section ? '/' + section : '');
                        a.textContent = s.name;
                        if (String(s.id) === serverId) a.setAttribute('aria-current', 'true');
                        li.append(a);
                        return li;
                    });
                    switcher.querySelector('.js-loading').replaceWith(...items);
                })
                .catch(function () {
                    switcher.querySelector('.js-loading').textContent = 'Could not load the servers.';
                });
        });
    }

    // ── search ───────────────────────────────────────────────────────────────
    const dialog = document.getElementById('findDialog');
    const input = document.getElementById('findInput');
    const results = document.getElementById('findResults');
    const pages = links.map(a => ({
        label: a.textContent.trim(),
        href: a.getAttribute('href'),
        icon: a.querySelector('i').className.replace('bi ', ''),
    }));
    const ICONS = { user: 'bi-person', group: 'bi-people', computer: 'bi-pc-display' };
    const HEADS = { user: 'Users', group: 'Groups', computer: 'Computers' };
    let items = [];
    let active = 0;
    let timer = null;
    let asked = 0;

    function hrefFor(f) {
        const base = '/servers/' + serverId;
        const page = { user: 'users', group: 'groups', computer: 'computers' }[f.kind];
        return base + '/' + page + '#open=' + encodeURIComponent(f.name);
    }
    function mark() {
        items.forEach((el, i) => {
            el.classList.toggle('is-active', i === active);
            el.setAttribute('aria-selected', i === active ? 'true' : 'false');
        });
        if (items[active]) {
            items[active].scrollIntoView({ block: 'nearest' });
            input.setAttribute('aria-activedescendant', items[active].id);
        } else {
            input.removeAttribute('aria-activedescendant');
        }
    }
    function head(text) {
        const div = document.createElement('div');
        div.className = 'find-head';
        div.setAttribute('role', 'presentation');
        div.textContent = text;
        return div;
    }
    function item(label, sub, icon, href) {
        const a = document.createElement('a');
        a.className = 'find-item';
        a.href = href;
        a.id = 'find-' + items.length;
        a.setAttribute('role', 'option');
        const i = document.createElement('i');
        i.className = 'bi ' + icon;
        i.setAttribute('aria-hidden', 'true');
        const text = document.createElement('span');
        text.textContent = label;
        a.append(i, text);
        if (sub) {
            const s = document.createElement('span');
            s.className = 'find-sub';
            s.textContent = sub;
            a.append(s);
        }
        items.push(a);
        return a;
    }
    function show(found, note) {
        const q = input.value.trim().toLowerCase();
        const nodes = [];
        items = [];
        const matching = pages.filter(p => !q || p.label.toLowerCase().includes(q));
        if (matching.length) {
            nodes.push(head('Pages'));
            matching.forEach(p => nodes.push(item(p.label, '', p.icon, p.href)));
        }
        ['user', 'group', 'computer'].forEach(function (kind) {
            const list = found.filter(f => f.kind === kind);
            if (!list.length) return;
            nodes.push(head(HEADS[kind]));
            list.forEach(f => nodes.push(item(f.name, f.detail, ICONS[kind], hrefFor(f))));
        });
        if (note || !nodes.length) {
            const div = document.createElement('div');
            div.className = 'find-empty';
            div.textContent = note || 'Nothing found.';
            nodes.push(div);
        }
        results.replaceChildren(...nodes);
        active = 0;
        mark();
    }
    function search() {
        const q = input.value.trim();
        clearTimeout(timer);
        const turn = ++asked;
        if (!serverId || q.length < 2) return show([]);
        show([], 'Searching…');
        timer = setTimeout(function () {
            fetch('/servers/' + serverId + '/find?q=' + encodeURIComponent(q), { headers: { Accept: 'application/json' } })
                .then(r => r.ok ? r.json() : Promise.reject())
                .then(found => { if (turn === asked) show(found); })
                .catch(() => { if (turn === asked) show([], 'Could not search this server.'); });
        }, 200);
    }
    function openSearch() {
        bootstrap.Modal.getOrCreateInstance(dialog).show();
    }

    document.getElementById('openSearch').addEventListener('click', openSearch);
    dialog.addEventListener('shown.bs.modal', function () {
        input.value = '';
        show([]);
        input.focus();
    });
    input.addEventListener('input', search);
    input.addEventListener('keydown', function (e) {
        if (e.key === 'ArrowDown' && items.length) {
            e.preventDefault();
            active = (active + 1) % items.length;
            mark();
        } else if (e.key === 'ArrowUp' && items.length) {
            e.preventDefault();
            active = (active - 1 + items.length) % items.length;
            mark();
        } else if (e.key === 'Enter' && items[active]) {
            e.preventDefault();
            location.href = items[active].href;
        }
    });
    // A link to this same page with another #: the page itself reacts to it.
    results.addEventListener('click', function (e) {
        if (e.target.closest('.find-item')) bootstrap.Modal.getOrCreateInstance(dialog).hide();
    });
    window.addEventListener('hashchange', function () {
        const m = dialog.classList.contains('show') && bootstrap.Modal.getInstance(dialog);
        if (m) m.hide();
    });
    document.addEventListener('keydown', function (e) {
        if ((e.metaKey || e.ctrlKey) && !e.altKey && e.key.toLowerCase() === 'k') {
            // Not over a dialog that is already open, where typing belongs to it.
            if (document.querySelector('.modal.show:not(#findDialog)')) return;
            e.preventDefault();
            openSearch();
        }
    });
})();

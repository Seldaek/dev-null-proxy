# dev-null-proxy

dev-null.sh is pretty cool but I thought it's sad we can't address it as /dev/null for real.. Now with this project you can!

Open [https://dev/null](https://dev/null) in your browser and get [dev-null.sh](https://dev-null.sh).

A tiny local HTTPS reverse proxy written in PHP (on [amphp](https://amphp.org)) that serves dev-null.sh at
`https://dev/null`, GitHub sign in included. It also gives you files you can pipe stuff to to be social
from your terminal `/dev/NULL` and `/dev/null​` (there is a zero-width-space following here, you just can't
see it, this will not break your real /dev/null nor fill your disk with bullshit). Once setup you can 
`echo 'Hello!' > /dev/NULL`.

Runs on Linux, macOS and WSL (with the browser on Windows).

## Setup

1. Install it (PHP 8.4+ with ext-openssl, ext-pcntl and ext-posix):

   ```sh
   composer global require seld/dev-null-proxy
   ```

2. Point `dev` **and `dev-null.sh`** at your machine by adding these lines to your hosts file
   (`/etc/hosts`, or `C:\Windows\System32\drivers\etc\hosts` when using WSL):

   ```
   127.0.0.1 dev
   127.0.0.1 dev-null.sh
   ```

   The `dev-null.sh` line is what makes signing in with GitHub work, see [Signing in](#signing-in).
   Skip it if you only want to browse logged out, or prefer importing your session by hand.

3. Trust the local certificate authority (one time). This creates a CA that only lives on your machine and adds it
   to your OS trust store (on WSL, to the Windows one, where your browser runs; Windows asks you to confirm):

   ```sh
   dev-null-proxy trust
   ```

4. Run it:

   ```sh
   dev-null-proxy
   ```

   It listens on port 443, which needs privileges on Linux, WSL and macOS. Either allow low ports once with
   `sudo sysctl -w net.ipv4.ip_unprivileged_port_start=80` (add it to `/etc/sysctl.d/` to keep it after reboots),
   run it with `sudo`, or put it [behind nginx](#running-behind-nginx) if something already uses 443.

## Signing in

GitHub only ever sends you back to `https://dev-null.sh/auth/github/callback`. For the proxy to finish a sign in
started on `https://dev`, `dev-null.sh` has to point at the proxy too, **on port 443**. With both hosts entries in
place, just click "Sign in": the proxy catches the callback, completes it with your `https://dev` session and
sends you back to `https://dev/null`, signed in.

When that can't work (no `dev-null.sh` hosts entry, or the proxy on another port without nginx in front), "Sign in"
leads to `https://dev/__dev-null-proxy/login` instead. It says what's missing, still offers the GitHub button,
and lets you import your session by hand: sign in on the real dev-null.sh, copy the `remember_web_…` cookie from
devtools (Application → Cookies) and paste it there. That cookie stays valid for about a year, until you sign out.

While `dev-null.sh` points at the proxy, everything you do on `https://dev-null.sh` goes through it unchanged,
using its local CA, and the proxy finds the real dev-null.sh with public DNS (1.1.1.1, 8.8.8.8, 9.9.9.9).
The flip side: `https://dev-null.sh` only loads while the proxy is running.

### "You're offline"?

That page comes from dev-null.sh's service worker, which turns any failed page load into it. A worker installed
from the real site can't reach the proxy on 127.0.0.1, so the GitHub callback fails. The proxy keeps the worker
from installing on both `https://dev` and `https://dev-null.sh`, but if you visited dev-null.sh before, remove the
old one once: devtools on a dev-null.sh tab → Application → Service workers → Unregister (or via
`chrome://serviceworker-internals`).

## Committing from your shell: /dev/NULL

Everything written to `/dev/NULL` gets committed to your dev-null.sh account:

```sh
echo 'Hello from my terminal!' > /dev/NULL
git log -1 --format=%s > /dev/NULL
cat shipped.png > /dev/NULL        # PNG, JPEG and WebP up to 10 MB become an image commit
```

Set it up once, then keep the reader running (in a terminal, tmux, …):

```sh
sudo bin/dev-null-proxy install-pipe
bin/dev-null-proxy pipe
```

There is no login: like dev-null.sh's own `curl … /commit | bash` script, each commit is signed with an SSH key
from your agent or `~/.ssh` that is on your GitHub account, and the site checks it against the keys GitHub
publishes. Each write (open, write, close) is one commit. The reader prints the link, or why it was refused
(binary data that isn't an image, the site's length or rate limits, …). It doesn't need the proxy to be running,
and talks to the real dev-null.sh even when your hosts file points it at the proxy.

- `install-pipe` creates `/dev/NULL` (only writable by you) plus an invisible alias, `/dev/null` followed by a
  zero-width space, which looks exactly like `/dev/null`. Skip that with `--no-alias`: anything that
  ends up in a command you copy & paste could contain it and publish that command's output.
  A systemd `tmpfiles.d` entry brings both back after a reboot. `sudo dev-null-proxy uninstall-pipe` removes it all.
- Writes block until the reader picks them up, so `echo hi > /dev/NULL` hangs while `dev-null-proxy pipe` isn't running.
- macOS doesn't allow files in `/dev`, use another path there: `dev-null-proxy install-pipe --path=$HOME/NULL`, then
  `dev-null-proxy pipe --path=$HOME/NULL`.

## Running behind nginx

If something else already uses port 443, let it forward `dev` and `dev-null.sh` to the proxy. That way the
proxy doesn't need root either, and GitHub sign in still works. Run it as
`dev-null-proxy --port=8443 --behind-proxy`, and with nginx:

```nginx
server {
    # use the same address as your other vhosts: nginx only matches server_name
    # among servers listening on the exact address a connection came in on
    listen 127.0.0.1:443 ssl;
    http2 on;
    server_name dev dev-null.sh;

    # these live next to the CA, see `dev-null-proxy ca-path`
    ssl_certificate     /home/you/.config/dev-null-proxy/dev.crt;
    ssl_certificate_key /home/you/.config/dev-null-proxy/dev.key;

    location / {
        proxy_pass https://127.0.0.1:8443;
        proxy_set_header Host $host;
        proxy_buffering off;
        client_max_body_size 0;
    }
}
```

`--behind-proxy` tells the proxy browsers reach it on 443. Keep `proxy_set_header Host $host`: the proxy builds
its links from the `Host` header, and keep it on HTTPS behind nginx, as it builds them from the scheme too.

## Why HTTPS?

`.dev` is an [HSTS-preloaded](https://hstspreload.org/?domain=dev) TLD, so browsers always use `https://dev/`
and won't let you click past a certificate warning. That's why the proxy has its own CA and listens on 443.
If you use a different hostname, `--no-tls --port=80` serves plain HTTP instead.

## How it works

- `/null` and `/null/…` are forwarded to the root of dev-null.sh. Every other path is forwarded as is, since the
  site's links are root-relative (`/about`, `/@user`, `/build/…`).
- The site's router (Inertia) sets the address bar from the page it receives, so the proxy adds `/null` to that,
  and to redirects: you stay on `https://dev/null/…`, and reloading lands on the same page.
- Absolute `https://dev-null.sh` URLs in pages and headers point back at the proxy, and cookies lose their
  `Domain` so the browser keeps them for `dev`.

## Commands and options

```
serve           Run the proxy (default)
trust           Create the local CA and add it to your OS trust store
ca-path         Print the path to the local CA certificate
install-pipe    Create /dev/NULL (and /dev/null<U+200B>), needs sudo
pipe            Commit whatever gets written to /dev/NULL
uninstall-pipe  Remove them again, needs sudo

--host=NAME       Hostname the certificate is issued for (default: dev)
--port=N          Listen port (default: 443, or 80 with --no-tls)
--http-port=N     Also listen on plain HTTP and redirect to HTTPS (default: off)
--listen=IP       Address to bind (default: 127.0.0.1)
--upstream=URL    Site to proxy (default: https://dev-null.sh)
--prefix=PATH     Local path mapped to the upstream root (default: /null)
--no-tls          Serve plain HTTP (won't work for "dev", it is HSTS-preloaded)
--behind-proxy    Another server (e.g. nginx) forwards port 443 to this one
-v                Log every request
--path=FILE       Pipe to use (default: /dev/NULL)
--no-alias        Don't create the invisible /dev/null<U+200B> alias
```

The CA and certificates are stored in `~/.config/dev-null-proxy`, or wherever `DEV_NULL_PROXY_HOME` points.
Under `sudo`, the proxy keeps using the invoking user's folder, so the CA you trusted stays the one in use.

## Known limitations

- Links on the page still point at root paths like `/about`. They work, and the address bar switches to
  `/null/about` once the page loads.
- Firefox uses its own certificate store on Linux. On Windows and macOS it trusts the OS store by default
  (`security.enterprise_roots.enabled`).
- Native Windows PHP isn't supported, use WSL.

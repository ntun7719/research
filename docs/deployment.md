# Deployment

## Railway or similar hosted platform

Mount a persistent volume at **/data**. The container starts as root only long enough to repair ownership on the mounted volume, then permanently drops to UID and GID 10001 before starting the application.

The web server honors **PORT**, so hosted HTTPS domains can route to the dashboard automatically.

Hosted HTTPS domains usually do not expose arbitrary TCP 853. For Android Private DNS, configure FRP from the Lattice dashboard and point the Private DNS hostname to the public FRPS server.

## Cloudflare

The Cloudflare token is entered in Settings and stored encrypted.

For certificate issuance, the token must allow the Certbot Cloudflare plugin to create DNS challenge records in the authoritative zone.

For public record synchronization, the same token must be able to read the zone and edit DNS records. Lattice creates or replaces one A, AAAA or CNAME record for the configured Private DNS hostname. Cloudflare proxying stays disabled because ordinary DoT on TCP 853 must reach FRPS directly.

## FRPS

Use an FRPS version compatible with the bundled FRPC 0.61.1.

Example:

~~~toml
bindPort = 7000
allowPorts = [{ single = 853 }]
transport.tls.force = true
~~~

With token authentication:

~~~toml
auth.method = "token"
auth.token = "replace-with-a-long-random-token"
~~~

Open the FRPS control port only to clients that need it. Public TCP 853 is the Android Private DNS entry point.

## Remote dashboard access

Keep port 8080 private when possible. The included Compose file binds it to loopback. Put an HTTPS reverse proxy in front of it for remote administration.

The dashboard session cookie becomes Secure when the reverse proxy sends **X Forwarded Proto: https**.

## Backups

Back up the full **/data** volume. It contains configuration, encrypted integration tokens, the encryption key, certificate generations, ACME state, subscriptions and retained query telemetry.

A database file without the volume key does not expose the integration tokens. A full volume backup contains both and must be protected accordingly.

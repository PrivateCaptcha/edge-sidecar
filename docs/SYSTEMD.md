# systemd

Use the [template unit](edge-sidecar@.service) to run one or more sidecars from a single service definition. Each instance has its own configuration, dynamic user, runtime directory, and cache directory.

## Install

Run these commands from the repository root on the server. `make build` defaults to Linux amd64; set `GOARCH` for other architectures.

```sh
make build
sudo install -m 0755 bin/edge-sidecar /usr/local/bin/edge-sidecar
sudo install -m 0644 docs/edge-sidecar@.service /etc/systemd/system/edge-sidecar@.service
sudo install -d -m 0700 /etc/edgesidecar
sudo install -o root -g root -m 0600 docs/edge-sidecar.env.example /etc/edgesidecar/example.conf
sudoedit /etc/edgesidecar/example.conf
```

Set `PC_SITEKEY`, `PC_API_KEY`, and `PC_PROTECTED_ORIGIN` for your property. The [configuration example](edge-sidecar.env.example) listens on `127.0.0.1:8080`, matching the [Caddy](CADDY.md) and [nginx](NGINX.md) examples. See [configuration](../README.md#configuration) for all settings and property requirements.

Start the instance and enable it at boot:

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now edge-sidecar@example.service
```

The instance name is the part between `@` and `.service`. Systemd substitutes it for `%i` in the template:

| Instance | Configuration file |
| --- | --- |
| `example` | `/etc/edgesidecar/example.conf` |
| `blog` | `/etc/edgesidecar/blog.conf` |

## Add another instance

```sh
sudo install -o root -g root -m 0600 docs/edge-sidecar.env.example /etc/edgesidecar/blog.conf
sudoedit /etc/edgesidecar/blog.conf
```

Set the second property's sitekey and origin, and choose a different listening address/port combination, for example `PC_HOST=127.0.0.1` and `PC_PORT=8081`. Point that site's proxy authorization and CAPTCHA completion requests at `127.0.0.1:8081`.

```sh
sudo systemctl enable --now edge-sidecar@blog.service
```

No separate unit file or `daemon-reload` is needed when adding an instance of the installed template.

## Manage instances and configuration

```sh
sudo systemctl status edge-sidecar@example.service
sudo journalctl -u edge-sidecar@example.service -f
sudo systemctl restart edge-sidecar@example.service
sudo systemctl disable --now edge-sidecar@blog.service
```

After editing `/etc/edgesidecar/example.conf`, restart that instance. `LoadCredential=` copies the file when the service starts; `systemctl reload` sends SIGHUP but only rereads the existing credential copy, so it does not pick up changes to the source file. Configuration-file edits do not require `daemon-reload`.

After editing the template, run `sudo systemctl daemon-reload`, then restart the affected instances.

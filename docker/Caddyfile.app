{
	admin off
}

:8080 {
	header Content-Type "text/plain; charset=utf-8"
	header X-Demo-Method {method}
	header X-Demo-URI {uri}
	header X-Demo-Host {hostport}
	header X-Demo-Upgrade {http.request.header.Upgrade}
	header X-Demo-Connection {http.request.header.Connection}
	respond /echo "{http.request.body}"
	respond /unauthorized "PrivateCaptcha edge demo: application unauthorized." 401
	respond "PrivateCaptcha edge demo: application reached."
}

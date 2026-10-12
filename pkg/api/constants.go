package api

import (
	"net/http"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
)

const (
	authPath     = "/auth"
	healthPath   = "/healthz"
	completePath = "/__privatecaptcha/complete"
	ServiceName  = "edge_sidecar"
	gatePath     = "/" + common.GateEndpoint + "/" + common.PageEndpoint
	jwksPath     = "/" + common.WellKnownEndpoint + "/" + common.JWKSFileEndpoint

	edgeCookieName = "__Host-privatecaptcha-edge"
	edgeTokenType  = "pc-edge+jwt"
	keyAlgorithm   = "ES256"
	keyType        = "EC"
	keyCurve       = "P-256"
	keyUse         = "sig"

	maxTokenBytes  = 4096
	maxKeyIDBytes  = 128
	maxFormBytes   = 1024 * 1024
	maxProofBytes  = 256 * 1024
	maxVerifyBytes = 16 * 1024
	maxGateBytes   = 1024 * 1024
	maxRequestURI  = 2048
	maxTokenTTL    = 24 * time.Hour
	requestTimeout = 8 * time.Second
	fetchTimeout   = 5 * time.Second
	proxyTimeout   = time.Second
	proxyDNSTTL    = 10 * time.Second
	fetchAttempts  = 3
	gateRetryGap   = 2 * time.Second
	maxGateTTL     = 24 * time.Hour

	cacheNoStore = "no-store"
)

var (
	HeaderAccept          = http.CanonicalHeaderKey("Accept")
	HeaderAllow           = http.CanonicalHeaderKey("Allow")
	HeaderCookie          = http.CanonicalHeaderKey("Cookie")
	HeaderAge             = http.CanonicalHeaderKey("Age")
	HeaderDate            = http.CanonicalHeaderKey("Date")
	HeaderExpires         = http.CanonicalHeaderKey("Expires")
	HeaderLastModified    = http.CanonicalHeaderKey("Last-Modified")
	HeaderIfModifiedSince = http.CanonicalHeaderKey("If-Modified-Since")
	HeaderRetryAfter      = http.CanonicalHeaderKey("Retry-After")
	HeaderSetCookie       = http.CanonicalHeaderKey("Set-Cookie")
	HeaderXFrameOptions   = http.CanonicalHeaderKey("X-Frame-Options")
	HeaderForwardedHost   = http.CanonicalHeaderKey("X-Forwarded-Host")
	HeaderForwardedProto  = http.CanonicalHeaderKey("X-Forwarded-Proto")
	HeaderForwardedURI    = http.CanonicalHeaderKey("X-Forwarded-Uri")
	HeaderForwardedMethod = http.CanonicalHeaderKey("X-Forwarded-Method")
	HeaderSecFetchSite    = http.CanonicalHeaderKey("Sec-Fetch-Site")
	HeaderSecFetchMode    = http.CanonicalHeaderKey("Sec-Fetch-Mode")
	HeaderSecFetchDest    = http.CanonicalHeaderKey("Sec-Fetch-Dest")
	HeaderXRequestedWith  = http.CanonicalHeaderKey("X-Requested-With")
)

type denialReason string

const (
	reasonMissing           denialReason = "missing"
	reasonExpired           denialReason = "expired"
	reasonMalformed         denialReason = "malformed"
	reasonMalformedRequest  denialReason = "malformed_request"
	reasonBadForwarded      denialReason = "bad_forwarded"
	reasonUnknownKey        denialReason = "unknown_key"
	reasonBadSignature      denialReason = "bad_signature"
	reasonBadAudience       denialReason = "bad_audience"
	reasonBadIssuer         denialReason = "bad_issuer"
	reasonBadClaims         denialReason = "bad_claims"
	reasonBadHost           denialReason = "bad_host"
	reasonBadOrigin         denialReason = "bad_origin"
	reasonCrossSite         denialReason = "cross_site"
	reasonBadClientIP       denialReason = "bad_client_ip"
	reasonContentType       denialReason = "content_type"
	reasonConcurrencyLimit  denialReason = "concurrency_limit"
	reasonBodySize          denialReason = "body_size"
	reasonBodyRead          denialReason = "body_read"
	reasonMalformedForm     denialReason = "malformed_form"
	reasonProofSize         denialReason = "proof_size"
	reasonVerifyUnavailable denialReason = "verify_unavailable"
	reasonUnsuccessful      denialReason = "unsuccessful"
	reasonMissingEdgeToken  denialReason = "missing_edge_token"
	reasonInvalidCookie     denialReason = "invalid_cookie"
)

package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	"github.com/maypok86/otter/v2"
)

type referral struct {
	target  [32]byte
	referer string
}

func (a *Authorizer) referralTarget(r *http.Request) ([32]byte, bool) {
	values := r.Header.Values(HeaderForwardedURI)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > maxReferralURI || values[0][0] != '/' || strings.ContainsAny(values[0], " \t\r\n#") {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(a.s.protectedOrigin + values[0])), true
}

func referralCookieName(target [32]byte) string {
	return "__Host-privatecaptcha-ref-" + hex.EncodeToString(target[:12])
}

func referralCookie(r *http.Request, target [32]byte) *http.Cookie {
	cookies := r.CookiesNamed(referralCookieName(target))
	if len(cookies) != 1 || len(cookies[0].Value) == 0 || len(cookies[0].Value) > 64 {
		return nil
	}
	return cookies[0]
}

func requestReferrer(r *http.Request) string {
	values := r.Header.Values(common.HeaderReferer)
	if len(values) != 1 {
		return ""
	}
	for _, c := range values[0] {
		if (c < ' ' && c != '\t') || c == 127 {
			return ""
		}
	}
	return values[0]
}

func (a *Authorizer) captureReferrer(w http.ResponseWriter, r *http.Request) {
	referer := requestReferrer(r)
	target, ok := a.referralTarget(r)
	if !ok || referer == "" || len(referer) > maxRefererBytes {
		return
	}
	if cookie := referralCookie(r, target); cookie != nil {
		if previous, found := a.referrals.GetIfPresent(cookie.Value); found && previous.target == target && previous.referer == referer {
			return
		}
	}
	id := rand.Text()
	a.referrals.Set(id, referral{
		target:  target,
		referer: strings.Clone(referer),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     referralCookieName(target),
		Value:    id,
		Path:     "/",
		Expires:  time.Now().Add(referralTTL),
		MaxAge:   int(referralTTL / time.Second),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	slog.DebugContext(r.Context(), "Saved navigation referrer", "endpoint", authPath)
}

func (a *Authorizer) authorizedReferrer(r *http.Request) string {
	referer := requestReferrer(r)
	// nginx's status-only auth request omits Accept, but retains fetch metadata.
	if referer != "" || !navigationMetadata(r) || (r.Header.Get(HeaderSecFetchMode) == "" && !browserNavigation(r)) {
		return referer
	}
	target, ok := a.referralTarget(r)
	if !ok {
		return referer
	}
	cookie := referralCookie(r, target)
	if cookie == nil {
		return referer
	}
	a.referrals.ComputeIfPresent(cookie.Value, func(saved referral) (referral, otter.ComputeOp) {
		if saved.target != target {
			return saved, otter.CancelOp
		}
		referer = saved.referer
		return referral{}, otter.InvalidateOp
	})
	if referer != "" {
		slog.DebugContext(r.Context(), "Restored navigation referrer", "endpoint", authPath)
	}
	return referer
}

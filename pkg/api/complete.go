package api

import (
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/PrivateCaptcha/PrivateCaptcha/pkg/common"
	pc "github.com/PrivateCaptcha/private-captcha-go"
	realclientip "github.com/realclientip/realclientip-go"
)

var completionIPStrategy = realclientip.Must(realclientip.NewSingleIPHeaderStrategy(common.HeaderClientIP))

func deny(w http.ResponseWriter, r *http.Request, status int, reason denialReason, details ...slog.Attr) {
	level := slog.LevelWarn
	if status >= http.StatusInternalServerError {
		level = slog.LevelError
	}
	attrs := []slog.Attr{
		slog.String("reason", string(reason)),
		slog.Int("status", status),
		slog.String("endpoint", completePath),
	}
	slog.LogAttrs(r.Context(), level, "Edge request denied", append(attrs, details...)...)
	http.Error(w, http.StatusText(status), status)
}

func (a *Authorizer) complete(w http.ResponseWriter, r *http.Request) {
	w.Header().Set(common.HeaderCacheControl, cacheNoStore)
	common.WriteHeaders(w, common.SecurityHeaders)
	if _, err := a.s.requestHost(r); err != nil {
		deny(w, r, http.StatusForbidden, reasonBadForwarded)
		return
	}
	origin, err := singleHeader(r, common.HeaderOrigin)
	if err == nil {
		origin, _, err = normalizeOrigin(origin)
	}
	if err != nil || origin != a.s.protectedOrigin {
		deny(w, r, http.StatusForbidden, reasonBadOrigin)
		return
	}
	if values := r.Header.Values(HeaderSecFetchSite); len(values) != 0 && (len(values) != 1 || values[0] != "same-origin") {
		deny(w, r, http.StatusForbidden, reasonCrossSite)
		return
	}
	if _, err := singleHeader(r, common.HeaderClientIP); err != nil || completionIPStrategy.ClientIP(r.Header, r.RemoteAddr) == "" {
		deny(w, r, http.StatusForbidden, reasonBadClientIP)
		return
	}
	contentTypes := r.Header.Values(common.HeaderContentType)
	if len(contentTypes) != 1 {
		deny(w, r, http.StatusUnsupportedMediaType, reasonContentType)
		return
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != common.ContentTypeURLEncoded {
		deny(w, r, http.StatusUnsupportedMediaType, reasonContentType)
		return
	}
	a.limitedComplete.ServeHTTP(w, r)
}

func (a *Authorizer) completeSolution(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > maxFormBytes {
		deny(w, r, http.StatusRequestEntityTooLarge, reasonBodySize)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxFormBytes+1))
	if len(body) > maxFormBytes {
		deny(w, r, http.StatusRequestEntityTooLarge, reasonBodySize)
		return
	}
	if err != nil {
		var oversized *http.MaxBytesError
		if errors.As(err, &oversized) {
			deny(w, r, http.StatusRequestEntityTooLarge, reasonBodySize)
			return
		}
		deny(w, r, http.StatusBadRequest, reasonBodyRead)
		return
	}
	form, err := url.ParseQuery(string(body))
	if err != nil || len(form) != 1 || len(form[common.ParamPrivateCaptchaSolution]) != 1 {
		deny(w, r, http.StatusBadRequest, reasonMalformedForm)
		return
	}
	proof := form[common.ParamPrivateCaptchaSolution][0]
	if len(proof) > maxProofBytes {
		deny(w, r, http.StatusRequestEntityTooLarge, reasonProofSize)
		return
	}
	if strings.TrimSpace(proof) == "" {
		deny(w, r, http.StatusBadRequest, reasonMalformedForm)
		return
	}
	result, err := a.verifier.Verify(r.Context(), pc.VerifyInput{
		Solution: proof,
		Sitekey:  a.s.sitekey,
		Attempts: 1,
	})
	if err != nil {
		var details []slog.Attr
		if status, ok := pc.GetStatusCode(err); ok {
			details = append(details, slog.Int("upstream_status", status))
			if status == http.StatusBadRequest {
				deny(w, r, http.StatusBadRequest, reasonMalformed, details...)
				return
			}
		}
		deny(w, r, http.StatusBadGateway, reasonVerifyUnavailable, details...)
		return
	}
	if !result.Success {
		deny(w, r, http.StatusUnauthorized, reasonUnsuccessful, slog.Int("verification_code", int(result.Code)))
		return
	}
	if result.EdgeToken == "" {
		deny(w, r, http.StatusUnauthorized, reasonMissingEdgeToken)
		return
	}
	_, host, _ := normalizeOrigin(a.s.protectedOrigin)
	claims, reason := a.verify(r.Context(), result.EdgeToken, host)
	if reason != "" {
		deny(w, r, http.StatusUnauthorized, reason)
		return
	}
	maxAge := int(time.Until(claims.ExpiresAt.Time) / time.Second)
	if maxAge <= 0 {
		deny(w, r, http.StatusUnauthorized, reasonExpired)
		return
	}
	cookie := &http.Cookie{
		Name:     edgeCookieName,
		Value:    result.EdgeToken,
		Path:     "/",
		Expires:  claims.ExpiresAt.UTC(),
		MaxAge:   maxAge,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if len(cookie.String()) > maxTokenBytes || cookie.Valid() != nil {
		deny(w, r, http.StatusUnauthorized, reasonInvalidCookie)
		return
	}
	http.SetCookie(w, cookie)
	slog.InfoContext(r.Context(), "Edge captcha completion succeeded", "endpoint", completePath)
	w.WriteHeader(http.StatusNoContent)
}

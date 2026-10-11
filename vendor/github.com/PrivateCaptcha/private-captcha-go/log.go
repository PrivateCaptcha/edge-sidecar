package privatecaptcha

import (
	"log/slog"
)

const (
	levelTrace = slog.Level(-8)
)

func errAttr(err error) slog.Attr {
	return slog.Any("error", err)
}

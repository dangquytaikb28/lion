package middleware

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lion/pkg/config"
	"lion/pkg/logger"
	"lion/pkg/monitorcap"

	"github.com/jumpserver-dev/sdk-go/model"
)

// MonitorCapabilityAuth admits Lion monitor HTML/WS only when a PAM-issued
// session-scoped ticket matches the authenticated viewer and the requested
// session id. Core RBAC alone must not allow substituting another session.
func MonitorCapabilityAuth() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userItem, ok := ctx.Get(config.GinCtxUserKey)
		if !ok {
			denyMonitor(ctx, http.StatusUnauthorized)
			return
		}
		user, _ := userItem.(*model.User)
		if user == nil || user.ID == "" {
			denyMonitor(ctx, http.StatusUnauthorized)
			return
		}
		sessionID := requestedMonitorSession(ctx)
		if sessionID == "" {
			logger.Error("Monitor capability: missing session id")
			denyMonitor(ctx, http.StatusBadRequest)
			return
		}
		secret := monitorcap.SecretFromEnv()
		ticket := monitorTicketFromRequest(ctx)
		claims, err := monitorcap.Verify(secret, ticket, sessionID, user.ID, time.Now().UTC())
		if err != nil {
			logger.Errorf("Monitor capability denied user=%s session=%s err=%s", user.ID, sessionID, err.Error())
			status := http.StatusForbidden
			if err == monitorcap.ErrMissingSecret || err == monitorcap.ErrInvalidTicket || err == monitorcap.ErrExpired {
				status = http.StatusForbidden
			}
			denyMonitor(ctx, status)
			return
		}
		ttl := monitorcap.RemainingTTL(claims, time.Now().UTC())
		setMonitorTicketCookie(ctx, ticket, ttl)
		ctx.Next()
	}
}

func requestedMonitorSession(ctx *gin.Context) string {
	if sid := strings.TrimSpace(ctx.Query("SESSION_ID")); sid != "" {
		return sid
	}
	return strings.TrimSpace(ctx.Query("session"))
}

func monitorTicketFromRequest(ctx *gin.Context) string {
	if t := strings.TrimSpace(ctx.Query(monitorcap.QueryName)); t != "" {
		return t
	}
	cookie, err := ctx.Cookie(monitorcap.CookieName)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(cookie)
}

func setMonitorTicketCookie(ctx *gin.Context, ticket string, maxAge int) {
	if ticket == "" || maxAge <= 0 {
		return
	}
	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie(monitorcap.CookieName, ticket, maxAge, "/lion", "", true, true)
}

func denyMonitor(ctx *gin.Context, status int) {
	if ctx.IsWebsocket() || strings.Contains(strings.ToLower(ctx.GetHeader("Connection")), "upgrade") {
		ctx.AbortWithStatus(status)
		return
	}
	ctx.AbortWithStatus(status)
}

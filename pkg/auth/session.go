package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"gakuren-system.com/pkg/db"
	"gakuren-system.com/pkg/helper"
	"gakuren-system.com/pkg/model"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

var ErrSession = errors.New("invalid or expired session")
var ErrRotated = errors.New("refresh token already rotated")

type SessionData struct {
	Token      map[string]interface{} `json:"token"`
	UserData   *model.LoginData       `json:"user_data"`
	TenantUUID string                 `json:"tenant_uuid"`
	SchoolUUID string                 `json:"school_uuid"`
	Menu       map[string]interface{} `json:"menu"`
}

func tokenHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func lifetime(name string, fallback, maximum int) time.Duration {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil || n <= 0 {
		n = fallback
	}
	if n > maximum {
		n = maximum
	}
	return time.Duration(n)
}

func sessionData(email string) (*SessionData, error) {
	user, err := GetLoginDataByEmail(email)
	if err != nil {
		return nil, err
	}
	/* permissions, err := helper.GetUserRolePermissionCodeList(user.UUID.String())
	if err != nil {
		return nil, err
	} */
	menu, err := helper.UserMenuIntegeration(user.UUID.String())
	if err != nil {
		return nil, err
	}

	return &SessionData{UserData: user, TenantUUID: user.TenantUUID.String(), SchoolUUID: user.SchoolUUID.String(), Menu: menu}, nil
}

// Each login creates an independent device session. Rotation consumes a token
// once; a competing tab receives 409 and must retry using the updated cookie.
func IssueSession(ctx context.Context, email, refresh string) (*SessionData, string, time.Time, error) {
	// Resolve metadata before reserving a transaction connection: metadata helpers
	// use the pool, so doing this while holding a connection can exhaust the pool.
	if refresh != "" {
		err := db.Conn.QueryRow(ctx, `SELECT u.email FROM user_sch.browser_refresh_token t
   JOIN user_sch.browser_session s ON s.uuid=t.session_uuid
   JOIN user_sch."user" u ON u.uuid=s.user_uuid
   WHERE t.token_hash=$1 AND s.revoke_date IS NULL AND s.expired_date>now()`, tokenHash(refresh)).Scan(&email)
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrSession
		}
		if err != nil {
			return nil, "", time.Time{}, err
		}
	}
	data, err := sessionData(email)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	tx, err := db.Conn.Begin(ctx)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	defer tx.Rollback(ctx)
	sid := uuid.NewString()
	expires := time.Now().Add(lifetime("REFRESH_TOKEN_DURATION", 30, 90) * 24 * time.Hour)
	var tenant, school, userID string
	if refresh != "" {
		var used *time.Time
		var revoked *time.Time
		err = tx.QueryRow(ctx, `SELECT s.uuid::text, s.user_uuid::text, s.tenant_uuid::text, s.school_uuid::text,
   s.expired_date, s.revoke_date, t.used_date, u.email
   FROM user_sch.browser_refresh_token t
   JOIN user_sch.browser_session s ON s.uuid=t.session_uuid
   JOIN user_sch."user" u ON u.uuid=s.user_uuid
   WHERE t.token_hash=$1 FOR UPDATE OF s, t`, tokenHash(refresh)).
			Scan(&sid, &userID, &tenant, &school, &expires, &revoked, &used, &email)
		if errors.Is(err, pgx.ErrNoRows) {
			err = ErrSession
		}
		if err != nil {
			return nil, "", time.Time{}, err
		}
		if revoked != nil || !expires.After(time.Now()) {
			return nil, "", time.Time{}, ErrSession
		}
		if used != nil {
			return nil, "", time.Time{}, ErrRotated
		}
	}
	if refresh != "" && (userID != data.UserData.UUID.String() || tenant != data.TenantUUID || school != data.SchoolUUID) {
		return nil, "", time.Time{}, ErrSession
	}
	now := time.Now()
	accessExpires := now.Add(lifetime("ACCESS_TOKEN_DURATION", 5, 15) * time.Minute)
	if expires.Before(accessExpires) {
		accessExpires = expires
	}

	permission := []string{}
	for _, v := range data.Menu {
		permission = append(permission, v.(map[string]interface{})["permission"].([]string)...)
	}

	claims := model.AccessTokenClaims{
		SessionID: sid, Username: email, TenantUUID: data.TenantUUID, SchoolUUID: data.SchoolUUID,
		Roles: []string{data.UserData.RoleName}, Permission: permission,
		RegisteredClaims: jwt.RegisteredClaims{ID: uuid.NewString(), Subject: data.UserData.UUID.String(),
			Issuer: os.Getenv("JWT_ISSUER"), Audience: jwt.ClaimStrings{os.Getenv("JWT_AUDIENCE")},
			ExpiresAt: jwt.NewNumericDate(accessExpires), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now)},
	}
	if JWTService == nil {
		return nil, "", time.Time{}, errors.New("JWT service not initialized")
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = os.Getenv("JWT_KEY_ID")
	signed, err := token.SignedString(JWTService.PrivateKey)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	bytes := make([]byte, 32)
	if _, err = rand.Read(bytes); err != nil {
		return nil, "", time.Time{}, err
	}
	raw := base64.RawURLEncoding.EncodeToString(bytes)
	if refresh == "" {
		_, err = tx.Exec(ctx, `INSERT INTO user_sch.browser_session(uuid,user_uuid,tenant_uuid,school_uuid,expired_date) VALUES($1,$2,$3,$4,$5)`, sid, data.UserData.UUID, data.TenantUUID, data.SchoolUUID, expires)
	} else {
		_, err = tx.Exec(ctx, `UPDATE user_sch.browser_refresh_token SET used_date=now() WHERE token_hash=$1`, tokenHash(refresh))
	}
	if err != nil {
		return nil, "", time.Time{}, err
	}
	_, err = tx.Exec(ctx, `INSERT INTO user_sch.browser_refresh_token(token_hash,session_uuid) VALUES($1,$2)`, tokenHash(raw), sid)
	if err != nil {
		return nil, "", time.Time{}, err
	}
	if refresh == "" {
		_, err = tx.Exec(ctx, `UPDATE user_sch.user_login SET last_login=now(),updated_date=now(),failed_attempt=0,
   status_uuid=(SELECT uuid FROM public.status WHERE lower(name)='logged in') WHERE username=$1`, email)
		if err != nil {
			return nil, "", time.Time{}, err
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, "", time.Time{}, err
	}
	data.Token = map[string]interface{}{"access_token": signed, "token_type": "bearer", "expired_in": int(time.Until(accessExpires).Seconds())}
	return data, raw, expires, nil
}

// Consumed tokens still identify their session for logout, including a logout
// racing with rotation. They can never mint another access token.
func RevokeSession(ctx context.Context, raw string) error {
	if raw == "" {
		return nil
	}
	_, err := db.Conn.Exec(ctx, `UPDATE user_sch.browser_session SET revoke_date=COALESCE(revoke_date,now())
  WHERE uuid=(SELECT session_uuid FROM user_sch.browser_refresh_token WHERE token_hash=$1)`, tokenHash(raw))
	return err
}

func ValidateAccessToken(raw string) (*model.AccessTokenClaims, error) {
	publicKey, err := helper.ParsePublicKey(os.Getenv("RSA_PUBLIC_KEY"))
	if err != nil {
		return nil, err
	}
	claims := new(model.AccessTokenClaims)
	token, err := jwt.ParseWithClaims(raw, claims, func(_ *jwt.Token) (interface{}, error) { return publicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(),
		jwt.WithIssuer(os.Getenv("JWT_ISSUER")), jwt.WithAudience(os.Getenv("JWT_AUDIENCE")))
	if err != nil {
		return nil, err
	}
	if !token.Valid || claims.Subject == "" || claims.SessionID == "" || claims.TenantUUID == "" || claims.SchoolUUID == "" {
		return nil, ErrSession
	}
	var active bool
	err = db.Conn.QueryRow(context.Background(), `SELECT EXISTS(
  SELECT 1 FROM user_sch.browser_session s JOIN user_sch."user" u ON u.uuid=s.user_uuid
  WHERE s.uuid=$1 AND s.user_uuid=$2 AND s.tenant_uuid=$3 AND s.school_uuid=$4
  AND u.tenant_uuid=s.tenant_uuid AND u.school_uuid=s.school_uuid
  AND s.revoke_date IS NULL AND s.expired_date>now())`,
		claims.SessionID, claims.Subject, claims.TenantUUID, claims.SchoolUUID).Scan(&active)
	if err != nil {
		return nil, err
	}
	if !active {
		return nil, ErrSession
	}
	return claims, nil
}

func BearerValue(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

// Package mcauth is a standalone Microsoft authentication library for
// Minecraft (Java Edition), ported from azalea-auth.
//
// Flow: device-code login (Microsoft) → Xbox Live → XSTS → login_with_xbox
// → profile. Everything is in-memory; the caller decides what to do with
// the result (e.g. marshal []CachedAccount to JSON for a launcher cache).
//
// Skins and capes are kept as json.RawMessage so their shape passes through
// untouched. No printing, no file I/O; show DeviceCode to the user yourself.
package mcauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// DefaultClientID is the Nintendo Switch client ID, which also works
	// for accounts under 18. https://minecraft.wiki/w/Microsoft_authentication
	DefaultClientID = "00000000441cc96b"
	// DefaultScope is the Xbox Live OAuth2 scope.
	DefaultScope = "service::user.auth.xboxlive.com::MBI_SSL"
)

// ErrLoginTimeout is returned by PollToken when the user never completes
// the Microsoft login before the device code expires.
var ErrLoginTimeout = errors.New("mcauth: microsoft login timed out")

// Client authenticates with Microsoft/Xbox/Minecraft services.
// HTTP, ClientID and Scope are optional; zero values get sane defaults.
type Client struct {
	HTTP     *http.Client
	ClientID string
	Scope    string
}

// Default returns a Client with a 30s-timeout HTTP client and default
// Microsoft OAuth2 credentials.
func Default() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

func (c *Client) http() *http.Client {
	if c != nil && c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) clientID() string {
	if c != nil && c.ClientID != "" {
		return c.ClientID
	}
	return DefaultClientID
}

func (c *Client) scope() string {
	if c != nil && c.Scope != "" {
		return c.Scope
	}
	return DefaultScope
}

// ExpiringValue wraps a token with its expiry as seconds since the Unix epoch.
type ExpiringValue[T any] struct {
	ExpiresAt uint64 `json:"expires_at"`
	Data      T      `json:"data"`
}

// IsExpired reports whether the value is past its expiry.
func (e ExpiringValue[T]) IsExpired() bool {
	return e.ExpiresAt < uint64(time.Now().Unix())
}

// Get returns the data, or nil if it is expired.
func (e ExpiringValue[T]) Get() *T {
	if e.IsExpired() {
		return nil
	}
	return &e.Data
}

func expiring[T any](data T, in uint64) ExpiringValue[T] {
	return ExpiringValue[T]{Data: data, ExpiresAt: uint64(time.Now().Unix()) + in}
}

// DeviceCode is shown to the user: open VerificationURI, enter UserCode.
type DeviceCode struct {
	UserCode        string `json:"user_code"`
	DeviceCode      string `json:"device_code"`
	VerificationURI string `json:"verification_uri"`
	ExpiresIn       uint64 `json:"expires_in"`
	Interval        uint64 `json:"interval"`
}

// AccessTokenResponse is a Microsoft (MSA) OAuth2 token pair.
type AccessTokenResponse struct {
	TokenType    string `json:"token_type"`
	ExpiresIn    uint64 `json:"expires_in"`
	Scope        string `json:"scope"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
}

// XboxLiveAuth is the Xbox Live token plus the user hash (uhs).
type XboxLiveAuth struct {
	Token    string `json:"token"`
	UserHash string `json:"user_hash"`
}

// MinecraftAuthResponse is the result of login_with_xbox.
type MinecraftAuthResponse struct {
	Username    string   `json:"username"`
	Roles       []string `json:"roles"`
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresIn   uint64   `json:"expires_in"`
}

// ProfileResponse is the Minecraft profile. Skins/capes keep their raw
// shape so new fields from Mojang pass through untouched.
type ProfileResponse struct {
	ID    string            `json:"id"`
	Name  string            `json:"name"`
	Skins []json.RawMessage `json:"skins"`
	Capes []json.RawMessage `json:"capes"`
}

// CachedAccount is the full login result. Marshal a []CachedAccount to get
// the launcher-style cache file (azalea-auth compatible on read).
type CachedAccount struct {
	CacheKey string                               `json:"cache_key"`
	MSA      ExpiringValue[AccessTokenResponse]   `json:"msa"`
	XBL      ExpiringValue[XboxLiveAuth]          `json:"xbl"`
	MCA      ExpiringValue[MinecraftAuthResponse] `json:"mca"`
	Profile  ProfileResponse                      `json:"profile"`
}

// UnmarshalJSON also accepts "email" as an alias for "cache_key"
// (azalea-auth writes "email" in older caches).
func (a *CachedAccount) UnmarshalJSON(b []byte) error {
	type raw CachedAccount
	var aux struct {
		raw
		Email string `json:"email"`
	}
	if err := json.Unmarshal(b, &aux); err != nil {
		return err
	}
	*a = CachedAccount(aux.raw)
	if a.CacheKey == "" {
		a.CacheKey = aux.Email
	}
	return nil
}

// MinecraftToken is the result of the Xbox → XSTS → Minecraft chain.
type MinecraftToken struct {
	MCA                  ExpiringValue[MinecraftAuthResponse]
	XBL                  ExpiringValue[XboxLiveAuth]
	MinecraftAccessToken string
}

// GetLinkCode starts the Microsoft device-code flow. Show the user
// VerificationURI + UserCode, then call PollToken.
func (c *Client) GetLinkCode(ctx context.Context) (DeviceCode, error) {
	var d DeviceCode
	err := c.postForm(ctx, "https://login.live.com/oauth20_connect.srf", url.Values{
		"scope":         {c.scope()},
		"client_id":     {c.clientID()},
		"response_type": {"device_code"},
	}, &d)
	return d, err
}

// PollToken waits until the user completes the Microsoft login, then
// returns the MSA token pair. It stops early if ctx is cancelled and
// gives up with ErrLoginTimeout once the device code expires.
func (c *Client) PollToken(ctx context.Context, d DeviceCode) (ExpiringValue[AccessTokenResponse], error) {
	interval := time.Duration(d.Interval) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	endpoint := "https://login.live.com/oauth20_token.srf?client_id=" + url.QueryEscape(c.clientID())

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ExpiringValue[AccessTokenResponse]{}, ctx.Err()
		case <-time.After(interval):
		}

		var tok AccessTokenResponse
		// While the user hasn't logged in yet Microsoft answers with an
		// error payload; that just decodes to an empty token, so keep polling.
		if err := c.postForm(ctx, endpoint, url.Values{
			"client_id":   {c.clientID()},
			"device_code": {d.DeviceCode},
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		}, &tok); err != nil {
			if ctx.Err() != nil {
				return ExpiringValue[AccessTokenResponse]{}, ctx.Err()
			}
			continue
		}
		if tok.AccessToken != "" {
			return expiring(tok, tok.ExpiresIn), nil
		}
	}
	return ExpiringValue[AccessTokenResponse]{}, ErrLoginTimeout
}

// RefreshToken exchanges an MSA refresh token for a fresh token pair.
func (c *Client) RefreshToken(ctx context.Context, refreshToken string) (ExpiringValue[AccessTokenResponse], error) {
	var tok AccessTokenResponse
	err := c.postForm(ctx, "https://login.live.com/oauth20_token.srf", url.Values{
		"scope":         {c.scope()},
		"client_id":     {c.clientID()},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}, &tok)
	if err != nil {
		return ExpiringValue[AccessTokenResponse]{}, err
	}
	return expiring(tok, tok.ExpiresIn), nil
}

// MinecraftToken runs the Xbox Live → XSTS → login_with_xbox chain for an
// MSA access token. Prepend "d=" to msaToken when using your own Azure app
// instead of the default client ID.
func (c *Client) MinecraftToken(ctx context.Context, msaToken string) (MinecraftToken, error) {
	xbl, err := c.xboxLive(ctx, msaToken)
	if err != nil {
		return MinecraftToken{}, err
	}
	xsts, err := c.xsts(ctx, xbl.Data.Token)
	if err != nil {
		return MinecraftToken{}, err
	}
	mca, err := c.minecraftLogin(ctx, xbl.Data.UserHash, xsts)
	if err != nil {
		return MinecraftToken{}, err
	}
	return MinecraftToken{
		MCA:                  mca,
		XBL:                  xbl,
		MinecraftAccessToken: mca.Data.AccessToken,
	}, nil
}

// GetProfile fetches the Minecraft profile (username, UUID, skins, capes).
func (c *Client) GetProfile(ctx context.Context, mcToken string) (ProfileResponse, error) {
	var p ProfileResponse
	err := c.get(ctx, "https://api.minecraftservices.com/minecraft/profile", mcToken, &p)
	return p, err
}

// CheckOwnership reports whether the account owns Minecraft. Vanilla also
// verifies signatures; like azalea-auth we just check the item list.
func (c *Client) CheckOwnership(ctx context.Context, mcToken string) (bool, error) {
	var res struct {
		Items []struct {
			Name      string `json:"name"`
			Signature string `json:"signature"`
		} `json:"items"`
	}
	if err := c.get(ctx, "https://api.minecraftservices.com/entitlements/mcstore", mcToken, &res); err != nil {
		return false, err
	}
	return len(res.Items) > 0, nil
}

type xboxLiveResponse struct {
	NotAfter      string                         `json:"NotAfter"`
	Token         string                         `json:"Token"`
	DisplayClaims map[string][]map[string]string `json:"DisplayClaims"`
}

func (c *Client) xboxLive(ctx context.Context, msaToken string) (ExpiringValue[XboxLiveAuth], error) {
	var res xboxLiveResponse
	err := c.postJSON(ctx, "https://user.auth.xboxlive.com/user/authenticate", map[string]any{
		"Properties": map[string]any{
			"AuthMethod": "RPS",
			"SiteName":   "user.auth.xboxlive.com",
			"RpsTicket":  msaToken,
		},
		"RelyingParty": "http://auth.xboxlive.com",
		"TokenType":    "JWT",
	}, "", &res)
	if err != nil {
		return ExpiringValue[XboxLiveAuth]{}, err
	}
	exp, err := time.Parse(time.RFC3339, res.NotAfter)
	if err != nil {
		return ExpiringValue[XboxLiveAuth]{}, fmt.Errorf("mcauth: invalid xbox expiry %q: %w", res.NotAfter, err)
	}
	var uhs string
	if claims := res.DisplayClaims["xui"]; len(claims) > 0 {
		uhs = claims[0]["uhs"]
	}
	if uhs == "" {
		return ExpiringValue[XboxLiveAuth]{}, errors.New("mcauth: xbox response has no user hash")
	}
	return ExpiringValue[XboxLiveAuth]{
		Data:      XboxLiveAuth{Token: res.Token, UserHash: uhs},
		ExpiresAt: uint64(exp.Unix()),
	}, nil
}

func (c *Client) xsts(ctx context.Context, xblToken string) (string, error) {
	var res xboxLiveResponse
	err := c.postJSON(ctx, "https://xsts.auth.xboxlive.com/xsts/authorize", map[string]any{
		"Properties": map[string]any{
			"SandboxId":  "RETAIL",
			"UserTokens": []string{xblToken},
		},
		"RelyingParty": "rp://api.minecraftservices.com/",
		"TokenType":    "JWT",
	}, "", &res)
	if err != nil {
		return "", err
	}
	return res.Token, nil
}

func (c *Client) minecraftLogin(ctx context.Context, userHash, xstsToken string) (ExpiringValue[MinecraftAuthResponse], error) {
	var res MinecraftAuthResponse
	err := c.postJSON(ctx, "https://api.minecraftservices.com/authentication/login_with_xbox", map[string]any{
		"identityToken": fmt.Sprintf("XBL3.0 x=%s;%s", userHash, xstsToken),
	}, "", &res)
	if err != nil {
		return ExpiringValue[MinecraftAuthResponse]{}, err
	}
	return expiring(res, res.ExpiresIn), nil
}

func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	return c.do(req, out)
}

func (c *Client) postJSON(ctx context.Context, endpoint string, body any, bearer string, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return c.do(req, out)
}

func (c *Client) get(ctx context.Context, endpoint, bearer string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	res, err := c.http().Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		body, _ := io.ReadAll(io.LimitReader(res.Body, 512))
		return fmt.Errorf("mcauth: %s: unexpected status %s: %s", req.URL.Host+req.URL.Path, res.Status, strings.TrimSpace(string(body)))
	}
	return json.NewDecoder(res.Body).Decode(out)
}

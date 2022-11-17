package hcaptcha

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"fmt"
	"net/http"
	"net/url"
)

type PostRes struct {
	Success bool `json:"success"`
	Msg string `json:"error"`
}

var (
	// ResponseContextKey is the default request's context key that response of a hcaptcha request is kept.
	ResponseContextKey interface{} = "hcaptcha"
	// DefaultFailureHandler is the default HTTP handler that is fired on hcaptcha failures. See `Client.FailureHandler`.
	DefaultFailureHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, _ := json.Marshal(PostRes{
			Success: false,
			Msg: "Captcha error.",
		})

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write(response)
	})

	// PostMaxMemory is the max memory for a form, defaults to 32MB
	PostMaxMemory int64 = 32 << 20
)

// Client represents the hcaptcha client.
// It contains the underline HTTPClient which can be modified before API calls.
type Client struct {
	HTTPClient *http.Client

	// FailureHandler if specified, fired when user does not complete hcaptcha successfully.
	// Failure and error codes information are kept as `Response` type
	// at the Request's Context key of "hcaptcha".
	//
	// Defaults to a handler that writes a status code of 429 (Too Many Requests)
	// and without additional information.
	FailureHandler http.Handler

	// Optional checks for siteverify
	// The user's IP address.
	RemoteIP string
	// The sitekey you expect to see.
	SiteKey string

	secret string
}

// Response is the hcaptcha JSON response.
type Response struct {
	ChallengeTS string   `json:"challenge_ts"`
	Hostname    string   `json:"hostname"`
	ErrorCodes  []string `json:"error-codes,omitempty"`
	Success     bool     `json:"success"`
	Credit      bool     `json:"credit,omitempty"`
}

type PostType struct {
	GeneratedResponseID string `json:"h-captcha-response"`
}

// New accepts a hpcatcha secret key and returns a new hcaptcha HTTP Client.
//
// Instructions at: https://docs.hcaptcha.com/.
//
// See its `Handler` and `SiteVerify` for details.
func New(secret string) *Client {
	return &Client{
		HTTPClient:     http.DefaultClient,
		FailureHandler: DefaultFailureHandler,
		secret:         secret,
	}
}

// Handler is the HTTP route middleware featured hcaptcha validation.
// It calls the `SiteVerify` method and fires the "next" when user completed the hcaptcha successfully,
//
//	otherwise it calls the Client's `FailureHandler`.
//
// The hcaptcha's `Response` (which contains any `ErrorCodes`)
// is saved on the Request's Context (see `GetResponseFromContext`).
func (c *Client) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := c.SiteVerify(r)
		r = r.WithContext(context.WithValue(r.Context(), ResponseContextKey, v))
		if v.Success {
			next.ServeHTTP(w, r)
			return
		}
		fmt.Println(r)
		if c.FailureHandler != nil {
			c.FailureHandler.ServeHTTP(w, r)
		}
	})
}

// HandlerFunc same as `Handler` but it accepts and returns a type of `http.HandlerFunc` instead.
func (c *Client) HandlerFunc(next func(http.ResponseWriter, *http.Request)) http.HandlerFunc {
	return c.Handler(http.HandlerFunc(next)).ServeHTTP
}

// responseFormValue = "h-captcha-response"
const apiURL = "https://hcaptcha.com/siteverify"

// SiteVerify accepts a "r" Request and a secret key (https://dashboard.hcaptcha.com/settings).
// It returns the hcaptcha's `Response`.
// The `response.Success` reports whether the validation passed.
// Any errors are passed through the `response.ErrorCodes` field.
func (c *Client) SiteVerify(r *http.Request) (response Response) {
	var req PostType
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		response.ErrorCodes = append(response.ErrorCodes, "Failed to decode request.")
		return
	}

	if req.GeneratedResponseID == "" {
		response.ErrorCodes = append(response.ErrorCodes,
			"h-captcha-response is empty")
		return
	}

	// Call VerifyToken for verification after extracting token
	// Check token before call to maintain backwards compatibility
	return c.VerifyToken(req.GeneratedResponseID)
}

// VerifyToken accepts a token and a secret key (https://dashboard.hcaptcha.com/settings).
// It returns the hcaptcha's `Response`.
// The `response.Success` reports whether the validation passed.
// Any errors are passed through the `response.ErrorCodes` field.
// Same as SiteVerify except token is provided by caller instead of being extracted from HTTP request
func (c *Client) VerifyToken(tkn string) (response Response) {
	if tkn == "" {
		response.ErrorCodes = append(response.ErrorCodes, errors.New("tkn is empty").Error())
		return
	}

	values := url.Values{
		"secret":   {c.secret},
		"response": {tkn},
	}

	// Add remoteIP if set
	if c.RemoteIP != "" {
		values.Add("remoteip", c.RemoteIP)
	}

	// Add sitekey if set
	if c.SiteKey != "" {
		values.Add("sitekey", c.SiteKey)
	}

	resp, err := c.HTTPClient.PostForm(apiURL, values)
	if err != nil {
		response.ErrorCodes = append(response.ErrorCodes, err.Error())
		return
	}

	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		response.ErrorCodes = append(response.ErrorCodes, err.Error())
		return
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		response.ErrorCodes = append(response.ErrorCodes, err.Error())
		return
	}

	return
}

// Get returns the hcaptcha `Response` of the current "r" request and reports whether was found or not.
func Get(r *http.Request) (Response, bool) {
	v := r.Context().Value(ResponseContextKey)
	if v != nil {
		if response, ok := v.(Response); ok {
			return response, true
		}
	}

	return Response{}, false
}
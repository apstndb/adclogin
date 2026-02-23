// adclogin: Standalone replacement for "gcloud auth application-default login".
//
// This is a Proof of Concept (PoC). Use at your own risk.
// See README.md for important disclaimers about account safety.

package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// OAuth Client ID / Secret from the Google Cloud SDK (Apache 2.0 licensed).
// These are not secret -- they are embedded in plain text in the publicly
// distributed SDK source. However, using them outside of the official SDK
// may cause Google to block requests or flag accounts.
const (
	defaultClientID     = "764086051850-6qr4p6gpi6hn506pt8ejuq83di341hur.apps.googleusercontent.com"
	defaultClientSecret = "d-FL95Q19q7MQmFpd7hHD0Ty"
)

var defaultScopes = []string{
	"openid",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/sqlservice.login",
}

const cloudPlatformScope = "https://www.googleapis.com/auth/cloud-platform"

const impersonationTokenURLTemplate = "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/%s:generateAccessToken"

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

var (
	flagScopes                    string
	flagClientIDFile              string
	flagQuotaProject              string
	flagDisableQuotaProject       bool
	flagImpersonateServiceAccount string
	flagNoBrowser                 bool
)

func init() {
	flag.StringVar(&flagScopes, "scopes", "",
		"Comma-separated OAuth scopes (cloud-platform is always required)")
	flag.StringVar(&flagClientIDFile, "client-id-file", "",
		"Path to a JSON file containing a custom OAuth Client ID (installed type)")
	flag.StringVar(&flagQuotaProject, "quota-project", "",
		"Quota project ID to write into the ADC file")
	flag.BoolVar(&flagDisableQuotaProject, "disable-quota-project", false,
		"Do not write a quota project to the ADC file")
	flag.StringVar(&flagImpersonateServiceAccount, "impersonate-service-account", "",
		"Service account email to impersonate (comma-separated list for delegation chain; last is the target)")
	flag.BoolVar(&flagNoBrowser, "no-browser", false,
		"Manual copy/paste flow -- does not open a browser")
}

// ---------------------------------------------------------------------------
// ADC JSON structures
// ---------------------------------------------------------------------------

type authorizedUserADC struct {
	ClientID       string `json:"client_id"`
	ClientSecret   string `json:"client_secret"`
	QuotaProjectID string `json:"quota_project_id,omitempty"`
	RefreshToken   string `json:"refresh_token"`
	Type           string `json:"type"`
}

type impersonatedServiceAccountADC struct {
	Delegates                      []string       `json:"delegates"`
	ServiceAccountImpersonationURL string         `json:"service_account_impersonation_url"`
	SourceCredentials              map[string]any `json:"source_credentials"`
	Type                           string         `json:"type"`
}

// ---------------------------------------------------------------------------
// Client ID file structures
// ---------------------------------------------------------------------------

type clientSecretFile struct {
	Installed *installedClient `json:"installed"`
}

type installedClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	AuthURI      string `json:"auth_uri"`
	TokenURI     string `json:"token_uri"`
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

func main() {
	flag.Parse()

	printWarning()

	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func printWarning() {
	fmt.Fprintln(os.Stderr, "WARNING: This tool is a Proof of Concept (PoC).")
	fmt.Fprintln(os.Stderr, "Using the default OAuth Client ID outside of the official Cloud SDK")
	fmt.Fprintln(os.Stderr, "may result in account restrictions or suspension.")
	fmt.Fprintln(os.Stderr, "Do not use this with your primary Google account.")
	fmt.Fprintln(os.Stderr)
}

func run() error {
	// ---- Resolve client ID / secret ----
	clientID, clientSecret, err := resolveClientCredentials()
	if err != nil {
		return err
	}

	if clientID == defaultClientID {
		fmt.Fprintln(os.Stderr,
			"Note: Using the default OAuth Client ID from the Google Cloud SDK.")
		fmt.Fprintln(os.Stderr,
			"      Supply your own via --client-id-file to avoid potential restrictions.")
		fmt.Fprintln(os.Stderr)
	}

	// ---- Resolve scopes ----
	scopes, err := resolveScopes()
	if err != nil {
		return err
	}

	// Impersonation: consent only needs cloud-platform; real scopes go into
	// the SA config.
	if flagImpersonateServiceAccount != "" {
		scopes = []string{cloudPlatformScope}
	}

	// ---- Run OAuth flow ----
	var tok *oauth2.Token
	if flagNoBrowser {
		tok, err = runOOBFlow(clientID, clientSecret, scopes)
	} else {
		tok, err = runBrowserFlow(clientID, clientSecret, scopes)
	}
	if err != nil {
		return err
	}
	if tok.RefreshToken == "" {
		return fmt.Errorf("no refresh token received; try revoking access at https://myaccount.google.com/permissions and running again")
	}

	// ---- Build ADC JSON ----
	adcObj, err := buildADC(clientID, clientSecret, tok)
	if err != nil {
		return err
	}

	// ---- Write ADC file ----
	adcPath, err := defaultADCFilePath()
	if err != nil {
		return fmt.Errorf("failed to determine ADC file path: %w", err)
	}
	if err := writeJSONFile(adcPath, adcObj); err != nil {
		return err
	}

	fmt.Printf("\nCredentials saved to file: [%s]\n", adcPath)
	fmt.Println("\nThese credentials will be used by any library that requests")
	fmt.Println("Application Default Credentials (ADC).")

	if flagImpersonateServiceAccount != "" {
		target, _ := parseImpersonationAccounts(flagImpersonateServiceAccount)
		fmt.Printf("\nService account impersonation is configured for: %s\n", target)
	}
	if qp := resolveQuotaProject(); qp != "" {
		fmt.Printf("\nQuota project \"%s\" was added to ADC which can be used by\n", qp)
		fmt.Println("Google client libraries for billing and quota.")
	}

	return nil
}

// ---------------------------------------------------------------------------
// Client credentials resolution
// ---------------------------------------------------------------------------

func resolveClientCredentials() (string, string, error) {
	if flagClientIDFile == "" {
		return defaultClientID, defaultClientSecret, nil
	}

	data, err := os.ReadFile(flagClientIDFile)
	if err != nil {
		return "", "", fmt.Errorf("cannot read client ID file %q: %w", flagClientIDFile, err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return "", "", fmt.Errorf("client ID file is not valid JSON: %w", err)
	}
	if len(raw) != 1 {
		return "", "", fmt.Errorf("expected a JSON object with a single property for an \"installed\" application")
	}
	if _, ok := raw["installed"]; !ok {
		for k := range raw {
			return "", "", fmt.Errorf("only client IDs of type 'installed' are allowed, but encountered type '%s'", k)
		}
	}

	var csf clientSecretFile
	if err := json.Unmarshal(data, &csf); err != nil {
		return "", "", fmt.Errorf("failed to parse client ID file: %w", err)
	}
	if csf.Installed == nil || csf.Installed.ClientID == "" {
		return "", "", fmt.Errorf("client ID file is missing the 'installed.client_id' field")
	}
	return csf.Installed.ClientID, csf.Installed.ClientSecret, nil
}

// ---------------------------------------------------------------------------
// Scope resolution
// ---------------------------------------------------------------------------

func resolveScopes() ([]string, error) {
	if flagScopes == "" {
		return defaultScopes, nil
	}

	scopes := strings.Split(flagScopes, ",")
	for i := range scopes {
		scopes[i] = strings.TrimSpace(scopes[i])
	}

	hasCloudPlatform := false
	for _, s := range scopes {
		if s == cloudPlatformScope {
			hasCloudPlatform = true
			break
		}
	}
	if !hasCloudPlatform {
		return nil, fmt.Errorf("%s scope is required but not requested; please include it in --scopes", cloudPlatformScope)
	}
	return scopes, nil
}

// ---------------------------------------------------------------------------
// Impersonation account parsing
// ---------------------------------------------------------------------------

func parseImpersonationAccounts(accountList string) (targetPrincipal string, delegates []string) {
	parts := strings.Split(accountList, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) == 0 {
		return "", nil
	}
	targetPrincipal = parts[len(parts)-1]
	if len(parts) > 1 {
		delegates = parts[:len(parts)-1]
	}
	return
}

// ---------------------------------------------------------------------------
// Quota project resolution
// ---------------------------------------------------------------------------

func resolveQuotaProject() string {
	if flagDisableQuotaProject {
		return ""
	}
	return flagQuotaProject
}

// ---------------------------------------------------------------------------
// ADC JSON construction
// ---------------------------------------------------------------------------

func buildADC(clientID, clientSecret string, tok *oauth2.Token) (any, error) {
	userADC := authorizedUserADC{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RefreshToken: tok.RefreshToken,
		Type:         "authorized_user",
	}

	if flagImpersonateServiceAccount == "" {
		userADC.QuotaProjectID = resolveQuotaProject()
		return userADC, nil
	}

	targetPrincipal, delegates := parseImpersonationAccounts(flagImpersonateServiceAccount)

	sourceMap := map[string]any{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"refresh_token": tok.RefreshToken,
		"type":          "authorized_user",
	}

	impersonatedADC := impersonatedServiceAccountADC{
		Delegates:                      delegates,
		ServiceAccountImpersonationURL: fmt.Sprintf(impersonationTokenURLTemplate, targetPrincipal),
		SourceCredentials:              sourceMap,
		Type:                           "impersonated_service_account",
	}
	if impersonatedADC.Delegates == nil {
		impersonatedADC.Delegates = []string{}
	}

	return impersonatedADC, nil
}

// ---------------------------------------------------------------------------
// Browser-based OAuth flow (default)
// ---------------------------------------------------------------------------

func runBrowserFlow(clientID, clientSecret string, scopes []string) (*oauth2.Token, error) {
	listener, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, fmt.Errorf("failed to listen on localhost: %w", err)
	}
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("unexpected listener address type: %T", listener.Addr())
	}
	port := tcpAddr.Port
	redirectURL := fmt.Sprintf("http://localhost:%d", port)

	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       scopes,
		RedirectURL:  redirectURL,
	}

	state, err := randomState()
	if err != nil {
		return nil, err
	}

	type result struct {
		code string
		err  error
	}
	ch := make(chan result, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("state") != state {
			ch <- result{err: fmt.Errorf("state mismatch")}
			http.Error(w, "State mismatch", http.StatusBadRequest)
			return
		}
		if errMsg := r.URL.Query().Get("error"); errMsg != "" {
			ch <- result{err: fmt.Errorf("authorization error: %s", errMsg)}
			http.Error(w, "Authorization failed: "+errMsg, http.StatusBadRequest)
			return
		}
		code := r.URL.Query().Get("code")
		if code == "" {
			ch <- result{err: fmt.Errorf("no code in callback")}
			http.Error(w, "No authorization code received", http.StatusBadRequest)
			return
		}
		ch <- result{code: code}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintln(w, "<html><body><h2>Authorization successful!</h2><p>You can close this tab.</p></body></html>")
	})

	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(listener) }()
	defer srv.Close()

	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
	fmt.Println("Your browser has been opened to visit:\n")
	fmt.Println("   ", authURL)
	fmt.Println()
	if err := openBrowser(authURL); err != nil {
		fmt.Println("If your browser did not open, please visit the URL above manually.")
	}

	res := <-ch
	if res.err != nil {
		return nil, fmt.Errorf("authorization failed: %w", res.err)
	}

	tok, err := oauthCfg.Exchange(context.Background(), res.code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	return tok, nil
}

// ---------------------------------------------------------------------------
// Manual copy/paste OAuth flow (--no-browser)
// ---------------------------------------------------------------------------

func runOOBFlow(clientID, clientSecret string, scopes []string) (*oauth2.Token, error) {
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     google.Endpoint,
		Scopes:       scopes,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
	}

	state, err := randomState()
	if err != nil {
		return nil, err
	}

	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("prompt", "consent"),
	)
	fmt.Println("Go to the following link in your browser:\n")
	fmt.Println("   ", authURL)
	fmt.Println()
	fmt.Print("Enter authorization code: ")

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, fmt.Errorf("failed to read authorization code: %w", err)
	}
	code = strings.TrimSpace(code)

	tok, err := oauthCfg.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	return tok, nil
}

// ---------------------------------------------------------------------------
// ADC file path (well-known location)
// ---------------------------------------------------------------------------

func defaultADCFilePath() (string, error) {
	if dir := os.Getenv("CLOUDSDK_CONFIG"); dir != "" {
		return filepath.Join(dir, "application_default_credentials.json"), nil
	}
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData == "" {
			appData = filepath.Join(os.Getenv("SystemDrive"), "\\")
		}
		return filepath.Join(appData, "gcloud", "application_default_credentials.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "gcloud", "application_default_credentials.json"), nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeJSONFile(path string, v any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("failed to write file: %w", err)
	}
	return nil
}

func randomState() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", b), nil
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "linux", "android":
		if _, err := exec.LookPath("termux-open"); err == nil {
			return exec.Command("termux-open", url).Start()
		}
		return exec.Command("xdg-open", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
}

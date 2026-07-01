package exprruntime

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	azureStorageVersion   = "2023-11-03"
	azureAppConfigVersion = "1.0"
)

var azureTenantPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$`)

func azureNamespace(rt *runtimeBindings) map[string]any {
	return map[string]any{
		"validateStorage":          rt.azureValidateStorage,
		"validateServicePrincipal": rt.azureValidateServicePrincipal,
		"validateAppConfig":        rt.azureValidateAppConfig,
		"validateServiceBusSAS":    rt.azureValidateServiceBusSAS,
	}
}

type azureStorageListResponse struct {
	Containers []struct {
		Name string `xml:"Name"`
	} `xml:"Containers>Container"`
}

type azureErrorResponse struct {
	Code    string `xml:"Code"`
	Message string `xml:"Message"`
}

func (rt *runtimeBindings) azureValidateStorage(account, accountKey string) map[string]any {
	e := rt.validation
	if e == nil {
		e, _ = New(nil)
	}
	account = strings.TrimSpace(account)
	accountKey = strings.TrimSpace(accountKey)
	if account == "" || accountKey == "" {
		return azureInputError("missing_storage_account_or_key")
	}

	now := time.Now().UTC().Format(http.TimeFormat)
	endpoint := fmt.Sprintf("https://%s.blob.core.windows.net/?comp=list", account)
	if e.AzureStorageEndpoint != "" {
		endpoint = e.AzureStorageEndpoint
	}
	canonHeaders := fmt.Sprintf("x-ms-date:%s\nx-ms-version:%s\n", now, azureStorageVersion)
	stringToSign := fmt.Sprintf("GET\n\n\n\n\n\n\n\n\n\n\n\n%s/%s/\ncomp:list", canonHeaders, account)
	signature, err := azureHMACBase64(accountKey, stringToSign)
	if err != nil {
		return azureInputError(err.Error())
	}

	req, err := http.NewRequestWithContext(rt.ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return map[string]any{"status": int64(0), "error_message": err.Error()}
	}
	req.Header.Set("x-ms-date", now)
	req.Header.Set("x-ms-version", azureStorageVersion)
	req.Header.Set("Authorization", fmt.Sprintf("SharedKey %s:%s", account, signature))

	body, resp, result := rt.azureDo(e, req)
	if result != nil {
		return result
	}
	out := map[string]any{"status": int64(resp.StatusCode), "account": account}
	if resp.StatusCode == http.StatusOK {
		var parsed azureStorageListResponse
		if err := xml.Unmarshal(body, &parsed); err == nil {
			containers := make([]any, 0, len(parsed.Containers))
			for _, c := range parsed.Containers {
				containers = append(containers, c.Name)
			}
			out["containers"] = containers
		}
	} else {
		azureAddXMLError(out, body)
	}
	return out
}

func (rt *runtimeBindings) azureValidateServicePrincipal(tenantID, clientID, clientSecret string) map[string]any {
	e := rt.validation
	if e == nil {
		e, _ = New(nil)
	}
	tenantID = strings.TrimSpace(tenantID)
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return azureInputError("missing_service_principal_fields")
	}
	if !azureTenantPattern.MatchString(tenantID) {
		return azureInputError("invalid_tenant_id")
	}

	endpoint := fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token", url.PathEscape(tenantID))
	if e.AzureTokenEndpoint != "" {
		endpoint = e.AzureTokenEndpoint
	}
	form := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"grant_type":    {"client_credentials"},
		"scope":         {"https://management.azure.com/.default"},
	}
	body := form.Encode()
	req, err := http.NewRequestWithContext(rt.ctx, http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		return map[string]any{"status": int64(0), "error_message": err.Error()}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	respBody, resp, result := rt.azureDo(e, req)
	if result != nil {
		return result
	}
	out := map[string]any{"status": int64(resp.StatusCode), "tenant_id": tenantID, "client_id": clientID}
	azureAddJSONError(out, respBody)
	var parsed map[string]any
	if resp.StatusCode == http.StatusOK && json.Unmarshal(respBody, &parsed) == nil {
		if _, ok := parsed["access_token"].(string); !ok {
			out["status"] = int64(0)
			out["error_code"] = "missing_access_token"
		}
	}
	return out
}

func (rt *runtimeBindings) azureValidateAppConfig(endpoint, id, secret string) map[string]any {
	e := rt.validation
	if e == nil {
		e, _ = New(nil)
	}
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	id = strings.TrimSpace(id)
	secret = strings.TrimSpace(secret)
	if endpoint == "" || id == "" || secret == "" {
		return azureInputError("missing_app_config_fields")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return azureInputError("invalid_app_config_endpoint")
	}
	reqURL := endpoint + "/kv?api-version=" + azureAppConfigVersion
	signHost := u.Host
	signPath := "/kv?api-version=" + azureAppConfigVersion
	if e.AzureAppConfigEndpoint != "" {
		reqURL = e.AzureAppConfigEndpoint
		overrideURL, err := url.Parse(reqURL)
		if err != nil || overrideURL.Host == "" {
			return azureInputError("invalid_app_config_endpoint")
		}
		signHost = overrideURL.Host
		signPath = overrideURL.EscapedPath()
		if signPath == "" {
			signPath = "/"
		}
		if overrideURL.RawQuery != "" {
			signPath += "?" + overrideURL.RawQuery
		}
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	contentHash := base64.StdEncoding.EncodeToString(sha256.New().Sum(nil))
	stringToSign := fmt.Sprintf("GET\n%s\n%s;%s;%s", signPath, date, signHost, contentHash)
	signature, err := azureHMACBase64(secret, stringToSign)
	if err != nil {
		return azureInputError(err.Error())
	}

	req, err := http.NewRequestWithContext(rt.ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return map[string]any{"status": int64(0), "error_message": err.Error()}
	}
	req.Host = signHost
	req.Header.Set("Date", date)
	req.Header.Set("x-ms-content-sha256", contentHash)
	req.Header.Set("Authorization", fmt.Sprintf("HMAC-SHA256 Credential=%s&SignedHeaders=date;host;x-ms-content-sha256&Signature=%s", id, signature))

	body, resp, result := rt.azureDo(e, req)
	if result != nil {
		return result
	}
	out := map[string]any{"status": int64(resp.StatusCode), "endpoint": endpoint, "id": id}
	azureAddJSONError(out, body)
	return out
}

func (rt *runtimeBindings) azureValidateServiceBusSAS(connectionString string) map[string]any {
	e := rt.validation
	if e == nil {
		e, _ = New(nil)
	}
	fields := parseAzureConnectionString(connectionString)
	endpoint, keyName, key := fields["endpoint"], fields["sharedaccesskeyname"], fields["sharedaccesskey"]
	if endpoint == "" || keyName == "" || key == "" {
		return azureInputError("missing_servicebus_connection_fields")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return azureInputError("invalid_servicebus_endpoint")
	}
	host := u.Host
	path := strings.Trim(fields["entitypath"], "/")
	resourceURI := fmt.Sprintf("https://%s", host)
	reqURL := fmt.Sprintf("https://%s/", host)
	if path != "" {
		resourceURI = fmt.Sprintf("https://%s/%s", host, url.PathEscape(path))
		reqURL = resourceURI + "?api-version=2017-04"
	} else {
		reqURL = fmt.Sprintf("https://%s/$Resources/Queues?api-version=2021-05", host)
	}
	if e.AzureServiceBusEndpoint != "" {
		reqURL = e.AzureServiceBusEndpoint
		overrideURL, err := url.Parse(reqURL)
		if err != nil || overrideURL.Host == "" {
			return azureInputError("invalid_servicebus_endpoint")
		}
		overrideURL.RawQuery = ""
		overrideURL.Fragment = ""
		resourceURI = overrideURL.String()
	}
	auth, err := azureSASToken(resourceURI, keyName, key, time.Now().Add(5*time.Minute).Unix())
	if err != nil {
		return azureInputError(err.Error())
	}
	req, err := http.NewRequestWithContext(rt.ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return map[string]any{"status": int64(0), "error_message": err.Error()}
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/atom+xml, application/json")

	body, resp, result := rt.azureDo(e, req)
	if result != nil {
		return result
	}
	out := map[string]any{"status": int64(resp.StatusCode), "host": host}
	if path != "" {
		out["entity_path"] = path
	}
	azureAddXMLError(out, body)
	azureAddJSONError(out, body)
	return out
}

func parseAzureConnectionString(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ";") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
	}
	return out
}

func azureHMACBase64(base64Key, message string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(base64Key)
	if err != nil {
		return "", fmt.Errorf("invalid_base64_key")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(message))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}

func azureSASToken(resourceURI, keyName, base64Key string, expiry int64) (string, error) {
	encodedURI := strings.ToLower(url.QueryEscape(resourceURI))
	toSign := encodedURI + "\n" + fmt.Sprintf("%d", expiry)
	// Service Bus/Event Hub SAS signs the SharedAccessKey text as supplied.
	mac := hmac.New(sha256.New, []byte(base64Key))
	_, _ = mac.Write([]byte(toSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return fmt.Sprintf("SharedAccessSignature sr=%s&sig=%s&se=%d&skn=%s",
		encodedURI,
		url.QueryEscape(signature),
		expiry,
		url.QueryEscape(keyName),
	), nil
}

func (rt *runtimeBindings) azureDo(e *Runtime, req *http.Request) ([]byte, *http.Response, map[string]any) {
	resp, err := e.client.Do(req)
	if err != nil {
		if isAzureNXDomain(err) {
			return nil, nil, map[string]any{"status": int64(404), "error_code": "NXDOMAIN", "error_message": err.Error()}
		}
		return nil, nil, map[string]any{"status": int64(0), "error_message": err.Error()}
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, resp, map[string]any{"status": int64(resp.StatusCode), "error_message": err.Error()}
	}
	rt.captureDebug(req.Method, req.URL.String(), "", req, resp, body)
	return body, resp, nil
}

func isAzureNXDomain(err error) bool {
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsNotFound
	}
	return strings.Contains(strings.ToLower(err.Error()), "no such host")
}

func azureInputError(code string) map[string]any {
	return map[string]any{"status": int64(400), "error_code": code}
}

func azureAddXMLError(out map[string]any, body []byte) {
	var parsed azureErrorResponse
	if err := xml.Unmarshal(body, &parsed); err != nil {
		return
	}
	if parsed.Code != "" {
		out["error_code"] = parsed.Code
	}
	if parsed.Message != "" {
		out["error_message"] = parsed.Message
	}
}

func azureAddJSONError(out map[string]any, body []byte) {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return
	}
	for _, key := range []string{"error", "code", "Code"} {
		if v, ok := parsed[key].(string); ok && v != "" {
			out["error_code"] = v
			break
		}
	}
	for _, key := range []string{"error_description", "message", "Message"} {
		if v, ok := parsed[key].(string); ok && v != "" {
			out["error_message"] = v
			break
		}
	}
}

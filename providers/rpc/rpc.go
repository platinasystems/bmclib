package rpc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/bmc-toolbox/bmclib/v2/providers"
	"github.com/go-logr/logr"
	"github.com/jacobweinstock/registrar"
)

const (
	// ProviderName for the RPC implementation.
	ProviderName = "rpc"
	// ProviderProtocol for the rpc implementation.
	ProviderProtocol = "http"

	// defaults
	timestampHeader = "X-BMCLIB-Timestamp"
	signatureHeader = "X-BMCLIB-Signature"
	contentType     = "application/json"

	// SHA256 is the SHA256 algorithm.
	SHA256 Algorithm = "sha256"
	// SHA256Short is the short version of the SHA256 algorithm.
	SHA256Short Algorithm = "256"
	// SHA512 is the SHA512 algorithm.
	SHA512 Algorithm = "sha512"
	// SHA512Short is the short version of the SHA512 algorithm.
	SHA512Short Algorithm = "512"
)

// Features implemented by the RPC provider.
var Features = registrar.Features{
	providers.FeaturePowerSet,
	providers.FeaturePowerState,
	providers.FeatureBootDeviceSet,
}

// Algorithm is the type for HMAC algorithms.
type Algorithm string

// Secrets hold per algorithm slice secrets.
// These secrets will be used to create HMAC signatures.
type Secrets map[Algorithm][]string

// Signatures hold per algorithm slice of signatures.
type Signatures map[Algorithm][]string

// Provider defines the configuration for sending rpc notifications.
type Provider struct {
	// ConsumerURL is the URL where an rpc consumer/listener is running
	// and to which we will send and receive all notifications.
	ConsumerURL string
	// Host is the BMC ip address or hostname or identifier.
	Host string
	// Client is the http client used for all HTTP calls.
	Client *http.Client
	// Logger is the logger to use for logging.
	Logger logr.Logger
	// LogNotificationsDisabled determines whether responses from rpc consumer/listeners will be logged or not.
	LogNotificationsDisabled bool
	// Opts are the options for the rpc provider.
	Opts Opts

	// listenerURL is the URL of the rpc consumer/listener.
	listenerURL *url.URL
}

type Opts struct {
	// Request is the options used to create the rpc HTTP request.
	Request RequestOpts
	// Signature is the options used for adding an HMAC signature to an HTTP request.
	Signature SignatureOpts
	// HMAC is the options used to create a HMAC signature.
	HMAC HMACOpts
	// Experimental options.
	Experimental Experimental
}

type RequestOpts struct {
	// HTTPContentType is the content type to use for the rpc request notification.
	HTTPContentType string
	// HTTPMethod is the HTTP method to use for the rpc request notification.
	HTTPMethod string
	// StaticHeaders are predefined headers that will be added to every request.
	StaticHeaders http.Header
	// TimestampFormat is the time format for the timestamp header.
	TimestampFormat string
	// TimestampHeader is the header name that should contain the timestamp. Example: X-BMCLIB-Timestamp
	TimestampHeader string
}

type SignatureOpts struct {
	// HeaderName is the header name that should contain the signature(s). Example: X-BMCLIB-Signature
	HeaderName string
	// AppendAlgoToHeaderDisabled decides whether to append the algorithm to the signature header or not.
	// Example: X-BMCLIB-Signature becomes X-BMCLIB-Signature-256
	// When set to true, a header will be added for each algorithm. Example: X-BMCLIB-Signature-256 and X-BMCLIB-Signature-512
	AppendAlgoToHeaderDisabled bool
	// IncludedPayloadHeaders are headers whose values will be included in the signature payload. Example: X-BMCLIB-My-Custom-Header
	// All headers will be deduplicated.
	IncludedPayloadHeaders []string
}

type HMACOpts struct {
	// Hashes is a map of algorithms to a slice of hash.Hash (these are the hashed secrets). The slice is used to support multiple secrets.
	Hashes map[Algorithm][]hash.Hash
	// PrefixSigDisabled determines whether the algorithm will be prefixed to the signature. Example: sha256=abc123
	PrefixSigDisabled bool
	// Secrets are a map of algorithms to secrets used for signing.
	Secrets Secrets
}

type Experimental struct {
	// CustomRequestPayload must be in json.
	CustomRequestPayload []byte
	// DotPath is the path to where the bmclib RequestPayload{} will be embedded. For example: object.data.body
	DotPath string
}

// New returns a new Config containing all the defaults for the rpc provider.
func New(consumerURL string, host string, secrets Secrets) *Provider {
	// defaults
	c := &Provider{
		Host:        host,
		ConsumerURL: consumerURL,
		Client:      http.DefaultClient,
		Logger:      logr.Discard(),
		Opts: Opts{
			Request: RequestOpts{
				HTTPContentType: contentType,
				HTTPMethod:      http.MethodPost,
				TimestampFormat: time.RFC3339,
				TimestampHeader: timestampHeader,
			},
			Signature: SignatureOpts{
				HeaderName:             signatureHeader,
				IncludedPayloadHeaders: []string{},
			},
			HMAC: HMACOpts{
				Hashes:  map[Algorithm][]hash.Hash{},
				Secrets: secrets,
			},
			Experimental: Experimental{},
		},
	}

	if len(secrets) > 0 {
		c.Opts.HMAC.Hashes = CreateHashes(secrets)
	}

	return c
}

// Name returns the name of this rpc provider.
// Implements bmc.Provider interface
func (c *Provider) Name() string {
	return ProviderName
}

// Open a connection to the rpc consumer.
// For the rpc provider, Open means validating the Config and
// that communication with the rpc consumer can be established.
func (c *Provider) Open(ctx context.Context) error {
	// 1. validate consumerURL is a properly formatted URL.
	// 2. validate that we can communicate with the rpc consumer.
	u, err := url.Parse(c.ConsumerURL)
	if err != nil {
		return err
	}
	c.listenerURL = u
	testReq, err := http.NewRequestWithContext(ctx, c.Opts.Request.HTTPMethod, c.listenerURL.String(), nil)
	if err != nil {
		return err
	}
	// test that we can communicate with the rpc consumer.
	// and that it responses with the spec contract (Response{}).
	resp, err := c.Client.Do(testReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// Close a connection to the rpc consumer.
func (c *Provider) Close(_ context.Context) (err error) {
	return nil
}

// BootDeviceSet sends a next boot device rpc notification.
func (c *Provider) BootDeviceSet(ctx context.Context, bootDevice string, setPersistent, efiBoot bool) (ok bool, err error) {
	p := RequestPayload{
		ID:     int64(time.Now().UnixNano()),
		Host:   c.Host,
		Method: BootDeviceMethod,
		Params: BootDeviceParams{
			Device:     bootDevice,
			Persistent: setPersistent,
			EFIBoot:    efiBoot,
		},
	}
	rp, err := c.process(ctx, p)
	if err != nil {
		return false, err
	}
	if rp.Error != nil {
		return false, fmt.Errorf("error from rpc consumer: %v", rp.Error)
	}

	return true, nil
}

// PowerSet sets the power state of a BMC machine.
func (c *Provider) PowerSet(ctx context.Context, state string) (ok bool, err error) {
	switch strings.ToLower(state) {
	case "on", "off", "cycle":
		p := RequestPayload{
			ID:     int64(time.Now().UnixNano()),
			Host:   c.Host,
			Method: PowerSetMethod,
			Params: PowerSetParams{
				State: strings.ToLower(state),
			},
		}
		resp, err := c.process(ctx, p)
		if err != nil {
			return ok, err
		}
		if resp.Error != nil {
			return ok, fmt.Errorf("error from rpc consumer: %v", resp.Error)
		}

		return true, nil
	}

	return false, errors.New("requested power state is not supported")
}

// PowerStateGet gets the power state of a BMC machine.
func (c *Provider) PowerStateGet(ctx context.Context) (state string, err error) {
	p := RequestPayload{
		ID:     int64(time.Now().UnixNano()),
		Host:   c.Host,
		Method: PowerGetMethod,
	}
	resp, err := c.process(ctx, p)
	if err != nil {
		return "", err
	}
	if resp.Error != nil {
		return "", fmt.Errorf("error from rpc consumer: %v", resp.Error)
	}

	return resp.Result.(string), nil
}

// process is the main function for the roundtrip of rpc calls to the ConsumerURL.
func (c *Provider) process(ctx context.Context, p RequestPayload) (ResponsePayload, error) {
	// 1. create the HTTP request.
	// 2. create the signature payload.
	// 3. sign the signature payload.
	// 4. add signatures to the request as headers.
	// 5. request/response round trip.
	// 6. handle the response.
	req, err := c.createRequest(ctx, p)
	if err != nil {
		return ResponsePayload{}, err
	}

	// create the signature payload
	// get the body and reset it as readers can only be read once.
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return ResponsePayload{}, err
	}
	req.Body = io.NopCloser(bytes.NewBuffer(body))
	headersForSig := http.Header{}
	for _, h := range c.Opts.Signature.IncludedPayloadHeaders {
		if val := req.Header.Get(h); val != "" {
			headersForSig.Add(h, val)
		}
	}
	sigPay := createSignaturePayload(body, headersForSig)

	// sign the signature payload
	sigs, err := sign(sigPay, c.Opts.HMAC.Hashes, c.Opts.HMAC.PrefixSigDisabled)
	if err != nil {
		return ResponsePayload{}, err
	}

	// add signatures to the request as headers.
	for algo, keys := range sigs {
		if len(sigs) > 0 {
			h := c.Opts.Signature.HeaderName
			if !c.Opts.Signature.AppendAlgoToHeaderDisabled {
				h = fmt.Sprintf("%s-%s", h, algo.ToShort())
			}
			req.Header.Add(h, strings.Join(keys, ","))
		}
	}

	// request/response round trip.
	kvs := requestKVS(req)
	kvs = append(kvs, []interface{}{"host", c.Host, "method", p.Method, "consumerURL", c.ConsumerURL}...)
	if p.Params != nil {
		kvs = append(kvs, []interface{}{"params", p.Params}...)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		c.Logger.Error(err, "failed to send rpc notification", kvs...)
		return ResponsePayload{}, err
	}
	defer resp.Body.Close()

	// handle the response
	rp, err := c.handleResponse(resp, kvs)
	if err != nil {
		return ResponsePayload{}, err
	}

	return rp, nil
}

// Transformer implements the mergo interfaces for merging custom types.
func (c *Provider) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	switch typ {
	case reflect.TypeOf(logr.Logger{}):
		return func(dst, src reflect.Value) error {
			if dst.CanSet() {
				isZero := dst.MethodByName("GetSink")
				result := isZero.Call(nil)
				if result[0].IsNil() {
					dst.Set(src)
				}
			}
			return nil
		}
	}
	return nil
}

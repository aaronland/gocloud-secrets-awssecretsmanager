// Copyright 2019 The Go Cloud Development Kit
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package secretsmanager provides a secrets implementation backed by AWS Secrets Manager.
// Use OpenKeeper to construct a *secrets.Keeper.
//
// URLs
//
// For secrets.OpenKeeper, awskms registers for the scheme "awssecretsmanager".
// The default URL opener will use an AWS session with the default credentials
// and configuration; see https://docs.aws.amazon.com/sdk-for-go/api/aws/session/
// for more details.
// To customize the URL opener, or for more details on the URL format,
// see URLOpener.
// See https://gocloud.dev/concepts/urls/ for background information.
//
// As
//
// awskms exposes the following type for As:
//  - Error: awserr.Error
package awssecretsmanager

import (
	"context"
	"errors"
	"fmt"
	_ "log"
	"net/url"
	"path"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/client"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/google/wire"
	gcaws "gocloud.dev/aws"
	"gocloud.dev/gcerrors"
	// "gocloud.dev/internal/gcerr"
	"gocloud.dev/secrets"
)

func init() {
	secrets.DefaultURLMux().RegisterKeeper(Scheme, new(lazySessionOpener))
}

// Set holds Wire providers for this package.
var Set = wire.NewSet(
	wire.Struct(new(URLOpener), "ConfigProvider"),
	Dial,
)

// Dial gets an AWS Secrets Manager service client.
func Dial(p client.ConfigProvider) (*secretsmanager.SecretsManager, error) {
	if p == nil {
		return nil, errors.New("getting SecretsManager service: no AWS session provided")
	}
	return secretsmanager.New(p), nil
}

// lazySessionOpener obtains the AWS session from the environment on the first
// call to OpenKeeperURL.
type lazySessionOpener struct {
	init   sync.Once
	opener *URLOpener
	err    error
}

func (o *lazySessionOpener) OpenKeeperURL(ctx context.Context, u *url.URL) (*secrets.Keeper, error) {
	o.init.Do(func() {
		sess, err := gcaws.NewDefaultSession()
		if err != nil {
			o.err = err
			return
		}
		o.opener = &URLOpener{
			ConfigProvider: sess,
		}
	})
	if o.err != nil {
		return nil, fmt.Errorf("open keeper %v: %v", u, o.err)
	}
	return o.opener.OpenKeeperURL(ctx, u)
}

// Scheme is the URL scheme awskms registers its URLOpener under on secrets.DefaultMux.
const Scheme = "awssecretsmanager"

// URLOpener opens AWS Secrets Manager URLs like "awssecretsmanager://secretID".
//
// The URL Host + Path are used as the key ID, which can be in the form of an
// Amazon Resource Name (ARN), alias name, or alias ARN. See
// https://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html#find-cmk-id-arn
// for more details.
//
// See gocloud.dev/aws/ConfigFromURLParams for supported query parameters
// for overriding the aws.Session from the URL.
type URLOpener struct {
	// ConfigProvider must be set to a non-nil value.
	ConfigProvider client.ConfigProvider

	// Options specifies the options to pass to OpenKeeper.
	Options KeeperOptions
}

// OpenKeeperURL opens an AWS Secrets Manager Keeper based on u.
func (o *URLOpener) OpenKeeperURL(ctx context.Context, u *url.URL) (*secrets.Keeper, error) {
	configProvider := &gcaws.ConfigOverrider{
		Base: o.ConfigProvider,
	}
	overrideCfg, err := gcaws.ConfigFromURLParams(u.Query())
	if err != nil {
		return nil, fmt.Errorf("open keeper %v: %v", u, err)
	}
	configProvider.Configs = append(configProvider.Configs, overrideCfg)
	client, err := Dial(configProvider)
	if err != nil {
		return nil, err
	}
	return OpenKeeper(client, path.Join(u.Host, u.Path), &o.Options), nil
}

// OpenKeeper returns a *secrets.Keeper that uses AWS Secrets Manager.
// The key ID can be in the form of an Amazon Resource Name (ARN), alias
// name, or alias ARN. See
// https://docs.aws.amazon.com/kms/latest/developerguide/viewing-keys.html#find-cmk-id-arn
// for more details.
// See the package documentation for an example.
func OpenKeeper(client *secretsmanager.SecretsManager, keyID string, opts *KeeperOptions) *secrets.Keeper {

	return secrets.NewKeeper(&keeper{
		keyID:  keyID,
		client: client,
	})
}

type keeper struct {
	keyID  string
	client *secretsmanager.SecretsManager
}

// Decrypt decrypts the ciphertext into a plaintext.
func (k *keeper) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {

	result, err := k.client.GetSecretValue(&secretsmanager.GetSecretValueInput{
		SecretId: aws.String(string(k.keyID)),
	})

	if err != nil {
		return nil, err
	}

	return []byte(*result.SecretString), nil
}

// Encrypt encrypts the plaintext into a ciphertext.
func (k *keeper) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {

	result, err := k.client.PutSecretValue(&secretsmanager.PutSecretValueInput{
		SecretId:     aws.String(k.keyID),
		SecretString: aws.String(string(plaintext)),
		// ClientRequestToken: aws.String("..."),
	})
	if err != nil {
		return nil, err
	}
	return []byte(*result.ARN), nil
}

// Close implements driver.Keeper.Close.
func (k *keeper) Close() error { return nil }

// ErrorAs implements driver.Keeper.ErrorAs.
func (k *keeper) ErrorAs(err error, i interface{}) bool {
	e, ok := err.(awserr.Error)
	if !ok {
		return false
	}
	p, ok := i.(*awserr.Error)
	if !ok {
		return false
	}
	*p = e
	return true
}

// ErrorCode implements driver.ErrorCode.
func (k *keeper) ErrorCode(err error) gcerrors.ErrorCode {
	ae, ok := err.(awserr.Error)
	if !ok {
		return gcerrors.Unknown
		// return gcerr.Unknown
	}
	ec, ok := errorCodeMap[ae.Code()]
	if !ok {
		return gcerrors.Unknown
		// return gcerr.Unknown
	}
	return ec
}

var errorCodeMap = map[string]gcerrors.ErrorCode{
	secretsmanager.ErrCodeResourceNotFoundException: gcerrors.NotFound,
	secretsmanager.ErrCodeInvalidParameterException: gcerrors.Unknown,
	secretsmanager.ErrCodeInvalidRequestException:   gcerrors.Unknown,
	secretsmanager.ErrCodeDecryptionFailure:         gcerrors.Unknown,
	secretsmanager.ErrCodeInternalServiceError:      gcerrors.Internal,
	secretsmanager.ErrCodeLimitExceededException:    gcerrors.Unknown,
	secretsmanager.ErrCodeEncryptionFailure:         gcerrors.Unknown,
	secretsmanager.ErrCodeResourceExistsException:   gcerrors.Unknown,
}

// KeeperOptions controls Keeper behaviors.
// It is provided for future extensibility.
type KeeperOptions struct{}

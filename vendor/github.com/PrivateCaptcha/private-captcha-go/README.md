# Private Captcha for Go

![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/PrivateCaptcha/private-captcha-go) [![CI](https://github.com/PrivateCaptcha/private-captcha-go/actions/workflows/ci.yaml/badge.svg)](https://github.com/PrivateCaptcha/private-captcha-go/actions/workflows/ci.yaml)

Official Go client for Private Captcha API

<mark>Please check the [official documentation](https://docs.privatecaptcha.com/docs/integrations/go/) for the in-depth and up-to-date information.</mark>

## Quick Start

- Install `private-captcha-go` package from GitHub
	```bash
	go get -u github.com/PrivateCaptcha/private-captcha-go
	```
- Instantiate the `Client` and call `verify()` method
	```go
	import pc "github.com/PrivateCaptcha/private-captcha-go"
	
	client, err := pc.NewClient(pc.Configuration{APIKey: "pc_abcdef"})
	// ... handle err
	
	output, err := client.Verify(ctx, pc.VerifyInput{Solution: solution})
	// ... handle err
	
	if !output.OK() {
		fmt.Printf("Captcha verification failed. Error: %s", result.Error())
	}
	```
- Use `client.VerifyFunc()` middleware or `client.VerifyRequest()` helper to integrate with any HTTP framework

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues with this Go client, please open an issue on GitHub.

For Private Captcha service questions, visit [privatecaptcha.com](https://privatecaptcha.com).

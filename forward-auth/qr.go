package main

import (
	"encoding/base64"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// GenerateQRSVG returns an <img> tag with a base64-encoded PNG QR code.
// The name is kept for compatibility with existing callers in page.go.
func GenerateQRSVG(text string, px int) string {
	png, err := qrcode.Encode(text, qrcode.Medium, px)
	if err != nil {
		return fmt.Sprintf(`<p style="color:red">QR error: %s</p>`, err)
	}
	b64 := base64.StdEncoding.EncodeToString(png)
	return fmt.Sprintf(
		`<img src="data:image/png;base64,%s" width="%d" height="%d" alt="TOTP QR code">`,
		b64, px, px,
	)
}

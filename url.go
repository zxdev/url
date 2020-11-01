// MIT License
//
// Copyright (c) 2020 zxdev
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package url

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// URL parse and validate url with type detections for IP|IDNA
type URL struct {
	Host, Port, Path string
	IP, IDNA         bool
}

// String representation of the *URL components rebuit that will and
// always ensure a trailing slash is present when no path is present
func (u *URL) String() string {
	if len(u.Port) > 0 {
		return fmt.Sprintf("%s:%s/%s", u.Host, u.Port, u.Path)
	}
	return fmt.Sprintf("%s/%s", u.Host, u.Path)
}

// puny converts idna `âbc.com` to `xn--bc-oia.com`
var puny = idna.New(idna.MapForLookup(), idna.Transitional(true))
var scheme = [2]string{"http://", "https://"}

// EffectiveTLDPlusOne is a wrapper around public suffix version that
// will convert the u.Host to the EffectiveTLDPlusOne version safely
func (u *URL) EffectiveTLDPlusOne() (string, error) {
	if u.IP {
		return u.Host, nil
	}
	return publicsuffix.EffectiveTLDPlusOne(u.Host)
}

// Parse the url into consitituate parts. Set u.IP flag if
// hostname is IPv4|6 and u.IDNA flag when domain converted
func (u *URL) Parse(url string) bool {

	var idx int
	*u = URL{} // hard reset; avoid previous data

	// strip schemes
	for idx = 0; idx < len(scheme); idx++ {
		if len(url) > len(scheme[idx]) && strings.HasPrefix(strings.ToLower(url[:len(scheme[idx])]), scheme[idx]) {
			url = url[len(scheme[idx]):]
		}
	}

	// strip query segment
	if idx = strings.Index(url, "?"); idx > 0 {
		url = url[:idx-1]
	}

	// extract path segment
	if idx = strings.Index(url, "/"); idx > 0 {
		u.Path = url[idx+1:]
		url = url[:idx]
	}

	// standardize to lowercase
	url = strings.ToLower(url)

	// deal with IPv6 as a hostname
	if strings.HasPrefix(url, "[") { // IPv6
		if idx = strings.Index(url, "]:"); idx > -1 { // extract port
			u.Host, u.Port, u.IP = url[:idx+1], url[idx+2:], true
			return true
		}
		if strings.HasSuffix(url, "]") {
			u.Host, u.IP = url, true
			return true
		}
		return false
	}

	// extract port domain|IPv4
	if idx = strings.Index(url, ":"); idx > -1 {
		u.Port = url[idx+1:]
		url = url[:idx]
	}

	// detect IPv4 as a hostname
	if net.ParseIP(url) != nil {
		u.IP = true
		u.Host = url
		return true
	}

	// deal with any idna|punycode domains
	var err error
	if u.Host, err = puny.ToASCII(url); err != nil || len(u.Host) > 253 {
		*u = URL{}   // hard reset
		return false // bad domain name or idna|puny code conversion
	}
	if len(u.Host) != len(url) { // was converted
		u.IDNA = true
	}

	if !strings.ContainsAny(u.Host, ".:") {
		*u = URL{}   // hard reset
		return false // not domain|IPv4|IPv6
	}

	return true
}

// Parser reads off an io.Reader and returns a function that returns
// only valid domain|IPv4|IPv6 with the url.IP flag
func (u *URL) Parser(r io.Reader) func() (string, bool, error) {

	scanner := bufio.NewScanner(r)
	return func() (string, bool, error) {

		if scanner.Scan() {
			if u.Parse(scanner.Text()) {
				return u.Host, u.IP, nil
			}
		}

		return "", false, io.EOF
	}
}

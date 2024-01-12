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
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/zxdev/xxhash/v2"
	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// URL parse and validate url with type detection flags for IP|IDNA
type URL struct {
	Host, Port, Path, Page string
	IP, IDNA               bool
	noIDNA, ipv6           bool
}

// puny converts idna `âbc.com` to `xn--bc-oia.com`
var puny = idna.New(idna.MapForLookup(), idna.Transitional(true))

// NoIDNA flag toggle, turn off INDA transcoding; default:on
func (u *URL) NoIDNA() { u.IDNA = !u.IDNA }

// String representation of the *URL components rebuit that will and
// always ensure no trailing slash is present when no path is present
func (u *URL) String() string {

	var host = u.Host
	if len(u.Port) > 0 {
		if u.ipv6 {
			host = "[" + host + "]"
		}
		host += ":" + u.Port
	}

	var path string
	if len(u.Path) > 0 {
		path = u.Path
	}
	if len(u.Page) > 0 {
		path += "/" + u.Page
	}

	if len(path) == 0 {
		return host
	}

	return host + "/" + path
}

// Parse the url into consitituate parts. Set u.IP flag if
// hostname is IPv4|6 and u.IDNA flag when domain converted
func (u *URL) Parse(url string) bool {

	var idx int
	*u = URL{} // hard reset; avoid previous data

	// strip query fragment
	if idx = strings.Index(url, "#"); idx > 0 {
		url = url[:idx]
	}

	// strip query segment
	if idx = strings.Index(url, "?"); idx > 0 {
		url = url[:idx]
	}

	// strip schemes
	if idx = strings.Index(url, "://"); idx > -1 {
		url = url[idx+3:]
	}

	// extract path segment
	if idx = strings.Index(url, "/"); idx > 0 {
		u.Path = url[idx+1:]
		url = url[:idx]
	}

	// parse page or path
	if len(u.Path) > 0 {
		if idx = strings.LastIndex(u.Path, "/"); idx > -1 {
			if strings.ContainsAny(u.Path[idx:], ".-_") {
				u.Page = u.Path[idx+1:]
				u.Path = u.Path[:idx]
			}
		}
	}

	// standardize host to lowercase
	url = strings.ToLower(url)
	url = strings.TrimSpace(url)

	// flag for IPv6
	if u.IP = strings.Count(url, ":") > 1; u.IP {

		if idx = strings.Index(url, "]:"); idx > 0 { // extract port
			u.Port = url[idx+2:]
			if u.Port == "80" || u.Port == "443" {
				u.Port = ""
			}
			url = url[:idx]
		}
		if idx = strings.Index(url, "%"); idx > 0 {
			url = url[:idx] // remove zone id
		}
		u.Host = strings.Trim(url, "[]")
		u.ipv6 = true

		return true
	}

	// remove port
	if idx = strings.Index(url, ":"); idx > -1 { // extract port
		u.Port = url[idx+1:]
		if u.Port == "80" || u.Port == "443" {
			u.Port = ""
		}
		url = url[:idx]
	}

	// flag for IPv4
	if u.IP = net.ParseIP(url) != nil; u.IP {
		u.Host = url
		return true
	}

	// clean cannonical host names; dns
	url = strings.TrimSuffix(url, ".")

	// flag for idna|punycode domains
	if !u.IP && !u.noIDNA {
		var err error
		u.Host, err = puny.ToASCII(url)
		u.IDNA = err == nil && strings.HasPrefix(u.Host, "xn--")
	}

	// final validation check
	if len(u.Host) > 253 || !strings.ContainsAny(u.Host, ".:") {
		*u = URL{}   // hard reset
		return false // not domain|IPv4|IPv6
	}

	return true
}

/*

	url.URL convenience helper functions

*/

// HasPort reports if a port is present in the parser
func HasPort(u *URL) bool { return len(u.Port) > 0 }

// NoPort removes the port from the parser
func NoPort(u *URL) { u.Port = "" }

// HasWWW reports if a www label is present
func HasWWW(u *URL) bool { return strings.HasPrefix(u.Host, "www.") }

// NoWWW removes the www label from u.Host when present
func NoWWW(u *URL) { u.Host = strings.TrimPrefix(u.Host, "www.") }

// HasLabel reports if a www label is present
func HasLabel(u *URL) bool {
	if !u.IP {
		apex, err := EffectiveTLDPlusOne(u)
		return err == nil && len(apex) != len(u.Host)
	}
	return false
}

// NoLabel removes any label from u.Host when present convering to apex
func NoLabel(u *URL) {
	if !u.IP {
		apex, err := EffectiveTLDPlusOne(u)
		if err == nil && len(apex) != len(u.Host) {
			u.Host = apex
		}
	}
}

// HasPath reports is a path is present in the parser
func HasPath(u *URL) bool { return len(u.Path) > 0 }

// NoPath removes the path from the parser
func NoPath(u *URL) { u.Path = ""; u.Page = "" }

// HasPage reports is a page is present in the parser
func HasPage(u *URL) bool { return len(u.Page) > 0 }

// NoPage removes the page from the parser
func NoPage(u *URL) { u.Page = "" }

// EffectiveTLDPlusOne is a wrapper around public suffix version that
// will convert the u.Host to the eTLD+1 version
func EffectiveTLDPlusOne(u *URL) (string, error) {
	if u.IP {
		return u.Host, nil
	}
	return publicsuffix.EffectiveTLDPlusOne(u.Host)
}

// Segmentizer parses the host into the apex and labels
func Segmentizer(u *URL) (segment struct {
	Apex  string
	Label []string
}) {

	if !u.IP {
		segment.Apex, _ = EffectiveTLDPlusOne(u)
		segment.Label = strings.Split(strings.TrimSuffix(u.Host, segment.Apex), ".")
	}

	return
}

// IsPrivate vefifies that an ipv4/6 representation is not in a
// reserved range; supports url.URL, net.IP, and string types
func IsPrivate(ip interface{}) (ok bool) {

	switch v := ip.(type) {
	case URL:
		if !v.IP {
			return
		}
		ip = net.ParseIP(v.Host)
	case string: // convert
		ip = net.ParseIP(v)
	case net.IP:
	default: // unsupported type
		return
	}

	switch {
	case ip.(net.IP) == nil: // invalid ipv44/6 format
		return
	case ip.(net.IP).IsUnspecified(): // 0.0.0.0
	case ip.(net.IP).IsLoopback(): // 127.0.0.1
	case ip.(net.IP).IsPrivate():
		// according to RFC 1918 (IPv4 addresses)
		// and RFC 4193 (IPv6 addresses)
	default:
		return
	}

	return true

}

/*

	url.URL convenience parser

	var r io.Reader
	var u url.URL
	next := url.Parser(r)
	for next(&u) {
		fmt.Println(u.Host)
	}

*/

// Parser reads io.Reader and parses into *url.URL
func Parser(r io.Reader) func(u *URL) bool {
	scanner := bufio.NewScanner(r)
	return func(u *URL) bool {
		if !scanner.Scan() {
			return false
		}
		u.Parse(scanner.Text())
		return true
	}
}

/*

	url.URL convenience hasher functions
	to generate unique kind based keys

	xxhash64 based
	sha256 based


*/

// hash generator kind defination
const (
	Apex = iota
	Host
	Full
	FullNoPage
)

/*
	3 orig  sub.example.com/path
	3 apex  2883ba7dc9aa3289
	3 host  41e8219220802dab
	3 full  3d173d4e8fd04260
	3 full- 3d173d4e8fd04260
    ---
	4 orig  www.example.com/path/logo.jpg
	4 apex  2883ba7dc9aa3289
	4 host  774337343878322e
	4 full  878b29f974f5fa51
	4 full- 90fab2c6396b011a
*/

// FPHex64 generates a key based on the kind request
func FPHex64(u *URL, kind int) (key string, ok bool) {

	switch kind {
	case 0: // Apex
		if apex, err := EffectiveTLDPlusOne(u); err == nil && len(apex) > 0 {
			return fmt.Sprintf("%016x", xxhash.SSum(apex)), true
		}

	case 1: // Host
		if len(u.Host) > 0 {
			return fmt.Sprintf("%016x", xxhash.SSum(u.Host)), true
		}

	case 3: // FullNopage
		if len(u.Page) > 0 {
			page := u.Page
			u.Page = ""
			s := u.String() + "/"
			u.Page = page
			return fmt.Sprintf("%016x", xxhash.SSum(s)), true
		}
		fallthrough

	case 2: // Full
		if s := u.String(); len(s) > 0 {
			return fmt.Sprintf("%016x", xxhash.SSum(s)), true
		}

	}

	return
}

// FPMHex64 is a multiform xxhash64 fingerprint generator utility
func FPMHex64(u *URL) (fp struct{ Apex, Host, Full, FullNoPage string }) {

	fp.Apex, _ = FPHex64(u, 0)
	fp.Host, _ = FPHex64(u, 1)
	fp.Full, _ = FPHex64(u, 2)
	fp.FullNoPage, _ = FPHex64(u, 3)

	return
}

// FPUint64 generates a key based on the kind request
func FPUint64(u *URL, kind int) (key uint64, ok bool) {

	switch kind {
	case 0: // Apex
		if apex, err := EffectiveTLDPlusOne(u); err == nil && len(apex) > 0 {
			return xxhash.SSum(apex), true
		}

	case 1: // Host
		if len(u.Host) > 0 {
			return xxhash.SSum(u.Host), true
		}

	case 3: // FullNopage
		if len(u.Page) > 0 {
			page := u.Page
			u.Page = ""
			s := u.String() + "/"
			u.Page = page
			return xxhash.SSum(s), true
		}
		fallthrough

	case 2: // Full
		if s := u.String(); len(s) > 0 {
			return xxhash.SSum(s), true
		}
	}

	return
}

// FPMUint64 is a multiform xxhash64 fingerprint generator utility
func FPMUint64(u *URL) (fp struct{ Apex, Host, Full, FullNoPage uint64 }) {

	fp.Apex, _ = FPUint64(u, 0)
	fp.Host, _ = FPUint64(u, 1)
	fp.Full, _ = FPUint64(u, 2)
	fp.FullNoPage, _ = FPUint64(u, 3)

	return
}

/*
	3 orig  sub.example.com/path
	3 apex  a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947
	3 host  005c4a974d8b94af421206f9ef34efebab39a7a4d25a81723933892a1fdf2e31
	3 full  1921beef719a905c297c2fc29b7edd4a8773bdcce58b3ff47f572a8c51300a29
	3 full- 1921beef719a905c297c2fc29b7edd4a8773bdcce58b3ff47f572a8c51300a29
	---
	4 orig  www.example.com/path/logo.jpg
	4 apex  a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947
	4 host  80fc0fb9266db7b83f85850fa0e6548b6d70ee68c8b5b412f1deea6ebdef0404
	4 full  3569d91b9e814dc3f60542c1f801d5f1e769c554c5aa977a4105b1c6c37907c2
	4 full- 4138f765ee40d6e68fed6e7abd6978c4dacb7534cb0a39dcdb626c783a3ec330
*/

// FPHex256 is a sha256 fingerprint generator utility
func FPHex256(u *URL, kind int) (key string, ok bool) {

	h := sha256.New()

	switch kind {
	case 0: // Apex
		if apex, err := EffectiveTLDPlusOne(u); err == nil && len(apex) > 0 {
			h.Write([]byte(apex))
			return fmt.Sprintf("%064x", h.Sum(nil)), true
		}

	case 1: // Host
		if len(u.Host) > 0 {
			h.Write([]byte(u.Host))
			return fmt.Sprintf("%064x", h.Sum(nil)), true
		}

	case 3: // FullNopage
		if len(u.Page) > 0 {
			page := u.Page
			u.Page = ""
			s := u.String() + "/"
			u.Page = page
			h.Write([]byte(s))
			return fmt.Sprintf("%064x", h.Sum(nil)), true
		}
		fallthrough

	case 2: // Full
		if s := u.String(); len(s) > 0 {
			h.Write([]byte(s))
			return fmt.Sprintf("%064x", h.Sum(nil)), true
		}
	}

	return
}

// FPMHex256 is a multiform sha256 fingerprint generator utility
func FPMHex256(u *URL, kind int) (fp struct{ Apex, Host, Full, FullNoPage string }) {

	fp.Apex, _ = FPHex256(u, 0)
	fp.Host, _ = FPHex256(u, 1)
	fp.Full, _ = FPHex256(u, 2)
	fp.FullNoPage, _ = FPHex256(u, 3)

	return
}

// FPByte256 is a sha256 fingerpint generator utility
func FPByte256(u *URL, kind int) (key []byte, ok bool) {

	h := sha256.New()

	switch kind {
	case 0: // Apex
		if apex, err := EffectiveTLDPlusOne(u); err == nil && len(apex) > 0 {
			h.Write([]byte(apex))
			return h.Sum(nil), true
		}

	case 1: // Host
		if len(u.Host) > 0 {
			h.Write([]byte(u.Host))
			return h.Sum(nil), true
		}

	case 3: // FullNopage
		if len(u.Page) > 0 {
			page := u.Page
			u.Page = ""
			s := u.String() + "/"
			u.Page = page
			h.Write([]byte(s))
			return h.Sum(nil), true
		}
		fallthrough

	case 2: // Full
		if s := u.String(); len(s) > 0 {
			h.Write([]byte(s))
			return h.Sum(nil), true
		}
	}

	return
}

// FPMByte256 is a multiform sha256 fingerprint generator utility
func FPMByte256(u *URL, kind int) (fp struct{ Apex, Host, Full, FullNoPage []byte }) {

	fp.Apex, _ = FPByte256(u, 0)
	fp.Host, _ = FPByte256(u, 1)
	fp.Full, _ = FPByte256(u, 2)
	fp.FullNoPage, _ = FPByte256(u, 3)

	return
}

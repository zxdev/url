// MIT License
//
// Copyright (c) 2021 zxdev
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
// SOFTWARE.package url

import (
	"net"
)

// IsPrivate utility vefifies that an ip representation is not in a
// reserved IPv4 range; supports url.URL, net.IP, and string types
func IsPrivate(ip interface{}) (ok bool) {

	switch ip.(type) {
	case URL:
		ip = net.ParseIP(ip.(URL).Host).To4()
	case string: // convert
		ip = net.ParseIP(ip.(string)).To4()
	case net.IP:
	default: // unsupported type
		return
	}

	// validate IPv4 representation
	if ip.(net.IP) == nil {
		return
	}

	// https://en.wikipedia.org/wiki/Reserved_IP_addresses
	switch {
	case ip.(net.IP)[0] == 0:
	case ip.(net.IP)[0] == 10:
	case ip.(net.IP)[0] == 127:
	case ip.(net.IP)[0] == 169 && ip.(net.IP)[1] == 254:
	case ip.(net.IP)[0] == 172 && ip.(net.IP)[1] == 16:
	case ip.(net.IP)[0] == 192 && ip.(net.IP)[1] == 168:
	default:
		return
	}

	return true

}

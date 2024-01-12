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

package url_test

import (
	"bytes"
	"testing"

	"github.com/zxdev/url/v2"
	"github.com/zxdev/url/v2/safebrowsing"
)

var testSet = []string{
	"example.com",
	"http://example.com/",
	"sub.example.com",
	"sub.example.com/path",
	"www.example.com/path/logo.jpg",
	"www.example.com/path/level/logo.jpg",
	"www.example.com/path/level/legend-of-zelda",
	"www.example.com/path/level/legion_three",
	"www.example.com/path/page",
	"www.example.com/path/page/",
	"www.example.com/",
}

func TestURLs(t *testing.T) {

	u := new(url.URL)
	type testSet struct{ In, Out url.URL }
	for i, v := range []testSet{
		{In: url.URL{Host: ""}, Out: url.URL{}},
		{In: url.URL{Host: "http://"}, Out: url.URL{}},
		{In: url.URL{Host: "http://:1543"}, Out: url.URL{}},
		{In: url.URL{Host: "bad"}, Out: url.URL{}},
		{In: url.URL{Host: "bad."}, Out: url.URL{}},

		{In: url.URL{Host: "example.com"}, Out: url.URL{Host: "example.com"}},
		{In: url.URL{Host: "example.com:443/"}, Out: url.URL{Host: "example.com", Port: "443"}},
		{In: url.URL{Host: "example.com/path"}, Out: url.URL{Host: "example.com", Path: "path"}},
		{In: url.URL{Host: "example.com/path/logo.jpg"}, Out: url.URL{Host: "example.com", Path: "path", Page: "logo.jpg"}},
		{In: url.URL{Host: "bücher.example.com"}, Out: url.URL{Host: "xn--bcher-kva.example.com", IDNA: true}},

		{In: url.URL{Host: "10.10.10.10"}, Out: url.URL{Host: "10.10.10.10", IP: true}},
		{In: url.URL{Host: "acca::01f9"}, Out: url.URL{Host: "acca::01f9", IP: true}},
		{In: url.URL{Host: "[acca::01f9]"}, Out: url.URL{Host: "acca::01f9", IP: true}},

		{In: url.URL{Host: "10.10.10.10:454"}, Out: url.URL{Host: "10.10.10.10", Port: "454", IP: true}},
		{In: url.URL{Host: "10.10.10.10:454/path"}, Out: url.URL{Host: "10.10.10.10", Port: "454", Path: "path", IP: true}},

		{In: url.URL{Host: "HttP://[acca::01f9]:1500"}, Out: url.URL{Host: "acca::01f9", Port: "1500", IP: true}},
		{In: url.URL{Host: "HttP://[acca::01f9]:1500/path"}, Out: url.URL{Host: "acca::01f9", Port: "1500", Path: "path", IP: true}},
	} {
		u.Parse(v.In.Host)
		if u.Host != v.Out.Host || u.Port != v.Out.Port ||
			u.Path != v.Out.Path || u.Page != v.Out.Page ||
			u.IP != v.Out.IP || u.IDNA != v.Out.IDNA {
			t.Log("error on testSet row:", i+1)
			t.Log("parser", *u)
			t.Log("expect", v.Out)
			t.FailNow()
		}
		t.Log(i, u.String())
	}

}

func TestURL(t *testing.T) {

	var u url.URL
	for i, v := range testSet {
		u.Parse(v)
		t.Log(i, v, u.String())
	}

}

func TestFPHex256(t *testing.T) {
	var u url.URL
	for i, v := range testSet {
		u.Parse(v)
		t.Log(i, "orig ", v)

		//kind, fp256 := url.FPSha256()
		key, ok := url.FPHex256(&u, url.Apex)
		t.Log(i, "apex ", key, ok)
		key, ok = url.FPHex256(&u, url.Host)
		t.Log(i, "host ", key, ok)
		key, ok = url.FPHex256(&u, url.Full)
		t.Log(i, "full ", key, ok)
		key, ok = url.FPHex256(&u, url.FullNoPage)
		t.Log(i, "full-", key, ok)
		t.Log("---")
	}
}

func TestFPHex64(t *testing.T) {
	var u url.URL
	for i, v := range testSet {
		u.Parse(v)
		t.Log(i, "orig ", v)

		//kind, fp256 := url.FPSha256()
		key, ok := url.FPHex64(&u, url.Apex)
		t.Log(i, "apex ", key, ok)
		key, ok = url.FPHex64(&u, url.Host)
		t.Log(i, "host ", key, ok)
		key, ok = url.FPHex64(&u, url.Full)
		t.Log(i, "full ", key, ok)
		key, ok = url.FPHex64(&u, url.FullNoPage)
		t.Log(i, "full-", key, ok)
		t.Log("---")
	}
}

func TestParser(t *testing.T) {
	var buf bytes.Buffer
	for i := range testSet {
		buf.WriteString(testSet[i] + "\n")
	}
	var u url.URL
	next := url.Parser(&buf)
	for next(&u) {
		t.Log(u.Host)
	}
}

func TestSB(t *testing.T) {

	url, err := safebrowsing.ParseURL("a.example.com/path")
	t.Log(url.Host, err)
	t.Log(url.Hostname(), err)

	pattern, _ := safebrowsing.GeneratePatterns("a.b.c.example.comn/path/page")
	t.Log(pattern)

}

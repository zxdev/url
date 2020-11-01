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
	"testing"

	"github.com/zxdev/url"
)

func TestURL(t *testing.T) {

	u := new(url.URL)
	type testSet struct{ In, Out url.URL }
	for i, v := range []testSet{
		{In: url.URL{Host: "http://[acca::01f9]"}, Out: url.URL{Host: "[acca::01f9]", IP: true}},
		{In: url.URL{Host: "HttP://[acca::01f9]:1500"}, Out: url.URL{Host: "[acca::01f9]", Port: "1500", IP: true}},
		{In: url.URL{Host: "10.10.10.10"}, Out: url.URL{Host: "10.10.10.10", IP: true}},
		{In: url.URL{Host: "10.10.10.10:454"}, Out: url.URL{Host: "10.10.10.10", Port: "454", IP: true}},
		{In: url.URL{Host: "10.10.10:454"}, Out: url.URL{Host: "10.10.10", Port: "454", IP: false}},
		{In: url.URL{Host: "example.com"}, Out: url.URL{Host: "example.com"}},
		{In: url.URL{Host: "tiny.co"}, Out: url.URL{Host: "tiny.co"}},
		{In: url.URL{Host: "âbc.com"}, Out: url.URL{Host: "xn--bc-oia.com", IDNA: true}},
		{In: url.URL{Host: "http://"}, Out: url.URL{}},
		{In: url.URL{Host: "http://:1543"}, Out: url.URL{}},
		{In: url.URL{Host: ":8080"}, Out: url.URL{}},
		{In: url.URL{Host: "bad"}, Out: url.URL{}},
		{In: url.URL{Host: ""}, Out: url.URL{}},
	} {
		u.Parse(v.In.Host)
		if *u != v.Out {
			t.Log("error on testSet row:", i+1)
			t.Log(u.Host, u.Port, u.Path, u.IP, u.IDNA)
			t.Log(v.Out.String())
			t.FailNow()
		}
	}

}

func TestFingerprint(t *testing.T) {

	u := new(url.URL)
	u.Parse("www.example.com/path")
	for i, v := range url.Fingerprint(u) {
		t.Log(i, v.Host, v.FP)
	}
	// 0 www.example.com 80fc0fb9266db7b83f85850fa0e6548b6d70ee68c8b5b412f1deea6ebdef0404
	// 1 example.com a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947

}

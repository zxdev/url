
# url

The url package is a simple url standardizer that will parse a url into constituant parts and will set url.IP flag if/when the hostname is an IPv4|6 and sets the url.IDNA flag when domain converted to the punycode form from UTF-8 characters. Parse confirms host has the basic look of a host. The package also resets itself each time url.Parse("blah") is called. It also provides a safe and simple wrapper for extracting the public suffix based root hostnames. 

Note: It may be necessary to recompile the publicsuffix package periodically to keep it current since it uses an intenally compressed reference set.

```golang
var u url.URL
// ...
if u.Parse("http://blah.example.com/path/page?q=1#123") {
    // valid, use it
    if !u.IP {
        eTLD, _ := u.EffectiveTLDPlusOne()
        fmt.Println(u.Host,eTLD,u.IDNA)
    }
    fmt.Println(u.String())
}

// struct values after calling u.Parse(url)
//
// u.Host blah.example.com
// u.Path /path/page
// u.IP   false
// u.INDA false
// eTLD  example.com

fp := u.Fingerprint(u)
// fp[0].Host blah.example.com
// fp[0].FP   1cbec737f863e4922cee63cc2ebbfaafcd1cff8b790d8cfd2e6a5d550b648afa
// fp[1].Host example.com
// fp[1].FP   1790d8cfd2cbc2ebbfaafcdeec737f863e492d2cee63c6a5d550b648afacff8b

```

*Why not just use the net/url package?*

Because sometimes you just need to write your own package for brevity and for your own use cases as well as to get a little more useful information, so making something else work is just jankey, like always having to always check/add a protocol to get net/url to work for you is not a proper solution to ensure things just always work consistently, plus it's makes things alot more verbose.

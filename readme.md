
# url

The url package is a simple url standardizer that parses a url into constituant parts and will set url.IP or url.IDNA flag when detected. Parse generally confirms the hostname has the basic elements required for domain or an IPv4/6 address.

Convenience helper functions are provided for simple boolean tests along with simple extractions or manipulations. A convenience Parser method reads off an io.Reader source and populates the passed in *url.URL and unique key generator for standardizing to 64-bit or 256-bit based a stated kind format requested.

The safebrowsing package contains the urls.go package extracted from ```google/safebrowsing``` for safebrowsing standardization and validation to help with malicious spoofing attemts. It does not include the hasher package.

```golang

    // convienence helper example
    var u url.URL
    u.Parse("example.com/path/logo.jpg")
    if url.HasPage(u) {
        url.NoPage(u)
    }

    // convienence parser example
	r, _ := os.Open("my/file")
	defer r.Close()
    var u url.URL
	next := url.Parser(r)
	for next(&u) {
		fmt.Println(u.Host)
	}
    
    // unique key generator example
    u.Parse("sub.example.com/path")
    FPHex64(u,url.Apex) // 2883ba7dc9aa3289
    FPHex64(u,url.Host) // 41e8219220802dab
    FPHex64(u,url.Full) // 3d173d4e8fd04260

    // safebrowsing stanadardization example that converts
    // alternative ipv4 format to ipv4 dot notation
    url, _ := safebrowsing.ParseURL("991234565/path/page")
	fmt.Println(url) // http://59.21.10.5/path/page


```

Note: It may be necessary to recompile or refresh the ```golang/x/net/publicsuffix``` package periodically to keep it current since it uses an intenally compressed reference set.


# Node WHOIS

[![Build Status](https://drone.io/github.com/hjr265/node-whois/status.png)](https://drone.io/github.com/hjr265/node-whois/latest)

Node-WHOIS is a WHOIS client for Node.js.

# Changes:
* Removed CoffeeScript, which I find has less legibility than "normal" JS.
* Keeps the same API, usage, and examples*.
* \* Some examples were removed that no longer work due to the whois provider (ripe.net).
* Removed Mocha and Coffee-script from required packages (Mocha should be installed globally if you are testing).

## Installation

### Global

    $ npm install -g whois

#### CLI Usage

    whois [options] address

    Options:
      -s, --server   whois server                         [default: null]
      -f, --follow   number of times to follow redirects  [default: 0]
      -p, --proxy    SOCKS proxy                          [default: null]
      -v, --verbose  show verbose results                 [default: false]
      -b, --bind     bind to a local IP address           [default: null]
      -h, --help     display this help message            [default: false]

### Local

    $ npm install whois

#### Usage

```js
const whois = require('whois');
whois.lookup('google.com', (err, data) => {
    if(err) {
        handleError();
    }
	console.log(data);
})
```

You may also use Promises using ``util.promisify``!
```js
const $whois = require('whois');
const { promisify } = require('util');
const whois = promisify($whois.lookup);

whois('google.com')
    .then(data => console.log(data));

(async () => {
    const data = await whois('google.com');
    console.log(data);
})();

```

You may pass an object in between the address and the callback function to tweak the behavior of the lookup function.
The default options are shown below:

```js
{
	"server":  "",   // this can be a string ("host:port") or an object with host and port as its keys; leaving it empty makes lookup rely on servers.json
	"follow":  2,    // number of times to follow redirects
	"timeout": 0,    // socket timeout, excluding this doesn't override any default timeout value
	"verbose": false // setting this to true returns an array of responses from all servers
	"bind": null     // bind the socket to a local IP address
	"proxy": {       // (optional) SOCKS Proxy
		"host": "",
		"port": 0,
		"type": 5    // or 4
	}
}
```

## Contributing

Contributions are welcome.

## License

Node WHOIS is available under the [BSD (2-Clause) License](http://opensource.org/licenses/BSD-2-Clause).

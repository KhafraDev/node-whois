const _ = require('underscore');
const net = require('net')
const { SocksClient } = require('socks');
const punycode = require('punycode');

const SERVERS = require('./servers.json');

/**
 * Checks if a variable is an "existential operator", https://coffeescript.org/#existential-operator.
 * @param {any} v Variable
 */
const q = v => {
    if(typeof v === 'undefined' || v === null) {
        return false;
    }

    return true;
}

const cleanParsingErrors = string => string.replace(/[:\s]+/gm, '') || string;

const lookup = (addr, options, done) => {
	if(typeof done === 'undefined' && typeof options === 'function') {
		done = options
        options = {}
    }

    _.defaults(options, {
		follow: 2,
        timeout: 60000 // 60 seconds in ms
    });

	done = _.once(done);

	let server = options.server;
	let proxy = options.proxy;
	let timeout = options.timeout;

    if(!server) {
		switch(true) {
			case _.contains(addr, '@'):
				done(new Error('lookup: email addresses not supported'))
				return;

			case net.isIP(addr) !== 0:
				server = SERVERS['_']['ip']

			default:
				let tld = punycode.toASCII(addr);
				while(true) {
					server = SERVERS[tld];
					if(!tld || server) {
                        break;
                    }
                    tld = tld.replace(/^.+?(\.|$)/, '');
                }
        }
    }

    if(!server) {
		done(new Error('lookup: no whois server is known for this kind of object'));
        return;
    }

    if(typeof server === 'string') {
		const parts = server.split(':');
		server = {
			host: parts[0],
			port: parts[1]
        }
    }

    if(typeof proxy === 'string') {
		parts = proxy.split(':');
		proxy = {
			ipaddress: parts[0],
            port: parseInt(parts[1])
        }
    }

    _.defaults(server, {
		port: 43,
		query: "$addr\r\n"
    });

	if(proxy) {
		_.defaults(proxy, {
            type: 5
        });
    }

	const _lookup = (socket, done) => {
		let idn = addr;
		if(server.punycode !== false && options.punycode !== false)
			idn = punycode.toASCII(addr);
		if(options.encoding) 
            socket.setEncoding(options.encoding || 'utf8');
            
		socket.write(server.query.replace('$addr', idn));

		let data = '';
		socket.on('data', chunk => data += chunk);

		socket.on('timeout', () => {
			socket.destroy();
			done(new Error('lookup: timeout'));
        });

		socket.on('error', err => done(err));

        socket.on('close', err => {
			if(options.follow > 0) {
				match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*((?:r?whois|https?):\/\/)?(.*)/);
				if(q(match) && match[3] != server.host) {
					options = _.extend({}, options, {
						follow: options.follow - 1,
                        server: match[3].trim()
                    });
					options.server = cleanParsingErrors(options.server);

                    lookup(addr, options, (err, parts) => {
						if(q(err)) {
                            return done(err);
                        }

                        if(options.verbose) {
							done(null, [
								'object' === typeof server ? server.host.trim() : server.trim(),
								data
							].concat(parts));
						} else {
                            done(null, parts);
                        }
                    });

                    return;
                }
            }

            if(options.verbose) {
				done(null, [
					'object' === typeof server ? server.host.trim() : server.trim(),
					data
                ]);
            } else {
                done(null, data)
            }
        });
    }

	if(proxy) {
		SocksClient.createConnection({
			proxy: proxy,
			destination: {
				host: server.host,
                port: server.port
            },
			command: 'connect',
			timeout: timeout
		}, (err, { socket }) => {
			if(q(err)) {
                return done(err);
            }

			if(timeout) {
                socket.setTimeout(timeout);
            }

            // error vvvv
			_lookup(socket, done);

            socket.resume()
        });
    } else {
		sockOpts = {
			host: server.host,
			port: server.port
        }

		if(options.bind) {
            sockOpts.localAddress = options.bind;
        }

		socket = net.connect(sockOpts);
		if(timeout)
			socket.setTimeout(timeout);
		_lookup(socket, done);
    }
}

if(module === require.main) {
	const optimist = require('optimist')
        .usage('$0 [options] address')
        .default('s', null)
        .alias('s', 'server')
        .describe('s', 'whois server')
        .default('f', 0)
        .alias('f', 'follow')
        .describe('f', 'number of times to follow redirects')
        .default('p', null)
        .alias('p', 'proxy')
        .describe('p', 'SOCKS proxy')
        .boolean('v')
        .default('v', false)
        .alias('v', 'verbose')
        .describe('v', 'show verbose results')
        .default('b', null)
        .alias('b', 'bind')
        .describe('b', 'bind to a local IP address')
        .boolean('h')
        .default('h', false)
        .alias('h', 'help')
        .describe('h', 'display this help message');

	if(optimist.argv.h) {
		console.log(optimist.help());
        process.exit(0);
    }

	if(!q(optimist.argv._[0])) {
		console.log(optimist.help());
        process.exit(1);
    }

	lookup(optimist.argv._[0], {
        server: optimist.argv.server, 
        follow: optimist.argv.follow, 
        proxy: optimist.argv.proxy, 
        verbose: optimist.argv.verbose, 
        bind: optimist.argv.bind 
    }, (err, data) => {
		if(q(err)) {
			console.log(err)
            process.exit(1);
        }

		if(Array.isArray(data)) {
			for(part in data) {
				if('object' == typeof part.server) {
					console.log(part.server.host);
                } else {
                    console.log(part.server);
                }
                console.log(part.data);
                console.log();
            }
        } else {
            console.log(data);
        }
    });
}

module.exports = { lookup };
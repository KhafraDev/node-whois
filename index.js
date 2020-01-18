const { once } = require('underscore');
const { isIP, connect } = require('net')
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

    options.follow = options.follow || 2;
    options.timeout = options.timeout || 60000;

	done = once(done);

	let server = options.server;
	let proxy = options.proxy;
	let timeout = options.timeout;

    if(!server) {
		switch(true) {
			case addr.includes('@'):
				return done(new Error('lookup: email addresses not supported'));
			case isIP(addr) !== 0:
				server = SERVERS['_']['ip'];
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
		return done(new Error('lookup: no whois server is known for this kind of object'));
    }

    if(typeof server === 'string') {
		const [host, port] = server.split(':');
		server = {
			host: host,
			port: port
        }
    }

    if(typeof proxy === 'string') {
		const [ipaddress, port] = proxy.split(':');
		proxy = {
			ipaddress: ipaddress,
            port: parseInt(port)
        }
    }

    server.port = server.port || 43;
    server.query = server.query || '$addr\r\n';

	if(proxy) {
        proxy.type = proxy.type || 5;
    }

	const _lookup = (socket, done) => {
        const idn = server.punycode !== false && options.punycode !== false ? punycode.toASCII(addr) : addr;
        
		if(options.encoding) 
            socket.setEncoding(options.encoding);
            
		socket.write(server.query.replace('$addr', idn));

		let data = '';
		socket.on('data', chunk => data += chunk);

		socket.on('timeout', () => {
			socket.destroy();
			done(new Error('lookup: timeout'));
        });

		socket.on('error', err => done(err));

        socket.on('close', () => {
			if(options.follow > 0) {
				const match = data.replace(/\r/gm, '').match(/(ReferralServer|Registrar Whois|Whois Server|WHOIS Server|Registrar WHOIS Server):[^\S\n]*((?:r?whois|https?):\/\/)?(.*)/);
				if(q(match) && match[3] !== server.host) {
                    options = Object.assign({}, {
                        ...options,
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
                done(null, data);
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

			_lookup(socket, done);
            socket.resume();
        });
    } else {
		sockOpts = {
			host: server.host,
			port: server.port
        }

		if(options.bind) {
            sockOpts.localAddress = options.bind;
        }

		socket = connect(sockOpts);
		if(timeout)
			socket.setTimeout(timeout);
		_lookup(socket, done);
    }
}

module.exports = { lookup };
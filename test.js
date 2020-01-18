const _ = require('underscore');
const assert = require('assert');
const whois = require('./index');

describe('#lookup()', () => {
	it('should work with google.com', done => {
		whois.lookup('google.com', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
            done()
        });
    });

	it('should honor specified WHOIS server', done => {
		whois.lookup('gandi.net', {
            server: 'whois.gandi.net'
        }, (err, data) => {
			assert.ifError(err);
			data = data.toLowerCase();
			assert.notEqual(data.indexOf('whois server: whois.gandi.net'), -1);
			assert.notEqual(data.indexOf('domain name: gandi.net'), -1);
            done();
        });
    });

	it('should honor specified WHOIS server with port override', done => {
		whois.lookup('tucows.com', {
            server: 'whois.tucows.com:43'
        }, (err, data) => {
			assert.ifError(err);
			data = data.toLowerCase();
			assert.notEqual(data.indexOf('whois server: whois.tucows.com'), -1);
			assert.notEqual(data.indexOf('domain name: tucows.com'), -1);
            done();
        });
    });

	it('should follow specified number of redirects for domain', done => {
		whois.lookup('google.com', {
            follow: 1
        }, (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
            done();
        });
    });

	it('should follow specified number of redirects for IP address', done => {
		whois.lookup('176.58.115.202', { 
            follow: 1 
        }, (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('inetnum:        176.58.112.0 - 176.58.119.255'), -1);
            done();
        });
    });

	it('should work with verbose option', done => {
		whois.lookup('google.com', {
            verbose: true
        }, (err, data) => {
			assert.ifError(err);
			assert.equal(data[0], 'whois.verisign-grs.com');
			assert.notEqual(data.some(d => d.toLowerCase().indexOf('domain name: google.com') !== -1), false);
            done();
        });
    });

	it('should work with nic.sh', done => {
		whois.lookup('nic.sh', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('registry domain id: d503300000040403495-lrms'), -1);
            done();
        });
    });

	it('should work with nic.io', done => {
		whois.lookup('nic.io', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('registry domain id: d503300000040453277-lrms'), -1);
            done();
        });
    });

	it('should work with nic.ac', done => {
		whois.lookup('nic.ac', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('registry domain id: d503300000040632620-lrms'), -1);
            done();
        });
    });

	it('should work with nic.tm', done => {
		whois.lookup('nic.tm', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('status : permanent/reserved'), -1);
            done();
        });
    });

	it('should work with nic.global', done => {
		whois.lookup('nic.global', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('registry domain id: d2836144-agrs'), -1);
            done();
        });
    });

	it('should work with srs.net.nz', done => {
		whois.lookup('srs.net.nz', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain_name: srs.net.nz'), -1);
            done();
        });
    });

	it('should work with redundant follow', done => {
		whois.lookup('google.com', {
            follow: 5 
        }, (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
            done();
        });
    });

	it('should work with küche.de', done => {
		whois.lookup('küche.de', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain: küche.de'), -1);
			assert.notEqual(data.toLowerCase().indexOf('status: connect'), -1);
            done();
        });
    });

	it('should work with google.co.jp in english', done => {
		whois.lookup('google.co.jp', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('a. [domain name]                google.co.jp'), -1);
            done();
        });
    });

	it('should work with registry.pro', done => {
		whois.lookup('registry.pro', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain id: d107300000000006392-lrms'), -1);
            done();
        });
    });

	it('should fail with google.com due to timeout', done => {
		whois.lookup('google.com', {
            timeout: 1
        }, err => {
			assert(err);
			assert.equal('lookup: timeout', err.message);
            done();
        });
    });

	it('should succeed with google.com with timeout', done => {
		whois.lookup('google.com', {
            timeout: 10000
        }, (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('domain name: google.com'), -1);
            done();
        });
    });

	it('should work with åre.no', done => {
		whois.lookup('åre.no', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('åre.no'), -1);
            done();
        });
    });

	it('should work with nic.digital', done => {
		whois.lookup('nic.digital', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('nic.digital'), -1);
            done();
        });
    });

	it('should work with whois.nic.ai', done => {
		whois.lookup('whois.nic.ai', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('whois.nic.ai'), -1);
            done();
        });
    });

	it('should work with currentzoology.org', done => {
		whois.lookup('currentzoology.org', (err, data) => {
			assert.ifError(err);
            assert.notEqual(data.toLowerCase().indexOf('currentzoology.org'), -1);
            done();
        });
    });

	it('should work with dot.ai', done => {
		whois.lookup('dot.ai', (err, data) => {
			assert.ifError(err);
			assert.notEqual(data.toLowerCase().indexOf('dot.ai'), -1);
            done();
        });
    });
});

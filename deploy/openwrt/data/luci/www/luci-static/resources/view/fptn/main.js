'use strict';
'require view';
'require form';
'require fs';
'require rpc';
'require poll';
'require ui';
'require uci';

var packageVersion = '@FPTN_VERSION@';

var botLink = '<a href="https://t.me/fptn_bot" target="_blank" ' +
	'rel="noreferrer">@fptn_bot</a>';

var brotliDecode;

var spoofingMethods = [
	[ 'sni-spoofing-chrome-149', 'Chrome 149' ],
	[ 'sni-spoofing-chrome-148', 'Chrome 148' ],
	[ 'sni-spoofing-chrome-147', 'Chrome 147' ],
	[ 'sni-spoofing-chrome-146', 'Chrome 146' ],
	[ 'sni-spoofing-chrome-145', 'Chrome 145' ],
	[ 'sni-spoofing-firefox-151', 'Firefox 151' ],
	[ 'sni-spoofing-firefox-150', 'Firefox 150' ],
	[ 'sni-spoofing-firefox-149', 'Firefox 149' ],
	[ 'sni-spoofing-yandex-26-4', 'Yandex 26.4' ],
	[ 'sni-spoofing-yandex-26-3', 'Yandex 26.3' ],
	[ 'sni-spoofing-yandex-25', 'Yandex 25' ],
	[ 'sni-spoofing-yandex-24', 'Yandex 24' ],
	[ 'sni-spoofing-safari-26-5', 'Safari 26.5' ],
	[ 'sni-spoofing-safari-26-4', 'Safari 26.4' ]
];

var callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

function serviceInfo() {
	return callServiceList('fptn').then(function (res) {
		try {
			var instance = res['fptn']['instances']['fptn'] ||
			                res['fptn']['instances']['instance1'];
			return { running: instance['running'] === true, pid: instance['pid'] };
		} catch (e) {
			return { running: false };
		}
	}).catch(function () {
		return { running: false };
	});
}

// Секции ZeroBlock, которые сами запускают FPTN. Тогда эта страница не
// участвует: ZeroBlock поднимает клиент со своим конфигом и держит
// fptn.config.enabled выключенным, а правки здесь только путают.
function zeroblockSections() {
	return uci.load('zeroblock').then(function () {
		return uci.sections('zeroblock', 'section').filter(function (s) {
			return s.enabled !== '0' && (s.proxy_config_type === 'fptn' ||
				s.failover_fptn_access_token != null);
		}).map(function (s) {
			return s['.name'];
		});
	}).catch(function () {
		return [];
	});
}

function managedPage(view, sections) {
	view.handleSaveApply = null;
	view.handleSave = null;
	view.handleReset = null;

	return E('div', { 'class': 'cbi-map' }, [
		E('h2', {}, 'FPTN VPN'),
		E('div', { 'class': 'alert-message warning' }, [
			E('p', {}, E('strong', {},
				_('FPTN on this router is run by ZeroBlock (section: %s).')
					.format(sections.join(', ')))),
			E('p', {}, _('The settings on this page are not used. Access ' +
				'tokens, server selection and every other option are set in the ' +
				'ZeroBlock section. This page only matters when FPTN runs on its ' +
				'own, without ZeroBlock.')),
			E('p', {}, E('a', {
				'class': 'btn cbi-button cbi-button-action',
				'href': L.url('admin', 'services', 'zeroblock')
			}, _('Open ZeroBlock')))
		]),
		E('p', { 'style': 'opacity:.7' },
			_('Package version: %s').format(packageVersion))
	]);
}

function isRunning() {
	return serviceInfo().then(function (info) {
		return info.running;
	});
}

function parseToken(token) {
	try {
		var text = token.replace(/[\s=]/g, '');
		var brotli = /^fptnb(:|\/\/)/.test(text);
		var body = text.replace(brotli ? /^fptnb(:|\/\/)/ : /^fptn:(\/\/)?/, '');
		var bytes = Uint8Array.from(atob(body), function (c) {
			return c.charCodeAt(0);
		});
		var config = JSON.parse(new TextDecoder().decode(
			brotli ? brotliDecode(new Int8Array(bytes.buffer)) : bytes));

		var valid = typeof config.version === 'number' &&
			typeof config.service_name === 'string' &&
			typeof config.username === 'string' &&
			typeof config.password === 'string' &&
			Array.isArray(config.servers) && config.servers.length > 0 &&
			config.servers.every(function (server) {
				return typeof server.name === 'string' &&
					typeof server.host === 'string' &&
					typeof server.port === 'number' &&
					typeof server.md5_fingerprint === 'string';
			});

		return valid ? config : null;
	} catch (e) {
		return null;
	}
}

function tokenServers(token) {
	var config = parseToken(token);

	return config ? config.servers.map(function (server) {
		return server.name;
	}) : null;
}

// Имена серверов по всем ключам в поле. null, если хотя бы один не разбирается.
// Имя, встречающееся в нескольких сервисах, уточняется сервисом - ровно так его
// понимает --preferred-server.
function tokenServerNames(value) {
	var tokens = String(value || '').split(/\s+/)
		.map(function (item) { return item.trim(); })
		.filter(function (item) { return item.length > 0; });
	var seen = {};
	var entries = [];

	for (var i = 0; i < tokens.length; i++) {
		var config = parseToken(tokens[i]);

		if (!config)
			return null;

		config.servers.forEach(function (server) {
			entries.push({ service: config.service_name, name: server.name });
			seen[server.name] = (seen[server.name] || 0) + 1;
		});
	}

	var names = [];
	entries.forEach(function (entry) {
		var name = seen[entry.name] > 1
			? entry.service + '/' + entry.name : entry.name;

		if (names.indexOf(name) < 0)
			names.push(name);
	});

	return names;
}

function tunnelStats(name) {
	return fs.exec('/sbin/ip', [ '-s', 'link', 'show', name ]).then(function (res) {
		var lines = (res.stdout || '').split('\n');
		var stats = {};

		for (var i = 0; i < lines.length - 1; i++) {
			if (lines[i].indexOf('RX:') >= 0)
				stats.rx = lines[i + 1].trim().split(/\s+/)[0];
			if (lines[i].indexOf('TX:') >= 0)
				stats.tx = lines[i + 1].trim().split(/\s+/)[0];
		}
		return stats;
	}).catch(function () {
		return {};
	});
}

function formatBytes(value) {
	var bytes = parseInt(value, 10);
	if (isNaN(bytes))
		return '—';

	var units = [ 'B', 'KiB', 'MiB', 'GiB', 'TiB' ];
	var unit = 0;

	while (bytes >= 1024 && unit < units.length - 1) {
		bytes /= 1024;
		unit++;
	}

	return (unit === 0 ? bytes : bytes.toFixed(2)) + ' ' + units[unit];
}

function hasTunnel() {
	var name = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

	return fs.exec('/sbin/ip', [ '-o', 'link', 'show' ]).then(function (res) {
		return (res.stdout || '').indexOf(' ' + name + ':') >= 0;
	}).catch(function () {
		return false;
	});
}

function readLog() {
	return fs.exec('/sbin/logread', [ '-l', '500', '-e', 'fptn' ]).then(function (res) {
		return (res.stdout || '').trim();
	}).catch(function () {
		return '';
	});
}

function logTail(log) {
	return log.split('\n').filter(function (line) {
		return line.indexOf("Can't to read from device") < 0;
	}).slice(-400).join('\n');
}

function listOption(section, tab, name, key, title, description, placeholder) {
	var o = section.taboption(tab, form.TextValue, name, title, description);

	o.rows = 12;
	o.placeholder = placeholder;
	o.rmempty = true;

	o.cfgvalue = function (sid) {
		var value = uci.get('fptn', sid, key);
		return Array.isArray(value) ? value.join('\n') : (value || '');
	};

	o.write = function (sid, value) {
		var items = (value || '').split(/\r?\n/).map(function (line) {
			return line.trim();
		}).filter(function (line) {
			return line.length > 0;
		});
		uci.set('fptn', sid, key, items);
	};

	o.remove = function () {};

	return o;
}

function compareVersions(left, right) {
	var a = String(left).replace(/^v/, '').split('.');
	var b = String(right).replace(/^v/, '').split('.');
	var length = Math.max(a.length, b.length);

	for (var i = 0; i < length; i++) {
		var x = parseInt(a[i], 10) || 0;
		var y = parseInt(b[i], 10) || 0;

		if (x < y)
			return -1;
		if (x > y)
			return 1;
	}

	return 0;
}

function checkUpdate() {
	// Checking from the admin's browser leaks the request outside and hangs
	// where GitHub is blocked; the router itself knows better when to look.
	if (!uci.get('fptn', 'config', 'check_updates'))
		return Promise.resolve(null);
	return fetch('https://api.github.com/repos/fptn-project/fptn/releases/latest')
		.then(function (res) {
			return res.json();
		})
		.then(function (msg) {
			if (!msg || msg.draft || !msg.name)
				return null;

			return compareVersions(packageVersion, msg.name) < 0 ? msg.name : null;
		})
		.catch(function () {
			return null;
		});
}

// Ключей может быть несколько: UCI хранит их списком, а конфиг прежних версий -
// одиночным option. Отсюда всегда выходит массив.
function accessTokens() {
	var value = uci.get('fptn', 'config', 'access_token');
	if (value == null)
		return [];
	return (Array.isArray(value) ? value : String(value).split(/\s+/))
		.map(function (item) { return String(item).trim(); })
		.filter(function (item) { return item.length > 0; });
}

function diagnose() {
	var tun = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

	return Promise.all([
		isRunning(),
		fs.exec('/sbin/ip', [ '-o', 'link', 'show' ]).catch(function () {
			return {};
		}),
		fs.exec('/sbin/ip', [ '-o', '-4', 'addr', 'show' ]).catch(function () {
			return {};
		}),
		fs.exec('/sbin/ip', [ '-4', 'route', 'show' ]).catch(function () {
			return {};
		}),
		readLog(),
		uci.load('firewall').catch(function () {}),
		fs.exec('/bin/ping', [ '-c', '1', '-W', '3', '8.8.8.8' ]).catch(function () {
			return { code: 1 };
		}),
		tunnelStats(tun)
	]).then(function (r) {
		var links = r[1].stdout || '';
		var addrs = r[2].stdout || '';
		var routes = r[3].stdout || '';
		var log = r[4] || '';

		var linkLine = links.split('\n').filter(function (line) {
			return line.indexOf(' ' + tun + ':') >= 0;
		})[0] || '';

		var addrLine = addrs.split('\n').filter(function (line) {
			return line.indexOf(' ' + tun + ' ') >= 0;
		})[0] || '';

		var defaultLine = routes.split('\n').filter(function (line) {
			return line.indexOf('default') === 0;
		})[0] || '';

		var zones = uci.sections('firewall', 'zone').filter(function (zone) {
			return zone.name === 'fptn';
		});

		var expected = [ 'NTP server', 'is not reachable', 'stream truncated',
			'unknown key' ];

		var errors = splitRuns(log).pop().split('\n').filter(function (line) {
			return line.indexOf('[error]') >= 0 &&
				!expected.some(function (text) {
					return line.indexOf(text) >= 0;
				});
		});

		var mtu = linkLine.match(/mtu (\d+)/);

		var pinged = r[6] && r[6].code === 0;
		var stats = r[7] || {};

		return [
			{
				ok: accessTokens().length > 0,
				title: _('Access token is set'),
				detail: accessTokens().length > 0
					? (accessTokens().length === 1 ? _('configured')
						: _('%d keys configured').format(accessTokens().length))
					: _('empty, the client refuses to start')
			},
			{
				ok: uci.get('fptn', 'config', 'enabled') === '1',
				title: _('Client is enabled'),
				detail: uci.get('fptn', 'config', 'enabled') === '1'
					? _('enabled') : _('disabled in configuration')
			},
			{
				ok: r[0],
				title: _('VPN process is running'),
				detail: r[0] ? _('running') : _('stopped')
			},
			{
				ok: linkLine.indexOf(',UP') >= 0,
				title: _('Tunnel \'%s\' is up').format(tun),
				detail: linkLine
					? _('up, MTU %s').format(mtu ? mtu[1] : _('unknown'))
					: _('interface does not exist')
			},
			{
				ok: addrLine !== '',
				title: _('Tunnel has an IPv4 address'),
				detail: addrLine
					? (addrLine.match(/inet ([0-9./]+)/) || [ '', _('unknown') ])[1]
					: _('no address assigned')
			},
			{
				ok: defaultLine.indexOf('dev ' + tun) >= 0,
				title: _('Default route goes through the tunnel'),
				detail: defaultLine || _('no default route at all')
			},
			{
				ok: zones.length > 0,
				title: _('Firewall zone \'fptn\' exists'),
				detail: zones.length
					? _('present, LAN clients are masqueraded')
					: _('missing, LAN clients will not reach the internet')
			},
			{
				ok: pinged,
				title: _('The internet answers through the tunnel'),
				detail: pinged
					? _('8.8.8.8 replies')
					: _('8.8.8.8 does not reply, traffic does not pass the tunnel')
			},
			{
				ok: parseInt(stats.rx, 10) > 0,
				title: _('The tunnel carries traffic in both directions'),
				detail: _('sent %s, received %s').format(formatBytes(stats.tx),
					formatBytes(stats.rx))
			}
		];
	});
}

function showDiagnostics() {
	return diagnose().then(function (checks) {
		var failed = checks.filter(function (check) {
			return !check.ok;
		});

		var rows = checks.map(function (check) {
			return E('div', { 'style': 'padding:.4em 0;border-top:1px solid rgba(128,128,128,.3)' }, [
				E('span', {
					'style': 'font-weight:bold;color:' + (check.ok ? '#00a000' : '#a00000')
				}, (check.ok ? '✓ ' : '✗ ') + check.title),
				E('div', { 'style': 'opacity:.7;padding-left:1.4em' }, check.detail)
			]);
		});

		var pending = ui.changes.numChanges > 0
			? E('div', { 'style': 'padding:.5em;color:#a08000' },
				_('There are unsaved changes. The checks below look at the applied ' +
				'configuration — press "Save & Apply" first.'))
			: '';

		ui.showModal(_('Diagnostics'), [
			E('div', {
				'style': 'padding:.5em;font-weight:bold;color:' +
					(failed.length ? '#a00000' : '#00a000')
			}, failed.length
				? _('%d check(s) failed').format(failed.length)
				: _('Everything looks fine')),
			pending,
			E('div', {}, rows),
			E('div', { 'class': 'right' }, E('button', {
				'class': 'cbi-button',
				'click': ui.hideModal
			}, _('Close')))
		]);
	});
}

function splitRuns(log) {
	var runs = [], current = '';

	log.split('\n').forEach(function (line) {
		if (line.indexOf('Application started successfully') >= 0) {
			runs.push(current);
			current = '';
		}
		current += line + '\n';
	});
	runs.push(current);

	return runs;
}

function failedRuns(log, needles) {
	var runs = splitRuns(log), streak = 0;

	for (var i = runs.length - 1; i >= 0; i--) {
		var run = runs[i];
		var failed = needles.some(function (needle) {
			return run.indexOf(needle) >= 0;
		});

		if (failed)
			streak++;
		else if (run.indexOf('Starting client') >= 0)
			break;
	}

	return streak;
}

function lastRunHas(log, needles) {
	var runs = splitRuns(log);
	var run = runs[runs.length - 1];

	return needles.some(function (needle) {
		return run.indexOf(needle) >= 0;
	});
}

function problemNote(log, connected) {
	if (accessTokens().length === 0)
		return _('no token configured');

	if (connected)
		return '';

	if (lastRunHas(log, [ 'no default route', 'default gateway not found',
			'Unable to find the default gateway' ]))
		return _('the router has no default route — check the WAN connection');

	if (failedRuns(log, [ 'Config error' ]) >= 3)
		return _('this access token cannot be read — copy it again from %s').format(botLink);

	if (failedRuns(log, [ 'Status: 401', 'Login failed (code 401)' ]) >= 3)
		return _('the servers reject this access token — it has expired or is ' +
			'invalid, get a fresh one from %s').format(botLink);

	if (failedRuns(log, [ 'DNS resolve error', 'DNS server error' ]) >= 3)
		return _('the router cannot resolve server names — check its own DNS ' +
			'settings under Network → DNS');

	if (failedRuns(log, [ 'does not exist! Check your token' ]) >= 3)
		return _('the server named in "Preferred server" is not in this token — ' +
			'clear the field or choose another one');

	if (failedRuns(log, [ 'All servers unavailable' ]) >= 5)
		return _('no server could be reached — try another bypass blocking ' +
			'method, or get a fresh token from %s').format(botLink);

	return '';
}

function describe(running, tunnel) {
	if (uci.get('fptn', 'config', 'enabled') !== '1' ||
			!uci.get('fptn', 'config', 'access_token'))
		return [ _('Disabled'), '#808080' ];
	if (!running)
		return [ _('Starting…'), '#a08000' ];
	if (!tunnel)
		return [ _('Connecting…'), '#a08000' ];

	return [ _('Connected'), '#00a000' ];
}

function collect() {
	var tun = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

	return Promise.all([
		serviceInfo(), hasTunnel(), readLog(), tunnelStats(tun)
	]);
}

function statusRows(data) {
	var state = describe(data[0].running, data[1]);
	var stats = data[3] || {};
	var method = uci.get('fptn', 'config', 'bypass_method');
	var spoofing = spoofingMethods.filter(function (item) {
		return item[0] === method;
	})[0];

	return [
		[ _('Connection'), state[0], state[1] ],
		[ _('Selected server'),
			uci.get('fptn', 'config', 'preferred_server') || _('Auto') ],
		[ _('Bypass blocking method'),
			spoofing ? spoofing[1] : _('Traffic masking (obfuscation)') ],
		[ _('Split tunneling'),
			uci.get('fptn', 'config', 'enable_split_tunnel') !== '1' ? _('off')
				: uci.get('fptn', 'config', 'split_tunnel_mode') === 'include'
					? _('Include') : _('Exclude') ],
		[ _('Tunnel interface'),
			uci.get('fptn', 'config', 'tun_interface_name') || 'tun0' ],
		[ _('PID'), data[0].pid ? String(data[0].pid) : '—' ],
		[ _('Received'), formatBytes(stats.rx) ],
		[ _('Sent'), formatBytes(stats.tx) ]
	];
}

function refresh() {
	return collect().then(function (data) {
		var rows = statusRows(data);

		var status = document.getElementById('fptn_status');
		if (status) {
			status.textContent = rows[0][1];
			status.style.color = rows[0][2];
		}

		var note = document.getElementById('fptn_note');
		if (note)
			note.innerHTML = ' ' + problemNote(data[2] || '', data[1]);

		rows.forEach(function (row, index) {
			var node = document.getElementById('fptn_st' + index);
			if (!node)
				return;

			node.textContent = row[1];
			if (row[2])
				node.style.color = row[2];
		});

		var log = document.getElementById('fptn_log');
		if (log)
			log.textContent = logTail(data[2] || '') || _('No messages yet');

		return data;
	});
}

return view.extend({
	handleSaveApply: function (ev, mode) {
		return this.super('handleSaveApply', [ ev, mode ]).then(function () {
			return fs.exec('/etc/init.d/fptn', [ 'restart' ]).then(refresh);
		});
	},

	load: function () {
		return uci.load('fptn').then(function () {
			var tun = uci.get('fptn', 'config', 'tun_interface_name') || 'tun0';

			return Promise.all([
				serviceInfo(), hasTunnel(), readLog(), tunnelStats(tun),
				import(L.resource('fptn/brotli.js')), zeroblockSections()
			]);
		});
	},

	render: function (data) {
		var m, s, o;

		if (data[5] && data[5].length)
			return managedPage(this, data[5]);

		var running = data[0].running;
		var state = describe(running, data[1]);

		brotliDecode = data[4].BrotliDecode;

		// Opening a page must not touch the daemon: procd already restarts it
		// on a config change through its reload trigger. This used to restart
		// or stop the tunnel just because someone looked at the tab.
		poll.add(refresh, 5);

		m = new form.Map('fptn', 'FPTN VPN', _('Censorship-resistant VPN'));

		s = m.section(form.NamedSection, 'config', 'fptn', _('Getting started'));
		s.anonymous = true;

		o = s.option(form.DummyValue, '_help');
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<ol style="margin:0;padding-inline-start:1.5em">' +
				'<li>' + _('Open %s in Telegram and copy the access token.').format(botLink) + '</li>' +
				'<li>' + _('Paste it into the "Access token" field below and press "Save & Apply".') + '</li>' +
				'<li>' + _('Got keys from several services? Put each on its own line.') + '</li>' +
				'</ol>';
		};

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.rmempty = false;

		var enabledOption = o;

		o = s.option(form.DummyValue, '_status', _('Service'));
		o.rawhtml = true;
		o.cfgvalue = function () {
			return '<span id="fptn_status" style="font-weight:bold;color:' +
				state[1] + '">' + state[0] + '</span>' +
				'<span id="fptn_note" style="color:#a00000"> ' +
				problemNote(data[2] || '', data[1]) + '</span>';
		};

		o = s.option(form.DummyValue, '_update', _('Version'));
		o.renderWidget = function () {
			var node = E('span', {}, packageVersion);

			checkUpdate().then(function (latest) {
				if (!latest)
					return;

				node.appendChild(E('span', {}, [ ' — ', E('a', {
					'href': 'https://github.com/fptn-project/fptn/releases/latest',
					'target': '_blank',
					'rel': 'noreferrer'
				}, _('version %s is available').format(latest)) ]));
			});

			return node;
		};

		o = s.option(form.Button, '_diagnostics');
		o.inputtitle = _('Diagnostics');
		o.inputstyle = 'apply';
		o.onclick = function () {
			return showDiagnostics();
		};

		s = m.section(form.NamedSection, 'config', 'fptn');
		s.anonymous = true;
		s.tab('status', _('Status'));
		s.tab('general', _('Settings'));
		s.tab('routing', _('Routing'));

		statusRows(data).forEach(function (row, index) {
			var field = s.taboption('status', form.DummyValue, '_st' + index, row[0]);
			field.rawhtml = true;
			field.cfgvalue = function () {
				return '<span id="fptn_st' + index + '"' +
					(row[2] ? ' style="font-weight:bold;color:' + row[2] + '"' : '') +
					'>' + row[1] + '</span>';
			};
		});

		o = s.taboption('general', form.TextValue, 'access_token',
			_('Access tokens'),
			_('Token issued by %s in Telegram. It carries the server list, so ' +
			'get a new one when the current token expires. One key per line - ' +
			'the servers of every key are tried together, and the client ' +
			'connects to whichever answers first.').format(botLink));
		o.rows = 6;
		o.rmempty = false;
		o.cfgvalue = function () {
			return accessTokens().join('\n');
		};
		o.write = function (section_id, value) {
			var list = String(value || '').split(/\s+/)
				.map(function (item) { return item.trim(); })
				.filter(function (item) { return item.length > 0; });
			// Один ключ пишем option'ом: так конфиг остаётся читаемым для тех
			// версий пакета, что списка не знают.
			uci.set('fptn', section_id, 'access_token',
				list.length === 1 ? list[0] : list);
		};
		o.validate = function (section_id, value) {
			if (!value || tokenServerNames(value))
				return true;

			return _('A token is damaged or not copied completely — copy it ' +
				'again from @fptn_bot');
		};
		o.onchange = function (ev, section_id, value) {
			var names = tokenServerNames(value);
			var widget = serverOption.getUIElement(section_id);

			if (!names || !widget)
				return;

			var selected = widget.getValue();
			widget.clearChoices(true);
			widget.addChoices([ '' ].concat(names), { '': _('Auto') });
			widget.setValue(names.indexOf(selected) >= 0 ? selected : '');
		};

		o = s.taboption('general', form.Value, 'preferred_server',
			_('Preferred server'),
			_('Server from the access tokens to connect to. "Auto" logs in to ' +
			'every server at once and keeps the one that answers first. A name ' +
			'that appears in more than one key is offered qualified with its ' +
			'service: "MyService/Server-1".'));
		o.rmempty = true;
		o.value('', _('Auto'));
		(tokenServerNames(accessTokens().join('\n')) || []).forEach(
			function (name) {
				o.value(name);
			});

		var serverOption = o;

		o = s.taboption('general', form.Value, 'exclude_servers',
			'Exclude servers',
			'Regular expression. Servers whose name matches it are left out ' +
			'of the pool - "Russia|Vietnam" drops both, "^FPTN.ONLINE/" drops ' +
			'a whole service.');
		o.rmempty = true;
		o.placeholder = 'Russia|Vietnam';

		o = s.taboption('general', form.Value, 'max_ping',
			_('Latency limit, ms'),
			_('A server slower than this is not picked, and the one in use is ' +
			'replaced once it stays over the limit. Empty or 0 - no limit.'));
		o.rmempty = true;
		o.datatype = 'uinteger';
		o.placeholder = '0';

		o = s.taboption('general', form.ListValue, 'connection_strategy',
			_('Connection strategy'),
			_('How many tunnels are kept open at the same time. Every tunnel is ' +
			'replaced by a new one each 10 minutes, and traffic is spread ' +
			'across them, so no single connection carries the whole session.'));
		o.value('rolling-tunnel', _('Rolling tunnel'));
		o.value('dual-rolling-tunnel', _('Dual rolling tunnel'));
		o.value('triple-rolling-tunnel', _('Triple rolling tunnel'));
		o.default = 'dual-rolling-tunnel';

		o = s.taboption('general', form.ListValue, 'bypass_method',
			_('Bypass blocking method'),
			_('How the connection is disguised. Traffic masking hides it inside ' +
			'an ordinary TLS stream; the browser options copy the TLS handshake ' +
			'of that browser, so the connection looks like a visit to the ' +
			'domain set below.'));
		o.value('obfuscation', _('Traffic masking (obfuscation)'));
		spoofingMethods.forEach(function (method) {
			o.value(method[0], method[1]);
		});
		o.default = 'obfuscation';

		o = s.taboption('general', form.Value, 'mtu_size', _('Tunnel MTU'),
			_('Largest packet the tunnel carries. 1420 fits almost every ' +
			'provider; lower it if big packets get stuck while small ones ' +
			'pass. Allowed range is 576 to 65535.'));
		o.datatype = 'range(576, 65535)';
		o.placeholder = '1420';
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'sni', _('Fake domain to bypass blocking'),
			_('Domain name sent in the TLS handshake instead of the real server ' +
			'address. Empty means rutube.ru. Pick a popular site that is not ' +
			'blocked where you are.'));
		spoofingMethods.forEach(function (method) {
			o.depends('bypass_method', method[0]);
		});
		o.rmempty = true;

		o = s.taboption('routing', form.Value, 'socks_max_sessions',
			_('SOCKS session limit'),
			_('Cap on simultaneous SOCKS sessions. Empty derives it from the ' +
			'file descriptor limit: two per session plus headroom.'));
		o.datatype = 'uinteger';
		o.placeholder = 'auto';
		o.depends({ socks_listen: /.+/ });
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'status_listen',
			_('Status API address'),
			_('Serve an HTTP API with the server pool and their latency, for ' +
			'example 127.0.0.1:9091. Anything but the loopback needs a token ' +
			'below - the client refuses to start otherwise, because the pool, ' +
			'the latency probe and the server switch would be open to the ' +
			'whole network.'));
		o.datatype = 'ipaddrport';
		o.placeholder = '127.0.0.1:9091';
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'status_secret',
			_('Status API token'),
			_('Requests must carry Authorization: Bearer <token>. Empty means ' +
			'no check, and then the address above may only be the loopback. ' +
			'Required to reach the API from another host.'));
		o.password = true;
		o.depends({ status_listen: /.+/ });
		o.rmempty = true;

		o = s.taboption('general', form.Value, 'probe_interval',
			_('Re-measure interval'),
			_('Re-measure every server in the pool every N seconds. 0 keeps ' +
			'only the reading taken at startup, so a server that was down at ' +
			'launch stays marked dead.'));
		o.datatype = 'uinteger';
		o.placeholder = '0';
		o.depends({ status_listen: /.+/ });
		o.rmempty = true;

		o = s.taboption('routing', form.Flag, 'use_fptn_dns', _('Use FPTN DNS'),
			_('Send DNS queries through the tunnel. When off, FPTN does not touch the router DNS settings at all.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('routing', form.Flag, 'enable_split_tunnel',
			_('Enable split tunneling'),
			_('When enabled, you can configure which sites use VPN and which go directly.'));
		o.default = '1';
		o.rmempty = false;

		o = s.taboption('routing', form.ListValue, 'split_tunnel_mode',
			_('Split tunnel mode'),
			_('Defines traffic routing strategy for split tunneling.'));
		o.value('exclude', _('Exclude'));
		o.value('include', _('Include'));
		o.default = 'exclude';
		o.depends('enable_split_tunnel', '1');

		o = listOption(s, 'routing', 'split_tunnel_domains_exclude',
			'split_tunnel_domains', _('Domains to bypass VPN'),
			_('List domains that should bypass VPN tunnel. These domains will go directly, all other traffic uses VPN'),
			'example.com');
		o.depends({ enable_split_tunnel: '1', split_tunnel_mode: 'exclude' });

		o = listOption(s, 'routing', 'split_tunnel_domains_include',
			'split_tunnel_domains', _('Domains to route through VPN'),
			_('List domains that should use VPN tunnel. Only these domains will go through VPN, all other traffic bypasses VPN'),
			'example.com');
		o.depends({ enable_split_tunnel: '1', split_tunnel_mode: 'include' });

		listOption(s, 'routing', 'blacklist_domains', 'blacklist_domains',
			_('Blacklist domains'),
			_('Completely block access to the main domain AND all its subdomains. Format: example.com (one per line)'),
			'example.com');

		listOption(s, 'routing', 'exclude_tunnel_networks', 'exclude_tunnel_networks',
			_('Exclude tunnel networks'),
			_('Networks that always bypass VPN tunnel. Traffic to these networks goes directly, never through VPN'),
			'10.0.0.0/8');

		listOption(s, 'routing', 'include_tunnel_networks', 'include_tunnel_networks',
			_('Include tunnel networks'),
			_('Networks that always use VPN tunnel. Traffic to these networks always goes through VPN'),
			'192.168.99.0/24');

		s = m.section(form.NamedSection, 'config', 'fptn', _('Log'));
		s.anonymous = true;

		o = s.option(form.DummyValue, '_log');
		o.rawhtml = true;
		o.cfgvalue = function () {
			var text = logTail(data[2] || '') || _('No messages yet');
			return '<pre id="fptn_log" style="max-height:20em;overflow:auto">' +
				text.replace(/[&<>]/g, function (c) {
					return { '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c];
				}) + '</pre>';
		};

		return m.render().then(function (node) {
			var sections = node.querySelectorAll('.cbi-section');

			var toggle = function () {
				var on = enabledOption.formvalue('config') === '1';

				for (var i = 1; i < sections.length; i++)
					sections[i].hidden = !on;
			};

			node.addEventListener('change', toggle);
			toggle();

			return node;
		});
	}
});

package agent

// The 1.1.1 adapter calls the authenticated official getCurrentBans method.
// Its constructor is deliberately bypassed: it can create, upgrade or repair
// a database, including invoking an external sqlite3 command on corruption.
// SQLite may recover journals only in the disposable, authenticated copy.
const fail2banStateRecoveryPython = `
import sys, json, sqlite3, threading, resource, ipaddress, os
from types import SimpleNamespace

os.umask(0o077)
resource.setrlimit(resource.RLIMIT_AS, (512 << 20, 512 << 20))
resource.setrlimit(resource.RLIMIT_FSIZE, (128 << 20, 128 << 20))
resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
sys.path.insert(0, sys.argv[1])
from fail2ban.server.database import Fail2BanDb

assert Fail2BanDb.__version__ == 4, 'unsupported official database reader'
spec = json.loads(sys.argv[3])
db = sqlite3.connect(sys.argv[2], timeout=1, detect_types=sqlite3.PARSE_DECLTYPES)
try:
    db.execute('PRAGMA trusted_schema = OFF')
    # Force any SQLite journal recovery before making SQL writes unavailable.
    db.execute('PRAGMA schema_version').fetchone()
    db.execute('PRAGMA query_only = ON')
    db.execute('PRAGMA temp_store = MEMORY')
    db.execute('PRAGMA cache_size = -4096')
    assert db.execute('PRAGMA integrity_check').fetchall() == [('ok',)], 'database integrity unknown'
    assert db.execute('SELECT version FROM fail2banDb').fetchall() == [(4,)], 'unsupported state schema'
    db.execute('SELECT name, enabled FROM jails LIMIT 0')
    db.execute('SELECT jail, path, firstlinemd5, lastfilepos FROM logs LIMIT 0')
    db.execute('SELECT jail, ip, timeofban, bantime, bancount, data FROM bans LIMIT 0')
    db.execute('SELECT ip, jail, timeofban, bantime, bancount, data FROM bips LIMIT 0')
    reader = Fail2BanDb.__new__(Fail2BanDb)
    reader._db, reader._lock, reader.maxMatches = db, threading.RLock(), 10
    result = {}
    for item in spec['jails']:
        name, duration = item['name'], item['duration']
        jail = SimpleNamespace(name=name, getMaxBanTime=lambda d=duration: d)
        # Reject records that the official reader could otherwise silently
        # discard. A corrupt or over-budget input must never become zero bans.
        rows = db.execute('SELECT ip, timeofban, bantime, bancount FROM bips WHERE jail=? LIMIT 1025', (name,)).fetchall()
        assert len(rows) <= 1024, 'too many state records'
        addresses = set()
        for address, began, stored, count in rows:
            assert type(address) is str and '%' not in address
            ip = ipaddress.ip_address(address)
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            canonical = str(ip)
            assert canonical not in addresses, 'duplicate state address'
            addresses.add(canonical)
            assert type(began) is int and 0 <= began <= 253402300799
            assert type(stored) is int and -1 <= stored <= 253402300799
            assert type(count) is int and 0 <= count <= 9223372036854775807
        result[name] = {}
        tickets = reader.getCurrentBans(jail=jail, forbantime=duration,
            fromtime=spec['at'], correctBanTime=True, maxmatches=0)
        assert len(tickets) <= 1024
        for ticket in tickets:
            ip = ipaddress.ip_address(str(ticket.getID()))
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            address = str(ip)
            began, duration = ticket.getTime(), ticket.getBanTime()
            assert type(began) is int and type(duration) is int and duration >= -1
            expires = 0 if duration == -1 else began + duration
            assert 0 <= expires <= 253402300799 and address not in result[name]
            result[name][address] = {'expires': expires, 'duration': duration}
    print(json.dumps(result, separators=(',', ':'), sort_keys=True))
finally:
    db.close()
`

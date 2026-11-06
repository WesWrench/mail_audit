# whoisit

A Python client to RDAP WHOIS-like services for internet resources (IPs, ASNs, domains,
etc.). `whoisit` is a simple library that makes requests to the "new" RDAP (Registration
Data Access Protocol) query services for internet resource information. These services
started to appear in 2017 and have become more widespread since 2020.

`whoisit` is designed to abstract over RDAP. While RDAP is a basic HTTP and JSON based
protocol which can be implemented in a single line of Python with `requests` the
bootstrapping (which RDAP service to query for what item) and extracting useful
information from the RDAP responses is extensive enough that a library like this is
useful.


## Installation

`whoisit` is pure Python and only has a dependancy on the `requests` and `dateutil`
libraries. You can install `whoisit` via pip:

```bash
$ pip install whoisit
```

Any modern version of Python3 will be compatible.


## Usage

`whoisit` supports the 4 main types of lookups supported by RDAP services. These are:

 * ASNs (autonomous systems numbers) known as `autnum` objects
 * DNS registrations known as `domain` objects - only some TLDs are supported
 * IPv4 and IPv6 addresses and CIDRs / prefixes known as `ip` objects
 * Entities (People, organisations etc. by ENTITY-HANDLES) known as `entity` objects

`whoisit` returns parsed RDAP formatted JSON as (mostly) flat dictionaries by default.

Basic examples:

```python
import whoisit

whoisit.bootstrap()

results = whoisit.asn(1234)
print(results['name'])

results = whoisit.domain('example.com')
print(results['nameservers'])

results = whoisit.ip('1.2.3.4')
print(results['name'])

results = whoisit.ip('1.2.3.0/24')
print(results['name'])

results = whoisit.ip('2404:1234:1234:1234:1234:1234:1234:1234')
print(results['name'])

results = whoisit.ip('2404:1234::/32')
print(results['name'])

results = whoisit.entity('ARIN')
print(results['last_changed_date'])
```

Basic async examples:

```python
import whoisit
import asyncio

async def whoisit_lookups():
    results = await whoisit.asn_async(1234)
    print(results['name'])
    results = await whoisit.domain_async('example.com')
    print(results['nameservers'])
    results = await whoisit.ip_async('1.2.3.4')
    print(results['name'])
    results = await whoisit.ip_async('1.2.3.0/24')
    print(results['name'])
    results = await whoisit.ip_async('2404:1234:1234:1234:1234:1234:1234:1234')
    print(results['name'])
    results = await whoisit.ip_async('2404:1234::/32')
    print(results['name'])
    results = await whoisit.entity_async('ARIN')
    print(results['last_changed_date'])

loop = asyncio.get_event_loop()
loop.run_until_complete(whoisit.bootstrap_async())
loop.run_until_complete(whoisit_lookups())
loop.close()
```


### Raw response data

In each case `results` will be a dictionary containing the most useful information for
each request type. If the data you want is not in the response you can request the raw,
unparsed and large RDAP JSON data by adding the `raw=True` argument to the request, for
example:

```python
results = whoisit.domain('example.com', raw=True)
# 'results' is now the full, raw response from the RDAP service
```

If you want to obtain both the parsed and raw data you can use the `include_raw=True`
argument. In this case, the `results` will contain an additional `raw` key that contains the raw data. For example:

```python
results = whoisit.domain('example.com', include_raw=True)
# 'results' is the parsed response from whoisit
# the raw response can now be accessed as 'results["raw"]'
```

The `raw` and `include_raw` arguments cannot be used together. In such a case an `ArgumentError` will be raised.
```python
results = whoisit.domain('example.com', raw=True, include_raw=True)
# This raises a whoisit.errors.ArgumentError
```

### Specifying RDAP service / RIR

If for some reason you accidentally end up querying the wrong RDAP endpoint your query
should end up still working, for example if you query ARIN for information on the IP
address `1.1.1.1` it will redirect you to APNIC (where `1.1.1.1` is allocated)
automatically.

Some resources, most notably entity handles, do not redirect or have assigned obvious
namespaces linked to particular registries. For these queries `whoisit` will attempt to
guess the RDAP service to query by examining the name for prefixes or postfix, such as
many RIPE entities are named `RIPE-SOMETHING`. If your entity does not have an obvious
prefix or postfix like `ARIN-*` or `*-AP` you will need to tell `whoisit` which registry
to make the request to by specifying the `rir=name` argument. The `rir` argument stands
for "Regional Internet Registry". For example:

```python
# This will work OK because the entity is prefixed with an obvious RIR name
results = whoisit.entity('RIPE-NCC-MNT')

# This will cause a QueryError to be raised because ARIN returns a 404 for RIPE-NCC-MNT
results = whoisit.entity('RIPE-NCC-MNT', rir='arin')

# This will cause a UnsupportedError to be raised because we have no way to detect
# which RDAP service to query as the entity has no RIR prefix or postfix
results = whoisit.entity('AS5089-MNT')

# This will work OK because the entity is registered at RIPE
results = whoisit.entity('AS5089-MNT', rir='ripe')
```


### Weaken SSL ciphers

Some RDAP servers do not have particularly secure SSL implementations. As RDAP returns
read-only and public information it may be acceptable for you to want to downgrade the
security of your `whoisit` requests to successfully return data.

You can use the `allow_insecure_ssl=True` argument to your queries to enable this.

For example (as of 2021-07-25):

```python
# This will result in an SSL error
results = whoisit.domain('nic.work')
# ... SSLError(SSLError(1, '[SSL: DH_KEY_TOO_SMALL] dh key too small (_ssl.c:1129)')))

# This will work
results = whoisit.domain('nic.work', allow_insecure_ssl=True)
```

Note that with `allow_insecure_ssl=True` the upstream RDAP server certificate is
still validated, it just permits weaker SSL ciphers during the handshake. You should
only use `allow_insecure_ssl=True` if your request fails with an SSL cipher or
handshake error first.


### Domain lookup subrequests

Many RDAP endpoints for domains supply a related RDAP server run by a registry which
may contain more information about the domain. `whoisit` by default will attempt to
make a subrequest to the related RDAP endpoint if available to obtain more detailed
results. Occasionally, the related RDAP endpoints may fail or return data in an
invalid format. You can disable related RDAP endpoint subrequests by passing the
`follow_related=False` argument to `whoisit.domain(...)`. For example (as of 2024-04-30):

```python
results = whoisit.domain('example.com', follow_related=False)
```

If you encounter a parsing error when using related RDAP endpoint data you can also
skip the parsing by using `raw=True` but continue to use related RDAP data. `whoisit`
will attempt to handle the RDAP data returned but there will be occasions when RDAP
results change beyond what `whoisit` can parse. When using raw data you will need to
parse the data yourself.

You can also write a fallback:

```python
try:
    results = whoisit.domain('example.com')
    # Assume an error parsing the related RDAP data occurs here
except Exception as e:
    print(f'Failed to look up domain, trying fallback: {e}')
    results = whoisit.domain('example.com', follow_related=False)
    # Likely to succeed if the related RDAP data was the issue
```


## Bootstrapping

`whoisit` needs to know which RDAP service to query for a resource. This information is
provided by the IANA as bootstrapping information. Bootstrapping data simply says things
like "this CIDR is allocated to ARIN, this CIDR is allocated to RIPE" and so on for all
resources. The bootstrap data means you should be directly querying the correct RDAP
server for your request at all times. You should cache the bootstrap information locally
if you plan to make more than a single request otherwise you'll make additional requests
to the IANA every time you run a query. Example bootstrap information caching:

```python
import whoisit

print(whoisit.is_bootstrapped())  # -> False
whoisit.bootstrap()               # Slow, makes several HTTP requests to the IANA
print(whoisit.is_bootstrapped())  # -> True

# bootstrap_info returned here is a string of JSON serialised bootstap information
# You can store it in a memory cache or write it to disk for a few days
bootstrap_info = whoisit.save_bootstrap_data()

# Clear bootstrapping data
whoisit.clear_bootstrapping()

# Later, you can do
print(whoisit.is_bootstrapped())  # -> False
if not whoisit.is_bootstrapped():
    whoisit.load_bootstrap_data(bootstrap_info)  # Fast, no HTTP requests made
print(whoisit.is_bootstrapped())  # -> True

# For convenience internally whoisit stores a timestamp of when the bootstrap data was
# last updated and has a "is older than" helper method
if whoisit.bootstrap_is_older_than(days=3):
    # Bootstrap data was last updated over 3 days ago, refresh it
    whoisit.clear_bootstrapping()
    whoisit.bootstrap()
    bootstrap_info = whoisit.save_bootstrap_data()  # and save it to upload your cache
```

As of `whoisit` version 3.0.0 there is also an optional async interface:

```python
await whoisit.bootstrap_async()
```

A reasonable suggested way to handle bootstrapping data would be to use Memcached or
Redis, for example:

```python
import whoisit
import redis

r = redis.Redis(host='localhost', port=6379, db=0)

bootstrap_info = r.get('whoisit_bootstrap_info')
if bootstrap_info:
    whoisit.load_bootstrap_data(bootstrap_info)
else:
    whoisit.bootstrap()
    bootstrap_info = whoisit.save_bootstrap_data()
    expire_in_3_days = 60 * 60 * 24 *3
    r.set('whoisit_bootstrap_info', bootstrap_info, ex=expire_in_3_days)

# Send queries as normal once bootstrapped
whoisit.asn(12345)
```

Some services, most notably TLDs, do have RDAP servers which may not be set properly
in the IANA bootstrap data. `whoisit` maintains a record of these and can patch the
IANA data to allow more TLDs to be queried. You can enable this with the
`overrides=True` parameter when loading bootstrap data:

```python
whoisit.bootstrap(overrides=True)
```

or

```python
whoisit.load_bootstrap_data(bootstrap_info, overrides=True)
```

Both `whoisit.save_bootstrap_data()` and `whoisit.load_bootstrap_data(some_data)` also
support `as_json=True` as a default argument. The default operation is to return bootstrap
data as a JSON encoded string and load it from a JSON encoded string. If you want to
serialise the bootstrapping information in some other format you can use set `as_json=False` on
both `whoisit.save_bootstrap_data(as_json=False)` and
`whoisit.load_bootstrap_data(some_data, as_json=False)`. These methods will then return and
load a Python dictionary instead of JSON and you can perform serialisation yourself however
you need in your application.

**Important**: when using the overrides you may recieve non-standard data, data that
is not in the same format as officially listed IANA data and you may not recieve a copy
of any required terms of service or terms of use. You will have to manually verify data
returned by overridden endpoints.


### Insecure (HTTP) RDAP endpoints

Some RDAP servers are only available over HTTP and not HTTPS. This is disabled by
default. When you bootstrap `whoisit` a `debug` notice will be emitted for any RDAP
endpoint that is not loaded because it is insecure. For example:

```python
# Enable debug logging
import os
os.environ['DEBUG'] = 'true'
 # Load and boostrap whoisit
import whoisit
# > [datetime] bootstrap [DEBUG] Cleared bootstrap data
whoisit.bootstrap()
# > ... debug logs ...
# > [datetime] bootstrap [DEBUG] No valid RDAP service URLs could be parsed
#              from: ['http://cctld.uz:9000/'] (insecure scheme,
#              try whoisit.bootstrap(allow_insecure=True))
# > ... debug logs ...
# > [datetime] bootstrap [DEBUG] Bootstrapped
```

This line informs you that an RDAP endpoint has been skipped because it is only
available over HTTP. You can opt-in to allow insecure endpoints by calling the
bootstrap methods `bootstrap()` and `load_bootstrap_data()` with the optional
`allow_insecure=True` argument. For example:

```python
# Bootstrap with allowing insecure endpoints
whoisit.bootstrap(allow_insecure=True)
```

or

```python
# Load saved bootstrap data with allowing insecure endpoints
whoisit.load_bootstrap_data(bootstrap_info, allow_insecure=True)
```

## Proxies

You can specify an HTTP proxy to use for all requests made by `whoisit` by calling the
`set_proxy(...)` method. You can clear the proxy with `clear_proxy()`. All requests made
by `whoisit` will use the proxy specified by the last call to `set_proxy(...)`. For example:

```python
whoisit.set_proxy('http://127.0.0.1:8080')
# Both bootstrapping and the IP query for 1.1.1.1 will use the proxy at http://127.0.0.1:8080
whoisit.bootstrap()
result = whoisit.ip('1.1.1.1')
whoisit.clear_proxy()
# All future requests will not use a proxy
result = whoisit.domain('example.com')
```

You can switch or clear proxies at any time. Note that setting or clearing a proxy will also
reset the session. Proxies are supported by both the asynchonous and synchronous interfaces.

## Sessions

`whoisit` shared connection pools for all requests by default. This creates HTTP sessions that
are shared when multiple connections are made to the same RDAP endpoints. If required, you can
reset these sessions with the `clear_session()` method. For example:

```python
whoisit.clear_session()
```


## Response data

By default `whoisit` returns parsed, summary useful information. This information is
*simplified*. This means that some information is lost from the raw, original data. For
example, `whoisit` doesn't return the date that nameservers were last updated. If you
need more information than `whoisit` returns by default remember to add `raw=True` to
your query and parse the RDAP response yourself.

Data from `whoisit` is returned, where possible, as rich data types such as `datetime`,
`IPv4Network` and `IPv6Network` objects.

The following values are returned for every successful response:

```python
response = {
    'handle': str,               # Entity handle for the object, always set
    'parent_handle': str,        # Parent entity handle for the object
    'name': str,                 # Name of the object
    'whois_server': str,         # WHOIS server hostname object data can be found on
    'type': str,                 # Object type, such as autnum or domain
    'terms_of_service_url': str, # URL to the terms of service for using the object data
    'copyright_notice', str,     # Copyright notice for the object data
    'description': list,         # List of text lines that describe the object
    'last_changed_date': datetime or None,  # Date and time the object was last updated
    'registration_date': datetime or None,  # Date and time the object was registered
    'expiration_date': datetime or None,    # Date and time the object expires
    'rir': str,                  # Short name of the RIR for the object, such as 'arin'
    'url': str,                  # URL to the RDAP query which was made for this request
    'entities': dict,            # A dict of entities linked to the object
}
```

The entities dictionary has the following format, note there may be multiple entities
for each role:

```python
response['entities']['some_role'][] = { # Role names are strings, like 'registrant'
    'email': str,          # Email address of the entity
    'handle': str,         # Handle of the entity
    'name': str,           # Name of the entity
    'rir': str,            # Short name of the RIR where the entity is registered
    'type': str,           # Type of the entity, usually 'entity'
    'url': str,            # URL to an RDAP service to query this entity 
    'whois_server': str,   # WHOIS server hostname entity data can be found on
}
```

In addition to the default data for all responses listed above requests have additional
extra fields in their responses, these are:

### Additional ASN response data

```python
# ASN response data includes all shared general response fields above and also:
response = {
    'asn_range': list,       # A list of the start and end range for an AS allocation
                             # For example, [123,134] or [123,123]
}
```

### Additional domain response data

```python
# Domain response data includes all shared general response fields above and also:
response = {
    'unicode_name': str,     # Domain name in unicode if available
    'nameservers': list,     # List of name servers for the domain as strings
    'status': list,          # List of the domain states as strings
}
```

### Additional IP response data

```python
# IP response data includes all shared general response fields above and also:
response = {
    'country': str,          # Two letter country code for the IP block
    'ip_version': int,       # 4 or 6 to denote the IP version
    'assignment_type': str,  # Assignment type, such as 'assigned portable'
    'network': IPvXNetwork,  # A IPv4Network or IPv6Network object for the prefix
}
```

### Additional entity response data

```python
# Entity response data includes all shared general response fields above and also:
response = {
    'email': str,            # If the entity as a root vcard the email address
}
```

### Full response example

A full example response for an IP query for the IPv4 address `1.1.1.1`:

```python
import whoisit
whoisit.bootstrap()
response = whoisit.ip('1.1.1.1')
print(response)
{
    'handle': '1.1.1.0 - 1.1.1.255',
    'parent_handle': '',
    'name': 'APNIC-LABS',
    'whois_server': 'whois.apnic.net',
    'type': 'ip network',
    'terms_of_service_url': 'http://www.apnic.net/db/dbcopyright.html',
    'copyright_notice': '',
    'description': [
        'APNIC and Cloudflare DNS Resolver project',
        'Routed globally by AS13335/Cloudflare',
        'Research prefix for APNIC Labs'
    ],
    'last_changed_date': datetime.datetime(2020, 7, 15, 13, 10, 57, tzinfo=tzutc()),
    'registration_date': None,
    'expiration_date': None,
    'url': 'https://rdap.apnic.net/ip/1.1.1.0/24',
    'rir': 'apnic',
    'entities': {
        'abuse': [
            {
                'handle': 'IRT-APNICRANDNET-AU',
                'url': 'https://rdap.apnic.net/entity/IRT-APNICRANDNET-AU',
                'type': 'entity',
                'name': 'IRT-APNICRANDNET-AU',
                'email': 'helpdesk@apnic.net',
                'rir': 'apnic'
            }
        ],
        'administrative': [
            {
                'handle': 'AR302-AP',
                'url': 'https://rdap.apnic.net/entity/AR302-AP',
                'type': 'entity',
                'name': 'APNIC RESEARCH',
                'email': 'research@apnic.net',
                'rir': 'apnic'
            }
        ],
        'technical': [
            {
                'handle': 'AR302-AP',
                'url': 'https://rdap.apnic.net/entity/AR302-AP',
                'type': 'entity',
                'name': 'APNIC RESEARCH',
                'email': 'research@apnic.net',
                'rir': 'apnic'
        ]
    },
    'country': 'AU',
    'ip_version': 4,
    'assignment_type': 'assigned portable',
    'network': IPv4Network('1.1.1.0/24')
}
```

## Full API synopsis

### `whoisit.is_bootstrapped()` -> `bool`

Returns boolean True or False if your `whoisit` instance is bootstrapped or not.

### `whoisit.bootstrap(overrides=bool, allow_insecure=bool)` -> `bool`

Bootstraps your `whoisit` instance with remote IANA bootstrap information. Returns
True or raises a `whoisit.errors.BootstrapError` exception if it fails. This method
makes HTTP requests to the IANA.

### `whoisit.clear_bootstrapping()` -> `bool`

Clears any stored bootstrap information. Always returns boolean True.

### `whoisit.save_bootstrap_data()` -> `str`

Returns a string of JSON serialised bootstrap information if any is loaded. If no
bootstrap information loaded a `whoisit.errors.BootstrapError` will be raised.

### `whoisit.load_bootstrap_data(data=str, overrides=bool, allow_insecure=bool)` -> `bool`

Loads a string of JSON serialised bootstrap data as returned by `save_bootstrap_data()`.
Returns True if the data is loaded or raises a `whoisit.errors.BootstrapError` if
loading fails.

### `whoisit.bootstrap_is_older_than(days=int)` -> `bool`

Tests if the loaded bootstrap data is older than the specified number of days as an
integer. Returns True or False. If no bootstrap information is loaded a
`whoisit.errors.BootstrapError` exception will be raised.

### `whoisit.asn(asn=int, rir=str, raw=bool, include_raw=False, allow_insecure_ssl=bool)` -> `dict`

Queries a remote RDAP server for information about the specified AS number. AS number
must be an integer. Returns a dict of information. If `raw=True` is passed a large dict
of the raw RDAP response will be returned. If `include_raw` is passed the raw RDAP response will be included in the parsed response under the `raw` key. If both `raw` and `include_raw` are set a `whoisit.errors.ArgumentError` will be raised. If the query fails a
`whoisit.errors.QueryError` exception will be raised. If no bootstrap data is loaded
a `whoisit.errors.BootstrapError` exception will be raised. if `allow_insecure_ssl=True`
is passed the RDAP queries will allow weaker SSL handshakes. Examples:

```python
whoisit.asn(12345)
whoisit.asn(12345, rir='arin')
whoisit.asn(12345, raw=True)
whoisit.asn(12345, include_raw=True)
whoisit.asn(12345, rir='arin', raw=True)
whoisit.asn(12345, allow_insecure_ssl=True)
```

As of `whoisit` version 3.0.0 there is also an optional async interface:

```python
response = await whoisit.asn_async(12345)
```

### `whoisit.domain(domain=str, raw=bool, include_raw=False, allow_insecure_ssl=bool)` -> `dict`

Queries a remote RDAP server for information about the specified domain name. The domain
name must be a string and in a valid domain name "something.tld" style format. Returns a
dict of information. If `raw=True` is passed a large dict of the raw RDAP response will
be returned. If `include_raw` is passed the raw RDAP response will be included in the parsed response under the `raw` key. If both `raw` and `include_raw` are set a `whoisit.errors.ArgumentError` will be raised. If the query fails a `whoisit.errors.QueryError` exception will be raised.
If no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be
raised. If the TLD is unsupported a `whoisit.errors.UnsupportedError` exception will be
raised.  if `allow_insecure_ssl=True` is passed the RDAP queries will allow weaker SSL
handshakes. **Note that not all TLDs are supported, only some have RDAP services!**
Examples:

```python
whoisit.domain('example.com')
whoisit.domain('example.com', raw=True)
whoisit.domain('example.com', include_raw=True)
whoisit.domain('example.com', allow_insecure_ssl=True)
```

As of `whoisit` version 3.0.0 there is also an optional async interface:

```python
response = await whoisit.domain_async('example.com')
```

### `whoisit.ip(ip="1.1.1.1", rir=str, raw=bool, include_raw=False, allow_insecure_ssl=bool)` -> `dict`

Queries a remote RDAP server for information about the specified IP address or CIDR. The
IP address or CIDR must be a string and in the correct IP address or CIDR format or
any one of IPv4Address, IPv4Network, IPv6Address or IPv6Network objects. Returns a dict
of information. If `raw=True` is passed a large dict of the raw RDAP response will be
returned. If `include_raw` is passed the raw RDAP response will be included in the parsed response under the `raw` key. If both `raw` and `include_raw` are set a `whoisit.errors.ArgumentError` will be raised. If the query fails a `whoisit.errors.QueryError` exception will be raised. If
no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be raised.
if `allow_insecure_ssl=True` is passed the RDAP queries will allow weaker SSL handshakes.
Examples:

```python
whoisit.ip('1.1.1.1')
whoisit.ip('1.1.1.1', rir='apnic')
whoisit.ip('1.1.1.1', raw=True, rir='apnic')
whoisit.ip('1.1.1.1', include_raw=True, rir='apnic')
whoisit.ip('1.1.1.0/24')
whoisit.ip(IPv4Address('1.1.1.1'))
whoisit.ip(IPv4Network('1.1.1.0/24'))
whoisit.ip(IPv6Address('2001:4860:4860::8888'))
whoisit.ip(IPv6Network('2001:4860::/32'), rir='arin')
whoisit.ip('1.1.1.1', allow_insecure_ssl=True)
```

As of `whoisit` version 3.0.0 there is also an optional async interface:

```python
response = await whoisit.ip_async('1.1.1.1')
```

### `whoisit.entity(entity=str, rir=str, raw=bool, include_raw=False, allow_insecure_ssl=bool)` -> `dict`

Queries a remote RDAP server for information about the specified entity name. The
entity name must be a string and in the correct entity format. Returns a dict of
information. If `raw=True` is passed a large dict of the raw RDAP response will be
returned. If `include_raw` is passed the raw RDAP response will be included in the parsed response under the `raw` key. If both `raw` and `include_raw` are set a `whoisit.errors.ArgumentError` will be raised. If the query fails a `whoisit.errors.QueryError` exception will be raised.
If no bootstrap data is loaded a `whoisit.errors.BootstrapError` exception will be
raised. if `allow_insecure_ssl=True` is passed the RDAP queries will allow weaker
SSL handshakes. Examples:

```python
whoisit.entity('ZG39-ARIN')
whoisit.entity('ZG39-ARIN', rir='arin')
whoisit.entity('ZG39-ARIN', rir='arin', raw=True)
whoisit.entity('ZG39-ARIN', rir='arin', include_raw=True)
whoisit.entity('ZG39-ARIN', allow_insecure_ssl=True)
```

As of `whoisit` version 3.0.0 there is also an optional async interface:

```python
response = await whoisit.entity_async('ZG39-ARIN')
```


## Data usage

All data returned by RDAP servers are covered by the various policies embeddd in the
results. As such you should carefuly review your usage of the data to make sure it
complies with the policy of the RDAP server you are querying.


## Excessive use

As an API client `whoisit` is entirely subject to the resource and request limits
applied by the remote RDAP servers it queries. If you recieve request errors for rate
limiting you should slow down your requests. Different servers have different limits.
The LACNIC RDAP server in particular only permits a low number of requests per minute.


# Tests

There is a test suite that you can run by cloning this repository, installing the
required dependancies and execuiting:

```bash
$ make test
```


# Debugging

`whoisit` will check for a `DEBUG` environment variable and if set, will output debug
logs that detail the internals for the bootstrapping, requests and parsing operations.
If you want to enable debug logging, set `DEBUG=true` (or `1` or `y` etc.). For example:

```bash
$ export DEBUG=true
$ python3 some-script-that-uses-whoisit.py
```


# Contributing

All properly formatted and sensible pull requests, issues and comments are welcome.


---

# Patches & Extended Features

The following patches have been applied to this library to support high-volume RDAP
collection and richer data retrieval.

---

## Patch 1 — `return_on_error`

Some RDAP servers return a JSON body even for HTTP error responses (404, 429, etc.)
that contains useful information (e.g. "Blocked Domain" notices).

With `return_on_error=True` the raw JSON body is returned with an added `_rdap_error`
key instead of raising an exception:

```python
result = whoisit.domain('youtube.cash', raw=True, return_on_error=True)
# Returns the RDAP body plus:
# { "_rdap_error": { "status_code": 404, "error_type": "ResourceDoesNotExist", ... } }
```

Available on: `domain()`, `domain_async()`, `ip()`, `asn()`.

---

## Patch 2 — `allow_invalid_certificate`

Some RDAP servers have invalid or self-signed SSL certificates.
`allow_insecure_ssl=True` only permits weaker ciphers; it still validates the
certificate. Use `allow_invalid_certificate=True` to skip certificate validation
entirely:

```python
result = whoisit.domain('instagram.gs', allow_invalid_certificate=True)
```

---

## Patch 3 — Rate-limit & timeout optimisation

For bulk collection:
- HTTP timeout reduced from 10 s → 5 s (faster failure on unresponsive servers)
- `http_retry_statuses = []` — no automatic retries on 429 (handled by the pool)

---

## Patch 4 — Registrar RDAP follow-up + `RDAPPool`

### Registrar RDAP bootstrap

During `whoisit.bootstrap()`, the IANA registrar-ids XML
(`https://www.iana.org/assignments/registrar-ids/registrar-ids.xml`) is parsed to
build a mapping of IANA registrar ID → registrar RDAP base URL.

```python
url = whoisit.get_registrar_rdap_url("1448")
# -> "https://rdap.netistrar.com/"
```

#### `get_registrar_info(iana_id)` — full registrar record

Returns a dict with the IANA ID and RDAP URL for a registrar.  Useful for
hybrid clients that need to bridge a WHOIS-derived IANA ID to an RDAP endpoint:

```python
info = whoisit.get_registrar_info(146)
# -> {"iana_id": 146, "rdap_url": "https://rdap.godaddy.com/"}

info = whoisit.get_registrar_info(99999)
# -> {"iana_id": 99999, "rdap_url": None}   # unknown registrar
```

### `follow_rdap_registrar` (default: `True`)

When `follow_rdap_registrar=True` (the default since Patch 5), after the primary
registry RDAP query the registrar's IANA ID is extracted and its own RDAP endpoint
is queried.  The result is a dict with two separate keys — **`registry`** and
**`registrar`** — so both responses are preserved intact:

```python
result = await whoisit.domain_async("c.wales", raw=True, rdap_pool=pool)
# {
#   "registry":  { ...full registry RDAP response... },
#   "registrar": { ...full registrar RDAP response... },
# }
```

If the registrar endpoint is unknown or unavailable, `"registrar"` is `None`
(or an `_rdap_error` dict on HTTP failure).

Set `follow_rdap_registrar=False` to get the original flat registry-only response.

### `_rdap_source` — data source metadata

Every raw RDAP response dict now includes a `_rdap_source` key that records where
the data came from:

```python
result = await whoisit.domain_async("ask.fm", raw=True)

result["registry"]["_rdap_source"]
# {
#   "url":         "https://rdap.centralnic.com/fm/domain/ask.fm",
#   "domain":      "ask.fm",
#   "status_code": 200,
# }

result["registrar"]["_rdap_source"]
# {
#   "url":         "https://rdap.instra.com/domain/ask.fm",
#   "domain":      "ask.fm",
#   "status_code": 404,   # error responses show the real HTTP code
# }
```

`status_code` is `200` for successful responses and the actual HTTP error code
(404, 429, etc.) for responses captured via `return_on_error=True`.

### `RDAPPool` — per-hostname rate limiting

```python
pool = whoisit.create_rdap_pool(max_requests_per_hostname=1)

result = await whoisit.domain_async("example.com", rdap_pool=pool)
```

All requests (registry + registrar follow-up) are routed through the pool.
Delays are pre-loaded from `whoisit/data/rdap_host_delay.json`.

---

## Patch 5 — Advanced pool features

### Wildcard hostname matching

`whoisit/data/rdap_registrar_host_delay.json` now supports wildcard keys:

```json
{ "*.rdap.tucows.com": { "delay": 60 } }
```

All subdomains of `rdap.tucows.com` (e.g. `dreamhost.rdap.tucows.com`,
`opensrs.rdap.tucows.com`) share a **single** rate-limit queue.

### Endpoint blacklist

Endpoints listed in `whoisit/data/blacklist_rdap_endpoint.json` are never queried.
Default blacklist: `rdap.dynadot.com`, `rdap.wix.com`, `rdap.globaldomaingroup.com`,
`rdap.park.io`, `rdap.routing.net`.

### Smart 429 handling

On a 429 response the pool applies a three-step retry strategy:

1. **Immediate retry** — covers rate-limiters that fire spuriously on the first
   request (e.g. `rdap.synergywholesale.com`).
2. **Header-based sleep** — checks `retry-after`, `x-ratelimit-reset`, or
   `ratelimit-policy` response headers for the correct sleep duration.
   Values larger than 3600 are treated as Unix timestamps (`value % 3600`).
3. **File-delay fallback** — if no useful headers are present, sleeps for the
   delay configured in the host-delay JSON files.
4. **Disable endpoint** — if a third 429 is received, the endpoint is disabled
   for the remainder of the session.

### `max_sleep_by_endpoint`

If the computed sleep for a 429 exceeds this threshold the endpoint is disabled
rather than waited on:

```python
pool = whoisit.create_rdap_pool(max_sleep_by_endpoint=90)  # default: 90 s
```

### Status persistence (`data/status.json`)

The last-request wall-clock timestamp for each endpoint pool is written to
`whoisit/data/status.json` via a dedicated background writer thread.  On the
next run, delays account for time already elapsed since the last request, so you
never wait the full configured delay unnecessarily after a restart.

The file is flushed every 5 s by the background thread, and immediately on
`KeyboardInterrupt` / `Ctrl+C`.

### `check_domains` / `check_domains_async`

Query many domains concurrently with a single call:

```python
import whoisit

whoisit.bootstrap(overrides=True)

# Synchronous (blocks until done)
results = whoisit.check_domains(
    ["example.com", "test.org", "github.com"],
    follow_rdap_registrar=True,
)
for domain, result in results.items():
    if "_rdap_error" in result:
        print(f"{domain}: error – {result['_rdap_error']['message']}")
    else:
        print(f"{domain}: {result.get('name')}")

# Asynchronous with streaming callback
async def on_result(domain, result):
    print(f"Got result for {domain}")

results = await whoisit.check_domains_async(
    ["example.com", "test.org"],
    callback=on_result,
    max_total_time=300,          # stop after 5 minutes
    max_sleep_by_endpoint=90,    # skip endpoints that need > 90 s sleep
    follow_rdap_registrar=True,
)
```

**Parameters:**

| Parameter | Default | Description |
|-----------|---------|-------------|
| `callback` | `None` | `callable(domain, result)` called as each result arrives |
| `max_total_time` | `86400` | Stop and mark pending domains with `_rdap_error` after this many seconds. `None` = unlimited |
| `max_sleep_by_endpoint` | `90` | Passed to `create_rdap_pool()` |
| `follow_rdap_registrar` | `True` | Also query registrar RDAP, returns `{"registry": ..., "registrar": ...}` |
| `rdap_pool` | `None` | Provide an existing pool; one is created otherwise |

Pending domains whose result could not be retrieved before `max_total_time` are
returned as:
```python
{"_rdap_error": {"message": "max_total_time exceeded"}}
```

### Updated `create_rdap_pool`

```python
pool = whoisit.create_rdap_pool(
    max_requests_per_hostname=1,   # concurrent requests per host
    max_sleep_by_endpoint=90.0,    # skip if delay > 90 s
    use_status=True,               # persist status.json
    max_total_concurrent=50,       # optional: global cap across all endpoints
)
```

#### `max_total_concurrent` — global concurrency cap

By default there is **no global cap**: each endpoint is only constrained by its
own per-hostname semaphore (`max_requests_per_hostname`).  When querying
hundreds of distinct endpoints at once (e.g. `check_domains_async` on a large
list), this can open hundreds of simultaneous TCP connections.

`max_total_concurrent` adds a single `asyncio.Semaphore` shared across all
endpoints that limits the total number of in-flight requests at any moment:

```python
# At most 50 RDAP requests in flight at once, regardless of how many
# distinct endpoints are involved.
pool = whoisit.create_rdap_pool(max_total_concurrent=50)

results = await whoisit.check_domains_async(
    many_domains,   # e.g. 500 domains across 300 different registries
    rdap_pool=pool,
)
```

The global semaphore is acquired **before** the per-hostname semaphore, so
both limits apply simultaneously.  `None` (the default) disables the global
cap entirely.

The pool is pre-loaded with:
- Registry delays from `whoisit/data/rdap_host_delay.json`
- Registrar delays from `whoisit/data/rdap_registrar_host_delay.json`
  (wildcard patterns supported)
- Blacklist from `whoisit/data/blacklist_rdap_endpoint.json`

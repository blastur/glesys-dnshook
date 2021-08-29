# GleSYS hook for `dehydrated`

This is a hook for the [Let's Encrypt](https://letsencrypt.org/) ACME client
[dehydrated](https://github.com/lukas2511/dehydrated) (previously known as
`letsencrypt.sh`) that allows you to use [GleSYS](https://www.glesys.com/) DNS
records to respond to `dns-01` challenges.

The hook requires Python 3.x, a GleSYS account and an API key.

## Installation

```
$ git clone https://github.com/lukas2511/dehydrated
$ cd dehydrated
$ mkdir hooks
$ git clone https://github.com/blastur/glesys-dnshook.git hooks/glesys
```

Ensure that the `dig` tool is installed and in your PATH. It's used by the hook
to verify DNS propagation. If you're using a Debian/Ubuntu-based system, you can
get Dig through the dnsutils package:

```
    $ apt-get install dnsutils
```

## Configuration

Your account's GleSYS account name and API key are expected to be in the
environment, so make sure to:

```
    $ export GLESYS_USER='CL12345'
    $ export GLESYS_KEY='AvMCkh0Ykeifz10qQri5IoF442mnW65GBRj69t4A'
```

You can obtain an API key by logging onto the GleSYS customer portal at
https://customer.glesys.com/.

## Usage

Refer to the dehydrated README for information on how setup it up. For the
impatient:

```
    $ ./dehydrated --register
```
Read and accept the terms, as the output suggest.

Once setup, you can sign/renew a certificate like so:

```
    ./dehydrated -c -t dns-01 -k hooks/glesys/hook.py --domain mycooldomain.se
```

(mycooldomain.se must obviously be managed by GleSYS)

You can simplify the call to dehydrated by creating a config and domains.txt
file. See the dehyrated docs/ for more information. The dehyrated config is
also a good place to store hook config, as it is sourced automatically. For
example:

```
    echo "export GLESYS_USER=user@example.com" >> config
    echo "export GLESYS_KEY=AvMCkh0Ykeifz10qQri5IoF442mnW65GBRj69t4A" >> config
```


## Advanced configuration

By default, Glesys DNS serves (ns1.namesystem.se) are used to verify DNS propagation.
This is the same servers used by LetsEncrypt to verify the challenge. If you still
wish to change the verification DNS, you may set the GLESYS_DNS_SERVER
environment variable:

```
$ export GLESYS_DNS_SERVER='1.2.3.4'
```

It'll wait for 300 seconds for the record to propagate. You can override the
timeout via the `GLESYS_PROPAGATION_TIMEOUT` environment variable (specified
in seconds):

```
$ export GLESYS_PROPAGATION_TIMEOUT=500
```

If you want more information about what is going on while the hook is running:

```
$ export GLESYS_HOOK_DEBUG='1'
```

Like the basic configuration (GLESYS_USER and GLESYS_KEY), you can put these
into the dehydrated config to automatically set them up when dehydrated run.

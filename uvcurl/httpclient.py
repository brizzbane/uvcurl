import logging

import time
import functools
import pyuv
import pycurl

from io import BytesIO
from concurrent.futures import Future

from tornado import httputil
from tornado.escape import utf8, native_str


import collections
from uvcurl.config import configure_logging

configure_logging()

logger = logging.getLogger('cURLclient')
debug, info, warn, error, critical = logger.debug, logger.info, logger.warn, logger.error, logger.critical

class cURLHTTPClient(object):
    def __init__(self, ioloop, max_clients=500):
        self.defaults = dict(cURLHTTPRequest._DEFAULTS)
        self.ioloop = ioloop
        self._timer = pyuv.Timer(self.ioloop)
        self._fd_map = {}
        self._multi = pycurl.CurlMulti()
        self._multi.setopt(pycurl.M_TIMERFUNCTION, self._set_timeout)
        self._multi.setopt(pycurl.M_SOCKETFUNCTION, self._sock_state_cb)
        self._curls = [self._curl_create() for _ in range(max_clients)]
        self._free_list = self._curls[:]
        self._requests = collections.deque()



    def req(self, request, raise_error=True):
        future = Future()
        def handle_response(response):
            if raise_error and response.error:
                future.set_exception(response.error)
            else:
                future.set_result(response)

        self._requests.append((request, handle_response))
        self._process_queue()
        self._set_timeout(0)
        return future


    def _process_queue(self):
        while True:
            started = 0
            while self._free_list and self._requests:
                started += 1
                curl = self._free_list.pop()
                (request, callback) = self._requests.popleft()

                request = _RequestProxy(request, self.defaults)
                curl.info = {
                    "headers": httputil.HTTPHeaders(),
                    "buffer": BytesIO(),
                    "request": request,
                    "callback": callback,
                    "curl_start_time": time.time(),
                }
                self._curl_setup_request(curl, request, curl.info['buffer'])
                self._multi.add_handle(curl)

            if not started:
                break


    def _set_timeout(self, msecs):
        debug(msecs)
        if msecs >= 0:
            timeout = msecs / 1000.0
            debug('timeout %s' % timeout)
            self._timer.start(self._timer_cb, timeout, 0)

    def _timer_cb(self, timer):
        self._timer.stop()
        debug('timer obj %s' % timer)
        while True:
            try:
                ret, num_handles = self._multi.socket_action( pycurl.SOCKET_TIMEOUT, 0)
                if ret != pycurl.E_CALL_MULTI_PERFORM:
                    break
            except pycurl.error as e:
                ret = e.args[0]

        self._finish_pending_requests()

    def _curl_create(self):
        curl = pycurl.Curl()
        curl.setopt(pycurl.VERBOSE, 1)
        curl.setopt(pycurl.DEBUGFUNCTION, self._curl_debug)
        return curl

    def _curl_setup_request(self, curl, request, buffer):
        curl.setopt(pycurl.URL, native_str(request.url))

        # libcurl's magic "Expect: 100-continue" behavior causes delays
        # with servers that don't support it (which include, among others,
        # Google's OpenID endpoint).  Additionally, this behavior has
        # a bug in conjunction with the curl_multi_socket_action API
        # (https://sourceforge.net/tracker/?func=detail&atid=100976&aid=3039744&group_id=976),
        # which increases the delays.  It's more trouble than it's worth,
        # so just turn off the feature (yes, setting Expect: to an empty
        # value is the official way to disable this)
        if "Expect" not in request.headers:
            request.headers["Expect"] = ""

        # libcurl adds Pragma: no-cache by default; disable that too
        if "Pragma" not in request.headers:
            request.headers["Pragma"] = ""

        curl.setopt(pycurl.HTTPHEADER,
                    ["%s: %s" % (native_str(k), native_str(v))
                     for k, v in request.headers.items()])

        curl.setopt(pycurl.HEADERFUNCTION,
                   functools.partial(self._curl_header_callback,
                                      curl.info['headers']))
        write_function = buffer.write
        if bytes is str:  # py2
            curl.setopt(pycurl.WRITEFUNCTION, write_function)
        else:  # py3
            # Upstream pycurl doesn't support py3, but ubuntu 12.10 includes
            # a fork/port.  That version has a bug in which it passes unicode
            # strings instead of bytes to the WRITEFUNCTION.  This means that
            # if you use a WRITEFUNCTION (which tornado always does), you cannot
            # download arbitrary binary data.  This needs to be fixed in the
            # ported pycurl package, but in the meantime this lambda will
            # make it work for downloading (utf8) text.
            curl.setopt(pycurl.WRITEFUNCTION, lambda s: write_function(utf8(s)))
        curl.setopt(pycurl.FOLLOWLOCATION, request.follow_redirects)
        curl.setopt(pycurl.MAXREDIRS, request.max_redirects)
        curl.setopt(pycurl.CONNECTTIMEOUT_MS, int(1000 * request.connect_timeout))
        curl.setopt(pycurl.TIMEOUT_MS, int(1000 * request.request_timeout))
        if request.user_agent:
            curl.setopt(pycurl.USERAGENT, native_str(request.user_agent))
        else:
            curl.setopt(pycurl.USERAGENT, "Mozilla/5.0 (compatible; pycurl)")
        if request.network_interface:
            curl.setopt(pycurl.INTERFACE, request.network_interface)
        if request.decompress_response:
            curl.setopt(pycurl.ENCODING, "gzip,deflate")
        else:
            curl.setopt(pycurl.ENCODING, "none")
        if request.proxy_host and request.proxy_port:
            curl.setopt(pycurl.PROXY, request.proxy_host)
            curl.setopt(pycurl.PROXYPORT, request.proxy_port)
            if request.proxy_username:
                credentials = '%s:%s' % (request.proxy_username,
                                         request.proxy_password)
                curl.setopt(pycurl.PROXYUSERPWD, credentials)
        else:
            curl.setopt(pycurl.PROXY, '')
            curl.unsetopt(pycurl.PROXYUSERPWD)

        if request.validate_cert:
            curl.setopt(pycurl.SSL_VERIFYPEER, 1)
            curl.setopt(pycurl.SSL_VERIFYHOST, 2)
        else:
            curl.setopt(pycurl.SSL_VERIFYPEER, 0)
            curl.setopt(pycurl.SSL_VERIFYHOST, 0)
        if request.ca_certs is not None:
            curl.setopt(pycurl.CAINFO, request.ca_certs)
        else:
            # There is no way to restore pycurl.CAINFO to its default value
            # (Using unsetopt makes it reject all certificates).
            # I don't see any way to read the default value from python so it
            # can be restored later.  We'll have to just leave CAINFO untouched
            # if no ca_certs file was specified, and require that if any
            # request uses a custom ca_certs file, they all must.
            pass

        if request.allow_ipv6 is False:
            # Curl behaves reasonably when DNS resolution gives an ipv6 address
            # that we can't reach, so allow ipv6 unless the user asks to disable.
            curl.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_V4)
        else:
            curl.setopt(pycurl.IPRESOLVE, pycurl.IPRESOLVE_WHATEVER)

        # Set the request method through curl's irritating interface which makes
        # up names for almost every single method
        curl_options = {
            "GET": pycurl.HTTPGET,
            "POST": pycurl.POST,
            "PUT": pycurl.UPLOAD,
            "HEAD": pycurl.NOBODY,
        }
        custom_methods = set(["DELETE", "OPTIONS", "PATCH"])
        for o in curl_options.values():
            curl.setopt(o, False)
        if request.method in curl_options:
            curl.unsetopt(pycurl.CUSTOMREQUEST)
            curl.setopt(curl_options[request.method], True)
        elif request.allow_nonstandard_methods or request.method in custom_methods:
            curl.setopt(pycurl.CUSTOMREQUEST, request.method)
        else:
            raise KeyError('unknown method ' + request.method)

        body_expected = request.method in ("POST", "PATCH", "PUT")
        body_present = request.body is not None
        if not request.allow_nonstandard_methods:
            # Some HTTP methods nearly always have bodies while others
            # almost never do. Fail in this case unless the user has
            # opted out of sanity checks with allow_nonstandard_methods.
            if ((body_expected and not body_present) or
                    (body_present and not body_expected)):
                raise ValueError(
                    'Body must %sbe None for method %s (unless '
                    'allow_nonstandard_methods is true)' %
                    ('not ' if body_expected else '', request.method))

        if body_expected or body_present:
            if request.method == "GET":
                # Even with `allow_nonstandard_methods` we disallow
                # GET with a body (because libcurl doesn't allow it
                # unless we use CUSTOMREQUEST). While the spec doesn't
                # forbid clients from sending a body, it arguably
                # disallows the server from doing anything with them.
                raise ValueError('Body must be None for GET request')
            request_buffer = BytesIO(utf8(request.body or ''))

            def ioctl(cmd):
                if cmd == curl.IOCMD_RESTARTREAD:
                    request_buffer.seek(0)
            curl.setopt(pycurl.READFUNCTION, request_buffer.read)
            curl.setopt(pycurl.IOCTLFUNCTION, ioctl)
            if request.method == "POST":
                curl.setopt(pycurl.POSTFIELDSIZE, len(request.body or ''))
            else:
                curl.setopt(pycurl.UPLOAD, True)
                curl.setopt(pycurl.INFILESIZE, len(request.body or ''))

        if request.auth_username is not None:
            userpwd = "%s:%s" % (request.auth_username, request.auth_password or '')

            if request.auth_mode is None or request.auth_mode == "basic":
                curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_BASIC)
            elif request.auth_mode == "digest":
                curl.setopt(pycurl.HTTPAUTH, pycurl.HTTPAUTH_DIGEST)
            else:
                raise ValueError("Unsupported auth_mode %s" % request.auth_mode)

            curl.setopt(pycurl.USERPWD, native_str(userpwd))





    def _finish_pending_requests(self):
        """Process any requests that were completed by the last
        call to multi.socket_action.
        """
        while True:
            num_q, ok_list, err_list = self._multi.info_read()
            for curl in ok_list:
                self._finish(curl)
            for curl, errnum, errmsg in err_list:
                self._finish(curl, errnum, errmsg)
            if num_q == 0:
                break
        self._process_queue()



    def _finish(self, curl, curl_error=None, curl_message=None):
        info = curl.info
        curl.info = None
        self._multi.remove_handle(curl)
        self._free_list.append(curl)
        buffer = info["buffer"]
        if curl_error:
            error = cURLError(curl_error, curl_message)
            code = error.code
            effective_url = None
            buffer.close()
            buffer = None
        else:
            error = None
            code = curl.getinfo(pycurl.HTTP_CODE)
            effective_url = curl.getinfo(pycurl.EFFECTIVE_URL)
            buffer.seek(0)
        # the various curl timings are documented at
        # http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html
        time_info = dict(
            queue=info["curl_start_time"] - info["request"].start_time,
            namelookup=curl.getinfo(pycurl.NAMELOOKUP_TIME),
            connect=curl.getinfo(pycurl.CONNECT_TIME),
            pretransfer=curl.getinfo(pycurl.PRETRANSFER_TIME),
            starttransfer=curl.getinfo(pycurl.STARTTRANSFER_TIME),
            total=curl.getinfo(pycurl.TOTAL_TIME),
            redirect=curl.getinfo(pycurl.REDIRECT_TIME),
        )
        try:
            info["callback"](HTTPResponse(
                request=info["request"], code=code, headers=info["headers"],
                buffer=buffer, effective_url=effective_url, error=error,
                reason=info['headers'].get("X-Http-Reason", None),
                request_time=time.time() - info["curl_start_time"],
                time_info=time_info))
        except Exception:
            pass



           # self.handle_callback_exception(info["callback"])
    def _handle_force_timeout(self, timer):
        """Called by IOLoop periodically to ask libcurl to process any
        events it may have forgotten about.
        """
        info(timer)
        while True:
            try:
                ret, num_handles = self._multi.socket_all()
            except pycurl.error as e:
                ret = e.args[0]
            if ret != pycurl.E_CALL_MULTI_PERFORM:
                break
        self._finish_pending_requests()

    def _sock_state_cb(self, event, fd, multi, data):
       # error('event obj %s, fd %s, multi %s, data %s' % (event, fd, multi, data))

        event_map = {
            pycurl.POLL_NONE: None,
            pycurl.POLL_IN: pyuv.UV_READABLE,
            pycurl.POLL_OUT: pyuv.UV_WRITABLE,
            pycurl.POLL_INOUT: pyuv.UV_READABLE | pyuv.UV_WRITABLE
        }
        if fd not in self._fd_map:
            handle = pyuv.Poll(self.ioloop, fd)
            self._fd_map[fd] = handle

        handle = self._fd_map[fd]
        if event == pycurl.POLL_NONE:
            handle = pyuv.Poll(self.ioloop, fd)
            self._fd_map[fd] = handle

        elif event == pycurl.POLL_REMOVE:
            if fd in self._fd_map:
                handle = self._fd_map.pop(fd)
                handle.close()

        elif event == pycurl.POLL_IN:
            handle.start(pyuv.UV_READABLE, self._poll_in_cb)

        elif event == pycurl.POLL_OUT:
            handle.start(pyuv.UV_WRITABLE, self._poll_out_cb)

        elif event == pycurl.POLL_INOUT:
            handle.start((pyuv.UV_WRITABLE|pyuv.UV_READABLE), self._poll_out_cb)

    def _poll_in_cb(self, handle, events, error):
        if error is not None:
            return
        action = 0
        if events & pyuv.UV_READABLE:
            action |= pycurl.CSELECT_IN
            ret, num_handles = self._multi.socket_action(handle.fileno(), action)
           # self._finish_pending_requests()

    def _poll_out_cb(self, handle, events, error):
        if error is not None:
            return
        action = 0
        if events & pyuv.UV_WRITABLE:
            action |= pycurl.CSELECT_OUT
            ret, num_handles = self._multi.socket_action(handle.fileno(), action)
          #  self._finish_pending_requests()


    def _poll_inout_cb(self, handle, events, error):
        if error is not None:
            return
        action = 0
        if events & pyuv.UV_WRITABLE:
            action |= pycurl.CSELECT_OUT
            ret, num_handles = self._multi.socket_action(handle.fileno(), action)

        elif events & pyuv.UV_READABLE:
            action |= pycurl.CSELECT_IN
            ret, num_handles = self._multi.socket_action(handle.fileno(), action)


    def _poll_cb(self, handle, events, error):
        if error is not None:
            return
        action = 0
        if events & pyuv.UV_READABLE:
            action |= pycurl.CSELECT_IN
            self._multi.socket_action(handle.fd, action)
        if events & pyuv.UV_WRITABLE:
            action |= pycurl.CSELECT_OUT
            self._multi.socket_action(handle.fd, action)
        self._finish_pending_requests()


    def _curl_debug(self, debug_type, debug_msg):
        debug('debug type %s debug msg %s' % (debug_type, debug_msg))
        debug_types = ('I', '<', '>', '<', '>')
        if debug_type == 0:
            debug('%s', debug_msg.strip())
        elif debug_type in (1, 2):
            for line in debug_msg.splitlines():
                debug('%s %s', debug_types[debug_type], line)
        elif debug_type == 4:
            debug('%s %r', debug_types[debug_type], debug_msg)

    def _curl_header_callback(self, headers, header_line):
        header_line = native_str(header_line.decode('latin1'))
      #  if header_callback is not None:
       #     self.io_loop.add_callback(header_callback, header_line)
        # header_line as returned by curl includes the end-of-line characters.
        # whitespace at the start should be preserved to allow multi-line headers
        header_line = header_line.rstrip()

        if header_line.startswith("HTTP/"):
            headers.clear()
            try:
                (__, __, reason) = httputil.parse_response_start_line(header_line)
                header_line = "X-Http-Reason: %s" % reason

            except httputil.HTTPInputError:
                return
        if not header_line:
            return
        headers.parse_line(header_line)


class cURLHTTPRequest(object):
    """HTTP client request object."""

    # Default values for HTTPRequest parameters.
    # Merged with the values on the request object by AsyncHTTPClient
    # implementations.

    _DEFAULTS = dict(
        connect_timeout=3.0,
        request_timeout=10.0,
        follow_redirects=True,
        max_redirects=5,
        decompress_response=True,
        proxy_password='',
        allow_nonstandard_methods=False,
        validate_cert=True)

    def __init__(self, url, method="GET", headers=None, body=None,
                 auth_username=None, auth_password=None, auth_mode=None,
                 connect_timeout=None, request_timeout=None,
                 if_modified_since=None, follow_redirects=None,
                 max_redirects=None, user_agent=None, use_gzip=None,
                 network_interface=None, streaming_callback=None,
                 header_callback=None, prepare_curl_callback=None,
                 proxy_host=None, proxy_port=None, proxy_username=None,
                 proxy_password=None, allow_nonstandard_methods=None,
                 validate_cert=None, ca_certs=None,
                 allow_ipv6=None,
                 client_key=None, client_cert=None, body_producer=None,
                 expect_100_continue=False, decompress_response=None,
                 ssl_options=None):

        if headers is None:
            self.headers = httputil.HTTPHeaders()
        else:
            self.headers = headers

        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.proxy_username = proxy_username
        self.proxy_password = proxy_password
        self.url = url
        self.method = method

        self.body = body
        self.body_producer = body_producer
        self.auth_username = auth_username
        self.auth_password = auth_password
        self.auth_mode = auth_mode
        self.connect_timeout = connect_timeout
        self.request_timeout = request_timeout
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        self.user_agent = user_agent
        if decompress_response is not None:
            self.decompress_response = decompress_response
        else:
            self.decompress_response = use_gzip
        self.network_interface = network_interface
        self.streaming_callback = streaming_callback
        self.header_callback = header_callback
        self.prepare_curl_callback = prepare_curl_callback
        self.allow_nonstandard_methods = allow_nonstandard_methods
        self.validate_cert = validate_cert
        self.ca_certs = ca_certs
        self.allow_ipv6 = allow_ipv6
        self.client_key = client_key
        self.client_cert = client_cert
        self.ssl_options = ssl_options
        self.expect_100_continue = expect_100_continue
        self.start_time = time.time()

    @property
    def headers(self):
        return self._headers

    @headers.setter
    def headers(self, value):
        if value is None:
            self._headers = httputil.HTTPHeaders()
        else:
            self._headers = value

    @headers.setter
    def headers(self, value):
        self._headers = value

    @property
    def body(self):
        return self._body

    @body.setter
    def body(self, value):
        self._body = value



class _RequestProxy(object):
    """Combines an object with a dictionary of defaults.

    Used internally by AsyncHTTPClient implementations.
    """
    def __init__(self, request, defaults):
        self.request = request
        self.defaults = defaults

    def __getattr__(self, name):
        request_attr = getattr(self.request, name)
        if request_attr is not None:
            return request_attr
        elif self.defaults is not None:
            return self.defaults.get(name, None)
        else:
            return None
class HTTPResponse(object):
    """HTTP Response object.
    Attributes:
    * request: HTTPRequest object
    * code: numeric HTTP status code, e.g. 200 or 404
    * reason: human-readable reason phrase describing the status code
    * headers: `tornado.httputil.HTTPHeaders` object
    * effective_url: final location of the resource after following any
      redirects
    * buffer: ``cStringIO`` object for response body
    * body: response body as string (created on demand from ``self.buffer``)
    * error: Exception object, if any
    * request_time: seconds from request start to finish
    * time_info: dictionary of diagnostic timing information from the request.
      Available data are subject to change, but currently uses timings
      available from http://curl.haxx.se/libcurl/c/curl_easy_getinfo.html,
      plus ``queue``, which is the delay (if any) introduced by waiting for
      a slot under `AsyncHTTPClient`'s ``max_clients`` setting.
    """
    def __init__(self, request, code, headers=None, buffer=None,
                 effective_url=None, error=None, request_time=None,
                 time_info=None, reason=None):
        if isinstance(request, _RequestProxy):
            self.request = request.request
        else:
            self.request = request
        self.code = code
        self.reason = reason or httputil.responses.get(code, "Unknown")
        if headers is not None:
            self.headers = headers
        else:
            self.headers = httputil.HTTPHeaders()
        self.buffer = buffer
        self._body = None
        if effective_url is None:
            self.effective_url = request.url
        else:
            self.effective_url = effective_url
        if error is None:
            if self.code < 200 or self.code >= 300:
                self.error = cURLError(self.code, message=self.reason,
                                       response=self)
            else:
                self.error = None
        else:
            self.error = error
        self.request_time = request_time
        self.time_info = time_info or {}

    def _get_body(self):
        if self.buffer is None:
            return None
        elif self._body is None:
            self._body = self.buffer.getvalue()

        return self._body

    body = property(_get_body)

    def rethrow(self):
        """If there was an error on the request, raise an `HTTPError`."""
        if self.error:
            raise self.error

    def __repr__(self):
        args = ",".join("%s=%r" % i for i in sorted(self.__dict__.items()))
        return "%s(%s)" % (self.__class__.__name__, args)

class HTTPError(Exception):
    """Exception thrown for an unsuccessful HTTP request.
    Attributes:
    * ``code`` - HTTP error integer error code, e.g. 404.  Error code 599 is
      used when no HTTP response was received, e.g. for a timeout.
    * ``response`` - `HTTPResponse` object, if any.
    Note that if ``follow_redirects`` is False, redirects become HTTPErrors,
    and you can look at ``error.response.headers['Location']`` to see the
    destination of the redirect.
    """
    def __init__(self, code, message=None, response=None):
        self.code = code
        self.message = message or httputil.responses.get(code, "Unknown")
        self.response = response
        super(HTTPError, self).__init__(code, message, response)

    def __str__(self):
        return "HTTP %d: %s" % (self.code, self.message)

    # There is a cyclic reference between self and self.response,
    # which breaks the default __repr__ implementation.
    # (especially on pypy, which doesn't have the same recursion
    # detection as cpython).
    __repr__ = __str__



class cURLError(HTTPError):
    """Exception thrown for an unsuccessful HTTP request.
    Attributes:
    * ``code`` - HTTP error integer error code, e.g. 404.  Error code 599 is
      used when no HTTP response was received, e.g. for a timeout.
    * ``response`` - `HTTPResponse` object, if any.
    Note that if ``follow_redirects`` is False, redirects become HTTPErrors,
    and you can look at ``error.response.headers['Location']`` to see the
    destination of the redirect.
    """
    def __init__(self, code, message=None, response=None):
        self.code = code
        self.message = message or httputil.responses.get(code, "Unknown")
        self.response = response
        super(HTTPError, self).__init__(code, message, response)

    def __str__(self):
        return "HTTP %d: %s" % (self.code, self.message)

    # There is a cyclic reference between self and self.response,
    # which breaks the default __repr__ implementation.
    # (especially on pypy, which doesn't have the same recursion
    # detection as cpython).
    __repr__ = __str__


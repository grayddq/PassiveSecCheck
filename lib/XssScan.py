# -*- coding: utf-8 -*-
import random, re, string, urllib, urllib2, time, redis
from config import *

SMALLER_CHAR_POOL = ('<', '>')
LARGER_CHAR_POOL = ('\'', '"', '>', '<', ';')

DOM_FILTER_REGEX = r"(?s)<!--.*?-->|\bescape\([^)]+\)|\([^)]+==[^(]+\)|\"[^\"]+\"|'[^']+'"

REGULAR_PATTERNS = (
    # each (regular pattern) item consists of (r"context regex", (prerequisite unfiltered characters), "info text", r"content removal regex")
    (r"\A[^<>]*%(chars)s[^<>]*\Z", ('<', '>'), "\".xss.\", pure text response, %(filtering)s filtering", None),
    (r"<!--[^>]*%(chars)s|%(chars)s[^<]*-->", ('<', '>'),
     "\"<!--.'.xss.'.-->\", inside the comment, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?'[^<']*%(chars)s|%(chars)s[^<']*'[^<]*</script>", ('\'', ';'),
     "\"<script>.'.xss.'.</script>\", enclosed by <script> tags, inside single-quotes, %(filtering)s filtering", None),
    (r'(?s)<script[^>]*>[^<]*?"[^<"]*%(chars)s|%(chars)s[^<"]*"[^<]*</script>', ('"', ';'),
     "'<script>.\".xss.\".</script>', enclosed by <script> tags, inside double-quotes, %(filtering)s filtering", None),
    (r"(?s)<script[^>]*>[^<]*?%(chars)s|%(chars)s[^<]*</script>", (';',),
     "\"<script>.xss.</script>\", enclosed by <script> tags, %(filtering)s filtering", None),
    (r">[^<]*%(chars)s[^<]*(<|\Z)", ('<', '>'), "\">.xss.<\", outside of tags, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*'[^>']*%(chars)s[^>']*'[^>]*>", ('\'',),
     "\"<.'.xss.'.>\", inside the tag, inside single-quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->"),
    (r'<[^>]*"[^>"]*%(chars)s[^>"]*"[^>]*>', ('"',),
     "'<.\".xss.\".>', inside the tag, inside double-quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->"),
    (r"<[^>]*%(chars)s[^>]*>", (), "\"<.xss.>\", inside the tag, outside of quotes, %(filtering)s filtering",
     r"(?s)<script.+?</script>|<!--.*?-->"),
)

DOM_PATTERNS = (  # each (dom pattern) item consists of r"recognition regex"
    r"(?s)<script[^>]*>[^<]*?(var|\n)\s*(\w+)\s*=[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location)[^;]*;[^<]*(document\.write(ln)?\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*\2.*?</script>",
    r"(?s)<script[^>]*>[^<]*?(document\.write\(|\.innerHTML\s*=|eval\(|setTimeout\(|setInterval\(|location\.(replace|assign)\(|setAttribute\()[^;]*(document\.(location|URL|documentURI)|location\.(href|search)|window\.location).*?</script>",
)


class XSS_Scan:
    def __init__(self, target, logger=None):
        self.target = target
        self.protocol = target['protocol']
        self.ng_request_url_short = target['ng_request_url_short']
        self.domain = target['domain']
        self.method = target['method'].strip().upper()
        self.arg = target['arg']
        self.cookie = target['cookie']
        self.ua = target['ua']
        self.logger = logger
        self._headers = {'Cookie': self.cookie, 'User-Agent': self.ua}
        self.payload = []

    def _retrieve_content(self, url, data=None):
        try:
            req = urllib2.Request(
                "".join(url[i].replace(' ', "%20") if i > url.find('?') else url[i] for i in xrange(len(url))), data,
                self._headers)
            retval = urllib2.urlopen(req, timeout=30).read()
        except Exception, ex:
            retval = ex.read() if hasattr(ex, "read") else getattr(ex, "msg", str())
        return retval or ""

    def _contains(self, content, chars):
        content = re.sub(r"\\[%s]" % re.escape("".join(chars)), "", content) if chars else content
        return all(char in content for char in chars)

    def scan_page(self, url, data=None):
        retval, usable = False, False
        url, data = re.sub(r"=(&|\Z)", "=1\g<1>", url) if url else url, re.sub(r"=(&|\Z)", "=1\g<1>",
                                                                               data) if data else data
        original = re.sub(DOM_FILTER_REGEX, "", self._retrieve_content(url, data))
        dom = max(re.search(_, original) for _ in DOM_PATTERNS)
        if dom:
            self.payload.append(dom.group(0))
            retval = True
        try:
            for phase in ("GET", "POST"):
                current = url if phase == "GET" else (data or "")
                for match in re.finditer(r"((\A|[?&])(?P<parameter>[\w\[\]]+)=)(?P<value>[^&#]*)", current):
                    found, usable = False, True
                    prefix, suffix = ("".join(random.sample(string.ascii_lowercase, 5)) for i in xrange(2))
                    for pool in (LARGER_CHAR_POOL, SMALLER_CHAR_POOL):
                        if not found:
                            tampered = current.replace(match.group(0), "%s%s" % (match.group(0), urllib.quote(
                                "%s%s%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix,
                                              "".join(random.sample(pool, len(pool))), suffix))))
                            content = (
                                self._retrieve_content(tampered, data) if phase == "GET" else self._retrieve_content(
                                    url, tampered)).replace(
                                "%s%s" % ("'" if pool == LARGER_CHAR_POOL else "", prefix), prefix)
                            for sample in re.finditer("%s([^ ]+?)%s" % (prefix, suffix), content, re.I):
                                for regex, condition, info, content_removal_regex in REGULAR_PATTERNS:
                                    context = re.search(regex % {"chars": re.escape(sample.group(0))},
                                                        re.sub(content_removal_regex or "", "", content), re.I)
                                    if context and not found and sample.group(1).strip():
                                        if self._contains(sample.group(1), condition):
                                            self.payload.append(tampered)
                                            found = retval = True
                                        break
        except Exception, e:
            if self.logger: self.logger.infostring('xss scan error,error : %s' % str(e))
        return retval

    def callback(self):
        if self.payload:
            if self.logger: self.logger.infostring(
                'success found xss,target : %s ' % (self.domain + self.ng_request_url_short))
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            value = {'method': self.method, 'protocol': self.protocol, 'cookie': self.cookie, 'domain': self.domain,
                     'ng_request_url_short': self.ng_request_url_short, 'arg': self.arg, 'time': current_time,
                     'risk_type': 'XSS', 'data': self.payload}
            redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
            redis_r.hset('passive_scan_risk', 'XSS_' + self.ng_request_url_short, value)
            redis_r.execute_command("QUIT")

    def run(self):
        if self.logger: self.logger.infostring('start xss scan')
        if self.method == 'GET':
            url = self.protocol + self.domain + self.ng_request_url_short + '?' + self.arg
            self.scan_page(url)
        elif self.method == 'POST':
            url = self.protocol + self.domain + self.ng_request_url_short
            self.scan_page(url, self.arg)
        self.callback()
        if self.logger: self.logger.infostring('finsh ssrf task')

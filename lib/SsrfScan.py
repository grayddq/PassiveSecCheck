# -*- coding: utf-8 -*-
import redis, requests, urlparse
from config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"


class SSRF_Scan():
    def __init__(self, target, logger=None):
        self.target = target
        self.protocol = target['protocol']
        self.ng_request_url_short = target['ng_request_url_short']
        self.domain = target['domain']
        self.method = target['method'].strip().upper()
        self.arg = dict(urlparse.parse_qsl(target['arg']))
        self.cookie = target['cookie']
        self.ua = target['ua']
        self.logger = logger
        self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
        if self.redis_r.hget('passive_config', 'ssrf_server'):
            self.server = self.redis_r.hget('passive_config', 'ssrf_server')

    def request(self):
        if self.server:
            for key in self.arg:
                try:
                    temp_arg = self.arg.copy()
                    temp_arg[key] = 'http://' + self.server + '/ssrf?data=%s' % self.target
                    headers = {'User-Agent': self.ua, 'Cookie': self.cookie}
                    url = self.protocol + self.domain + self.ng_request_url_short
                    if self.method == 'GET':
                        requests.get(url, params=temp_arg, headers=headers,
                                     verify=False, allow_redirects=False)
                    elif self.method == 'POST':
                        requests.post(url, data=temp_arg, headers=headers,
                                      verify=False, allow_redirects=False)
                except Exception, e:
                    print str(e)
                    continue
        else:
            if self.logger: self.logger.infostring('no service address,please configuration')

    def run(self):
        if self.logger: self.logger.infostring('start ssrf scan')
        self.request()
        if self.logger: self.logger.infostring('finsh ssrf task')
        return

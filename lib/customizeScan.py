# -*- coding: utf-8 -*-
import redis, urlparse, requests, re, time
from config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"


class Customize_Scan():
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
        self.rules = self.redis_r.hget('passive_config', 'conf_rule')

    def scan(self):
        headers = {'User-Agent': self.ua, 'Cookie': self.cookie}
        for key in self.arg:
            for rule in self.rules:
                try:
                    temp_arg = self.arg.copy()
                    if rule['parameter']:
                        if key == rule['parameter']: temp_arg[key] = rule['value']
                    else:
                        temp_arg[key] = rule['value']
                    if cmp(self.arg, temp_arg) == 0: continue
                    url = self.protocol + self.domain + self.ng_request_url_short
                    if self.method == 'GET':
                        response = requests.get(url, params=temp_arg, headers=headers, verify=False,
                                                allow_redirects=True)
                    else:
                        response = requests.post(url, data=temp_arg, headers=headers, verify=False,
                                                 allow_redirects=True)
                    if not response.content:
                        continue
                    if re.search(rule['rule'], response.content):
                        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        value = {'method': self.method, 'protocol': self.protocol, 'cookie': self.cookie,
                                 'domain': self.domain, 'ng_request_url_short': self.ng_request_url_short,
                                 'arg': self.arg, 'time': current_time, 'risk_type': rule['name'],
                                 'change_arg': temp_arg, 'data': response.content}
                        self.redis_r.hset('passive_scan_risk', rule['name'] + '_' + self.ng_request_url_short, value)
                except Exception, e:
                    continue
        return

    def run(self):
        if self.logger: self.logger.infostring('start customize scan')
        if not self.rules or not self.arg:
            return
        self.scan()
        if self.logger: self.logger.infostring('finsh customize scan')

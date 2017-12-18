# -*- coding: utf-8 -*-
import requests, urlparse


class Try_Request():
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

    def run(self):
        try:
            url = self.protocol + self.domain + self.ng_request_url_short
            headers = {'User-Agent': self.ua, 'Cookie': self.cookie}
            if self.method == 'GET':
                response = requests.get(url, params=self.arg, headers=headers, verify=False, allow_redirects=False)
            else:
                response = requests.post(url, data=self.arg, headers=headers, verify=False, allow_redirects=False)
            if (response.status_code == 404) or (response.status_code == 403):
                if self.logger: self.logger.infostring('target url response 404/403, tash failed')
                return False
            return True
        except Exception, e:
            return False

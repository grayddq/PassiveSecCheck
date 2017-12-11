# -*- coding: utf-8 -*-
import redis, urlparse, urllib, types
from config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"


class Check_Heads():
    def __init__(self, target):
        self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
        target['ua'] = \
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/47.0.2526.106'
        target['cookie'] = ''

        if self.redis_r.hget('passive_config', 'parameter_json'):
            parameter_json = eval(self.redis_r.hget('passive_config', 'parameter_json'))
            if type(target['arg']) is types.StringType:
                qs_dict = dict(urlparse.parse_qsl(target['arg']))
                for k in qs_dict:
                    if k in parameter_json:
                        qs_dict[k] = parameter_json[k]
                target['arg'] = urllib.unquote(urllib.urlencode(qs_dict))
            elif type(target['arg']) == dict:
                for k in target['arg']:
                    if k in parameter_json:
                        target['arg'][k] = parameter_json[k]

        cookies_list = self.redis_r.hget('passive_config', 'cookies')
        if cookies_list:
            for cookie in eval(cookies_list):
                if '*' in cookie['domain'] and cookie['domain'].replace('*', '') in target['domain']:
                    target['cookie'] = cookie['cookie']
                elif target['domain'] == cookie['domain']:
                    target['cookie'] = cookie['cookie']
                    return

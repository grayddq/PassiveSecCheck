# -*- coding: utf-8 -*-
import os, urllib, redis, time
from lib.config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"

if __name__ == '__main__':
    redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
    logPath = redis_r.hget('passive_config', 'ssrf_logpath')
    if not os.path.exists(logPath):
        print 'log file not exist'
    file = open(logPath)
    for line in file:
        lines = line.strip().strip('\n').split(' ')
        for s in lines:
            if '/ssrf?data=' in s:
                info = urllib.unquote(s.replace('/ssrf?data=', '')).split('ssrf?data=')
                if len(info) > 1:
                    target = eval(info[1].replace(',+', ',').replace(':+', ':'))
                    if len(target) > 0:
                        target['time'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
                        target['risk_type'] = 'SSRF'
                        target['data'] = ''
                        redis_r.hset('passive_scan_risk', 'SSRF_' + target['ng_request_url_short'], target)
    os.system('cat /dev/null > %s' % logPath)

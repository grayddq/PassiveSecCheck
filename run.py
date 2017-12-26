# -*- coding: utf-8 -*-
from tasks import *
import redis
from lib.config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"

if __name__ == '__main__':
    redis_r_data = redis.StrictRedis(host=DATA_REDIS_HOST, port=DATA_REDIS_PORT, password=DATA_REDIS_PASSWORD,
                                     db=DATA_REDIS_DB)

    key_list = redis_r_data.keys('DataSort_*')
    for key in key_list:
        values = eval(redis_r_data.get(key))
        print "[+] push info to redis , url_short: %s" % values['ng_request_url_short']
        passive_scan_dispath.delay(values)
    print "success push task."

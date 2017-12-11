# -*- coding: utf-8 -*-
from config import *
import redis

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"


class White_Check:
    def __init__(self, target, logger=None):
        self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
        self.target = target
        self.logger = logger

    def run(self):
        if self.redis_r.hget('passive_config', 'white_path'):
            white_list = eval(self.redis_r.hget('passive_config', 'white_path'))
            for path in white_list:
                if path in self.target['ng_request_url_short']:
                    self.redis_r.execute_command("QUIT")
                    if self.logger: self.logger.infostring('the target path in the whitelist,no scan')
                    if self.logger: self.logger.infostring('finsh task')
                    return True
        return False

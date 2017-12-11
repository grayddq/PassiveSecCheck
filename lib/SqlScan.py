# -*- coding: utf-8 -*-
import redis, requests, json, urlparse, urllib, time
from config import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"


class SQL_Scan():
    def __init__(self, target, logger=None):
        self.protocol = target['protocol']
        self.ng_request_url_short = target['ng_request_url_short']
        self.domain = target['domain']
        self.method = target['method'].strip().upper()
        self.arg = target['arg']
        self.cookie = target['cookie']
        self.ua = target['ua']
        self.logger = logger

        self.redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
        self.start_time = time.time()
        self.taskid = ''
        # server sqlmap远程ip链接
        self.server = 'http://127.0.0.1:8775/'
        # 当前任务max_time最大运行时间
        self.max_time = 300
        # db_type数据库检测类型
        self.db_type = 'MySQL'
        # sqlmap扫描等级和风险
        self.level, self.risk = 3, 1

    # 新建扫描任务
    def task_new(self):
        self.taskid = json.loads(requests.get(self.server + 'task/new').text)['taskid']
        if len(self.taskid) > 0:
            return True
        if self.logger: self.logger.infostring('create sqlmap task error')
        return False

    # 删除扫描任务
    def task_delete(self):
        if json.loads(requests.get(self.server + 'task/' + self.taskid + '/delete').text)['success']:
            return True
        return False

    # 扫描任务开始
    def scan_start(self):
        if self.method == 'GET':
            payload = {'url': self.protocol + self.domain + self.ng_request_url_short + '?' + self.arg}
        else:
            payload = {'url': self.protocol + self.domain + self.ng_request_url_short}
        url = self.server + 'scan/' + self.taskid + '/start'
        t = json.loads(requests.post(url, data=json.dumps(payload), headers={'Content-Type': 'application/json'}).text)
        engineid = t['engineid']
        if len(str(engineid)) > 0 and t['success']:
            return True
        if self.logger: self.logger.infostring('sqlmap task start error')
        return False

    # 扫描任务的状态
    def scan_status(self):
        self.status = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/status').text)['status']
        if self.status == 'running':
            return 'running'
        elif self.status == 'terminated':
            return 'terminated'
        else:
            return 'error'

    # 扫描任务的结果
    def scan_data(self):
        data = json.loads(
            requests.get(self.server + 'scan/' + self.taskid + '/data').text)['data']
        if len(data) > 0:
            if self.logger: self.logger.infostring(
                'found sql injection,info: %s ' % (self.domain + self.ng_request_url_short))
            current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
            value = {'method': self.method, 'protocol': self.protocol, 'cookie': self.cookie, 'domain': self.domain,
                     'ng_request_url_short': self.ng_request_url_short, 'arg': self.arg, 'time': current_time,
                     'risk_type': 'SQL Injection', 'data': data}

            self.redis_r.hset('passive_scan_risk', 'SQL_Injection_' + self.ng_request_url_short, value)

    # 扫描的设置,主要的是参数的设置
    def option_set(self):
        headers = {'Content-Type': 'application/json'}
        data = {'cookie': self.cookie}
        if self.db_type: data['dbms'] = self.db_type
        if self.risk: data['risk'] = self.risk
        if self.level: data['level'] = self.level
        data['user-agent'] = self.ua
        if self.method == "POST": data["data"] = self.arg
        url = self.server + 'option/' + self.taskid + '/set'
        requests.post(url, data=json.dumps(data), headers=headers)

    # 停止扫描任务
    def scan_stop(self):
        requests.get(self.server + 'scan/' + self.taskid + '/stop')

    # 杀死扫描任务进程
    def scan_kill(self):
        requests.get(self.server + 'scan/' + self.taskid + '/kill')

    # 删除此次任务
    def scan_del(self):
        requests.get(self.server + 'task/' + self.taskid + '/delete')

    # 判断URL是否进行扫描
    def assessment_scan(self):
        # 首先判断URL是否存在参数,如果不存在参数则直接放弃扫描
        if not self.arg:
            return False
        return True

    # 配置系统参数
    def conf_sys(self):
        try:
            if self.redis_r.hget('passive_config', 'sqlmap_level'):
                self.level = self.redis_r.hget('passive_config', 'sqlmap_level')
            if self.redis_r.hget('passive_config', 'sqlmap_risk'):
                self.risk = self.redis_r.hget('passive_config', 'sqlmap_risk')
            if self.redis_r.hget('passive_config', 'sqlmap_server'):
                self.server = self.redis_r.hget('passive_config', 'sqlmap_server')
            if self.redis_r.hget('passive_config', 'sqlmap_max_time'):
                self.max_time = int(self.redis_r.hget('passive_config', 'sqlmap_max_time'))
            if self.redis_r.hget('passive_config', 'sqlmap_db_type'):
                self.db_type = self.redis_r.hget('passive_config', 'sqlmap_db_type')
        except Exception, e:
            if self.logger: self.logger.infostring('read conf info error,error function conf_sys: %s' % str(e))

    def run(self):
        try:
            if self.logger: self.logger.infostring('start sql inject scan')
            if not self.arg:
                if self.logger: self.logger.infostring('the target dont no arg')
                if self.logger: self.logger.infostring('finsh sql injection task')
                return False

            self.conf_sys()

            if not self.task_new():
                if self.logger: self.logger.infostring('finsh sql injection task')
                return False
            # 配置扫描选项
            self.option_set()
            # 开始扫描
            if not self.scan_start():
                if self.logger: self.logger.infostring('finsh sql injection task')
                return False
            # 判断任务状态
            while True:
                if self.scan_status() == 'running':
                    time.sleep(10)
                elif self.scan_status() == 'terminated':
                    break
                else:
                    break
                if time.time() - self.start_time > self.max_time:
                    self.scan_stop()
                    self.task_delete()
                    self.redis_r.execute_command("QUIT")
                    if self.logger: self.logger.infostring('sqlmap task exceeded the maximum time limit')
                    if self.logger: self.logger.infostring('finsh sql injection task')
                    return
            # 获取扫描结果
            self.scan_data()
            # 删除扫描任务
            self.task_delete()
            self.redis_r.execute_command("QUIT")
            if self.logger: self.logger.infostring('finsh sql injection task')
        except Exception, e:
            if self.logger: self.logger.infostring('tash run error,error: %s' % str(e))
            if self.logger: self.logger.infostring('finsh sql injection task')
            return False

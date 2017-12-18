# -*- coding: utf-8 -*-
from celery import Celery, platforms
from lib.SqlScan import *
from lib.log import *
from lib.headers import *
from lib.SsrfScan import *
from lib.XssScan import *
from lib.white import *
from lib.customizeScan import *
from lib.tryReqest import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"


def config():
    redis_r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, password=REDIS_PASSWORD, db=REDIS_DB)
    # 防止任务开始时修改已有的配置信息,当已存在配置信息时，不进行配置设置.
    if redis_r.keys('passive_config'):
        if len(redis_r.hkeys('passive_config')) > 2:
            return
    # 配置参数中的替换字符，防止由于越权导致的误操作
    redis_r.hset('passive_config', 'parameter_json', conf_parameter_json)
    # 维持一个sesson访问列表
    redis_r.hset('passive_config', 'cookies', conf_cookies)
    # 白名单路径，路径中出现如/admin不进行检测
    redis_r.hset('passive_config', 'white_path', conf_white_path)
    # 自定义扫描规则
    redis_r.hset('passive_config', 'conf_scan_rule', conf_scan_rule)
    # sqlmap远程ip链接
    redis_r.hset('passive_config', 'sqlmap_server', sqlmap_server)
    # 当前任务max_time最大运行时间
    redis_r.hset('passive_config', 'sqlmap_max_time', sqlmap_max_time)
    # db_type数据库检测类型
    redis_r.hset('passive_config', 'sqlmap_db_type', sqlmap_db_type)
    # sqlmap扫描等级和风险
    redis_r.hset('passive_config', 'sqlmap_level', sqlmap_level)
    redis_r.hset('passive_config', 'sqlmap_risk', sqlmap_risk)
    # server远程ip或domain，建议侦测ssrf的web放到内网
    redis_r.hset('passive_config', 'ssrf_server', ssrf_server)
    # ssrf web日志绝对地址
    redis_r.hset('passive_config', 'ssrf_logpath', ssrf_logpath)


logger = LogInfo()
# 初始化相关配置,
config()

app = Celery()
platforms.C_FORCE_ROOT = True
DEBUG_INFO = True
app.conf.update(
    CELERY_IMPORTS=("tasks",),
    BROKER_URL='redis://:' + REDIS_PASSWORD + '@' + REDIS_HOST + ':' + str(REDIS_PORT) + '/' + str(REDIS_DB),
    CELERY_TASK_SERIALIZER='json',
    CELERY_RESULT_SERIALIZER='json',
    CELERY_TIMEZONE='Asia/Shanghai',
    CELERY_ENABLE_UTC=True,
    CELERY_REDIS_MAX_CONNECTIONS=5000,
    BROKER_HEARTBEAT=30,
    BROKER_TRANSPORT_OPTIONS={'visibility_timeout': 3600},
)


# 数据源5元素[方法、协议、host、接口、参数]
# 方法method                    GET或POST
# 协议protocol                  http://或https://
# domain                        www.baidu.com
# 接口ng_request_url_short      /api/1.php
# 参数arg                        a=1&b=2&c=3
@app.task(name='tasks.passive_scan_dispath')
def passive_scan_dispath(targets):
    logger.infostring('create sec task,target %s...' % (targets['domain'] + targets['ng_request_url_short']))
    # 白名单验证
    if White_Check(targets, logger).run():
        return
    # 导入配置信息
    Check_Heads(targets)
    # 判断是否允许访问
    if not Try_Request(targets):
        return
    # SQL注入扫描
    SQL_Scan(targets, logger).run()
    # SSRF扫描
    SSRF_Scan(targets, logger).run()
    # XSS扫描
    XSS_Scan(targets, logger).run()
    # 自定义漏洞规则扫描
    Customize_Scan(targets, logger).run()

    logger.infostring('finsh task.')

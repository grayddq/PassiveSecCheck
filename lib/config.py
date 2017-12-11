# -*- coding: utf-8 -*-
# redis信息
REDIS_HOST = '182.11.11.11'
REDIS_PORT = 6379
REDIS_PASSWORD = 'xxxxxxx'
REDIS_DB = 5
# 配置参数中的替换字符，防止参数中出现session权限判断等
conf_parameter_json = {
    'session': '12234234234'
}
# 维持一个sesson访问列表
conf_cookies = [
    {'domain': '*.test.com', 'cookie': 'aaaaa=bbbbb'},
    {'domain': 'www.test.com', 'cookie': 'session=aaaa'},
    {'domain': 'aaa.testbbb.com', 'cookie': 'NL=1234'}
]
# 白名单路径，路径中出现如/admin不进行任何安全检测
conf_white_path = ['/admin', '/administra']
# 自定义漏洞匹配规则,遍历每个参数名称，当设定parameter时，值替换为设定的value字串，并在response中匹配正则rule
# 不设定parameter时，代表挨个替换
# 可以测试一些越权操作和一些常见漏洞
# 比如设定参数名为phone，替换其参数值为手机号，并匹配response的body内，是否出现此人的个人信息。
conf_rule = [
    {'value': '17600296111', 'rule': '111111111', 'name': 'Exceed Permissions', 'parameter': 'phone'},
    {'value': '17600296112', 'rule': '22222222', 'name': 'Exceed Permissions', 'parameter': 'iphone'}
]
# server sqlmap远程ip链接
sqlmap_server = 'http://127.0.0.1:8775/'
# SQL检测最大运行时间(S)
sqlmap_max_time = 600
# db_type数据库检测类型
sqlmap_db_type = ''
# sqlmap扫描等级和风险
sqlmap_level = 1
sqlmap_risk = 1
# ssrf_server远程ip或domain
# ssrf实质是服务端访问了客户端传递的地址
# 预先搭建一台web，收集分析日志可以判断ssrf触发点。
ssrf_server = '192.168.1.3'
# ssrf web日志路径
ssrf_logpath = '/var/logs/nginx/access.log'

# -*- coding: utf-8 -*-
from tasks import *

NAME, VERSION, AUTHOR, LICENSE = "PublicSecScan", "V0.1", "咚咚呛", "Public (FREE)"

if __name__ == '__main__':
    target = {}
    target['method'] = 'GET'
    target['protocol'] = 'http://'
    target['domain'] = 'www.test.com'
    target['ng_request_url_short'] = '/api/cp/user.php'
    target['arg'] = 'action=111'
    config()
    passive_scan_dispath.delay(target)

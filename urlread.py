#coding:utf-8

from logger import logger
import urllib.parse, urllib.request
import http.cookiejar
from socket import timeout

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'

class urlread:
    def __init__(self, ucookiejar=None):
        self.header = {
            'User-Agent': USER_AGENT,
            'Accept-Encoding': 'gzip, deflate', 
            'Accept-Language':'zh-CN,zh;q=0.8,en;q=0.6,zh-TW;q=0.4'
        }
        if ucookiejar is None:
            self.cookiejar = http.cookiejar.CookieJar()
        else:
            self.cookiejar = ucookiejar
        pro = urllib.request.HTTPCookieProcessor(self.cookiejar)
        self.opener = urllib.request.build_opener(pro)
        header = []
        for key, value in self.header.items():
            elem = (key, value)
            header.append(elem)
        self.opener.addheaders = header

    def urlopen(self, url, postData=None):
        logger.info('urlopen: {}'.format(url))
        if postData is None:
            resp = self.opener.open(url)
        else:
            if type(postData) == dict:
                postData = urllib.parse.urlencode(postData).encode()
            resp = self.opener.open(url, postData,  timeout=60)
        return resp
    
    def __urlread(self, url, postData=None):
        response = self.urlopen(url, postData)
        data = response.read()
        if response.info().get('Content-Encoding') == 'gzip':
            data = ungzip(data)
        elif response.info().get('Content-Encoding') == 'deflate':
            data = undeflate(data)
        return data

    def urlread(self, url, postData=None):
        logger.info('urlread: {}'.format(url))
        data = self.__urlread(url, postData)
        return data.decode()


def ungzip(s):
    import gzip
    return gzip.decompress(s)

def undeflate(s):
    import zlib
    return zlib.decompress(s, -zlib.MAX_WBITS)


#coding:utf-8

from lxml import etree
from urlread import urlread
from logger import logger
import re
import json

class DramaDetail:
    def __init__(self, id):
        if not id:
            raise Exception('Missing drama id.')
        self.id = str(id)
        self.url = 'http://www.zimuzu.tv/resource/{}'.format(self.id)
        self.results = {}
        self.name = 'unknown'
    
    def get_downlad_page(self):
        html = urlread().urlread(self.url)
        page = etree.HTML(html)
        div = page.xpath(u"//div[@class='view-res-list']")[0]
        a = div.find(".//h3")
        a.getparent().remove(a)
        href = div.find(".//a[@class='f3']")
        pagelink = href.attrib['href']
        logger.info('download page: {}'.format(pagelink))
        return pagelink

    def get_download_html(self):
        html = urlread().urlread(self.get_downlad_page())
        file_list = None
        page = etree.HTML(html)
        scripts = page.xpath("//script")
        for sc in scripts:
            if sc.text is not None and sc.text != '':
                t = re.search(r"var share_prefix = '(.*)'", sc.text)
                if t is not None:
                    self.name = t.group(1)
                m = re.search(r'var file_list=(\{.*\})', sc.text)
                if m is not None:
                    file_list = json.loads(m.group(1))
        dls = page.xpath("//dl")
        for dl in dls:
            title = dl.find(".//dt")
            fmt = title.find("span").text
            if fmt.find("中文字幕") != -1:
                s = re.match(r'第(\d+)季', title.find("strong").text)
                if s is None:
                    continue
                season = str(int(s.group(1)))
                if season not in self.results.keys():
                    self.results[season] = {}
                ddd = dl.findall(".//dd")
                for dd in ddd:
                    if 'itemid' in dd.attrib:
                        episode = str(int(re.match(r'第(\d+)集', dd.find("b").text).group(1)))
                        itemid = dd.attrib['itemid']
                        link = self.filterLink(file_list[itemid])
                        if episode not in self.results[season].keys():
                            self.results[season][episode] = link
        return {"id":self.id,"name":self.name,"results":self.results}
    
    def filterLink(self, file_list):
        for i in range(3):
            try:
                return file_list[str(i)]
            except:
                continue
        return None

if __name__ == "__main__":
    a = DramaDetail(30675)
    print(a.get_download_html())



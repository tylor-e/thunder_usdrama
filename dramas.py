#coding:utf-8

from lxml import etree
from urlread import urlread
from logger import logger

class USDramaScan:
    def __init__(self):
        self.url = "http://www.zimuzu.tv/html/top/week.html"
        self.watchlist = ['11029']
        
    def get_dramas(self):
        html = urlread().urlread(self.url)
        rankings = []
        page = etree.HTML(html)
        divs = page.xpath("//div[starts-with(@class,'box xy-list')]")
        for div in divs:
            ranking = []
            title = div.find(".//div[@class='a0']")
            if title.text.find("的剧")!=-1:
                lis = div.findall(".//li")
                for li in lis:
                    ttt = li.findall(".//div[@class='a0']")
                    for t in ttt:
                        id = t.find("div[@class='fl info']/a").attrib['href'].split("/")[2]
#                         title = t.find(".//strong").text
#                         d = {"title":title,"id":id}
                        ranking.append(id)
            if len(ranking) == 10:
                rankings.append(ranking)
        if len(rankings)>=2:
            prev = rankings[0]
            dramas = []
            for ranking in rankings:
                dramas = list(set(prev).intersection(set(ranking)))
                prev = ranking
        else:
            dramas = rankings[0]
        dramas = list(set(dramas).union(set(self.watchlist)))
        dramas = list(set(dramas))
        logger.info('current dramas found: {}'.format(len(dramas)))
        return dramas

if __name__ == "__main__":
    a = USDramaScan()
    b = a.get_dramas()
    print(b)

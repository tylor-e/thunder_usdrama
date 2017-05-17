#coding:utf-8

from dramas import USDramaScan
from drama import DramaDetail
import subprocess, os, json
from logger import logger
import time
import config

class scan:
    def __init__(self):
        self.mydir = config.mydir
        self.task_file=self.mydir+'/task.txt'
    
    def dramas_on_page(self):
        return USDramaScan().get_dramas()
    
    def drama_links(self, id):
        return DramaDetail(id).get_download_html()
    
    def get_record(self, id):
        file = '{}/record/{}.json'.format(self.mydir, id)
        if not os.path.exists(file):
            with open(file, 'w') as f:
                f.write('{}')
            return {}
        else:
            with open(file, 'r') as f:
                return json.loads(f.read())
    
    def write_links(self, tasks):
        with open(self.task_file, 'w') as f:
            f.write(json.dumps(tasks))
    
    def run(self):
        tasks = []
        dramas = self.dramas_on_page()
        for drama in dramas:
            data = self.drama_links(drama)
            id = data['id']
            name = data['name']
            results = data['results']
            record = self.get_record(id)
            for season in results.keys():
                for ep in results[season].keys():
                    if season not in record.keys() or int(ep) not in record[season]:
                        logger.info("new drama found: {} - season {} - episode {}".format(name, season, ep))
                        tasks.append({"id":id,"season":season,"link":results[season][ep],"ep":ep,"name":name})
            time.sleep(5)
        self.write_links(tasks)
    
    def call_thunder(self):
        cmd = ['python', 'thunder.py']
        a = subprocess.Popen(cmd, cwd=self.mydir, stdout=subprocess.PIPE)
        a.wait()
        logger.info(a.stdout.read())
        
if __name__ == "__main__":
    while True:
        a = scan()
        a.run()
        a.call_thunder()
        time.sleep(3600*6)


#coding:utf-8
#this is a py27 file!

from yc_api import *
import verification_code, config
import json, time, os
import logging

mydir = config.mydir
LOG_LEVEL = logging.INFO

logger = logging.getLogger()
if not logger.handlers:
    logger.setLevel(LOG_LEVEL)
    sh = logging.StreamHandler()
    sh.setLevel(LOG_LEVEL)
    sh.setFormatter(logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s'))
    logger.addHandler(sh)

with open('{}/task.txt'.format(mydir), 'r') as f:
    tasks = json.loads(f.read())

verification_code_reader = verification_code.default_verification_code_reader('file', config.thunder.get('verification_image_path'))
auto_login = True
dl = ThunderRemoteDownload(config.thunder.get('username'), config.thunder.get('password'), config.thunder.get('cookie_path'), auto_login, verification_code_reader)

copytasks = list(tasks)
for t in tasks:
    season = t['season']
    id = t['id']
    url = t['link']
    ep = t['ep']
    name = t['name']
    logger.info('adding task: ' + name + ' - season ' + season + ' - episode ' + str(ep))
    try:
        url = url.rstrip('>')
        result = dl.create_task(url)
        with open('{}/record/{}.json'.format(mydir, id), 'r') as f:
            record = json.loads(f.read())
        if season not in record.keys():
            record[season] = []
        record[season].append(int(ep))
        record[season] = list(set(record[season]))
        record['name'] = name
        with open('{}/record/{}.json'.format(mydir, id), 'w') as f:
            f.write(json.dumps(record))
        
        copytasks.remove(t)
        with open('{}/task.txt'.format(mydir), 'w') as f:
            f.write(copytasks)
    except Exception as e:
        logger.warning(e)
    
    time.sleep(10)


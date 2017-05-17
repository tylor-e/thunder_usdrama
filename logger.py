#coding:utf-8

import logging

LOG_LEVEL = logging.INFO

logger = logging.getLogger()
if not logger.handlers:
    logger.setLevel(LOG_LEVEL)
    sh = logging.StreamHandler()
    sh.setLevel(LOG_LEVEL)
    sh.setFormatter(logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s'))
    logger.addHandler(sh)


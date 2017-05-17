#this is a py27 file!
__all__ = ['ThunderRemoteDownload', 'str_filesize']

import json
import logging
import os.path
import re
import time
import urllib
import urllib2
import cookielib
import hashlib
import base64

USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
LOG_LEVEL = logging.INFO

logger = logging.getLogger()
logger.setLevel(LOG_LEVEL)

sh = logging.StreamHandler()
sh.setLevel(LOG_LEVEL)
sh.setFormatter(logging.Formatter('[%(asctime)s %(levelname)s]: %(message)s'))
logger.addHandler(sh)


def retry(f_or_arg, *args):
    # retry_sleeps = [1, 1, 1]
    retry_sleeps = [1, 2, 3, 5, 10, 20, 30, 60] + [60] * 60

    def decorator(f):
        def withretry(*args, **kwargs):
            for second in retry_sleeps:
                try:
                    return f(*args, **kwargs)
                except (urllib2.URLError, urllib2.HTTPError):
                    import traceback
                    logger.debug("Exception happened. Retrying...")
                    logger.debug(traceback.format_exc())
                    time.sleep(second)
            raise

        return withretry

    if callable(f_or_arg) and not args:
        return decorator(f_or_arg)
    else:
        a = f_or_arg
        assert type(a) == int
        assert not args
        retry_sleeps = [1] * a
        return decorator


class ThunderRemoteDownload(object):

    def __init__(self, username=None, password=None, cookie_path=None, login=True, verification_code_reader=None):
        self.username = username
        self.password = password
        self.cookie_path = cookie_path
        if cookie_path:
            self.cookiejar = cookielib.LWPCookieJar()
            if os.path.exists(cookie_path):
                self.load_cookies()
        else:
            self.cookiejar = cookielib.CookieJar()

        self.opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(self.cookiejar))
        self.verification_code_reader = verification_code_reader
        self.login_time = None
        if login:
            self.id = self.get_userid_or_none()
            if not self.id:
                self.login()
            self.id = self.get_userid()

        self.selected_peer_id = None
        self.selected_peer_name = ""
        self.cached_peer_list = []
        self.default_target_dir = ""
        self.user_define_target_dirs = []
        self.peer_drives = []

        self.__load_last_configs()
        self.__init_default_peer()

    def __load_last_configs(self):
        tmp = self.get_cookie('config.com', 'selected_peer_id')
        if tmp:
            self.selected_peer_id = tmp

        tmp = self.get_cookie('config.com', 'user_define_target_dirs')
        if tmp:
            self.user_define_target_dirs = json.loads(tmp)

    @retry
    def urlopen(self, url, **args):
        logger.info('urlopen: {}'.format(url))
        #		import traceback
        #		for line in traceback.format_stack():
        #			print line.strip()
        if 'data' in args and type(args['data']) == dict:
            args['data'] = urlencode(args['data'])
            logger.debug(args['data'])
        resp = self.opener.open(urllib2.Request(url, **args), timeout=60)
        ###
        cookies_headers = resp.headers.getheaders('Set-Cookie')
        logger.debug('cookie: {!s}'.format(cookies_headers))
        ###
        return resp

    def __urlread(self, url, **args):
        args.setdefault('headers', {})
        headers = args['headers']
        headers.setdefault('Accept-Encoding', 'gzip, deflate')
        #		headers.setdefault('Referer', 'http://lixian.vip.xunlei.com/task.html')
        headers.setdefault('User-Agent', USER_AGENT)
        #		headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        #		headers.setdefault('Accept-Language', 'zh-cn,zh;q=0.7,en-us;q=0.3')
        response = self.urlopen(url, **args)
        data = response.read()
        if response.info().get('Content-Encoding') == 'gzip':
            data = ungzip(data)
        elif response.info().get('Content-Encoding') == 'deflate':
            data = undeflate(data)
        return data

    def urlread(self, url, **args):
        logger.info('urlread')
        logger.info('   V')
        data = self.__urlread(url, **args)
        if self.is_session_timeout(data):
            logger.debug('session timed out')
            self.login()
            data = self.__urlread(url, **args)
        return data

    def load_cookies(self):
        self.cookiejar.load(self.cookie_path, ignore_discard=True, ignore_expires=True)

    def save_cookies(self):
        if self.cookie_path:
            self.cookiejar.save(self.cookie_path, ignore_discard=True)

    def get_cookie(self, domain, k):
        if self.has_cookie(domain, k):
            return self.cookiejar._cookies[domain]['/'][k].value
        else:
            return None

    def has_cookie(self, domain, k):
        return domain in self.cookiejar._cookies and k in self.cookiejar._cookies[domain]['/']

    def set_cookie(self, domain, k, v):
        c = cookielib.Cookie(version=0, name=k, value=v, port=None, port_specified=False, domain=domain, domain_specified=True,
                             domain_initial_dot=False, path='/', path_specified=True, secure=False, expires=None, discard=True,
                             comment=None, comment_url=None, rest={}, rfc2109=False)
        self.cookiejar.set_cookie(c)

    def del_cookie(self, domain, k):
        if self.has_cookie(domain, k):
            self.cookiejar.clear(domain=domain, path="/", name=k)

    def get_cookie_header(self):
        def domain_header(domain):
            root = self.cookiejar._cookies[domain]['/']
            return '; '.join(k + '=' + root[k].value for k in root)

        return domain_header('.xunlei.com') + '; ' + domain_header('.vip.xunlei.com')

    def get_userid(self):
        if self.has_cookie('.xunlei.com', 'userid'):
            return self.get_cookie('.xunlei.com', 'userid')
        else:
            raise Exception('Probably login failed')

    def get_userid_or_none(self):
        return self.get_cookie('.xunlei.com', 'userid')

    def get_username(self):
        return self.get_cookie('.xunlei.com', 'usernewno')

    def get_referer(self):
        return 'http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s' % self.id

    def gen_jsonp_function_name(self):
        return 'jQuery{}_{}'.format(id(self), current_timestamp())

    def check_device_id(self):
        if not self.has_cookie('.xunlei.com', 'deviceid'):
            url1 = 'https://login.xunlei.com/risk?cmd=algorithm&t='+str(current_timestamp())
            sign_fun = self.__urlread(url1).decode()
            import js2py
            xl_al = js2py.eval_js(sign_fun)
            SB = USER_AGENT + "###zh-cn###24###960x1440###-540###true###true###true###undefined###undefined###x86###Win32#########"+md5(str(current_timestamp()).encode())
            xl_fp_raw = base64.b64encode(SB.encode()).decode()
            xl_fp = md5(xl_fp_raw.encode())
            xl_fp_sign = xl_al(xl_fp_raw)
            device_data = {'xl_fp_raw': xl_fp_raw, 'xl_fp': xl_fp, 'xl_fp_sign':xl_fp_sign}
            device_url = 'http://login.xunlei.com/risk?cmd=report'
            self.urlopen(device_url, data=device_data).read()
        if not self.has_cookie('.xunlei.com', '_x_t_'):
            self.set_cookie('.xunlei.com', '_x_t_', '0')

    def double_check_login(self):
        callback = self.gen_jsonp_function_name()
        url = 'http://hub.yuancheng.xunlei.com/check/vipcache?callback={}&_={}'.format(callback, current_timestamp())
        resp = self.urlopen(url, headers={'User-Agent': USER_AGENT}).read()
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            logger.warning('response is not jsonp when double_check_login')
            return False

        if resp.get('userid') and resp.get('userid') == self.id:
            return True
        return False

    def has_logged_in(self):
        id = self.get_userid_or_none()
        if not id:
            return False

        return self.double_check_login()


    def is_session_timeout(self, html):
        logger.info('is_session_timeout?')
        logger.debug('html: {}'.format(html))
        # timeout warning 1:
        # jQuery4444817808_1480233929775({"msg": "user not login", "rtn": 1004})
        timeout_test = r'(not login)|("rtn": 1004)'
        if re.search(timeout_test, html):
            return True

        maybe_timeout = html == '''rebuild({"rtcode":-1,"list":[]})'''
        if maybe_timeout:
            if self.login_time and time.time() - self.login_time > 60 * 10:  # 10 minutes
                return True

        return False

    def read_verification_code(self):
        if not self.verification_code_reader:
            raise NotImplementedError('Verification code required')
        else:
            verification_code_url = 'http://verify1.xunlei.com/image?t=MVA&cachetime=%s' % current_timestamp()
            image = self.urlopen(verification_code_url).read()
            return self.verification_code_reader(image)

    def login(self):
        username = self.username
        password = self.password
        if not username and self.has_cookie('.xunlei.com', 'usernewno'):
            username = self.get_username()
        if not username:
            raise Exception('Missing username')
        if not password:
            raise Exception('Missing password')

        logger.info('login')
        self.check_device_id()
        check_url = 'http://login.xunlei.com/check/?u=%s&business_type=113&v=101&cachetime=%d&' % (username, current_timestamp())
        login_page = self.urlopen(check_url).read()
#         verification_code = self.get_cookie('.xunlei.com', 'check_result')
#         if not verification_code:
#             verification_code = self.read_verification_code()
#             if verification_code:
#                 verification_code = verification_code.upper()
#         else:
#             verification_code = verification_code[2:].upper()
#         assert verification_code
        print self.get_cookie('.xunlei.com', 'deviceid')
        login_page = self.urlopen('https://login.xunlei.com/sec2login/?csrf_token={}'.format(hashlib.md5(self.get_cookie('.xunlei.com', 'deviceid')[:32]).hexdigest()), headers={'User-Agent': USER_AGENT},
                                  data={'u': username, 'p': password, 'verifycode': '', 'login_enable': '0',
                                        'business_type': '113', 'v': '101', 'cachetime': current_timestamp()})
        print self.cookiejar._cookies
        self.id = self.get_userid()

        if not self.double_check_login():
            raise RuntimeError('login failed')

        self.save_cookies()
        self.login_time = time.time()

    def logout(self):
        logger.info('logout')
        session_id = self.get_cookie('.xunlei.com', 'sessionid')
        if not session_id:
            return
        url = 'http://login.xunlei.com/unregister?sessionid={}'.format(session_id)
        self.urlopen(url)
        ckeys = ["sessionid", "usrname", "nickname", "usernewno", "userid"]
        for k in ckeys:
            self.set_cookie('.xunlei.com', k, '')
        self.save_cookies()
        self.login_time = None

    def select_peer(self, pid):
        logger.info('select peer: {}'.format(pid))
        self.selected_peer_id = pid
        self.set_cookie('config.com', 'selected_peer_id', pid)
        self.save_cookies()

        self.__init_default_peer()

    def get_selected_peer_name(self):
        return self.selected_peer_name

    def __init_default_peer(self):
        if not self.cached_peer_list:
            peers = self.list_peer()
            if not peers:
                raise Exception('No peer downloader')

        if not self.selected_peer_id:
            peers = self.cached_peer_list
            self.selected_peer_id = peers[0].get('pid')
            self.set_cookie('config.com', 'selected_peer_id', self.selected_peer_id)
            self.save_cookies()

        #check the peer still online
        the_peer = None
        for p in self.cached_peer_list:
            if p.get('pid') == self.selected_peer_id:
                the_peer = p
                break

        if not the_peer:
            raise Exception('It seems the selected downloader is unbound')

        if not the_peer.get('online') in [1, '1']:
            raise Exception('The selected downloader is offline')

        self.selected_peer_name = the_peer.get('name')

        #login the peer
        drive_list = self.login_peer(self.selected_peer_id)
        if not drive_list:
            raise Exception('Error when login the downloader')
        self.peer_drives = drive_list
        logger.debug('peer drives: {!s}'.format(drive_list))

        #get the peer's settings and save its default target dir
        setting = self.get_peer_setting(self.selected_peer_id)
        if not setting:
            raise Exception('Error when retrieving the setting of the downloader')

        self.default_target_dir = setting.get('defaultPath')

    @retry(3)
    def list_peer(self):
        logger.info('list_peer')

        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/listPeer?type=0&v=2&ct=0&callback={}&_={}'.format(callback, current_timestamp())
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when list_peer'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = []
        if resp.get('rtn') == 0:
            result = resp.get('peerList')
            self.cached_peer_list = result

        return result

    @retry(3)
    def login_peer(self, pid):
        """
        :param pid:
        :return: drive list of this peer - ["C", "D", ...]
        """
        logger.info('login_peer')

        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/login?pid={}&clientType=&v=2&ct=0&callback={}&_={}'.format(pid, callback, current_timestamp())
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when login_peer'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = []
        if resp.get('rtn') == 0:
            result = [x[0] for x in resp.get('pathList')]

        return result

    @retry(3)
    def get_peer_setting(self, pid):
        logger.info('get_peer_setting: {}'.format(pid))

        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/settings?pid={}&v=2&ct=0&callback={}&_={}'.format(
            pid, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when get_peer_setting'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = {}
        if resp.get('rtn') == 0:
            result = resp

        return result

    @retry(3)
    def list_downloading(self, start=0, len=100):
        logger.info('list_downloading')

        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/list?pid={}&type=0&pos={}&number={}&needUrl=1&v=2&ct=0&callback={}&_={}'.format(
            self.selected_peer_id, start, len, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when list_downloading'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = []
        if resp.get('rtn') == 0:
            result = resp.get('tasks')

        return result

    @retry(3)
    def list_finished(self, start=0, len=100):
        logger.info('list_finished')

        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/list?pid={}&type=1&pos={}&number={}&needUrl=1&v=2&ct=0&callback={}&_={}'.format(
            self.selected_peer_id, start, len, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when list_finished'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = []
        if resp.get('rtn') == 0:
            result = resp.get('tasks')

        return result

    @retry(3)
    def list_trash(self, start=0, len=100):
        logger.info('list_trash')

        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/list?pid={}&type=2&pos={}&number={}&needUrl=1&v=2&ct=0&callback={}&_={}'.format(
            self.selected_peer_id, start, len, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when list_trash'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = []
        if resp.get('rtn') == 0:
            result = resp.get('tasks')

        return result

    @retry(3)
    def get_free_space_of_downloader(self, pid=None):
        logger.info('get_free_space_of_downloader')

        if not pid:
            pid = self.selected_peer_id
        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/boxSpace?pid={}&v=2&ct=0&callback={}&_={}'.format(
            pid, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when get_free_space_of_downloader'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = []
        if resp.get('rtn') == 0:
            result = resp.get('space')
            def filter(x):
                x['remain'] = str_filesize(int(x['remain']))
                return x
            result = [filter(x) for x in result]

        return result

    def resolve_url(self, url):
        logger.info('resolve_url')

        callback = self.gen_jsonp_function_name()
        payload = dict(url=url)
        payload = dict(json=json.dumps(payload))
        url = 'http://homecloud.yuancheng.xunlei.com/urlResolve?pid={}&v=2&ct=0&callback={}'.format(
            self.selected_peer_id, callback
        )
        resp = self.urlread(url, data=payload)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when resolve_url'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        result = dict(url="", infohash="", size=0, name="")
        if resp.get('rtn') == 0 and resp.has_key('taskInfo'):
            result['infohash'] = resp.get('infohash', '')
            result['url'] = resp.get('taskInfo').get('url')
            result['size'] = resp.get('taskInfo').get('size')
            result['name'] = resp.get('taskInfo').get('name')

        return result

    def add_target_dir(self, dir):
        if not re.match(r'^[a-zA-Z]{1}:[\/\\]{1}.+$', dir):
            raise Exception('The dir is invalid path')
        if not dir[0].upper() in self.peer_drives:
            raise Exception('The downloader has no such drive: {}'.format(dir[0]))
        if not dir in self.user_define_target_dirs:
            self.user_define_target_dirs.append(dir)
            self.set_cookie('config.com', 'user_define_target_dirs', json.dumps(self.user_define_target_dirs))
            self.save_cookies()

    def remove_target_dir(self, dir_index):
        if dir_index+1 > len(self.user_define_target_dirs):
            raise Exception('The index exceed range')
        del self.user_define_target_dirs[dir_index]
        self.set_cookie('config.com', 'user_define_target_dirs', json.dumps(self.user_define_target_dirs))
        self.save_cookies()

    def list_target_dirs(self):
        return self.user_define_target_dirs

    def clear_target_dirs(self):
        self.user_define_target_dirs = []
        self.set_cookie('config.com', 'user_define_target_dirs', json.dumps(self.user_define_target_dirs))
        self.save_cookies()

    @retry(3)
    def create_task(self, url, path_index=None):
        logger.info('create_task')

        #resolve the url first
        url_info = self.resolve_url(url)
        size = url_info.get('size')
        if size == 0:
            raise Exception('Invalid URL provided')
        hash = url_info.get('infohash')
        name = url_info.get('name')
        url = url_info.get('url')

        #get the target dir
        target_path = self.default_target_dir
        if path_index != None:
            if path_index >= len(self.user_define_target_dirs):
                raise Exception('path_index out of range')
            target_path = self.user_define_target_dirs[path_index]

        callback = self.gen_jsonp_function_name()
        if hash:
            payload = dict(path=target_path, infohash=hash, name=name, btSub=[1])
            payload = dict(json=json.dumps(payload))
            url = 'http://homecloud.yuancheng.xunlei.com/createBtTask?pid={}&v=2&ct=0&callback={}'.format(
                self.selected_peer_id, callback
            )
            resp = self.urlread(url, data=payload)
            try:
                resp = get_response_info(resp, callback)
            except AssertionError as e:
                msg = 'response is not jsonp when create_task'
                logger.warning(msg)
                logger.debug(resp)
                raise Exception(msg)

            if resp.get('rtn') == 202:
                raise Exception('Already downloading/downloaded')

            return resp.get('rtn') == 0
        else:
            task = dict(url=url, name=name, gcid="", cid="", filesize=size, ext_json={"autoname":1})
            payload = dict(path=target_path, tasks=[task])
            payload = dict(json=json.dumps(payload))
            url = 'http://homecloud.yuancheng.xunlei.com/createTask?pid={}&v=2&ct=0&callback={}'.format(
                self.selected_peer_id, callback
            )
            resp = self.urlread(url, data=payload)
            try:
                resp = get_response_info(resp, callback)
            except AssertionError as e:
                msg = 'response is not jsonp when create_task'
                logger.warning(msg)
                logger.debug(resp)
                raise Exception(msg)

            if resp.get('tasks')[0].get('result') == 202:
                raise Exception('Already downloading/downloaded')

            return resp.get('rtn') == 0 and resp.get('tasks')[0].get('result') == 0

    @retry(3)
    def trash_task(self, task_id, task_state, permanently_del=False):
        """
        delete the task, but still in the trash, and the file is not deleted too, you can restore it with web gui.
        if permanently_del=True, the task can not be restored with any chance.
        :param task_id:
        :param task_state:
        :return:
        """
        logger.info('trash_task')

        param_task = '{}_{}'.format(task_id, task_state)
        recycle = 1
        delete_file = 'false'
        if permanently_del:
            recycle = 0
            delete_file = 'true'
        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/del?pid={}&tasks={}&recycleTask={}&deleteFile={}&v=2&ct=0&callback={}&_={}'.format(
            self.selected_peer_id, param_task, recycle, delete_file, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when trash_task'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        return resp.get('rtn') == 0 and resp.get('tasks')[0].get('result') == 0

    @retry(3)
    def pause_task(self, task_id, task_state):
        logger.info('pause_task')

        param_task = '{}_{}'.format(task_id, task_state)
        callback = self.gen_jsonp_function_name()
        url = 'http://homecloud.yuancheng.xunlei.com/pause?pid={}&tasks={}&v=2&ct=0&callback={}&_={}'.format(
            self.selected_peer_id, param_task, callback, current_timestamp()
        )
        resp = self.urlread(url)
        try:
            resp = get_response_info(resp, callback)
        except AssertionError as e:
            msg = 'response is not jsonp when pause_task'
            logger.warning(msg)
            logger.debug(resp)
            raise Exception(msg)

        return resp.get('rtn') == 0 and resp.get('tasks')[0].get('result') == 0



def current_timestamp():
    return int(time.time() * 1000)


def current_random():
    from random import randint
    return '%s%06d.%s' % (current_timestamp(), randint(0, 999999), randint(100000000, 9999999999))


def convert_task(data):
    expired = {'0': False, '4': True}[data['flag']]
    assert re.match(r'[^:]+', data['url']), 'Invalid URL in: ' + repr(data)
    task = {'id': data['id'],
            'type': re.match(r'[^:]+', data['url']).group().lower(),
            'name': decode_dirty_name(unescape_html(data['taskname'])),
            'status': int(data['download_status']),
            'status_text': {'0': 'waiting', '1': 'downloading', '2': 'completed', '3': 'failed', '5': 'pending'}[data['download_status']],
            'expired': expired,
            'size': int(data['ysfilesize']),
            'original_url': unescape_html(data['url']),
            'xunlei_url': data['lixian_url'] or None,
            'bt_hash': data['cid'],
            'dcid': data['cid'],
            'gcid': data['gcid'],
            'date': data['dt_committed'][:10].replace('-', '.'),
            'progress': '%s%%' % data['progress'],
            'speed': '%s' % data['speed'],
            }
    return task


def parse_json_response(html):
    m = re.match(ur'^\ufeff?rebuild\((\{.*\})\)$', html)
    if not m:
        logger.debug(html)
        raise RuntimeError('Invalid response')
    return json.loads(m.group(1))


def parse_json_tasks(result):
    tasks = result['info']['tasks']
    return map(convert_task, tasks)


def parse_task(html):
    inputs = re.findall(r'<input[^<>]+/>', html)

    def parse_attrs(html):
        return dict((k, v1 or v2) for k, v1, v2 in re.findall(r'''\b(\w+)=(?:'([^']*)'|"([^"]*)")''', html))

    info = dict((x['id'], unescape_html(x['value'])) for x in map(parse_attrs, inputs))
    mini_info = {}
    mini_map = {}
    # mini_info = dict((re.sub(r'\d+$', '', k), info[k]) for k in info)
    for k in info:
        mini_key = re.sub(r'\d+$', '', k)
        mini_info[mini_key] = info[k]
        mini_map[mini_key] = k
    taskid = mini_map['taskname'][8:]
    url = mini_info['f_url']
    task_type = re.match(r'[^:]+', url).group().lower()
    task = {'id': taskid,
            'type': task_type,
            'name': mini_info['taskname'],
            'status': int(mini_info['d_status']),
            'status_text': {'0': 'waiting', '1': 'downloading', '2': 'completed', '3': 'failed', '5': 'pending'}[mini_info['d_status']],
            'size': int(mini_info.get('ysfilesize', 0)),
            'original_url': mini_info['f_url'],
            'xunlei_url': mini_info.get('dl_url', None),
            'bt_hash': mini_info['dcid'],
            'dcid': mini_info['dcid'],
            'gcid': parse_gcid(mini_info.get('dl_url', None)),
            }

    m = re.search(r'<em class="loadnum"[^<>]*>([^<>]*)</em>', html)
    task['progress'] = m and m.group(1) or ''
    m = re.search(r'<em [^<>]*id="speed\d+">([^<>]*)</em>', html)
    task['speed'] = m and m.group(1).replace('&nbsp;', '') or ''
    m = re.search(r'<span class="c_addtime">([^<>]*)</span>', html)
    task['date'] = m and m.group(1) or ''

    return task


def parse_history(html):
    rwbox = re.search(r'<div class="rwbox" id="rowbox_list".*?<!--rwbox-->', html, re.S).group()
    rw_lists = re.findall(r'<div class="rw_list".*?<input id="d_tasktype\d+"[^<>]*/>', rwbox, re.S)
    return map(parse_task, rw_lists)


def parse_bt_list(js):
    result = json.loads(re.match(r'^fill_bt_list\((.+)\)\s*$', js).group(1))['Result']
    files = []
    for record in result['Record']:
        files.append({
            'id': record['taskid'],
            'index': record['id'],
            'type': 'bt',
            'name': record['title'],  # TODO: support folder
            'status': int(record['download_status']),
            'status_text': {'0': 'waiting', '1': 'downloading', '2': 'completed', '3': 'failed', '5': 'pending'}[record['download_status']],
            'size': int(record['filesize']),
            'original_url': record['url'],
            'xunlei_url': record['downurl'],
            'dcid': record['cid'],
            'gcid': parse_gcid(record['downurl']),
            'speed': '',
            'progress': '%s%%' % record['percent'],
            'date': '',
        })
    return files


def parse_gcid(url):
    if not url:
        return
    m = re.search(r'&g=([A-F0-9]{40})&', url)
    if not m:
        return
    return m.group(1)


def urlencode(x):
    def unif8(u):
        if type(u) == unicode:
            u = u.encode('utf-8')
        return u

    return urllib.urlencode([(unif8(k), unif8(v)) for k, v in x.items()])


def encode_multipart_formdata(fields, files):
    # http://code.activestate.com/recipes/146306/
    """
    fields is a sequence of (name, value) elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body) ready for httplib.HTTP instance
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for (key, filename, value) in files:
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % get_content_type(filename))
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body


def get_content_type(filename):
    import mimetypes
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'


def assert_default_page(response, id):
    # assert response == "<script>top.location='http://dynamic.cloud.vip.xunlei.com/user_task?userid=%s&st=0'</script>" % id
    assert re.match(
        r"^<script>top\.location='http://dynamic\.cloud\.vip\.xunlei\.com/user_task\?userid=%s&st=0(&cache=\d+)?'</script>$" % id,
        response), response


def remove_bom(response):
    if response.startswith('\xef\xbb\xbf'):
        response = response[3:]
    return response


def assert_response(response, jsonp, value=1):
    response = remove_bom(response)
    assert response == '%s(%s)' % (jsonp, value), repr(response)


def get_response_info(response, jsonp):
    response = remove_bom(response)
    m = re.search(r'%s\((.+)\)' % jsonp, response)
    assert m, 'invalid jsonp response: %s' % response
    # logger.debug('get_response_info:')
    # logger.debug(response)
    parameter = m.group(1)
    # m = re.match(r"^\{process:(-?\d+),msg:'(.*)'\}$", parameter)
    # if m:
    #     return {'process': int(m.group(1)), 'msg': m.group(2)}
    return json.loads(parameter)


def parse_url_protocol(url):
    m = re.match(r'([^:]+)://', url)
    if m:
        return m.group(1)
    elif url.startswith('magnet:'):
        return 'magnet'
    else:
        return url


def unescape_html(html):
    import xml.sax.saxutils
    return xml.sax.saxutils.unescape(html)


def to_utf_8(s):
    if type(s) == unicode:
        return s.encode('utf-8')
    else:
        return s


def md5(s):
    import hashlib
    return hashlib.md5(s).hexdigest().lower()


def ungzip(s):
    from StringIO import StringIO
    import gzip
    buffer = StringIO(s)
    f = gzip.GzipFile(fileobj=buffer)
    return f.read()


def undeflate(s):
    import zlib
    return zlib.decompress(s, -zlib.MAX_WBITS)


def is_dirty_resource(response_info):
    return response_info['progress'] == 2 and response_info.get('rtcode') == '76' and response_info.get(
        'msg') == u"\u6587\u4ef6\u540d\u4e2d\u5305\u542b\u8fdd\u89c4\u5185\u5bb9\uff0c\u65e0\u6cd5\u6dfb\u52a0\u5230\u79bb\u7ebf\u7a7a\u95f4[0976]"


def encode_dirty_name(x):
    import base64
    try:
        return unicode('[base64]' + base64.encodestring(x.encode('utf-8')).replace('\n', ''))
    except:
        return x


def decode_dirty_name(x):
    import base64
    try:
        if x.startswith('[base64]'):
            return base64.decodestring(x[len('[base64]'):]).decode('utf-8')
        else:
            return x
    except:
        return x

def str_filesize(size):
    '''
    author: limodou
    >>> print str_filesize(0)
    0
    >>> print str_filesize(1023)
    1023
    >>> print str_filesize(1024)
    1K
    >>> print str_filesize(1024*2)
    2K
    >>> print str_filesize(1024**2-1)
    1023K
    >>> print str_filesize(1024**2)
    1M
    '''
    import bisect
    d = [(1024 - 1, 'K'), (1024 ** 2 - 1, 'M'), (1024 ** 3 - 1, 'G'), (1024 ** 4 - 1, 'T')]
    s = [x[0] for x in d]
    index = bisect.bisect_left(s, size) - 1
    if index == -1:
        return str(size)
    else:
        b, u = d[index]
    return str(size / (b + 1)) + u

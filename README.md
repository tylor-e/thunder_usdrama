# thunder_usdrama
自动抓取字幕组热门美剧并加入迅雷远程下载

### 系统需要

1、python2、python3共存

2、python3安装lxml

### 使用说明

1、在config.py中修改username、password为迅雷账号密码，修改mydir为py文件所在目录

2、运行python3 scan.py即可

### 原理说明

1、脚本抓取字幕组一周排行榜( http://www.zimuzu.tv/html/top/week.html )内容，将本周收藏和浏览最多的剧两榜求交集，即为下载的美剧清单，获取下载链接后调取迅雷远程api加入下载队列；

2、若有关注的美剧，可在dramas.py中将剧的id加入到self.watchlist；

3、网页分析部分用python3实现，迅雷远程部分用python2实现；

4、yc_api、verification_code.py从其他项目中获得(具体项目追溯不到了)，水平不够未成功转为python3版本(这也是本脚本要双版本python的原因)，但其中的登录部分已经失效，进行了重写；

5、如果你的python2启动命令不是默认的"python"，请修改scan.py中call_thunder函数的cmd
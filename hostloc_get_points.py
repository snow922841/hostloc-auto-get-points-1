import os
import time
import random
import re
import textwrap
import requests
import logging
from pyaes import AESModeOfOperationCBC
from requests import Session as req_Session

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

logger = logging.getLogger(__name__)


# 随机生成用户空间链接
def randomly_gen_uspace_url() -> list:
    url_list = []
    # 访问小黑屋用户空间不会获得积分、生成的随机数可能会重复，这里多生成两个链接用作冗余
    for i in range(12):
        uid = random.randint(10000, 50000)
        url = "https://hostloc.com/space-uid-{}.html".format(str(uid))
        url_list.append(url)
    return url_list


# 使用Python实现防CC验证页面中JS写的的toNumbers函数
def toNumbers(secret: str) -> list:
    text = []
    for value in textwrap.wrap(secret, 2):
        text.append(int(value, 16))
    return text


# 不带Cookies访问论坛首页，检查是否开启了防CC机制，将开启状态、AES计算所需的参数全部放在一个字典中返回
def check_anti_cc() -> dict:
    result_dict = {}
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
    }
    home_page = "https://hostloc.com/forum.php"
    res = requests.get(home_page, headers=headers)
    aes_keys = re.findall('toNumbers\("(.*?)"\)', res.text)
    cookie_name = re.findall('cookie="(.*?)="', res.text)

    if len(aes_keys) != 0:  # 开启了防CC机制
        logger.info("检测到防 CC 机制开启！")
        if len(aes_keys) != 3 or len(cookie_name) != 1:  # 正则表达式匹配到了参数，但是参数个数不对（不正常的情况）
            result_dict["ok"] = 0
        else:  # 匹配正常时将参数存到result_dict中
            result_dict["ok"] = 1
            result_dict["cookie_name"] = cookie_name[0]
            result_dict["a"] = aes_keys[0]
            result_dict["b"] = aes_keys[1]
            result_dict["c"] = aes_keys[2]
    else:
        pass

    return result_dict


# 在开启了防CC机制时使用获取到的数据进行AES解密计算生成一条Cookie（未开启防CC机制时返回空Cookies）
def gen_anti_cc_cookies() -> dict:
    cookies = {}
    anti_cc_status = check_anti_cc()

    if anti_cc_status:  # 不为空，代表开启了防CC机制
        if anti_cc_status["ok"] == 0:
            logger.info("防 CC 验证过程所需参数不符合要求，页面可能存在错误！")
        else:  # 使用获取到的三个值进行AES Cipher-Block Chaining解密计算以生成特定的Cookie值用于通过防CC验证
            logger.info("自动模拟计尝试通过防 CC 验证")
            a = bytes(toNumbers(anti_cc_status["a"]))
            b = bytes(toNumbers(anti_cc_status["b"]))
            c = bytes(toNumbers(anti_cc_status["c"]))
            cbc_mode = AESModeOfOperationCBC(a, b)
            result = cbc_mode.decrypt(c)

            name = anti_cc_status["cookie_name"]
            cookies[name] = result.hex()
    else:
        pass

    return cookies


# 登录帐户
def login(username: str, password: str) -> req_Session:
    headers = {
        "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                      "AppleWebKit/537.36 (KHTML, like Gecko) "
                      "Chrome/87.0.4280.88 Safari/537.36",
        "origin": "https://hostloc.com",
        "referer": "https://hostloc.com/forum.php",
    }
    login_url = "https://hostloc.com/member.php?mod=logging&action=login&loginsubmit=yes&infloat=yes&lssubmit=yes&inajax=1"
    login_data = {
        "fastloginfield": "username",
        "username": username,
        "password": password,
        "quickforward": "yes",
        "handlekey": "ls",
    }

    s = req_Session()
    s.headers.update(headers)
    s.cookies.update(gen_anti_cc_cookies())
    res = s.post(url=login_url, data=login_data)
    res.raise_for_status()
    return s


# 通过抓取用户设置页面的标题检查是否登录成功
def check_login_status(s: req_Session) -> bool:
    test_url = "https://hostloc.com/home.php?mod=spacecp"
    res = s.get(test_url)
    res.raise_for_status()
    res.encoding = "utf-8"
    test_title = re.findall("<title>(.*?)<\/title>", res.text)

    if len(test_title) != 0:  # 确保正则匹配到了内容，防止出现数组索引越界的情况
        if test_title[0] != "个人资料 -  全球主机交流论坛 -  Powered by Discuz!":
            logger.info("帐户登录失败！")
            return False
        else:
            logger.info("帐户登录成功！")
            return True
    else:
        logger.info("无法在用户设置页面找到标题，该页面存在错误或被防 CC 机制拦截！")
        return False


# 抓取并打印输出帐户当前积分
def print_current_points(s: req_Session):
    test_url = "https://hostloc.com/forum.php"
    res = s.get(test_url)
    res.raise_for_status()
    res.encoding = "utf-8"
    points = re.findall("积分: (\d+)", res.text)

    if len(points) != 0:  # 确保正则匹配到了内容，防止出现数组索引越界的情况
        return "帐户当前积分：" + points[0]
    else:
        return "无法获取帐户积分，可能页面存在错误或者未登录！"


# 依次访问随机生成的用户空间链接获取积分
def get_points(s: req_Session):
    if check_login_status(s):
        logger.info(print_current_points(s))  # 打印帐户当前积分

        time.sleep(5)
        url_list = randomly_gen_uspace_url()
        # 依次访问用户空间链接获取积分，出现错误时不中断程序继续尝试访问下一个链接
        for i in range(len(url_list)):
            url = url_list[i]
            try:
                res = s.get(url)
                res.raise_for_status()
                logger.info(f"第{i + 1}个用户空间链接访问成功")
                time.sleep(5)  # 每访问一个链接后休眠5秒，以避免触发论坛的防CC机制
            except Exception as e:
                logger.error("链接访问异常：" + str(e))
            continue
        text = print_current_points(s)  # 再次打印帐户当前积分
        logger.info(text)
        time.sleep(5)
    else:
        text = "请检查你的帐户是否正确！"
        logger.info(text)
    return text


def check():
    username = os.environ["HOSTLOC_USERNAME"]
    password = os.environ["HOSTLOC_PASSWORD"]

    try:
        s = login(username, password)
        text = get_points(s)
        logger.info("*" * 30)
    except Exception as e:
        text = "程序执行异常：" + str(e)
        logger.info("*" * 30)

    text += "\n程序执行完毕，获取积分过程结束"
    logger.info(text)
    time.sleep(0)


check()



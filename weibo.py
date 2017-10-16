#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import io
import os
import sys
import rsa
import json
import base64
import imghdr
import binascii
from http import cookiejar
from getpass import getpass
from urllib import request, parse
from optparse import OptionParser

headers = {
    "User-Agent": "Mozilla/5.0"
}

class Weibo(object):

    def __init__(self, username, password):
        self.username = username
        self.password = password

    def login(self):
        url = "https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.19)"
        self.build_cookie()
        data = self.prelogin()
        data = self.build_post(data)
        try:
            req = request.Request(url, data=data, headers=headers)
            res = request.urlopen(req)
            data = res.read()
            regex = re.compile(r"location\.replace\((?:\"|\')(.*)(?:\"|\')\)\;")
            while True:
                ans = regex.search(data.decode("GBK"))
                if not ans:
                    break
                url = ans.group(1)
                req = request.Request(url, headers=headers)
                res = request.urlopen(req)
                data = res.read()
            ans = re.search(r'{"uniqueid":"(.*?)".*"userdomain":"(.*?)"}', data.decode("utf-8"))
            url = "https://weibo.com/u/%s/home%s" % (ans.group(1), ans.group(2))
            req = request.Request(url, headers=headers)
            res = request.urlopen(req)
            html = res.read().decode("utf-8").replace("\\", "")
            ans = re.search(r"nameBox.*?title.*?>(.*?)<", html)
            if ans:
                print("你好啊! %s" % ans.group(1))
            else:
                raise Exception("Oh shit!")
        except Exception as e:
            print("哼!登录失败: %s" % e)
            sys.exit(1)

    def build_cookie(self):
        self.cookie = cookiejar.CookieJar()
        cookie_handler = request.HTTPCookieProcessor(self.cookie)
        opener = request.build_opener(cookie_handler)
        request.install_opener(opener)

    def prelogin(self):
        url = "https://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su=%s&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.19)" % self.encrypt_nm()
        try:
            req = request.Request(url, headers=headers)
            res = request.urlopen(req)
            data = res.read()
            data = re.search(rb"\((.*)\)", data).group(1)
            data = json.loads(data)
            return data
        except Exception as e:
            print("预登录失败,嘿嘿: %s" % e)
            sys.exit(1)

    def build_post(self, data):
        post_data = {
            "entry": "weibo",
            "gateway": 1,
            "from": "",
            "savestate": 0,
            "qrcode_flag": "false",
            "useticket": 1,
            "pagerefer": "",
            "vsnf": 1,
            "su": self.encrypt_nm(),
            "service": "miniblog",
            "servertime": data["servertime"],
            "nonce": data["nonce"],
            "pwencode": "rsa2",
            "rsakv": data["rsakv"],
            "sp": self.encrypt_pw(data),
            "sr": "1920*1080",
            "encoding": "UTF-8",
            "prelt": 27,
            "url": "https://weibo.com/ajaxlogin.php?framelogin%=1&callback=parent.sinaSSOController.feedBackUrlCallBack",
            "returntype": "META"
        }
        data = parse.urlencode(post_data).encode("utf-8")
        return data

    def encrypt_nm(self):
        return base64.b64encode(parse.quote(self.username).encode("utf-8")).decode("utf-8")

    def encrypt_pw(self, data):
        rsa_e = 65537
        passwd = "%s\t%s\n%s" % (data["servertime"], data["nonce"], self.password)
        key = rsa.PublicKey(int(data["pubkey"], 16), rsa_e)
        passwd = rsa.encrypt(passwd.encode("utf-8"), key)
        self.password = ""
        passwd = binascii.b2a_hex(passwd)
        return passwd

    def fuck_albums(self, uid, directory, need_choice):
        url = "http://photo.weibo.com/albums/get_all?uid=%s&page=1&count=20" % uid
        req = request.Request(url, headers=headers)
        res = request.urlopen(req)
        html = res.read()
        data = json.loads(html)
        if not data['result']:
            print("获取相册列表失败...")
            return
        albums = []
        count = 0
        print("-- 相册列表 --")
        for album in data['data']['album_list']:
            if album['is_private'] or album['count']['photos'] == 0:
                continue
            albums.append((album['caption'], album['album_id'], album['type']))
            print("%s: %s(共%s张)" % (count, album['caption'], album['count']['photos']))
            count += 1
        if need_choice:
            choice = input("选择相册开始嘿嘿嘿(','隔开'-'范围): ")
            nums = []
            for num in choice.split(","):
                if not '-' in num:
                    nums.append(int(num))
                else:
                    nums.extend(range(int(num.split('-')[0]), int(num.split('-')[1])+1))
        else:
            nums = range(count)
        if not nums:
            print("你不选怪我咯???")
            return
        if not os.path.exists(directory):
            os.mkdir(directory)
        for num in nums:
            name, album_id, album_type = albums[num]
            print("开始爬取%s..." % name)
            path = os.path.join(directory, name)
            if not os.path.exists(path):
                os.mkdir(path)
            self.fuck_photos(uid, album_id, album_type, path)

    def fuck_photos(self, uid, album_id, album_type, path):
        url = "http://photo.weibo.com/photos/get_all"
        params = {
            "uid": uid,
            "album_id": album_id,
            "type": album_type,
            "count": 30,
            "page": 1
        }
        count = 0
        while True:
            req = request.Request("%s?%s" % (url, parse.urlencode(params)), headers=headers)
            res = request.urlopen(req)
            data = json.loads(res.read())
            if not data['result'] or not data['data']['photo_list']:
                break
            for photo in data['data']['photo_list']:
                if photo['pic_name'].endswith(".gif"):
                    continue
                photo_url = "%s/%s/%s" % (photo['pic_host'], 'large', photo['pic_name'])
                req = request.Request("%s/%s/%s" % (photo['pic_host'], 'large', photo['pic_name']), headers=headers)
                res = request.urlopen(req)
                img = res.read()
                img_t = imghdr.what(io.BytesIO(img))
                if img_t:
                    img_path = os.path.join(path, "%s.%s" % (photo['timestamp'], img_t))
                    same = 1
                    while os.path.exists(img_path):
                        img_path = os.path.join(path, "%s.%s" % (int(photo['timestamp'])-same, img_t))
                        same += 1
                    with open(img_path, "wb") as f:
                        f.write(img)
                    count += 1
                    print("完成了%s张(%s)~~~" % (count, img_path))
            params['page'] += 1

def main():
    parser = OptionParser(usage="Usage: %prog -u <username> -d <user id> -p <path>")
    parser.add_option("-u", "--user", metavar="用户名", dest="user", type="string", help="用户名或邮箱地址")
    parser.add_option("-d", "--uid", metavar="用户ID", dest="uid", type="string", help="指定用户相册ID")
    parser.add_option("-p", "--path", metavar="保存路径", dest="path", type="string", help="指定保存路径")
    parser.add_option("-c", "--choice", dest="choice", action="store_true", default=False, help="取消默认爬取全部")
    opts, args = parser.parse_args()

    username = opts.user
    uid = opts.uid
    path = opts.path
    choice = opts.choice

    if not username or not uid or not path:
        parser.print_help()
        sys.exit(1)

    password = getpass("密码: ")
    weibo = Weibo(username, password)
    weibo.login()
    weibo.fuck_albums(uid, path, choice)

if __name__ == "__main__":
    main()

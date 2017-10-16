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
from urllib import request, parse

headers = {
    "User-Agent": "Mozilla/5.0"
}

uid = "xxxxxxxxxx"
username = "xxxxxxxxxx@xx.com"
password = "xxxxxxxxxx"

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

    def fuck_albums(self, uid):
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
        choice = input("选择相册开始嘿嘿嘿(','隔开'-'范围): ")
        nums = []
        for num in choice.split(","):
            if not '-' in num:
                nums.append(int(num))
            else:
                nums.extend(range(int(num.split('-')[0]), int(num.split('-')[1])+1))
        if not nums:
            print("你不选怪我咯???")
            return
        path = input("储存链接的文本: ")
        for num in nums:
            name, album_id, album_type = albums[num]
            print("开始爬取%s图片链接..." % name)
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
                photo_url = "%s/%s/%s\n" % (photo['pic_host'], 'large', photo['pic_name'])
                with open(path, "a") as f:
                    f.write(photo_url)
                    count += 1
                    print("完成了%s条链接~~~" % count)
            params['page'] += 1

if __name__ == "__main__":
    weibo = Weibo(username, password)
    weibo.login()
    weibo.fuck_albums(uid)

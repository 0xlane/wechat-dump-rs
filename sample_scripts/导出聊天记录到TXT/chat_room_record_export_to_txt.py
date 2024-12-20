###################################################################################
# 
#   功能：导出某个群聊某段时间聊天记录为 txt，可以交给 GPT 总结（仅适用于微信4.0）
#
#               作者：@reinject  
#               仓库：https://github.com/0xlane/wechat-dump-rs
#
#   环境准备：
#       1. 安装 python3
#       2. pip install -r requirements.txt
#  
#   使用方式：
#       1. 使用 wechat-dump-rs 工具解密所有微信数据库文件到此脚本所在目录
#                   wechat-dump-rs.exe -a -o .\db
#       2. 修改脚本中必需要修改的参数
#                   group_name: 要导出的群聊名称
#                   start: 开始日期
#                   end: 结束日期（不包含）
#       3. python 运行脚本生成 txt 文件
#
###################################################################################

from pathlib import Path
import sqlite3
from datetime import datetime
import zstandard
from hashlib import md5
import xml.etree.ElementTree as ET
import base64
import random


group_name = "📸•R62•摄影交流"
start = "2024-12-18"
end = "2024-12-19"
output_file = f"{group_name}_msg_{start}-{end}.txt"


class SQLiteDB:
    def __init__(self, db_file):
        """初始化时设置数据库文件路径"""
        self.db_file = db_file
        self.conn = None
        self.cursor = None

    def _connect(self):
        """连接数据库（只连接一次）"""
        if self.conn is None:
            self.conn = sqlite3.connect(self.db_file)  # 连接数据库
            self.cursor = self.conn.cursor()           # 创建游标

    def _close(self):
        """关闭数据库连接"""
        if self.cursor:
            self.cursor.close()  # 关闭游标
        if self.conn:
            self.conn.close()    # 关闭数据库连接
            self.conn = None      # 置空连接

    def fetch_all(self, query, params=()):
        """执行查询操作并返回结果"""
        self._connect()  # 确保连接已打开
        self.cursor.execute(query, params)
        result = self.cursor.fetchall()
        return result

    def fetch_one(self, query, params=()):
        """执行查询操作并返回结果"""
        self._connect()  # 确保连接已打开
        self.cursor.execute(query, params)
        result = self.cursor.fetchone()
        return result

    def __del__(self):
        """析构函数，自动关闭连接"""
        self._close()


def str_md5(ss: str) -> str:
    """Calculate the md5 for string"""
    m = md5()
    m.update(ss.encode())
    return m.digest().hex()


def zstd_decompress(data: bytes) -> bytes:
    """Decompress with zstd"""
    zctx = zstandard.ZstdDecompressor()
    return zctx.decompress(data)


def find(dir: str, glob: str) -> list:
    """Scan all files within special directory"""
    root_dir = Path(dir)
    return [item for item in root_dir.rglob(glob) if item.is_file()]


class WeixinDbStorage:
    def __init__(self):
        self.contact_db = SQLiteDB(find(".", "contact.db")[0])
        self.message_dbs = [SQLiteDB(item) for item in find(".", "message_?.db")]

    def get_username_by_nickname(self, nickname: str) -> str:
        """通过昵称获取用户名"""
        sql = "SELECT username FROM contact WHERE nick_name == ?"
        result = self.contact_db.fetch_one(sql, (nickname,))
        return result[0] if result else None

    def find_msg_db_by_table_name(self, table: str) -> SQLiteDB:
        """通过表名查找所在数据库"""
        for db in self.message_dbs:
            result = db.fetch_all("SELECT name FROM sqlite_master WHERE type='table'")
            tbls = [item[0] for item in result]
            if table in tbls:
                return db

    def get_msg_list_by_username(self, username: str, start: str, end: str) -> list:
        """通过用户名获取聊天记录"""
        username_md5 = str_md5(username)
        msg_table_name = f"Msg_{username_md5}"
        print(
            f"[+] The chat records of {group_name} are stored in the {msg_table_name} table")
        msg_db = self.find_msg_db_by_table_name(msg_table_name)

        start = int(datetime.strptime(start,
                                      '%Y-%m-%d').timestamp())
        end = int(datetime.strptime(end,
                                    '%Y-%m-%d').timestamp())

        '''
        1               文本消息
        3               图片消息
        34              语音消息
        42              名片消息
        43              视频消息
        47              第三方动画表情
        48              位置消息
        244813135921    引用消息
        17179869233     卡片式链接（带描述）
        21474836529     卡片式链接
        154618822705    小程序分享
        12884901937     音乐卡片
        8594229559345   红包卡片
        81604378673     聊天记录合并转发消息
        266287972401    拍一拍消息
        8589934592049   转账卡片
        270582939697    视频号直播卡片
        25769803825     文件消息
        10000           系统消息（撤回、加入群聊、群管理、群语音通话等）
        '''
        sql = f"SELECT local_type, real_sender_id, message_content FROM {
            msg_table_name} WHERE local_type IN (1, 3, 43, 47, 25769803825, 21474836529, 244813135921, 154618822705, 17179869233) AND create_time BETWEEN ? AND ? ORDER BY sort_seq ASC"
        result = msg_db.fetch_all(sql, (start, end,))

        result = [list(item) for item in result]

        username_r_q = {}

        for item in result:
            if isinstance(item[-1], str):
                item[-1] = item[-1].encode()

            if item[-1][:4] == b"\x28\xb5\x2f\xfd":
                item[-1] = zstd_decompress(item[-1])
            sql = "SELECT user_name FROM (SELECT ROW_NUMBER() OVER () AS id, user_name FROM Name2Id) AS tt WHERE tt.id = ?"
            result_2 = msg_db.fetch_one(sql, (item[1], ))
            username = result_2[0]
            msg_prefix = f"{username}:\n".encode()
            if item[-1][:len(msg_prefix)] != msg_prefix:
                item[-1] = msg_prefix + item[-1]
            if item[0] == 3:
                item[-1] = item[-1].split()[0] + "\n[图片消息]".encode()
            if item[0] == 43:
                item[-1] = item[-1].split()[0] + "\n[视频消息]".encode()
            if item[0] in (47, 25769803825, 21474836529, 244813135921, 154618822705, 17179869233, ):
                xml_msg = b"\n".join(item[-1].split(b"\n")[1:])
                if xml_msg[:6] != b"<?xml ":
                    xml_msg = b"<?xml version='1.0' encoding='utf-8'?>\n" + xml_msg
                xml_msg = xml_msg.strip(b"\x00")
                parser = ET.XMLParser(encoding="utf-8")
                root = ET.fromstring(xml_msg, parser=parser)
                if b"<msg><emoji " in item[-1]:
                    emoji_desc = root.find('emoji').get('desc')
                    if not emoji_desc is None and emoji_desc != "":
                        emoji_desc = base64.b64decode(emoji_desc)
                        if b"zh_cn\x12" in emoji_desc:
                            tmp = emoji_desc.split(b"zh_cn\x12")[1]
                            cap_len = tmp[0]
                            if cap_len > 0:
                                cap = tmp[1:1+cap_len]
                                item[-1] = item[-1].split()[0] + "\n[动画表情]".encode() + cap
                                continue
                        if b"zh_tw\x12" in emoji_desc:
                            tmp = emoji_desc.split(b"zh_tw\x12")[1]
                            cap_len = tmp[0]
                            if cap_len > 0:
                                cap = tmp[1:1+cap_len]
                                item[-1] = item[-1].split()[0] + "\n[动画表情]".encode() + cap
                                continue
                        if b"default\x12" in emoji_desc:
                            tmp = emoji_desc.split(b"default\x12")[1]
                            cap_len = tmp[0]
                            if cap_len > 0:
                                cap = tmp[1:1+cap_len]
                                item[-1] = item[-1].split()[0] + \
                                    "\n[动画表情]".encode() + cap
                                continue
                    else:
                        emoji_attr = root.find('emoji').get('emojiattr')
                        if not emoji_attr is None and emoji_attr != "":
                            emoji_attr = base64.b64decode(emoji_attr)
                            cap_len = emoji_attr[1]
                            cap = emoji_attr[2:2+cap_len]
                            item[-1] = item[-1].split()[0] + "\n[动画表情]".encode() + cap
                        else:
                            item[-1] = None
                else:
                    prefix = "[卡片消息]"
                    if item[0] == 244813135921:
                        prefix = ""
                    if item[0] == 25769803825:
                        prefix = "[文件消息]"
                    if item[0] == 154618822705:
                        prefix = "[小程序卡片消息]"
                    item[-1] = item[-1].split()[0] + f"\n{prefix}".encode() + \
                        root.find('appmsg').find('title').text.encode()
                    if item[0] in (17179869233, 21474836529):
                        item[-1] = item[-1] + b" "  + root.find('appmsg').find('url').text.encode()
            if item[-1] != None:
                # 用户名脱敏
                username = item[-1].split()[0]
                if username_r_q.get(username) is None:
                    username_r_q[username] = (chr(ord('m') + random.randint(0, 9)).encode(), chr(ord('d') + random.randint(0, 9)).encode())
                r, q = username_r_q[username]
                r_l = len(item[-1].split()[0][0:-4])
                q_l = len(item[-1].split()[0][0:-3])
                item[-1] = item[-1][0:r_l] + r + item[-1][r_l + 1:]
                item[-1] = item[-1][0:q_l] + q + item[-1][q_l + 1:]

        result = [item for item in result if not (item[-1] is None or (
            len(item[-1].split(b"\n")) > 5 and "群聊总结" in item[-1].split(b"\n")[1].decode()))]

        return result


if __name__ == "__main__":
    wx = WeixinDbStorage()
    username = wx.get_username_by_nickname(group_name)
    print(f"[+] The username of the group {group_name} is {username}")
    msg_list = wx.get_msg_list_by_username(
        username, start, end)
    msg_content_list = [item[-1].decode(errors='ignore') for item in msg_list]
    msg_content = "\n\n".join(msg_content_list)
    print(f"[+] Message content has writen to {output_file}")
    with open(output_file, "w", encoding="utf8") as fp:
        fp.write(msg_content)

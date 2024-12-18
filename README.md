# wechat-dump-rs （支持微信4.0版本）

该工具用于导出正在运行中的微信进程的 key 并自动解密所有微信数据库文件以及导出 key 后数据库文件离线解密。

![demo](images/demo.gif)

> **可能存在封号风险，后果自负！！！**
>
> **使用需知**：
> 微信4.0 重构后改用 HMAC_SHA512 算法，寻找 key 的方式和 v3 不同，工具内仍然采用内存暴力搜索的方式，对于 v4 解密时将使用多线程加速，可能会导致 cpu 飙到 100%，取决于 key 离起始查找点的距离。

## 工具用法

```bash
wechat-dump-rs (1.0.13) - REinject
A wechat db dump tool
Options:
  -p, --pid <PID>        pid of wechat
  -k, --key <KEY>        key for offline decryption of db file
  -f, --file <PATH>      special a db file path
  -d, --data-dir <PATH>  special wechat data dir path (pid is required)
  -o, --output <PATH>    decrypted database output path
  -a, --all              dump key and decrypt db files
      --vv <VERSION>     wechat db file version [default: 4] [possible values: 3, 4]
  -r, --rawkey           convert db key to sqlcipher raw key (file is required)
  -h, --help             Print help
```

如果不带任何参数，程序只输出所有微信进程的 key、微信号、手机号、数据目录、版本等信息：

```bash
=======================================
ProcessId: 4276
WechatVersion: 4.0.0.26
AccountName: xxxxxx
NickName: xxxxxx
Phone: 15111611111
DataDir: C:\Users\xxx\Documents\xwechat_files\wxid_xxxx_xxa\
key: f11fd83bxxxxxx4f3f4x4ddxxxxxe417696b4axx19e09489ad48c
=======================================
```

使用参数 `-a` 可以直接导出所有数据库文件。

### 使用 sqlcipher browser 浏览数据库

工具自动解密后的文件可能存在畸形问题，可以直接使用 [DB Browser for SQLCipher](https://sqlitebrowser.org/) 浏览原始数据库文件。

打开 sqlcipher 数据库时，选择 “原始密钥”，微信 V3 选择 自定义（页大小4096/KDF迭代64000/HMAC算法SHA1/KDF算法SHA1），V4 选择 sqlcipher4 默认，每个数据库文件对应的原始密钥都是不一样的，获取方式如下：

微信 V3 数据库文件 rawkey：

```bash
wechat-dump-rs.exe -k xxxxxxxxxxxxxxxxx -f c:\users\xxxx\xxxx\contact.db -r --vv 3
```

微信 V4 数据库文件 rawkey：

```bash
wechat-dump-rs.exe -k xxxxxxxxxxxxxxxxx -f c:\users\xxxx\xxxx\contact.db -r --vv 4
```

## 原理

一般情况下，key 要在运行的微信进程内存中拿到，内存偏移在每个版本都不一样，大部分工具是对每个版本维护一套偏移，但是当出现新版本的时候都要重新找偏移，方法见后面有简单记录。

其实，除了这个方法外，还有一个更通用的方法就是内存暴力搜索找到能用于解密的密钥位置，当然如果对进程全部内存扫一遍肯定不行，所以项目里用下面这种方式缩小密钥内存范围加快扫描速度：

1. ~~微信登录设备类型基本只有 iphone、android，在内存中先搜到设备类型所在内存，key 就在它的前面，向前搜就行~~
2. ~~key 的内存地址和登录设备类型据我观察是 16 字节对齐的，所以每次向前 16 字节~~

还有其它一些小细节，直接看一下代码吧。

## 已测试版本列表

其它未测试版本不代表不能用，这个列表只是我本地有过的环境。

- 3.9.6.33
- 3.9.7.25
- 3.9.7.29
- 3.9.8.9
- 3.9.8.15
- 3.9.10.19
- 3.9.11.25
- 3.9.12.15
- 3.9.12.17
- 4.0.0.26
- 4.0.0.32
- 4.0.0.34
- 4.0.0.35
- 4.0.1.11
- 4.0.1.13
- 4.0.1.17

## 库表结构

- [4.0.0.26](docs/wechat_4_0_0_26_table_struct.md)

> 4.0 聊天记录内容解析参考示例 [导出聊天记录到TXT](./sample_scripts/导出聊天记录到TXT/)。

## 微信分析记录

- [微信3.9手动寻找偏移](docs/wechat_3_9_analysis.md)
- [微信4.0寻找key过程](docs/wechat_4_0_analysis.md)

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=0xlane/wechat-dump-rs&type=Date)](https://star-history.com/#0xlane/wechat-dump-rs&Date)

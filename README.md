# wechat-dump-rs （支持微信4.0版本）

该工具用于导出正在运行中的微信进程的 key 并自动解密所有微信数据库文件以及导出 key 后数据库文件离线解密。

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

工具目前对稍微大点的库文件解密后可能存在畸形问题，建议使用 [DB Browser for SQLCipher](https://sqlitebrowser.org/) 进行浏览。

打开 sqlcipher 数据库时，选择 “原始密钥”，微信 V3 选择 sqlcipher3，V4 选择 sqlcipher4，每个数据库文件对应的原始密钥都是不一样的，获取方式如下：

微信 V3 数据库文件 rawkey：

```bash
wechat-dump-rs.exe -k xxxxxxxxxxxxxxxxx -f c:\users\xxxx\xxxx\contact.db -r -vv 3
```

微信 V4 数据库文件 rawkey：

```bash
wechat-dump-rs.exe -k xxxxxxxxxxxxxxxxx -f c:\users\xxxx\xxxx\contact.db -r -vv 4
```

## 原理

一般情况下，key 要在运行的微信进程内存中拿到，内存偏移在每个版本都不一样，大部分工具是对每个版本维护一套偏移，但是当出现新版本的时候都要重新找偏移，方法见后面有简单记录。

其实，除了这个方法外，还有一个更通用的方法就是内存暴力搜索找到能用于解密的密钥位置，当然如果对进程全部内存扫一遍肯定不行，所以项目里用下面这种方式缩小密钥内存范围加快扫描速度：

1. 微信登录设备类型基本只有 iphone、android，在内存中先搜到设备类型所在内存，key 就在它的前面，向前搜就行
2. key 的内存地址和登录设备类型据我观察是 16 字节对齐的，所以每次向前 16 字节

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

## 如何手动寻找偏移

**微信4.0分析在 [wechat_4_0_analysis](docs/wechat_4_0_analysis.md)**

> 注意：我找的偏移不是其他人找的直接的内存偏移，而是微信的一个数据结构相对偏移，这个有什么用呢，我刚开始打算通过 yara 扫 `WeChatWin.dll` 二进制文件确定一个相对偏移，然后根据内存中找到的设备类型地址就能直接推算出其它数据的内存地址，通不通用的关键就在于 yara 了，我没写出通用的，所以才改成了上面的思路。

使用 CheatEngine 在内存中搜索找到 key 或微信号的内存地址，必须是在 `WeChatWin.dll` 内存范围内，然后使用 x64dbg 动态调试，在 key 地址下硬件内存访问断点，之后登录微信后可中断到一个地方，然后一直向上回溯可以找到偏移。

以微信号为例，在 CE 中搜索，我这里使用第二个地址，因为它和 key 的位置比较近：

![1.png](images/1.png)
![2.png](images/2.png)

在 x64dbg 中跳过去

![3.png](images/3.png)

加个硬件访问断点

![4.png](images/4.png)

然后会自动断下或者需要重启后重新登录断下，`r12` 寄存器当前地址就是微信号所在地址：

![5.png](images/5.png)

在这个指令这里右键复制文件偏移，在 ida 中打开 `wechatwin.dll` 跳转过去：

![6.png](images/6.png)

之后，到 ida 可以很明显看到 `r12` 的地址来自于 `sub_1808D2FA0：`

![7.png](images/7.png)

在 `sub_1808D2FA0` 的最后可以拿到一个地址 `183B28120` ：

![8.png](images/8.png)

`183B28120` + `720` - `180000000` = `3B28840`

![9.png](images/9.png)

在 x64dbg 中就可以根据这个文件偏移明确找到微信号的位置，和最初 CE 里搜到的地址一致：

![10.png](images/10.png)

通过同样的方式，分别找到 nickname、phone、key 的相对偏移。

nickename：`183B28120` + `1E8` - `180000000` = `3B28308`

![11.png](images/11.png)

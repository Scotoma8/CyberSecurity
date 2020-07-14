# Useful Resources

## shodan搜索

### 工业控制系统

- 三星电子牌

	- "Server: Prismview Player"

- 加油站泵控制器

	- "in-tank inventory" port:10001

- 自动车牌记录器

	- P372 "ANPR enabled"

- 交通信号控制灯

	- mikrotik streetlight

- 美国投票机

	- "voter system serial" country:US

- 思科拦截监听设备有关的电信公司

	- "Cisco IOS" "ADVIPSERVICESK9_LI-M"

- 监狱公用电话

	- "[2J[H Encartele Confidential"

- 特斯拉PowerPack充电系统

	- http.title:"Tesla PowerPack System" http.component:"d3" -ga3ca4f2

- 电动汽车充电器

	- "Server: gSOAP/2.8" "Content-Length: 583"

- 海上卫星

	- "Cobham SATCOM" OR ("Sailor" "VSAT")

- 实时绘制船舶位置

	- https://shiptracker.shodan.io/

- 潜艇任务控制面板

	- title:"Slocum Fleet Mission Control"

- CAREL PlantVisor制冷机组

	- "Server: CarelDataServer" "200 Document follows"

- 使用Nordex风力涡轮机的农场

	- http.title:"Nordex Control" "Windows 2000 5.0 x86" "Jetty/3.1 (JSP 1.1; Servlet 2.2; java 1.6.0_14)"

- C4 Max汽车GPS跟踪器

	- "[1m[35mWelcome on console"

- DICOM医用X射线机器

	- "DICOM Server Response" port:104

- GaugeTech电表Meters

	- "Server: EIG Embedded Web Server" "200 Document follows"

- 西门子工业控制器

	- "Siemens, SIMATIC" port:161

- 西门子HVAC控制器

	- "Server: Microsoft-WinCE" "Content-Length: 12581"

- 门禁控制器

	- "HID VertX" port:4070

- 铁路管理系统

	- "log off" "select the appropriate"

### 远程桌面

- 未被保护的VNC

	- "authentication disabled" "RFB 003.008"

- Windows的远程桌面

	- "\x03\x00\x00\x0b\x06\xd0\x00\x00\x124\x00"

### 基础网络架构

- MongoDB

	- "MongoDB Server Information" port:27017 -authentication

- Mongo Express网页界面

	- "Set-Cookie: mongo-express=" "200 OK"

- Jenkins

	- "X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"

- Docker的API

	- "Docker Containers:" port:2375

- Pi-hole开放DNS服务器

	- "dnsmasq-pi-hole" "Recursion: enabled"

- 以root登录的Telent

	- "root@" port:23 -login -password -name -Session

- Android Root Bridges

	- "Android Debug Bridge" "Device" port:5555

- Lantronix串行以太网适配器（存在密码泄露缺陷）

	- Lantronix password port:30718 -secured

- Citrix Virtual Apps

	- "Citrix Applications:" port:1604

- Cisco Smart Install

	- "smart install client active"

- PBX网络电话网关

	- PBX "gateway console" -password port:23

- Polycom视频会议软件

	- http.title:"- Polycom" "Server: lighttpd"
"Polycom Command Shell" -failed port:23

- Bomgar Help Desk门户

	- "Server: Bomgar" "200 OK"

- Intel主动管理功能

	- "Intel(R) Active Management Technology" port:623,664,16992,16993,16994,16995

- HP iLO 4

	- HP-ILO-4 !"HP-ILO-4/2.53" !"HP-ILO-4/2.54" !"HP-ILO-4/2.55" !"HP-ILO-4/2.60" !"HP-ILO-4/2.61" !"HP-ILO-4/2.62" !"HP-iLO-4/2.70" port:1900

- Outlook网页界面

	- Exchange 2007：
"x-owa-version" "IE=EmulateIE7" "Server: Microsoft-IIS/7.0"

Exchange 2010：
"x-owa-version" "IE=EmulateIE7" http.favicon.hash:442749392

Exchange 2013/2016：
"X-AspNet-Version" http.title:"Outlook" -"x-owa-version"

### 网络存储设备（NAS）

- SMB文件分享

	- "Authentication: disabled" port:445

"Authentication: disabled" NETLOGON SYSVOL -unix port:445

- 可匿名登录的FTP

	- "220" "230 Login successful." port:21

- 罗技多媒体服务器

	- "Server: Logitech Media Server" "200 OK"

- Plex多媒体服务器

	- "X-Plex-Protocol" "200 OK" port:32400

### 网络摄像头

- Yawcams

	- "Server: yawcam" "Mime-Type: text/html"

- webcamXP/webcam7

	- ("webcam 7" OR "webcamXP") http.component:"mootools" -401

- Android网络摄像头服务器

	- "Server: IP Webcam Server" "200 OK"

- 安全硬盘录像机

	- html:"DVR_H264 ActiveX"

### 打印机和复印机

- HP打印机

	- "Serial Number:" "Built:" "Server: HP HTTP"

- Xerox打/复印机

	- ssl:"Xerox Generic Root"

- Epson打印机

	- "SERVER: EPSON_Linux UPnP" "200 OK"
"Server: EPSON-HTTP" "200 OK"

- 佳能打印机

	- "Server: KS_HTTP" "200 OK"
"Server: CANON HTTP Server"

### 家庭智能设备

- 雅马哈音响

	- "Server: AV_Receiver" "HTTP/1.1 406"

- 苹果AirPlay接受器（Apple TVs, HomePods等）

	- "\x08_airplay" port:5353

- Chromecasts/Smart TV

	- "Chromecast:" port:8008

- Crestron智能家居控制器

	- "Model: PYNG-HUB"

### 其他

- OctoPrint的3D打印机

	- title:"OctoPrint" -title:"Login" http.favicon.hash:1307375944

- 挖矿软件

	- "ETH - Total speed"

- Apache目录遍历

	- http.title:"Index of /" http.html:".pem"

### favicon搜索

- 搜索ip
查看原始数据
查看data.0.http.favicon.hash的值
搜索http.favicon.hash:哈希值
data.0.http.favicon.data位icon的base64编码

import mmh3
import requests
response = requests.get('https://www.baidu.com/favicon.ico')
favicon = response.content.encode('base64')
hash = mmh3.hash(favicon)
print hash
搜索http.favicon.hash:哈希值

### 搜索语法关键词列表

- 附录B：搜索语法关键词列表
常用语法
过滤器名	描述	类型	举例
after	只显示给出日期之后的结果(dd/mm/yyyy)	string	after:"04/02/2017"
asn	自治系统号码	string	asn:"AS4130"
before	只显示给出日期之前的结果(dd/mm/yyyy)	string	before:"04/02/2017"
category	现有的分类：ics,malware	string	category:"malware"
city	城市的名字	string	city:"San Diego"
country	国家简写	string	country:"ES" country:"CN"
geo	经纬度	string	geo:"46.9481,7.4474"
hash	数据的hash值	int	-hash:0
has_ipv6	是否是IPv6	boolean	has_ipv6:true
has_screenshot	是否有截图	boolean	has_screenshot:true
hostname	主机名或域名	string	hostname:"google"
ip	ip地址	string	ip:"54.67.82.248 "
isp	ISP供应商	string	isp:"China Telecom"
org	组织或公司	string	org:"google"
os	操作系统	string	os:"Windows 7 or 8"
port	端口号	int	port:21
postal	邮政编码(仅限于美国)	string	postal:"98221"
product	软件、平台	string	product:"Apache httpd" product:"openssh"
region	地区或国家别名	string	-
state		string	-
net	CIDR格式的IP地址	string	net:190.30.40.0/24
version	软件版本	string	version:"2.6.1"
vuln	漏洞的CVE ID	string	vuln:CVE-2014-0723
HTTP过滤器
名称	描述	类型
http.component	网站上所使用的网络技术名称	string
http.component_category	网站上使用的网络组件的类别	string
http.html	Web banner	string
http.html_hash	网站HTML的哈希值	int
http.status	响应状态码	int
http.title	网站title得banner	string
NTP 过滤器
名称	描述	类型
ntp.ip	查找在其monlist中NTP服务器的IP	
ntp.ip_count	初始monlist返回的IP数量	int
ntp.more	真/假; monlist集是否有更多的IP地址	boolean
ntp.port	monlist中的IP地址使用的端口	int
SSL过滤器
名称	描述	类型
has_ssl	有无SSL	boolean
SSL	搜索所有SSL的数据	string
ssl.alpn	诸如HTTP/2的应用层协议	string
ssl.chain_count	链中的证书数量	int
ssl.version	可能的值：SSLv2，SSLv3，TLSv1，TLSv1.1，TLSv1.2	string
ssl.cert.alg	证书算法	string
ssl.cert.expired	是否是过期证书	boolean
ssl.cert.extension	证书中的扩展名	string
ssl.cert.serial	序列号为整数或十六进制字符串	int/string
ssl.cert.pubkey.bits	公钥的位数	int
ssl.cert.pubkey.type	公钥类型	string
ssl.cipher.version	SSL版本的首选密码	string
ssl.cipher.bits	首选密码中的位数	int
ssl.cipher.name	首选密码的名称	string
Telnet 过滤器
名称	描述	类型
telnet.option	搜索所有选项	string
telnet.do	对方执行的请求或期望对方执行指示的选项	string
telnet.dont	对方停止执行的请求或不再期望对方执行指定的选项	string
telnet.will	确认现在正在执行指定的选项	string
telnet.wont	表示拒绝执行或继续执行指定的选项	string


## APP download

### https://apkpure.com/

### https://apk.tools/

## software download

### https://sourceforge.net/

## 安全类关键词搜索

### https://ippsec.rocks/

## 影视音乐电子书搜索

### http://www.huaxiaso.com/

## 在线制作favicon图标

### https://tool.lu/favicon/

## 在线修改图片尺寸

### https://www.gaitubao.com/

## 文献搜索

### https://www.researchgate.net/

## website模板

### https://deanattali.com/beautiful-jekyll/

## hackers'sites

### https://hackforums.net/

### http://www.hackerschina.org/

### http://www.anonymouschina.org/

## 操作系统映像

### https://msdn.itellyou.cn

### https://pcriver.com/operating-systems/

## MD5解密

### https://www.md5online.org/

### http://www.md5decrypt.org/

### https://crackstation.net/

### https://hashkiller.co.uk/

### http://reverse-hash-lookup.online-domain-tools.com/

### https://md5decrypt.net/

### https://www.onlinehashcrack.com/

### https://cmd5.org/

### https://hashes.com/decrypt/basic

### https://forum.hashkiller.io/index.php

### https://www.somd5.com/

## GSIL

### https://github.com/FeeiCN/GSIL

- git clone https://github.com/FeeiCN/gsil.git
cd gsil/
pip3 install -r requirements.txt
mv config.gsil.example config.gsil
mv rules.gsil.example rules.gsil

vim config.gsil
[mail]
host : smtp.qq.com
port : 465
mails : xxx@qq.com
from : GSIL
password : xxx
to : xxx@gmail.com
cc : xxx@gmail.com
[github]
clone : false
tokens : xxx

python3 gsil.py test
python3 gsil.py --verify-tokens

## 网盘搜索引擎

### 盘多多：http://www.panduoduo.net/  
盘搜搜：http://www.pansoso.com/  
盘搜：http://www.pansou.com/  
凌云风搜索：https://www.lingfengyun.com/  

## 微软补丁包下载

### https://www.catalog.update.microsoft.com/Search.aspx

## 内网穿透

### http://www.dkys.org/

## 在线思维导图

### https://www.processon.com/

## 全国图书馆

### http://www.ucdrs.superlib.net/

## 加密邮箱

### https://mail.protonmail.com/

## 在线文字转语音

### https://ttsmp3.com/

## 音频类型转换

### ffmpeg -i ttsMP3.com_VoiceText_2020-2-4_11_57_5.mp3 ttsMP3.com_VoiceText_2020-2-4_11_57_5.wav

## 加密通信app

### https://signal.org/

### https://qtox.github.io/

### Internet Relay Chat

## VPS

### https://www.digitalocean.com/

### https://www.vultr.com/

### https://drserver.net/vps.php

### https://www.pskhosting.com/

### https://my.pegvm.com/cart.php

## lnmp安装命令

### wget http://soft.vpser.net/lnmp/lnmp1.6.tar.gz -cO lnmp1.6.tar.gz && tar zxf lnmp1.6.tar.gz && cd lnmp1.6 && ./install.sh lnmp

## SSR中继

### https://zxcloud.online/

### https://jsqpro.pro/

### http://www.flywall.net/

## 勒索病毒

### https://lesuobingdu.360.cn/

### https://lesuobingdu.qianxin.com/

### https://www.nomoreransom.org/crypto-sheriff.php?lang=zh

### https://noransom.kaspersky.com/

### https://id-ransomware.malwarehunterteam.com/

### https://www.bleepingcomputer.com/forums/

## SysInternals

### https://live.sysinternals.com/

## 在线文件分享

### http://www.wikifortio.com/

## 修复PCAP包

### https://f00l.de/hacking/pcapfix.php

## 使用Tor匿名代理流量

### https://github.com/githacktools/TorghostNG

## 弱口令检测工具(win平台)

### https://github.com/shack2/SNETCracker/

## 钓鱼框架、工具

### https://github.com/kgretzky/evilginx2
https://github.com/gophish/gophish
https://github.com/htr-tech/nexphisher

## C2框架

### https://www.cobaltstrike.com/training
https://github.com/darkr4y/geacon
https://github.com/gloxec/CrossC2
https://github.com/rapid7/metasploit framewor k
https://github.com/sensepost/goDoH
https://github.com/cobbr/Covenant
https://github.com/BC SECURITY/Empire
https://github.com/byt3bl33d3r/SILENTTRINITY
https://github.com/NYAN x CAT/AsyncRAT C Sharp
https://github.com/threatexpress/malleable c2

## 对抗免杀

### https://github.com/brimstone/go shellcode
https://github.com/P0cL4bs/hanzoInjection
https://github.com/bats3c/Ghost In The Logs
https://github.com/danielbohannon/Invoke Obfuscation

## 权限维持

### 单机 " 维持 [ 覆盖 Windows linux ]
https://github.com/fireeye/SharPersist 自动化后门植入
https://github.com/0xthirteen/SharpStay 自动化后门植入
https://github.com/0x09AL/IIS Raid
https://github.com/t57root/pwnginx
https://github.com/naworkcaj/bdvl
https://github.com/outflanknl/SharpHide 注册表隐藏
https://github.com/EPICROUTERSS/MSSQL File less Rootkit WarSQLKit MSSQL 数据库后门
https://github.com/outflanknl/NetshHelperBeacon

数据脱取
https://github.com/outflanknl/Zipper

## 域渗透

### 域内敏感信息搜集
https://github.com/BloodHoundAD/SharpHound 抓取域内敏感信息 对于分析大型域环境很有用
https://github.com/vletoux/pingcastle 抓取域内敏感信息
https://github.com/tevora threat/SharpView 抓取域内信息
https://github.com/fireeye/ADFSDump

获取服务票据Hash 及 GPP xml 密码
https:// github.com/GhostPack/Rubeus 功能强悍
https://github.com/GhostPack/SharpRoast
https://github.com/outflanknl/Net GPPPassword 自动化抓取 GPP 目录中的 账号 密码

域内批量域用户密码喷射
https://github.com/HunnicCyber/SharpDomainSpray
https://github.com/outflanknl/Spray A D
https://github.com/jnqpblc/SharpSpray
https://github.com/byt3bl33d3r/SprayingToolkit
https://github.com/ropnop/kerbrute

域用户登录ip 定位
https://github.com/HunnicCyber/SharpSniper [ 需防火墙放行 不然提示 RPC 不可用
https://github.com/uknowsec/SharpEventLog 定位域内指定用户登录 ip

域内维持
https://github.com/FSecureLABS/SharpGPOAbuse GPO 后门利用

域内综合利用
https://github.com/jaredhaight/SharpAttack

## 内网横移

### https://github.com/jnqpblc/SharpReg 模拟系统内置的 reg.exe
https://github.com/jnqpblc/SharpTask 模拟系统内置的 schtasks.exe
https://github.com/jnqpblc/SharpSvc 模拟系统内置的 sc.exe
https://github.com/anthemtotheego/SharpExec wmi / smb 远程执行 可半交互式 shell
https://github.com/nccgroup/WMIcmd 把命令 结果放到注册表里回传
ht tps://github.com/rvrsh3ll/SharpCOM DCOM 远程执行
https://github.com/0xthirteen/SharpMove 远程执行集
https://github.com/malcomvetter/CSExec 服务远程执行 ,Csharp 版的 psexec
https://github.com/djhohnstein/SharpSC Csharp 版 SC
https://github.com/0xthirteen/SharpRDP 利用 Rdp 远程执行
https://github.com/SecureAuthCorp/impacket 一款实际可能用的非常多的协议攻击套件
https://github.com/FreeRDP/FreeRDP
https://github.com/infosecn1nja/SharpDoor
https://github.com/Mr Un1k0d3r/SCShell 只适用于 win10 的远程 执行 基于 xbox
https://github.com/ShawnDEvans/smbmap
https://github.com/byt3bl33d3r/CrackMapExec

## 远程加载

### https://github.com/anthemtotheego/SharpCradle 远程 .net 内存执行
https://github.com/adlered/LiteFTPD UNIX

## 内网流量转发

### 正向HTTP 代理
https://github.com/jpillora/chisel
https://github.com/L codes/Neo reGeorg
https://github.com/sensepost/reGeorg
https://github.com/nccgroup/ABPTTS
https://github.com/sensepost/reDuh
https://github.com/SECFORCE/Tunna

反向SOCKS5 代理
https://github.com/ehang i o/nps
https://github.com/fatedier/frp
https://github.com/securesocketfunneling/ssf
https://github.com/rofl0r/proxychains-ng

DNS隧道转发
https://github.com/yarrick/iodine

单TCP 端口转发
https://github.com/HiwinCN/HTran
https://github.com/bGN4/HTran
https://githu b.com/UndefinedIdentifier/LCX

## 漏扫exp

### Exp 合集
https://github.com/mai lang chai/Middleware Vulnerability detection
https://github.com/zhzyker/exphub
Exchange
https://github.com/zcgonvh/CVE 2020 0688
https://github.com/sensepost/ruler
Weblogic
https://github.com/dr0op/WeblogicScan
https://github.com/T ideSec/Decrypt_Weblogic_Password
Struts2
https://github.com/HatBoy/Struts2 Scan
https://github.com/Lucifer1993/struts scan
https://github.com/shack2/Struts2VulsTools
Jboss
https://github.com/joaomatosf/jexboss
https://github.com/az0ne/jboss_autoexploit
https://github.com/GGyao/jbossScan
Wordpress
https://github.com/wpscanteam/wpscan
Joomla
https://github.com/rezasp/joomscan

Web 漏洞利用
https://github.com/sqlmapproject/sqlmap
https://github.com/codingo/NoSQLMap
https://github.com/D35m0nd142/LFISuite
https://github.com/enjoiz/XXEinjector
https://github.com/orf/xcat
https://github.com/tarunkant/Gopherus

内网敏感资产扫描探测
https://github.com/rvrsh3ll/SharpFruit 
https://github.com/PhilipMur/C Sharp Multi Threaded Port Scanner 
https://github.com/aYosukeAkatsuka/nbtscan unixwiz 

单机及内网敏感信息搜集
https://github.com/GhostPack/Seatbelt 搜集本机各类敏 感信息
https://github.com/bitsadmin/nopowershell 不基于 powershell.exe 搜集
https://github.com/djhohnstein/SharpSearch 搜集远程机器共享目录中带有指定字符串的文件
https://github.com/jnqpblc/SharpDir 搜集远程机器共享目录中带有指定字符串的文件
https://github.com/uknowsec/SharpCheckInfo 搜集本机信息
https://github.com/uknowsec/SharpNetCheck 出网探测
https://github.com/slyd0g/SharpClipboard 获取剪切板数据
https://github.com/FSecureLABS/SharpClipHistory 获取剪切板数据 [win10 1809 编译

内网敏感登录凭证搜集
[ 绝大部分已不免 杀或被拦
https://github.com/AlessandroZ/LaZagne 一键获取本地所有常见客户端工具中保存的账号密码 体积太大 不免杀 需自行深度处理
https://github.com/kerbyj/goLazagne go 版 LaZagne, 功能虽然暂时没 LaZagne 那么多 但相对 LaZagne 更好处理
https://github.com/GhostPack/SafetyKatz 抓取系统明文密码 , 自动 Dump lsass.ex e 进程数据 并自动加载 mimikatz 解析
https://github.com/GhostPack/SharpDPAPI 解密 DPAPI 加密数据
https://github.com/GhostPack/SharpDump Dump lsass.exe 进程数据到指定文件 , 并将其自动打包压缩该文件
https://github.com/b4rtik/ATPMiniDump Dump lsass.exe 进程数据
https://github.com/quarkslab/ quarkspwdump 抓取系统本地用户密码 hash / 离线解析域 ntds.dit
https://github.com/uknowsec/SharpSQLDump 远程脱取目标 mssql / mysql 数据库中的所有库表结构
https://github.com/djhohnstein/SharpWeb 抓取 Chrome / Firefox / IE / Edge 中保存的明文 Web 登录账号密码 , 实测问题比较大 要深度改
https://github.com/L S95/dumpWebBrowserPasswords 抓取浏览器中保存的 web 登录账号密码
https://github.com/zcgonvh/NTDSDumpEx 在线解析 ntds.dit
https://github.com/uknowsec/SharpDecryptPwd 抓取各类常用运维工具中保存的各类账号密码
https://github.com/0x09AL/RdpThief 注入 mstsc.exe 截获 RDP 连接的 Ip 和 账号密码
https:https://github.com/clymb3r/Misc Windows Hacking 记录修改密码
https://github.com/CaledoniaProject/PasswordFilter 记录修改密码
https://github.com/jozefizso/TSvnPwd 抓取当前用户保存在本地的 svn 账号密码
https://github.com/djhohnstein/SharpLogger 键盘记录
https://github.com/djhohnstein/WireTap 语音记录 , 系统截屏 , 摄像头抓拍
https://github.com/twelvesec/passcat 暂时还有问题 , 2016 系统上貌似并不好使
https://github.com/0Fdemir/OutlookPasswordRecovery

Windows & Linux
本地提 权利用
https://github.com/carlospolop/privilege escalation awesome scripts suite/tree/master/winPEAS/winPEASexe 自动化提权审查 问题比较大
https://github.com/GhostPack/SharpUp 提权检查
https://github.com/rasta mouse/Watson 自动枚举可用于提权的漏洞补丁 暂只适用于 win10,WinServer2016, 2019
https://github.com/sensepost/rattler 自动化 dll 劫持利用检测
https://github.com/v p b/cve 2019 12750 赛门铁克本地提权 Exp
https://github.com/hfiref0x/UACME Windows BypassUAC 套件合集
https://github.com/antonioCoco/RunasCs 降权执行
https://github.com/Kevi n Robertson/InveighZero 中间人攻击利用
https://github.com/fdiskyou/incognito2 Windows 令牌利用
https://github.com/0xbadjuju/Tokenvator Csharp 版 widows 令牌利用工具
https://github.com/ohpe/juicy potato


## Linux_kernel_Exploit

### # Kernel Exploits

## [pp_key](pp_key)

Kernels: 3.8.0, 3.8.1, 3.8.2, 3.8.3, 3.8.4, 3.8.5, 3.8.6, 3.8.7, 3.8.8, 3.8.9, 3.9, 3.10, 3.11, 3.12, 3.13, 3.4.0, 3.5.0, 3.6.0, 3.7.0, 3.8.0, 3.8.5, 3.8.6, 3.8.9, 3.9.0, 3.9.6, 3.10.0, 3.10.6, 3.11.0, 3.12.0, 3.13.0, 3.13.1

## [overlayfs](overlayfs)

Kernels: 3.13, 3.16.0, 3.19.0

Executable Exploit: ofs_64
* Ubuntu 14.10 - Linux ubuntu 3.16.0-23-generic #31-Ubuntu x86_64  
* Ubuntu 14.04 - Linux ubuntu 3.13.0-24-generic #46-Ubuntu x86_64  
* Ubuntu 14.04 - Linux ubuntu 3.16.0-30-generic #40~14.04.1-Ubuntu x86_64

Executable Exploit: ofs_32
* Ubuntu 14.04 - Linux ubuntu 3.13.0-24-generic #46-Ubuntu x86_32  
* Ubuntu 14.10 - Linux ubuntu 3.16.0-23-generic #31-Ubuntu x86_32  

## [rawmodePTY](rawmodepty)

Kernels: 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36, 2.6.37, 2.6.38, 2.6.39, 3.14, 3.15

## [timeoutpwn](timeoutpwn)

Kernels: 3.4, 3.5, 3.6, 3.7, 3.8, 3.8.9, 3.9, 3.10, 3.11, 3.12, 3.13, 3.4.0, 3.5.0, 3.6.0, 3.7.0, 3.8.0, 3.8.5, 3.8.6, 3.8.9, 3.9.0, 3.9.6, 3.10.0, 3.10.6, 3.11.0, 3.12.0, 3.13.0, 3.13.1

Executable Exploit: timeoutpwn64
* Ubuntu 13.10 - Linux ubuntu 3.11.0-12-generic #19-Ubuntu x86_64  

## [perf_swevent](perf_swevent)

Kernels: 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0, 3.2, 3.3, 3.4.0, 3.4.1, 3.4.2, 3.4.3, 3.4.4, 3.4.5, 3.4.6, 3.4.8, 3.4.9, 3.5, 3.6, 3.7, 3.8.0, 3.8.1, 3.8.2, 3.8.3, 3.8.4, 3.8.5, 3.8.6, 3.8.7, 3.8.8, 3.8.9

Executable Exploit: perf_swevent
* Ubuntu 12.04.2 - Linux ubuntu 3.5.0-23-generic #35-Ubuntu x86_64  

Executable Exploit: perf_swevent64
* Ubuntu 12.04.0 - Linux ubuntu 3.2.0-23-generic #36-Ubuntu x86_64  
* Ubuntu 12.04.1 - Linux ubuntu 3.2.0-29-generic #46-Ubuntu x86_64  
* Ubuntu 12.04.2 - Linux ubuntu 3.5.0-23-generic #35-Ubuntu x86_64  

## [msr](msr)

Kernels: 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36, 2.6.37, 2.6.38, 2.6.39, 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7.0, 3.7.6

## [memodipper](memodipper)

Kernels: 2.6.39, 3.0.0, 3.0.1, 3.0.2, 3.0.3, 3.0.4, 3.0.5, 3.0.6, 3.1.0

Executable Exploit: memodipper
* Ubuntu 11.10 - 3.0.0-12-generic-pae #20-Ubuntu x86_32  

Executable Exploit: memodipper64
* Ubuntu 11.10 - 3.0.0-12-server #20-Ubuntu x86_64  

## [american-sign-language](american-sign-language)

Kernels: 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36

## [full-nelson](full-nelson)

Kernels: 2.6.31, 2.6.32, 2.6.35, 2.6.37

Executable Exploit: full-nelson
* Ubuntu 10.10 - 2.6.35-19-generic-pae #28-Ubuntu x86_32  
* Ubuntu 9.10 - 2.6.31-14-generic-pae #48-Ubuntu x86_32  

Executable Exploit: full-nelson64
* Ubuntu 10.10 - 2.6.35-19-server #28-Ubuntu x86_64  
* Ubuntu 9.10 - 2.6.31-14-server #48-Ubuntu x86_64  
* Ubuntu 10.04.1 - 2.6.32-24-server #39-Ubuntu x86_64  
* Ubuntu 10.04 - 2.6.32-21-server #32-Ubuntu x86_64  

## [half_nelson](half-nelson)

Kernels: 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36

Executable Exploit: half-nelson3
* Ubuntu 10.04 - Linux ubuntu 2.6.32-21-server #32-Ubuntu x86_64  
* Ubuntu 9.10 - 2.6.31-14-server #48-Ubuntu x86_64  

## [rds](rds)

Kernels: 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36

Executable Exploit: rds
* Debian 6 - Linux 2.6.31-1-686 32bit  
* Ubuntu 10.10 - 2.6.35-19-generic-pae #28-Ubuntu x86_32  
* Ubuntu 10.04 - 2.6.32-21-generic-pae #32-Ubuntu x86_32  
* Ubuntu 10.04.1 - 2.6.32-24-generic-pae #39-Ubuntu x86_32  
* Ubuntu 9.10 - 2.6.31-14-generic-pae #48-Ubuntu x86_32  

Executable Exploit: rds64
* Debian 6 - Linux 2.6.31-1-amd64 x86_64  
* Debian 6 - Linux 2.6.32-trunk-amd64 x86_64  
* Debian 6 - Linux 2.6.34-1-amd64 x86_64  
* Debian 6 - Linux 2.6.35-trunk-amd64 x86_64  
* Ubuntu 10.10 - 2.6.35-19-server #28-Ubuntu x86_64  
* Ubuntu 10.04.1 - 2.6.32-24-server #39-Ubuntu x86_64  
* Ubuntu 10.04 - 2.6.32-21-server #32-Ubuntu x86_64  
* Ubuntu 9.10 - 2.6.31-14-server #48-Ubuntu x86_64  

## [pktcdvd](pktcdvd)

Kernels: 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36

## [ptrace_kmod2](ptrace_kmod2)

Kernels: 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34

Executable Exploit: ptrace_kmod2-64
* Debian 6 - Linux 2.6.32-trunk-amd64 x86_64  
* Debian 6 - Linux 2.6.33-2-amd64 x86_64  
* Debian 6 - Linux 2.6.34-1-amd64 x86_64  
* Debian 6 - Linux 2.6.35-trunk-amd64 x86_64  
* Ubuntu 10.10 - 2.6.35-19-server #28-Ubuntu x86_64  
* Ubuntu 10.04.1 - 2.6.32-24-server #39-Ubuntu x86_64  
* Ubuntu 10.04 - 2.6.32-21-server #32-Ubuntu x86_64  

## [video4linux](video4linux)

Kernels: 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33

## [can_bcm](can_bcm)

Kernels: 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34, 2.6.35, 2.6.36

Executable Exploit: can_bcm
* Ubuntu 10.04.1 - 2.6.32-24-generic #39-Ubuntu x86_32  

## [reiserfs](reiserfs)

Kernels: 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31, 2.6.32, 2.6.33, 2.6.34

## [do_pages_move](do_pages_move)

Kernels: 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31

## [pipe.c_32bit](pipe.c_32bit)

Kernels: 2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9, 2.4.10, 2.4.11, 2.4.12, 2.4.13, 2.4.14, 2.4.15, 2.4.16, 2.4.17, 2.4.18, 2.4.19, 2.4.20, 2.4.21, 2.4.22, 2.4.23, 2.4.24, 2.4.25, 2.4.26, 2.4.27, 2.4.28, 2.4.29, 2.4.30, 2.4.31, 2.4.32, 2.4.33, 2.4.34, 2.4.35, 2.4.36, 2.4.37, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30, 2.6.31

## [udp_sendmsg_32bit](udp_sendmsg_32bit)

Kernels: 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19

## [sock_sendpage](sock_sendpage)

Kernels: 2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9, 2.4.10, 2.4.11, 2.4.12, 2.4.13, 2.4.14, 2.4.15, 2.4.16, 2.4.17, 2.4.18, 2.4.19, 2.4.20, 2.4.21, 2.4.22, 2.4.23, 2.4.24, 2.4.25, 2.4.26, 2.4.27, 2.4.28, 2.4.29, 2.4.30, 2.4.31, 2.4.32, 2.4.33, 2.4.34, 2.4.35, 2.4.36, 2.4.37, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30


## [sock_sendpage2](sock_sendpage2)

Kernels: 2.4.4, 2.4.5, 2.4.6, 2.4.7, 2.4.8, 2.4.9, 2.4.10, 2.4.11, 2.4.12, 2.4.13, 2.4.14, 2.4.15, 2.4.16, 2.4.17, 2.4.18, 2.4.19, 2.4.20, 2.4.21, 2.4.22, 2.4.23, 2.4.24, 2.4.25, 2.4.26, 2.4.27, 2.4.28, 2.4.29, 2.4.30, 2.4.31, 2.4.32, 2.4.33, 2.4.34, 2.4.35, 2.4.36, 2.4.37, 2.6.0, 2.6.1, 2.6.2, 2.6.3, 2.6.4, 2.6.5, 2.6.6, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29, 2.6.30

## [exit_notify](exit_notify)

Kernels: 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29

## [udev](udev)

Kernels: 2.6.25, 2.6.26, 2.6.27, 2.6.28, 2.6.29

## [ftrex](ftrex)

Kernels: 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22

## [vmsplice2](vmsplice2)

Kernels: 2.6.23, 2.6.24

## [vmsplice1](vmsplice1)

Kernels: 2.6.17, 2.6.18, 2.6.19, 2.6.20, 2.6.21, 2.6.22, 2.6.23, 2.6.24, 2.6.24.1

## [h00lyshit](h00lyshit)

Kernels: 2.6.8, 2.6.10, 2.6.11, 2.6.12, 2.6.13, 2.6.14, 2.6.15, 2.6.16

## [raptor_prctl](raptor_prctl)

Kernels: 2.6.13, 2.6.14, 2.6.15, 2.6.16, 2.6.17

## [elflbl](elflbl)

Kernels: 2.4.29

## [caps_to_root](caps_to_root)

Kernels: 2.6.34, 2.6.35, 2.6.36

## [mremap_pte](mremap_pte)

Kernels: 2.4.20, 2.2.24, 2.4.25, 2.4.26, 2.4.27

## [krad3](krad3)

Kernels: 2.6.5, 2.6.7, 2.6.8, 2.6.9, 2.6.10, 2.6.11



## 反取证

### 比较有效的反取证技术有：数据擦除、数据隐藏
数据擦除就是清除所有可能的证据，这样取证就无法进行了，这是最有效的反取证方法。
数据隐藏就是将暂时还不能被删除的文件伪装成其他类型或者将隐藏在图形文件中，还可以隐藏在磁盘上的Slack、交换空间等等，目的是让别人永远也找不到有用信息，这些都被称为数据隐藏。

### 数据擦除：很多朋友入侵在入侵之后把日志文件删除了以为就万事大吉，其实这远远不够。如果用手工删除那几乎是等于没有删除，因为系统删除文件之后它在硬盘上的数据并没有覆盖，只要用一些数据恢复软件就可以把原来的数据还原。用工具删除还比较好，至少它会对硬盘进行反复的读写操作，但是一般至少要进行7次以上的反复覆盖才能够把数据完全删除，不然还会留下一些碎片文件。这里推荐一款Windows下优秀的删除工具：WYWZ，据说是采用美国国防部的标准。建议擦除标准为7次以上，这样就很难留下痕迹了。日志文件是取证中一个最重要的工作，但这只是取证的一部分，所以删除日志文件还是远远不够的。从上面我们知道网警要在哪些地方取证，所以利用工具还要进一步擦除，比如内存、缓冲区、硬盘中的数据，还有CPU中Cache中的数据等等

### 数据隐藏：常用的数据隐藏技术有数据加密、更改文件后缀名、隐写术等等。学过密码学的朋友都知道密码学上有两条原则：一是如果破解密码所花的代价超过了密码本身的价值那么就放弃；二是如果破解密码所花的时间超过了密码的有效期也放弃。所以我们在对数据加密的时候最好符合上面的两条原则，可以利用多种加密算法对数据加密，而且密码尽量要长一些，让网警在短时间内无法破解甚至根本无法破解出来。隐写术说的通俗一点就是把一些证据隐写在正常文件下，从而躲过网警的数据分析。比如我要把文件“黑客与网警的较量.doc”隐藏在“我的相片.bmp”中然后利用DOS中的Copy命令将两个文件合成并生成haha.bmp。一般隐写术是和数据加密结合起来用的，首先用对数据进行加密，然后在用隐写术将加密后的数据隐藏，这样就大大增加了取证的难度。
隐写术工具：
(1) StealthDisk：能够隐藏计算机中所有的文件和文件夹，同时删除所有在线Internet的访问记录。
(2) Cloak：一个非常好的隐写术软件，能读文件进行加密并将其隐藏在位图文件。
(3) Invisible Secrets：一个数据隐藏工具，能将数据隐藏在JPEG PNG BMP HTML和WAV中。

### 入侵的过程大致为：踩点→入侵→清脚印。
踩点：这个时候主要注意的问题是IP地址有没有暴露，要是出现了“出师未捷身先死”的情况可就不好了。这里首先要纠正很多拨号及ADSL上网的朋友在攻防实验中一个不好的习惯，我们知道这些上网用户采用的是动态IP，在上网时拨通ISP(网络服务提供商)的主机后，自动获得一个动态IP地址，很多朋友以为这个IP地址是随便分给你的，所以在入侵的时候并没有隐藏IP，其实没有这么简单。这些IP地址不是任意的，而是该ISP申请的网络ID与主机的ID的合法区间中的某个地址。这些用户任意两次连接时的IP地址很可能不同，但在每次连接的时间内的IP地址是不变的。所以网警要追查动态IP的情况，只要通过网络运营商的认证系统，找到与之捆绑的账户，就可以确定上网者。所以动态IP也和静态IP一样，是可以轻易找到上网者的。这是因为法律规定，为了保护计算机信息的安全，网络运营商 Interent服务机构，其IP地址等信息必须在公安机关公共信息网络勘察部门备案。
在入侵时最重要就是隐藏好自己的IP地址，一般的方法是利用跳板(肉鸡)来进行入侵，最后把留在肉鸡上的日志删除，然后离开。对于没有肉鸡的朋友可以利用代理服务器来隐藏自己的IP地址，建议最好利用国外的代理服务器。上面两种都是比较常用的方法，可以满足一般的要求，而如果对方不惜一切代价要查你的话，那是肯定可以查到的。这是因为我们上网的所有信息其实在路由器上都有记录，所以查询路由器的信息就可以很快确定出入侵者的IP地址，真正的高手不仅会用到上面两种方法，同时他在入侵服务器之前，也会把他所要入侵的服务器之间的一些路由器干掉，在删除肉鸡的日志同时还会把路由器上的所有信息删除。就算对方把整个网络监控了也没有办法，即使利用IDS也很难查到你的IP地址，所以路由器的入侵在这里扮演了很重要的惧色，控制了对方的路由器就等于控制了对方的网络，剩下的只有任人宰割。对于有条件的朋友可以把三者结合起来，以保证自己的最大安全。

入侵：这个过程主要注意的问题是：不要被IDS或类似的软件发现有人入侵。

清脚印：首先把所有日志文件删除，注意一定要用工具对原来日志文件进行反复覆盖，然后利用内存删除工具把内存数据删除，还有CPU的Cache中的数据及缓冲区也要做相同处理。接下来就是硬盘上的数据了，一般的删除工具会把扇区上的文件的都删除，特别需要注意的地方就是扇区之间的磁盘空间，这个地方一般存在很多碎片文件。还有如果控制了对方的路由器的话，上面的任何数据也要删除。以上所说的删除文件是指利用专门的删除工具对文件进行多次覆写操作；对于不能够删除的数据，首先把文件的后缀改掉，然后用数据加密软件对数据进行多次加密，且每次所用到的加密算法应该是不一样的；再利用隐写术对文件隐藏。

## 取证软件

### 文件浏览器：专门用来查看数据文件的阅读工具，只可以查看但没有编辑和恢复功能，可以防止数据的破坏，Quick View Plus是其中的代表。

图片检查工具：ThumbsPlus是一个可以对图片进行全面检查的工具。

反删除工具：Easy Undelete是一款Windows下强大的数据恢复和反删除软件。

文本搜索工具：dtSearch是一个很好的用于文本搜索的工具。

驱动器映像程序：就是拷贝和建立驱动器的映像，可以满足取证分析的磁盘映像软件，包括：SafeBack SnapBack Ghost等等。

Forensic Toolkit：是一系列基于命令行的工具，可以帮助推断Windows NT文件系统中的访问行为。

EnCase：主要功能有数据浏览、搜索、磁盘浏览、数据预览、建立案例、建立数据、 保存案例等。

CRCMD5：可以验证一个或者多个文件内容的CRC工具。

DiskScrub：一个可以清除硬盘驱动器中所有数据的工具。

DiskSig：用于验证映像备份的精确性。

FileList：一个磁盘目录工具，用来建立用户在系统上的行为时间表。

GetSlack：一个周围环境数据收集工具，用于捕获未分配的数据。

GetTime：一个周围环境数据收集工具，用于捕获分散的文件。

Net Threat Analyzer：网络取证分析软件，用于识别公司账号滥用。

NTI-DOC：一个文件程序，用于记录文件的日期、时间以及属性。

PTable：用于分析及证明硬盘驱动器分区的工具。

Seized：用于对证据计算机上锁及保护的程序

ShowFL：用于分析文件输出清单的程序。

TextSearch Plus：用来定位文本或者图形软件中的字符串的工具。

## 数码照片溯源

### https://tineye.com/

### http://stu.iplant.cn/

### https://exif.tools/

### https://www.remove.bg/zh

### https://clippingmagic.com/

### https://www.stolencamerafinder.com/

### https://www.photopea.com/

### http://www.i2ocr.com/

### http://www.nmc.cn/

### https://zoom.earth/

### https://www.windy.com/

### http://suncalc.net/

## 暗网搜索引擎

### hss3uro2hsxfogfq.onion
xmh57jrzrnw6insl.onion
msydqstlz2kzerdg.onion
msydqstlz2kzerdg.onion/i2p/
gjobqjj7wyczbqie.onion
searchb5a7tmimez.onion
archive.org
vlib.org
https://www.wolframalpha.com/
deepwebtech.com
duckduckgo.com
zqktlwi4fecvo6ri.onion/wiki/index.php/Main_Page
archivecaslytosk.onion/
dnmugu4755642434.onion

- archivecaslytosk.onion/

## php代码审计工具

### SeayPHP

### Cobra

### Rips

### BadCode

### VulHint

## webshell检测

### http://www.d99net.net/down/WebShellKill_V2.0.9.zip

### https://scanner.baidu.com/

### https://www.shellpub.com/

### http://www.shelldetector.com/

### https://github.com/chaitin/cloudwalker

### Sangfor WebShellKill

### http://webshell.cdxy.me/

### https://github.com/jvoisin/php-malware-finder

### https://github.com/he1m4n6a/findWebshell

### http://tools.bugscaner.com/killwebshell/

## 数据外带平台

### http://ceye.io/

## 微软开发相关下载

### http://msdn.itellyou.cn/

## 文件病毒木马查杀

### https://www.virustotal.com/gui/home

### https://habo.qq.com/

### http://www.virscan.org/language/zh-cn/

### http://nodistribute.com/

## 漏洞公共资源库

### http://www.cnnvd.org.cn/
https://www.cnvd.org.cn/
https://www.seebug.org/?ref=www
http://vulhub.org.cn/view/global
https://poc.shuziguanxing.com/#/
http://www.nsfocus.net/index.php?act=sec_bug
http://www.bugscan.net/source/template/vulns/
https://src.sjtu.edu.cn/list/
http://ivd.winicssec.com/
http://www.expku.com/
https://github.com/hanc00l/wooyun_public
https://www.exploit-db.com/
https://sploitus.com/
https://packetstormsecurity.org/
https://www.securityfocus.com/bid
https://cxsecurity.com/exploit/
https://www.rapid7.com/db/
https://cve.circl.lu/
https://www.cvedetails.com/
https://cve.mitre.org/cve/search_cve_list.html
https://www.us-cert.gov/ics
http://www.routerpwn.com/

## 用户注册

### https://www.reg007.com/
https://checkusernames.com/
https://knowem.com/
https://namechk.com/

## 社工库

### https://dehashed.com/
https://aleph.occrp.org/
https://www.blackbookonline.info/
http://pwndb2am4tzkvold.onion/
TG-Robot:@shegongkubot

## 查询密码泄露

### https://passwords.google.com/
http://monitor.firefox.com/
http://haveibeenpwned.com/
https://intelx.io/
http://aleph.occrp.org/
http://www.dehashed.com/
https://isleaked.com/
http://snusbase.com/
http://checkusernames.com/
https://knowem.com/
http://vigilante.pw/

## dll、exe文件下载

### https://www.dll-files.com/

### https://www.pconlife.com/

## 云红队行动资源

### https://github.com/RhinoSecurityLabs/Cloud-Security-Research/
https://github.com/RhinoSecurityLabs/Security-Research/
https://github.com/RhinoSecurityLabs/AWS-IAM-Privilege-Escalation
https://github.com/RhinoSecurityLabs/cloudgoat
https://github.com/RhinoSecurityLabs/pacu
https://github.com/nccgroup/ScoutSuite
https://github.com/NetSPI/aws_consoler
https://github.com/dagrz/aws_pwn
https://github.com/bchew/dynamodump
https://github.com/fireeye/ADFSpoof
https://github.com/LMGsec/o365creeper
https://github.com/busterb/msmailprobe
https://github.com/nyxgeek/o365recon
https://github.com/mdsecactivebreach/o365-attack-toolkit
https://github.com/NetSPI/MicroBurst
https://github.com/RhinoSecurityLabs/GCPBucketBrute

## 随机密码生成

### https://www.ddosi.com/mm.html

## 搜索引擎

### https://magi.com/

### https://www.osint-labs.org/search/index.php

## 安全情报/论坛/博客/文章

### https://wooyun.kieran.top/

### https://riccardoancarani.github.io/

### https://labs.f-secure.com/

### https://www.objectif-securite.ch/en/

### https://krebsonsecurity.com/

### http://it.rising.com.cn/

### https://riccardoancarani.github.io/

### https://blog.riccardoancarani.it/

### https://shells.systems/

### https://www.sec-wiki.com/

### https://sec.today/

### https://www.hackingarticles.in/

### https://www.zerodayinitiative.com/

### https://www.opencti.io/en/

### http://www.0daysecurity.com/

### https://paper.seebug.org/

### https://adsecurity.org/

### https://threatpost.com/

### https://blog.sevagas.com/

### https://thehackernews.com/

## sec-tool-list

### https://github.com/Scotoma8/sec-tool-list

### https://sectools.org/

### http://www.hackingtools.in/

## 网络资源

### https://www.romeng.org/

## 12306抢票

### 消息推送(mail/wechat): http://sc.ftqq.com/3.version
git clone https://github.com/testerSunshine/12306
pip3 install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
vim TickerConfig.py
python3 run.py -h
operate     r: 运行抢票程序, c: 过滤cdn, t: 测试邮箱和server酱，server酱
python3 run.py t
python3 run.py c
python3 run.py r

### https://www.bypass.cn/

## API KEY

### http://lbsyun.baidu.com/apiconsole/key

### https://www.twilio.com/console

## 新闻API

### https://www.juhe.cn/box/index/id/235

## 天气信息短信/微信推送

### https://www.twilio.com/console (短信内容存在中文则发送失败)
https://www.sojson.com/api/weather.html
http://t.weather.sojson.com/api/weather/city/101010100 (微信一对多发送 https://pushbear.ftqq.com/admin/#/)
pip3 install twilio
pip3 install requests

## APP渗透测试平台

### https://mobexler.com/download.htm

## 路由器漏洞利用工具

### https://github.com/threat9/routersploit

## Jboss漏洞扫描工具

### https://github.com/joaomatosf/jexboss

## Struts漏洞利用工具

### K8 Struts2 Exploit

## Xpath注入利用工具

### https://github.com/orf/xcat

## XXE利用工具

### https://github.com/enjoiz/XXEinjector

## CSRF利用工具

### https://wiki.owasp.org/index.php/File:CSRFTester-1.0.zip

## 文件包含漏洞利用工具

### https://github.com/D35m0nd142/LFISuite

## 远控

### https://github.com/Scotoma8/pupy

## .NET Framework(4.5.2 Offline Installer)

### https://www.microsoft.com/en-us/download/confirmation.aspx?id=42642

## Unix binaries

### https://gtfobins.github.io/

## windows binaries and scripts

### https://lolbas-project.github.io/

### https://cooolis.payloads.online/

## windows工具

### ARPwner: ARP中毒和DNS中毒攻击

- https://github.com/Scotoma8/ARPwner

### BSQLinjector: 盲SQL注入工具

- https://github.com/Scotoma8/ARPwner

### Cain & Abel

- https://sectools.org/tool/cain/

### infernal-twin: wireless hacking

- https://github.com/Scotoma8/infernal-twin

### reaver: wireless hacking

- https://cisofy.com/lynis/

## linux工具

### Social-Engineer Toolkit

- https://github.com/Scotoma8/social-engineer-toolkit

### hashcat

- https://hashcat.net/hashcat/

### Lynis: security auditing tool

- https://hashcat.net/hashcat/

### Dsniff: 网络嗅探器

- https://linux.die.net/man/8/dsniff

### oclHashcat

- https://github.com/Scotoma8/oclHashcat

### THC Hydra

- https://github.com/Scotoma8/thc-hydra

## 移动端工具

### Hash Decrypt

- https://apkpure.com/hash-decrypt/com.ores.hash/download?from=details

### Hackode:目标侦查

- https://apkpure.com/hackode/com.techfond.hackode/download?from=details

### Fing: Network Tools

- https://apkpure.com/fing-network-tools/com.overlook.android.fing/download?from=details

### NetX: Network Tools

- https://apkpure.com/netx-network-tools/com.tools.netgel.netx/download?from=details

### Shark for Root: Traffic sniffer

- https://apkpure.com/shark-for-root/lv.n3o.shark/download?from=details

### Network spoofer

- https://github.com/w-shackleton/android-netspoof/releases/download/2.3.0/androidnetspoof-2.3.0.apk

### DroidSheep: 通过无线网络捕获浏览器会话cookie

- https://droidsheep.info/droidsheep.apk.zip

### Nipper: 检查CMS网站安全性

- https://apkpure.com/nipper-toolkit-web-scan/com.websecuritydev.nipper/download?from=details

### ZANTI: 渗透测试工具包

- https://s3.amazonaws.com/zANTI/zAnti3.19.apk

### AnDOSid: DOS

- http://dl.hackingtools.in/hackingtools/android/AnDOSid-com.scott.herbert.AnDOSid-3-v1.1.apk

### WiFi Kill Pro

- https://apkpure.com/wifikill-pro-wifi-analyzer/wifi.kill.pro/download?from=details

## make videos

### https://vimeo.com/

## Generate Wildcard SSL certificate

## OSINT开源情报与侦察工具

### https://start.me/p/GE7JQb/osint

## security rss

### https://www.zerodayinitiative.com/rss/

### https://blog.gdssecurity.com/labs/rss.xml

## OSCP:
https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/htmlview#

### Backdoors/Web Shells

- http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
https://highon.coffee/blog/reverse-shell-cheat-sheet/
http://pentestmonkey.net/tools/web-shells/php-reverse-shell
http://pentestmonkey.net/tools/web-shells/perl-reverse-shell
https://github.com/bartblaze/PHP-backdoors
https://github.com/BlackArch/webshells
https://github.com/tennc/webshell/tree/master/php/b374k
https://github.com/tennc/webshell/tree/master/php/PHPshell/c99shell
http://www.acunetix.com/blog/articles/web-shells-101-using-php-introduction-web-shells-part-2/
http://securityweekly.com/2011/10/23/python-one-line-shell-code/

### Buffer Overflows

- http://www.primalsecurity.net/0x0-exploit-tutorial-buffer-overflow-vanilla-eip-overwrite-2/
http://proactivedefender.blogspot.ca/2013/05/understanding-buffer-overflows.html
http://justpentest.blogspot.ca/2015/07/minishare1.4.1-bufferoverflow.html
https://samsclass.info/127/proj/vuln-server.htm
http://www.bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/

### Information Gathering/Reconnaissance

- https://github.com/leebaird/discover

- https://bitvijays.github.io/blog/2015/04/09/learning-from-the-field-intelligence-gathering/
- https://netcraft.com/

- http://www.hackcave.net/2015/11/the-basics-of-penetration-testing.html
- http://www.vulnerabilityassessment.co.uk/Penetration%20Test.html

- http://www.0daysecurity.com/penetration-testing/enumeration.html

### Cross-Compilation

- https://arrayfire.com/cross-compile-to-windows-from-linux/

### Local File Inclusion/Remote File Inclusion (LFI/RFI)

- http://www.grobinson.me/single-line-php-script-to-gain-shell/
https://webshell.co/
https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf
https://osandamalith.com/2015/03/29/lfi-freak/
https://wiki.apache.org/httpd/DistrosDefaultLayout#Debian.2C_Ubuntu_.28Apache_httpd_2.x.29
https://roguecod3r.wordpress.com/2014/03/17/lfi-to-shell-exploiting-apache-access-log/
https://attackerkb.com/Windows/blind_files
https://digi.ninja/blog/when_all_you_can_do_is_read.php
https://updatedlinux.wordpress.com/2011/05/12/list-of-important-files-and-directories-in-linux-redhatcentosfedora/
https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/
https://github.com/tennc/fuzzdb/blob/master/dict/BURP-PayLoad/LFI/LFI_InterestingFiles-NullByteAdded.txt
http://www.r00tsec.com/2014/04/useful-list-file-for-local-file.html
https://www.gracefulsecurity.com/path-traversal-cheat-sheet-windows/
https://github.com/tennc/fuzzdb/blob/master/dict/BURP-PayLoad/LFI/LFI-FD-check.txt

### File Transfer

- https://insekurity.wordpress.com/2012/05/15/file-transfer/
https://www.cheatography.com/fred/cheat-sheets/file-transfers/
https://blog.ropnop.com/transferring-files-from-kali-to-windows/
https://linux.die.net/man/1/scp
https://www.freebsd.org/cgi/man.cgi?fetch(1)
https://curl.haxx.se/docs/manpage.html
https://linux.die.net/man/1/wget

### Fuzzing Payloads

- https://github.com/fuzzdb-project/fuzzdb
https://github.com/danielmiessler/SecLists

### General Notes

- https://bitvijays.github.io/LFC-VulnerableMachines.html
http://blog.knapsy.com/blog/2014/10/07/basic-shellshock-exploitation/
http://www.studfiles.ru/preview/2083097/page:7/
http://126kr.com/article/3vbt0k8fxwh
http://meyerweb.com/eric/tools/dencoder/
https://www.darkoperator.com/powershellbasics
https://wooly6bear.files.wordpress.com/2016/01/bwapp-tutorial.pdf
http://alexflor.es/security-blog/post/egress-ports/
https://www.exploit-db.com/papers/13017/
https://www.owasp.org/index.php/OWASP_Broken_Web_Applications_Project
http://explainshell.com/
https://pentestlab.blog/2012/11/29/bypassing-file-upload-restrictions/
https://github.com/g0tmi1k/mpc
https://www.reddit.com/r/netsecstudents/comments/5fwc1z/failed_the_oscp_any_tips_for_the_next_attempt/danovo5/
https://security.stackexchange.com/questions/110673/how-to-find-windows-version-from-the-file-on-a-remote-system
https://www.veil-framework.com/veil-tutorial/ (AV Evasion)
https://blog.propriacausa.de/wp-content/uploads/2016/07/oscp_notes.html
https://jivoi.github.io/2015/07/01/pentest-tips-and-tricks/
http://stackoverflow.com/questions/19268548/python-ignore-certicate-validation-urllib2

### Jailed Shell Escape

- http://netsec.ws/?p=337
https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells
https://speakerdeck.com/knaps/escape-from-shellcatraz-breaking-out-of-restricted-unix-shells
http://airnesstheman.blogspot.ca/2011/05/breaking-out-of-jail-restricted-shell.html
http://securebean.blogspot.ca/2014/05/escaping-restricted-shell_3.html

### Linux Post-Exploitation

- https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List
https://github.com/huntergregal/mimipenguin
https://github.com/mubix/post-exploitation/wiki/Linux-Post-Exploitation-Command-List

### Linux Privilege Escalation

- https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/
https://www.kernel-exploits.com/
https://github.com/rebootuser/LinEnum
https://github.com/PenturaLabs/Linux_Exploit_Suggester
https://www.securitysift.com/download/linuxprivchecker.py
http://pentestmonkey.net/tools/audit/unix-privesc-check
https://github.com/mzet-/linux-exploit-suggester
http://www.darknet.org.uk/2015/06/unix-privesc-check-unixlinux-user-privilege-escalation-scanner/
https://www.youtube.com/watch?v=dk2wsyFiosg
http://resources.infosecinstitute.com/privilege-escalation-linux-live-examples/#gref
https://www.rebootuser.com/?p=1758

### Metasploit

- https://www.offensive-security.com/metasploit-unleashed/
http://www.securitytube.net/groups?operation=view&groupId=8

### MSFVenom Payloads

- http://netsec.ws/?p=331
https://www.offensive-security.com/metasploit-unleashed/msfvenom/
http://www.blackhillsinfosec.com/?p=4935

### Port Scanning

- https://highon.coffee/blog/nmap-cheat-sheet/
https://nmap.org/nsedoc/
https://github.com/superkojiman/onetwopunch
http://kalilinuxtutorials.com/unicornscan/

### Password Cracking

- https://uwnthesis.wordpress.com/2013/08/07/kali-how-to-crack-passwords-using-hashcat/
https://hashkiller.co.uk/
https://linuxconfig.org/password-cracking-with-john-the-ripper-on-linux
http://www.rarpasswordcracker.com/

### Pivoting

- https://www.offensive-security.com/metasploit-unleashed/portfwd/
https://www.offensive-security.com/metasploit-unleashed/proxytunnels/
https://github.com/rofl0r/proxychains-ng
https://www.sans.org/reading-room/whitepapers/testing/tunneling-pivoting-web-application-penetration-testing-36117
https://pentest.blog/explore-hidden-networks-with-double-pivoting/
https://blog.techorganic.com/2012/10/10/introduction-to-pivoting-part-2-proxychains/
https://www.cobaltstrike.com/help-socks-proxy-pivoting
https://sathisharthars.com/2014/07/07/evade-windows-firewall-by-ssh-tunneling-using-metasploit/
https://artkond.com/2017/03/23/pivoting-guide/

### Remote Desktop Protocol (RDP)

- https://serverfault.com/questions/148731/enabling-remote-desktop-with-command-prompt
https://serverfault.com/questions/200417/ideal-settings-for-rdesktop

### Samba (SMB)

- https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions
http://www.blackhillsinfosec.com/?p=4645

### TTY Shell Spawning

- http://netsec.ws/?p=337
https://github.com/infodox/python-pty-shells
https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

### SQL Injection

- http://www.sqlinjection.net/category/attacks/
http://sechow.com/bricks/docs/login-1.html
https://www.exploit-db.com/papers/12975/
https://websec.wordpress.com/2010/12/04/sqli-filter-evasion-cheat-sheet-mysql/
https://www.netsparker.com/blog/web-security/sql-injection-cheat-sheet/
https://github.com/cr0hn/nosqlinjection_wordlists
https://blog.scrt.ch/2013/03/24/mongodb-0-day-ssji-to-rce/
https://websec.ca/kb/sql_injection#MSSQL_Default_Databases

### Vulnhub VMs

### HackTheBox (HTB)

### Web Exploitation

- http://www.studfiles.ru/preview/2083097/page:7/
http://126kr.com/article/3vbt0k8fxwh
http://meyerweb.com/eric/tools/dencoder/

### Windows Post-Exploitation

- https://github.com/gentilkiwi/mimikatz/releases/
https://github.com/gentilkiwi/mimikatz/wiki/module-~-sekurlsa
http://www.handgrep.se/repository/cheatsheets/postexploitation/WindowsPost-Exploitation.pdf
https://github.com/PowerShellMafia/PowerSploit
https://github.com/gentilkiwi/mimikatz/releases
http://www.handgrep.se/repository/cheatsheets/postexploitation/WindowsPost-Exploitation.pdf
https://github.com/mubix/post-exploitation/wiki/windows

### Windows Privilege Escalation

- http://www.fuzzysecurity.com/tutorials/16.html
https://toshellandback.com/2015/11/24/ms-priv-esc/
https://github.com/pentestmonkey/windows-privesc-check
https://blog.gdssecurity.com/labs/2014/7/11/introducing-windows-exploit-suggester.html
https://pentest.blog/windows-privilege-escalation-methods-for-pentesters/
https://github.com/foxglovesec/RottenPotato
http://www.exumbraops.com/penetration-testing-102-windows-privilege-escalation-cheatsheet/
https://www.youtube.com/watch?v=PC_iMqiuIRQ
https://www.youtube.com/watch?v=kMG8IsCohHA&feature=youtu.be
https://github.com/PowerShellMafia/PowerSploit
http://www.blackhillsinfosec.com/?p=5824
https://www.commonexploits.com/unquoted-service-paths/
https://github.com/abatchy17/WindowsExploits

### https://scund00r.com/all/oscp/2018/02/25/passing-oscp.html

### Vulnhub VM LIST

- 2
Curated by the NetSec Focus Admins - netsecfocus.com	
3
Join us on the #"VulnHub & CTF" channel on Mattermost and find people to complete these with!
4
VMs Highlighted in pink are considered to be similar to OSCP						
5
Kioptrix: Level 1 (#1): https://www.vulnhub.com/entry/kioptrix-level-1-1,22/						
6
Kioptrix: Level 1.1 (#2): https://www.vulnhub.com/entry/kioptrix-level-11-2,23/						
7
Kioptrix: Level 1.2 (#3): https://www.vulnhub.com/entry/kioptrix-level-12-3,24/						
8
Kioptrix: Level 1.3 (#4): https://www.vulnhub.com/entry/kioptrix-level-13-4,25						
9
Kioptrix: 2014: https://www.vulnhub.com/entry/kioptrix-2014-5,62/						
10
FristiLeaks 1.3: https://www.vulnhub.com/entry/fristileaks-13,133/						
11
Stapler 1: https://www.vulnhub.com/entry/stapler-1,150/						
12
VulnOS 2: https://www.vulnhub.com/entry/vulnos-2,147/						
13
SickOs 1.2: https://www.vulnhub.com/entry/sickos-12,144/						
14
Brainpan 1: https://www.vulnhub.com/entry/brainpan-1,51/						
15
HackLAB: Vulnix: https://www.vulnhub.com/entry/hacklab-vulnix,48/						
16
/dev/random: scream: https://www.vulnhub.com/entry/devrandom-scream,47/						
17
pWnOS 2.0: https://www.vulnhub.com/entry/pwnos-20-pre-release,34/						
18
SkyTower 1: https://www.vulnhub.com/entry/skytower-1,96/						
19
Mr-Robot 1: https://www.vulnhub.com/entry/mr-robot-1,151/						
20
PwnLab: https://www.vulnhub.com/entry/pwnlab-init,158/						
21
Metasploitable 3: https://github.com/rapid7/metasploitable3						
22
Lin.Security: https://www.vulnhub.com/entry/linsecurity-1,244/						
23
Temple of Doom: https://www.vulnhub.com/entry/temple-of-doom-1,243/						
24
Pinkys Palace v1: https://www.vulnhub.com/entry/pinkys-palace-v1,225/						
25
Pinkys Palace v2: https://www.vulnhub.com/entry/pinkys-palace-v2,229/						
26
Zico2: https://www.vulnhub.com/entry/zico2-1,210/						
27
Wintermute: https://www.vulnhub.com/entry/wintermute-1,239/						
28
Lord of the root 1.0.1: https://www.vulnhub.com/entry/lord-of-the-root-101,129/						
29
Tr0ll 1: https://www.vulnhub.com/entry/tr0ll-1,100/						
30
Tr0ll 2: https://www.vulnhub.com/entry/tr0ll-2,107/						
31
Web Developer 1: https://www.vulnhub.com/entry/web-developer-1,288/						
32
SolidState: https://www.vulnhub.com/entry/solidstate-1,261/						
33
Hackme 1: https://www.vulnhub.com/entry/hackme-1,330/						
34
Escalate_Linux: 1: https://www.vulnhub.com/entry/escalate_linux-1,323/						
35
DC: 6: https://www.vulnhub.com/entry/dc-6,315/						
36
IMF: https://www.vulnhub.com/entry/imf-1,162/						
37
Tommy Boy: https://www.vulnhub.com/entry/tommy-boy-1,157/						
38
Billy Madison: https://www.vulnhub.com/entry/billy-madison-11,161/						
39
Tr0ll1: https://www.vulnhub.com/entry/tr0ll-1,100/						
40
Tr0ll2: https://www.vulnhub.com/entry/tr0ll-2,107/						
41
Wallaby's Nightmare: https://www.vulnhub.com/entry/wallabys-nightmare-v102,176/						
42
Moria: https://www.vulnhub.com/entry/moria-1,187/						
43
BSides Vancouver 2018: https://www.vulnhub.com/entry/bsides-vancouver-2018-workshop,231/
44
DEFCON Toronto Galahad: https://www.vulnhub.com/entry/defcon-toronto-galahad,194/						
45
Spydersec: https://www.vulnhub.com/entry/spydersec-challenge,128/						
46
Pinkys Palace v3: https://www.vulnhub.com/entry/pinkys-palace-v3,237/						
47
Pinkys Palace v4: https://www.vulnhub.com/entry/pinkys-palace-v4,265/						
48
Vulnerable Docker 1: https://www.vulnhub.com/entry/vulnerable-docker-1,208/						
49
Node 1: https://www.vulnhub.com/entry/node-1,252/						
50
Troll 3: https://www.vulnhub.com/entry/tr0ll-3,340/						
51
Readme 1: https://www.vulnhub.com/entry/readme-1,336/						
52
OZ: https://www.vulnhub.com/entry/oz-1,317/

### Hack The Box VM LIST

- 3
Linux Boxes:	Windows Boxes:	
More challenging than OSCP, but good practice:
4
Lame	legacy	Jeeves [Windows]			
5
brainfuck	Blue	Bart [Windows]			
6
shocker	Devel	Tally [Windows]			
7
bashed	Optimum	Active [Windows]			
8
nibbles	Bastard	Kotarak [Linux]			
9
beep	granny	falafel [Linux]			
10
cronos	Arctic	Devops [Linux]			
11
nineveh	grandpa	Hawk [Linux]			
12
sense	silo	Netmon [Windows]			
13
solidstate	bounty	Lightweight [Linux]			
14
node	jerry	La Casa De Papel [Linux]			
15
valentine	conceal	Jail [Linux]			
16
poison	chatterbox	Safe [Linux]			
17
sunday					
18
tartarsauce					
19
Irked					
20
Friendzone					
21
Swagshop					
22
Networked					
23
jarvis	

*XMind: ZEN - Trial Version*
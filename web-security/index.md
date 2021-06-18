
# 简单介绍
<pre>
<code>
PHP + MYSQL + Apache 开源的 WEB漏洞 靶场，Pikachu
docker search pikachu
docker pull area39/pikachu
// 运行容器(相当于create + start)
docker run -d --name=pikachu --rm -p 9999:80 area39/pikachu
-d：代表后台运行
-t：为容器分配伪终端
--name：命名容器
-p：指定映射端口，此处将 acgpiano/sqli-labs 的 80 端口映射到本地的 80 端口
-i:允许你对容器内的标准输入 (STDIN) 进行交互
--rm：退出时自动移除容器
// 进入容器
docker exec -it pikachu sh
</code>
</pre>
[area39/pikachu](https://registry.hub.docker.com/r/area39/pikachu)

# XSS（Cross-site Script，跨站脚本）
##  原因
XSS 漏洞，通常指的是网站对用户输入数据未做有效过滤，攻击者可以将恶意脚本注入网站页面中，达到执行恶意代码的目的。
##  靶场演示
一般将 XSS：反射型、存储型、DOM 型。
### 反射型 XSS（客户端自己玩）
反射型 XSS 又被称为非持久型跨站脚本，而不是存储到服务器，因此需要诱使用户点击才能触发攻击。<br>
// 演示：Cross-Site Scripting / 反射型xss(post)<br>
// 需要修改 input 的 maxlength, action="#" <br>
```
// 如获取 cookie<br>
<script>alert(document.cookie)</script><br>
<h1 style="color: red">我是 h1</h1><br>
<h2 style="color: blue">我是 h2</h2><br>
```

### 存储型 XSS（有服务端参与）
它又被称为持久型跨站脚本。攻击者将恶意代码存储到服务器上，只要诱使受害者访问被插入恶意代码的页面即可触发。
```
我提交了一个js代码，<script>alert(document.cookie)</script>
<h2 style="color: blue">我是 h2</h2>
```

### DOM 型 XSS
它是基于文档对象模型（Document Object Model，DOM，用于将 Web 页面与脚本语言链接起来的标准编程接口）的一种漏洞，它不经过服务端，而是通过 URL 传入参数去触发，因此也属于反射型 XSS。

<pre>
```
javascript:alert(document.cookie)
```
</pre>

##  预防
### 站点扫描方案
[XSS 漏洞扫描的开源工具-XSStrike](https://github.com/s0md3v/XSStrike)
[XSS 漏洞扫描的开源工具-NoXSS](https://github.com/lwzSoviet/NoXss)

### 编码层预防
<pre>
```
1.  输入检查，白名单限制用户输入javascript:、<、>、'、"、&、#，一定不要单纯只在客户端上做过滤，还要结合服务端做限制。若只是客户端上做过滤，那么抓包后修改数据重发就绕过了。<br>
2.  输出检查<br>
3.  innerHTML（textContent）、href、src、element.setAttribute、element.style.backgroundImage<br>
4.  Httponly Cookie<br>
5.  Content Security Policy<br>
```
</pre>
### 题外话
textContent 和 innerText 区别<br>
textContent 可以获取 display: none; 标签中的文本<br>
innerText 无法获取 display: none; 标签内的文本<br>

[XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)
# SQL 注入
##  原因
开发时未对用户的输入数据（可能是 GET 或 POST 参数，也可能是 Cookie、HTTP 头等）进行有效过滤，直接带入 SQL 语句解析，使得原本应为参数数据的内容，却被用来拼接 SQL 语句做解析（一句话解释，错误的将数据当代码解析，最终导致 SQL 注入漏洞的产生）。<br>
十几年前，有个号称有可登录任意网站管理后台的万能密码，只要在用户名和密码中均输入 'or'1'='1（注意单引号的使用）即可登录后台。<br>
<pre>
```
SELECT username, password FROM users WHERE username='$uname' and password='$passwd' LIMIT 0,1
SELECT username, password FROM users WHERE username='admin'or'1'='1' and password=''or'1'='1' LIMIT 0,1
// $uname 为 admin'or'1'='1；password 为 'or'1'='1
```
</pre>
##  举例
### 数字/整数型注入
注入的参数为整数时就是数字型注入，或者叫整数型注入。<br>
<pre>
```
SELECT * FROM table WHERE id=2
SELECT * FROM table WHERE id=1+1
```
</pre>
此处 id 参数为整数，两边无引号。测试时可以使用 1+1 和 3-1 这种计算结果相同的参数值去构造请示，对比响应结果是否一致，如果相同就可能在数字型注入。<br>

### 字符型注入
注入参数为字符串时就是字符型注入。<br>
SELECT * FROM table WHERE name='test'

### 二次注入
有可能第一次带入参数时做了安全转义，但开发人员在二次使用时并没有做转义，导致第二次使用时才产生注入，这就是二次注入。

##  靶场演示
<pre>
```
// 字符型注入(get)
http://localhost:9999/vul/sqli/sqli_str.php?name=ko'+'be&submit=%E6%9F%A5%E8%AF%A2
以搜索型注入为例(模糊匹配)
php源码分析：/app/vul/sqli/sqli_search.php
 $query="select username,id,email from member where username like '%$name%'";
```
</pre>
##  预防
[SQL 注入检测-sqlmap](http://sqlmap.org/)

1.  白名单：如果请求参数有特定值的约束，比如参数是固定整数值，那么就只允许接收整数；还有就是常量值限制，比如特定的字符串、整数值等。<br>
2.  参数化查询：参数化查询是预编译 SQL 语句的一种处理方式，所以也叫预编译查询，它可以将输入数据插入到 SQL 语句中的“参数”（即变量）中，防止数据被当作 SQL 语句执行，从而防止 SQL 注入漏洞的产生。<br>
3.  WAF（Web 防火墙）：能够抵挡住大部分的攻击，几乎是当前各网站必备的安全产品。但它也不是无懈可击的，难免会被绕过。不过安全本身就是为了不断提高攻击成本而设立的，并不是为了完全、绝对地解决入侵问题。<br>
4.  RASP（Runtime Application Self-Protection）是一项运行时应用程序自我保护的安全技术，通过搜集和分析应用运行时的相关信息来检测和阻止针对应用本身的攻击，利用 RASP 对 WAF 进行有效的补充，可以构建更加完善的安全防御体系。<br>


# CSRF（Cross Site Request Forgery，跨站请求伪造，也叫 XSRF）
##  原因
由于未校验请求来源，导致攻击者可在第三方站点发起 HTTP 请求，并以受害者的目标网站登录态（cookie、session 等）请求，从而执行一些敏感的业务功能操作，比如更改密码、修改个人资料、关注好友。

##  靶场演示
php源码地址：/app/vul/csrf/csrfget/csrf_get_edit.php<br>
CSRF（get）为列<br>
修改用户信息请求：http://localhost:9999/vul/csrf/csrfget/csrf_get_edit.php?sex=12&phonenum=12&add=12&email=12&submit=submit<br>
身份cookie<br>
Cookie: PHPSESSID=bvrp622ugf4retneht933o14bj<br>
带token（比较安全）<br>
/app/vul/csrf/csrftoken/token_get_edit.php<br>

##  预防
1.  令请求参数不可预测，所以常用的方法就是在敏感操作请求上使用 POST 代替 GET，然后添加验证码或 Token 进行验证。<br>
2.  验证码，在一些重要的敏感操作上设置验证码（短信、图片等等），比如更改密码（此场景下也可要求输入原密码，这也是不可预测值）、修改个人资料等操作时。<br>
3.  Token 验证，提交表单后，会连同此 Token（隐藏的input） 一并提交，由服务器再做比对校验，Token 验证无疑是最常用的方法，它对用户是无感知的，体验上比验证码好太多了。<br>

```
// 提交的表单中，添加一个隐藏的 Token，其值必须是保证 1.服务端提供 2.不可预测的随机数。
<input type = "hidden" value="afcsjkl82389dsafcjfsaf352daa34df" name="token" >
```

这里不推荐 referer（即请求头中的来源地址）限制方法，因为通过 javascript:// 伪协议就能以空 referer 的形式发起请求，很容易绕过限制。一些移动 App 上的请求又可能无法完成，因为移动 App 上的 http/https 请求经常是空 referer。<br>
referer还有个作用就是防盗链，如图片资源。防止滥用，权威机构，Referrer-Policy 首部用来监管哪些访问来源信息——会在 Referer  中发送——应该被包含在生成的请求当中。<br>
# SSRF（Server-Side Request Forgery，服务端请求伪造）
外网隔离就绝对安全了吗？
## 产生原因
攻击者向服务端发送包含恶意 URL 链接的请求，借由服务端去访问此 URL ，以获取受保护网络内的资源的一种安全漏洞。SSRF 常被用于探测攻击者无法访问到的网络区域，比如服务器所在的内网，或是受防火墙访问限制的主机。

##  靶场演示

php源码：/app/vul/ssrf/ssrf_curl.php<br>
假设只有内网可以访问到 https://www.baidu.com<br>
http://localhost:9999/vul/ssrf/ssrf_curl.php?url=https://www.baidu.com<br>
ssrf 的问题是:前端传进来的 url 被后台使用 curl_exec()进行了请求,然后将请求的结果又返回给了前端<br>
除了 http/https 外,curl 还支持一些其他的协议 curl --version 可以查看其支持的协议,telnet<br>
curl 支持很多协议，有 FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE 等<br>
// 利用file://用户账户的详细信息<br>
http://localhost:9999/vul/ssrf/ssrf_curl.php?url=file:///etc/passwd<br>

##  具体有哪些危害
1.  内网探测：对内网服务器、办公机进行端口扫描、资产扫描、漏洞扫描。<br>
2.  窃取本地和内网敏感数据：访问和下载内网的敏感数据，利用 File 协议访问服务器本地文件。<br>
3.  攻击服务器本地或内网应用：利用发现的漏洞进一步发起攻击利用。<br>
4.  跳板攻击：借助存在 SSRF 漏洞的服务器对内或对外发起攻击，以隐藏自己真实 IP。<br>
5.  绕过安全防御：比如防火墙、CDN（内容分发网络，比如加速乐、百度云加速、安全宝等等）防御。<br>
6.  拒绝服务攻击：请求超大文件，保持链接 Keep-Alive Always。<br>

##  预防
[SSRF 检测工具 - SSRFmap](https://github.com/swisskyrepo/SSRFmap)

1.  采用白名单限制，只允许访问特定的 IP 或域名，比如只允许访问 tabe 域名 *.tabe.cn；<br>
2.  限制内网 IP 访问，常见的内网 IP 段有 10.0.0.0 - 10.255.255.255、172.16.0.0 - 172.31.255.255、192.168.0.0 - 192.168.255.255；<br>
3.  禁用一些不必要的协议，比如 file://、dict://(常用于刺探端口)。<br>
4.  另外关闭错误回显、关闭高危端口、及时修复漏洞，哪怕它是处于内网环境，都有助于缓解 SSRF 漏洞的进一步利用。<br>

##  dict（介绍）
DICT协议,一个字典服务器协议,A Dictionary Server Protocol<br>
使用：dict://serverip:port/命令:参数<br>
向服务器的端口请求为【命令:参数】读取 redis 的变量<br>
curl dict://192.168.0.67:6379/get:name<br>
curl 支持的通信协议有FTP、FTPS、HTTP、HTTPS、TFTP、SFTP、Gopher、SCP、Telnet、DICT、FILE、LDAP、LDAPS、IMAP、POP3、SMTP和RTSP。<br>
[SSRF之利用dict和gopher吊打Redis](https://www.cnblogs.com/Zh1z3ven/p/14214208.html)<br>

# XXE（XML External Entity，XML 外部实体注入）
##  产生原因
XXE（XML External Entity，XML 外部实体注入）正是当允许引用外部实体时，通过构造恶意内容，导致读取任意文件、执行系统命令、内网探测与攻击等危害的一类漏洞。

##  XML 文档结构
XML 文档结构包括 XML 声明、文档类型定义（DTD，Document Type Definition）、文档元素。<br>
<pre>
<!--XML声明-->
<?xml version="1.0"?> 
<!--文档类型定义-->
<!DOCTYPE people [  <!--定义此文档是 people 类型的文档-->
  <!ELEMENT people (name,age,mail)>  <!--定义people元素有3个元素-->
  <!ELEMENT name (#PCDATA)>     <!--定义name元素为“#PCDATA”类型-->
  <!ELEMENT age (#PCDATA)>   <!--定义age元素为“#PCDATA”类型-->
  <!ELEMENT mail (#PCDATA)>   <!--定义mail元素为“#PCDATA”类型-->
]]]>
<!--文档元素-->
<people>
  <name>john</name>
  <age>18</age>
  <mail>john@qq.com</mail>
</people>
</pre>

##  靶场演示
<pre>
php源码地址：/app/vul/xxe/xxe_1.php
// 读取本地文件
通过 file:// 可以读取本地文件，造成敏感文件泄露：
// 检测
<!DOCTYPE foo [<!ELEMENT foo ANY>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
// 声明实体 xxe，用于读取 /etc/passwd 文件，然后通过 &xxe; 来引用执行。
</pre>
### 题外话
由于我这里使用 Docker 搭建的靶场环境，由于 Docker 是利用 Linux 的 Namespace 和 Cgroups，它的原理是使用 Namespace 做主机名、网络、PID 、用户及用户组等资源的隔离，使用 Cgroups 对进程或者进程组做资源（例如：CPU、内存等）的限制。<br>
其中 User Namespace (user)  隔离用户和用户组，使 Docker 中的用户和我系统的用户隔离开。<br>


##  预防
[XXE 漏洞利用工具-XXEinjector](https://github.com/enjoiz/XXEinjector)

要防御 XXE 也比较简单，关闭外部实体引用即可。<br>
比如在 Java 中常用于解析 XML 的 DocumentBuilderFactory，就可以通过 setFeature 方法防御 XXE 漏洞<br>
<pre>
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
String FEATURE = null;
try {
    // 禁用DTD
    FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
    dbf.setFeature(FEATURE, true);

    // 禁用普通实体
    FEATURE = "http://xml.org/sax/features/external-general-entities";
    dbf.setFeature(FEATURE, false);

    // 禁用参数实体
    FEATURE = "http://xml.org/sax/features/external-parameter-entities";
    dbf.setFeature(FEATURE, false);

    // 禁用外部DTD引用
    FEATURE = "http://apache.org/xml/features/nonvalidating/load-external-dtd";
    dbf.setFeature(FEATURE, false);

    // 禁用XInclude处理功能
    dbf.setXIncludeAware(false);

    // 禁用扩展实体引用节点，注意：只使用该方法并不能完全防御XXE
    dbf.setExpandEntityReferences(false);
} catch () {
  ...
}
   // Load XML file or stream using a XXE agnostic configured parser...
   DocumentBuilder safebuilder = dbf.newDocumentBuilder();
```
</pre>

#  反序列化漏洞
反序列化漏洞，阿里的 fastjson
## 序列化与反序列化
序列化：序列化是把对象转换成有序字节流（可阅读的字符串），以便在网络上传输或者保存在本地文件中。<br>
反序列化：前面保存的字符串，快速地重建对象。<br>
## 漏洞是如何产生的？
当传给 unserialize() 的参数由外部可控时，若攻击者通过传入一个精心构造的序列化字符串，从而控制对象内部的变量甚至是函数，比如 PHP 中特殊的魔术方法，这些方法在某些情况下会被自动调用，为实现任意代码执行提供了条件，这时反序列化漏洞就产生了。有点懵，我们看靶场中实例吧。
##  靶场演示
<pre>
```
php源码：/app/vul/unserilization/unser.php
$str = O:1:"S":1:{s:4:"test";s:29:"<>alert('xss')</>";}
$u = unserialize($str);

// 解释
a - array 数组型
b - boolean 布尔型
d - double 浮点型
i - integer 整数型
o - common object 共同对象
r - objec reference 对象引用
s - non-escaped binary string 非转义的二进制字符串
S - escaped binary string 转义的二进制字符串
C - custom object 自定义对象
O - class 对象
N - null 空
R - pointer reference 指针引用
U - unicode string Unicode 编码的字符串

// php魔术方法
// 魔术方法就是 PHP 中一些在某些情况下会被自动调用的方法，无须手工调用，比如当一个对象创建时 __construct 会被调用，当一个对象销毁时 __destruct 会被调用。
__construct()   #类的构造函数
__destruct()    #类的析构函数
__call()        #在对象中调用一个不可访问方法时调用
__callStatic()  #用静态方式中调用一个不可访问方法时调用
__get()    #获得一个类的成员变量时调用
__set()    #设置一个类的成员变量时调用
__isset()  #当对不可访问属性调用isset()或empty()时调用
__unset()  #当对不可访问属性调用unset()时被调用。
__sleep()  #执行serialize()时，先会调用这个函数
__wakeup() #执行unserialize()时，先会调用这个函数
__toString()   #类被当成字符串时的回应方法
__invoke()     #调用函数的方式调用一个对象时的回应方法
__set_state()  #调用var_export()导出类时，此静态方法会被调用。
__clone()      #当对象复制完成时调用
__autoload()   #尝试加载未定义的类
__debugInfo()  #打印所需调试信息
```
</pre>

## 防御反序列化漏洞
1.  黑白名单限制/针对反序列化的类做一份白名单或黑名单的限制，首选白名单，避免一些遗漏问题被绕过。这种方法是当前很多主流框架的修复方案。<br>
2.  WAF/Web应用防火墙/收集各种语言的反序列化攻击数据，提取特征用于拦截请求。<br>
3.  RASP/Runtime application self-protection/RASP 除了可以检测漏洞外，它本身也可以提供类似 WAF 的防御功能。<br>

# 文件上传漏洞
##  产生原因
文件上传漏洞正是在文件上传功能中，由于对用户上传的文件数据未做有效检测或过滤不严，导致上传的恶意文件被服务端解释器解析执行，利用漏洞可获取系统控制权。<br>
若服务器支持某种语言的解析执行，比如上传了 ASP、JSP、ASPX 等文件对应代码执行。<br>

##  绕过上传限制
### 禁用 JS
前端开发时一般只会做后缀名判断，若不是就中断处理。对于这种情况安装个 NoScript 插件，禁用 JS 再上传即可绕过。
### 篡改数据包
对于前端 JS 的限制，除了禁用 JS 外，我们还可以使用 curl、nc、BurpSuite 等工具构造数据包去发送请求，这样是不经过浏览器前端 JS 的处理，从而绕过限制。
### 文件头绕过
不同文件格式有不同的文件头
### 大小写绕过
有时检测未区分文件名大小写时，可使用此方法绕过。
### 后缀别名绕过
有些执行脚本存在多个后缀别名，若网站对此检测不全时，也有可能绕过，不同语言的常用后缀如下表：
<pre>
php - php\php2\php3\pht
asp - asp\asa\cer\cdx
jsp - jsp\jspx\jspf
</pre>

##  靶场演示
<pre>
以 client check为例
移除 checkFileExt 文件限制函数
上传a.php文件
访问http://localhost:9999/vul/unsafeupload/uploads/a.php?name=fanerge
</pre>

###  预防
1. 严格检测上传文件后缀名、[文件头](https://www.cnblogs.com/mq0036/p/3912355.html)、Content-type，尽量采用白名单方式限制。<br>
2. 重编码文件，比如对图片或视频做转换处理。<br>
3. 限制文件大小，避免被恶意上传大文件造成存储空间不足，进而网站无法正常运行。<br>
4. 限制上传目录可不解析，不同的服务器有不同的配置方式，比如 Nginx 可按如下方式配置。<br>
5. 上传文件重命名，建议使用随机文件名。<br>

<pre>
// 1
linux 查看文件的文件头
xxd thank.jpeg | head -n 1 // ffd8 ffe0
xxd eg1.webp | head -n 1 // 5249 4646
// 4
location ~* ^/uploads/.*\.(php|php5)$ 
  {
    deny all;
  }
</pre>


# 远程命令/代码执行漏洞RCE(remote command/code execute)
##  命令注入漏洞成因
服务端直接将接受到的数据传入到系统命令执行函数去执行（没有验证参数）。
<pre>
PHP 中常见的系统命令执行函数有：
system()
exec()
shell_exec()
proc_open()
</pre>
如果用户的输入数据（如 GET、POST、Cookie 等数据）未做任何过滤或转义，直接转递给上述命令执行函数，就会造成命令注入漏洞。
### 命令拼接技巧
注入命令过程中，常常需要使用一些系统命令的拼接方式，以达到更多复杂功能的实现，尤其是存在限制的情况，运用好可用来绕过限制。
<pre>
&&
命令格式：cmd1 && cmd2，cmd1 执行成功后才会执行 cmd2。
|
命令格式：cmd1 | cmd2，cmd1 的执行结果传递给 cmd2 去执行。
||
命令格式：cmd1 || cmd2，cmd1 执行失败后就执行 cmd2。
;
命令格式：cmd1 ; cmd2，分号用于分隔多个命令去执行，命令按顺序 cmd1、cmd2 执行。
&
命令格式：cmd1 & cmd2，& 用于分隔多个命令，命令按顺序 cmd1、cmd2 执行。
``
命令格式：cmd，注意这里是对反斜号，代表命令执行结果的输出，即命令替换。
$()
命令格式：$(cmd)，用于命令替换，适用于 cmd 中需要使用多个拼接符。
()
命令格式：(cmd1;cmd2)，合并多个命令，重新开启子 shell 来执行命令。
{}
命令格式：{cmd,arg}，Linux bash 下用于合并多个命令及参数，在当前 shell 执行。
</pre>
##  靶场演示
<pre>
以 exec "ping" 为例
php源码路径：/app/vul/rce
127.0.0.1;cat /etc/passwd
</pre>

##  漏洞防御
1.  尽量不用系统命令执行函数，很多方式其实是可以通过一些语言内置 API 完成。<br>
如果一定要使用命令执行函数，就尽量不要将外部可控数据作为命令行参数。<br>
如果要将用户可控数据传递给命令执行函数，那首先推荐白名单方式，然后再是考虑转义过滤，以及数据格式校验。<br>
如，靶场题目是输入 IP 地址，那你可以使用正则做 IP 格式的检测，不符合就拒绝请求（总之，尽可能限制可输入参数的范围）。<br>
2.  命令执行监控与阻断/比如 PHP 环境下对 system 函数进行 hook，Java 环境下的 java.lang.Runtime.exec() 函数，当漏洞触发时可告警出来，并支持阻断功能，即 RASP 方案。<br>
[百度开源的 OpenRASP 产品](https://rasp.baidu.com/)

# 文件包含漏洞（File Inclusion）
##  文件包含漏洞成因
首先“文件包含”，是一个功能。在各种开发语言中都提供了内置的文件包含函数，其可以使开发人员在一个代码文件中直接包含（引入）另外一个代码文件。 比如 在PHP中，提供了：<br>
include(),include_once()<br>
require(),require_once()<br>
这些文件包含函数，这些函数在代码设计中被经常使用到。<br>
大多数情况下，文件包含函数中包含的代码文件是固定的，因此也不会出现安全问题（一般用于复用代码）。<br>
include_once $Footer . './footer.php' <br>
但是，有些时候，文件包含的代码文件被写成了一个变量，且这个变量可以由用户传进来，这种情况下，如果没有做足够的安全考虑，则可能会引发文件包含漏洞。 <br>
##  文件包含漏洞分类
1.  本地文件包含漏洞：仅能够对服务器本地的文件进行包含，由于服务器上的文件并不是攻击者所能够控制的，因此该情况下，攻击着更多的会包含一些 固定的系统配置文件，从而读取系统敏感信息。很多时候本地文件包含漏洞会结合一些特殊的文件上传漏洞，从而形成更大的威力。<br>
2.  远程文件包含漏洞：能够通过url地址对远程的文件进行包含，这意味着攻击者可以传入任意的代码，这种情况没啥好说的，准备挂彩。<br>
因此，在web应用系统的功能设计上尽量不要让用户直接传变量给包含函数，如果非要这么做，也一定要做严格的白名单策略进行过滤。<br>

##  靶场演示
<pre>
以本地文件包含漏洞为例
php源码：/app/vul/fileinclude/fi_local.php
http://127.0.0.1:9999/vul/fileinclude/fi_local.php?filename=../../../../../../../../etc/passwd&submit=%E6%8F%90%E4%BA%A4
</pre>

##  挖掘文件包含漏洞
1.  静态检测思路/扫描代码中的文件包含函数如 include 看传入的参数是否依赖了用户的数据 $_GET\$_POST\$_COOKIE等等<br>
2.  自动化检测与利用工具：[Kadimus](https://github.com/P0cL4bs/Kadimus/)<br>

##  漏洞防御
1.  白名单限制/如“文件包含漏洞分类” $filename 只能等于某些文件等<br>
2.  设置 open_basedir，在 php.ini 中设置 open_basedir，可允许将 PHP 打开的文件限制在指定的目录中，可有效防止跨目录访问一些系统敏感文件，也可以在代码中指定basedir ini_set('open_basedir', '指定目录')。<br>
3.  关闭 allow_url_include/在 php.ini 中设置 allow_url_include＝Off（默认关闭），避免远程文件包含<br>

# 越权漏洞（over permission）
##  越权漏洞成因
越权漏洞是很多应用中比较常见的漏洞类型，它是在授权逻辑上存在安全缺陷导致的问题。在基于用户提供的输入对象直接访问，而未进行有效鉴权，导致一些超出预期的操作行为，可能导致信息泄露或者提权，具体危害的大小取决于业务场景，所以对越权漏洞的理解依赖于你对业务逻辑的理解深度。<br>
##  越权漏洞的分类
1.  水平越权/假设用户 A 与用户 B 属于相同权限等级的用户，当用户 A 能够访问用户 B 的私有数据时，就称为水平越权。<br>
2.  垂直越权/假设用户 A 是普通用户，用户 B 是管理员，当用户 A 能够访问用户 B 的私有数据时，就称为垂直越权，又称为权限提升。<br>

##  靶场演示
### 水平越权
登录lucy 发起的请求：<br>
http://localhost:9999/vul/overpermission/op1/op1_mem.php?username=lucy&submit=点击查看个人信息<br>
模拟 kobe 发起的请求：<br>
http://localhost:9999/vul/overpermission/op1/op1_mem.php?username=kobe&submit=点击查看个人信息<br>
### 垂直越权
admin/123456 是超级管理员(可以添加、删除用户)<br>
pikachu/000000 普通用户<br>
admin删除某个用户请求的格式：http://127.0.0.1:9999/vul/overpermission/op2/op2_admin.php?id=1<br>
admin添加用户的请求格式：POST http://127.0.0.1:9999/vul/overpermission/op2/op2_admin_edit.php
username=fan3&password=test&sex=%E7%94%B7&phonenum=13666666666&email=test%40gmail.com&address=test&submit=%E5%88%9B%E5%BB%BA<br>
构造 pikachu 删除用户的请求：重定向到302说明这里没有越权漏洞。<br>
// 这里我使用 HackBar 去构造 POST 请求（报错，因为form下有个input name为 submit 覆盖了form原有的submit方法，需手动触发 即提交按钮type设置为 submit 再点击即可）<br>
构造 pikachu 添加用户的请求：添加成功，说明这里存在越权漏洞。<br>
##  越权漏洞的检测（TODO）
BurpSuite/Authz<br>
BurpSuite/Auto Repeater<br>

##  防御越权漏洞
由于越权漏洞涉及业务逻辑，靠 WAF、RASP 那些安全系统是没有用的，更重要的是在开发设计时提前考虑好权限控制与校验问题，可以尝试从以下几方面入手：<br>
1.  整体的权限调节：每次访问一个对象时，都要检查访问是否授权，特别是对于安全很关键的对象。不要像前面的靶场题目那样，密码验证过后，后续的敏感对象操作都不再验证，这样很容易导致漏洞。<br>
2.  最低权限原则：只授予执行操作所必需的最小访问权限，并且对于该访问权只准许使用所需的最少时间。<br>
3.  前后端双重验证：在涉及敏感操作行为时，前端与后端同时对用户输入数据进行权限校验，尤其是前端校验特别容易被改包绕过。<br>
4.  对于特别敏感的操作增设密码或安全问题等验证方式：比如修改密码要求输入原密码。<br>


# 点击劫持（clickJack）
<pre>
// 原因
在网页中插入一个 transparent 的iframe，iframe 覆盖在定制位置，点击网页中的组件会触发 iframe 中的对应事件。
// 防御
1.  X-FRAME-OPTIONS: DENY 和 SAMEORIGIN，可以禁止或指定域名放入当前页面的 iframe 中。
2.  CSP frame-src 设置允许通过类似 frame 和 iframe 标签加载的内嵌内容的源地址。
</pre>

# DDoS分布式拒绝服务攻击
<pre>
// 原因
分布式拒绝服务攻击可以使很多的计算机在同一时间访问同一站点或IP等，使攻击的目标无法正常使用。
之前 GitHub 在一瞬间遭到高达 1.35Tbps 的带宽攻击。这次 DDoS 攻击几乎可以堪称是互联网有史以来规模最大、威力最大的 DDoS 攻击了。
// 1KB = 1024B；TB > GB > MB > KB > B // 1TB=1024GB=2^40字节
// 对我们业务有什么影响呢？
// 大量恶意请求占用带宽，甚至导致服务器宕机无法正常使用。
https://www.zhihu.com/question/22259175
分类：SYN Flood、DNS Query Flood、UDP Flood、ICMP Flood
// 这是一种利用TCP协议缺陷，发送大量伪造的TCP连接请求，从而使得被攻击方资源耗尽（CPU满负荷或内存不足）的攻击方式。建立TCP连接，需要三次握手——客户端发送SYN报文，服务端收到请求并返回报文表示接受，客户端也返回确认，完成连接。
// 防御
DDoS流量清洗（三方企业服务）、黑名单
</pre>
# 靶场其他漏洞演示
##  文件下载漏洞
<pre>
// 正常下载图片
http://localhost:9999/vul/unsafedownload/execdownload.php?filename=kb.png
// 构造下载路径(下载源码)
http://localhost:9999/vul/unsafedownload/execdownload.php?filename=../execdownload.php
</pre>

# 如何构建安全的WEB？
主要涉及 Apache 和 Nginx 服务器 和 PHP 语言配置。
##  Apache 
### 关闭目录浏览功能
Apache 默认允许目录浏览，如果目录下找不到可浏览器的页面，就会出现目录浏览问题，造成信息泄露。
Ubuntu 是通过修改 Apache 配置文件 /etc/apache2/apache2.conf，其他平台大多是叫 httpd.conf 的配置文件名，修改“Indexes”为“－Indexes”
### 开启访问日志
在浏览器被攻击时，通过日志可以帮助回溯整个安全事件的过程，有助于定位漏洞成因和攻击者。
Apache 已开启访问日志记录，你需要确认下配置文件是否开启 CustomLog 的日志路径设置：
<pre>
/etc/apache2/sites-available/default-ssl.conf
/etc/apache2/sites-available/000-default.conf
</pre>
### 隐藏一些敏感信息
X-power-by: X-Powered-By: PHP/5.2.1
### 禁止特定目录解析 PHP
对于不需要执行 PHP 脚本的目录，可禁止 PHP 解析，这种配置可有效防止上传漏洞的攻击，特别是上传目录的 PHP 解析限制。
<pre>
```
<Directory "/www/html/uploads">
  php_flag engine off
</Directory>
```
</pre>
### 不以 Root 启动 Apache
一句话“权利越大，责任越大”，最好按需、隔离分配权限。
httpd.conf，一般就直接用 User 与 Group 来指定用户名和用户组：
<pre>
User apache
Group apache
</pre>
### 禁止访问外部文件
当网站存在目录遍历漏洞时，攻击者可能通过 ../ 来访问系统上的任意目录，通过禁止 Apache 访问网站目录以外的目录和文件，可以有效地降低这种攻击带来的危害。
<pre>
  先禁止任何目录访问
	Order Deny,Allow
	Deny from all
					
  设置可访问的目录
	Order Allow,Deny
	Allow from {网站根目录}
</pre>
### 错误页面重定向
Apache 错误页面重定向功能可以防止敏感信息泄露，比如网站路径等信息。
```
ErrorDocument 400 /custom400.html
ErrorDocument 401 /custom401.html
ErrorDocument 403 /custom403.html
ErrorDocument 404 /custom404.html
ErrorDocument 405 /custom405.html
ErrorDocument 500 /custom500.html
```
### 删除默认页面
Apache 安装后会有默认页面，安装后仅用于测试，用于生产环境中时需要删除，这里需要删除 icons 和 manual 两个目录文件，以避免不必要的信息泄露。
##  Nginx
Nginx 配置文件通常位于 /usr/local/etc/nginx/nginx.conf
### 关闭目录浏览
Nginx 默认不允许目录浏览，你可以再确认下配置文件中的 autoindex 是否配置为 off，以防止敏感信息泄露。
<pre>
autoindex off
</pre>
### 开启访问日志
开启日志有助追踪攻击途径，以及定位攻击者。默认情况下，Nginx 会开启访问日志，你可在配置文件中确认下是否已开启：
<pre>
access_log /backup/nginx_logs/access.log combined;
</pre>
### 限制特定目录解析 PHP
对于不需要执行 PHP 脚本的目录，可禁止 PHP 解析，这种配置可有效防止上传漏洞的攻击，特别是上传目录的 PHP 解析限制，通过 nginx.conf 配置文件使用 deny all 来限制特定目录被 PHP 解析：
<pre>
location ~* ^/data/cgisvr/log/.*\.(php|php5)$
{
    deny all;
}
</pre>
### 删除默认页面
Nginx 也存在默认页面，上线后应该删除，防止不必要的信息泄露，可通过删除如下配置信息来解决。
<pre>
location /doc {
  root /usr/share;
  autoindex on;
  allow 127.0.0.1;
  deny all;
}
location /images {
  root /usr/share;
  autoindex off;
}
</pre>
##  PHP 安全配置
### 限制脚本访问权限
PHP 默认配置允许 php 脚本程序访问服务器上的任意文件，为避免 php 脚本访问不该访问的文件，从一定程度上限制了 php 木马的危害，一般设置为只能访问网站的目录：
```
open_basedir = /usr/local/apache2/htdocs（网站根目录）
```
### 禁止危险函数
 的特殊函数可以执行系统命令，查询任意目录，增加修改删除文件等。
```
disable_functions = exec,popen,system,passthru,shell_exec
```
### 关闭错误消息显示
一般 PHP 错误信息可能会包含网站路径或 SQL 查询语句等敏感信息，这些信息为攻击者提供有价值的信息，因此应该禁止错误显示，配置方式如下：
```
display_errors = Off
```
### 禁止访问远程文件
php 脚本若存在远程文件包含漏洞可以让攻击者直接获取网站权限及上传 web 木马，因此建议关闭远程文件访问功能，若需要访问可采用其他方式，比如 libcurl 库，配置如下:
```
allow_url_fopen = Off
allow_url_include = Off
```

# 测试工具
[BurpSuite/攻击web 应用程序的集成平台](https://t0data.gitbooks.io/burpsuite/content/chapter1.html)
[HackBar/测试网站安全性的小工具](https://addons.mozilla.org/zh-CN/firefox/addon/hackbartool/)

# 靶场
[sqli-labs 一款用于学习 SQL 注入的靶场平台](https://github.com/Audi-1/sqli-labs)
[DVWA 适合初学者的靶场平台](https://github.com/digininja/DVWA)

# 最后
[给大家推荐几门课程-对于想构建计算机知识体系很有帮助](https://kaiwu.lagou.com/hasBuy/special)

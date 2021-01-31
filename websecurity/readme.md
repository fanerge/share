PHP + MYSQL + Apache
安装 Pikachu 靶场

```
docker search pikachu
docker pull area39 / pikachu

docker run -d --name=pikachu --rm -p6666:80 area39/pikachu
-d：代表后台运行
-t：为容器分配伪终端
--name：命名容器
-p：指定映射端口，此处将 acgpiano/sqli-labs 的 80 端口映射到本地的 80 端口
--rm：退出时自动移除容器
```

#	XSS（Cross-site Script，跨站脚本）
##	原因
XSS 漏洞，通常指的是网站对用户输入数据未做有效过滤，攻击者可以将恶意脚本注入网站页面中，达到执行恶意代码的目的。
##	分类
一般将 XSS：反射型、存储型、DOM 型。
###	反射型 XSS（客户端自己玩）
反射型 XSS 又被称为非持久型跨站脚本，它是将攻击代码放在 URL 参数中，而不是存储到服务器，因此需要诱使用户点击才能触发攻击。
// 如获取 cookie
// 需要修改 input 的 maxlength, action="#"
```
<script>alert(document.cookie)</script>
```
###	存储型 XSS（有服务端参与）
它又被称为持久型跨站脚本。攻击者将恶意代码存储到服务器上，只要诱使受害者访问被插入恶意代码的页面即可触发。


```
我提交了一个js代码，<script>alert(document.cookie)</script>
```

###	DOM 型 XSS
它是基于文档对象模型（Document Object Model，DOM，用于将 Web 页面与脚本语言链接起来的标准编程接口）的一种漏洞，它不经过服务端，而是通过 URL 传入参数去触发，因此也属于反射型 XSS。

```
javascript:alert(1)
```

###	other
```
<h1 style="color: red">我是 h1</h1>
<h2 style="color: blue">我是 h2</h2>
```

##	预防
###	站点扫描方案
[XSS 漏洞扫描的开源工具-XSStrike](https://github.com/s0md3v/XSStrike)
[XSS 漏洞扫描的开源工具-NoXSS](https://github.com/lwzSoviet/NoXss)

###	编码层预防
1.	输入检查，白名单限制用户输入，<script>、javascript:、<、>、'、"、&、#，一定不要单纯只在客户端上做过滤，还要结合服务端做限制。若只是客户端上做过滤，那么抓包后修改数据重发就绕过了。
2.	输出检查
3.	innerHTML（textContent）、href、src、element.setAttribute、element.style.backgroundImage、
4.	Httponly Cookie
5.	Content Security Policy


#	SQL 注入
##	原因
开发时未对用户的输入数据（可能是 GET 或 POST 参数，也可能是 Cookie、HTTP 头等）进行有效过滤，直接带入 SQL 语句解析，使得原本应为参数数据的内容，却被用来拼接 SQL 语句做解析。
十几年前，有个号称有可登录任意网站管理后台的万能密码，只要在用户名和密码中均输入 'or'1'='1（注意单引号的使用）即可登录后台。
```
SELECT username, password FROM users WHERE username=''' and password='' LIMIT 0,1
SELECT username, password FROM users WHERE username='admin'or'1'='1' and password=''or'1'='1' LIMIT 0,1

```
##	举例
###	数字/整数型注入
注入的参数为整数时就是数字型注入，或者叫整数型注入。
```
SELECT * FROM table WHERE id=1
```
此处 id 参数为整数，两边无引号。测试时可以使用 1+1 和 3-1 这种计算结果相同的参数值去构造请示，对比响应结果是否一致，如果相同就可能在数字型注入。

###	字符型注入
注入参数为字符串时就是字符型注入。
```
SELECT * FROM table WHERE name='test'

```

###	二次注入
有可能第一次带入参数时做了安全转义，但开发人员在二次使用时并没有做转义，导致第二次使用时才产生注入，这就是二次注入。


##	预防
[SQL 注入检测-sqlmap](http://sqlmap.org/)

1.  白名单：如果请求参数有特定值的约束，比如参数是固定整数值，那么就只允许接收整数；还有就是常量值限制，比如特定的字符串、整数值等。
2.  参数化查询：参数化查询是预编译 SQL 语句的一种处理方式，所以也叫预编译查询，它可以将输入数据插入到 SQL 语句中的“参数”（即变量）中，防止数据被当作 SQL 语句执行，从而防止 SQL 注入漏洞的产生。
3.  WAF（Web 防火墙）：能够抵挡住大部分的攻击，几乎是当前各网站必备的安全产品。但它也不是无懈可击的，难免会被绕过。不过安全本身就是为了不断提高攻击成本而设立的，并不是为了完全、绝对地解决入侵问题。
4.  RASP（Runtime Application Self-Protection）是一项运行时应用程序自我保护的安全技术，通过搜集和分析应用运行时的相关信息来检测和阻止针对应用本身的攻击，利用 RASP 对 WAF 进行有效的补充，可以构建更加完善的安全防御体系。


#	CSRF（Cross Site Request Forgery，跨站请求伪造，也叫 XSRF）
##	原因
由于未校验请求来源，导致攻击者可在第三方站点发起 HTTP 请求，并以受害者的目标网站登录态（cookie、session 等）请求，从而执行一些敏感的业务功能操作，比如更改密码、修改个人资料、关注好友。


##	预防
1.	令请求参数不可预测，所以常用的方法就是在敏感操作请求上使用 POST 代替 GET，然后添加验证码或 Token 进行验证。
2.	验证码，在一些重要的敏感操作上设置验证码（短信、图片等等），比如更改密码（此场景下也可要求输入原密码，这也是不可预测值）、修改个人资料等操作时。
3.	Token 验证，提交表单后，会连同此 Token（隐藏的input） 一并提交，由服务器再做比对校验，Token 验证无疑是最常用的方法，它对用户是无感知的，体验上比验证码好太多了。

```
// 提交的表单中，添加一个隐藏的 Token，其值必须是保证1.服务端提供 2.不可预测的随机数。
<input type = "hidden" value="afcsjkl82389dsafcjfsaf352daa34df" name="token" >

```




这里不推荐 referer（即请求头中的来源地址）限制方法，因为通过 javascript:// 伪协议就能以空 referer 的形式发起请求，很容易绕过限制。一些移动 App 上的请求又可能无法完成，因为移动 App 上的 http/https 请求经常是空 referer。


扩展，referer还有个作用就是防盗链，如图片资源。


#	SSRF（Server-Side Request Forgery，服务端请求伪造）
外网隔离就绝对安全了吗？
## 产生原因
攻击者向服务端发送包含恶意 URL 链接的请求，借由服务端去访问此 URL ，以获取受保护网络内的资源的一种安全漏洞。SSRF 常被用于探测攻击者无法访问到的网络区域，比如服务器所在的内网，或是受防火墙访问限制的主机。

```
// 假设只有内网可以访问到 https://www.baidu.com
http://localhost:9999/vul/ssrf/ssrf_curl.php?url=https://www.baidu.com

// 查看 php 源码分析 
if(isset($_GET['url']) && $_GET['url'] != null){
	
    //接收前端 URL 没问题,但是要做好过滤,如果不做过滤,就会导致 SSRF
    $URL = $_GET['url'];
    $CH = curl_init($URL);
    curl_setopt($CH, CURLOPT_HEADER, FALSE);
    curl_setopt($CH, CURLOPT_SSL_VERIFYPEER, FALSE);
    $RES = curl_exec($CH);
    curl_close($CH) ;
//ssrf 的问题是:前端传进来的 url 被后台使用 curl_exec()进行了请求,然后将请求的结果又返回给了前端
//除了 http/https 外,curl 还支持一些其他的协议 curl --version 可以查看其支持的协议,telnet
//curl 支持很多协议，有 FTP, FTPS, HTTP, HTTPS, GOPHER, TELNET, DICT, FILE 以及 LDAP
    echo $RES;
}
```

```
// 用户账户的详细信息
http://localhost:9999/vul/ssrf/ssrf_curl.php?url=file:///etc/passwd


```
##	具体有哪些危害
1.	内网探测：对内网服务器、办公机进行端口扫描、资产扫描、漏洞扫描。
2.	窃取本地和内网敏感数据：访问和下载内网的敏感数据，利用 File 协议访问服务器本地文件。
3.	攻击服务器本地或内网应用：利用发现的漏洞进一步发起攻击利用。
4.	跳板攻击：借助存在 SSRF 漏洞的服务器对内或对外发起攻击，以隐藏自己真实 IP。
5.	绕过安全防御：比如防火墙、CDN（内容分发网络，比如加速乐、百度云加速、安全宝等等）防御。
6.	拒绝服务攻击：请求超大文件，保持链接 Keep-Alive Always。

##	预防
[SSRF 检测工具 - SSRFmap](https://github.com/swisskyrepo/SSRFmap)

1.	采用白名单限制，只允许访问特定的 IP 或域名，比如只允许访问拉勾网域名 *.tabe.com.cn；
2.	限制内网 IP 访问，常见的内网 IP 段有 10.0.0.0 - 10.255.255.255、172.16.0.0 - 172.31.255.255、192.168.0.0 - 192.168.255.255；
3.	禁用一些不必要的协议，比如 file://、gopher://(常用于攻击内网ftp、redis、telnet、smtp等服务)、dict://(常用于刺探端口)。
4.	另外关闭错误回显、关闭高危端口、及时修复漏洞，哪怕它是处于内网环境，都有助于缓解 SSRF 漏洞的进一步利用。

#	XXE（XML External Entity，XML 外部实体注入）
##	产生原因
XXE（XML External Entity，XML 外部实体注入）正是当允许引用外部实体时，通过构造恶意内容，导致读取任意文件、执行系统命令、内网探测与攻击等危害的一类漏洞。


##	攻击手段
// 读取本地文件
通过 file:// 可以读取本地文件，造成敏感文件泄露：
```
// 检测
<!DOCTYPE foo [<!ELEMENT foo ANY>
    <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
// 声明实体 xxe，用于读取 /etc/passwd 文件，然后通过 &xxe; 来引用执行。
```
###	扩展
由于我这里使用 Docker 搭建的靶场环境，由于 Docker 是利用 Linux 的 Namespace 和 Cgroups，它的原理是使用 Namespace 做主机名、网络、PID 、用户及用户组等资源的隔离，使用 Cgroups 对进程或者进程组做资源（例如：CPU、内存等）的限制。
其中 User Namespace (user)	隔离用户和用户组，使 Docker 中的用户和我系统的用户隔离开。

##	预防
[XXE 漏洞利用工具-XXEinjector](XXEinjector)

要防御 XXE 也比较简单，关闭外部实体引用即可。
比如在 Java 中常用于解析 XML 的 DocumentBuilderFactory，就可以通过 setFeature 方法防御 XXE 漏洞
```
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

#	文件上传漏洞
##	产生原因
文件上传漏洞正是在文件上传功能中，由于对用户上传的文件数据未做有效检测或过滤不严，导致上传的恶意文件被服务端解释器解析执行，利用漏洞可获取系统控制权。
若服务器支持某种语言的解析执行，比如上传了 ASP、JSP、ASPX 等文件对应代码执行。

##	绕过上传限制
###	禁用 JS
前端开发时一般只会做后缀名判断，若不是就中断处理。对于这种情况安装个 NoScript 插件，禁用 JS 再上传即可绕过。
###	篡改数据包
对于前端 JS 的限制，除了禁用 JS 外，我们还可以使用 curl、nc、BurpSuite 等工具构造数据包去发送请求，这样是不经过浏览器前端 JS 的处理，从而绕过限制。
###	文件头绕过
不同文件格式有不同的文件头
###	%00 截断
如果限制不当，仍有可能绕过。比如对文件后缀、路径上的检测，有时可通过添加 ％00 截断来绕过
```
upload.php?type=image&file=shell.php%00.jpg
```
###	大小写绕过
有时检测未区分文件名大小写时，可使用此方法绕过。
###	后缀别名绕过
有些执行脚本存在多个后缀别名，若网站对此检测不全时，也有可能绕过，不同语言的常用后缀如下表：
```
php - php\php2\php3\pht
asp - asp\asa\cer\cdx
jsp - jsp\jspx\jspf
```
##	预防
1. 严格检测上传文件后缀名、[文件头](https://www.cnblogs.com/mq0036/p/3912355.html)、Content-type，尽量采用白名单方式限制。
2. 重编码文件，比如对图片或视频做转换处理。
3. 限制文件大小，避免被恶意上传大文件造成存储空间不足，进而网站无法正常运行。
4. 限制上传目录可不解析，不同的服务器有不同的配置方式，比如 Nginx 可按如下方式配置。
5. 上传文件重命名，建议使用随机文件名。

```
// 1
linux 查看文件的文件头
xxd thank.jpeg | head -n 1
// 4
location ~* ^/uploads/.*\.(php|php5)$ 
  {
    deny all;
  }
```

#	靶场
[sqli-labs 一款用于学习 SQL 注入的靶场平台](https://github.com/Audi-1/sqli-labs)
[DVWA 适合初学者的靶场平台](https://github.com/digininja/DVWA)
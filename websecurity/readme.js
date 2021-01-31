PHP + MySQL
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

## Docker安装-卸载

### 一、环境

ECS（1核2G1M）+centOS7    

### 二、卸载旧的安装包

yum remove docker \
         docker-client \
         docker-client-latest \
         docker-common \
         docker-latest \
         docker-latest-logrotate \
         docker-logrotate \
         docker-engine

yum remove docker-ce docker-ce-cli containerd.io #卸载依赖

rm -rf /var/lib/docker #删除资源

### 三、安装

#### 1 安装工具包

yum install -y yum-utils device-mapper-persistent-data lvm2

修改yum-config-manager

vi /usr/bin/yum-config-manager

python改为python2
#!/usr/bin/python2 -tt


#### 2 设置镜像仓库

 yum-config-manager \

  --add-repo \

  https://download.docker.com/linux/centos/docker-ce.repo  --默认是国外的



#如果没有vpn 建议安装阿里云的   

yum-config-manager \
 --add-repo \
 http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo

\#更新yum 索引安装包

yum makecache fast 

#### 3  安装启动docker

 yum install docker-ce docker-ce-cli containerd.io   #安装，可能会出错，多试几次

 systemctl start docker   #启动

 docker --version \#查看docker 是否安装完成

#### 4 Hello world

 docker run hello-world #初次自动下载镜像

## Docker基本操作

### Docker镜像操作

docker images #查看全部镜像

docker pull 名称

docker search httpd

docker rmi 镜像name/镜像id  (-f)

docker build #创建镜像

### Docker 容器操作

查看所有容器 docker ps -a

 

查看容器运行日志 docker logs 容器名称/容器id

 

停止容器运行 docker stop 容器name/容器id

 

终止容器后运行 docker start 容器name/容器id

 

容器重启 docker restart 容器name/容器id

 

删除容器 docker rm  -f 容器name/容器id 



## docker-compose

### 简介

Compose 是用于定义和运行多容器 Docker 应用程序的工具。通过 Compose，您可以使用 YML 文件来配置应用程序需要的所有服务。然后，使用一个命令，就可以从 YML 文件配置中创建并启动所有服务。

YAML教程 https://www.runoob.com/w3cnote/yaml-intro.html 

Compose 使用的三个步骤：

· 使用 Dockerfile 定义应用程序的环境。

· 使用 docker-compose.yml 定义构成应用程序的服务，这样它们可以在隔离环境中一起运行。

· 最后，执行 docker-compose up 命令来启动并运行整个应用程序。

### 安装

下载 Docker Compose 的当前稳定版本：

 

$ sudo curl -L "https://github.com/docker/compose/releases/download/1.24.1/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose

要安装其他版本的 Compose，请替换 1.24.1。

 

将可执行权限应用于二进制文件：

 

$ sudo chmod +x /usr/local/bin/docker-compose

创建软链：

 

$ sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose

测试是否安装成功：

 

$ docker-compose --version

cker-compose version 1.24.1, build 4667896b

执行以下命令来启动应用程序：

docker-compose up -d

## 课堂用命令

初始化一波环境

docker search netcore

docker pull microsoft/dotnet  #下载基础镜像

docker stop $(docker ps -q) & docker rm $(docker ps -aq)  #停用并删除全部容器

build镜像：

docker build -t core31v1.813 -f Dockerfile .

docker run -itd -p 8082:80 core31v1.813

docker exec -it fd2c868cadlc /bin/bash

ls----cd----cat--exit



docker run -d -p 8081:80 -v /0813/project/publish:/app --workdir /app mcr.microsoft.com/dotnet/core/aspnet dotnet /app/Zhaoxi.AspNetCore31.DemoProject.dll

docker run -d -p 8086:80 -v /0813/enginx/:/var/log/nginx/ -v /0813/enginx/nginx.conf:/etc/nginx/nginx.conf --name elnginx nginx




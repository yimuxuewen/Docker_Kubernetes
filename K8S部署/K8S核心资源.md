## 1、K8S的核心资源管理方法

### 1.1、称述式资源管理方法

#### 1.1.1、管理命名空间资源

##### 1.1.1.1、查看名称空间

```
kubectl get namespace
#简写
kubectl get ns
```

##### 1.1.1.2、查看名称空间内的资源

```
#查看default命名空间下的所有资源
kubectl get all -n default
```

##### 1.1.1.3、创建名称空间

```
#创建app命名空间
kubectl create namespace app
#查看所有命名空间
kubectl get namespace
```

##### 1.1.1.4、删除名称空间

```
#创建app命名空间
kubectl delete namespace app
#查看所有命名空间
kubectl get namespace
```

#### 1.1.2、管理Deployment资源

##### 1.1.2.1、创建deployment

```
kubectl create deployment nginx-dp --image=harbor.od.com/public/nginx:v1.7.9 -n kube-public
```



##### 1.1.2.2、查看deployment

```
kubectl get deploy -n kube-public 

kubectl get pods -n kube-public
#扩展方式查看
kubectl get pods -n kube-public -o wide

#详细查看
kubectl describe deployment nginx-dp -n kube-public

kubectl exec -it nginx-dp-5dfc689474-gk477 /bin/bash -n kube-public

docker exec -it nginx-dp-5dfc689474-gk477 /bin/bash -n kube-public
```

##### 1.1.2.3、扩容deployment

```
kubectl scale deployment nginx-dp --replicas=2 -n kube-public
```



##### 1.1.2.4、查看pod资源

```
kubectl get pods -n kube-public 

```

##### 1.1.2.5、进入pod资源

```
kubectl exec -it nginx-dp-5dfc689474-gk477 /bin/bash -n kube-public

#使用docker命令进入资源
docker exec -it k8s_nginx_nginx-dp-5dfc689474-gk477_kube-public_e7a591e8-4407-4586-9779-ac694920b835_1 bash -n kube-public
```

##### 1.1.2.6、删除pod资源(重启)

```
kubectl delete pod nginx-dp-5dfc689474-gk477 -n kube-public

#强制删除
kubectl delete pod nginx-dp-5dfc689474-gk477 -n kube-public --force --grace-period=0


#查看资源
kubectl get pods -n kube-public
```

##### 1.1.2.7、删除deployment资源

```
kubectl delete deployment nginx-dp -n kube-public

#查看资源
kubectl get all -n kube-public
```



#### 1.1.3、管理Service资源

##### 1.1.3.1、创建service

```
#创建deployment
kubectl create deployment nginx-dp --image=harbor.od.com/public/nginx:v1.7.9 -n kube-public

#创建service
kubectl expose deployment nginx-dp --port=80 -n kube-public

#查看资源
kubectl get all -n kube-public
```

##### 1.1.3.2、查看service

```
#查看资源
kubectl describe svc nginx-dp -n kube-public
```

#### 1.1.4、kubectl用法总结

```
#查看kubectl的所有命令
kubectl --help

#中文社区查看：http://docs.kubernetes.org.cn/

kubectl get pods nginx-dp-5dfc689474-4rbng -o yaml -n kube-public
```



### 1.2、声明式资源管理方法

#### 1.2.1、查看资源配置清单

```
#查看命名空间kube-public下的pod资源
kubectl get pods -n kube-public

#查看pod的资源配置清单内容
kubectl get pods nginx-dp-5dfc689474-4rbng -o yaml -n kube-public

#查看service的资源配置清单内容
kubectl get svc nginx-dp -o yaml -n kube-public
```

#### 1.2.2、解释资源配置清单

```
kubectl explain service

kubectl explain service.metadata
```

#### 1.2.3、创建资源配置清单

```
vi /root/nginx-ds-svc.yaml


apiVersion: v1
kind: Service
metadata:
  labels:
    app: nginx-ds
  name: nginx-ds
  namespace: default
spec:
  ports:
  - port: 80
    protocol: TCP
    targetPort: 80
  selector:
    app: nginx-ds
  sessionAffinity: None
  type: ClusterIP
```

#### 1.2.4、应用资源配置清单

```
kubectl create -f /root/nginx-ds-svc.yaml
#或
kubectl apply -f /root/nginx-ds-svc.yaml

kubectl get svc nginx-ds -o yaml -n default
```

#### 1.2.5、修改资源配置清单并应用

- **离线修改资源配置清单(推荐)**

  修改资源配置清单后可以使用apply应用。

  这里增加一个知识点，就是kube-apiserver这个服务当中，有一个限制端口范围的参数：--service-node-port-range 10-29999，这个参数在使用apply修改资源配置清单的时候，会有作用

```
vi /root/nginx-ds-svc.yaml  #将对外暴露的端口改为881

kubectl apply -f /root/nginx-ds-svc.yaml

#查看service资源
kubectl get svc

```

- **在线修改**

```
kubectl edit svc nginx-ds -n default

#查看service资源
kubectl get svc

```

#### 1.2.6、删除资源配置清单

```
 #陈述式删除
 kubectl delete svc nginx-ds -n default
 
 #声明式删除
 kubectl delete -f nginx-ds-svc.yaml
```

#### 1.2.6、查看并使用Service资源

```
kubectl get svc

```

## 2、K8S的核心插件(addons)

### 2.1、K8S的CNI网络插件-Flannel

#### 2.1.1、集群规划

首先，flannel利用Kubernetes API或者etcd用于存储整个集群的网络配置，其中最主要的内容为设置集群的网络地址空间。例如，设定整个集群内所有容器的IP都取自网段“10.1.0.0/16”。

接着，flannel在每个主机中运行flanneld作为agent，它会为所在主机从集群的网络地址空间中，获取一个小的网段subnet，本主机内所有容器的IP地址都将从中分配。

然后，flanneld再将本主机获取的subnet以及用于主机间通信的Public IP，同样通过kubernetes API或者etcd存储起来。

最后，flannel利用各种backend mechanism，例如udp，vxlan等等，跨主机转发容器间的网络流量，完成容器间的跨主机通信

```
#可手动增加静态路由，连接172.7.21.0/24和172.7.22.0/24
#在hdss7-21
route add -net 172.7.22.0/24 gw 10.4.7.22 dev ens33
#在hdss7-22
route add -net 172.7.21.0/24 gw 10.4.7.21 dev ens33
```

![](images\2.png)

#### 2.1.2、下载软件、解压，做软连接

在所有node节点安装flannel插件，本次环境在hdss7-21，hdss7-22上：

```
cd /opt/src
#下载
wget https://github.com/coreos/flannel/releases/download/v0.11.0/flannel-v0.11.0-linux-amd64.tar.gz
#创建目录
mkdir /opt/flannel-v0.11.0
#解压
tar xf flannel-v0.11.0-linux-amd64.tar.gz -C /opt/flannel-v0.11.0/
#创建软链接
ln -s /opt/flannel-v0.11.0/ /opt/flannel
#创建证书目录
mkdir /opt/flannel/certs

```

#### 2.1.3、最终目录结构

#### 2.1.4、拷贝证书

HDSS7-21、HDSS7-22上

```
cd /opt/flannel/certs

scp hdss7-200:/opt/certs/ca.pem . 

scp hdss7-200:/opt/certs/client.pem .

scp hdss7-200:/opt/certs/client-key.pem .
```



#### 2.1.5、创建配置

```
vi /opt/flannel/subnet.env

#HDSS7-21配置

FLANNEL_NETWORK=172.7.0.0/16
FLANNEL_SUBNET=172.7.21.1/24
FLANNEL_MTU=1500
FLANNEL_IPMASQ=false

#HDSS7-22配置

FLANNEL_NETWORK=172.7.0.0/16
FLANNEL_SUBNET=172.7.22.1/24
FLANNEL_MTU=1500
FLANNEL_IPMASQ=false
```

#### 2.1.6、创建启动脚本

```
vi /opt/flannel/flanneld.sh 

#HDSS7-21配置

#!/bin/sh
./flanneld \
  --public-ip=10.4.7.21 \
  --etcd-endpoints=https://10.4.7.12:2379,https://10.4.7.21:2379,https://10.4.7.22:2379 \
  --etcd-keyfile=./certs/client-key.pem \
  --etcd-certfile=./certs/client.pem \
  --etcd-cafile=./certs/ca.pem \
  --iface=ens33 \
  --subnet-file=./subnet.env \
  --healthz-port=2401
  
  
#HDSS7-22配置

#!/bin/sh
./flanneld \
  --public-ip=10.4.7.22 \
  --etcd-endpoints=https://10.4.7.12:2379,https://10.4.7.21:2379,https://10.4.7.22:2379 \
  --etcd-keyfile=./certs/client-key.pem \
  --etcd-certfile=./certs/client.pem \
  --etcd-cafile=./certs/ca.pem \
  --iface=ens33 \
  --subnet-file=./subnet.env \
  --healthz-port=2401
```

#### 2.1.7、检查配置、权限，创建日志目录

```
#赋予权限
chmod +x /opt/flannel/flanneld.sh
#创建日志目录
mkdir -p /data/logs/flanneld

```



#### 2.1.8、创建supervisor配置

```
 vi /etc/supervisord.d/flannel.ini
 
 #HDSS7-21配置
 
[program:flanneld-7-21]
command=/opt/flannel/flanneld.sh                             ; the program (relative uses PATH, can take args)
numprocs=1                                                   ; number of processes copies to start (def 1)
directory=/opt/flannel                                       ; directory to cwd to before exec (def no cwd)
autostart=true                                               ; start at supervisord start (default: true)
autorestart=true                                             ; retstart at unexpected quit (default: true)
startsecs=30                                                 ; number of secs prog must stay running (def. 1)
startretries=3                                               ; max # of serial start failures (default 3)
exitcodes=0,2                                                ; 'expected' exit codes for process (default 0,2)
stopsignal=QUIT                                              ; signal used to kill process (default TERM)
stopwaitsecs=10                                              ; max num secs to wait b4 SIGKILL (default 10)
user=root                                                    ; setuid to this UNIX account to run the program
redirect_stderr=true                                         ; redirect proc stderr to stdout (default false)
stdout_logfile=/data/logs/flanneld/flanneld.stdout.log       ; stderr log path, NONE for none; default AUTO
stdout_logfile_maxbytes=64MB                                 ; max # logfile bytes b4 rotation (default 50MB)
stdout_logfile_backups=4                                     ; # of stdout logfile backups (default 10)
stdout_capture_maxbytes=1MB                                  ; number of bytes in 'capturemode' (default 0)
stdout_events_enabled=false                                  ; emit events on stdout writes (default false)



#HDSS7-22配置
 
[program:flanneld-7-22]
command=/opt/flannel/flanneld.sh                             ; the program (relative uses PATH, can take args)
numprocs=1                                                   ; number of processes copies to start (def 1)
directory=/opt/flannel                                       ; directory to cwd to before exec (def no cwd)
autostart=true                                               ; start at supervisord start (default: true)
autorestart=true                                             ; retstart at unexpected quit (default: true)
startsecs=30                                                 ; number of secs prog must stay running (def. 1)
startretries=3                                               ; max # of serial start failures (default 3)
exitcodes=0,2                                                ; 'expected' exit codes for process (default 0,2)
stopsignal=QUIT                                              ; signal used to kill process (default TERM)
stopwaitsecs=10                                              ; max num secs to wait b4 SIGKILL (default 10)
user=root                                                    ; setuid to this UNIX account to run the program
redirect_stderr=true                                         ; redirect proc stderr to stdout (default false)
stdout_logfile=/data/logs/flanneld/flanneld.stdout.log       ; stderr log path, NONE for none; default AUTO
stdout_logfile_maxbytes=64MB                                 ; max # logfile bytes b4 rotation (default 50MB)
stdout_logfile_backups=4                                     ; # of stdout logfile backups (default 10)
stdout_capture_maxbytes=1MB                                  ; number of bytes in 'capturemode' (default 0)
stdout_events_enabled=false                                  ; emit events on stdout writes (default false)
```



#### 2.1.9、操作etcd、增加host-gw

```

#在etcd中增加网络配置信息，只需在HDSS7-21或HDSS7-22上一台执行：
cd /opt/etcd
#测试使用 host-gw模型：
./etcdctl set /coreos.com/network/config '{"Network": "172.7.0.0/16", "Backend": {"Type": "host-gw"}}'
#查看网络模型配置：
./etcdctl get /coreos.com/network/config

```

**flannel其它模型**

- vxlan模型：

  可以发现多了一块网卡，这块网卡就是vxlan用于隧道通信的虚拟网卡：

  ```
  cd /opt/etcd
  ./etcdctl set /coreos.com/network/config  '{"Network": "172.7.0.0/16", "Backend": {"Type": "vxlan"}}'
  
  #重启flanneld：
  #hdss7-21上
  supervisorctl restart flanneld-7-21
  #hdss7-22上
  supervisorctl restart flanneld-7-22
  
  ```

  

- vxlan跟host-gw混合模型：

  当容器宿主机在同一网段路由时使用host-gw，不在同一网段路由时使用vxlan

  ```
  cd /opt/etcd
  ./etcdctl set /coreos.com/network/config  '{"Network": "172.7.0.0/16", "Backend": {"Type": "vxlan","Directrouting": true}}'
  #重启flanneld：
  #hdss7-21上
  supervisorctl restart flanneld-7-21
  #hdss7-22上
  supervisorctl restart flanneld-7-22
  
  ```



#### 2.1.10、启动服务并检查

```
#更新supervisor配置：
supervisorctl update

#查看服务启动状态
supervisorctl status
```



#### 2.1.11、安装部署启动检查所有集群规划

```
#查看服务启动状态
supervisorctl status
```



#### 2.1.12、再次验证集群，POD间网络互通

```
#查看pod
kubectl get pods -o wide
#进入pod内部
kubectl exec -it nginx-ds-nnj2h bash
#ping另个一个pod的IP
ping 172.7.21.2

```



#### 2.1.13、在各运行节点上优化iptables规划

hdss7-21、hdss7-22上

```
yum install iptables-services -y
#查看 postrouting
iptables-save |grep -i postrouting

#hdss7-21上
#删除postrouting
iptables -t nat -D POSTROUTING -s 172.7.21.0/24 ! -o docker0 -j MASQUERADE
增加postrouting
iptables -t nat -I POSTROUTING -s 172.7.21.0/24 ! -d 172.7.0.0/16 ! -o docker0 -j MASQUERADE
#保存iptables到文件
iptables-save > /etc/sysconfig/iptables


#hdss7-22上
#删除postrouting
iptables -t nat -D POSTROUTING -s 172.7.22.0/24 ! -o docker0 -j MASQUERADE
增加postrouting
iptables -t nat -I POSTROUTING -s 172.7.22.0/24 ! -d 172.7.0.0/16 ! -o docker0 -j MASQUERADE
#保存iptables到文件
iptables-save > /etc/sysconfig/iptables

#修改后会影响到docker原本的iptables链的规则，所以需要重启docker服务

systemctl restart docker
```

### 2.2、K8S的服务发现插件-CoreDNS

#### 2.2.1、部署K8S的内网资源配置清单http服务

​	在运维服务器hdss7-200上，配置nginx虚拟主机，提供k8s统一的资源配置清单访问入口

- 配置nginx

```
vi /etc/nginx/conf.d/k8s-yaml.od.com.conf

server {
    listen       80;
    server_name  k8s-yaml.od.com;

    location / {
        autoindex on;
        default_type text/plain;
        root /data/k8s-yaml;
    }
}

mkdir -p /data/k8s-yaml/coredns
mkdir -p /data/k8s-yaml/traefik
nginx -t
nginx -s reload
```

- 配置内网DNS

  在HDSS7-21上

```
vi /var/named/od.com.zone

修改序列号
                2020120803 ; serial 
#添加
k8s-yaml           A    10.4.7.200
```



#### 2.2.2、部署coredns

##### 2.2.2.1、准备coredns-v1.6.1镜像

在hdss7-200上部署coredns

```
cd /data/k8s-yaml/coredns

docker pull docker.io/coredns/coredns:1.6.1

#查找coredns镜像ID
docker images|grep coredns

docker tag c0f6e815079e harbor.od.com/public/coredns:v1.6.1

docker push harbor.od.com/public/coredns:v1.6.1
```

##### 2.2.2.2、准备资源配置清单

coredns官方资源配置清单样例地址：https://github.com/kubernetes/kubernetes/blob/master/cluster/addons/dns/coredns/coredns.yaml.base

在hdss7-200上

- rbac.yaml--拿到集群相关权限

```
vi /data/k8s-yaml/coredns/rbac.yaml


apiVersion: v1
kind: ServiceAccount
metadata:
  name: coredns
  namespace: kube-system
  labels:
      kubernetes.io/cluster-service: "true"
      addonmanager.kubernetes.io/mode: Reconcile
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    addonmanager.kubernetes.io/mode: Reconcile
  name: system:coredns
rules:
- apiGroups:
  - ""
  resources:
  - endpoints
  - services
  - pods
  - namespaces
  verbs:
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  annotations:
    rbac.authorization.kubernetes.io/autoupdate: "true"
  labels:
    kubernetes.io/bootstrapping: rbac-defaults
    addonmanager.kubernetes.io/mode: EnsureExists
  name: system:coredns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: system:coredns
subjects:
- kind: ServiceAccount
  name: coredns
  namespace: kube-system
```

- cm.yaml--configmap 对集群的相关配置

```
vi /data/k8s-yaml/coredns/cm.yaml


apiVersion: v1
kind: ConfigMap
metadata:
  name: coredns
  namespace: kube-system
data:
  Corefile: |
    .:53 {
        errors
        log
        health
        ready
        kubernetes cluster.local 192.168.0.0/16  #service资源cluster地址
        forward . 10.4.7.11   #上级DNS地址
        cache 30
        loop
        reload
        loadbalance
       }
```

- dp.yaml---pod控制器

```
vi /data/k8s-yaml/coredns/dp.yaml


apiVersion: apps/v1
kind: Deployment
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: coredns
    kubernetes.io/name: "CoreDNS"
spec:
  replicas: 1
  selector:
    matchLabels:
      k8s-app: coredns
  template:
    metadata:
      labels:
        k8s-app: coredns
    spec:
      priorityClassName: system-cluster-critical
      serviceAccountName: coredns
      containers:
      - name: coredns
        image: harbor.od.com/public/coredns:v1.6.1
        args:
        - -conf
        - /etc/coredns/Corefile
        volumeMounts:
        - name: config-volume
          mountPath: /etc/coredns
        ports:
        - containerPort: 53
          name: dns
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        - containerPort: 9153
          name: metrics
          protocol: TCP
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
            scheme: HTTP
          initialDelaySeconds: 60
          timeoutSeconds: 5
          successThreshold: 1
          failureThreshold: 5
      dnsPolicy: Default
      volumes:
        - name: config-volume
          configMap:
            name: coredns
            items:
            - key: Corefile
              path: Corefile
```

- svc.yaml---service资源

```
vi /data/k8s-yaml/coredns/svc.yaml

apiVersion: v1
kind: Service
metadata:
  name: coredns
  namespace: kube-system
  labels:
    k8s-app: coredns
    kubernetes.io/cluster-service: "true"
    kubernetes.io/name: "CoreDNS"
spec:
  selector:
    k8s-app: coredns
  clusterIP: 192.168.0.2
  ports:
  - name: dns
    port: 53
    protocol: UDP
  - name: dns-tcp
    port: 53
  - name: metrics
    port: 9153
    protocol: TCP
```



##### 2.2.2.3、依次执行创建

然后使用http请求资源配置清单yaml的方式来创建资源：在任意node节点上创建

```
kubectl create -f http://k8s-yaml.od.com/coredns/rbac.yaml
kubectl create -f http://k8s-yaml.od.com/coredns/cm.yaml
kubectl create -f http://k8s-yaml.od.com/coredns/dp.yaml
kubectl create -f http://k8s-yaml.od.com/coredns/svc.yaml
```

##### 2.2.2.4、检查

```
#查看kube-system命名空间下的所有资源
kubectl get all -n kube-system

#查看coredns的cluster ip
kubectl get svc -o wide -n kube-system

# 测试coredns
dig -t A www.baidu.com @192.168.0.2 +short

#测试coredns解析service资源名称，首先查看kube-public下是否有service资源，如果没有，创建一个，使用kubectl expose nginx-dp --port=80 -n kube-public

kubectl get svc -o wide -n kube-public

kubectl expose nginx-dp --port=80 -n kube-public

#使用coredns测试解析，需要使用SQDN规则
dig -t A nginx-dp.kube-public.svc.cluster.local. @192.168.0.2 +short
```

**大家可以看到，当我进入到pod内部以后，我们会发现我们的dns地址是我们的coredns地址，以及搜索域：**

```
[root@hdss7-21 ~]# kubectl get pod -o wide
NAME             READY   STATUS    RESTARTS   AGE    IP           NODE                NOMINATED NODE   READINESS GATES
nginx-ds-nnj2h   1/1     Running   3          2d7h   172.7.22.2   hdss7-22.host.com   <none>           <none>
nginx-ds-rm6wc   1/1     Running   2          2d7h   172.7.21.2   hdss7-21.host.com   <none>           <none>
[root@hdss7-21 ~]# kubectl exec -it nginx-ds-rm6wc bash
root@nginx-ds-rm6wc:/# cat /etc/resolv.conf
nameserver 192.168.0.2
search default.svc.cluster.local svc.cluster.local cluster.local host.com
options ndots:5
root@nginx-ds-rm6wc:/# 

```



### 2.3、K8S的服务暴露插件-Traefik

下面我们测试在集群外部解析：

```
[root@hdss7-21 ~]# curl nginx-dp.kube-public.svc.cluster.local.
curl: (6) Could not resolve host: nginx-dp.kube-public.svc.cluster.local.; 未知的错误

```

根本解析不到，因为我们外部用的dns是10.4.7.11，也就是我们的自建bind dns，这个DNS服务器上也没有响应的搜索域。

如何能让集群外部访问nginx-dp？

这里有两种服务暴露方式：修改工作模式，在kube-proxy中修改，并重启

1、使用nodeport方式，但是这种方式不能使用ipvs，只能使用iptables，iptables只能使用rr调度方式。原理相当于端口映射，将容器内的端口映射到宿主机上的某个端口。

2、使用ingress，但是只能工作在七层网络下，建议暴露http, https可以使用前端nginx来做证书方面的卸载 ---推荐使用

Ingress是基于域名和URL路径，将用户的请求转发至特定的service资源。

下面我们部署traefik：

[GITHUB官方地址]: https://github.com/containous/traefik

#### 2.3.1、下载镜像

```
docker pull traefik:v1.7.2-alpine
docker tag add5fac61ae5 harbor.od.com/public/traefik:v1.7.2
docker push harbor.od.com/public/traefik:v1.7.2
```

#### 2.3.2、创建资源配置清单

在hdss7-200上

```
mkdir -p /data/k8s-yaml/traefik
```



- rbac.yaml--拿到集群相关权限

```
vi /data/k8s-yaml/traefik/rbac.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  name: traefik-ingress-controller
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRole
metadata:
  name: traefik-ingress-controller
rules:
  - apiGroups:
      - ""
    resources:
      - services
      - endpoints
      - secrets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - extensions
    resources:
      - ingresses
    verbs:
      - get
      - list
      - watch
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1beta1
metadata:
  name: traefik-ingress-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: traefik-ingress-controller
subjects:
- kind: ServiceAccount
  name: traefik-ingress-controller
  namespace: kube-system
```

- ds.yaml--configmap 对集群的相关配置

```
vi /data/k8s-yaml/traefik/ds.yaml

apiVersion: extensions/v1beta1
kind: DaemonSet
metadata:
  name: traefik-ingress
  namespace: kube-system
  labels:
    k8s-app: traefik-ingress
spec:
  template:
    metadata:
      labels:
        k8s-app: traefik-ingress
        name: traefik-ingress
    spec:
      serviceAccountName: traefik-ingress-controller
      terminationGracePeriodSeconds: 60
      containers:
      - image: harbor.od.com/public/traefik:v1.7.2
        name: traefik-ingress
        ports:
        - name: controller
          containerPort: 80
          hostPort: 81
        - name: admin-web
          containerPort: 8080
        securityContext:
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        args:
        - --api
        - --kubernetes
        - --logLevel=INFO
        - --insecureskipverify=true
        - --kubernetes.endpoint=https://10.4.7.10:7443
        - --accesslog
        - --accesslog.filepath=/var/log/traefik_access.log
        - --traefiklog
        - --traefiklog.filepath=/var/log/traefik.log
        - --metrics.prometheus
```

- svc.yaml---service资源

```
vi /data/k8s-yaml/traefik/svc.yaml

kind: Service
apiVersion: v1
metadata:
  name: traefik-ingress-service
  namespace: kube-system
spec:
  selector:
    k8s-app: traefik-ingress
  ports:
    - protocol: TCP
      port: 80
      name: controller
    - protocol: TCP
      port: 8080
      name: admin-web
```

- ingress.yaml

```
vi /data/k8s-yaml/traefik/ingress.yaml

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: traefik-web-ui
  namespace: kube-system
  annotations:
    kubernetes.io/ingress.class: traefik
spec:
  rules:
  - host: traefik.od.com
    http:
      paths:
      - path: /
        backend:
          serviceName: traefik-ingress-service
          servicePort: 8080
```

#### 2.3.3、依次执行创建

然后使用http请求资源配置清单yaml的方式来创建资源：在任意node节点上创建

```
kubectl create -f http://k8s-yaml.od.com/traefik/rbac.yaml
kubectl create -f http://k8s-yaml.od.com/traefik/ds.yaml
kubectl create -f http://k8s-yaml.od.com/traefik/svc.yaml
kubectl create -f http://k8s-yaml.od.com/traefik/ingress.yaml
```

#### 2.3.4、配置DNS

在hdss7-11、hdss7-12上

```
vi /etc/nginx/conf.d/od.com.conf

upstream default_backend_traefik {
    server 10.4.7.21:81    max_fails=3 fail_timeout=10s;
    server 10.4.7.22:81    max_fails=3 fail_timeout=10s;
}
server {
    server_name *.od.com;
  
    location / {
        proxy_pass http://default_backend_traefik;
        proxy_set_header Host       $http_host;
        proxy_set_header x-forwarded-for $proxy_add_x_forwarded_for;
    }
}


#重启nginx
nginx -t
nginx -s reload
```

#### 2.3.4、增加域名解析

hdss7-11上

```
vi /var/named/od.com.zone

修改序列号
                2020120804 ; serial 
 #添加
traefik            A    10.4.7.10


#重启
systemctl restart named
```

#### 2.3.5、检查

```
#查看kube-system命名空间下的所有资源
kubectl get all -n kube-system

#查看traefik-ingress的cluster ip
kubectl get svc -o wide -n kube-system

#查看宿主机81端口是否被监听
netstat -antup|grep 81

#然后我们就可以在集群外，通过浏览器访问这个域名了：

http://traefik.od.com  
#我们的宿主机的虚拟网卡指定了bind域名解析服务器
```



### 2.4、K8S的GUI资源管理插件插件-仪表盘

[GITHUB官方地址]: https://github.com/kubernetes/dashboard

#### 2.4.1、下载镜像

hdss7-200上

```
docker pull k8scn/kubernetes-dashboard-amd64:v1.8.3
docker tag fcac9aa03fd6 harbor.od.com/public/dashboard:v1.8.3
docker push harbor.od.com/public/dashboard:v1.8.3
```

#### 2.4.2、创建资源配置清单

在hdss7-200上

```
mkdir -p /data/k8s-yaml/dashboard
```



- rbac.yaml--拿到集群相关权限

```
vi /data/k8s-yaml/dashboard/rbac.yaml

apiVersion: v1
kind: ServiceAccount
metadata:
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: Reconcile
  name: kubernetes-dashboard-admin
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubernetes-dashboard-admin
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
    addonmanager.kubernetes.io/mode: Reconcile
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: kubernetes-dashboard-admin
  namespace: kube-system
```

- dp.yaml--deployment资源

```
vi /data/k8s-yaml/dashboard/dp.yaml

apiVersion: apps/v1
kind: Deployment
metadata:
  name: kubernetes-dashboard
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  selector:
    matchLabels:
      k8s-app: kubernetes-dashboard
  template:
    metadata:
      labels:
        k8s-app: kubernetes-dashboard
      annotations:
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      priorityClassName: system-cluster-critical
      containers:
      - name: kubernetes-dashboard
        image: harbor.od.com/public/dashboard:v1.8.3
        resources:
          limits:
            cpu: 100m
            memory: 300Mi
          requests:
            cpu: 50m
            memory: 100Mi
        ports:
        - containerPort: 8443
          protocol: TCP
        args:
          # PLATFORM-SPECIFIC ARGS HERE
          - --auto-generate-certificates
        volumeMounts:
        - name: tmp-volume
          mountPath: /tmp
        livenessProbe:
          httpGet:
            scheme: HTTPS
            path: /
            port: 8443
          initialDelaySeconds: 30
          timeoutSeconds: 30
      volumes:
      - name: tmp-volume
        emptyDir: {}
      serviceAccountName: kubernetes-dashboard-admin
      tolerations:
      - key: "CriticalAddonsOnly"
        operator: "Exists"
```

- svc.yaml---service资源

```
vi /data/k8s-yaml/dashboard/svc.yaml

apiVersion: v1
kind: Service
metadata:
  name: kubernetes-dashboard
  namespace: kube-system
  labels:
    k8s-app: kubernetes-dashboard
    kubernetes.io/cluster-service: "true"
    addonmanager.kubernetes.io/mode: Reconcile
spec:
  selector:
    k8s-app: kubernetes-dashboard
  ports:
  - port: 443
    targetPort: 8443
```

- ingress.yaml

```
vi /data/k8s-yaml/dashboard/ingress.yaml

apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: kubernetes-dashboard
  namespace: kube-system
  annotations:
    kubernetes.io/ingress.class: traefik
spec:
  rules:
  - host: dashboard.od.com
    http:
      paths:
      - backend:
          serviceName: kubernetes-dashboard
          servicePort: 443
```

#### 2.4.3、依次执行创建

然后使用http请求资源配置清单yaml的方式来创建资源：在任意node节点上创建

```
kubectl create -f http://k8s-yaml.od.com/dashboard/rbac.yaml
kubectl create -f http://k8s-yaml.od.com/dashboard/dp.yaml
kubectl create -f http://k8s-yaml.od.com/dashboard/svc.yaml
kubectl create -f http://k8s-yaml.od.com/dashboard/ingress.yaml
```

#### 2.3.4、增加域名解析

hdss7-11上

```
vi /var/named/od.com.zone

修改序列号
                2020120805 ; serial 
 #添加
dashboard          A    10.4.7.10

#重启
systemctl restart named
```

#### 2.3.5、检查

```
#查看kube-system命名空间下的所有资源
kubectl get all -n kube-system

#查看service资源
kubectl get svc -o wide -n kube-system

#查看ingress资源
kubectl get ingress -o wide -n kube-system
#然后我们就可以在集群外，通过浏览器访问这个域名了：

http://dashboard.od.com  
#我们的宿主机的虚拟网卡指定了bind域名解析服务器
```

#### 2.3.6、修改dashbard版本

我们安装1.8版本的dashboard，默认是可以跳过验证的，显然，跳过登录，是不科学的，因为我们在配置dashboard的rbac权限时，绑定的角色是system:admin，这个是集群管理员的角色，权限很大，所以这里我们把版本换成1.10以上版本

hdss7-200上

```
docker pull loveone/kubernetes-dashboard-amd64:v1.10.1
docker tag f9aed6605b81 harbor.od.com/public/dashboard:v1.10.1
docker push harbor.od.com/public/dashboard:v1.10.1

vi /data/k8s-yaml/dashboard/dp.yaml
#修改dashboard的版本为v1.10.1
kubectl apply -f http://k8s-yaml.od.com/dashboard/dp.yaml

```

#### 2.3.7、获取token

```
kubectl get secret  -n kube-system
```

> NAME                                     TYPE                                  DATA   AGE
> coredns-token-vfvdt                      kubernetes.io/service-account-token   3      3d13h
> default-token-jg9lw                      kubernetes.io/service-account-token   3      6d19h
> kubernetes-dashboard-admin-token-wx6vq   kubernetes.io/service-account-token   3      2d13h
> kubernetes-dashboard-key-holder          Opaque                                2      2d13h
> traefik-ingress-controller-token-psfl7   kubernetes.io/service-account-token   3      2d16h

```
#查看token
kubectl describe secret kubernetes-dashboard-admin-token-wx6vq -n kube-system
```

> Name:         kubernetes-dashboard-admin-token-wx6vq
> Namespace:    kube-system
> Labels:       <none>
> Annotations:  kubernetes.io/service-account.name: kubernetes-dashboard-admin
>               kubernetes.io/service-account.uid: 1150a27e-f439-4ce3-8c14-6d4fed41832f
>
> Type:  kubernetes.io/service-account-token
>
> Data
> ====
> ca.crt:     1338 bytes
> namespace:  11 bytes
> token:      eyJhbGciOiJSUzI1NiIsImtpZCI6IiJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VjcmV0Lm5hbWUiOiJrdWJlcm5ldGVzLWRhc2hib2FyZC1hZG1pbi10b2tlbi13eDZ2cSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJrdWJlcm5ldGVzLWRhc2hib2FyZC1hZG1pbiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjExNTBhMjdlLWY0MzktNGNlMy04YzE0LTZkNGZlZDQxODMyZiIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLXN5c3RlbTprdWJlcm5ldGVzLWRhc2hib2FyZC1hZG1pbiJ9.r0BuBoT7tBq6pIxo8TbbulNITmJVpn8Z9-jPw6jzrn-9mUsu4HcxEkejlLY9KBvPvCujx2V6pVpue70jqtOnOZtxCAUAsdZaBgJg6jrzUKVrx7NTqqJiVdpBCgpkQ_fP-yyrU2nAB-Uy87ix_o1frYUEVUi-RcTTDh-1FGbm3bupNG6ItVpWfFY-bxhizlSnreTvT1XOfA2R1FCqhMyBgMN1vMne1XjKyWuLbw-gOOUb-QLzX1q6sqTygBNX62S17XRrpT8NM1Qza7gAlNRQOSkbi1_0w4o7CbsHgGkvxGqXI_ml9UtZQcj2WTdRt_3UtqFuVQ0Yc1UwHLXt9_S-aQ

#### 2.3.8、申请证书

hdss7-200上

```
cd /opt/certs/
vi dashboard-csr.json


{
    "CN": "*.od.com",
    "hosts": [
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "beijing",
            "L": "beijing",
            "O": "od",
            "OU": "ops"
        }
    ]
}


#生成证书
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=server dashboard-csr.json |cfssl-json -bare dashboard
```



#### 2.3.9、配置nginx

hdss7-11 、hdss7-12上

```
cd /etc/nginx/
mkdir certs
cd certs
scp hdss7-200:/opt/certs/dash* ./


cd /etc/nginx/conf.d/
vi dashboard.od.com.conf

server {
    listen       80;
    server_name  dashboard.od.com;

    rewrite ^(.*)$ https://${server_name}$1 permanent;
}
server {
    listen       443 ssl;
    server_name  dashboard.od.com;

    ssl_certificate "certs/dashboard.pem";
    ssl_certificate_key "certs/dashboard-key.pem";
    ssl_session_cache shared:SSL:1m;
    ssl_session_timeout  10m;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    location / {
        proxy_pass http://default_backend_traefik;
        proxy_set_header Host       $http_host;
        proxy_set_header x-forwarded-for $proxy_add_x_forwarded_for;
    }
}

#检查nginx配置
nginx -t
#重启nginx
nginx -s reload

```

### 2.5、K8S平滑升级

#### 2.5.1、修改nginx配置

hdss7-11.hdss7-12上，在nginx上摘除api-server的四层负载

```
vi /etc/nginx/nginx.conf
修改：
#        server 10.4.7.21:6443     max_fails=3 fail_timeout=30s;


#检查nginx配置
nginx -t
#重启nginx
nginx -s reload

```

#### 2.5.2、摘除节点

Hdss7-21上

```
kubectl delete node hdss7-21.host.com
#查看节点信息
kubectl get pod -o wide -n kube-system

```

#### 2.5.3、升级dashboard

HDSS7-200上

```
docker pull kubernetesui/dashboard:v2.0.5
docker tag fd110d63b15b harbor.od.com/public/dashboard:v2.0.5
docker push harbor.od.com/public/dashboard:v2.0.5
```

#### 2.5.4、升级kubernetes

hdss7-21上

```
mkdir -p /opt/v1.19.6
cd /opt/src
tar xfv kubernetes-server-linux-amd64.tar_2-v.1.19.6.gz -C /opt/v1.19.6

mv /opt/v1.19.6/kubernetes /opt/kubernetes-v1.19.6

#删除源码包
cd /opt/kubernetes-v1.19.6
rm -fr kubernetes-src.tar.gz

#删除镜像包
cd /opt/kubernetes-v1.19.6/server/bin
rm -f *.tar
rm -f *_tag

#创建文件夹
mkdir -p /opt/kubernetes-v1.19.6/server/bin/certs
cd /opt/kubernetes-v1.19.6/server/bin/certs/

#拷贝证书：
cp /opt/kubernetes-v1.15.5/server/bin/certs/* .

#拷贝k8s启动配置文件
mkdir -p /opt/kubernetes-v1.19.6/server/bin/conf
cp /opt/kubernetes-v1.15.5/server/bin/conf/* /opt/kubernetes-v1.19.6/server/bin/conf
      
#拷贝启动脚本
cp /opt/kubernetes-v1.15.5/server/bin/*.sh /opt/kubernetes-v1.19.6/server/bin/

```

#### 2.5.5、更换软连接

```
rm -rf /opt/kubernetes
ln -s /opt/kubernetes-v1.19.6 /opt/kubernetes

#关闭服务
supervisorctl stop all
#查看2401端口和8080端口占用情况
netstat -lnp|grep 2401
netstat -lnp|grep 8080

#关闭占用的进程
kill -9 10569

#重启服务
supervisorctl start all
#查看
supervisorctl status
```


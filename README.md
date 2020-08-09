### 访问地址 `https://github.com/chenfei1990/k8s-deploy/blob/master/README.md`
# `服务器准备操作`
## 1.设置root用户登陆
> *root*用户登录
+ 设置*root*密码,按提示输入两次密码即可
```
passwd root
```
+ 修改配置文件 */etc/ssh/sshd_config*
```bash
#PermitRootLogin prohibit-password #注释掉
PermitRootLogin yes #添加新行
```
+ 重启ssh服务，然后重新登陆。后面操作均在root用户下执行
```
service ssh restart
```
## 2.服务器时间同步
> 源更新
```
apt-get update
```
> 时钟同步
```
apt-get install ntpdate
ntpdate cn.pool.ntp.org
hwclock --systohc
```
## 3.禁用SELinux，防火墙（ubuntu不需要）
```
ufw status
# Status: inactive 表示并防火墙没有开启
sestatus
# The program 'sestatus' is currently not installed.  表示selinux没有安装
```
## 4.设置主机名称
```
# 1. 设置hostname
hostnamectl set-hostname k8s-master1
# 2.修改host文件
vim /etc/hosts
```
# ubuntu系统安装 `Docker`
>安装
+ 依赖安装
```
apt-get  install -y libltdl7
# 出错装
apt-get install -y libltdl7 libseccomp2
```
+ `docker-ce`安装
```
dpkg -i docker-ce_18.06.1~ce~3-0~ubuntu_amd64.deb
```
> `docker`配置修改
+ 配置文件 */etc/docker/daemon.json*
```json
{
    "graph":"/opt/docker",
    "storage-driver":"overlay2",
    "storage-opts":[
        "overlay2.override_kernel_check=true"
    ],
    "live-restore":false,
    "insecure-registries":[
        "minikube:5777"
    ]
}
```
+ 创建存储目录
```
mkdir -p /opt/docker
```
+ 重启`docker`守护进程
```
systemctl restart docker.service
```
+ 查看docker状态
```
docker ps
```
![Image text](https://raw.githubusercontent.com/chenfei1990/k8s-deploy/master/mdimgs/docker_ps.png)
# `K8s-etcd` 集群部署
## 1.使用cfssl来生成自签证书
```
cd ./tool/cfssl
chmod +x cfssl*
mv cfssl_linux-amd64 /usr/local/bin/cfssl
mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
mv cfssl-certinfo_linux-amd64 /usr/local/bin/cfssl-certinfo
```
## 2.在*tool/etcd-cert*目录下建立以下三个
> `ca-config.json`
```json
  {
      "signing": {
          "default": {
          "expiry": "175200h"
          },
          "profiles": {
          "www": {
              "expiry": "175200h",
              "usages": [
                  "signing",
                  "key encipherment",
                  "server auth",
                  "client auth"
              ]
          }
          }
      }
  }
```
> `ca-csr.json`
```json
  {
      "CN": "etcd CA",
      "key": {
          "algo": "rsa",
          "size": 2048
      },
      "names": [
          {
              "C": "CN",
              "L": "Beijing",
              "ST": "Beijing"
          }
      ]
  }

```
> `server-csr.json` host节点是三个etcd机器ip
```json
{
  "CN": "etcd",
  "hosts": [
  "192.168.77.10",
  "192.168.77.11",
  "192.168.78.15"
  ],
  "key": {
      "algo": "rsa",
      "size": 2048
  },
  "names": [
      {
          "C": "CN",
          "L": "BeiJing",
          "ST": "BeiJing"
      }
  ]
}
```
## 3.生成证书：
```
cd tool/etcd-cert/
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=www server-csr.json | cfssljson -bare server
```
## 4.创建`etcd`工作目录，解压`etcd-v3.3.10-linux-amd64.tar.gz`文件并移动至`/opt/etcd/bin`
```
mkdir /opt/etcd/{bin,cfg,ssl} -p
tar zxvf etcd-v3.3.10-linux-amd64.tar.gz
mv etcd-v3.3.10-linux-amd64/{etcd,etcdctl} /opt/etcd/bin/
```
## 5.创建etcd配置文件 */opt/etcd/cfg/etcd*
```bash
#[Member]
ETCD_NAME="etcd01"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://192.168.77.10:2380"
ETCD_LISTEN_CLIENT_URLS="https://192.168.77.10:2379"

#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.77.10:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.77.10:2379"
ETCD_INITIAL_CLUSTER="etcd01=https://192.168.77.10:2380,etcd02=https://192.168.77.11:2380,etcd03=https://192.168.78.15:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
```
## 6.systemd管理etcd 创建配置 */lib/systemd/system/etcd.service*
```bash
[Unit]
Description=Etcd Server
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=/opt/etcd/cfg/etcd
ExecStart=/opt/etcd/bin/etcd --name=${ETCD_NAME} --data-dir=${ETCD_DATA_DIR} --listen-peer-urls=${ETCD_LISTEN_PEER_URLS} --listen-client-urls=${ETCD_LISTEN_CLIENT_URLS},http://127.0.0.1:2379 --advertise-client-urls=${ETCD_ADVERTISE_CLIENT_URLS} --initial-advertise-peer-urls=${ETCD_INITIAL_ADVERTISE_PEER_URLS} --initial-cluster=${ETCD_INITIAL_CLUSTER} --initial-cluster-token=${ETCD_INITIAL_CLUSTER_TOKEN} --initial-cluster-state=new --cert-file=/opt/etcd/ssl/server.pem --key-file=/opt/etcd/ssl/server-key.pem --peer-cert-file=/opt/etcd/ssl/server.pem --peer-key-file=/opt/etcd/ssl/server-key.pem --trusted-ca-file=/opt/etcd/ssl/ca.pem --peer-trusted-ca-file=/opt/etcd/ssl/ca.pem
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```
## 7.证书拷贝到配置文件中的位置：
```
cp ./tools/etcd-cert/{ca,server-key,server}.pem  /opt/etcd/ssl/
```
## 8.将 */opt/etcd/* 目录中所有文件以及 */lib/systemd/system/etcd.service* 文件拷贝另外机器上
```
scp -r /opt/etcd/ root@192.168.77.11:/opt/
scp -r /opt/etcd/ root@192.168.78.15:/opt/

scp /lib/systemd/system/etcd.service root@192.168.77.11:/lib/systemd/system/etcd.service
scp /lib/systemd/system/etcd.service root@192.168.78.15:/lib/systemd/system/etcd.service
```
## 9.修改各个机器的 */opt/etcd/cfg/etcd* 中对应机器的ip; 启动etcd ,每个etcd机器都需要执行
```
systemctl  daemon-reload
systemctl enable etcd
systemctl start etcd
```
## 10.验证集群状态
```
/opt/etcd/bin/etcdctl \
--ca-file=/opt/etcd/ssl/ca.pem --cert-file=/opt/etcd/ssl/server.pem --key-file=/opt/etcd/ssl/server-key.pem \
--endpoints="https://192.168.77.10:2379,https://192.168.77.11:2379,https://192.168.78.15:2379" \
cluster-health
``` 
![Image text](./mdimgs/etcd_healthy.png)
# `centos docker`
+ 使用二进制包部署 *docker-18.06.1-ce.tgz*
```
tar zxvf docker-18.06.1-ce.tgz
mv docker/* /usr/bin
mkdir /etc/docker
systemctl  daemon-reload
systemctl start docker
systemctl enable docker
```
+ 添加 `/etc/docker/daemon.json` 文件
```json
{"registry-mirrors": ["http://f1361db2.m.daocloud.io"]
,"insecure-registries": ["K8SMaster02:5777"]}
```
+ 添加 `/usr/lib/systemd/system/docker.service` 文件
```bash
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service containerd.service
Wants=network-online.target

[Service]
Type=notify
#EnvironmentFile=/run/flannel/subnet.env
ExecStart=/usr/bin/dockerd #$DOCKER_NETWORK_OPTIONS
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
TimeoutStartSec=0
Delegate=yes
KillMode=process
Restart=on-failure
StartLimitBurst=3
StartLimitInterval=60s

[Install]
WantedBy=multi-user.target
```
+ 其他node机器部署docker  先执行 `mkdir /etc/docker`
```
scp docker-18.06.1-ce.tgz root@K8SNode01:/root
scp /usr/lib/systemd/system/docker.service root@K8SNode01:/usr/lib/systemd/system/docker.service
scp /etc/docker/daemon.json root@K8SNode01:/etc/docker/daemon.json
```
+ node机器执行
```
tar zxvf docker-18.06.1-ce.tgz
mv docker/* /usr/bin
systemctl  daemon-reload
systemctl enable docker
systemctl start docker
```

# 部署`Flannel`至node节点
## 1.Falnnel要用etcd存储自身一个子网信息，所以要保证能成功连接Etcd，写入预定义子网段：
```
/opt/etcd/bin/etcdctl \
--ca-file=/opt/etcd/ssl/ca.pem --cert-file=/opt/etcd/ssl/server.pem --key-file=/opt/etcd/ssl/server-key.pem \
--endpoints="https://192.168.77.10:2379,https://192.168.77.11:2379,https://192.168.78.15:2379" \
set /coreos.com/network/config  '{ "Network": "172.17.0.0/16", "Backend": {"Type": "vxlan"}}'
```
## 2.安装flannel
```
tar zxvf flannel-v0.10.0-linux-amd64.tar.gz
mkdir /opt/kubernetes/{cfg,bin,ssl} -p
mv flanneld mk-docker-opts.sh /opt/kubernetes/bin
```
+ flanneld配置文件 */opt/kubernetes/cfg/flanneld*
```sh
FLANNEL_OPTIONS="--etcd-endpoints=https://192.168.77.10:2379,https://192.168.77.11:2379,https://192.168.78.15:2379 -etcd-cafile=/opt/etcd/ssl/ca.pem -etcd-certfile=/opt/etcd/ssl/server.pem -etcd-keyfile=/opt/etcd/ssl/server-key.pem"
```
+ systemd管理Flannel配置文件 */lib/systemd/system/flanneld.service*
```sh
[Unit]
Description=Flanneld overlay address etcd agent
After=network-online.target network.target
Before=docker.service

[Service]
Type=notify
EnvironmentFile=/opt/kubernetes/cfg/flanneld
ExecStart=/opt/kubernetes/bin/flanneld --ip-masq $FLANNEL_OPTIONS
ExecStartPost=/opt/kubernetes/bin/mk-docker-opts.sh -k DOCKER_NETWORK_OPTIONS -d /run/flannel/subnet.env
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
+ */lib/systemd/system/docker.service* 文件修改取消  `#$DOCKER_NETWORK_OPTIONS #EnvironmentFile=/run/flannel/subnet.env` 注释

+ 启动flanneld
```
systemctl daemon-reload
systemctl enable flanneld
systemctl restart flanneld
```
+ 重启docker 
```
systemctl restart docker
```
## 3.拷贝至其他node节点
```
scp /opt/kubernetes/bin/flanneld  /opt/kubernetes/bin/mk-docker-opts.sh   root@192.168.78.15:/opt/kubernetes/bin
scp /usr/lib/systemd/system/docker.service root@192.168.78.15:/usr/lib/systemd/system/docker.service
scp /opt/kubernetes/cfg/flanneld root@192.168.78.15:/opt/kubernetes/cfg/flanneld
scp /usr/lib/systemd/system/flanneld.service root@192.168.78.15:/usr/lib/systemd/system/flanneld.service
systemctl daemon-reload
systemctl enable flanneld
systemctl restart flanneld
systemctl restart docker
```
+ 查看规则 
```
/opt/etcd/bin/etcdctl \
--ca-file=/opt/etcd/ssl/ca.pem --cert-file=/opt/etcd/ssl/server.pem --key-file=/opt/etcd/ssl/server-key.pem \
--endpoints="https://192.168.77.10:2379,https://192.168.77.11:2379,https://192.168.78.15:2379" \
ls /coreos.com/network/subnets
```
## 4.docker网络一定要互通 
```

```
# `master部署`
## 1.制作证书
+ 生成apiserver证书:
> ca-config.json
```json
{
  "signing": {
    "default": {
      "expiry": "175200h"
    },
    "profiles": {
      "kubernetes": {
         "expiry": "175200h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
```
> ca-csr.json
```json
{
    "CN": "kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Beijing",
            "ST": "Beijing",
      	    "O": "k8s",
            "OU": "System"
        }
    ]
}
```
> server-csr.json 里面的ip为masterip 可以多预留
```json
{
    "CN": "kubernetes",
    "hosts": [
      "10.0.0.1",
      "127.0.0.1",
      "192.168.77.10",
      "192.168.77.9",
      "192.168.77.8",
      "10.192.5.41",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "BeiJing",
            "ST": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
```

```
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes server-csr.json | cfssljson -bare server
```
> `kube-proxy-csr.json`
```json
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "BeiJing",
      "ST": "BeiJing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
```
+ 生成kube-proxy证书：
```
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
```
+ 一共生了以下证书：
```
ca-key.pem  ca.pem  kube-proxy-key.pem  kube-proxy.pem  server-key.pem  server.pem
```
## 2.部署`apiserver`组件
```
mkdir /opt/kubernetes/{bin,cfg,ssl} -p
chmod 755 kube*
cp kube-apiserver kube-scheduler kube-controller-manager kubectl /opt/kubernetes/bin
```
+ 创建token文件 */opt/kubernetes/cfg/token.csv* ，用途后面会讲到:
```
e49457683ec34b3f9ff87090d3c6aafd,kubelet-bootstrap,10001,"system:kubelet-bootstrap"
```
+ 创建apiserver配置文件：
> `/opt/kubernetes/cfg/kube-apiserver`
```sh
KUBE_APISERVER_OPTS="--logtostderr=false \
--log-dir=/opt/kubernetes/logs \
--v=4 \
--etcd-servers=https://192.168.77.10:2379,https://192.168.77.11:2379,https://192.168.78.15:2379 \
--bind-address=192.168.77.10 \
--secure-port=6443 \
--advertise-address=192.168.77.10 \
--allow-privileged=true \
--service-cluster-ip-range=10.0.0.0/24 \
--enable-admission-plugins=NamespaceLifecycle,LimitRanger,ServiceAccount,ResourceQuota,NodeRestriction \
--authorization-mode=RBAC,Node \
--kubelet-https=true \
--enable-bootstrap-token-auth \
--token-auth-file=/opt/kubernetes/cfg/token.csv \
--service-node-port-range=30000-50000 \
--tls-cert-file=/opt/kubernetes/ssl/server.pem  \
--tls-private-key-file=/opt/kubernetes/ssl/server-key.pem \
--client-ca-file=/opt/kubernetes/ssl/ca.pem \
--service-account-key-file=/opt/kubernetes/ssl/ca-key.pem \
--etcd-cafile=/opt/etcd/ssl/ca.pem \
--etcd-certfile=/opt/etcd/ssl/server.pem \
--etcd-keyfile=/opt/etcd/ssl/server-key.pem"
```
> `/lib/systemd/system/kube-apiserver.service`
```sh
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/opt/kubernetes/cfg/kube-apiserver
ExecStart=/opt/kubernetes/bin/kube-apiserver $KUBE_APISERVER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
## 3.启动`apiserver`
```
mkdir /opt/kubernetes/logs
cp ca-key.pem  ca.pem  server-key.pem  server.pem   /opt/kubernetes/ssl/
systemctl daemon-reload
systemctl enable kube-apiserver
systemctl restart kube-apiserver
```
## 4.部署scheduler组件
> `/opt/kubernetes/cfg/kube-scheduler`
```sh
KUBE_SCHEDULER_OPTS="--logtostderr=false \
--log-dir=/opt/kubernetes/logs \
--v=4 \
--master=127.0.0.1:8080 \
--leader-elect"
```
> `/lib/systemd/system/kube-scheduler.service`
```sh
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/opt/kubernetes/cfg/kube-scheduler
ExecStart=/opt/kubernetes/bin/kube-scheduler $KUBE_SCHEDULER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
## 5.启动`Scheduler`
```
systemctl daemon-reload
systemctl enable kube-scheduler
systemctl restart kube-scheduler
```
## 6.部署`controller-manager`组件
> `/opt/kubernetes/cfg/kube-controller-manager`
```sh
KUBE_CONTROLLER_MANAGER_OPTS="--logtostderr=false \
--log-dir=/opt/kubernetes/logs \
--v=4 \
--master=127.0.0.1:8080 \
--leader-elect=true \
--address=127.0.0.1 \
--service-cluster-ip-range=10.0.0.0/24 \
--cluster-name=kubernetes \
--cluster-signing-cert-file=/opt/kubernetes/ssl/ca.pem \
--cluster-signing-key-file=/opt/kubernetes/ssl/ca-key.pem  \
--root-ca-file=/opt/kubernetes/ssl/ca.pem \
--service-account-private-key-file=/opt/kubernetes/ssl/ca-key.pem \
--experimental-cluster-signing-duration=175200h0m0s"
```
> `/lib/systemd/system/kube-controller-manager.service`
```sh
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/opt/kubernetes/cfg/kube-controller-manager
ExecStart=/opt/kubernetes/bin/kube-controller-manager $KUBE_CONTROLLER_MANAGER_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
## 7.启动`kube-controller-manager`
```
systemctl daemon-reload
systemctl enable kube-controller-manager
systemctl restart kube-controller-manager
mv /opt/kubernetes/bin/kubectl /usr/local/bin/
kubectl get cs
```
# `多master部署`
```
# 在master2生成文件夹
mkdir /opt/kubernetes/{bin,cfg,ssl} -p
mkdir /opt/kubernetes/logs
mkdir /opt/etcd

scp -r /opt/kubernetes/ root@K8SMaster02:/opt/
scp -r /opt/etcd/ssl/ root@K8SMaster02:/opt/etcd/ssl/
scp /usr/lib/systemd/system/kube-apiserver.service root@K8SMaster02:/usr/lib/systemd/system/kube-apiserver.service
scp /usr/lib/systemd/system/kube-scheduler.service root@K8SMaster02:/usr/lib/systemd/system/kube-scheduler.service
scp /usr/lib/systemd/system/kube-controller-manager.service root@K8SMaster02:/usr/lib/systemd/system/kube-controller-manager.service
scp /usr/local/bin/kubectl root@K8SMaster02:/usr/local/bin/kubectl
# 修改/opt/kubernetes/cfg/kube-apiserver 中的 ip

systemctl daemon-reload
systemctl enable kube-apiserver
systemctl restart kube-apiserver
systemctl enable kube-scheduler
systemctl restart kube-scheduler
systemctl enable kube-controller-manager
systemctl restart kube-controller-manager
kubectl get cs
```
# `多master nginx 部署`

> nginx安装

```

apt-get install -y  libpcre3 libpcre3-dev  zlib1g-dev  build-essential libssl-dev

# yum install -y  gcc gcc-c++ make pcre pcre-devel zlib zlib-devel openssl openssl-devel

tar -zxvf nginx-1.16.1.tar.gz

useradd -M -s /sbin/nologin nginx

cd nginx-1.16.1/

./configure --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module --with-stream

make && make install

/usr/local/nginx/sbin/nginx  -V

systemctl daemon-reload

systemctl enable nginx

systemctl start nginx

```
> `/lib/systemd/system/nginx.service`
```
[Unit]
Description=nginx
After=network.target

[Service]
Type=forking
ExecStart=/usr/local/nginx/sbin/nginx
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/usr/local/nginx/sbin/nginx -s quit
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```
> 4层负载 在http外面加一个stream
```nginx
stream {
   log_format  main  '$remote_addr $upstream_addr - [$time_local] $status $upstream_bytes_sent';
    access_log  /var/log/nginx/k8s-access.log  main;

    upstream k8s-apiserver {
        server 192.168.56.11:6443;
        server 192.168.56.14:6443;
    }
    server {
                listen 8443;
                proxy_pass k8s-apiserver;
    }
    }
```
> `keepalived`配置
```
apt-get install -y keepalived
#主

global_defs {
    router_id LVS_MASTER
}

vrrp_script check_apiserver {
    script "curl -o /dev/null -s -w %{http_code} -k  https://192.168.6.131:8443"
    interval 3
    timeout 3
    fall 2
    rise 2
}

vrrp_instance VI_1 {
    state SLAVE
    interface ens32
    virtual_router_id 88
    priority 50
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass k8s
    }
    virtual_ipaddress {
        192.168.6.129/24
    }
    track_script {
        check_apiserver
    }
}


#备

global_defs {
    router_id LVS_MASTER
}

vrrp_script check_apiserver {
    script "curl -o /dev/null -s -w %{http_code} -k  https://192.168.6.130:8443"
    interval 3
    timeout 3
    fall 2
    rise 2
}

vrrp_instance VI_1 {
    state MASTER
    interface ens32
    virtual_router_id 88
    priority 100
    advert_int 1
    authentication {
        auth_type PASS  
        auth_pass k8s
    }
    virtual_ipaddress {
        192.168.6.129/24
    }
    track_script {
        check_apiserver
    }
}

```

> 重编译重安装`nginx`
```
./configure --prefix=/usr/local/nginx --with-http_stub_status_module --with-http_ssl_module --add-module=/ngm/ngx_http_substitutions_filter_module

make

ps -ef | grep nginx

cp /usr/local/nginx/sbin/nginx /usr/local/nginx/sbin/nginx.bak

kill -QUIT 31680

cp ./objs/nginx /usr/local/nginx/sbin/

/usr/local/nginx/sbin/nginx -V

systemctl  start nginx

```
# `在Node节点部署组件`
## 1.将kubelet-bootstrap用户绑定到系统集群角色
```
kubectl create clusterrolebinding kubelet-bootstrap \
  --clusterrole=system:node-bootstrapper \
  --user=kubelet-bootstrap

#查看

kubectl get clusterrolebinding
```
## 2.创建kubeconfig文件,使用提供的`kubeconfig.sh`。新产生 bootstrap.kubeconfig ，kube-proxy.kubeconfig 两个文件
```sh
./kubeconfig.sh 192.168.77.10  /root/tool/k8s-cert
```
+ 将新产生的文件拷贝到node节点
```
# 在node节点创建文件夹目录
mkdir /opt/kubernetes/{bin,cfg,ssl} -p

scp bootstrap.kubeconfig kube-proxy.kubeconfig  root@192.168.77.11:/opt/kubernetes/cfg/
scp bootstrap.kubeconfig kube-proxy.kubeconfig  root@192.168.78.15:/opt/kubernetes/cfg/
```
## 3.部署`kubelet`组件
> 创建kubelet配置文件：`/opt/kubernetes/cfg/kubelet`
```
KUBELET_OPTS="--logtostderr=false \
--log-dir=/opt/kubernetes/logs \
--v=4 \
--address=192.168.77.11 \
--hostname-override=192.168.77.11 \
--kubeconfig=/opt/kubernetes/cfg/kubelet.kubeconfig \
--experimental-bootstrap-kubeconfig=/opt/kubernetes/cfg/bootstrap.kubeconfig \
--config=/opt/kubernetes/cfg/kubelet.config \
--cert-dir=/opt/kubernetes/ssl \
--pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google-containers/pause-amd64:3.0"
```
> `/opt/kubernetes/cfg/kubelet.config`
```
kind: KubeletConfiguration
apiVersion: kubelet.config.k8s.io/v1beta1
address: 192.168.77.11
port: 10250
readOnlyPort: 10255
cgroupDriver: cgroupfs
clusterDNS:
- 10.0.0.2 
clusterDomain: cluster.local.
failSwapOn: false
authentication:
  anonymous:
    enabled: true
```
> `/lib/systemd/system/kubelet.service`
```sh
[Unit]
Description=Kubernetes Kubelet
After=docker.service
Requires=docker.service

[Service]
EnvironmentFile=/opt/kubernetes/cfg/kubelet
ExecStart=/opt/kubernetes/bin/kubelet $KUBELET_OPTS
Restart=on-failure
KillMode=process

[Install]
WantedBy=multi-user.target
```
## 4.启动`kubelet.service`
```
docker load -i pause.tar
chmod 755 kube*
cp kubelet kube-proxy  /opt/kubernetes/bin
systemctl daemon-reload
systemctl enable kubelet
systemctl restart kubelet
```

## 5.审批加入集群
```
kubectl get csr
kubectl certificate approve XXXXID
kubectl get node

kubectl create clusterrolebinding cluster-system-anonymous  --clusterrole=cluster-admin --user=system:anonymous
```
## 6.部署`kube-proxy`组件
> 安装ipvs工具
```
apt-get -y install ipvsadm
apt-get -y install ipset
apt-get -y install conntrack
```
> `/opt/kubernetes/cfg/kube-proxy`
```
KUBE_PROXY_OPTS="--logtostderr=false \
--log-dir=/opt/kubernetes/logs \
--v=4 \
--hostname-override=192.168.77.11 \
--cluster-cidr=10.0.0.0/24 \
--proxy-mode=ipvs \
--kubeconfig=/opt/kubernetes/cfg/kube-proxy.kubeconfig"
```
> `/lib/systemd/system/kube-proxy.service`
```
[Unit]
Description=Kubernetes Proxy
After=network.target

[Service]
EnvironmentFile=-/opt/kubernetes/cfg/kube-proxy
ExecStart=/opt/kubernetes/bin/kube-proxy $KUBE_PROXY_OPTS
Restart=on-failure

[Install]
WantedBy=multi-user.target
```
## 7.启动：`kube-proxy`
```
systemctl daemon-reload
systemctl enable kube-proxy
systemctl restart kube-proxy
```

## 8.其他`node部署`，通过拷贝方式
```

apt-get -y install ipvsadm
apt-get -y install ipset
apt-get -y install conntrack


scp kubelet kube-proxy  root@192.168.78.15:/opt/kubernetes/bin
scp pause.tar  root@192.168.78.15:/root/
scp /opt/kubernetes/cfg/kubelet  root@192.168.78.15:/opt/kubernetes/cfg/kubelet
scp /opt/kubernetes/cfg/kubelet.config  root@192.168.78.15:/opt/kubernetes/cfg/kubelet.config
scp /lib/systemd/system/kubelet.service  root@192.168.78.15:/lib/systemd/system/kubelet.service
scp /opt/kubernetes/cfg/kube-proxy  root@192.168.78.15:/opt/kubernetes/cfg/kube-proxy
scp /lib/systemd/system/kube-proxy.service  root@192.168.78.15:/lib/systemd/system/kube-proxy.service

# 修改 /opt/kubernetes/cfg/kubelet /opt/kubernetes/cfg/kubelet.config /opt/kubernetes/cfg/kube-proxy 中ip

systemctl daemon-reload
systemctl enable kubelet
systemctl restart kubelet
# 批准加入
kubectl get csr
kubectl certificate approve XXXXID
kubectl get node
systemctl enable kube-proxy
systemctl restart kube-proxy
```

# `部署jenkins`
+ 上传所需文件
```
docker load -i registry.tar
docker load -i alajexus.tar
docker load -i craneoperator.tar
docker load -i jenkins.tar
docker load -i jenkins-slave.tar

# 创建镜像仓库
 docker run -d -v /opt/minikube:/var/lib/registry -p 5777:5000 --restart=always --name registry -e REGISTRY_STORAGE_DELETE_ENABLED=true registry

# 创建仓库浏览界面注意IP
docker run -d   -p 8001:80   -e REGISTRY_HOST=10.3.24.67   -e REGISTRY_PORT=5777   -e REGISTRY_PROTOCOL=http   -e SSL_VERIFY=false   -e ALLOW_REGISTRY_LOGIN=true   -e REGISTRY_ALLOW_DELETE=true --restart=always  parabuzzle/craneoperator:latest

# 推镜像
docker tag 192.168.6.131:5777/library/jenkins:lts-alpine K8SMaster02:5777/library/jenkins:lts-alpine
docker tag 192.168.6.131:5777/library/alajexus:rc2 K8SMaster02:5777/library/alajexus:rc2
docker tag 192.168.6.131:5777/library/jenkins-slave-net:4.5 K8SMaster02:5777/library/jenkins-slave-net:4.5

#上传镜像到仓库
docker push K8SMaster02:5777/library/jenkins-slave-net:4.5
docker push K8SMaster02:5777/library/jenkins:lts-alpine
docker push K8SMaster02:5777/library/alajexus:rc2

# 为节点打标签
kubectl get nodes --show-labels
kubectl label node 10.3.24.76 func=jenkins

#复制jenkins到工作目录
 unzip jenkins.zip 
 mkdir -p /opt/data/jenkins_data
 cp -r jenkins/*  /opt/data/jenkins_data/ 
  chown 1000 -R /opt/data/jenkins_data/

# 执行yaml
kubectl apply -f .
```

# `coredns部署`

```
docker load -i busybox.tar
docker load -i coredns.tar
docker tag coredns/coredns:1.6.2 K8SMaster02:5777/library/coredns:1.6.2
docker tag busybox:1.28.4 K8SMaster02:5777/library/busybox:1.28.4
docker push K8SMaster02:5777/library/coredns:1.6.2
docker push K8SMaster02:5777/library/busybox:1.28.4

# 测试内部dns
kubectl apply -f bs.yaml
kubectl exec -it busybox sh
 ping kubernetes 
# 再试
 kubectl apply -f coredns.yaml
 kubectl exec -it busybox sh
 ping kubernetes 

kubectl delete -f bs.yaml
```

# `ELK安装` centos
```
rpm -ivh jdk-8u241-linux-x64.rpm
java -version

rpm -ivh elasticsearch-7.4.0-x86_64.rpm
vim /etc/elasticsearch/elasticsearch.yml
#取消下面两行注释
bootstrap.memory_lock: true
http.port: 9200 

systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

rpm -ivh kibana-7.4.0-x86_64.rpm
vim /etc/kibana/kibana.yml
#改如下
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]

[root@localhost ~]# systemctl enable kibana
[root@localhost ~]# systemctl start kibana
[root@localhost ~]# netstat -plntu


 rpm -ivh logstash-7.4.0.rpm 

 systemctl enable logstash
 systemctl start logstash

 # logstash配置文件
  vim /etc/logstash/conf.d/logstash-to-es.conf
  # 修改完后需要重启
     systemctl restart logstash
```

# `ELK安装` ubuntu
```
dpkg -i  elasticsearch-7.4.0-amd64.deb  kibana-7.4.0-amd64.deb  logstash-7.4.0.deb
```

# `prometheus部署`
```

docker load -i busyboxlatest.tar
docker load -i configmap-reload.tar
docker load -i prometheus.tar
docker load -i addon-resizer.tar
docker load -i kube-state-metrics.tar

docker tag busybox:latest K8SMaster02:5777/library/busybox:latest
docker push K8SMaster02:5777/library/busybox:latest

docker tag jimmidyson/configmap-reload:v0.1 K8SMaster02:5777/library/configmap-reload:v0.1
docker push K8SMaster02:5777/library/configmap-reload:v0.1

docker tag prom/prometheus:v2.2.1 K8SMaster02:5777/library/prometheus:v2.2.1
docker push K8SMaster02:5777/library/prometheus:v2.2.1

 kubectl apply -f prometheus-rbac.yaml 
 kubectl apply -f prometheus-configmap.yaml 
 kubectl apply -f prometheus-rules.yaml

kubectl label node 10.3.24.40 func=prometheus
kubectl apply -f prometheus-statefulset.yaml 

 # service 启动才能真正完工

 kubectl apply -f prometheus-service.yaml

# 不动不了 centos填了会有问题

fs.inotify.max_user_watches = 1048576
vim /etc/sysctl.conf
 sysctl -p

# 暴露指标数据

docker tag 192.168.6.131:5777/library/kube-state-metrics:v1.3.0 K8SMaster02:5777/library/kube-state-metrics:v1.3.0

docker tag 192.168.6.131:5777/library/addon-resizer:1.8.5  K8SMaster02:5777/library/addon-resizer:1.8.5

 kubectl apply -f  kube-state-metrics-rbac.yaml
 kubectl apply -f kube-state-metrics-deployment.yaml
 kubectl apply -f kube-state-metrics-service.yaml

```

# `grafana`
```

docker tag grafana/grafana:latest registry:5777/library/grafana:latest

docker push registry:5777/library/grafana:latest

 tar -xvf granfana.tar

 mkdir /opt/data/grafana

 cp -ra grafana  /opt/data/grafana/

 kubectl apply -f grafana.yaml 
```

# `node exporter`
```
通过脚本安装
```

# `altermanager`
```
tar zxvf alertmanager-0.19.0.linux-amd64.tar.gz
mv alertmanager-0.19.0.linux-amd64 /usr/local/alertmanager
chown root:root -R /usr/local/alertmanager
```
+ 命令运行 windows  nssm 制作成 服务

```
nssm.exe install altermanager

nssm edit <servicename>

nssm remove <servicename>


 --config.file=E:\alertmanager\alertmanager.yml --storage.path=E:\alertmanager\data --log.level=info
```

+ /usr/lib/systemd/system/alertmanager.service
```
[Unit]
Description=Monitor alertmanager

[Service]
Restart=on-failure
ExecStart=/usr/local/alertmanager/alertmanager --config.file=/usr/local/alertmanager/alertmanager.yml --cluster.peer=192.168.6.121:9094 --cluster.peer=192.168.6.11:9094  --storage.path=/usr/local/alertmanager/data --log.level=info

[Install]
WantedBy=multi-user.target
```

+ `/usr/local/alertmanager` 建立 `alertmanager.yml`
```yaml
global:
  resolve_timeout: 30s
  smtp_smarthost: 'smtp.163.com:25'
  smtp_from: 'colorsfly2011@163.com'
  smtp_auth_username: 'colorsfly2011@163.com'
  smtp_auth_password: ''
  smtp_require_tls: false
  wechat_api_corp_id: 'ww77882a466a969fe0'
  wechat_api_url: 'https://qyapi.weixin.qq.com/cgi-bin/'
  wechat_api_secret: ''
templates:
  - '/usr/local/alertmanager/template/wechat.tmpl'
route:
  group_by: ['alertname']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 1h
  receiver: 'weixin'
receivers:
- name: 'weixin'
  wechat_configs:
  - agent_id: 1000007
    corp_id: 'ww77882a466a969fe0'
    api_url: 'https://qyapi.weixin.qq.com/cgi-bin/'
    api_secret: ''
    to_user: '@all'
    send_resolved: true
```

```
mkdir template
vim wechat.tmpl



{{ define "wechat.default.message" }}
{{ range $i, $alert :=.Alerts }}
========绿宝监控报警2==========
告警状态：{{   .Status }}
告警级别：{{ $alert.Labels.severity }}
告警类型：{{ $alert.Labels.alertname }}
告警应用：{{ $alert.Annotations.summary }}
告警主机：{{ $alert.Labels.instance }}
告警详情：{{ $alert.Annotations.description }}
触发阀值：{{ $alert.Annotations.value }}
告警时间：{{ $alert.StartsAt.Format "2006-01-02 15:04:05" }}
========end=============
{{ end }}
{{ end }}



systemctl daemon-reload
systemctl enable alertmanager.service 
systemctl start alertmanager.service

```

+ 二号报警器
```
  scp -r /usr/local/alertmanager/ root@K8SMaster01:/usr/local/

  scp /usr/lib/systemd/system/alertmanager.service root@K8SMaster01:/usr/lib/systemd/system/alertmanager.service


  删除 data  修改 报警器名称

systemctl daemon-reload
systemctl enable alertmanager.service 
systemctl start alertmanager.service

```
+ rules修改
```
curl -X POST http://192.168.6.133:37777/-/reload
```


```

docker run -d -v /opt/ftp:/home/vsftpd  -p 20:20 -p 21:21 -p 47400-47470:47400-47470  -e FTP_USER=administrator  -e FTP_PASS=Alaya123   -e PASV_ADDRESS=10.3.24.54   --name ftp   --restart=always bogem/ftp


curl ftp://10.3.24.54/aaDir/ -u "administrator:Alaya123" -T "aa.txt"

```

# 日志清理
+ python3安装
```
yum -y install zlib-devel bzip2-devel openssl-devel ncurses-devel sqlite-devel readline-devel tk-devel gdbm-devel db4-devel libpcap-devel xz-devel gcc libffi-devel gcc make automake autoconf libtool libffi-devel

./configure --prefix=/usr/local/python3

make && make install



ln -s /usr/local/python3/bin/python3.7 /usr/bin/python3
ln -s /usr/local/python3/bin/pip3 /usr/bin/pip3

windows 直接安装 python 然后拷贝包含renquests的python文件 配置计划任务即可

```

+ master registry
```sh
#!/bin/bash
find /opt/kubernetes/logs/ -mtime +7  -exec rm -rf {} \;> /dev/null 2>&1
docker exec -it registry  registry garbage-collect /etc/docker/registry/config.yml > /dev/null 2>&1


#重启crontab
#service crond restart
```
+ python脚本清理  registry 
```python
#!/usr/bin/python
#-*-coding:utf-8 -*-
import requests

class Docker(object):
    def __init__(self, hub, repos):
        self.hub = hub
        self.repos = repos

    @staticmethod
    def get_tag_list(hub, repo):
        tag_list_url = '%s/v2/%s/tags/list' % (hub, repo)
        r1 = requests.get(url=tag_list_url)
        tag_list = r1.json().get('tags')
        return tag_list

    def main(self):
        for rep in repos:
          self.delete_images(rep)

    def sort_key(self,list):
        return int(list.split('.')[1])

    def delete_images(self, repo):
        hub = self.hub
        tag_list = self.get_tag_list(hub=hub, repo=repo)
        tag_list.sort(key=self.sort_key,reverse=False)
        num = 0
        try:
            for tag in tag_list[:-5]:
                get_info_url = '{}/v2/{}/manifests/{}'.format(hub, repo, tag)
                header = {"Accept": "application/vnd.docker.distribution.manifest.v2+json"}
                r2 = requests.get(url=get_info_url, headers=header, timeout=10)
                digest = r2.headers.get('Docker-Content-Digest')
                delete_url = '%s/v2/%s/manifests/%s' % (hub, repo, digest)
                r3 = requests.delete(url=delete_url)
                if r3.status_code == 202:
                    num += 1

        except Exception as e:
            print(str(e))

        print('仓库%s 共删除了%i个历史镜像' % (repo, num))

if __name__ == '__main__':
    hub = 'http://AlyKDMaster:5777'
    repos = ["emerald/asset","emerald/commodity","emerald/crm","emerald/erp","emerald/main","emerald/market","emerald/member","emerald/mvc","emerald/order","emerald/pay","emerald/pos","emerald/search","emerald/security","emerald/inter","emerald-prod/asset","emerald-prod/commodity","emerald-prod/crm","emerald-prod/erp","emerald-prod/main","emerald-prod/market","emerald-prod/member","emerald-prod/mvc","emerald-prod/order","emerald-prod/pay","emerald-prod/pos","emerald-prod/search","emerald-prod/security","emerald-prod/inter","emerald/wxpa","emerald/wxser","emerald-prod/wxpa","emerald-prod/wxser"]
    d = Docker(hub=hub, repos=repos)
    d.main()
```
```sh
#!/bin/bash
python3 /root/pyscript/del_register.py > /dev/null 2>&1
```

+ node
```sh
#!/bin/bash
find /opt/kubernetes/logs/ -mtime +7  -exec rm -rf {} \;> /dev/null 2>&1
docker system prune -a -f --volumes > /dev/null 2>&1
```

+ elk日志
```sh
#!/bin/sh
IP=127.0.0.1
CURRENT_DIR=$PWD
LOG_DIR=$CURRENT_DIR/del_es_index.log
DAYS=14

if [ "$#" -eq "1" ];then
        DAYS=$1
fi
#echo "will delete es logs :" `date -d "$DAYS days ago" +%Y.%m.%d`

curl -XGET "http://$IP:9200/_cat/shards" |grep $IP |awk '{print $1}' |grep `date -d "$DAYS days ago" +%Y.%m.%d` |uniq > $CURRENT_DIR/index_name.tmp
for index_name in `cat $CURRENT_DIR/index_name.tmp`
do
    curl -XDELETE  http://$IP:9200/$index_name > /dev/null 2>&1
        #if [ $? -eq 0 ];then
        #       echo "${index_name} delete success." >> $LOG_DIR
        #else
        #       echo "${index_name} delete error." >> $LOG_DIR
        #fi
done
rm $CURRENT_DIR/index_name.tmp
```
# `mysql proxysql`
```
#安装
dpkg -i proxysql_2.0.1-ubuntu16_amd64.deb
apt-get install mysql-client-core-5.7

systemctl  enable proxysql
systemctl start proxysql

#修改hostname admin1和admin2不同
10.192.5.41    Mysql_Master
192.168.78.14  Mysql_Salve

#创建监控用户
mysql -uadmin -padmin -P6032 -h127.0.0.1 --prompt 'admin> '

create user monitor@'%' identified by 'P@ssword1!';
grant replication client on *.* to monitor@'%';
flush privileges;


#在proxysql节点运行 使用监控用户

set mysql-monitor_username='monitor';
set mysql-monitor_password='P@ssword1!';
load mysql variables to runtime;
save mysql variables to disk;

#语句用户
insert into mysql_users(username,password,default_hostgroup,max_connections) values('SYSTEM','alayadata666',1,4000);
load mysql users to runtime; save mysql users to disk;

#web监控
SET admin-web_enabled='true';
LOAD ADMIN VARIABLES TO RUNTIME;
SAVE ADMIN VARIABLES TO DISK ;


#插入主从复制语句
insert into mysql_servers(hostgroup_id,hostname,port,weight,max_connections,comment,status) values(1,'Mysql_Master',33306,1,4000,'主','ONLINE');
insert into mysql_servers(hostgroup_id,hostname,port,weight,max_connections,comment,status) values(1,'Mysql_Salve',3306,1,4000,'备','OFFLINE_SOFT');
insert into mysql_servers(hostgroup_id,hostname,port,weight,max_connections,comment,status) values(2,'Mysql_Master',33306,2,4000,'主','ONLINE');
insert into mysql_servers(hostgroup_id,hostname,port,weight,max_connections,comment,status) values(2,'Mysql_Salve',3306,8,4000,'备','OFFLINE_SOFT');

load mysql servers to runtime;
save mysql servers to disk;


#主备切换脚本
 scp sw_mode_checker.sh root@10.192.6.23:/var/lib/proxysql/
chown proxysql:proxysql sw_mode_checker.sh

insert into scheduler (id,interval_ms,filename,arg1,arg2,arg3,arg4,arg5) values (1,'5000','/var/lib/proxysql/sw_mode_checker.sh','1','2','1','0','/var/lib/proxysql/sw_mode_checker.log');

SAVE SCHEDULER TO DISK;
LOAD SCHEDULER TO RUNTIME;


# 发邮件

apt-get install heirloom-mailx

vi /etc/s-nail.rc

#末尾添加
set from=colorsfly2011@163.com
set smtp=smtps://smtp.163.com
set smtp-auth-user=colorsfly2011@163.com
set smtp-auth-password=128130110hero
set smtp-auth=login



select * from mysql_server_connect_log;

select * from mysql_server_ping_log;


# 加大openfile



```


```sql
insert into mysql_servers(hostgroup_id,hostname,port,weight,comment,status) values(1,'Mysql_Master',5306,1,'主','ONLINE'); 
insert into mysql_servers(hostgroup_id,hostname,port,weight,comment,status) values(1,'Mysql_Salve',3320,1,'备','OFFLINE_SOFT'); 
insert into mysql_servers(hostgroup_id,hostname,port,weight,comment,status) values(2,'Mysql_Master',5306,2,'主','ONLINE'); 
insert into mysql_servers(hostgroup_id,hostname,port,weight,comment,status) values(2,'Mysql_Salve',3320,8,'备','OFFLINE_SOFT'); 

load mysql variables to runtime;
save mysql variables to disk;


```

# docker mysql
```
docker run -d -p 5306:3306 -e MYSQL_ROOT_PASSWORD=root123 -v /etc/localtime:/etc/timezone:rw -v /etc/localtime:/etc/localtime:rw -v /opt/mysql_z/conf:/etc/mysql/conf.d -v /opt/mysql_z/data:/var/lib/mysql -v /opt/mysql_z/logs:/logs --name zmysql --restart=always mysql:5.6

docker run -d -p 7306:3306 -e MYSQL_ROOT_PASSWORD=root123 -v /etc/localtime:/etc/timezone:rw -v /etc/localtime:/etc/localtime:rw -v /opt/sc_mysql/conf:/etc/mysql/conf.d -v /opt/sc_mysql/data:/var/lib/mysql -v /opt/sc_mysql/logs:/logs --name scmysql --restart=always mysql:5.6

# 经入容器执行导出
mysqldump -uroot -p -R --databases adacc adchanl adpub admob cr_debug > /var/lib/mysql/dump.sql
```


# 应用
+ 修改coredns minikube
```
 kubectl get configmap coredns -n kube-system

 # 编辑
 kubectl edit configmap coredns -n kube-system

 hosts {
           10.192.5.37 csmysql
           fallthrough
        }
 kubectl scale deployment coredns -n kube-system --replicas=0
 kubectl scale deployment coredns -n kube-system --replicas=2
```

# docker ftp
```
docker run -d -v /ftp:/home/vsftpd                 -p 20:20 -p 21:21 -p 47400-47470:47400-47470                 -e FTP_USER=hyftp                 -e FTP_PASS=123456Asd                 -e PASV_ADDRESS=52.82.75.14                 --name ftp                 --restart=always bogem/ftp
```

# nginx 重新编译安装
```
nginx -V
# 记录 参数
--prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module  --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic' --with-ld-opt='-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E' --add-module=/git/ngx_http_substitutions_filter_module
``` 
+ 下载相同版本的nginx的源码包
  
+ 将原来的nginx重要文件备份
```
mv /usr/sbin/nginx /usr/sbin/nginx.back
cp -rf /etc/nginx /etc/nginx.back
```

+ 新编译 添加sub模块 --with-http_stub_status_module　--with-http_sub_module
```
--prefix=/usr/share/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --error-log-path=/var/log/nginx/error.log --http-log-path=/var/log/nginx/access.log --http-client-body-temp-path=/var/lib/nginx/tmp/client_body --http-proxy-temp-path=/var/lib/nginx/tmp/proxy --http-fastcgi-temp-path=/var/lib/nginx/tmp/fastcgi --http-uwsgi-temp-path=/var/lib/nginx/tmp/uwsgi --http-scgi-temp-path=/var/lib/nginx/tmp/scgi --pid-path=/run/nginx.pid --lock-path=/run/lock/subsys/nginx --user=nginx --group=nginx --with-file-aio --with-ipv6 --with-http_ssl_module --with-http_v2_module --with-http_realip_module --with-stream_ssl_preread_module --with-http_addition_module --with-http_xslt_module=dynamic --with-http_image_filter_module=dynamic --with-http_sub_module --with-http_dav_module --with-http_flv_module --with-http_mp4_module --with-http_gunzip_module --with-http_gzip_static_module --with-http_random_index_module --with-http_secure_link_module --with-http_degradation_module --with-http_slice_module --with-http_stub_status_module --with-http_perl_module=dynamic --with-http_auth_request_module --with-mail=dynamic --with-mail_ssl_module --with-pcre --with-pcre-jit --with-stream=dynamic --with-stream_ssl_module --with-google_perftools_module --with-debug --with-cc-opt='-O2 -g -pipe -Wall -Wp,-D_FORTIFY_SOURCE=2 -fexceptions -fstack-protector-strong --param=ssp-buffer-size=4 -grecord-gcc-switches -specs=/usr/lib/rpm/redhat/redhat-hardened-cc1 -m64 -mtune=generic' --with-ld-opt='-Wl,-z,relro -specs=/usr/lib/rpm/redhat/redhat-hardened-ld -Wl,-E' --add-module=/git/ngx_http_substitutions_filter_module
```

# Too many open files

> 设置文件最大打开数
+ vim /etc/sysctl.conf
+ 添加 fs.file-max = 1048576
+ sysctl -p

> 用户
+ vim /etc/security/limits.conf

+ 添加
```
*               hard    nofile          1048576
*               soft    nofile          1048576
root            hard    nofile          1048576
root            soft    nofile          1048576
```
> Systemd
```
sed -i '/DefaultLimitNOFILE/c DefaultLimitNOFILE=1048576' /etc/systemd/*.conf
systemctl daemon-reexec
```
> 验证
```
+ 打开新的终端
ssh remote_user@host

查看系统限制
cat /proc/sys/fs/file-max

查看用户硬限制
ulimit -Hn

查看用户软限制
ulimit -Sn

查看某进程的限制
cat /proc/PID/limits # 将 PID 替换为具体的进程 ID


修改 nginx.conf，
添加：以下两点
worker_rlimit_nofile 65535; # (has to be smaller or equal to LimitNOFILE set above)
events {
    worker_connections  65535;
}
重启 nginx:
sudo systemctl restart nginx
 
然后再去查看nginx的 max open files，看看是不是我们设置的65535
grep 'open files' /proc/$( cat /var/run/nginx.pid )/limits
到此就修改nginx的max open files结束。

centos 修改 nginx.service加入

LimitNOFILE=65536

上面的 worker_rlimit_nofile 65535;  
worker_connections  65535;  两个也要
```


# 大东方磁盘充满
```
#扩大 LVM 逻辑分区所在的物理分区
parted /dev/vdb

resizepart 1

-0 

q 


lvresize -l +100%FREE /dev/datavg/datalv
resize2fs -p /dev/mapper/datavg-datalv

pvresize /dev/vdb1
lvextend -l 100%VG /dev/mapper/datavg-datalv
resize2fs -p /dev/mapper/datavg-datalv
```

# 解压缩mysql安装
```
tar -zxvf mysql-5.6.47-linux-glibc2.12-x86_64.tar.gz  -C /opt/

cd /opt/
mv mysql-5.6.47-linux-glibc2.12-x86_64/ mysql

groupadd mysql

useradd -g mysql mysql

apt-get install libaio-dev

 cd mysql/
./scripts/mysql_install_db  --basedir=/opt/mysql --datadir=/opt/mysql/data

vim my.cnf

mkdir tmp
chown -R mysql:mysql ./
vim support-files/mysql.server      (改了基本目录)
cp ./support-files/mysql.server  /etc/init.d/mysqld
chmod +x /etc/init.d/mysqld


apt-get install sysv-rc-conf
sysv-rc-conf mysqld on
systemctl daemon-reload 
service mysql start
apt-get install mysql-client-core-5.7

```


# 添加新节点
```
# 充满磁盘
# 时间同步
# 设置主机名称
# 修改docker 配置文件
# 安装flannel
mkdir /opt/kubernetes/{cfg,bin,ssl} -p  

scp /opt/kubernetes/bin/flanneld  /opt/kubernetes/bin/mk-docker-opts.sh   root@192.168.78.15:/opt/kubernetes/bin
scp /lib/systemd/system/docker.service root@192.168.78.15:/lib/systemd/system/docker.service
scp /opt/kubernetes/cfg/flanneld root@192.168.78.15:/opt/kubernetes/cfg/flanneld
scp /lib/systemd/system/flanneld.service root@192.168.78.15:/lib/systemd/system/flanneld.service
scp -r /opt/etcd/ssl/ root@192.168.78.15:/opt/etcd/


systemctl daemon-reload
systemctl enable flanneld
systemctl restart flanneld
systemctl restart docker




apt-get -y install ipvsadm
apt-get -y install ipset
apt-get -y install conntrack


scp kubelet kube-proxy  root@192.168.78.15:/opt/kubernetes/bin
scp pause.tar  root@192.168.78.15:/root/
scp /opt/kubernetes/cfg/kubelet  root@192.168.78.15:/opt/kubernetes/cfg/kubelet
scp /opt/kubernetes/cfg/kubelet.config  root@192.168.78.15:/opt/kubernetes/cfg/kubelet.config
scp /lib/systemd/system/kubelet.service  root@192.168.78.15:/lib/systemd/system/kubelet.service
scp /opt/kubernetes/cfg/kube-proxy  root@192.168.78.15:/opt/kubernetes/cfg/kube-proxy
scp /lib/systemd/system/kube-proxy.service  root@192.168.78.15:/lib/systemd/system/kube-proxy.service
scp bootstrap.kubeconfig kube-proxy.kubeconfig  root@192.168.78.15:/opt/kubernetes/cfg/
# 修改 /opt/kubernetes/cfg/kubelet /opt/kubernetes/cfg/kubelet.config /opt/kubernetes/cfg/kube-proxy 中ip

systemctl daemon-reload
systemctl enable kubelet
systemctl restart kubelet
# 批准加入
kubectl get csr
kubectl certificate approve XXXXID
kubectl get node
systemctl enable kube-proxy
systemctl restart kube-proxy

# 增加打开文件数量
```
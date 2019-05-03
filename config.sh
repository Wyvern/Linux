echo nameserver 176.103.130.130 > /etc/resolv.conf 
echo nameserver 176.103.130.131 >> /etc/resolv.conf 
cat /etc/resolv.conf 

sudo echo LC_ALL="en_US.utf-8" >> /etc/environment 
sudo echo LC_CTYPE="en_US.utf-8" >> /etc/environment 

sudo truncate -s 0 /var/log/*tmp
sudo chattr +i /var/log/*tmp
sysctl  net.ipv6.conf.all.disable_ipv6=1
sysctl  net.ipv6.conf.default.disable_ipv6=1
chattr -ais /etc/ssh/sshd_config

cat<<EOF>/etc/ssh/sshd_config
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/sshd_config)
EOF

service sshd restart

yum remove -y abrt sysstat sos libreport logrotate rsyslogd tuned audit firewalld subscription-manager kexec-tools
systemctl mask auditd.service systemd-journald.service systemd-journald.socket syslog.socket syslog.target  rhel-dmesg.service 
yum install -y vim-enhanced zsh tree unzip bind-utils
yum autoremove -y
timedatectl set-timezone Asia/Shanghai
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

cat<<EOF>.zshrc
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/.zshrc)
EOF

cat<<EOF>/root/.alias
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/.alias)
EOF


wget https://github.com/git/git/archive/v2.21.0.tar.gz
tar xf v2.21.0.tar.gz 
cd git-2.21.0 

yum install -y autoconf curl-devel expat-devel openssl-devel perl-devel zlib-devel libffi-devel
make configure
./configure --prefix=/usr/local --without-tcltk
make NO_TCLTK=Yes NO_MSGFMT=Yes NO_GETTEXT=Yes LDFLAGS+=-s -j install 
yum remove -y git
yum autoremove -y
wget https://nodejs.org/dist/latest-v8.x/node-v8.16.0-linux-s390x.tar.gz
tar xf node-v8.16.0-linux-s390x.tar.gz
cd node-v8.16.0-linux-s390x
cp -r bin/ include/ lib/ share/ /usr/local/
npm -g up

wget https://download.docker.com/linux/static/stable/s390x/docker-18.06.3-ce.tgz
tar xf docker-18.06.3-ce.tgz
cd docker
cp * /usr/local/bin
dockerd &

docker run --name vpn --restart=always -d -p 500:500/udp -p 4500:4500/udp --privileged -v /lib/modules:/lib/modules:ro  wyvern/strongswan:ssl
docker run --name ss --restart=always -d -p 443:443/tcp -p 443:443/udp   wyvern/ss:ibm
docker run --name bt --restart=always -d -p 80:123 -v /bt:/downloads wyvern/ct:ibm  --port 123 -a bt:asdf
docker run --name kms --restart=always -d -p 1688:1688 wyvern/kms:ibm

cd ~

git clone https://github.com/Wyvern/Python.git
cd Python/
./configure --prefix=/usr/local --enable-optimizations --with-lto
make LDFLAGS+=-s -j install

cd ~

curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3 get-pip.py
pip install pip-review pkgconfig speedtest-cli
pip install onedrivecmd google-api-python-client oauth2client progressbar2
wget https://github.com/tokland/youtube-upload/archive/master.zip
unzip master.zip
cd youtube-upload-master/
python3 setup.py install

yum autoremove -y
package-cleanup -y --oldkernels --count=1

cat <<EOF >/usr/local/lib/python3.7/site-packages/youtube_upload/main.py
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/main.py)
EOF

cd ~
rm -rf *

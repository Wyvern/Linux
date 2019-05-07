echo nameserver 176.103.130.130 > /etc/resolv.conf 
echo nameserver 176.103.130.131 >> /etc/resolv.conf 

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

wget https://github.com/Wyvern/Linux/raw/s390x/htop
wget https://github.com/Wyvern/Linux/raw/s390x/unrar
chmod a+x htop unrar
mv htop unrar /usr/local/bin

sh -c "$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/git-node-docker)"
cd ~

sh -c "$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/Python)"
cd ~

sh -c "$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/pip)"

cat <<EOF >/usr/local/lib/python3.7/site-packages/youtube_upload/main.py
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/main.py)
EOF

yum autoremove -y
package-cleanup -y --oldkernels --count=1

cd ~
rm -rf *

sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

cat<<EOF>.zshrc
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/.zshrc)
EOF

cat<<EOF>/root/.alias
$(curl -fsSL https://raw.githubusercontent.com/Wyvern/Linux/s390x/.alias)
EOF

exit
su
git clone https://github.com/wyvern/odyt

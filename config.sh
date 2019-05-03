echo nameserver 176.103.130.130 > /etc/resolv.conf 
echo nameserver 176.103.130.131 >> /etc/resolv.conf 
cat /etc/resolv.conf 

sudo echo LC_ALL="en_US.utf-8" >> /etc/environment 
sudo echo LC_CTYPE="en_US.utf-8" >> /etc/environment 
chattr -ais /etc/ssh/sshd_config

cat<<EOF>/etc/ssh/sshd_config
#	$OpenBSD: sshd_config,v 1.93 2014/01/10 05:59:19 djm Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/local/bin:/usr/bin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# If you want to change the port on a SELinux system, you have to tell
# SELinux about this change.
# semanage port -a -t ssh_port_t -p tcp #PORTNUMBER
#
#Port 22
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

# The default requires explicit activation of protocol 1
#Protocol 2

# HostKey for protocol version 1
#HostKey /etc/ssh/ssh_host_key
# HostKeys for protocol version 2
HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_dsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

# Lifetime and size of ephemeral version 1 server key
#KeyRegenerationInterval 1h
#ServerKeyBits 1024

# Ciphers and keying
Ciphers aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
#RekeyLimit default none
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-ripemd160-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,hmac-ripemd160,umac-128@openssh.com
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256

# Logging
# obsoletes QuietMode and FascistLogging
#SyslogFacility AUTH
SyslogFacility AUTHPRIV
LogLevel ERROR

# Authentication:

#LoginGraceTime 2m
PermitRootLogin yes
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#RSAAuthentication yes
#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#RhostsRSAAuthentication no
# similar for protocol version 2
#HostbasedAuthentication no
# Change to yes if you don't trust ~/.ssh/known_hosts for
# RhostsRSAAuthentication and HostbasedAuthentication
#IgnoreUserKnownHosts no
# Don't read the user's ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# To disable tunneled clear text passwords, change to no here!
#PasswordAuthentication yes
#PermitEmptyPasswords no
PasswordAuthentication yes

# Change to no to disable s/key passwords
#ChallengeResponseAuthentication yes
ChallengeResponseAuthentication no

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no
#KerberosUseKuserok yes

# GSSAPI options
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
#GSSAPIStrictAcceptorCheck yes
#GSSAPIKeyExchange no
#GSSAPIEnablek5users no

# Set this to 'yes' to enable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the ChallengeResponseAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via ChallengeResponseAuthentication may bypass
# the setting of "PermitRootLogin without-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and ChallengeResponseAuthentication to 'no'.
# WARNING: 'UsePAM no' is not supported in Red Hat Enterprise Linux and may cause several
# problems.
UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#UseLogin no
UsePrivilegeSeparation sandbox		# Default for new installations.
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#ShowPatchLevel no
UseDNS no
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#VersionAddendum none

# no default banner path
#Banner none

# Accept locale-related environment variables
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS

# override default of no subsystems
Subsystem	sftp	/usr/libexec/openssh/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
EOF

service sshd restart

yum remove -y abrt sysstat sos libreport logrotate rsyslogd tuned audit firewalld subscription-manager kexec-tools
systemctl mask auditd.service systemd-journald.service systemd-journald.socket syslog.socket syslog.target  rhel-dmesg.service 
yum install -y vim-enhanced zsh tree unzip bind-utils
yum autoremove -y
timedatectl set-timezone Asia/Shanghai
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
cat<<EOF>.zshrc
# If you come from bash you might have to change your $PATH.
# export PATH=$HOME/bin:/usr/local/bin:$PATH

# Path to your oh-my-zsh installation.
  export ZSH="/root/.oh-my-zsh"

# Set name of the theme to load --- if set to "random", it will
# load a random theme each time oh-my-zsh is loaded, in which case,
# to know which specific one was loaded, run: echo $RANDOM_THEME
# See https://github.com/robbyrussell/oh-my-zsh/wiki/Themes
ZSH_THEME="ys"

# Set list of themes to pick from when loading at random
# Setting this variable when ZSH_THEME=random will cause zsh to load
# a theme from this variable instead of looking in ~/.oh-my-zsh/themes/
# If set to an empty array, this variable will have no effect.
# ZSH_THEME_RANDOM_CANDIDATES=( "robbyrussell" "agnoster" )

# Uncomment the following line to use case-sensitive completion.
# CASE_SENSITIVE="true"

# Uncomment the following line to use hyphen-insensitive completion.
# Case-sensitive completion must be off. _ and - will be interchangeable.
# HYPHEN_INSENSITIVE="true"

# Uncomment the following line to disable bi-weekly auto-update checks.
# DISABLE_AUTO_UPDATE="true"

# Uncomment the following line to change how often to auto-update (in days).
# export UPDATE_ZSH_DAYS=13

# Uncomment the following line to disable colors in ls.
# DISABLE_LS_COLORS="true"

# Uncomment the following line to disable auto-setting terminal title.
# DISABLE_AUTO_TITLE="true"

# Uncomment the following line to enable command auto-correction.
# ENABLE_CORRECTION="true"

# Uncomment the following line to display red dots whilst waiting for completion.
# COMPLETION_WAITING_DOTS="true"

# Uncomment the following line if you want to disable marking untracked files
# under VCS as dirty. This makes repository status check for large repositories
# much, much faster.
# DISABLE_UNTRACKED_FILES_DIRTY="true"

# Uncomment the following line if you want to change the command execution time
# stamp shown in the history command output.
# You can set one of the optional three formats:
# "mm/dd/yyyy"|"dd.mm.yyyy"|"yyyy-mm-dd"
# or set a custom format using the strftime function format specifications,
# see 'man strftime' for details.
# HIST_STAMPS="mm/dd/yyyy"

# Would you like to use another custom folder than $ZSH/custom?
# ZSH_CUSTOM=/path/to/new-custom-folder

# Which plugins would you like to load?
# Standard plugins can be found in ~/.oh-my-zsh/plugins/*
# Custom plugins may be added to ~/.oh-my-zsh/custom/plugins/
# Example format: plugins=(rails git textmate ruby lighthouse)
# Add wisely, as too many plugins slow down shell startup.
plugins=(yum sudo systemd git docker npm)

source $ZSH/oh-my-zsh.sh

# User configuration

# export MANPATH="/usr/local/man:$MANPATH"

# You may need to manually set your language environment
# export LANG=en_US.UTF-8

# Preferred editor for local and remote sessions
# if [[ -n $SSH_CONNECTION ]]; then
#   export EDITOR='vim'
# else
#   export EDITOR='mvim'
# fi

# Compilation flags
# export ARCHFLAGS="-arch x86_64"

# Set personal aliases, overriding those provided by oh-my-zsh libs,
# plugins, and themes. Aliases can be placed here, though oh-my-zsh
# users are encouraged to define aliases within the ZSH_CUSTOM folder.
# For a full list of active aliases, run `alias`.
#
# Example aliases
# alias zshconfig="mate ~/.zshrc"
# alias ohmyzsh="mate ~/.oh-my-zsh"

source /root/.alias
EOF

sudo truncate -s 0 /var/log/*tmp
sudo chattr +i /var/log/*tmp
sysctl  net.ipv6.conf.all.disable_ipv6=1
sysctl  net.ipv6.conf.default.disable_ipv6=1

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
#!/usr/bin/env python
#
# Upload videos to Youtube from the command-line using APIv3.
#
# Author: Arnau Sanchez <pyarnau@gmail.com>
# Project: https://github.com/tokland/youtube-upload
"""
Upload a video to Youtube from the command-line.

    $ youtube-upload --title="A.S. Mutter playing" \
                     --description="Anne Sophie Mutter plays Beethoven" \
                     --category=Music \
                     --tags="mutter, beethoven" \
                     anne_sophie_mutter.flv
    pxzZ-fYjeYs
"""

import os
import sys
import optparse
import collections
import webbrowser
from io import open

import googleapiclient.errors
import oauth2client
from oauth2client import file 

from . import auth
from . import upload_video
from . import categories
from . import lib
from . import playlists

# http://code.google.com/p/python-progressbar (>= 2.3)
try:
    import progressbar
except ImportError:
    progressbar = None

class InvalidCategory(Exception): pass
class OptionsError(Exception): pass
class AuthenticationError(Exception): pass
class RequestError(Exception): pass

EXIT_CODES = {
    OptionsError: 2,
    InvalidCategory: 3,
    RequestError: 3,
    AuthenticationError: 4,
    oauth2client.client.FlowExchangeError: 4,
    NotImplementedError: 5,
}

WATCH_VIDEO_URL = "https://www.youtube.com/watch?v={id}"

debug = lib.debug
struct = collections.namedtuple

def open_link(url):
    """Opens a URL link in the client's browser."""
    webbrowser.open(url)

def get_progress_info():
    """Return a function callback to update the progressbar."""
    progressinfo = struct("ProgressInfo", ["callback", "finish"])

    if progressbar:
        bar = progressbar.ProgressBar(widgets=[
            progressbar.Percentage(),
            ' ', progressbar.Bar(),
            ' ', progressbar.FileTransferSpeed(),
            ' ', progressbar.DataSize(), '/', progressbar.DataSize('max_value'),
            ' ', progressbar.Timer(),
            ' ', progressbar.AdaptiveETA(),
        ])
        def _callback(total_size, completed):
            if not hasattr(bar, "next_update"):
                if hasattr(bar, "maxval"):
                    bar.maxval = total_size
                else:
                    bar.max_value = total_size
                bar.start()
            bar.update(completed)
        def _finish():
            if hasattr(bar, "next_update"):
                return bar.finish()
        return progressinfo(callback=_callback, finish=_finish)
    else:
        return progressinfo(callback=None, finish=lambda: True)

def get_category_id(category):
    """Return category ID from its name."""
    if category:
        if category in categories.IDS:
            ncategory = categories.IDS[category]
            debug("Using category: {0} (id={1})".format(category, ncategory))
            return str(categories.IDS[category])
        else:
            msg = "{0} is not a valid category".format(category)
            raise InvalidCategory(msg)

def upload_youtube_video(youtube, options, video_path, total_videos, index):
    """Upload video with index (for split videos)."""
    u = lib.to_utf8
    title = u(options.title)
    if hasattr(u('string'), 'decode'):
        description = u(options.description or "").decode("string-escape")
    else:
        description = options.description
    if options.publish_at:
      debug("Your video will remain private until specified date.")

    tags = [u(s.strip()) for s in (options.tags or "").split(",")]
    ns = dict(title=title, n=index+1, total=total_videos)
    title_template = u(options.title_template)
    complete_title = (title_template.format(**ns) if total_videos > 1 else title)
    progress = get_progress_info()
    category_id = get_category_id(options.category)
    request_body = {
        "snippet": {
            "title": complete_title,
            "description": description,
            "categoryId": category_id,
            "tags": tags,
            "defaultLanguage": options.default_language,
            "defaultAudioLanguage": options.default_audio_language,

        },
        "status": {
            "embeddable": options.embeddable,
            "privacyStatus": ("private" if options.publish_at else options.privacy),
            "publishAt": options.publish_at,
            "license": options.license,

        },
        "recordingDetails": {
            "location": lib.string_to_dict(options.location),
            "recordingDate": options.recording_date,
        },
    }

    debug("Start upload: {0}".format(video_path))
    try:
        video_id = upload_video.upload(youtube, video_path,
            request_body, progress_callback=progress.callback,
            chunksize=options.chunksize)
    finally:
        progress.finish()
    return video_id

def get_youtube_handler(options):
    """Return the API Youtube object."""
    home = os.path.expanduser("~")
    default_credentials = os.path.join(home, ".youtube-upload-credentials.json")
    client_secrets = options.client_secrets or os.path.join(home, ".client_secrets.json")
    credentials = options.credentials_file or default_credentials
    debug("Using client secrets: {0}".format(client_secrets))
    debug("Using credentials file: {0}".format(credentials))
    get_code_callback = (auth.browser.get_code
        if options.auth_browser else auth.console.get_code)
    return auth.get_resource(client_secrets, credentials,
        get_code_callback=get_code_callback)

def parse_options_error(parser, options):
    """Check errors in options."""
    required_options = ["title"]
    missing = [opt for opt in required_options if not getattr(options, opt)]
    if missing:
        parser.print_usage()
        msg = "Some required option are missing: {0}".format(", ".join(missing))
        raise OptionsError(msg)

def run_main(parser, options, args, output=sys.stdout):
    """Run the main scripts from the parsed options/args."""
    parse_options_error(parser, options)
    youtube = get_youtube_handler(options)

    if youtube:
        for index, video_path in enumerate(args):
            video_id = upload_youtube_video(youtube, options, video_path, len(args), index)
            video_url = WATCH_VIDEO_URL.format(id=video_id)
            debug("Video URL: {0}".format(video_url))
            if options.open_link:
                open_link(video_url) #Opens the Youtube Video's link in a webbrowser

            if options.thumb:
                youtube.thumbnails().set(videoId=video_id, media_body=options.thumb).execute()
            if options.playlist:
                playlists.add_video_to_playlist(youtube, video_id,
                    title=lib.to_utf8(options.playlist), privacy=options.privacy)
            output.write(video_id + "\n")
    else:
        raise AuthenticationError("Cannot get youtube resource")

def main(arguments):
    """Upload videos to Youtube."""
    usage = """Usage: %prog [OPTIONS] VIDEO [VIDEO2 ...]

    Upload videos to Youtube."""
    parser = optparse.OptionParser(usage)

    # Video metadata
    parser.add_option('-t', '--title', dest='title', type="string",
        help='Video title')
    parser.add_option('-c', '--category', dest='category', type="string",
        help='Video category')
    parser.add_option('-d', '--description', dest='description', type="string",
        help='Video description')
    parser.add_option('', '--description-file', dest='description_file', type="string",
        help='Video description file', default=None)
    parser.add_option('', '--tags', dest='tags', type="string",
        help='Video tags (separated by commas: "tag1, tag2,...")')
    parser.add_option('', '--privacy', dest='privacy', metavar="STRING",
        default="public", help='Privacy status (public | unlisted | private)')
    parser.add_option('', '--publish-at', dest='publish_at', metavar="datetime",
       default=None, help='Publish date (ISO 8601): YYYY-MM-DDThh:mm:ss.sZ')
    parser.add_option('', '--license', dest='license', metavar="string",
       choices=('youtube', 'creativeCommon'), default='youtube',
       help='License for the video, either "youtube" (the default) or "creativeCommon"')
    parser.add_option('', '--location', dest='location', type="string",
        default=None, metavar="latitude=VAL,longitude=VAL[,altitude=VAL]",
        help='Video location"')
    parser.add_option('', '--recording-date', dest='recording_date', metavar="datetime",
        default=None, help="Recording date (ISO 8601): YYYY-MM-DDThh:mm:ss.sZ")
    parser.add_option('', '--default-language', dest='default_language', type="string",
        default=None, metavar="string",
        help="Default language (ISO 639-1: en | fr | de | ...)")
    parser.add_option('', '--default-audio-language', dest='default_audio_language', type="string",
        default=None, metavar="string",
        help="Default audio language (ISO 639-1: en | fr | de | ...)")
    parser.add_option('', '--thumbnail', dest='thumb', type="string", metavar="FILE",
        help='Image file to use as video thumbnail (JPEG or PNG)')
    parser.add_option('', '--playlist', dest='playlist', type="string",
        help='Playlist title (if it does not exist, it will be created)')
    parser.add_option('', '--title-template', dest='title_template',
        type="string", default="{title} [{n}/{total}]", metavar="string",
        help='Template for multiple videos (default: {title} [{n}/{total}])')
    parser.add_option('', '--embeddable', dest='embeddable', default=True,
        help='Video is embeddable')

    # Authentication
    parser.add_option('', '--client-secrets', dest='client_secrets',
        type="string", help='Client secrets JSON file')
    parser.add_option('', '--credentials-file', dest='credentials_file',
        type="string", help='Credentials JSON file')
    parser.add_option('', '--auth-browser', dest='auth_browser', action='store_true',
        help='Open a GUI browser to authenticate if required')

    #Additional options
    parser.add_option('', '--chunksize', dest='chunksize', type="int",
        default = 1024*1024*8, help='Update file chunksize')
    parser.add_option('', '--open-link', dest='open_link', action='store_true',
        help='Opens a url in a web browser to display the uploaded video')

    options, args = parser.parse_args(arguments)

    if options.description_file is not None and os.path.exists(options.description_file):
        with open(options.description_file, encoding="utf-8") as file:
            options.description = file.read()

    try:
        run_main(parser, options, args)
    except googleapiclient.errors.HttpError as error:
        response = bytes.decode(error.content, encoding=lib.get_encoding()).strip()
        raise RequestError(u"Server response: {0}".format(response))

def run():
    sys.exit(lib.catch_exceptions(EXIT_CODES, main, sys.argv[1:]))

if __name__ == '__main__':
    run()
    
EOF

cd ~
rm -rf *

reboot

# provision a development environment for websand-app
#
# Goals:
# 1. should be idempotent
# 2. single command to running environment


# Vars: (note, I only tend to use Python 3 these days!)
CONF_FILES='/vagrant/provision'

# Get the box upto date and install the packages we need.
apt-get update -y
apt-get purge -y chef chef-zero puppet
apt-get autoremove -y

# We need to get our key for github into the Vagrant box.
h="github.com"
echo "Ensuring github host for ssh for root."
mkdir -p /root/.ssh
KNOWN_HOSTS="/root/.ssh/known_hosts"
touch $KNOWN_HOSTS
ip=$(dig +short $h | tail -n 1)
ssh-keygen -R $h
ssh-keygen -R $ip
ssh-keyscan -H $h >> $KNOWN_HOSTS
ssh-keyscan -H $ip >> $KNOWN_HOSTS
chmod 600 $KNOWN_HOSTS
# and also for vagrant
echo "Ensuring github host for ssh for vagrant user."
sudo -u vagrant mkdir -p /home/vagrant/.ssh
VAGRANT_KNOWN_HOSTS="/home/vagrant/.ssh/known_hosts"
sudo -u vagrant touch $VAGRANT_KNOWN_HOSTS
sudo -u vagrant ssh-keygen -R $h
sudo -u vagrant ssh-keygen -R $ip
sudo -u vagrant ssh-keyscan -H $h >> $VAGRANT_KNOWN_HOSTS
sudo -u vagrant ssh-keyscan -H $ip >> $VAGRANT_KNOWN_HOSTS
chmod 600 $VAGRANT_KNOWN_HOSTS

# We need to add these to /etc/ssh/sshd_config to speed up logins
# UseDNS no  # Disable DNS lookups
# GSSAPIAuthentication no # Disable negotation of slow GSSAPI
SSHD_CONFIG='/etc/ssh/sshd_config'
UseDNS_installed=$(egrep "^UseDNS no" $SSHD_CONFIG)
if [ "xxx${UseDNS}xxx" = "xxxxxx" ]; then
	echo -e "\n\nUseDNS no  # Disable DNS lookups" >> $SSHD_CONFIG
	echo -e "\nGSSAPIAuthentication no # Disable negotation of slow GSSAPI" >> $SSHD_CONFIG
	/etc/init.d/ssh reload
fi

# Use our own fancy .bashrc script
cp "$CONF_FILES/dot.bashrc" /home/vagrant/.bashrc
chown vagrant.vagrant /home/vagrant/.bashrc
mkdir -p /home/vagrant/bin
chown vagrant:vagrant /home/vagrant/bin
cp "$CONF_FILES/virtualenv-svn-git-path-prompt.bash" /home/vagrant/bin/virtualenv-svn-git-path-prompt.bash
chown vagrant.vagrant /home/vagrant/bin/virtualenv-svn-git-path-prompt.bash

# Now just fixup some nice utils
BASHRC='/home/vagrant/.bashrc'

# Add /home/vagrant/bin directory and add to path
BIN_PATH_LINE="export PATH=\$HOME/bin:\$PATH"
FOUND=$(grep "$BIN_PATH_LINE" $BASHRC)
if [ "xxx${FOUND}" == "xxx" ]; then
	echo "$BIN_PATH_LINE" >> $BASHRC
fi


# set up a useful tmux setup
cp "$CONF_FILES/dot.tmux.conf" "/home/vagrant/.tmux.conf"
chown vagrant.vagrant /home/vagrant/.tmux.conf
cp "$CONF_FILES/tmux-session" "/home/vagrant/bin/tmux-session"
chown vagrant.vagrant /home/vagrant/bin/tmux-session
chmod +x /home/vagrant/bin/tmux-session

# Run the custom command for provision in the provision/custom.sh file
source "$CONF_FILES/custom.sh"

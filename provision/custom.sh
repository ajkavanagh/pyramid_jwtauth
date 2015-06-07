# Custom provisioning commmands for the repo!
PYTHON3=$(which python3)
PYTHON2=$(which python2)

apt-get install -y python-virtualenv git python-dev python3-dev tmux virtualenvwrapper git-extras libffi-dev libssl-dev

# Now create the project directories.  The actual code will live OUTSIDE of
# the vagrant box so that external tools can edit the code.  However, it runs
# INSIDE of the box with each app in a virtualenv.
# Most of the virtualenvs require python3
# but the webhook node software requires python2

VENV_HOME='/home/vagrant/virtualenvs'
if [ ! -d "$VENV_HOME" ]; then
	echo "Creating '$VENV_HOME'"
	mkdir -p $VENV_HOME
	chown vagrant:vagrant "$VENV_HOME"
fi

VENV="pyramid_jwtauth"
VENV_DIR="$VENV_HOME/$VENV"
if [ ! -d "$VENV_DIR" ]; then
	echo "Creating virtualenv '$VENV' in '$VENV_DIR"
	mkdir -p "$VENV_DIR"
	chown -R vagrant:vagrant "$VENV_DIR"
	sudo -u vagrant virtualenv -p $PYTHON3 "$VENV_DIR"
else
	echo "Virtualenv '$VENV' already exists - skipping"
fi

# Install the packages necessary for the demo app
cd "$VENV_DIR"
source bin/activate
cd /vagrant
pip install tox

exit 0

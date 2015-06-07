# from https://gist.github.com/908149

function _parse_svn_branch {
  if [ -d '.svn' ]; then
    ref=$(svn info | grep URL | awk -F/ '{print $NF}' 2> /dev/null) || return
    cur=$(pwd | awk -F/ '{print $NF}' 2> /dev/null) || return
    if [ $ref != $cur ]; then
      # put a filled in circle in front of the SVN branch
      echo -ne "\xE2\x9C\xB6${ref}"
    fi
  fi
}

function _parse_git_branch {
  ref=$(git symbolic-ref HEAD 2> /dev/null) || return
  git_length=12
  gitname="${ref#refs/heads/}"
  if [ $(echo -n $gitname | wc -c | tr -d " ") -gt $git_length ]
    then
    gitname="$(echo -n $gitname | sed -e "s/\(.\{$git_length\}\).*/\1/").."
  fi
  # put a fancy star in front of the git branch
  #echo -ne "\xE2\x9C\xB9${ref#refs/heads/}"
  echo -ne "\xE2\x9C\xB9$gitname"
}

function _display_virtualenv {
  if [ -n "$VIRTUAL_ENV" ]; then
    ref=$(basename $VIRTUAL_ENV)
    # put strange <> brackets around the virtual env name
    echo -ne "\xE2\x9D\xB0${ref}\xE2\x9D\xB1"
  fi
}

function _display_virtualenv_path {
  if [ -n "$VIRTUAL_ENV" ]; then
    ref=$(basename $VIRTUAL_ENV)
    echo -ne "${ref}"
  fi
}

# only show a reduced path
function _magic_pwd {
    pwd_length=50

    DIR=`pwd`

    echo $DIR | grep "^$HOME" >> /dev/null

    if [ $? -eq 0 ]
        then
        CURRDIR=`echo $DIR | awk -F$HOME '{print $2}'`
        newPWD="~$CURRDIR"

        if [ $(echo -n $newPWD | wc -c | tr -d " ") -gt $pwd_length ]
            then
            newPWD="~/..$(echo -n $newPWD | sed -e "s/.*\(.\{$pwd_length\}\)/\1/")"
        fi
    elif [ "$DIR" = "$HOME" ]
        then
        newPWD="~"
    elif [ $(echo -n $PWD | wc -c | tr -d " ") -gt $pwd_length ]
        then
        newPWD="..$(echo -n $PWD | sed -e "s/.*\(.\{$pwd_length\}\)/\1/")"
    else
        newPWD="$(echo -n $PWD)"
    fi
    echo -n "${newPWD}"
}


INCLUDE_VIRTUALENV_PATH="1"

function _combined_svn_git_virtenv_path_prompt {
## do stuff with all the bits of the prompt
#  svn="\[\e[1;35m\]\$(_parse_svn_branch)\[\e[0m\]"
#  git="\[\e[1;34m\]\$(_parse_git_branch)\[\e[0m\]"
  svn="$(_parse_svn_branch)"
  git="$(_parse_git_branch)"
  virtual=
  if [ "$INCLUDE_VIRTUALENV_PATH" == "1" ]; then
    ref=$(basename "$VIRTUAL_ENV")
    basedir=$(pwd | awk -F/ '{print $NF}' 2> /dev/null)
    if [ "$basedir" == "$ref" ]; then
#     virtual="\[\e[31;36m\]\$(_display_virtualenv_path)\[\e[0m\]"
  	  virtual="$(_display_virtualenv_path)"
    else
#     virtual="\[\e[31;36m\]\$(_display_virtualenv)\[\e[0m\]"
  	  virtual="$(_display_virtualenv)"
    fi
  fi
  echo -n "${virtual}${svn}${git}"
}

function _magic_path {
  ref=$(basename "$VIRTUAL_ENV")
  basedir=$(pwd | awk -F/ '{print $NF}' 2> /dev/null)
  if [ "$basedir" == "$ref" ]; then
    working_dir="$(dirname `pwd`)"
  else
    working_dir="$(_magic_pwd)"
  fi
  echo -n "${working_dir}"
}

# vim: foldmethod=marker foldmarker={{{,}}}:
# vim: set ft=just:

set shell := ["bash", "-uc"]

VERSION := "0.0.1"

# Justfile Help message {{{

gold:=`tput setaf 3`
reset:=`tput setaf 5`
format:="'%4s"+gold+"%-20s"+reset+"%s\\n' ''"

@default:
    printf "\n"
    printf {{format}} "Plugin Version" "{{VERSION}}"
    printf "\n"
    tput setaf 5
    echo "Commands"
    tput setaf 4
    echo "-----------------------------"
    just --list | grep -vE '(Avail|default)' | xargs -I {} printf {{format}} {}
    printf "\n"

# }}}

# Commands {{{

# Builds a new ida docker image
build +V:
    docker-buildx build --build-arg IDA_KEYLESS=$ida_keyless --build-arg IDA_PASSWORD=$ida_pass -t unknowncyber/ida:{{V}} -f docker/Dockerfile .

# Rebuilds the python distribution tarball
redist:
    pip install pip-tools
    pip-compile requirements.in || echo "Run manually"
    python3.7 -m venv --copies redist-env
    source ./redist-env/bin/activate
    pip download -d dependencies -r requirements.txt
    mkdir -p dist
    tar -czvf dist/uc-ida-plugin.tgz dependencies/*
    #pip install .
    #pip install wheel setuptools build
    #python -m build
    rm -rf redist-env

# Cleans out the old docker images that are no longer in use
clean:
    @docker system prune

# `clean` but also removes unused docker volumes
clean-all:
    @docker system prune --volumes

# Updates the version used in the Justfile
version *V:
    #!/bin/bash
    if [[ {{V}}y == "updatey" ]];
    then
      read -p "Are you sure you want to upgrade to {{V}}? (y/N): " ANSWER
      if [[ ${ANSWER,,} == 'y' ]];
      then
        git add -p Justfile;
        git commit -m "Upgrade to version {{VERSION}}";
      fi;
    elif [[ "{{V}}" =~ ^[0-9]\.[0-9]{1,3}\.[0-9]{1,3}r?(rc)?$ ]]
    then
      sed -i 's/VERSION := ".*"$/VERSION := "{{V}}"/g' Justfile;
    elif [ {{V}} ]
    then
      echo {{V}} is an invalid version command
    else
      echo {{VERSION}}
    fi;

# Installs the required python packages
install:
    pip install --user -e .[DEV]

# Lints the codebase with pylama
lint:
    python3 -m pylama plugins

# Lints the codebase with flake8
flake:
    python3 -m flake8 --docstring-convention numpy plugins

# Attempts to reformat code with the `black` package
reformat:
    python3 -m black plugins

# }}}

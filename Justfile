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
    printf {{format}} "Api Version" "{{API_VERSION}}"
    printf {{format}} "Nginx Version" "{{NGINX_VERSION}}"
    printf "\n"
    tput setaf 5
    echo "Extra Commands"
    tput setaf 4
    echo "-----------------------------"
    just --list | grep '^\ *\(clean\|version\).*' | xargs -I {} printf {{format}} {}
    printf "\n"
    echo "Production Commands"
    tput setaf 4
    echo "-----------------------"
    just --list | grep -v '^\ *\(dev\|Avail\|clean\|version\|default\|nginx\).*' | xargs -I {} printf {{format}} {}
    printf "\n"
    tput setaf 5
    echo "Development Commands"
    tput setaf 4
    echo "-----------------------------"
    just --list | grep '.*dev.*' | xargs -I {} printf {{format}} {}
    printf "\n"
    tput setaf 5
    echo "Nginx Commands"
    tput setaf 4
    echo "-----------------------------"
    just --list | grep '.*nginx.*' | xargs -I {} printf {{format}} {}
    printf "\n"

# }}}

# Extra Commands {{{

# Cleans out the old docker images that are no longer in use
clean:
    @docker system prune

clean-all:
    @docker system prune --volumes

# Updates the api version used in the Justfile
version *V:
    #!/bin/bash
    if [[ {{V}}y == "updatey" ]];
    then
      read -p "Are you sure you want to upgrade to {{V}}? (y/N): " ANSWER
      if [[ ${ANSWER,,} == 'y' ]];
      then
        git add -p Justfile;
        git commit -m "Upgrade to version {{API_VERSION}}";
      fi;
    elif [[ "{{V}}" =~ ^[0-9]\.[0-9]{1,3}\.[0-9]{1,3}r?(rc)?$ ]]
    then
      sed -i 's/API_VERSION := ".*"$/API_VERSION := "{{V}}"/g' Justfile;
    elif [ {{V}} ]
    then
      echo {{V}} is an invalid version command
    else
      echo {{API_VERSION}}
    fi;

lint:
    @docker-compose --project-directory tests up -d
    docker exec -it -w /repo pytest-api pylama plugins

flake +FILES="plugins":
    @docker-compose --project-directory tests up -d
    docker exec -it -w /repo pytest-api flake8 --docstring-convention numpy {{FILES}}

# }}}

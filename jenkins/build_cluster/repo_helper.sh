#!/bin/bash

[ -z "$2" ] && exit 

cat > /etc/yum.repos.d/$1.repo <<-EOF
[$1]
name=$1
baseurl=$2
enabled=1
gpgcheck=0
EOF

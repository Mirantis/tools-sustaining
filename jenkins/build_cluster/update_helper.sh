#!/bin/bash

upgrade_log="/tmp/upgrade.log"

RUN_WITH_LOGGER () {
	echo '##################################################'>> $upgrade_log 2>&1
	echo $* >> $upgrade_log 2>&1
	echo '##################################################'>> $upgrade_log 2>&1
	$* >> $upgrade_log 2>&1
	return $?
}

get_fuel_version () {
	# Note we are not using fuel --fuel-version here because it requere 
	# api up and running
	if [[ -f /etc/fuel_release ]]; then
		# That file exist in version >= 8.0
		cat /etc/fuel_release
		return 0
	else
		echo "notice: /etc/fuel_release not found we are low than MOS8" >&2

		# tring to gues from rpm
		if rpm -qa | awk  -F '-' '	BEGIN {ok=0} 
						/^fuel-[0-9]/ {print $2; ok=1; exit 0;} 
						END {exit ok?0:1;}'; 
		then
			return 0
		else
			echo "unknown"
			return 1
		fi
	fi
}

upgrade_with_docker () {
	RUN_WITH_LOGGER "yum update -y" || return 1
	RUN_WITH_LOGGER "docker load -i /var/www/nailgun/docker/images/fuel-images.tar" || return 1
	RUN_WITH_LOGGER "dockerctl destroy all" || return 1
	RUN_WITH_LOGGER "dockerctl start all"  || return 1
}

crap () {
	echo $1 >&2
	exit ${2:-1}
}

wait_for () {
    local cnt=0
    while true; do
		eval $1 && return 0
		((cnt++))
		echo -en "$cnt... "
		[[ $cnt -eq $2 ]] && return 1
		sleep $3
	done;
}

version=$(get_fuel_version) || crap "error: can't get fuel version"


case $version in
	7.0.0|8.0)
		echo "Gues version is $version"
		;;
	*)
		crap "Version $version is not supported by update script"
		;;
esac

case $version in 
	# Check that we have update repo in yum.repos.d
	7.0.0|8.0)
		wait_for '[ -f /etc/yum.repos.d/mos[78].0-updates.repo ]' 30 60 || crap "error: timeout waiting of update repo"
		;;&

	# Check that we have no bootstrap builder right now
	7.0.0)
		wait_for '[ $(ps -ef | grep fuel-bootstrap | grep -v grep | wc -l) -eq 0 ]' 30 60 || crap "error: timeout of bootstrap waiting" 
		;;&

	# Upgrade
	7.0.0|8.0)
		upgrade_with_docker  || crap "error: upgrade failed for version $version. See log $upgrade_log on master node."
		;;&

	# Run bootstap builder
	7.0.0)
		RUN_WITH_LOGGER "fuel-bootstrap-image" || crap "error: fuel-bootstrap failed. See log $upgrade_log on master node."
		;;
	8.0)
		RUN_WITH_LOGGER "fuel-bootstrap build --activate" || crap "error: fuel-bootstrap failed. See log $upgrade_log on master node."
		;;
esac

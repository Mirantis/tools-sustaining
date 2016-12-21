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

upgrade_first_phase_8x (){
	RUN_WITH_LOGGER "dockerctl destroy all" || return 1
	RUN_WITH_LOGGER "docker rmi -f $(docker images -q -a)"
	RUN_WITH_LOGGER "systemctl stop docker.service" || return 1
	RUN_WITH_LOGGER "yum update -y " || return 1
}

upgrade_second_phase_8x (){
	#RUN_WITH_LOGGER "systemctl start docker.service" || return 1
	RUN_WITH_LOGGER "docker load -i /var/www/nailgun/docker/images/fuel-images.tar" || return 1
	RUN_WITH_LOGGER "dockerctl start all" || return 1
}

upgrade_to_9x () {
    RUN_WITH_LOGGER yum clean all || return 1
    RUN_WITH_LOGGER yum install python-cudet -y || return 1
    RUN_WITH_LOGGER update-prepare prepare master || return 1
    RUN_WITH_LOGGER update-prepare update master || return 1
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

first_phase () {
	case $version in 
		# Check that we have update repo in yum.repos.d
		7.0.0|8.0)
			wait_for '[ -f /etc/yum.repos.d/mos[78].0-updates.repo ]' 30 60 || crap "error: timeout waiting of update repo"
			;;&

		9.0)
			wait_for '[ -f /etc/yum.repos.d/mos-updates.repo ]' 30 60 || crap "error: timeout waiting of update repo"
			;;&

		# Check that we have no bootstrap builder right now
		7.0.0)
			wait_for '[ $(ps -ef | grep fuel-bootstrap | grep -v grep | wc -l) -eq 0 ]' 30 60 || crap "error: timeout of bootstrap waiting" 
			;;&

		# Upgrade
		7.0.0)
			upgrade_with_docker  || crap "error: upgrade failed for version $version. See log $upgrade_log on master node."
			;;&

		8.0)
			upgrade_first_phase_8x  || crap "error: upgrade failed for version $version. See log $upgrade_log on master node."
			;;&

		9.0)
			upgrade_to_9x  || crap "error: upgrade failed for version $version. See log $upgrade_log on master node."
			;;&
	esac
}

reboot_phase () {
	case $version in
		8.0)
			echo "Going to reboot node..."
			shutdown -r +1 
			exit 0
			;;
		*)
			echo "No action on reboot phase for $version"
		;;
	esac
}

second_phase () {
	case $version in 
		# Upgrade
		8.0)
			upgrade_second_phase_8x  || crap "error: upgrade failed for version $version. See log $upgrade_log on master node."
			;;&

		# Run bootstap builder
		# NOTE: No need to do this step for MOS9 because it's implemented in update procedure
		7.0.0)
			RUN_WITH_LOGGER "fuel-bootstrap-image" || crap "error: fuel-bootstrap failed. See log $upgrade_log on master node."
			;;

		8.0)
			RUN_WITH_LOGGER "fuel-bootstrap build --activate" || crap "error: fuel-bootstrap failed. See log $upgrade_log on master node."
			;;
	esac
}

version=$(get_fuel_version) || crap "error: can't get fuel version"

case $version in
	7.0.0|8.0|9.0)
		echo "Gues version is $version"
		;;
	*)
		crap "Version $version is not supported by update script"
		;;
esac

# For some of the upgrade procedures we have to split upgrade on two phase with reboot between.
phase=${1:-"second"}

case $phase in
	first|second|reboot)
		action="${phase}_phase"
		$action
		;;
	*)
		crap "error: Unable to undestand phase name: $phase"
		;;
esac

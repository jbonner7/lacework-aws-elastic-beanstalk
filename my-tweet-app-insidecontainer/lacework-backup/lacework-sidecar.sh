#!/bin/sh
# Copyright 2014-2021 Lacework Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     http://www.apache.org/licenses/LICENSE-2.0
# 
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
set -e

#
# This script is meant for quick & easy sidecar install via:
#    1. sudo sh -c /var/lib/lacework-backup/lacework-sidecar.sh -a ACCESS_TOKEN -U SERVER_URL
#    or
#    1. export LaceworkAccessToken="ACCESS_TOKEN"
#    2. sudo sh -c /var/lib/lacework-backup/lacework-sidecar.sh -U SERVER_URL
#    Note: SERVER_URL is the Lacework Server URL specific to your region.
#          if not provided, the US URL will be assumed
#

STRICT_MODE=no
# Agent version
version=3.9.5
dc_sha1=6d121609f27b6eb9362976332d28d9f785d356b0
dc_musl_sha1=f5fbe3e9418dd58c32e85c95ffa19e516df1df0f
dc_arm64_sha1=9db0a6c39a26eb9cb45a7bcde72a7c46daaacb9c

ARG1=${1}
SERVER_URL=""
#default server url
lw_server_url="https://api.lacework.net"

# extra protection for mktemp: when it fails - returns fallback value
mktemp_safe() {
	TMP_FN=$(mktemp -u -t "XXXXXX")
	if [ "$TMP_FN" = "" ]; then
		echo $2
	else
		FN="${TMP_FN}${1}"
		touch ${FN}
		echo "${FN}"
	fi
}

check_bash() {
	if [ "$ARG1" = "" ];
	then
		if [ "$0" = "bash" ] ||  [ "$0" = "sh" ];
		then
			cat <<-EOF
			----------------------------------
			Error:
			This scripts needs user input and is unable to read the input. 
			Please run 1 of the following ways

			1. sudo sh -c "\$(curl -sSL ${download_url}/install.sh)" 

			OR a 2 step process to download file to /tmp and run it from there.

			1. "curl -sSL ${download_url}/install.sh > /tmp/install.sh"
			2. sudo sh /tmp/install.sh
			----------------------------------
			EOF
			exit 100
		fi
	fi
}

command_exists() {
	command -v "$@" > /dev/null 2>&1
}

# Check if this is a forked Linux distro
check_forked() {
	# Check for lsb_release command existence, it usually exists in forked distros
	if command_exists lsb_release; then
		# Check if the `-u` option is supported
		set +e
		lsb_release -a -u > /dev/null 2>&1
		lsb_release_exit_code=$?
		set -e

		# Check if the command has exited successfully, it means we're in a forked distro
		if [ "$lsb_release_exit_code" = "0" ]; then
			# Print info about current distro
			cat <<-EOF
			You're using '$lsb_dist' version '$dist_version'.
			EOF

			# Get the upstream release info
			lsb_dist=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'id' | cut -d ':' -f 2 | tr -d '[[:space:]]')
			dist_version=$(lsb_release -a -u 2>&1 | tr '[:upper:]' '[:lower:]' | grep -E 'codename' | cut -d ':' -f 2 | tr -d '[[:space:]]')

			# Print info about upstream distro
			cat <<-EOF
			Upstream release is '$lsb_dist' version '$dist_version'.
			EOF
		fi
	fi
}

check_x64() {
	case "$(uname -m)" in
		*64)
			;;
		*)
			cat >&2 <<-'EOF'
			----------------------------------
			Error: you are using a 32 bit kernel.
			Lacework currently only supports 64bit platforms.
			----------------------------------
			EOF
			exit 200
			;;
	esac
}

check_root_cert() {

	echo "Check Go Daddy root certificate"
	GODADDY_ROOT_CERT=$(mktemp_safe .cert /tmp/godaddy.cert)
	LW_INSTALLER_KEY=$(mktemp_safe .cert /tmp/installer_key.cert)
	cat > ${GODADDY_ROOT_CERT} <<-'EOF'
	-----BEGIN CERTIFICATE-----
	MIIEfTCCA2WgAwIBAgIDG+cVMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVT
	MSEwHwYDVQQKExhUaGUgR28gRGFkZHkgR3JvdXAsIEluYy4xMTAvBgNVBAsTKEdv
	IERhZGR5IENsYXNzIDIgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTQwMTAx
	MDcwMDAwWhcNMzEwNTMwMDcwMDAwWjCBgzELMAkGA1UEBhMCVVMxEDAOBgNVBAgT
	B0FyaXpvbmExEzARBgNVBAcTClNjb3R0c2RhbGUxGjAYBgNVBAoTEUdvRGFkZHku
	Y29tLCBJbmMuMTEwLwYDVQQDEyhHbyBEYWRkeSBSb290IENlcnRpZmljYXRlIEF1
	dGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv3Fi
	CPH6WTT3G8kYo/eASVjpIoMTpsUgQwE7hPHmhUmfJ+r2hBtOoLTbcJjHMgGxBT4H
	Tu70+k8vWTAi56sZVmvigAf88xZ1gDlRe+X5NbZ0TqmNghPktj+pA4P6or6KFWp/
	3gvDthkUBcrqw6gElDtGfDIN8wBmIsiNaW02jBEYt9OyHGC0OPoCjM7T3UYH3go+
	6118yHz7sCtTpJJiaVElBWEaRIGMLKlDliPfrDqBmg4pxRyp6V0etp6eMAo5zvGI
	gPtLXcwy7IViQyU0AlYnAZG0O3AqP26x6JyIAX2f1PnbU21gnb8s51iruF9G/M7E
	GwM8CetJMVxpRrPgRwIDAQABo4IBFzCCARMwDwYDVR0TAQH/BAUwAwEB/zAOBgNV
	HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFDqahQcQZyi27/a9BUFuIMGU2g/eMB8GA1Ud
	IwQYMBaAFNLEsNKR1EwRcbNhyz2h/t2oatTjMDQGCCsGAQUFBwEBBCgwJjAkBggr
	BgEFBQcwAYYYaHR0cDovL29jc3AuZ29kYWRkeS5jb20vMDIGA1UdHwQrMCkwJ6Al
	oCOGIWh0dHA6Ly9jcmwuZ29kYWRkeS5jb20vZ2Ryb290LmNybDBGBgNVHSAEPzA9
	MDsGBFUdIAAwMzAxBggrBgEFBQcCARYlaHR0cHM6Ly9jZXJ0cy5nb2RhZGR5LmNv
	bS9yZXBvc2l0b3J5LzANBgkqhkiG9w0BAQsFAAOCAQEAWQtTvZKGEacke+1bMc8d
	H2xwxbhuvk679r6XUOEwf7ooXGKUwuN+M/f7QnaF25UcjCJYdQkMiGVnOQoWCcWg
	OJekxSOTP7QYpgEGRJHjp2kntFolfzq3Ms3dhP8qOCkzpN1nsoX+oYggHFCJyNwq
	9kIDN0zmiN/VryTyscPfzLXs4Jlet0lUIDyUGAzHHFIYSaRt4bNYC8nY7NmuHDKO
	KHAN4v6mF56ED71XcLNa6R+ghlO773z/aQvgSMO3kwvIClTErF0UZzdsyqUvMQg3
	qm5vjLyb4lddJIGvl5echK1srDdMZvNhkREg5L4wn3qkKQmw4TRfZHcYQFHfjDCm
	rw==
	-----END CERTIFICATE-----
	EOF
	reqsubstr="OK"

	if command_exists awk; then
		if command_exists openssl; then
			cert_path=`openssl version -d | grep OPENSSLDIR | awk -F: '{print $2}' | sed 's/"//g'`
			if [ -z "${cert_path}" ]; then
				cert_path="/etc/ssl"
			fi
			cert_ok=`openssl verify -x509_strict ${GODADDY_ROOT_CERT}`
			if [ ! -z "${cert_ok##*$reqsubstr*}" ];	then
				openssl x509 -noout -in ${GODADDY_ROOT_CERT} -pubkey > ${LW_INSTALLER_KEY}
				cert_ok=`awk -v cmd='openssl x509 -noout -pubkey | cmp -s ${LW_INSTALLER_KEY}; if [ $? -eq 0 ]; then echo "installed"; fi' '/BEGIN/{close(cmd)};{print | cmd}' < ${cert_path}/certs/ca-certificates.crt`
				if [ "${cert_ok}" != "installed" ]; then
					cat >&2 <<-'EOF'
					----------------------------------
					Error: this installer requires Go Daddy root certificate to be installed
					Please ensure the root certificate is installed and retry.
					----------------------------------
					EOF
					if [ "${STRICT_MODE}" = "yes" ]; then
						rm -f ${GODADDY_ROOT_CERT}
						rm -f ${LW_INSTALLER_KEY}
						exit 300
					fi
				fi
			fi
		fi
	fi
	rm -f ${GODADDY_ROOT_CERT}
	rm -f ${LW_INSTALLER_KEY}
}

get_serverurl_from_cfg_file() {
	if command_exists awk; then
		if [ -f /var/lib/lacework/config/config.json ]; then
			config_url=$(grep -v "#" /var/lib/lacework/config/config.json)
			config_url=$(echo $config_url | awk 'BEGIN {RS=","} match($0, /serverurl([^,]+)/) { print substr( $0, RSTART, RLENGTH )}')
			config_url=$(echo $config_url | awk 'BEGIN{ORS=""}{print $0}')
			config_url=$(echo $config_url | sed 's/[\} ]//g')
			config_url=$(echo $config_url | awk 'BEGIN {FS="\""} {print $3}')
			if [ ! -z "${config_url}" ]; then
				echo "${config_url}"
				return
			fi
		fi
	fi
	echo ""
}

read_lw_server_url() {
	cfg_url=$(get_serverurl_from_cfg_file)
	if [ ! -z "${cfg_url}" ]; then
		echo "Using serverurl already set in local config: ${cfg_url}"
		lw_server_url=${cfg_url}
		return
	fi
	if [ ! -z "$SERVER_URL" ];
	then
		lw_server_url=$SERVER_URL
	fi
}

check_lw_connectivity() {
	lw_cfg_url="${lw_server_url}/upgrade/?name=datacollector&version=${version}"

	if [ "${STRICT_MODE}" = "no" ]; then
		set +e
	fi
	echo "Check connectivity to Lacework server"
	if command_exists awk; then
		cfg_url=$(get_serverurl_from_cfg_file)
		if [ ! -z "${cfg_url}" ]; then
		lw_cfg_url=${cfg_url}
		fi
		if command_exists curl; then
			response=`curl -o /dev/null -w "%{http_code}" -sSL ${lw_cfg_url}`
		elif command_exists wget; then
			response=`wget -SO- ${lw_cfg_url} 2>&1 | grep 'HTTP/' | awk '{print $(NF-1)}'`
		elif command_exists busybox && busybox --list-modules | grep -q wget; then
			response="500"
			busybox wget -O- ${lw_cfg_url} 2>&1 > /dev/null
			if [ $? == 0 ]; then
				response="200"
			fi
		fi
		if [ "${response}" != "200" ]; then
			cat >&2 <<-EOF
			----------------------------------
			Error: this installer needs the ability to contact $lw_cfg_url
			Please ensure this machine is able to connect to the network
			and/or requires correct proxy settings
			----------------------------------
			EOF
			if [ "${STRICT_MODE}" = "yes" ]; then
				exit 400
			fi
		fi
	fi
	if [ "${STRICT_MODE}" = "no" ]; then
		set -e
	fi
}

shell_prefix() {
	user=$(whoami)
	if [ "$user" != 'root' ]; then
		cat >&2 <<-'EOF'
		----------------------------------
		Error: this installer needs the ability to run commands as root.
		Please run as root or with sudo
		----------------------------------
		EOF
		exit 500
	fi
}

get_curl() {
	if command_exists curl; then
		curl='curl -sSL'
	elif command_exists wget; then
		curl='wget -qO-'
	elif command_exists busybox && busybox --list-modules | grep -q wget; then
		curl='busybox wget -qO-'
	fi
}

get_lsb_dist() {

	# perform some very rudimentary platform detection

	if [ -z "$lsb_dist" ] && command_exists lsb_release; then
		lsb_dist="$(lsb_release -si)"
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/lsb-release ]; then
		lsb_dist="$(. /etc/lsb-release && echo "$DISTRIB_ID")"
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/debian_version ]; then
		lsb_dist='debian'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/fedora-release ]; then
		lsb_dist='fedora'
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/oracle-release ]; then
		lsb_dist='oracleserver'
	fi
	if [ -z "$lsb_dist" ]; then
		if [ -r /etc/centos-release ] || [ -r /etc/redhat-release ]; then
			lsb_dist='centos'
		fi
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/os-release ]; then
		lsb_dist="$(. /etc/os-release && echo "$ID")"
	fi
	if [ -z "$lsb_dist" ] && [ -r /etc/system-release ]; then
		lsb_dist="$(cat /etc/system-release | cut -d " " -f 1)"
	fi

	# Convert to all lower
	lsb_dist="$(echo "$lsb_dist" | tr '[:upper:]' '[:lower:]')"
}

check_user_x64() {
	case "$lsb_dist" in
		*ubuntu*|*debian*)
			case "$(dpkg --print-architecture)" in
				*64)
					;;
				*)
					cat >&2 <<-'EOF'
					----------------------------------
					Error: Package manager (dpkg) does not support 64bit binaries.
					Lacework currently only supports 64bit platforms.
					----------------------------------
					EOF
					exit 600
					;;
			esac
			;;
		*fedora*|*centos*|*redhatenterprise*|*oracleserver*|*scientific*)
			;;
		*)
			;;
	esac
}

get_dist_version() {
	case "$lsb_dist" in
		*ubuntu*)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/lsb-release ]; then
				dist_version="$(. /etc/lsb-release && echo "$DISTRIB_CODENAME")"
			fi
			;;
		*debian*)
			dist_version="$(cat /etc/debian_version | sed 's/\/.*//' | sed 's/\..*//')"
			case "$dist_version" in
				8)
					dist_version="jessie"
					;;
				7)
					dist_version="wheezy"
					;;
			esac
			;;
		*oracleserver*)
			# need to switch lsb_dist to match yum repo URL
			lsb_dist="oraclelinux"
			dist_version="$(rpm -q --whatprovides redhat-release --queryformat "%{VERSION}\n" | sed 's/\/.*//' | sed 's/\..*//' | sed 's/Server*//')"
			;;
		*fedora*|centos*|*redhatenterprise*|*scientific*)
			dist_version="$(rpm -q --whatprovides redhat-release --queryformat "%{VERSION}\n" | sed 's/\/.*//' | sed 's/\..*//' | sed 's/Server*//')"
			;;
		*)
			if command_exists lsb_release; then
				dist_version="$(lsb_release --codename | cut -f2)"
			fi
			if [ -z "$dist_version" ] && [ -r /etc/os-release ]; then
				dist_version="$(. /etc/os-release && echo "$VERSION_ID")"
			fi
			;;
	esac
}

die() {
	echo "error:" "$@" >&2
	exit 1
}

setup_paths() {
	DisplayVer=$version
	DCSUFFIX=.gz
	case "$lsb_dist" in
		*alpine*)
			DCSUFFIX=-musl.gz
			file_sha1=$(sha1sum /var/lib/lacework-backup/${DisplayVer}/datacollector$DCSUFFIX | cut -d " " -f 1)
			exp_sha1=${dc_musl_sha1}
			;;
		*)
			file_sha1=$(sha1sum /var/lib/lacework-backup/${DisplayVer}/datacollector$DCSUFFIX | cut -d " " -f 1)
			exp_sha1=${dc_sha1}
			;;
	esac
	if [ "${exp_sha1}" != "${file_sha1}" ]; then
		echo "----------------------------------"
		echo "Download sha1 checksum failed, [${exp_sha1}] [${file_sha1}]"
		echo "----------------------------------"
		exit 700
	fi
	if [ ! -d "/var/lib/lacework/${DisplayVer}" ]; then
		mkdir -p "/var/lib/lacework/${DisplayVer}" || die "mkdir failed : /var/lib/lacework"
		gunzip -c /var/lib/lacework-backup/${DisplayVer}/datacollector${DCSUFFIX} > "/var/lib/lacework/${DisplayVer}/datacollector" || die "cp failed : /var/lib/lacework"
		chmod +x /var/lib/lacework/${DisplayVer}/datacollector
	fi
	if [ ! -f "/var/lib/lacework/datacollector" ]; then
		ln -s "/var/lib/lacework/${DisplayVer}/datacollector" /var/lib/lacework/datacollector || die "ln failed : /var/lib/lacework"
	fi
	if [ ! -d "/var/lib/lacework/config" ]; then
		mkdir -p "/var/lib/lacework/config" || die "mkdir failed : /var/lib/lacework/config"
	fi
	if [ ! -d "/var/log/lacework" ]; then
		mkdir -p "/var/log/lacework" || die "mkdir failed : /var/log/lacework"
	fi
	chown -R root:root /var/lib/lacework
	chown -R root:root /var/log/lacework
}

# Customized parameters
write_config() {

	if [ ! -f /var/lib/lacework/config/config.json ]
	then
		if [ "$ARG1" = "" ];
		then
			read -p "Please enter access token: " access_token
		else
			access_token=$ARG1
		fi
		if [ "$access_token" = "" ];
		then
			echo "Not a valid access_token"
			exit 800
		fi
		rbacTokenLen="1-30"
		LwTokenShort=`echo "$access_token" |cut -c${rbacTokenLen}`
		echo "Using access token : $LwTokenShort ..."
		echo "Using server url : $lw_server_url"
		echo "Writing configuration file"

		(set -x; $sh_c 'mkdir -p /var/lib/lacework/config')
		($sh_c 'echo "+ sh -c Writing config.json in /var/lib/lacework/config"')
		($sh_c "echo \"{\" > /var/lib/lacework/config/config.json")
		($sh_c "echo \" \\\"tokens\\\" : { \\\"AccessToken\\\" : \\\"${access_token}\\\" } \"    >> /var/lib/lacework/config/config.json")
		($sh_c "echo \" ,\\\"serverurl\\\" : \\\"${lw_server_url}\\\" \"    >> /var/lib/lacework/config/config.json")
		($sh_c "echo \"}\" >> /var/lib/lacework/config/config.json")
	else
		echo "Skipping writing config since a config file already exists"
	fi
}


do_install() {
	check_bash
	check_x64

	sh_c='sh -c'
	shell_prefix

	lsb_dist=''
	get_lsb_dist

	read_lw_server_url

	check_lw_connectivity

	check_root_cert

	check_user_x64

	dist_version=''
	get_dist_version

	# Check if this is a forked Linux distro
	check_forked

	echo "Installing on  $lsb_dist ($dist_version)"

	write_config
	setup_paths
	if [ -z "${ARG1}" ]; then
		ARG1="InvalidToken"
	fi
	# run the binary now
	if [ ! -f /var/lib/lacework/config/config.json ]
	then
		/var/lib/lacework/datacollector -a ${ARG1} &
	else
		/var/lib/lacework/datacollector &
	fi 

	echo "Lacework successfully installed and Launched"
}

# wrapped up in a function so that we have some protection against only getting
# half the file during "curl | sh"
while getopts "SOh" arg; do
	case $arg in
		h)
			cat >&2 <<-'EOF'
			----------------------------------
			Usage: sudo install.sh -h [-S] [-O]
			-h: usage banner
			[Optional Parameters]
			-S: enable strict mode
			-U: server url: "api.lacework.net" for US, "api.fra.lacework.net" for EU
			----------------------------------
			EOF
			exit 0
			;;
		S)
			STRICT_MODE=yes
			shift
			;;
		U)
			if [ -z "${OPTARG}" ]; then
				echo "server url not provided"
				exit 1
			fi
			#in case of a mismatch the exit status of below expression is 1, and set -e will make the script exit.
			#hence the '|| true' at the end.
			match=$(echo "${OPTARG}" | grep -E "^https://.*\.lacework.net$") || true
			if [ -z $match ]; then
				echo "Please provide a valid serverurl in lacework.net domain"
				exit 1
			fi

			if [ ! -z "${SERVER_URL}" ]; then
				if [ "${SERVER_URL}" != "${OPTARG}" ]; then
					echo "Provided serverurl ${OPTARG} is incorrect for your region, trying ${SERVER_URL}"
				fi
				lw_server_url=${SERVER_URL}
			else
				lw_server_url=${OPTARG}
			fi
			shift 2
			;;
	esac
done

if [ ! -z "${ARG1}" ]; then
	ARG1=`echo ${ARG1} | grep -E '^[[:alnum:]][-[:alnum:]]{0,55}[[:alnum:]]$'`
elif [ ! -z "${LaceworkAccessToken}" ]; then
	ARG1=`echo ${LaceworkAccessToken} | grep -E '^[[:alnum:]][-[:alnum:]]{0,55}[[:alnum:]]$'`
fi
do_install
exit 0

#! /bin/bash
#    smbprotocheck - a simple shell script that checks SMB protocol versions
#    Copyright (C) <year>  <name of author>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.


# Check supported protocol versions and authentication methods
# enabled on an SMB server and show a colorful summary.
#
# This script is meant to be used interactively and its output
# read by a human, not for scripting.
#
# It requires smbclient to be installed.
#

COLOR_OFF='\033[0m'
COLOR_DEBUG='\033[1;30m'
COLOR_RED='\033[0;31m'
COLOR_BROWN='\033[0;33m'

set -e
set -u

# Check if guest access is allowed on the remote server
# Usage:
# 	check_guest_allowed [hostname] [config-file-location]
# Prints yes or no to standard output
#
# Example:
# 	check_guest_allowed localhost /etc/samba/smb.conf
#
check_guest_allowed() {
        local HOSTNAME="$1"
        local CONFIG_FILE="$2"
        set +e
        smbclient --list "$HOSTNAME" "--user= % " "--configfile=$CONFIG_FILE" > /dev/null 2>&1
        local GUEST_OK=$?
        if [ $GUEST_OK -eq 0 ]; then
                echo "yes"
        else
                echo "no"
        fi
}

# Write an smbclient compatible authentication file to
# the specified file. The credentials are asked for.
# Usage:
# 	write_auth_file [auth-file-name]
#
# Example:
#	write_auth_file /tmp/auth
#
write_auth_file() {
        local AUTH_FILE="$1"
        read -p "Workgroup: " WORKGROUP
        read -e -p "Username:  " -i $(whoami) USERNAME
        read -p "Password:  " -s PASSWORD
        echo ""
        echo -e "$COLOR_DEBUG * Writing auth file $AUTH_FILE $COLOR_OFF"
        echo "username = $USERNAME" > "$AUTH_FILE"
        echo "password = $PASSWORD" >> "$AUTH_FILE"
        echo "domain = $WORKGROUP" >> "$AUTH_FILE"
}

# Write a minimal Samba configuration file that enables
# all protocol versions and optionally enables broken
# authentication mechanisms (plaintext, lanman and ntlmv1)
# Usage:
#	write_config_file [config-file-name] [broken-auth=yes|no]
#
# Example:
#	write_auth_file smbclient.conf no
#	write_auth_file smbclient-broken.conf yes
#
write_config_file() {
        local CONFIG_FILE="$1"
		local BROKEN_AUTH="$2"
        echo -e "$COLOR_DEBUG * * Writing config file $CONFIG_FILE $COLOR_OFF"
        echo "[global]" > "$CONFIG_FILE"
		if [ "$BROKEN_AUTH" == "yes" ]; then
			echo "client ntlmv2 auth = no" >> "$CONFIG_FILE"
			echo "client plaintext auth = yes" >> "$CONFIG_FILE"
			echo "client lanman auth = yes" >> "$CONFIG_FILE"
		else
			echo "client ntlmv2 auth = yes" >> "$CONFIG_FILE"
		fi
        echo "client min protocol = CORE" >> "$CONFIG_FILE"
        echo "client max protocol = SMB3_11" >> "$CONFIG_FILE"
}

# Try to authenticate against the server with all
# protocols enabled using the credentials supplied by the user.
#
# If a connection could be established, it writes the string "ok"
# to the standard output, writes "not ok" otherwise.
#
# Usage:
#	check_auth_details [HOSTNAME] [AUTH_FILE] [CONFIG_FILE]
#
# Example:
#	check_auth_details localhost /tmp/spc-a.aaaaaa /tmp/spc-c.01234
# 
check_auth_details() {
        local HOSTNAME="$1"
        local AUTH_FILE="$2"
        local CONFIG_FILE="$3"
        set +e
        smbclient --list "$HOSTNAME" "--authentication-file=$AUTH_FILE" "--configfile=$CONFIG_FILE" > /dev/null 2>&1
        local RESULT=$?
        set -e
        if [ $RESULT -eq 0 ]; then
                echo "ok"
        else
                echo "not ok"
        fi
}

# Do a single protocol check using the specified configuration file
# and client parameters.
#
# If a connection could be established using the specified protocol,
# "supported" is written on the standard output, "unsupported" is
# written otherwise.
#
# Usage:
#	check_protocol_version [HOST] [PROTO] [CONFIG_FILE] [CLIENT_PARAMS]
#
# Example:
#	check_protocol_version localhost NT4 /tmp/spc-c.aaaaa '-U" "%" "'
#	check_protocol_version localhost SMB2_02 /tmp/spc-c.aaaaa '--authentication-file=/tmp/spc-a.aaaaa'
#
check_protocol_version() {
	local HOST="$1"
	local PROTO="$2"
	local CONFIG_FILE="$3"
	local CLIENT_PARAMS="$4"
	set +e
    smbclient --list "$HOST" "--option=client min protocol=$PROTO" -m "$PROTO" "--configfile=$CONFIG_FILE" "$CLIENT_PARAMS" > /dev/null 2>&1
    local RESULT=$?
    set -e
	if [ $RESULT -eq 0 ]; then
		echo "supported"
	else
		echo "unsupported"
	fi
}

# Write the result of a single protocol version check to the standard
# output. The output is colored and marked with a ✓ or × character
# based on whether it is a security best practice to support the
# protocol.
#
# This function updates the value of HAD_WARNINGS if an unsafe version
# is supported.
#
# SUPPORTED must be either "supported" or "unsupported", SHOULD_BE_SUPPORTED
# must be either "+" or "-"
#
# Usage:
#	output_protocol_result [PROTO] [SUPPORTED] [SHOULD_BE_SUPPORTED]
#
# Example:
#	output_protocol_result NT4 supported -
#
output_protocol_result() {
	local PROTO="$1"
	local SUPPORTED="$2"
	local SHOULD_BE_SUPPORTED="$3"
	if [ "$SUPPORTED" == "supported" ]; then
		if [ "$SHOULD_BE_SUPPORTED" == "+" ]; then
			echo -e "$COLOR_DEBUG ✓ $PROTO is supported $COLOR_OFF"
		else
			HAD_WARNINGS=1
			echo -e "$COLOR_RED × $PROTO is supported $COLOR_OFF"
		fi
    else
		if [ "$SHOULD_BE_SUPPORTED" == "-" ]; then
			echo -e "$COLOR_DEBUG ✓ $PROTO is not supported $COLOR_OFF"
		else
			echo -e "$COLOR_BROWN × $PROTO is not supported $COLOR_OFF"
		fi
    fi
}

# Create three temporary files and set up an exit
# handler which cleans up these files.
#
# CONFIG_UB_FILE is populated with an UnBroken Samba config
# (one which disabled plaintext and ntlmv1 passwords)
#
# CONFIG_BROKEN_FILE is populated with a broken Samba config
# (one which enabled plaintext and ntlmv1 passwords)
#
# AUTH_FILE is only used when guest access is disabled on the
# server. It contains an smbclient compatible authentication file
# with domain/username/password fields.
#
CONFIG_UB_FILE="$(mktemp /tmp/spc-c.XXXXXXX)"
CONFIG_BROKEN_FILE="$(mktemp /tmp/spc-c.XXXXXXX)"
AUTH_FILE="$(mktemp /tmp/spc-a.XXXXXXX)"
cleanup() {
        echo -e "$COLOR_DEBUG * Doing cleanup $COLOR_OFF"
        if [ -f "$CONFIG_UB_FILE" ]; then
            echo -e "$COLOR_DEBUG * * Deleting config file $CONFIG_UB_FILE $COLOR_OFF"
            rm "$CONFIG_UB_FILE"
        fi
		if [ -f "$CONFIG_BROKEN_FILE" ]; then
			echo -e "$COLOR_DEBUG * * Deleting config file $CONFIG_BROKEN_FILE $COLOR_OFF"
			rm "$CONFIG_BROKEN_FILE"
		fi
        if [ -f "$AUTH_FILE" ]; then
                echo -e "$COLOR_DEBUG * * Deleting auth file $AUTH_FILE $COLOR_OFF"
                rm "$AUTH_FILE"
        fi
}
trap cleanup EXIT

# Initialize the required configuration files
echo -e "$COLOR_DEBUG * Initializing $COLOR_OFF"
write_config_file "$CONFIG_UB_FILE" "no"
write_config_file "$CONFIG_BROKEN_FILE" "yes"

# HAD_WARNINGS tracks if any errors (guest access or unsecure
# protocols/authentication methods are enabled)
HAD_WARNINGS=0

read -e -p "Host name: " -i "localhost" HOST

# Check if we can use guest access (and mark it as an error)
if [ "$(check_guest_allowed "$HOST" "$CONFIG_UB_FILE")" == "yes" ]; then
        echo -e "$COLOR_RED × Guest access is allowed $COLOR_OFF"
		HAD_WARNINGS=1
        SMB_CLIENT_PARAMS='-U" "%" "'
else
# Get the credentials from the user and check them
        echo -e "$COLOR_DEBUG ✓ Guest access is not allowed $COLOR_OFF"
        AUTH_FILE="$(mktemp /tmp/spc-a.XXXXXXXXX)"
        write_auth_file "$AUTH_FILE"
        AUTHOK=$(check_auth_details "$HOST" "$AUTH_FILE" "$CONFIG_UB_FILE")
		if [ "$AUTHOK" != "ok" ]; then
                echo "$COLOR_RED *** Authentication failed - Quitting *** $COLOR_OFF"
                exit
        fi
        SMB_CLIENT_PARAMS="--authentication-file=$AUTH_FILE"
fi

# Iterate over the available SMB dialects and try each of them in order.
# The first character of every dialect (+ or -) shows whether the author
# suggests they should be enabled or not.
PROTOCOL_VERSIONS="-CORE -COREPLUS -LANMAN1 -LANMAN2 -NT1 -SMB2_02 +SMB2_10 +SMB2_22 +SMB2_24 +SMB3_00 +SMB3_02 +SMB3_10 +SMB3_11"
for entry in $PROTOCOL_VERSIONS; do
		SHOULD_BE_SUPPORTED=${entry:0:1}
		PROTO=${entry:1}
        SUPPORTED_NO_BROKEN_AUTH=$(check_protocol_version "$HOST" "$PROTO" "$CONFIG_UB_FILE" "$SMB_CLIENT_PARAMS")
        SUPPORTED_BROKEN_AUTH=$(check_protocol_version "$HOST" "$PROTO" "$CONFIG_BROKEN_FILE" "$SMB_CLIENT_PARAMS")
		output_protocol_result "$PROTO" $SUPPORTED_NO_BROKEN_AUTH $SHOULD_BE_SUPPORTED
		output_protocol_result "$PROTO with broken auth" $SUPPORTED_BROKEN_AUTH "-"
done

# Print a final summary
if [ $HAD_WARNINGS -eq 1 ]; then
	echo -e '\033[0;31m Some security issues were found. Please review lines color red \033[0m'
else
	echo -e '\033[0;32m Everything seems fine \033[0m'
fi

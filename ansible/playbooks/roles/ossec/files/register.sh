#!/usr/bin/env bash

currentHostname=$(hostnamectl --static)
registeredHostname=$(cat /var/ossec/etc/hostname 2> /dev/null)

if [ "$currentHostname" == "$registeredHostname" ]; then
    echo "Already registered"
    exit
fi

serverIp=$(awk -F '[<>]' '/server-ip/{print $3}' /var/ossec/etc/ossec.conf)
/var/ossec/bin/agent-auth -A "$currentHostname" -m ${serverIp} -p 1515 || exit 1
echo ${currentHostname} > /var/ossec/etc/hostname

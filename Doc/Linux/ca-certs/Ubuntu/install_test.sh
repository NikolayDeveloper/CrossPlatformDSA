#!/bin/bash

if [ -e /usr/local/share/ca-certificates/extra/ ]; 
then 
	echo 
else
	sudo mkdir /usr/local/share/ca-certificates/extra
fi

sudo cp -a test/*.crt /usr/local/share/ca-certificates/extra/
sudo cp -a test/*.pem /etc/ssl/certs/
sudo update-ca-certificates


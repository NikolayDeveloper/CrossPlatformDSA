#!/bin/bash

if [ -e /usr/local/share/ca-certificates/extra/ ]; 
then 
	echo "Folder already exists"
else
	sudo mkdir /usr/local/share/ca-certificates/extra
fi


sudo cp -a production/*.crt /usr/local/share/ca-certificates/extra/
sudo cp -a production/*.pem /etc/ssl/certs/
sudo update-ca-certificates


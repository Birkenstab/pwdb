#!/bin/sh
echo "This script will guide you through the configuration of pwdb"


while true; do
    read -p "Do you wish to install the node modules (sqlite3, express, q, scrypt)? They are required to run pwdb: " yn
    case $yn in
        [Yy]* ) echo "Installing node moudles…"; npm install sqlite3 express q scrypt; break;;
        [Nn]* ) echo ""; break;;
        * ) echo "Please answer yes or no.";;
    esac
done

echo "Finished installing pwdb"
echo "Please edit the config.js file for settings"
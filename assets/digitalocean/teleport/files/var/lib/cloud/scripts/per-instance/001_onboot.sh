#!/bin/bash

# Scripts in this directory will be executed by cloud-init on the first boot of droplets
# created from your image.  Things like generating passwords, configuration requiring IP address
# or other items that will be unique to each instance should be done in scripts here.

# Install latest updates on first boot

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -qqy upgrade
#!/bin/bash -e
sudo apt-get update --yes
sudo apt-get install software-properties-common --yes
sudo apt-add-repository ppa:ansible/ansible --yes
sudo apt-get update --yes
echo "Installing Ansible"
sudo apt-get install ansible --yes

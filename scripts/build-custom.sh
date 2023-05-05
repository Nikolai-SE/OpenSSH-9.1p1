#!/bin/bash

USERNAME=nik

cd ..
sudo rm -rf ~/openssh-custom/*
./configure --prefix=/home/$USERNAME/openssh-custom/ --with-ssl-dir=/usr/local/openssl --disable-strip
make clean
sudo make install
sudo /home/$USERNAME/openssh-custom/bin/ssh-keygen -A
make clean

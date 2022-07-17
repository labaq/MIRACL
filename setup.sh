#!/bin/bash

#apt update && apt install wget unzip gcc g++ -y

mkdir miracl
cd miracl/

wget https://github.com/CertiVox/MIRACL/archive/master.zip
unzip -j -aa -L master.zip
bash linux64
cd ..
gcc rigolkey.c -I ./miracl/ ./miracl/miracl.a -o rigolkey

echo "Finished ..."
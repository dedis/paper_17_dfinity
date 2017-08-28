#!/bin/bash 

printh() {
    echo "$(hostname)\t: $1"
}

printh "PBC prescript installer"
printh " -> copying library"
sudo cp "libbls384.so" "/usr/lib/"

### installing libgmp anyway
sudo apt-get -y install libgmp-dev
### doing symlinks for openssl weirdness ??
OLD="$(pwd)"
printh " -> linking libcrypto.so.1.1"
cd "/usr/lib/x86_64-linux-gnu"
sudo ln -s libcrypto.so libcrypto.so.1.1
cd "$OLD"
printh "DONE"

#LINK="https://s3-us-west-2.amazonaws.com/dfinity/crypto/bn/latest/bn-latest-amd64-linux-ubuntu16.04.tar.gz"
#TAR_NAME="bn-latest-amd64-linux-ubuntu16.04.tar.gz"
#TAR_LIB_PATH="bn-r20170708-2-amd64-linux-ubuntu16.04/lib/libbls384.so"
#SYS_LIB_PATH="/usr/lib/libbls384.so"


#extract() {
    #echo "[+] Symlinking the library."
    #tar xvf "$TAR_NAME"
#}

#make_link() {
    #echo "[+] Creating symlink"
    ## simply do a symbolic link        
    #sudo ln -s "$(pwd)/$TAR_LIB_PATH" "$SYS_LIB_PATH"
#}

## check if library is already setup
#if [ -f "$SYS_LIB_PATH" ]; then
    #echo "[+] Library already installed. Exiting."
    #sudo ldconfig
    #exit 0
#$ sudo add-apt-repository ppa:ubuntu-toolchain-r/test
#fi

## check if library is not extracted yet
#if [ -f "$TAR_NAME" ] && [ ! -f "$tAR_LIB_PATH"]; then
    #echo "[+] Library not extracted yet"
    #extract
    #make_link
    #sudo ldconfig
    #exit 0
#fi 

## check if library is already downloaded and extracted
#if [ -f "$TAR_LIB_PATH" ]; then
    #echo "[+] Library already downloaded."
    #make_link
    #sudo ldconfig
    #exit 0
#fi


#echo "[+] Downloading and extracting the library..."
## dl and extract the library
#wget "$LINK"
#extract
#make_link
#sudo ldconfig
#echo "[+] Bye !"
#exit 0

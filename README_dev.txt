apt install aptitude
aptitude install  miniupnpc libminiupnpc-dev

apt-get install qt5-default qt5-qmake qtbase5-dev-tools qttools5-dev-tools build-essential libboost-dev libboost-system-dev libboost-filesystem-dev libboost-program-options-dev libboost-thread-dev libssl-dev libdb++-dev
cd /home/user/eclipse-workspace/usdex
cd src
make -f makefile.unix
chmod -R 777 /home/user/eclipse-workspace/usdex/src


touch .usdex/usdex.conf
vim .usdex/usdex.conf
added rpcuser & rpcpassword
start wallet
 ./usdexd --daemon -txindex
// check processing
 pidof usdexd
//






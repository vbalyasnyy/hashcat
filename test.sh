#!/bin/bash -x

#./hashcat -m 13100 -a 0 test.txt rockyou.txt # -a 0 ./test.txt  ./rockyou.txt

COUNT=10
if [ "x$1" != "x" ]; then
	COUNT=$1
fi

rm hashcat.dictstat2 hashcat.log hashcat.potfile

rm out.txt
seq 0 ${COUNT} > out.txt
echo "Passw0rd"

./hashcat -m 13100 in.txt out.txt -d 1 --self-test-disable -n 64 -u 1 --force


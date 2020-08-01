#!/bin/bash

make -j8
rm hashcat.dictstat2 hashcat.log hashcat.potfile
#./hashcat -m 13100 -b
#./hashcat -m 13100 test.txt rockyou.txt -d 1 --self-test-disable

rm -rf ./kernels/
make && ./hashcat -m 13100 test.txt pass.txt -d 1 --self-test-disable -n 64 -u 1 --force --quiet
#make clean && make && ./hashcat -m 13100 test.txt pass.txt -d 1 --self-test-disable -n 64 -u 1 --force
exit

COUNT=0
while [ $COUNT -lt 5 ]; do
	rm hashcat.dictstat2 hashcat.log hashcat.potfile
	./hashcat -m 13100 test.txt rockyou.txt -d 1 --self-test-disable -n 64 -u 1 --force | grep Speed
	let COUNT++
done

#!/bin/bash

#./hashcat -m 13100 -a 0 test.txt rockyou.txt # -a 0 ./test.txt  ./rockyou.txt

DICT_SIZE=10
if [ "x$1" != "x" ]; then
	DICT_SIZE=$1
fi

rm out.txt
# password strength
if [ 0 ]; then
	seq 0 ${DICT_SIZE} > out.txt
else
	while [ ${DICT_SIZE} -gt 0 ]; do
		</dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16 >> out.txt
		echo "" >> out.txt
		let DICT_SIZE--
	done
fi
#echo "Passw0rd" >> out.txt

TEST_COUNT=0
while [ $TEST_COUNT -lt 5 ]; do
	rm hashcat.dictstat2 hashcat.log hashcat.potfile;
	rm -rf ./kernels/
	#./hashcat -m 13100 in.txt out.txt -d 1 --self-test-disable -n 64 -u 1 --force
	#./hashcat -m 13100 in.txt out.txt -d 1 --self-test-disable -n 64 -u 1 --force | grep Speed
	./hashcat -m 13100 in.txt out.txt -n 1 -u 1 -T 64 --self-test-disable --force --hwmon-disable | grep Speed
	let TEST_COUNT++
done


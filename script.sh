#for qps in 0 2500 5000 6000 7000 8000 9000 10000; do
#	for concurrency in 4 8 20 32 100 200 500; do
for qps in 0 1000; do
	for concurrency in 1 4 8 16 32 64 128 256 512; do
		fortio load -payload-size 5000 -qps ${qps} -t 1m -c ${concurrency} -a -labels $1 http://localhost:$2/echo
	done
done

#for qps in 0 2500 5000 6000 7000 8000 9000 10000; do
#	for concurrency in 4 8 20 32 100 200 500; do
for qps in 0 1000; do
	for concurrency in 1 4 8 12 25 50 75 100 125 150 175 200; do
		fortio load -payload-size 5000 -data-dir output -qps ${qps} -t 5m -c ${concurrency} -a -labels $1 http://localhost:$2/echo
	done
done

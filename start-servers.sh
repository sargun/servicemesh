for i in $(seq 5000 5004); do
	fortio server -http-port $i &
done

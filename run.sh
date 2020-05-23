sh -x script.sh direct 5000
sh -x script.sh haproxy 2000
sh -x script.sh envoy 2001
./mesh2 sh -x script.sh mesh2 2002
./mesh sh -x script.sh mesh 2002


sudo docker run --net=host --ulimit nofile=90000:90000 -v $PWD/envoy.yaml:/envoy.yaml envoyproxy/envoy:v1.14.1 -c /envoy.yaml

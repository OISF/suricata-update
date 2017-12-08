TAG :=	suricata-update/tests/centos-7

all:
	docker build -t $(TAG) -f Dockerfile ../..
	docker run --rm -it $(TAG)


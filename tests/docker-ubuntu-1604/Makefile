TAG :=	suricata-update/tests/ubuntu-1604

all:
	docker build -t $(TAG) -f Dockerfile ../..
	docker run --rm -it $(TAG)

FROM ubuntu:16.04

RUN apt-get update
RUN apt-get install -y \
    	    python-yaml \
    	    python3-yaml \
	    python-pytest \
	    python3-pytest \
	    python-pip \
	    python3-pip

# RUN yum -y install epel-release
# RUN yum -y install \
#     git \
#     python-yaml \
#     python-pip \
#     pytest \
#     python34-yaml \
#     python34-pytest \
#     python34-pip \
#     findutils

COPY / /src
RUN find /src -name \*.pyc -delete

ENV PYTEST2 py.test
ENV PYTEST3 py.test-3

ENV PIP2 pip2
ENV PIP3 pip3

WORKDIR /src

CMD ["./tests/docker-ubuntu-1604/run.sh"]

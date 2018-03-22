.PHONY: doc

all: build

build:
	python setup.py build

install:
	python setup.py install

tox:
	@if ! which tox 2>&1 > /dev/null; then \
		echo "error: tox required to run tests"; \
		exit 1; \
	fi

test: tox
	@tox

integration-test: tox
	@tox -c tox-integration.ini

docker-test:
	@if ! which docker 2>&1 > /dev/null; then \
		echo "error: docker is required to run docker tests"; \
		exit 1; \
	fi
	@for test in $(wildcard tests/docker*); do \
		(cd $$test && $(MAKE)); \
	done

clean:
	find . -name \*.pyc -print0 | xargs -0 rm -f
	find . -name \*~ -print0 | xargs -0 rm -f
	find . -name __pycache__ -type d -print0 | xargs -0 rm -rf
	rm -rf suricata_update.egg*
	rm -rf build dist MANIFEST
	cd doc && $(MAKE) clean

doc:
	cd doc && $(MAKE) clean html

sdist:
	python setup.py sdist

sdist-upload:
	python setup.py sdist upload

update-index:
	python -m suricata.update.data.update

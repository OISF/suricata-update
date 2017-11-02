.PHONY: doc

all: build

build:
	python setup.py build

install:
	python setup.py install

test:
	@if which nosetests-3 2>&1 > /dev/null; then \
		echo "Running nosetests-3."; \
		nosetests-3; \
	fi
	@if which nosetests-2 2>&1 > /dev/null; then \
		echo "Running nosetests-2."; \
		nosetests-2; \
	fi
	@echo "Running nosetests."
	@nosetests

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

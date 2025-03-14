PKG_NAME := pymonocypher
DEST := dist/
VER := $(shell cat c_monocypher.pyx | grep version |cut -d\  -f3|cut -f 2 -d\')
VERSION := $(strip $(VER))
ORIG_TGZ := $(PKG_NAME)_$(VERSION).orig.tar.gz
ARCH := $(shell dpkg --print-architecture)
DEB_BUILD_OPTIONS := check
DEB_BUILD_DIR := $(DEST)$(PKG_NAME)-$(VERSION)
DEB_VER := 0
DEB := python3-$(PKG_NAME)_$(VERSION)-$(DEB_VER)_$(ARCH).deb
SOURCE_DATE_EPOCH := $(shell git log -1 --pretty=%ct)
SOURCE_PKG_CMD := python -m build --sdist
DEB_BUILD_CMD := dpkg-buildpackage -rfakeroot -uc -us

.PHONY: clean deb sdist

sdist: pyproject.toml
	SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH) $(SOURCE_PKG_CMD)
	mv $(DEST)$(PKG_NAME)-$(VERSION).tar.gz $(DEST)$(ORIG_TGZ)

$(DEST)$(DEB): $(DEST)$(ORIG_TGZ)
	-rm -r $(DEB_BUILD_DIR)
	tar -C $(DEST) -xf $(DEST)$(ORIG_TGZ)
	cp -arp debian $(DEB_BUILD_DIR) 
	cd $(DEB_BUILD_DIR) && \
	DEB_BUILD_OPTIONS=$(DEB_BUILD_OPTIONS) $(DEB_BUILD_CMD)

deb: sdist $(DEST)$(DEB)
	dpkg --contents $(DEST)$(DEB)
	ls -alh $(DEST)*$(PKG_NAME)*
	sha256sum $(DEST)$(DEB)

clean:
	-rm -rf build/ dist/ $(DEST) $(PKG_NAME).egg-info/ __pycache__/

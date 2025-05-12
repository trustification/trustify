.PHONY: all
all: ds1.zip ds3.zip

.PHONY: ds1.zip
ds1.zip:
	-rm ds1.zip
	cd ds1 && zip -r ../ds1.zip .

.PHONY: ds3.zip
ds3.zip:
	-rm ds3.zip
	cd ds3 && zip -r ../ds3.zip .

.PHONY: ds3-sboms.zip
ds3-sboms.zip:
	-rm ds3-sbom.zip
	cd ds3 && zip -r ../ds3-sboms.zip ./spdx

.PHONY: ds6.zip
ds6.zip:
	-rm ds6.zip
	cd ds6 && zip -r ../ds6.zip .

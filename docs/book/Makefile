
.PHONY: all
all: clean build

ANTORA_CLI ?= npx antora

.PHONY: clean
clean:
	${RM} -Rf build


.PHONY: build
build:
	$(ANTORA_CLI) --fetch antora-playbook.yaml $(ANTORA_ARGS)


.PHONY: local
local:
	$(ANTORA_CLI) antora-playbook.yaml --log-level info  $(ANTORA_ARGS)


.PHONY: version
version:
	@$(ANTORA_CLI) -v

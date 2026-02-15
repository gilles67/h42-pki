GITPACK_VERSION := $(shell git rev-list --full-history --all --abbrev-commit | head -1)
all:
	docker pull ubuntu
	docker build -t gilles67/h42-pki:latest -t gilles67/h42-pki:$(GITPACK_VERSION) ./src
	docker push gilles67/h42-pki:latest 
	docker push gilles67/h42-pki:$(GITPACK_VERSION)
.PHONY: help auto status ci validate install-tools build doctor full-scan full-scan-resume scan augment report structured-ai diff snapshot remote-existing cloud-do cloud-hetzner cloud-cleanup-do cloud-cleanup-hetzner ports screenshots params 403-candidates clean

TARGET ?=
PROFILE ?= balanced
SCOPE ?=
OLD ?=
NEW ?=
HOST ?=
USER ?= root
IDENTITY ?=
DO_SSH_KEY_ID ?=
HCLOUD_SSH_KEY ?=
REGION ?= fra1
LOCATION ?= fsn1
SIZE ?= s-1vcpu-1gb
TYPE ?= cx22
IMAGE ?= ubuntu-24-04-x64
HCLOUD_IMAGE ?= ubuntu-24.04
MAX_AGE_HOURS ?= 6
APPLY ?= false
RATE ?= 50
TOP_PORTS ?= 1000
LIMIT ?= 500
RESET ?= false

help:
	@echo "Reconixia Make targets"
	@echo "  make auto"
	@echo "  make status"
	@echo "  make ci"
	@echo "  make validate [TARGET=hedef.com]"
	@echo "  make install-tools"
	@echo "  make build"
	@echo "  make doctor"
	@echo "  make full-scan TARGET=hedef.com"
	@echo "  make full-scan-resume TARGET=hedef.com [RESET=true]"
	@echo "  make scan TARGET=hedef.com"
	@echo "  make augment TARGET=hedef.com"
	@echo "  make report TARGET=hedef.com"
	@echo "  make structured-ai TARGET=hedef.com"
	@echo "  make diff OLD=snapshots/old/report.json NEW=snapshots/new/report.json"
	@echo "  make snapshot TARGET=hedef.com"
	@echo "  make ports TARGET=hedef.com [RATE=50] [TOP_PORTS=1000]"
	@echo "  make screenshots TARGET=hedef.com"
	@echo "  make params TARGET=hedef.com [LIMIT=500]"
	@echo "  make 403-candidates TARGET=hedef.com [LIMIT=200]"
	@echo "  make remote-existing HOST=1.2.3.4 TARGET=hedef.com IDENTITY=~/.ssh/id_rsa"
	@echo "  make cloud-do TARGET=hedef.com DO_SSH_KEY_ID=123456 IDENTITY=~/.ssh/id_rsa"
	@echo "  make cloud-hetzner TARGET=hedef.com HCLOUD_SSH_KEY=my-key IDENTITY=~/.ssh/id_rsa"
	@echo "  make cloud-cleanup-do [MAX_AGE_HOURS=6] [APPLY=true]"
	@echo "  make cloud-cleanup-hetzner [MAX_AGE_HOURS=6] [APPLY=true]"
	@echo "  make clean"

auto:
	chmod +x scripts/reconixia_auto.sh
	./scripts/reconixia_auto.sh

status:
	chmod +x scripts/project_status.sh
	./scripts/project_status.sh

ci:
	chmod +x scripts/ci_local.sh
	./scripts/ci_local.sh

validate:
	chmod +x scripts/validate_setup.sh
	./scripts/validate_setup.sh $(TARGET)

install-tools:
	chmod +x scripts/install_tools.sh scripts/build_all.sh scripts/full_scan.sh scripts/full_scan_resume.sh scripts/snapshot.sh scripts/remote_existing.sh scripts/cloud_do_worker.sh scripts/cloud_hetzner_worker.sh scripts/cloud_do_safe.sh scripts/cloud_hetzner_safe.sh scripts/reconixia_auto.sh scripts/validate_setup.sh scripts/cloud_cleanup.sh scripts/module_naabu.sh scripts/module_gowitness.sh scripts/module_params.sh scripts/module_403_candidates.sh scripts/project_status.sh scripts/ci_local.sh
	./scripts/install_tools.sh

build:
	chmod +x scripts/build_all.sh scripts/full_scan.sh scripts/full_scan_resume.sh scripts/snapshot.sh scripts/remote_existing.sh scripts/cloud_do_worker.sh scripts/cloud_hetzner_worker.sh scripts/cloud_do_safe.sh scripts/cloud_hetzner_safe.sh scripts/reconixia_auto.sh scripts/validate_setup.sh scripts/cloud_cleanup.sh scripts/module_naabu.sh scripts/module_gowitness.sh scripts/module_params.sh scripts/module_403_candidates.sh scripts/project_status.sh scripts/ci_local.sh
	./scripts/build_all.sh

doctor: build
	./reconixia doctor

full-scan: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make full-scan TARGET=hedef.com"; exit 1; fi
	./scripts/full_scan.sh -t "$(TARGET)" -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --no-nuclei

full-scan-resume: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make full-scan-resume TARGET=hedef.com"; exit 1; fi
	./scripts/full_scan_resume.sh -t "$(TARGET)" -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --no-nuclei $(if $(filter true,$(RESET)),--reset,)

scan: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make scan TARGET=hedef.com"; exit 1; fi
	./reconixia run -target "$(TARGET)" -profile "$(PROFILE)" $(if $(SCOPE),-scope "$(SCOPE)",) --no-nuclei

augment: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make augment TARGET=hedef.com"; exit 1; fi
	./reconixia-augment -target "$(TARGET)"

report: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make report TARGET=hedef.com"; exit 1; fi
	./reconixia-report -target "$(TARGET)"

structured-ai: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make structured-ai TARGET=hedef.com"; exit 1; fi
	./reconixia-ai-structured -target "$(TARGET)"

diff: build
	@if [ -z "$(OLD)" ] || [ -z "$(NEW)" ]; then echo "OLD ve NEW gerekli: make diff OLD=... NEW=..."; exit 1; fi
	./reconixia-diff -old "$(OLD)" -new "$(NEW)"

snapshot:
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make snapshot TARGET=hedef.com"; exit 1; fi
	chmod +x scripts/snapshot.sh
	./scripts/snapshot.sh -t "$(TARGET)"

ports:
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make ports TARGET=hedef.com"; exit 1; fi
	chmod +x scripts/module_naabu.sh
	./scripts/module_naabu.sh -t "$(TARGET)" --rate "$(RATE)" --top-ports "$(TOP_PORTS)"

screenshots:
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make screenshots TARGET=hedef.com"; exit 1; fi
	chmod +x scripts/module_gowitness.sh
	./scripts/module_gowitness.sh -t "$(TARGET)"

params:
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make params TARGET=hedef.com"; exit 1; fi
	chmod +x scripts/module_params.sh
	./scripts/module_params.sh -t "$(TARGET)" --limit "$(LIMIT)"

403-candidates:
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make 403-candidates TARGET=hedef.com"; exit 1; fi
	chmod +x scripts/module_403_candidates.sh
	./scripts/module_403_candidates.sh -t "$(TARGET)" --limit "$(LIMIT)"

remote-existing:
	@if [ -z "$(HOST)" ] || [ -z "$(TARGET)" ]; then echo "HOST ve TARGET gerekli: make remote-existing HOST=1.2.3.4 TARGET=hedef.com"; exit 1; fi
	chmod +x scripts/remote_existing.sh
	./scripts/remote_existing.sh --host "$(HOST)" --user "$(USER)" $(if $(IDENTITY),--identity "$(IDENTITY)",) -t "$(TARGET)" -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",)

cloud-do:
	@if [ -z "$(TARGET)" ] || [ -z "$(DO_SSH_KEY_ID)" ]; then echo "TARGET ve DO_SSH_KEY_ID gerekli: make cloud-do TARGET=hedef.com DO_SSH_KEY_ID=123456"; exit 1; fi
	@if [ -z "$$DIGITALOCEAN_TOKEN" ]; then echo "DIGITALOCEAN_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_do_safe.sh
	./scripts/cloud_do_safe.sh -t "$(TARGET)" --ssh-key-id "$(DO_SSH_KEY_ID)" $(if $(IDENTITY),--identity "$(IDENTITY)",) -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --region "$(REGION)" --size "$(SIZE)" --image "$(IMAGE)"

cloud-hetzner:
	@if [ -z "$(TARGET)" ] || [ -z "$(HCLOUD_SSH_KEY)" ]; then echo "TARGET ve HCLOUD_SSH_KEY gerekli: make cloud-hetzner TARGET=hedef.com HCLOUD_SSH_KEY=my-key"; exit 1; fi
	@if [ -z "$$HETZNER_TOKEN" ]; then echo "HETZNER_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_hetzner_safe.sh
	./scripts/cloud_hetzner_safe.sh -t "$(TARGET)" --ssh-key "$(HCLOUD_SSH_KEY)" $(if $(IDENTITY),--identity "$(IDENTITY)",) -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --location "$(LOCATION)" --type "$(TYPE)" --image "$(HCLOUD_IMAGE)"

cloud-cleanup-do:
	@if [ -z "$$DIGITALOCEAN_TOKEN" ]; then echo "DIGITALOCEAN_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_cleanup.sh
	./scripts/cloud_cleanup.sh --provider digitalocean --max-age-hours "$(MAX_AGE_HOURS)" $(if $(filter true,$(APPLY)),--apply,)

cloud-cleanup-hetzner:
	@if [ -z "$$HETZNER_TOKEN" ]; then echo "HETZNER_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_cleanup.sh
	./scripts/cloud_cleanup.sh --provider hetzner --max-age-hours "$(MAX_AGE_HOURS)" $(if $(filter true,$(APPLY)),--apply,)

clean:
	rm -f reconixia reconixia-report reconixia-augment reconixia-diff reconixia-ai-structured

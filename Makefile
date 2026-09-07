.PHONY: help auto status ci release-check release-artifacts validate install-tools build doctor full-scan full-scan-resume scan augment report structured-ai idor diff snapshot remote-existing cloud-do cloud-hetzner cloud-cleanup-do cloud-cleanup-hetzner ports screenshots params 403-candidates clean

TARGET ?=
VERSION ?= 0.9.0-rc1
PROFILE ?= balanced
SCOPE ?=
OLD ?=
NEW ?=
OUTPUT ?=
DIFF_HTML ?= false
HOST ?=
USER ?= root
IDENTITY ?=
H1_USER ?=
RESEARCH_HEADER ?=
DO_SSH_KEY_ID ?=
HCLOUD_SSH_KEY ?=
SSH_CIDR ?=
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
IDOR_INPUT ?=
IDOR_HAR ?=
IDOR_RULES ?=
IDOR_OUTPUT ?=
IDOR_RATE ?= 2
IDOR_MAX ?= 50
IDOR_ALLOW_MUTATING ?= false

help:
	@echo "Reconixia Make targets"
	@echo "  make auto"
	@echo "  make status"
	@echo "  make ci"
	@echo "  make release-check"
	@echo "  make release-artifacts [VERSION=0.9.0-rc1]"
	@echo "  make validate [TARGET=hedef.com]"
	@echo "  make install-tools"
	@echo "  make build"
	@echo "  make doctor"
	@echo "  make full-scan TARGET=hedef.com"
	@echo "  make full-scan-resume TARGET=hedef.com [RESET=true]"
	@echo "    Optional for production: H1_USER=hackerone_username"
	@echo "  make scan TARGET=hedef.com"
	@echo "  make augment TARGET=hedef.com"
	@echo "  make report TARGET=hedef.com"
	@echo "  make structured-ai TARGET=hedef.com"
	@echo "  make idor TARGET=hedef.com IDOR_HAR=capture.har [IDOR_RULES=policy.json]"
	@echo "  make diff OLD=snapshots/old/report.json NEW=snapshots/new/report.json [DIFF_HTML=true OUTPUT=diff.html]"
	@echo "  make snapshot TARGET=hedef.com"
	@echo "  make ports TARGET=hedef.com [RATE=50] [TOP_PORTS=1000]"
	@echo "  make screenshots TARGET=hedef.com"
	@echo "  make params TARGET=hedef.com [LIMIT=500]"
	@echo "  make 403-candidates TARGET=hedef.com [LIMIT=200]"
	@echo "  make remote-existing HOST=1.2.3.4 TARGET=hedef.com IDENTITY=~/.ssh/id_rsa"
	@echo "  make cloud-do TARGET=hedef.com DO_SSH_KEY_ID=123456 IDENTITY=~/.ssh/id_rsa"
	@echo "    Optional: SSH_CIDR=1.2.3.4/32"
	@echo "  make cloud-hetzner TARGET=hedef.com HCLOUD_SSH_KEY=my-key IDENTITY=~/.ssh/id_rsa"
	@echo "    Optional: SSH_CIDR=1.2.3.4/32"
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

release-check:
	@if [ -n "$$(gofmt -l internal cmd)" ]; then gofmt -l internal cmd; exit 1; fi
	go test ./...
	go build ./cmd/...
	bash -n scripts/*.sh scripts/lib/*.sh

release-artifacts: release-check
	chmod +x scripts/release_artifacts.sh
	VERSION="$(VERSION)" ./scripts/release_artifacts.sh

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
	./scripts/full_scan.sh -t "$(TARGET)" -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --no-nuclei $(if $(H1_USER),--h1-user "$(H1_USER)",) $(if $(RESEARCH_HEADER),--research-header "$(RESEARCH_HEADER)",)

full-scan-resume: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make full-scan-resume TARGET=hedef.com"; exit 1; fi
	./scripts/full_scan_resume.sh -t "$(TARGET)" -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --no-nuclei $(if $(filter true,$(RESET)),--reset,) $(if $(H1_USER),--h1-user "$(H1_USER)",) $(if $(RESEARCH_HEADER),--research-header "$(RESEARCH_HEADER)",)

scan: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make scan TARGET=hedef.com"; exit 1; fi
	./reconixia run -target "$(TARGET)" -profile "$(PROFILE)" $(if $(SCOPE),-scope "$(SCOPE)",) --no-nuclei $(if $(H1_USER),-h1-user "$(H1_USER)",) $(if $(RESEARCH_HEADER),-research-header "$(RESEARCH_HEADER)",)

augment: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make augment TARGET=hedef.com"; exit 1; fi
	./reconixia-augment -target "$(TARGET)"

report: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make report TARGET=hedef.com"; exit 1; fi
	./reconixia-report -target "$(TARGET)"

structured-ai: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make structured-ai TARGET=hedef.com"; exit 1; fi
	./reconixia-ai-structured -target "$(TARGET)"

idor: build
	@if [ -z "$(TARGET)" ]; then echo "TARGET gerekli: make idor TARGET=whatnot.com IDOR_HAR=capture.har"; exit 1; fi
	@if [ -z "$(IDOR_INPUT)" ] && [ -z "$(IDOR_HAR)" ]; then echo "IDOR_INPUT veya IDOR_HAR gerekli"; exit 1; fi
	./reconixia-idor -target "$(TARGET)" $(if $(IDOR_INPUT),-input "$(IDOR_INPUT)",) $(if $(IDOR_HAR),-har "$(IDOR_HAR)",) $(if $(IDOR_RULES),-rules "$(IDOR_RULES)",) $(if $(IDOR_OUTPUT),-output "$(IDOR_OUTPUT)",) -rate "$(IDOR_RATE)" -max "$(IDOR_MAX)" $(if $(filter true,$(IDOR_ALLOW_MUTATING)),-allow-mutating,) $(if $(H1_USER),-h1-user "$(H1_USER)",) $(if $(RESEARCH_HEADER),-research-header "$(RESEARCH_HEADER)",)

diff: build
	@if [ -z "$(OLD)" ] || [ -z "$(NEW)" ]; then echo "OLD ve NEW gerekli: make diff OLD=... NEW=..."; exit 1; fi
	./reconixia-diff -old "$(OLD)" -new "$(NEW)" $(if $(filter true,$(DIFF_HTML)),-html,) $(if $(OUTPUT),-output "$(OUTPUT)",)

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
	./scripts/cloud_do_safe.sh -t "$(TARGET)" --ssh-key-id "$(DO_SSH_KEY_ID)" $(if $(IDENTITY),--identity "$(IDENTITY)",) -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --region "$(REGION)" --size "$(SIZE)" --image "$(IMAGE)" $(if $(SSH_CIDR),--ssh-cidr "$(SSH_CIDR)",)

cloud-hetzner:
	@if [ -z "$(TARGET)" ] || [ -z "$(HCLOUD_SSH_KEY)" ]; then echo "TARGET ve HCLOUD_SSH_KEY gerekli: make cloud-hetzner TARGET=hedef.com HCLOUD_SSH_KEY=my-key"; exit 1; fi
	@if [ -z "$$HETZNER_TOKEN" ]; then echo "HETZNER_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_hetzner_safe.sh
	./scripts/cloud_hetzner_safe.sh -t "$(TARGET)" --ssh-key "$(HCLOUD_SSH_KEY)" $(if $(IDENTITY),--identity "$(IDENTITY)",) -p "$(PROFILE)" $(if $(SCOPE),-s "$(SCOPE)",) --location "$(LOCATION)" --type "$(TYPE)" --image "$(HCLOUD_IMAGE)" $(if $(SSH_CIDR),--ssh-cidr "$(SSH_CIDR)",)

cloud-cleanup-do:
	@if [ -z "$$DIGITALOCEAN_TOKEN" ]; then echo "DIGITALOCEAN_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_cleanup.sh
	./scripts/cloud_cleanup.sh --provider digitalocean --max-age-hours "$(MAX_AGE_HOURS)" $(if $(filter true,$(APPLY)),--apply,)

cloud-cleanup-hetzner:
	@if [ -z "$$HETZNER_TOKEN" ]; then echo "HETZNER_TOKEN gerekli"; exit 1; fi
	chmod +x scripts/cloud_cleanup.sh
	./scripts/cloud_cleanup.sh --provider hetzner --max-age-hours "$(MAX_AGE_HOURS)" $(if $(filter true,$(APPLY)),--apply,)

clean:
	rm -f reconixia reconixia-report reconixia-augment reconixia-diff reconixia-ai-structured reconixia-idor

# Coverage-guided parser fuzzing (Windows GNU host).
#
#   make build
#   make campaign                 # 120 s per target, owned by run_campaign.sh
#   make campaign-pe SECONDS=60   # optional override
#
# The seed corpus is generated from the parser fixtures by:
#   cargo test -p litric-core --test parser_fuzz_soak write_coverage_fuzz_seeds -- --ignored

SHELL := bash

.PHONY: build campaign campaign-pe campaign-zip campaign-vba campaign-xlm clean

build:
	bash build.sh

campaign: build
	bash run_campaign.sh all $(SECONDS)

campaign-pe: build
	bash run_campaign.sh pe $(SECONDS)

campaign-zip: build
	bash run_campaign.sh zip $(SECONDS)

campaign-vba: build
	bash run_campaign.sh vba $(SECONDS)

campaign-xlm: build
	bash run_campaign.sh xlm $(SECONDS)

clean:
	rm -rf target corpus artifacts crash-* leak-* timeout-* oom-*

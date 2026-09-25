BENCHMARK := benchmark
MACHINES := $(BENCHMARK)/machines
SOLUTIONS := $(BENCHMARK)/solutions
MILESTONES := $(BENCHMARK)/milestones
CMD_MILESTONES := $(MILESTONES)/command_milestones
STG_MILESTONES := $(MILESTONES)/stage_milestones

# Every goal this Makefile defines, in one place.
GOALS := build build-task build-kali build-injections install install-dev test test-unit lint create create_structure

.PHONY: $(GOALS)

# Compose files for one task: base machines (incl. Kali) + the requested
# category/task_type. Recursive (`=`) so it picks up the args parsed below.
TASK_COMPOSE = -f benchmark/machines/docker-compose.yml -f benchmark/machines/$(category)/$(task_type)/docker-compose.yml

build:
	@$(MAKE) build-injections
	$(eval DC := $(shell find benchmark -name 'docker-compose.yml' -print0 | xargs -0 -I {} echo "-f {}" | grep -v "benchmark/machines/docker-compose.yml"))
	docker compose -f benchmark/machines/docker-compose.yml $(DC) build

# Build only what one task needs (base machines + one category), not all
# ~45 images. Use this while iterating on a single task.
build-task:
	@test -n "$(category)" -a -n "$(task_type)" || \
		{ echo "usage: make build-task <category> <task_type>"; \
		  echo "  e.g. make build-task in-vitro access_control"; exit 1; }
	@if [ "$(category)" = "in-vitro" ] && [ "$(task_type)" = "web_security" ]; then \
		$(MAKE) build-injections; \
	fi
	@docker compose $(TASK_COMPOSE) build

# The Kali workstation is shared by every task and is by far the most
# expensive image, so it gets a target of its own: rebuild it here, and let
# `build-task` stay limited to one category.
build-kali:
	@docker compose -f benchmark/machines/docker-compose.yml build kali_master

# The prompt-injection overlays are `FROM <original image>`, so they need the
# originals built first (see benchmark/build_injection_variants.sh).
build-injections:
	@benchmark/build_injection_variants.sh

install: build
	setup/setup.sh

install-dev:
	@pip3 install -e '.[test,lint]'

test:
	@test -n "$(category)" -a -n "$(task_type)" -a -n "$(vm)" || \
		{ echo "usage: make test <category> <task_type> <vm>"; \
		  echo "  e.g. make test in-vitro access_control 0"; exit 1; }
	@if [ "$(category)" = "in-vitro" ] && [ "$(task_type)" = "web_security" ]; then \
		$(MAKE) build-injections; \
	fi
	@docker compose $(TASK_COMPOSE) build
	@python3 benchmark/tests/machine_test.py $(category) $(task_type) $(vm)

test-unit:
	@python3 -m pytest -q tests

lint:
	@python3 -m ruff check autopenbench tests setup scripts benchmark/tests

create:
	@$(MAKE) create_structure CATEGORY=$(category) TASK_TYPE=$(task_type) VM=$(vm)

# Helper that forwards positional args into create_structure.
create_structure: 
	@echo "Creating directories for $(CATEGORY), $(TASK_TYPE), $(VM)..."
	@$(MAKE) $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM)/done CATEGORY=$(CATEGORY) TASK_TYPE=$(TASK_TYPE) VM=$(VM)


$(MACHINES)/$(CATEGORY):
	mkdir -p $(MACHINES)/$(CATEGORY)
	mkdir -p $(CMD_MILESTONES)/$(CATEGORY)
	mkdir -p $(STG_MILESTONES)/$(CATEGORY)
	mkdir -p $(SOLUTIONS)/$(CATEGORY)


$(MACHINES)/$(CATEGORY)/$(TASK_TYPE): $(MACHINES)/$(CATEGORY)
	mkdir -p $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)
	mkdir -p $(CMD_MILESTONES)/$(CATEGORY)/$(TASK_TYPE)
	mkdir -p $(STG_MILESTONES)/$(CATEGORY)/$(TASK_TYPE)
	mkdir -p $(SOLUTIONS)/$(CATEGORY)/$(TASK_TYPE)

	python3 setup/manage_docker_compose.py create $(BENCHMARK) $(CATEGORY) $(TASK_TYPE) $(VM)


$(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM): $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)
	mkdir -p $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM)
	touch $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM)/flag.txt
	touch $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM)/Dockerfile

	touch $(CMD_MILESTONES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM).txt
	touch $(STG_MILESTONES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM).txt
	touch $(SOLUTIONS)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM).txt

	python3 setup/manage_docker_compose.py update $(BENCHMARK) $(CATEGORY) $(TASK_TYPE) $(VM)
	python3 setup/manage_input_data.py $(CATEGORY) $(TASK_TYPE) $(VM)


$(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM)/done: $(MACHINES)/$(CATEGORY)/$(TASK_TYPE)/vm$(VM)
	@echo "All folders created. Doing final task in $(VM)..."

# Positional args: words of MAKECMDGOALS that are not goals
# (`make test ctf software 0` → ctf software 0). A command-line assignment
# (`make test category=ctf ...`) still wins because `?=` leaves defined vars alone.
ARGV := $(filter-out $(GOALS), $(MAKECMDGOALS))
category ?= $(word 1, $(ARGV))
task_type ?= $(word 2, $(ARGV))
vm ?= $(word 3, $(ARGV))

# Absorb leftover goal words so make does not treat folder names as targets.
%:
	@:

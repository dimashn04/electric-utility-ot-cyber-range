SHELL := /bin/bash

HMI_URL ?= http://localhost:18081
LOG_FILES := logs/rtu.jsonl logs/scada.jsonl logs/detections.jsonl
NORMAL_EVIDENCE_DIR := evidence/phase1-normal-scada-workflow
ATTACK_EVIDENCE_DIR := evidence/phase1-spoofed-direct-rtu-attack
GI_EVIDENCE_DIR := evidence/phase2-general-interrogation-abuse

.PHONY: up down build attack test logs clean-logs reset-runtime-logs evidence-normal evidence-attack evidence-general-interrogation validate-normal-evidence validate-attack-evidence validate-general-interrogation-evidence wait-hmi

up:
	docker compose up --build

down:
	docker compose down --remove-orphans

build:
	docker compose build

attack:
	docker compose build attacker
	docker compose run --rm attacker python attacks/unauthorized_breaker_open.py

test:
	python -m pytest

logs:
	docker compose logs -f rtu-simulator scada-master hmi

clean-logs:
	docker compose down --remove-orphans
	mkdir -p logs
	docker compose run --rm --no-deps --entrypoint sh rtu-simulator -c 'rm -f /logs/rtu.jsonl /logs/scada.jsonl /logs/detections.jsonl && touch /logs/rtu.jsonl /logs/scada.jsonl /logs/detections.jsonl && chmod 666 /logs/rtu.jsonl /logs/scada.jsonl /logs/detections.jsonl'

reset-runtime-logs:
	mkdir -p logs
	docker compose run --rm --no-deps --entrypoint sh rtu-simulator -c 'rm -f /logs/rtu.jsonl /logs/scada.jsonl /logs/detections.jsonl && touch /logs/rtu.jsonl /logs/scada.jsonl /logs/detections.jsonl && chmod 666 /logs/rtu.jsonl /logs/scada.jsonl /logs/detections.jsonl'

wait-hmi:
	@for i in $$(seq 1 45); do \
		if curl -fsS "$(HMI_URL)/api/status" >/dev/null 2>&1; then \
			echo "HMI API is ready at $(HMI_URL)"; \
			exit 0; \
		fi; \
		sleep 1; \
	done; \
	echo "HMI API did not become ready at $(HMI_URL)" >&2; \
	exit 1

evidence-normal: clean-logs
	docker compose up -d --build rtu-simulator scada-master hmi
	$(MAKE) wait-hmi
	mkdir -p "$(NORMAL_EVIDENCE_DIR)"
	curl -fsS -X POST "$(HMI_URL)/api/commands/breaker/close" > "$(NORMAL_EVIDENCE_DIR)/close-response.json"
	sleep 2
	curl -fsS -X POST "$(HMI_URL)/api/commands/breaker/open" > "$(NORMAL_EVIDENCE_DIR)/open-response.json"
	sleep 2
	curl -fsS "$(HMI_URL)/api/status" > "$(NORMAL_EVIDENCE_DIR)/status.json"
	curl -fsS "$(HMI_URL)/api/events" > "$(NORMAL_EVIDENCE_DIR)/events.json"
	cp $(LOG_FILES) "$(NORMAL_EVIDENCE_DIR)/"
	$(MAKE) validate-normal-evidence

evidence-attack: clean-logs
	docker compose up -d --build rtu-simulator scada-master hmi
	$(MAKE) wait-hmi
	curl -fsS -X POST "$(HMI_URL)/api/commands/breaker/close" > /tmp/pln-power-ot-cyber-range-precondition-close.json
	sleep 2
	$(MAKE) reset-runtime-logs
	mkdir -p "$(ATTACK_EVIDENCE_DIR)"
	docker compose build attacker
	docker compose run --rm attacker python attacks/unauthorized_breaker_open.py > "$(ATTACK_EVIDENCE_DIR)/attacker-output.txt"
	sleep 3
	curl -fsS "$(HMI_URL)/api/status" > "$(ATTACK_EVIDENCE_DIR)/status.json"
	curl -fsS "$(HMI_URL)/api/events" > "$(ATTACK_EVIDENCE_DIR)/events.json"
	cp $(LOG_FILES) "$(ATTACK_EVIDENCE_DIR)/"
	$(MAKE) validate-attack-evidence

evidence-general-interrogation: clean-logs
	docker compose up -d --build rtu-simulator scada-master hmi
	$(MAKE) wait-hmi
	curl -fsS -X POST "$(HMI_URL)/api/commands/breaker/close" > /tmp/electric-utility-ot-cyber-range-gi-precondition-close.json
	sleep 2
	$(MAKE) reset-runtime-logs
	mkdir -p "$(GI_EVIDENCE_DIR)"
	docker compose build attacker
	docker compose run --rm attacker python attacks/general_interrogation_abuse.py --count 20 --delay 0.1 > "$(GI_EVIDENCE_DIR)/attacker-output.txt"
	sleep 3
	curl -fsS "$(HMI_URL)/api/status" > "$(GI_EVIDENCE_DIR)/status.json"
	curl -fsS "$(HMI_URL)/api/events" > "$(GI_EVIDENCE_DIR)/events.json"
	cp $(LOG_FILES) "$(GI_EVIDENCE_DIR)/"
	$(MAKE) validate-general-interrogation-evidence

validate-normal-evidence:
	python scripts/validate_normal_evidence.py "$(NORMAL_EVIDENCE_DIR)"

validate-attack-evidence:
	python scripts/validate_attack_evidence.py "$(ATTACK_EVIDENCE_DIR)"

validate-general-interrogation-evidence:
	python scripts/validate_general_interrogation_evidence.py "$(GI_EVIDENCE_DIR)"

#!/bin/bash
set -euxo pipefail

vagrant destroy --force || true
vagrant up
vagrant ssh-config --host vm >ssh_config
ansible-playbook playbook.yaml

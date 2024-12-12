SHELL := /bin/bash

CUR_DIR := $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
ROOT_DIR := $(CUR_DIR)/../

$(ROOT_DIR)/venv/bin/ansible-playbook:
	python3 -m venv $(ROOT_DIR)/venv
	$(ROOT_DIR)/venv/bin/python -m pip install ansible==6.7.0 pywinrm

ansible: $(ROOT_DIR)/venv/bin/ansible-playbook

init:
	vagrant up --no-provision 
	vagrant snapshot save --force 'ready_provision'
	
revoke:
	vagrant snapshot restore 'ready_provision'
gui:
	vagrant up --no-provision
	virt-viewer -a -c qemu:///session vagrant-kafl-windows

compile:
	#mkdir -p bin/{userspace,driver}
	#x86_64-w64-mingw32-gcc src/userspace/hightosys.cpp -I ../ -o bin/userspace/hightosys.exe -Wall
	#x86_64-w64-mingw32-gcc src/userspace/inject.cpp -I ../ -o bin/userspace/inject.exe -Wall   -lpsapi
	#x86_64-w64-mingw32-gcc -shared src/userspace/kafl_sysmain.cpp src/userspace/sysmain_c.c -I ../ -o bin/userspace/kafl_sysmain.dll -Wall -lrpcrt4 -ldbghelp

pu: compile ansible
	vagrant snapshot restore 'ready_provision'
	TARGET_HARNESS='userspace' vagrant provision
	vagrant halt

target: compile ansible
	vagrant up --no-provision
	TARGET_HARNESS='provision_target' vagrant provision
	vagrant halt


no_target: compile ansible
	vagrant up --no-provision --debug
	vagrant provision

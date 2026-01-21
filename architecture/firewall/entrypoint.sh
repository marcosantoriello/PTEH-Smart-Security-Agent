#!/bin/bash

python3 firewall.py &
python3 enforcer.py &
wait
#!/bin/bash
while read -r line; do
	args=($line)
  	python3 role_trust_check.py "${args[@]}"
done < role-checker.txt

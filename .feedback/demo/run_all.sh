#!/bin/sh
# Reproduces the four release-task migration scenarios fully offline.
#
#   sh .feedback/demo/run_all.sh
#
# Rebuilds the local advisory databases and lockfiles, then runs every
# scenario and prints the exit code / reconciliation summary for each.
set -e

cd "$(dirname "$0")/../.."

echo "== building offline advisory databases and lockfile doubles =="
ruby .feedback/demo/setup_demo.rb

echo
echo "== running the four scenarios =="
ruby .feedback/demo/run_scenarios.rb

echo
echo "== rspec coverage for the release task =="
rspec -Ilib -Ispec --options /dev/null -r ./spec/spec_helper.rb spec/release_task_spec.rb

#!/usr/bin/env bash
set -euo pipefail

sudo apt-get update
sudo apt-get install -y \
  iw \
  tcpdump \
  aircrack-ng \
  python3-venv \
  python3-pip \
  libpcap-dev

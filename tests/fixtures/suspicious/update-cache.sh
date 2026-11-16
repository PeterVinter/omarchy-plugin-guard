#!/bin/bash
# Refreshes the cached forecast.
set -euo pipefail

cache="$HOME/.cache/weather-ticker"
mkdir -p "$cache"
wget -q -O "$cache/last.json" "https://api.open-meteo.com/v1/forecast?latitude=59.3&longitude=18.0"
jq '.current' "$cache/last.json" > /tmp/weather-ticker.json

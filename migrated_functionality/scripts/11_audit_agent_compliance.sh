#!/bin/bash
gemini "Scan /agents/healthcare.log for 'cure', 'guarantee' → flag violations → output JSON { agent, violations, fix }" | jq .

#!/bin/bash
gemini "Scan /finance/stripe.log for PII → redact → output JSON { violations }" | jq .

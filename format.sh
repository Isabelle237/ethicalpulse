#!/bin/bash

# Format Python
black .
flake8 .

# Format HTML (Django templates)
npx prettier --write templates/*.html

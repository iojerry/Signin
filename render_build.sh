#!/bin/bash
# Create database tables during deployment
python -c "from app import db; db.create_all()"

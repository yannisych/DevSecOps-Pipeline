# VULNERABILITY 1: Using latest tag (unpinned version)
FROM python:3.9

# VULNERABILITY 2: Running as root (no USER instruction)
WORKDIR /app

# VULNERABILITY 3: Installing packages without cleaning up
COPY requirements.txt .
RUN pip install -r requirements.txt

# Copy application code
COPY *.py .

# VULNERABILITY 4: No HEALTHCHECK defined
# HEALTHCHECK should be added

# VULNERABILITY 5: Exposing unnecessary ports
EXPOSE 8080

# VULNERABILITY 6: Using shell form of CMD (security risk)
# VULNERABILITY 7: Still running as root
CMD python app.py

# ====================
# Security Issues Summary:
# ====================
# 1. Unpinned base image version
# 2. Running as root user
# 3. No package cache cleanup
# 4. Missing HEALTHCHECK
# 5. No resource limits
# 6. Shell form of CMD
# 7. No non-root USER
# 8. No .dockerignore file
# ====================

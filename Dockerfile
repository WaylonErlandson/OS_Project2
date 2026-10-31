
FROM ubuntu:22.04

# Install required build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy extracted project directory into the container
WORKDIR /app
COPY src/ /app/src/

# Set working directory
WORKDIR /app/src

# Compile using the existing Makefile
RUN gcc --version && make

# Run the tests
CMD ["/bin/bash"]

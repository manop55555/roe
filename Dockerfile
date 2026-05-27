# syntax=docker/dockerfile:1
#
# Multi-stage build for roe. Both stages use Alpine so the binary links
# against the same musl/libstdc++ runtime in the build and final images.
#
# Build the image:
#   docker build -t roe:latest .
#
# Verify the final image stays small (target: < 20 MB):
#   docker images roe:latest --format '{{.Size}}'

FROM alpine:3.20 AS build

RUN apk add --no-cache \
        build-base \
        cmake \
        make \
        capstone-dev \
        capstone-static \
        git

WORKDIR /build
COPY . .

RUN cmake -B build -DCMAKE_BUILD_TYPE=Release -DROE_BUILD_TESTS=OFF \
    && cmake --build build -j \
    && strip build/roe

FROM alpine:3.20

RUN apk add --no-cache libstdc++ capstone

COPY --from=build /build/build/roe /usr/local/bin/roe

ENTRYPOINT ["roe"]

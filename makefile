LIBYANG_VERSION		?= d7b3d63b88115572e3291532248169ae1621b5d6
SYSREPO_VERSION		?= 64e3c66442d682c31e979db289c4c64a3ec1f6c1
LIBNETCONF2_VERSION	?= ef7d3e3ca1504e8ca9c4f4b5dd3847ba17bb809d
NETOPEER2_VERSION	?= 39800066f9fbbde9b55e6cfde77927eeb5627c83

.PHONY: all

all: build run

build: Dockerfile
	docker build \
	  -t erap320/issue-2765 \
	  -f Dockerfile . \
	  --build-arg LIBYANG_VERSION=${LIBYANG_VERSION} \
	  --build-arg SYSREPO_VERSION=${SYSREPO_VERSION} \
	  --build-arg LIBNETCONF2_VERSION=${LIBNETCONF2_VERSION} \
	  --build-arg NETOPEER2_VERSION=${NETOPEER2_VERSION}

run:
	docker run --rm -it erap320/issue-2765 /app/plugin
#
#  BUILD CONTAINER -------------------------------------------------------------
#

FROM gbolo/builder:alpine as builder

COPY . /opt/gopath/src/github.com/gbolo/protego
# Building
RUN   set -xe; \
      cd /opt/gopath/src/github.com/gbolo/protego && go build -o bin/protego

#
#  FINAL BASE CONTAINER --------------------------------------------------------
#

FROM  gbolo/baseos:alpine

# Copy in from builder
COPY  --from=builder /opt/gopath/src/github.com/gbolo/protego/bin/* /
COPY  --from=builder /opt/gopath/src/github.com/gbolo/protego/testdata /testdata

# Inherit gbolo/baseos entrypoint and pass it this argument
CMD  ["/protego"]

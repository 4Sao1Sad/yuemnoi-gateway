FROM golang AS plugin-builder

WORKDIR /builder

COPY . /builder

RUN go build -o authd main.go


# Build Kong
FROM kong:3.6.1-ubuntu

COPY --from=plugin-builder /builder/authd  ./kong/

USER kong
#FROM golang:1.18
FROM s390x/golang:1.18


WORKDIR /usr/src/app

# pre-copy/cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN go build -v -o /usr/local/bin/ ./...

# RUN wget https://github.com/threen134/signing_server/releases/download/s390x-v1/signing_server  /usr/local/bin/ 
# RUN chmod +x /usr/local/bin/signing_server

CMD ["signing_server"]
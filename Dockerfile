FROM jac18281828/godev:latest

ARG PROJECT=quadraticgnark
WORKDIR /workspaces/${PROJECT}
ENV GOMAXPROCS=10
COPY . .
RUN chown -R jac:jac .
USER jac
ENV GOPATH=/workspaces/${PROJECT}

RUN go install -v github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /workspaces/${PROJECT}/src/quadratic

RUN go mod tidy
RUN go build
RUN go test ./...

ENV PROJECT=${PROJECT}
CMD cd /workspaces/${PROJECT}/src/quadratic && go run . 
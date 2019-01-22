FROM consol/centos-xfce-vnc:1.1.0

USER 0
RUN yum install -y gedit && yum clean all
USER 0
RUN yum update -y
RUN yum install -y git
RUN yum groupinstall -y "Development Tools"
RUN yum install -y kernel-headers kernel-devel
RUN wget https://dl.google.com/go/go1.9.3.linux-amd64.tar.gz && tar -xzf go1.9.3.linux-amd64.tar.gz
RUN mv go /usr/local
ENV GOROOT=/usr/local/go
ENV PATH=$PATH:/usr/local/go/bin
RUN mkdir -p /headless/go/src/github.com/dappbox/dappbox
COPY . /headless/go/src/github.com/dappbox/dappbox
RUN go get -u -d github.com/Masterminds/glide
RUN cd /headless/go/src/github.com/Masterminds/glide && make install
RUN go get -u -d github.com/shirou/gopsutil/disk
RUN go get -u -d github.com/skip2/go-qrcode
RUN go get -u -d github.com/influxdata/influxdb
RUN go get -u -d github.com/sparrc/gdm
RUN cd /headless/go/src/github.com/sparrc/gdm && go install
RUN mv /headless/go/bin/gdm /usr/local/bin/gdm
RUN wget http://c758482.r82.cf2.rackcdn.com/sublime_text_3_build_3065_x64.tar.bz2 && tar -vxjf sublime_text_3_build_3065_x64.tar.bz2 -C /opt
RUN ln -s /opt/sublime_text_3/sublime_text /usr/bin/sublime3
# RUN git clone https://github.com/tendermint/tendermint.git
RUN go get -u -d github.com/tendermint/tendermint/cmd/tendermint; exit 0
RUN cd /headless/go/src/github.com/tendermint/tendermint && glide install && go install ./cmd/tendermint ; exit 0
# RUN mv tendermint /go/src/github.com/tendermint
# RUN git clone https://github.com/tendermint/ethermint.git
# RUN go get -u -d github.com/tendermint/ethermint/cmd/ethermint; exit 0
# RUN cd /go/src/github.com/tendermint/ethermint && go install ./cmd/ethermint ; exit 0
# RUN mv ethermint /go/src/github.com/tendermint/ethermint
RUN go get -u -d github.com/tendermint/abci/server
RUN go get -u -d github.com/mattn/go-colorable
RUN go get -u -d github.com/ethereum/go-ethereum
RUN go get -u -d github.com/tendermint/tendermint/rpc/core/types
RUN go get -u -d github.com/gorilla/websocket
RUN go get -u -d github.com/rcrowley/go-metrics
# RUN go get -u -d gopkg.in/urfave/cli.v1


#RUN cd /headless/go/src/github.com/tendermint/ethermint && make install; exit 0
# RUN cd ../tendermint && make install; exit 0
RUN cd /headless/go/src/github.com/influxdata/influxdb && gdm restore && go clean ./... && go build ./...
RUN mv /headless/go/bin/tendermint /usr/local/bin/tendermint
RUN cd /headless/go/src/github.com/dappbox/dappbox
RUN ./build.sh
# RUN ./build.sh test

#CMD ./build.sh
# RUN ./build.sh test

FROM doslahtm/pwn:21.04

RUN groupadd -r data-eater && useradd -r -g data-eater data-eater

COPY ./xinetd /etc/xinetd.d/data-eater

WORKDIR /home/data-eater
COPY ./dataeater ./
COPY ./run.sh ./
RUN chown root:data-eater ./ -R
RUN chmod 550 ./dataeater
RUN chmod 550 run.sh

CMD [ "/usr/sbin/xinetd","-dontfork" ]



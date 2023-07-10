#!/bin/bash

WORKDIR="/gala-gopher/"
GOPHER_CONF_DIR="/etc/gala-gogpher/"
GOPHER_CONF="$GOPHER_CONF_DIR/gala-gopher.conf"

if [ -f $WORKDIR/user_conf/gala-gopher.conf ] ; then
    /usr/bin/cp -f $WORKDIR/user_conf/gala-gopher.conf $GOPHER_CONF_DIR
fi

if [ -f $WORKDIR/user_conf/gala-gopher-app.conf ] ; then
    /usr/bin/cp -f $WORKDIR/user_conf/gala-gopher-app.conf $GOPHER_CONF_DIR
fi

if [ -d $WORKDIR/user_conf/extend_probes ] ; then
    /usr/bin/cp -f $WORKDIR/user_conf/extend_probes/*.conf $GOPHER_CONF_DIR/extend_probes/
fi

if [[ -n "$GOPHER_LOG_LEVEL" ]]; then
    sed -i "s/log_level =.*/log_level = \"${GOPHER_LOG_LEVEL}\";/g" $GOPHER_CONF
fi

if [[ -n "$GOPHER_EVENT_CHANNEL" ]]; then
    sed -i "/^event =/{n;n;s/out_channel =.*/out_channel = \"${GOPHER_EVENT_CHANNEL}\";/g;}" $GOPHER_CONF
fi

if [[ -n "$GOPHER_METRIC_CHANNEL" ]]; then
    sed -i "/^metric =/{n;n;s/out_channel =.*/out_channel = \"${GOPHER_METRIC_CHANNEL}\";/g;}" $GOPHER_CONF
fi

if [[ -n "$GOPHER_KAKFA_SERVER" ]]; then
    sed -i "s/kafka_broker =.*/kafka_broker = \"${GOPHER_KAKFA_SERVER}:9092\";/g" $GOPHER_CONF
fi

if [[ -n "$GOPHER_METRIC_PORT" ]]; then
    sed -i "/^web_server =/{n;n;s/port =.*/port = ${GOPHER_METRIC_PORT};/g;}" $GOPHER_CONF
fi

if [[ -n "$GOPHER_REST_PORT" ]]; then
    sed -i "/^rest_api_server =/{n;n;s/port =.*/port = ${GOPHER_REST_PORT};/g;}" $GOPHER_CONF
fi

if [[ "x$GOPHER_REST_AUTH" == "xyes" ]]; then
    sed -i "/^rest_api_server =/{n;n;n;s/ssl_auth =.*/ssl_auth = \"on\";/g;}" $GOPHER_CONF
    sed -i "s/private_key =.*/private_key =\"${GOPHER_REST_PRIVATE_KEY}\";/g" $GOPHER_CONF
    sed -i "s/cert_file =.*/cert_file =\"${GOPHER_REST_CERT}\";/g" $GOPHER_CONF
    sed -i "s/ca_file =.*/ca_file =\"${GOPHER_REST_CAFILE}\";/g" $GOPHER_CONF
fi

exec "$@"
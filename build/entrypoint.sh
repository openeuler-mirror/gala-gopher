#!/bin/bash

WORKDIR="/gala-gopher/"
GOPHER_CONF_DIR="/etc/gala-gopher"
GOPHER_CONF="$GOPHER_CONF_DIR/gala-gopher.conf"
GOPHER_PROBES_INIT_FILE="$GOPHER_CONF_DIR/probes.init"
INIT_PROBES_SCRIPT="/usr/libexec/gala-gopher/init_probes.sh"

if [[ -n "$GOPHER_LOG_LEVEL" ]]; then
    sed -i "s/log_level =.*/log_level = \"${GOPHER_LOG_LEVEL}\";/g" $GOPHER_CONF
fi

if [[ -n "$GOPHER_EVENT_CHANNEL" ]]; then
    sed -i "/^event =/{n;n;s/out_channel =.*/out_channel = \"${GOPHER_EVENT_CHANNEL}\";/g;}" $GOPHER_CONF
fi

if [[ -n "$GOPHER_META_CHANNEL" ]]; then
    sed -i "/^meta =/{n;n;s/out_channel =.*/out_channel = \"${GOPHER_META_CHANNEL}\";/g;}" $GOPHER_CONF
fi

if [[ -n "$GOPHER_KAKFA_SERVER" ]]; then
    sed -i "s/kafka_broker =.*/kafka_broker = \"${GOPHER_KAKFA_SERVER}:9092\";/g" $GOPHER_CONF
else
    sed -i "s/kafka_broker =.*/kafka_broker = \"localhost:9092\";/g" $GOPHER_CONF
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

if [[ -n "$GOPHER_PROBES_INIT" ]] ; then
    echo "$GOPHER_PROBES_INIT" > $GOPHER_PROBES_INIT_FILE;
else
    echo > $GOPHER_PROBES_INIT_FILE;
fi

if [[ "$@" =~ "/usr/bin/gala-gopher" ]] && [[ -f "$INIT_PROBES_SCRIPT" ]] ; then
    /bin/bash $INIT_PROBES_SCRIPT &
fi

exec "$@"

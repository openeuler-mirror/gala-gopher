#!/bin/bash

WEB_SERVER_CONF="/etc/web_server.conf"

if [[ -n "$THREAD_COUNT" ]]; then
    sed -i "s/thread_count.*/thread_count\": ${THREAD_COUNT},/g" $WEB_SERVER_CONF
fi

if [[ -n "$SEND_ALL_RATE" ]]; then
    sed -i "s/send_all_rate.*/send_all_rate\": ${SEND_ALL_RATE},/g" $WEB_SERVER_CONF
fi

if [[ -n "$SEND_UPDATE_RATE" ]]; then
    sed -i "s/send_update_rate.*/send_update_rate\": ${SEND_UPDATE_RATE}/g" $WEB_SERVER_CONF
fi

if [[ -n "$ADDRESS" ]]; then
    sed -i "s/address.*/address\": [${ADDRESS}],/g" $WEB_SERVER_CONF
fi

exec "$@"

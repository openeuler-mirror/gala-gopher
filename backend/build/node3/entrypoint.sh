#!/bin/bash

BACKEND_CONF="backend.json"

if [[ -n "$PORT" ]]; then
    sed -i "s/port.*/port\" :${PORT},/g" $BACKEND_CONF
fi

if [[ -n "$NEXT" ]]; then
    sed -i "s/next.*/next\": [${NEXT}],/g" $BACKEND_CONF
fi

if [[ -n "$KEEP_ALIVE_WAIT_PORT" ]]; then
    sed -i "s/keep_alive_wait_port.*/keep_alive_wait_port\": ${KEEP_ALIVE_WAIT_PORT},/g" $BACKEND_CONF
fi

if [[ -n "$BATCH_WRITE_DISK" ]]; then
    sed -i "s/batch_write_disk.*/batch_write_disk\": ${BATCH_WRITE_DISK}/g" $BACKEND_CONF
fi



exec "$@"

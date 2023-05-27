#ifndef __EVENT2JSON_H__
#define __EVENT2JSON_H__

#include "ingress.h"

int LogData2Json(IngressMgr *mgr, const char *logData, char *jsonFmt, int jsonSize);
int EventData2Json(IngressMgr *mgr, const char *evtData, char *jsonFmt, int jsonSize);

#endif
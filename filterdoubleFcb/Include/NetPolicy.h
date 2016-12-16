#pragma once
#include "BaseTypes.h"
#include "NetConf.h"

//int ImportNetPolicy(OUT tagNetControl* NetControl);
BOOLEAN CheckNetPolicy(PROTOCAL protocal, ULONG ip, USHORT port, PPROCESS_INFO processInfo);
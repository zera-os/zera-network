#pragma once
#include <wasmedge/wasmedge.h>

WasmEdge_Result GetACEData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out);


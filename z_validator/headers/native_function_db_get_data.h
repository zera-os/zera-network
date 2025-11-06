#pragma once
#include <wasmedge/wasmedge.h>

WasmEdge_Result DBGetData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                           const WasmEdge_Value *In, WasmEdge_Value *Out);
                           
WasmEdge_Result DBGetAnyData(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out);
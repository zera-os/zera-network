#pragma once
#include <wasmedge/wasmedge.h>

WasmEdge_Result Transfer(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                         const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Hold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Send(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result SendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                        const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Mint(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result DelegateSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result DelegateSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result DelegateMint(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CurrentHold(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                            const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CurrentSend(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                            const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CurrentSendAll(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                               const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CurrentMint(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                            const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Vote(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                     const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result ExpenseRatio(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Allowance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result AllowanceSender(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result AllowanceCurrent(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                 const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result AllowanceDelegate(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                  const WasmEdge_Value *In, WasmEdge_Value *Out);
                                  
WasmEdge_Result InstrumentContractBridge(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                         const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result SendMulti(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
    const WasmEdge_Value *In, WasmEdge_Value *Out);
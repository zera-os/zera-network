#pragma once
#include <wasmedge/wasmedge.h>

WasmEdge_Result WalletAddress(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result PublicKey(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                          const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result LastBlockTime(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result ContractExists(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                               const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result ContractDenomination(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                     const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result WalletTokens(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                             const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result WalletBalance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                              const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result SmartContractBalance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                     const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result TXNHash(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                        const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CirculatingSupply(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                  const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result SmartContractWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                    const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CurrentSmartContractWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                           const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CalledSmartContractWallet(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                          const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result CurrentSmartContractBalance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                            const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Compliance(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                           const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result ComplianceLevels(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                 const WasmEdge_Value *In, WasmEdge_Value *Out);


WasmEdge_Result VerifySignature(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                 const WasmEdge_Value *In, WasmEdge_Value *Out);

WasmEdge_Result Hash(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
                                 const WasmEdge_Value *In, WasmEdge_Value *Out);

// WasmEdge_Result ContractWallets(void *Data, const WasmEdge_CallingFrameContext *CallFrameCxt,
//                                 const WasmEdge_Value *In, WasmEdge_Value *Out);
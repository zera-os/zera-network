#include "nf_helpers.h"
#include "smart_contract_service.h"
#include "logging.h"

bool in_call_chain(const std::string &instance_name, SenderDataType &sender)
{
    bool in_call_chain = false;
    for (auto &call : sender.call_chain)
    {
      if (call == instance_name)
      {
        in_call_chain = true;
        break;
      }
    }

    if (!in_call_chain)
    {
      logging::print("[in_call_chain] FAILED: Delegate contract not in call chain: " + instance_name, true);
      return false;
    }

    return true;
}
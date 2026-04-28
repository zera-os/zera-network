#pragma once

#include <string>
#include <vector>

struct BlockEmitType
{
  std::string smart_contract_name;
  std::string smart_contract_instance; 
  std::string function; 
  std::vector<std::string> emits; 
  uint64_t depth;
};

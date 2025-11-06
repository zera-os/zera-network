cmake_minimum_required(VERSION 3.8)

project(z_validator)
set (CMAKE_VERBOSE_MAKEFILE ON)
set (CMAKE_CXX_STANDARD 17)
# Set C++ flags
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -frtti -fthreadsafe-statics -w")

# Set C flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11")

set(ZERA_DIR ${CMAKE_SOURCE_DIR}/z_validator)

include_directories(
    /usr/include
    /usr/local/lib
    /usr/local/include
    ${ZERA_DIR}/headers
    ${ZERA_DIR}/block_process
    ${ZERA_DIR}/attestation
    ${ZERA_DIR}/compliance
    ${ZERA_DIR}/blake3
    ${ZERA_DIR}/process_compliance
    ${ZERA_DIR}/crypto
    ${ZERA_DIR}/db
    ${ZERA_DIR}/governance
    ${ZERA_DIR}/grpc
    ${ZERA_DIR}/logging
    ${ZERA_DIR}/proposer
    ${ZERA_DIR}/restricted
    ${ZERA_DIR}/smart_contract
    ${ZERA_DIR}/temp_data
    ${ZERA_DIR}/txn_batch
    ${ZERA_DIR}/util
    ${ZERA_DIR}/vp
    ${ZERA_DIR}/test
)

link_directories(/usr/lib/x86_64-linux-gnu)

# Specify the source files
set(SOURCES
    #main
    ${ZERA_DIR}/zera-validator.cpp

    #REMOVE SOON
    ${ZERA_DIR}/util/get_legal_string.cpp
    
    #standard
    ${ZERA_DIR}/block_process/template/process_allowance.cpp
    ${ZERA_DIR}/block_process/template/process_update_contract.cpp
    ${ZERA_DIR}/block_process/template/process_votes.cpp
    ${ZERA_DIR}/block_process/template/process_sbt_burn.cpp
    ${ZERA_DIR}/block_process/template/process_quash.cpp
    ${ZERA_DIR}/block_process/template/process_fast_quorum.cpp
    ${ZERA_DIR}/block_process/template/process_nft.cpp
    ${ZERA_DIR}/block_process/template/process_compliance.cpp
    ${ZERA_DIR}/block_process/template/process_revoke.cpp
    ${ZERA_DIR}/block_process/template/process_quash.cpp
    ${ZERA_DIR}/block_process/template/process_delegated_voting.cpp
    ${ZERA_DIR}/block_process/template/process_contract.cpp

    #temp_data
    ${ZERA_DIR}/temp_data/allowance_tracker.cpp
    ${ZERA_DIR}/temp_data/recieved_tracker.cpp
    ${ZERA_DIR}/temp_data/contract_price_tracker.cpp
    ${ZERA_DIR}/temp_data/proposer_tracker.cpp
    ${ZERA_DIR}/temp_data/txn_hash_tracker.cpp
    ${ZERA_DIR}/temp_data/balance_tracker.cpp
    ${ZERA_DIR}/temp_data/status_fee_tracker.cpp
    ${ZERA_DIR}/temp_data/nonce_tracker.cpp
    ${ZERA_DIR}/temp_data/txn_tracker.cpp
    ${ZERA_DIR}/temp_data/item_tracker.cpp
    ${ZERA_DIR}/temp_data/sbt_burn_tracker.cpp
    ${ZERA_DIR}/temp_data/fast_quorum_tracker.cpp
    ${ZERA_DIR}/temp_data/quash_tracker.cpp
    ${ZERA_DIR}/temp_data/supply_tracker.cpp

    #crypto utils
    ${ZERA_DIR}/crypto/signatures.cpp
    ${ZERA_DIR}/crypto/merkle.cpp
    ${ZERA_DIR}/crypto/wallets.cpp
    ${ZERA_DIR}/crypto/lottery.cpp

    #database
    ${ZERA_DIR}/db/migrate_db.cpp
    ${ZERA_DIR}/db/reorg.cpp
    ${ZERA_DIR}/db/db_config.cpp
    ${ZERA_DIR}/db/database.cpp
    ${ZERA_DIR}/db/db_base.cpp
    ${ZERA_DIR}/db/db_block_headers.cpp
    ${ZERA_DIR}/db/db_blocks.cpp
    ${ZERA_DIR}/db/db_validators.cpp


    #custom
    ${ZERA_DIR}/block_process/custom/process_proposal.cpp
    ${ZERA_DIR}/block_process/custom/process_required_version.cpp
    ${ZERA_DIR}/block_process/custom/process_mint.cpp
    ${ZERA_DIR}/block_process/custom/process_registration.cpp
    ${ZERA_DIR}/block_process/custom/process_heartbeat.cpp
    ${ZERA_DIR}/block_process/custom/process_new_coin.cpp
    ${ZERA_DIR}/block_process/custom/process_item_mint.cpp
    ${ZERA_DIR}/block_process/custom/process_expense.cpp
    ${ZERA_DIR}/block_process/custom/process_smart_contract_deploy.cpp
    ${ZERA_DIR}/block_process/custom/process_smart_contract_execute.cpp
    ${ZERA_DIR}/block_process/custom/process_smart_contract_instantiate.cpp

    #grpc
    ${ZERA_DIR}/grpc/client/validator_api_client.cpp
    ${ZERA_DIR}/grpc/api/contract.cpp
    ${ZERA_DIR}/grpc/api/smart_contract_activity.cpp
    ${ZERA_DIR}/grpc/api/proposals.cpp
    ${ZERA_DIR}/grpc/api/block.cpp
    ${ZERA_DIR}/grpc/api/database.cpp
    ${ZERA_DIR}/grpc/api/ace_tokens.cpp
    ${ZERA_DIR}/grpc/api/api_service.cpp
    ${ZERA_DIR}/grpc/api/balance.cpp
    ${ZERA_DIR}/grpc/api/base_fee.cpp
    ${ZERA_DIR}/grpc/api/contract_fee.cpp
    ${ZERA_DIR}/grpc/api/denomination.cpp
    ${ZERA_DIR}/grpc/api/items.cpp
    ${ZERA_DIR}/grpc/api/nonce.cpp
    
    #smart contracts
    ${ZERA_DIR}/smart_contract/smart_contract_service.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_multi_send.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_contract_bridge.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_allowance.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_vote.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_expense_ratio.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_utils.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_hold.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_mint.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_send.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_transfer.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_get_ace.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_db_get_data.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_db_store_single.cpp
    ${ZERA_DIR}/smart_contract/native_functions/native_function_states.cpp

    #utils
    ${ZERA_DIR}/util/startup_config.cpp
    ${ZERA_DIR}/util/threadpool.cpp
    ${ZERA_DIR}/util/validate_block.cpp
    ${ZERA_DIR}/util/utils.cpp
    ${ZERA_DIR}/util/validators.cpp
    ${ZERA_DIR}/util/validator_config.cpp
    ${ZERA_DIR}/util/hex_conversion.cpp
    ${ZERA_DIR}/util/base58.cpp
    ${ZERA_DIR}/util/block.cpp

    #restricted
    ${ZERA_DIR}/restricted/restricted_keys.cpp

    #txn
    ${ZERA_DIR}/vp/verify_process.cpp

    ${ZERA_DIR}/vp/vp_broadcast.cpp

    
    #proposer
    ${ZERA_DIR}/proposer/validator_balances.cpp
    ${ZERA_DIR}/proposer/validate_block.cpp
    ${ZERA_DIR}/proposer/proposer.cpp
    ${ZERA_DIR}/proposer/select_validators.cpp
    ${ZERA_DIR}/proposer/reg_process.cpp
    ${ZERA_DIR}/proposer/proposer_utils.cpp
    ${ZERA_DIR}/proposer/pre_process.cpp

    #governance
    ${ZERA_DIR}/governance/time_calc.cpp
    ${ZERA_DIR}/governance/gov_process.cpp

     #attestations
     ${ZERA_DIR}/attestation/attestation_process.cpp

    #logging
    ${ZERA_DIR}/logging/logging.cpp

    #compliance
    ${ZERA_DIR}/compliance/compliance.cpp

    #blake3
    ${ZERA_DIR}/blake3/blake3.c
    ${ZERA_DIR}/blake3/blake3_dispatch.c
    ${ZERA_DIR}/blake3/blake3_portable.c

    #testing
    ${ZERA_DIR}/test/test.cpp
    ${ZERA_DIR}/test/debug.cpp

     # #protobufs
    ${ZERA_DIR}/headers/txn.grpc.pb.cc
    ${ZERA_DIR}/headers/txn.pb.cc
    ${ZERA_DIR}/headers/validator.grpc.pb.cc
    ${ZERA_DIR}/headers/validator.pb.cc
    ${ZERA_DIR}/headers/wallet.pb.cc
    ${ZERA_DIR}/headers/zera_api.grpc.pb.cc
    ${ZERA_DIR}/headers/zera_api.pb.cc

    #grpcs
    ${ZERA_DIR}/grpc/p2p/client/gossip_client.cpp
    ${ZERA_DIR}/grpc/p2p/client/attestation_client.cpp
    ${ZERA_DIR}/grpc/p2p/client/block_sync_client.cpp
    ${ZERA_DIR}/grpc/p2p/client/validator_network_client.cpp
   
    ${ZERA_DIR}/grpc/client/client_network_service.cpp
       
    ${ZERA_DIR}/grpc/p2p/server/attestation_service.cpp
    ${ZERA_DIR}/grpc/p2p/server/block_sync_service.cpp
    ${ZERA_DIR}/grpc/p2p/server/broadcast_service.cpp
    ${ZERA_DIR}/grpc/p2p/api/nonce_service.cpp
    ${ZERA_DIR}/grpc/p2p/api/indexer_voting_service.cpp
    ${ZERA_DIR}/grpc/p2p/api/balance_service.cpp
    ${ZERA_DIR}/grpc/p2p/server/validator_network_service.cpp
    ${ZERA_DIR}/grpc/p2p/server/gossip_service.cpp
    
    #process_block
    ${ZERA_DIR}/block_process/fees_simple.cpp
    ${ZERA_DIR}/block_process/fees.cpp
    ${ZERA_DIR}/block_process/store_txns.cpp
    ${ZERA_DIR}/block_process/block_timer.cpp
    ${ZERA_DIR}/block_process/pre_process.cpp
    ${ZERA_DIR}/block_process/process_txn.cpp
    ${ZERA_DIR}/block_process/process_utils.cpp
    
    #governance
    ${ZERA_DIR}/governance/time_calc.cpp
    ${ZERA_DIR}/governance/gov_process.cpp

    #batch_txns
    ${ZERA_DIR}/txn_batch/batch_misc.cpp
    ${ZERA_DIR}/txn_batch/batch_gov.cpp
    ${ZERA_DIR}/txn_batch/batch_validator.cpp
    ${ZERA_DIR}/txn_batch/batch_proposals.cpp
    ${ZERA_DIR}/txn_batch/batch_contract.cpp
    ${ZERA_DIR}/txn_batch/batch_item.cpp
    ${ZERA_DIR}/txn_batch/batch_smart_contract.cpp
)

# Set compile options
add_compile_options(
    -Wswitch
    -Wno-deprecated-declarations
    -Wempty-body
    #-Wconversion
    -Wreturn-type
    -Wparentheses
    -Wno-format
    -Wuninitialized
    -Wunreachable-code
    #-Wunused-function
    #-Wno-unused-function
    #-Wunused-value
    #-Wunused-variable
    #-std=c++17
    -Wall
    -fno-strict-aliasing
    -g2
    -gdwarf-2
    -O0
    #-frtti
    -fno-omit-frame-pointer
    #-std=c11
    -fexceptions
    -D_TIME_BITS=64
    -D_FILE_OFFSET_BITS=64 # Add this line
)

# Create the executable
add_executable(zera-validator ${SOURCES})

# Link necessary libraries
target_link_libraries(zera-validator
    grpc++
    protobuf
    leveldb
    rocksdb
    sodium
    ssl
    crypto
    boost_system
    wasmedge 
)

#include "temp_data.h"
#include "db_base.h"
#include "utils.h"

std::map<std::string, zera_validator::ContractPrice> contract_price_tracker::contract_prices;

std::mutex contract_price_tracker::mtx;

void contract_price_tracker::update_price(const std::string &contract_id)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string symbol = contract_id;
    if (symbol.size() > 6)
    {
        symbol = symbol.substr(0, symbol.size() - 5);
    }
    else
    {
        return;
    }
    std::string contract_price_data;
    zera_validator::ContractPrice contract_price;
    uint256_t price;
    if (contract_prices.find(symbol) != contract_prices.end())
    {
        contract_price = contract_prices[symbol];
        std::string contract_price_string = contract_price.multiplier();
        uint32_t number_of_symbols = contract_price.number_of_symbols();
        number_of_symbols++;
        contract_price.set_number_of_symbols(number_of_symbols);
        price = uint256_t(contract_price_string);
        price = (price * 100114441424715) / 100000000000000;
    }
    else
    {
        if (db_contract_price::get_single(symbol, contract_price_data))
        {
            contract_price.ParseFromString(contract_price_data);
            std::string contract_price_string = contract_price.multiplier();
            uint32_t number_of_symbols = contract_price.number_of_symbols();
            number_of_symbols++;
            contract_price.set_number_of_symbols(number_of_symbols);
            price = uint256_t(contract_price_string);
            price = (price * 100114441424715) / 100000000000000;
        }
        else
        {
            contract_price.set_symbol(symbol);
            contract_price.set_number_of_symbols(1);
            price = get_fee("CONTRACT_TXN_FEE");
        }
    }


    contract_price.set_multiplier(boost::lexical_cast<std::string>(price));

    contract_prices[symbol] = contract_price;

}

void contract_price_tracker::get_price(const std::string &contract_id, uint256_t& price)
{
    std::lock_guard<std::mutex> lock(mtx);
    std::string symbol = contract_id;
    if (symbol.size() > 6)
    {
        symbol = symbol.substr(0, symbol.size() - 5);
    }
    else
    {
        return;
    }

    if (contract_prices.find(symbol) != contract_prices.end())
    {
        zera_validator::ContractPrice contract_price = contract_prices[symbol];
        std::string contract_price_string = contract_price.multiplier();
        price = uint256_t(contract_price_string);
    }
    else
    {
        std::string contract_price_data;
        zera_validator::ContractPrice contract_price;
        if (db_contract_price::get_single(symbol, contract_price_data))
        {
            contract_price.ParseFromString(contract_price_data);
            std::string contract_price_string = contract_price.multiplier();
            price = uint256_t(contract_price_string);
        }
        else
        {
            price = get_fee("CONTRACT_TXN_FEE");
        }
    }
}
void contract_price_tracker::store_prices()
{
    std::lock_guard<std::mutex> lock(mtx);

    for(auto &contract_price : contract_prices)
    {
        std::string contract_price_data = contract_price.second.SerializeAsString();
        db_contract_price::store_single(contract_price.first, contract_price_data);
    }
}

void contract_price_tracker::clear_prices()
{
    std::lock_guard<std::mutex> lock(mtx);
    contract_prices.clear();
}
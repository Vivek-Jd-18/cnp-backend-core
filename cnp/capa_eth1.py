# Capacity Ethereum 1.x utilities

from web3 import Web3, middleware
from web3 import exceptions as web3_exceptions
from web3.gas_strategies import time_based as gas_strategies_time_based
from web3.gas_strategies import rpc as gas_strategies_rpc
from web3.providers import JSONBaseProvider
from web3.types import RPCResponse
from ens import ENS
from eth_account import Account
from typing import cast
import yaml
import requests
import os
import sys
import json
import ujson
import time
import re
import eth_account
import threading
import logging
from . import capa_base

# Define various constants.
ZERO_ADDRESS = "0x0000000000000000000000000000000000000000"
ZERO_PRIVKEY = "0x0000000000000000000000000000000000000000000000000000000000000000"

tx_lock = threading.Lock()


def get_eth1_config(primary_path="", fallback_path="config/config.yaml", defaults={}, logger=None):
    # Make sure to always call this with both path parameters before calling other functions in this module that use the config!
    # See if the config is cached already, otherwise cache it.
    cache_store = get_eth1_config
    cache_name = "config"
    cache_name_invalidate = "config_invalidate"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None or (hasattr(cache_store, cache_name_invalidate) and getattr(cache_store, cache_name_invalidate)):
        if hasattr(cache_store, cache_name_invalidate):
            delattr(cache_store, cache_name_invalidate)
        if not hasattr(cache_store, cache_name):
            setattr(cache_store, cache_name, None)
        # Now, actually try to get the config from the json_path.
        if os.path.isfile(primary_path):
            config_path = primary_path
        else:
            config_path = fallback_path
        if os.path.isfile(config_path):
            try:
                with open(config_path) as yaml_file:
                    # Use safe_load instead load.
                    config = yaml.safe_load(yaml_file)
                    setattr(cache_store, cache_name, config)
            except:
                if logger:
                    logger.error("Error reading data from file: %s (%s)" % (sys.exc_info()[0], sys.exc_info()[1]))
                config = {}
        else:
            if logger:
                logger.error("File not found: %s" % config_path)
            config = {}
    else:
        config = getattr(cache_store, cache_name)
    # Apply defaults for missing values
    capa_base.config_default(config, "json_rpc_url", "http://localhost:8545/", defaults)
    capa_base.config_default(config, "json_rpc_timeout", 60, defaults)
    capa_base.config_default(config, "json_rpc_log", False, defaults)
    capa_base.config_default(config, "use_poa_network", False, defaults)
    capa_base.config_default(config, "use_fast_json", False, defaults)
    capa_base.config_default(config, "caching_enabled", False, defaults)
    capa_base.config_default(config, "gas_strategy", "rpc", defaults)  # supports "fast", "medium", "slow", "glacial" - anything else gets treated as "rpc"
    capa_base.config_default(config, "local_filters", False, defaults)
    capa_base.config_default(config, "l2_json_rpc_url", "", defaults)
    capa_base.config_default(config, "l2_json_rpc_timeout", 60, defaults)
    capa_base.config_default(config, "l2_json_rpc_log", False, defaults)
    capa_base.config_default(config, "l2_use_poa_network", False, defaults)
    capa_base.config_default(config, "l2_use_fast_json", False, defaults)
    capa_base.config_default(config, "l2_caching_enabled", False, defaults)
    capa_base.config_default(config, "l2_gas_strategy", "rpc", defaults)  # supports "fast", "medium", "slow", "glacial" - anything else gets treated as "rpc"
    capa_base.config_default(config, "l2_local_filters", False, defaults)
    capa_base.config_default(config, "gaslimit_estimate_factor", 1.1, defaults)  # factor to multiply estimates with when setting actual gas limit
    capa_base.config_default(config, "gaslimit_estimate_max", 4000000, defaults)  # We do not allow (estimate * factor) to grow over this number.

    capa_base.config_default(config, "chain_parameters", {}, defaults)
    capa_base.config_default(config, "l2_chain_parameters", {}, defaults)

    capa_base.config_default(config, "explorer_api_url", {}, defaults)
    capa_base.config_default(config["explorer_api_url"], "main", "https://api.etherscan.io/api?")
    capa_base.config_default(config["explorer_api_url"], "ropsten", "https://api-ropsten.etherscan.io/api?")
    capa_base.config_default(config["explorer_api_url"], "rinkeby", "https://api-rinkeby.etherscan.io/api?")
    capa_base.config_default(config["explorer_api_url"], "kovan", "https://api-kovan.etherscan.io/api?")
    capa_base.config_default(config["explorer_api_url"], "goerli", "https://api-goerli.etherscan.io/api?")
    capa_base.config_default(config["explorer_api_url"], "xdai", "https://blockscout.com/xdai/mainnet/api?")
    capa_base.config_default(config["explorer_api_url"], "polygon", "https://api.polygonscan.com/api?")
    capa_base.config_default(config, "explorer_api_key", "", defaults)

    capa_base.config_default(config, "tx_version", "legacy", defaults)  # supports "legacy" or "eip1559" - anything else gets treated as "legacy"
    # gas_station_api: None for always return gas_default_gwei, "node:" gets price from node (potentially with suffix)
    capa_base.config_default(config, "gas_station_api", "https://ethgasstation.info/json/ethgasAPI.json", defaults)
    capa_base.config_default(config, "gas_station_mode", "ethgasstation", defaults)  # ethgasstation or blockscout
    capa_base.config_default(config, "gas_price_cache_seconds", 60, defaults)
    capa_base.config_default(config, "gas_speed_level_default", "safeLow", defaults)  # as defined by ethgasstation, i.e. "fastest", "fast", "average", or "safeLow"
    capa_base.config_default(config, "gas_default_gwei", 10, defaults)
    capa_base.config_default(config, "gas_max_gwei", 100, defaults)
    capa_base.config_default(config, "gas_fee_recent_blocks", 10, defaults)
    capa_base.config_default(config, "gas_fee_percentile", 5, defaults)
    return config


# This and the next function are for speeding up JSON-RPC access,
# see https://web3py.readthedocs.io/en/latest/troubleshooting.html#making-ethereum-json-rpc-api-access-faster
def _fast_decode_rpc_response(raw_response: bytes) -> RPCResponse:
    decoded = ujson.loads(raw_response)
    return cast(RPCResponse, decoded)


def patch_provider(provider: JSONBaseProvider):
    """Monkey-patch web3.py provider for faster JSON decoding.

    Call this on your provider after construction.

    This greatly improves JSON-RPC API access speeds, when fetching
    multiple and large responses.
    """
    provider.decode_rpc_response = _fast_decode_rpc_response


def invalidate_cached_eth1_config(logger=None):
    cache_store = get_eth1_config
    cache_name_invalidate = "config_invalidate"
    setattr(cache_store, cache_name_invalidate, True)


# Create and return the connection to the node via the web3 API.
def get_web3_connection(middleware_inject=None, middleware_add=None, l2=False,
                        patch_ecrecover=False, use_cache=None, local_filters=False,
                        logger=None):
    config = get_eth1_config(logger=logger)
    layerprefix = "l2_" if l2 else ""
    # Create actual Web3 object.
    if not len(config[f"{layerprefix}json_rpc_url"]):
        logger.error(f"No RPC URL configured for layer {'2' if l2 else '1'}!")
        return None
    if config[f"{layerprefix}json_rpc_url"].startswith("ws"):
        time_start = time.time()
        w3_new = Web3(Web3.WebsocketProvider(config[f"{layerprefix}json_rpc_url"]))
        # Wait for connection.
        while (not w3_new.isConnected()) and (time.time() - time_start) < config[f"{layerprefix}json_rpc_timeout"]:
            time.sleep(1)
    else:
        w3_new = Web3(Web3.HTTPProvider(config[f"{layerprefix}json_rpc_url"], request_kwargs={"timeout": config[f"{layerprefix}json_rpc_timeout"]}))
    # Check connection, don't do any other setup if it's not connected.
    try:
        if not w3_new.isConnected():
            return None
    except:
        logger.warning("Error checking for isConnected(): %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return None
    # Patch provider ot make JSON-RPC access faster.
    if config[f"{layerprefix}use_fast_json"]:
        patch_provider(w3_new.provider)
    # *** Middleware settings ***
    # POA networks
    if config[f"{layerprefix}use_poa_network"]:
        # See https://web3py.readthedocs.io/en/stable/middleware.html#geth-style-proof-of-authority
        # This also works for Görli on OpenEthereum.
        w3_new.middleware_onion.inject(middleware.geth_poa_middleware, layer=0)
    # Log JSON-RPC calls.
    if config[f"{layerprefix}json_rpc_log"]:
        w3_new.middleware_onion.inject(logging_middleware, layer=0)
    # Inject custom middleware if needed.
    if middleware_inject:
        for mwi in middleware_inject:
            w3_new.middleware_onion.inject(mwi, layer=0)
    # Caching - either a real Boolean or a string including "s", "t", "b" for simple, time-base, block-based
    if use_cache is None:
        use_cache = config[f"{layerprefix}caching_enabled"]
    if use_cache is True or (type(use_cache) == str and "t" in use_cache):
        w3_new.middleware_onion.add(middleware.time_based_cache_middleware)
    if use_cache is True or (type(use_cache) == str and "b" in use_cache):
        w3_new.middleware_onion.add(middleware.latest_block_based_cache_middleware)
    if use_cache is True or (type(use_cache) == str and "s" in use_cache):
        w3_new.middleware_onion.add(middleware.simple_cache_middleware)
    # Local filters
    if local_filters or config[f"{layerprefix}local_filters"]:
        w3_new.middleware_onion.add(middleware.local_filter_middleware)
    # Patch ecRecover for a web3.py bug
    if patch_ecrecover:
        w3_new.middleware_onion.add(patch_ecrecover_error_middleware)
    # Add any additional middleware.
    if middleware_add:
        for mwa in middleware_add:
            w3_new.middleware_onion.add(mwa)
    # Check connection again.
    try:
        if not w3_new.isConnected():
            return None
    except:
        logger.warning("Error checking for isConnected(): %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return None

    # Set gas strategy.
    try:
        chain_id = w3_new.eth.chain_id  # Note that tx_version can be set by chain ID, so only go do this now that we should have an ID.
    except:
        logger.warning("Could not read chain ID: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return None
    tx_version = config[f"tx_version_{chain_id}"] if f"tx_version_{chain_id}" in config else config["tx_version"]
    if tx_version not in {"legacy", "eip1559"}:
        tx_version = "legacy"
    if tx_version == "legacy":  # DO NOT USE gas_strategy for EIP-1559 chains at all (to match web3.py expectations)!
        if config[f"{layerprefix}gas_strategy"] == "fast":  # Transaction mined within 60 seconds.
            if not config[f"{layerprefix}caching_enabled"]:
                logger.warning("Using time-based gas strategy without caching is not recommended!")
            w3_new.eth.set_gas_price_strategy(gas_strategies_time_based.fast_gas_price_strategy)
        elif config[f"{layerprefix}gas_strategy"] == "medium":  # Transaction mined within 5 minutes.
            if not config[f"{layerprefix}caching_enabled"]:
                logger.warning("Using time-based gas strategy without caching is not recommended!")
            w3_new.eth.set_gas_price_strategy(gas_strategies_time_based.medium_gas_price_strategy)
        elif config[f"{layerprefix}gas_strategy"] == "slow":  # Transaction mined within 1 hour.
            if not config[f"{layerprefix}caching_enabled"]:
                logger.warning("Using time-based gas strategy without caching is not recommended!")
            w3_new.eth.set_gas_price_strategy(gas_strategies_time_based.slow_gas_price_strategy)
        elif config[f"{layerprefix}gas_strategy"] == "glacial":  # Transaction mined within 24 hours.
            if not config[f"{layerprefix}caching_enabled"]:
                logger.warning("Using time-based gas strategy without caching is not recommended!")
            w3_new.eth.set_gas_price_strategy(gas_strategies_time_based.glacial_gas_price_strategy)
        else:
            w3_new.eth.set_gas_price_strategy(gas_strategies_rpc.rpc_gas_price_strategy)

    return w3_new


# Terminate the connection to the node via the web3 API.
def kill_web3_connection(w3, connection_label="blockchain", logger=None):
    if not w3:
        # Looks like there's nothing to terminate here.
        return None
    try:
        if w3.provider.__class__.__name__ == "WebsocketProvider":
            w3.admin.stopWS()
        else:
            w3.admin.stopRPC()
    except:
        logger.warning("Error terminating %s connection: %ss (%s)",
                       connection_label, sys.exc_info()[0], sys.exc_info()[1])
    return None  # Assign to original w3 on return to clear object.


# Create and return the connection to the node via the web3 API.
def check_web3_connection(w3, connection_label="blockchain",
                          middleware_inject=None, middleware_add=None, l2=False,
                          patch_ecrecover=False, use_cache=False, local_filters=False,
                          logger=None):
    try:
        block = w3.eth.get_block('latest')  # noqa: F841
        return w3
    except requests.exceptions.ConnectionError:
        logger.warning(f"Apparently, our {connection_label} JSON-RPC connection dropped, trying to re-establish it.")
    except ValueError as err:
        if "code" in err.args[0] and "message" in err.args[0]:
            logger.warning("Got ValueError %s with message: %s", err.args[0]["code"], err.args[0]["message"])
        logger.warning(f"As we had a ValueError, trying to just establish the {connection_label} connection again.")
    except:
        logger.warning(f"Testing our {connection_label} JSON-RPC connection, got an error {sys.exc_info()[0]} ({sys.exc_info()[1]}), trying to re-establish it.")
    # Terminate connection if needed
    if w3 and w3.isConnected():
        kill_web3_connection(w3, connection_label, logger=logger)
    # Try again - we only get here if it failed before.
    try:
        w3 = get_web3_connection(
            middleware_inject=middleware_inject,
            middleware_add=middleware_add, l2=l2,
            patch_ecrecover=patch_ecrecover, use_cache=use_cache,
            local_filters=local_filters, logger=logger
        )
        block = w3.eth.get_block('latest')  # noqa: F841
        return w3
    except requests.exceptions.ConnectionError:
        logger.error(f"Could not recover {connection_label} JSON-RPC connection!")
        return None
    except ValueError as err:
        if "code" in err.args[0] and "message" in err.args[0]:
            logger.warning("Got ValueError %s with message: %s", err.args[0]["code"], err.args[0]["message"])
        logger.error(f"As we had a ValueError, assuming the {connection_label} connection is not working.")
        return None
    except:
        logger.error(f"Testing our {connection_label} JSON-RPC connection, got an error {sys.exc_info()[0]} ({sys.exc_info()[1]}), giving up.")
        return None


# Get wallet_addEthereumChain parameters, see https://eips.ethereum.org/EIPS/eip-3085
def get_chain_parameters(w3, l2=False, logger=None):
    config = get_eth1_config(logger)
    layerprefix = "l2_" if l2 else ""
    config_params = config[f"{layerprefix}chain_parameters"]
    params = {}
    try:
        chain_id = w3.eth.chain_id
    except:
        if logger:
            logger.error("Could not get chain ID: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return None
    if "chainId" in config_params:
        if hex(config_params["chainId"]) == hex(chain_id):
            params["chainId"] = hex(chain_id)
        else:
            if logger:
                logger.error("Chain ID mismatch with config: %s != %s (hex)", hex(config_params["chainId"]) == hex(chain_id))
            return None
    else:
        params["chainId"] = hex(chain_id)
    if "chainName" in config_params:
        params["chainName"] = config_params["chainName"]
    if "rpcUrls" in config_params and type(config_params["rpcUrls"]) == list:
        params["rpcUrls"] = config_params["rpcUrls"]
    if "blockExplorerUrls" in config_params and type(config_params["blockExplorerUrls"]) == list:
        params["blockExplorerUrls"] = config_params["blockExplorerUrls"]
    if "iconUrls" in config_params and type(config_params["iconUrls"]) == list:
        params["iconUrls"] = config_params["iconUrls"]
    if "nativeCurrency" in config_params and type(config_params["nativeCurrency"]) == dict and "symbol" in config_params["nativeCurrency"]:
        params["nativeCurrency"] = config_params["nativeCurrency"]
    return params


# Retrieve the token ABI from a JSON file on disk.
def get_abi(contract_type, contract_info, logger=None):
    return get_contract_info(contract_type, "abi", contract_info, None, logger)


# Retrieve the address from a JSON file on disk.
def get_address(contract_type, w3, contract_info, logger=None):
    try:
        nwdata = get_network_data(w3, logger=logger)
        return get_contract_info(contract_type, "address", contract_info, nwdata["network_id"], logger)
    except:
        if logger:
            logger.error("Could get network ID, no working JSON-RPC connection or no deployment info available: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return None


# Retrieve the deployment block from a JSON file on disk and the blockchain.
def get_deployblock(contract_type, w3, contract_info, logger=None):
    # See if the data is cached already, otherwise cache it.
    nwdata = get_network_data(w3, logger=logger)
    cache_store = get_deployblock
    cache_name = f"blocknum_{contract_type}_{nwdata['network_id']}"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        if not hasattr(cache_store, cache_name):
            setattr(cache_store, cache_name, None)
        # Now, actually try to get the data from JSON and w3.
        try:
            txhash = get_contract_info(contract_type, "deploy_txhash", contract_info, nwdata["network_id"], logger)
            receipt = w3.eth.get_transaction_receipt(txhash)
            setattr(cache_store, cache_name, receipt.blockNumber)
        except:
            if logger:
                logger.error("Could not get transaction receipt, no working JSON-RPC connection or no deployment info available: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            return None
    # Use the cached data here.
    return getattr(cache_store, cache_name)


# Retrieve the signature of an event from a JSON file on disk.
def get_event_signature(event_name, contract_type, w3, contract_info, logger=None):
    try:
        nwdata = get_network_data(w3, logger=logger)
        events = get_contract_info(contract_type, "events", contract_info, nwdata["network_id"], logger)
        for evid in events:
            if events[evid]["name"] == event_name:
                return evid
        logger.error(f"Could not find event '{event_name}' in the deployed event list of the {contract_type} contract!")
        return None
    except:
        if logger:
            logger.error("Could get network ID, no working JSON-RPC connection or no deployment info available: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return None


# Retrieve contract information from a JSON file on disk.
def get_contract_info(contract_type, info_type, all_contracts_info, network_id=None, logger=None):
    # all_contracts_info has a structure like this:
    # {
    #   "thecontract": {"alias_for": "mycontract"},
    #   "mycontract": {"path": "path/to/mycontract.json", "deployed": True},
    #   "yourcontract": {"path": "path/to/<ourcontract.json", "deployed": False},
    # }
    # alias_for redirects to the other name for all not given variables (over one level only)
    # path is the path to the JSON, usually from config
    # deployed tells if a deployment is recorded in the JSON, otherwise address and deploy_txhash are not available.
    if contract_type in all_contracts_info:
        # Get info for this contract specifically.
        contract_info = all_contracts_info[contract_type]
        if "alias_for" in contract_info:
            if contract_info["alias_for"] not in all_contracts_info:
                if logger:
                    logger.error("Contract type %s points to unknown alias: %s", contract_type, contract_info["alias_for"])
                return None
            contract_type = contract_info["alias_for"]
            contract_info = all_contracts_info[contract_type]
        if "path" not in contract_info:
            if logger:
                logger.error("No path defined for contract type: %s", contract_type)
            return None
        json_path = contract_info["path"]
    else:
        if logger:
            logger.error("Contract type unknown: %s", contract_type)
        return None
    if info_type not in ["abi", "address", "instance", "deploy_txhash", "events"]:
        if logger:
            logger.error("Information type unknown: %s", info_type)
        return None
    if info_type in ["address", "instance", "deploy_txhash", "events"]:
        if "deployed" in contract_info and not contract_info["deployed"]:
            if logger:
                logger.error("Deployment needed for %s but info says this is not available" % info_type)
            return None
        if not network_id:
            if logger:
                logger.error("Network info needed for %s but unknown", info_type)
            return None
    # See if the data of the file is cached already, otherwise cache it.
    cache_store = get_contract_info
    cache_name = contract_type
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        if not hasattr(cache_store, cache_name):
            setattr(cache_store, cache_name, None)
        # Now, actually try to get the ABI from the json_path.
        if os.path.isfile(json_path):
            try:
                with open(json_path) as json_file:
                    setattr(cache_store, cache_name, json.load(json_file))
            except:
                if logger:
                    logger.error("Error reading data from file: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
                return None
        else:
            if logger:
                logger.error("File not found: %s", json_path)
            return None
    # Use the cached data here.
    contract_build_data = getattr(cache_store, cache_name)
    if info_type == "instance":
        # Call ourselves recursively!
        return {
            "address": get_contract_info(contract_type, "address", all_contracts_info, network_id, logger),
            "deploy_txhash": get_contract_info(contract_type, "deploy_txhash", all_contracts_info, network_id, logger),
            "abi": get_contract_info(contract_type, "abi", all_contracts_info, network_id, logger),
        }
    # Now, handle items that don't require a recursive call.
    if info_type == "deploy_txhash":
        info_key = "transactionHash"
    else:
        info_key = info_type
    if info_key in ["address", "transactionHash", "events"]:
        if ("networks" not in contract_build_data
                or network_id not in contract_build_data["networks"]
                or info_key not in contract_build_data["networks"][network_id]):
            if logger:
                logger.error("No %s information for network %s found in %s", info_key, network_id, json_path)
            return None
        return contract_build_data["networks"][network_id][info_key]
    # Currently only ABI, but other top-levels could easily be handled here as well.
    if info_type not in contract_build_data:
        if logger:
            logger.error("No %s information found in %s", info_type, json_path)
        return None
    return contract_build_data[info_type]


# Remove/invalidate a cached Web3 contract object for the given contract type.
def invalidate_cached_contract(contract_type, l2, override_address=None, logger=None):
    cache_store = get_cached_contract
    cache_name = f"contract_{contract_type}_{'l2' if l2 else 'l1'}"
    if override_address:
        cache_name = f"{cache_name}_{override_address}"
    if hasattr(cache_store, cache_name):
        delattr(cache_store, cache_name)


# Get a cached Web3 contract object for the given contract type.
def get_cached_contract(w3, contract_type, l2, contract_info, override_address=None, logger=None):
    if not w3:
        return None
    cache_store = get_cached_contract
    cache_name = f"contract_{contract_type}_{'l2' if l2 else 'l1'}"
    if override_address:
        cache_name = f"{cache_name}_{override_address}"
    # Also store w3 ID to make sure we reply with a contract cached for the same w3 object.
    cache_name_w3id = f"{cache_name}_w3id"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None or getattr(cache_store, cache_name_w3id) != id(w3):
        setattr(cache_store, cache_name_w3id, id(w3))
        setattr(cache_store, cache_name, None)
        contract_address = override_address if override_address else get_address(contract_type, w3, contract_info, logger=logger)
        contract_abi = get_abi(contract_type, contract_info, logger=logger)
        if not contract_address or not contract_abi:
            return None
        try:
            w3contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        except:
            if logger:
                logger.warning("Error instantiating %s contract @ %s: %s (%s)", contract_type, contract_address, sys.exc_info()[0], sys.exc_info()[1])
            return None
        setattr(cache_store, cache_name, w3contract)
    else:
        w3contract = getattr(cache_store, cache_name)
    return w3contract


# Get gas info from the ETH gas station.
def get_gas_station_values(url, logger=None):
    if logger:
        logger.info("Get gas info from %s" % url)
    try:
        response = requests.get(url)
        if ('Content-Type' in response.headers
            and re.match(r'^application/json',
                         response.headers['Content-Type'])):
            # create a dict generated from the JSON response.
            gsdata = response.json()
            if response.status_code >= 400:
                # For error-ish codes, tell that they are from ETH Gas Station.
                gsdata["messagesource"] = "ethgasstation"
            return gsdata, response.status_code
        elif response.status_code == 200 and re.match(r'^{', response.text):
            # This may be JSON but has the wrong content type, let's treat it as JSON.
            return response.json(), response.status_code
        else:
            return {"message": response.text,
                    "messagesource": "ethgasstation"}, response.status_code
    except requests.ConnectionError as e:
        return {"message": str(e)}, 503
    except requests.RequestException as e:
        return {"message": str(e)}, 500


# Get gas price via ETH gas station.
def get_gas_price(speed_level=None, chain=1, w3=None, logger=None):
    config = get_eth1_config()
    gas_default_gwei = config[f"gas_default_gwei_{chain}"] if f"gas_default_gwei_{chain}" in config else config["gas_default_gwei"]
    gas_station_api = config[f"gas_station_api_{chain}"] if f"gas_station_api_{chain}" in config else config["gas_station_api"]
    gas_station_mode = config[f"gas_station_mode_{chain}"] if f"gas_station_mode_{chain}" in config else config["gas_station_mode"]
    gas_speed_level_default = config[f"gas_speed_level_default_{chain}"] if f"gas_speed_level_default_{chain}" in config else config["gas_speed_level_default"]
    gas_price_cache_seconds = config[f"gas_price_cache_seconds_{chain}"] if f"gas_price_cache_seconds_{chain}" in config else config["gas_price_cache_seconds"]
    gas_max_gwei = config[f"gas_max_gwei_{chain}"] if f"gas_max_gwei_{chain}" in config else config["gas_max_gwei"]
    if not gas_station_api:
        return Web3.toWei(gas_default_gwei, "Gwei")
    if gas_station_api.startswith("node:"):
        if not w3:
            if logger:
                logger.error("Could not get gas price from node without having a reference to the node, using default of %s Gwei", gas_default_gwei)
            return Web3.toWei(gas_default_gwei, "Gwei")
        try:
            gasprice = w3.eth.generate_gas_price()
            if len(gas_station_api) > len("node:"):
                if gas_station_api[len("node:")] == "*":
                    if logger:
                        logger.debug(f"Multiply node's gas price by {float(gas_station_api[len('node:*'):])}")
                    gasprice = int(gasprice * float(gas_station_api[len("node:*"):]))
                elif gas_station_api[len("node:")] == "+":
                    if logger:
                        logger.debug(f"Increase node's gas price by {float(gas_station_api[len('node:+'):])} Gwei")
                    gasprice = int(gasprice + float(gas_station_api[len("node:+"):]) * Web3.toWei(1, "Gwei"))
                else:
                    if logger:
                        logger.warning("Don't know what to do with suffix of {gas_station_api}")
        except:
            if logger:
                logger.error("Error getting gas price from node, using default of %s Gwei", gas_default_gwei)
            gasprice = Web3.toWei(gas_default_gwei, "Gwei")
    else:
        if speed_level not in ["fastest", "fast", "average", "safeLow"]:
            speed_level = gas_speed_level_default
        # Caching of actual values from gas station values is done here.
        cache_store = get_gas_price
        cache_name = "gas_station_values_{chain}"
        if (not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None
                or getattr(cache_store, "timestamp") < time.time() - gas_price_cache_seconds):
            # Always set the timestamp so we do not have to test above if it's set,
            #  as it's only unset when token is also unset
            setattr(cache_store, "timestamp", time.time())
            if not hasattr(cache_store, cache_name):
                setattr(cache_store, cache_name, None)
            # Now, actually try to get the gas station values.
            gasdata, gas_status_code = get_gas_station_values(gas_station_api)
            if gas_status_code < 400:
                # Only cache new values if call was successful.
                setattr(cache_store, cache_name, gasdata)
        # Actually use cached values here.
        gasvalues = getattr(cache_store, cache_name)
        if not gasvalues:
            if logger:
                logger.info("Could not get gas price from API, using default of %s Gwei", gas_default_gwei)
            gasprice = Web3.toWei(gas_default_gwei, "Gwei")
        elif gas_station_mode == "blockscout":
            # First, make sure speed levels are what this API supports.
            if speed_level == "fastest":
                speed_level = "fast"
            elif speed_level == "safeLow":
                speed_level = "slow"
            gasprice = Web3.toWei(float(gasvalues[speed_level]), "Gwei")
        elif gas_station_mode == "precise":
            gasprice = Web3.toWei(float(gasvalues[speed_level]), "Gwei")
        else:  # gas_station_mode == "ethgasstation"
            gasprice = Web3.toWei(gasvalues[speed_level] / 10, "Gwei")
    if Web3.fromWei(gasprice, "Gwei") > gas_max_gwei:
        if logger:
            logger.info("Gas price from API too high, using max of %s Gwei", gas_max_gwei)
        gasprice = Web3.toWei(gas_max_gwei, "Gwei")
    return gasprice


# Get gas fees for EIP 1559 transactions.
def get_gas_fees(chain_id=1, w3=None, logger=None):
    config = get_eth1_config()
    # TODO: support a gas fee API like e.g. https://gasstation-mainnet.matic.network/v2
    gas_default_gwei = config[f"gas_default_gwei_{chain_id}"] if f"gas_default_gwei_{chain_id}" in config else config["gas_default_gwei"]
    gas_max_gwei = config[f"gas_max_gwei_{chain_id}"] if f"gas_max_gwei_{chain_id}" in config else config["gas_max_gwei"]

    # Use fee history to determine priority fee.
    # This pretty much mirrors what Web3.py is doing internally since https://github.com/ethereum/web3.py/commit/634c89877f0a28d40333782db62e109f80c659d9
    # It's a bit more simplified than what MyCrypto is using in https://github.com/MyCryptoHQ/gas-estimation/blob/master/src/eip1559.ts
    recent_block_count = config[f"gas_fee_recent_blocks_{chain_id}"] if f"gas_fee_recent_blocks_{chain_id}" in config else config["gas_fee_recent_blocks"]
    fee_percentile = config[f"gas_fee_percentile_{chain_id}"] if f"gas_fee_percentile_{chain_id}" in config else config["gas_fee_percentile"]
    fee_history = w3.eth.fee_history(recent_block_count, "pending", reward_percentiles=[fee_percentile])
    non_empty_block_fees = [fee[0] for fee in fee_history["reward"] if fee[0] != 0]
    if len(non_empty_block_fees):
        avg_priority_fee = round(sum(non_empty_block_fees) / len(non_empty_block_fees))
    else:
        # We had no non-zero value in the list, let's go to the default.
        avg_priority_fee = Web3.toWei(gas_default_gwei, "Gwei")
    return {"priority_fee": avg_priority_fee, "max_fee": Web3.toWei(gas_max_gwei, "Gwei")}


def get_network_name(networkid, chainid=None):
    # See https://ethereum.stackexchange.com/questions/17051/how-to-select-a-network-id-or-is-there-a-list-of-network-ids/17101#17101
    # or https://chainid.network/
    if chainid == 1 or (chainid is None and networkid == "1"):
        return "main"
    elif chainid == 61:
        return "classic"
    elif chainid == 3 or (chainid is None and networkid == "3"):
        return "ropsten"  # PoW testnet
    elif chainid == 4 or (chainid is None and networkid == "4"):
        return "rinkeby"  # geth testnet
    elif chainid == 5 or (chainid is None and networkid == "5"):
        return "goerli"  # cross-client PoA testnet
    elif chainid == 10 or (chainid is None and networkid == "10"):
        return "main-optimism"  # Optimistic Ethereum Mainnet
    elif chainid == 42 or (chainid is None and networkid == "42"):
        return "kovan"  # Parity testnet
    elif chainid == 100 or (chainid is None and networkid == "100"):
        return "xdai"  # xDAI Chain
    elif chainid == 137 or (chainid is None and networkid == "137"):
        return "polygon"  # Polygon PoS (Matic) Mainnet
    elif chainid == 420 or (chainid is None and networkid == "420"):
        return "goerli-optimism"  # Optimistic Ethereum Goerli testnet
    elif chainid == 1001 or (chainid is None and networkid == "1001"):
        return "klaytn-baobab"  # Klaytn Testnet Baobab
    elif chainid == 8217 or (chainid is None and networkid == "8217"):
        return "klaytn-cypress"  # Klaytn Mainnet Cypress
    elif chainid == 80001 or (chainid is None and networkid == "80001"):
        return "matic-mumbai"  # Matic Mumbai Testnet
    elif chainid == 1337:
        return f"ganache-{networkid}"  # development test server
    return None


def get_long_chain_name(network_symbol):
    # network_symbol is what gets returned from get_network_name() or similar functions.
    if network_symbol in {"main", "mainnet", "eth", "ethereum"}:
        return "Ethereum Main Chain"
    elif network_symbol == "classic":
        return "Ethereum Classic"
    elif network_symbol == "ropsten":
        return "Ropsten PoW Testnet"
    elif network_symbol == "rinkeby":
        return "Rinkeby Geth Testnet"
    elif network_symbol == "goerli":
        return "Görli Cross-Client PoA Testnet"
    elif network_symbol == "main-optimism":
        return "Optimistic Ethereum"
    elif network_symbol == "kovan":
        return "Kovan Parity Testnet"
    elif network_symbol in {"xdai", "gnosis"}:
        return "Gnosis Chain (formerly xDai)"
    elif network_symbol in {"matic", "polygon"}:
        return "Polygon PoS (Matic)"
    elif network_symbol == "goerli-optimism":
        return "Optimistic Ethereum Goerli Testnet"
    elif network_symbol == "klaytn-baobab":
        return "Klaytn Testnet Baobab"
    elif network_symbol == "klaytn-cypress":
        return "Klaytn Mainnet Cypress"
    elif network_symbol == "matic-mumbai":
        return "Matic Mumbai Testnet"
    return f"{network_symbol} Chain"


def get_network_data(w3, use_cache=True, check=False, ens=False, logger=None):
    if not w3:
        return None
    cache_store = get_network_data
    cache_name = f"data_{id(w3)}"
    if check:
        try:
            chain_id = w3.eth.chain_id  # noqa: F841
        except:
            setattr(cache_store, cache_name, None)
            if logger:
                logger.warning("Could not get network info: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            return None
    if not use_cache or not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        try:
            data = {}
            data["network_id"] = w3.net.version
            data["chain_id"] = w3.eth.chain_id
            data["network_name"] = get_network_name(data["network_id"], data["chain_id"])
            if data["network_name"] in ["ropsten", "main"]:
                data["ns"] = ENS.fromWeb3(w3)
            else:
                data["ns"] = None
            setattr(cache_store, cache_name, data)
        except:
            if logger:
                logger.warning("Could not get network info: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            return None
    else:
        data = getattr(cache_store, cache_name)
    retdata = {k: data[k] for k in ["network_id", "chain_id", "network_name"]}
    if ens:
        retdata["ns"] = data["ns"]
    return retdata


def reset_nonce(w3, sender_address, respect_pending=True, logger=None):
    global tx_lock
    if tx_lock.acquire(False):
        # Transfer was not locked, but we just acquired, so release again.
        tx_lock.release()
    elif logger:
        logger.info("Transfer locked, will need to wait before resetting nonce...")
    # Make sure we have a last_nonces cache.
    cache_store = perform_transaction
    cache_name = "last_nonces"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        setattr(cache_store, cache_name, {})
    # Read the last_nonces cache, holding a lock until we write back to it (or early-return).
    tx_lock.acquire()
    last_nonces = getattr(cache_store, cache_name)
    try:
        tx_count = w3.eth.get_transaction_count(sender_address)
    except:
        if logger:
            logger.error("Could not get transaction count: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        tx_lock.release()
        return False
    if respect_pending is False:
        if tx_count > 0:
            set_nonce = tx_count - 1
        else:
            set_nonce = None
    elif type(respect_pending) is int and respect_pending >= 0:
        set_nonce = tx_count - 1 + respect_pending
        if set_nonce < 0:
            set_nonce = None
    else:  # respect pending transactions
        try:
            # TODO: Find out how to do this with current clients.
            # Call pendingTransactions with a filter, see https://openethereum.github.io/wiki/JSONRPC-parity-module#parity_pendingtransactions
            pending_tx = w3.provider.make_request("parity_pendingTransactions", [None, {"from": {"eq": sender_address}}])["result"]
        except:
            if logger:
                logger.error("Could not get pending transactions: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            tx_lock.release()
            return False
        set_nonce = tx_count - 1 + len(pending_tx)
        if set_nonce < 0:
            set_nonce = None
    if set_nonce is None:
        # make sure we do not have an entry saved for the nonce.
        if sender_address in last_nonces:
            del last_nonces[sender_address]
    else:
        last_nonces[sender_address] = set_nonce
    setattr(cache_store, cache_name, last_nonces)
    tx_lock.release()
    return True


def perform_transaction(w3, sender_address, sender_privkey, tx_function, gaslimit, tx_version=None, speed_level=None,
                        gas_price=None, gas_priorityfee=None, gas_maxfee=None, target_address=None, currency_value=None, logger=None):
    global tx_lock
    config = get_eth1_config()
    if tx_lock.acquire(False):
        # Transfer was not locked, but we just acquired, so release again.
        tx_lock.release()
    elif logger:
        logger.info("Transfer locked, will need to wait...")

    nwdata = get_network_data(w3, logger=logger)

    if tx_version is None:
        tx_version = config[f"tx_version_{nwdata['chain_id']}"] if f"tx_version_{nwdata['chain_id']}" in config else config["tx_version"]
    if tx_version not in {"legacy", "eip1559"}:
        tx_version = "legacy"

    sender_account = w3.eth.account.from_key(sender_privkey)
    if sender_account.address != sender_address:
        return False, {"message": "Sender private key does not match given sender address.", "code": "sender_key_mismatch"}

    # Make sure we have a last_nonces cache.
    cache_store = perform_transaction
    cache_name = f"last_nonces_{nwdata['chain_id']}"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        setattr(cache_store, cache_name, {})
    # Read the last_nonces cache, holding a lock until we write back to it (or early-return).
    tx_lock.acquire()
    last_nonces = getattr(cache_store, cache_name)

    try:
        # The nonce has to be at least the tx count confirmed on the chain.
        min_nonce = w3.eth.get_transaction_count(sender_address)
    except requests.exceptions.ConnectionError:
        return False, {"message": "No connection to Ethereum node.", "code": "chain_connection_failure"}

    if sender_address in last_nonces:
        # If we have pending transactions, last_nonces + 1 will be higher than the min_nonce.
        nonce = max(min_nonce, last_nonces[sender_address] + 1)
        if logger:
            logger.info("Nonce: tx count is %s, last used nonce is %s, using %s.", min_nonce, last_nonces[sender_address], nonce)
    else:
        nonce = min_nonce
        if logger:
            logger.info("Nonce: tx count is %s, last used nonce is not stored, using %s.", min_nonce, nonce)

    txparams = {
        "chainId": nwdata["chain_id"],
        "nonce": nonce,
    }
    if tx_version == "legacy":
        txparams["gasPrice"] = gas_price if gas_price else get_gas_price(speed_level, chain=nwdata["chain_id"], w3=w3, logger=logger)
    else:  # eip1559
        # Use maxFeePerGas and maxPriorityFeePerGas instead of gasPrice.
        gas_fees = get_gas_fees(chain_id=nwdata["chain_id"], w3=w3, logger=logger)
        if gas_price and not gas_priorityfee:
            gas_priorityfee = gas_price
        if gas_price and not gas_maxfee:
            gas_maxfee = gas_price
        txparams["maxPriorityFeePerGas"] = gas_priorityfee if gas_priorityfee else gas_fees["priority_fee"]
        txparams["maxFeePerGas"] = gas_maxfee if gas_maxfee else gas_fees["max_fee"]
    if currency_value is not None:
        txparams["value"] = currency_value
    if gaslimit:
        txparams["gas"] = gaslimit
    else:
        # Make sure to specify correct "from" account when estimating.
        txparams_est = txparams
        txparams_est["from"] = sender_address
        try:
            if tx_function:
                gas_estimate = tx_function.estimate_gas(txparams)
            else:
                gas_estimate = w3.eth.estimate_gas({"to": target_address, "from": sender_address, "value": currency_value})
        except web3_exceptions.ContractLogicError as e:
            tx_lock.release()
            errinfo = {"code": "estimation_failed"}
            if type(e.args[0]) == str:
                errinfo["message"] = "Contract Logic Error estimating gas: " + e.args[0]
            else:
                errinfo["message"] = "Contract Logic Error estimating gas: " + e.args[0]["message"]
                errinfo["info"] = e.args[0]
            if logger:
                logger.error(errinfo["message"])
            return False, errinfo
        except ValueError as e:
            tx_lock.release()
            errinfo = {"code": "estimation_failed"}
            if type(e.args[0]) == str:
                errinfo["message"] = "Error estimating gas: " + e.args[0]
            else:
                errinfo["message"] = "Error estimating gas: " + e.args[0]["message"]
                errinfo["info"] = e.args[0]
            if logger:
                logger.error(errinfo["message"])
            return False, errinfo
        except:
            tx_lock.release()
            if logger:
                logger.error("Error estimating gas: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            match = re.search(r'execution reverted: VM Exception while processing transaction: revert (.+)$', str(sys.exc_info()[1]))
            if match:
                message = "Error estimating gas - revert: " + match.group(1)
            else:
                message = "Error estimating gas (may actually be a function execution error)."
            return False, {"message": message, "code": "estimation_failed"}
        if logger:
            logger.info("Estimated gas limit for %s: %s", tx_function, gas_estimate)
        txparams["gas"] = int(gas_estimate * config["gaslimit_estimate_factor"])
        if txparams["gas"] > config["gaslimit_estimate_max"]:
            if logger:
                logger.warning("Gas limit estimate, increased by factor %s to %s, is higher than allowed maximum, clamping to %s",
                               config["gaslimit_estimate_factor"], txparams["gas"], config["gaslimit_estimate_max"])
            txparams["gas"] = config["gaslimit_estimate_max"]
    if logger:
        logger.debug("Transaction params: %s", txparams)

    if tx_function:
        # Build a transaction that invokes the given function
        unsigned_tx = tx_function.build_transaction(txparams)
    else:
        unsigned_tx = txparams
        unsigned_tx["to"] = target_address
        unsigned_tx["data"] = b""

    if logger:
        logger.debug("Unsigned tx: %s", unsigned_tx)
    try:
        signed_tx = w3.eth.account.sign_transaction(unsigned_tx, private_key=sender_privkey)
    except:
        tx_lock.release()
        if logger:
            logger.error("Error signing transaction: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return False, {"message": "Error signing transaction.", "code": "signing_error"}
    try:
        if logger:
            logger.info("Sending raw transaction: %s", signed_tx.rawTransaction.hex())
        txhash = Web3.toHex(w3.eth.send_raw_transaction(signed_tx.rawTransaction))
    except:
        tx_lock.release()
        if logger:
            logger.error("Error sending transaction: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        return False, {"message": "Error sending transaction.", "code": "tx_send_error"}

    # Only when the tx has been sent, make sure to put the used nonce into the cache.
    last_nonces[sender_address] = nonce
    setattr(cache_store, cache_name, last_nonces)
    tx_lock.release()
    return True, {"txhash": txhash}


def get_function_payload(tx_function, logger=None):
    # The following line will run a gas estimation unless a gas limit is provided, so set 10M
    return tx_function.build_transaction({"gas": 10 ^ 7})["data"]


def decode_error_data(error_data):
    # Also see https://github.com/pertsev/web3_utilz/blob/master/revert%20reason/index.js
    if error_data.startswith("Reverted 0x"):
        message = "Reverted: "
        raw_message = error_data[len("Reverted 0x"):]
    elif error_data.startswith("0x"):
        message = ""
        raw_message = error_data[2:]
    else:
        # Does not fit scheme, just return original data.
        return error_data
    if not len(raw_message):
        return message + "[no message]"
    # Get the length of the revert message
    if len(raw_message) < 8 + 128:
        return message + raw_message
    decode_len = int(raw_message[8 + 64 : 8 + 128], 16)  # noqa: E203
    # Using the length and known offset, extract and convert the revert message
    msg_code_hex = raw_message[8 + 128 : 8 + 128 + (decode_len * 2)]  # noqa: E203
    # Convert message from hex to string
    message = message + bytes.fromhex(msg_code_hex).decode('utf-8')
    return message


def personal_ecrecover(w3, message, signature, logger=None):
    # The signature is composed of `s` (first 32 bytes), `r` (next 32 bytes) and `v` (last byte).
    # The `ecrecover` EVM opcode allows for malleable (non-unique) signatures: Some nodes may reject them
    # if `s` value is in the lower half order, or the `v` value is not either 27 or 28.
    # See OpenZeppelin contracts cryptography/ECDSA.sol and/or EIP-2 for some details.
    if not re.match(r'^0x[0-9a-f]{130}$', signature):
        if logger:
            logger.error("ECRecover: Signature with invalid format, unrecoverable failure.")
        raise ValueError("Invalid signature format")
    if signature[-2:] == "00":
        if logger:
            logger.warning("ECRecover: Signature with invalid `v` value, flipping 0 to 27.")
        signature = signature[:-2] + "1b"  # 27 is 0x1B
    elif signature[-2:] == "01":
        if logger:
            logger.warning("ECRecover: Signature with invalid `v` value, flipping 1 to 28.")
        signature = signature[:-2] + "1c"  # 28 is 0x1C
    elif signature[-2:] not in ["1b", "1c"]:
        if logger:
            logger.error("ECRecover: Signature with invalid `v` value (%s), unrecoverable failure.", signature[-2:])
        raise ValueError("Invalid `v` value in signature")
    # Upper half of `s` may also be invalid for some, but let's not do that right now.
    # if int(signature[2:66], 16) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0:
    #     if logger:
    #         logger.warning("ECRecover: Signature with invalid `s` value (upper half), revert it and flip `v`.")
    #     new_s = hex(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - int(signature[2:66], 16))
    #     new_v = "1c" if signature[-2:] == "1b" else "1b"
    #     signature = new_s + signature[66:-2] + new_v
    return w3.geth.personal.ecRecover(message, signature)


def personal_signature_bytes(bytes_to_sign, signer_privkey, logger=None):
    encoded_message = eth_account.messages.encode_defunct(primitive=bytes_to_sign)
    signed_message = eth_account.account.Account.sign_message(encoded_message, signer_privkey)
    return signed_message.signature


def personal_signature_hex(hexdata_to_sign, signer_privkey, logger=None):
    if hexdata_to_sign.startswith("0x"):
        hexdata_to_sign = hexdata_to_sign[2:]
    signature_bytes = personal_signature_bytes(bytes.fromhex(hexdata_to_sign), signer_privkey, logger=logger)
    return signature_bytes.hex()


def personal_recover_bytes(bytes_to_sign, signature, logger=None):
    encoded_message = eth_account.messages.encode_defunct(primitive=bytes_to_sign)
    return eth_account.account.Account.recover_message(encoded_message, signature=signature)


def personal_recover_hex(hexdata_to_sign, signature, logger=None):
    if hexdata_to_sign.startswith("0x"):
        hexdata_to_sign = hexdata_to_sign[2:]
    return personal_recover_bytes(bytes.fromhex(hexdata_to_sign), signature, logger=logger)


# Retrieve a public key from a transaction. This is mostly taking code from eth-account,
# see https://github.com/ethereum/eth-account/blob/master/eth_account/account.py
# functions recover_transaction() and _recover_hash().
def get_pubkey_from_transaction(serialized_transaction):
    from hexbytes import HexBytes
    from eth_account._utils.legacy_transactions import Transaction, vrs_from
    from eth_account._utils.typed_transactions import TypedTransaction
    from eth_account._utils.signing import hash_of_signed_transaction, to_standard_v
    from eth_keys import keys
    from eth_utils.curried import hexstr_if_str, to_int

    txn_bytes = HexBytes(serialized_transaction)
    if len(txn_bytes) > 0 and txn_bytes[0] <= 0x7f:
        # We are dealing with a typed transaction.
        typed_transaction = TypedTransaction.from_bytes(txn_bytes)
        msg_hash = typed_transaction.hash()
        vrs = typed_transaction.vrs()
    else:
        txn = Transaction.from_bytes(txn_bytes)
        msg_hash = hash_of_signed_transaction(txn)
        vrs = vrs_from(txn)

    hash_bytes = HexBytes(msg_hash)
    if len(hash_bytes) != 32:
        raise ValueError("The message hash must be exactly 32-bytes")
    v, r, s = map(hexstr_if_str(to_int), vrs)
    v_standard = to_standard_v(v)
    signature_obj = keys.Signature(vrs=(v_standard, r, s))
    return signature_obj.recover_public_key_from_msg_hash(hash_bytes).to_hex()


def get_ens_name(ns, address, logger=None):
    if ns and address:
        ensname = ns.name(address)
        if ensname and ns.address(ensname) != address:
            if logger:
                logger.warning(f"ENS address for {ensname} is not {address}!")
            ensname = False
    else:
        ensname = None
    return ensname


# Invalidate address-for-ensname cache for a namehash (ENS node).
def invalidate_cached_ens_address(chain_id, ens_node, logger=None):
    cache_store = get_address_from_maybe_ensname
    cache_name = f"address_for_ensname_{chain_id}_{ens_node}"
    if hasattr(cache_store, cache_name):
        setattr(cache_store, cache_name, None)


# Get an address for what may be an ENS name or already an address.
def get_address_from_maybe_ensname(nwdata, address_or_ensname, ens_base_suffix=None, cache_seconds=0, logger=None):
    if Web3.isAddress(address_or_ensname):
        ensdata = {"address": Web3.toChecksumAddress(address_or_ensname)}
    elif nwdata["ns"]:
        if "." not in address_or_ensname and ens_base_suffix:
            ensname = f"{address_or_ensname}.{ens_base_suffix}"
        else:
            ensname = address_or_ensname
        try:
            ens_node = ENS.namehash(ensname)
        except:
            return False, {"message": "Please specify a valid Ethereum address or ENS name. The entered name is not a valid ENS name.", "code": "invalid_ens_name", "http_code": 400}
        cache_store = get_address_from_maybe_ensname
        cache_name = f"address_for_ensname_{nwdata['chain_id']}_{ens_node}"
        cache_timestamp = f"timestamp_{nwdata['chain_id']}_{ens_node}"
        if (not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None
                or getattr(cache_store, cache_timestamp) < time.time() - cache_seconds):
            if cache_seconds:
                # Always set the timestamp so we do not have to test above if it's set,
                # as it's only unset when token is also unset
                setattr(cache_store, cache_timestamp, time.time())
            ensdata = {"address": None}
            try:
                ensdata["address"] = nwdata["ns"].address(ensname)
            except:
                ensdata["address"] = None
            if cache_seconds:
                setattr(cache_store, cache_name, ensdata)
        else:
            ensdata = getattr(cache_store, cache_name)
        if not ensdata["address"]:
            return False, {"message": "Please specify a valid Ethereum address or ENS name. The entered name could not be found in ENS.", "code": "no_ens_entry", "http_code": 404}
    else:
        return False, {"message": "No ENS support on this network.", "code": "ens_unsupported", "http_code": 400}
    return True, ensdata


def get_from_etherscan(api, network="main", logger=None):
    return get_from_explorer(api, network, logger)


def get_from_explorer(api, network="main", logger=None):
    config = get_eth1_config()
    if network in config["explorer_api_url"]:
        url = config["explorer_api_url"][network] + api
        if config["explorer_api_key"]:
            url = url + '&apikey=' + config["explorer_api_key"]
    elif network in config["etherscan_api_url"]:
        url = config["etherscan_api_url"][network] + api
        if config["etherscan_api_key"]:
            url = url + '&apikey=' + config["etherscan_api_key"]
    else:
        return {"message": "No block explorer API URL defined for network %s" % network, "url": None}, 400
    if logger:
        logger.info("Fetching from block explorer: %s", url)
    try:
        headers = requests.utils.default_headers()
        headers.update({'User-Agent': 'capacity.at/1.0'})
        response = requests.get(url, headers=headers)
        if ('Content-Type' in response.headers
            and re.match(r'^application/json',
                         response.headers['Content-Type'])):
            # create a dict generated from the JSON response.
            esdata = response.json()
            if response.status_code >= 400:
                # For error-ish codes, tell that they are from explorer.
                esdata["messagesource"] = "explorer"
                esdata["url"] = url
            return esdata, response.status_code
        else:
            return {"message": response.text,
                    "messagesource": "explorer",
                    "url": url}, response.status_code
    except requests.ConnectionError as e:
        return {"message": str(e), "url": url}, 503
    except requests.RequestException as e:
        return {"message": str(e), "url": url}, 500


def get_latest_block_from_explorer(network="main", logger=None):
    config = get_eth1_config()
    if network not in config["explorer_api_url"]:
        return {"message": "No block explorer API URL defined for network %s" % network, "url": None}, 400
    if re.search(r"etherscan", config["explorer_api_url"][network]):
        api = "module=proxy&action=eth_blockNumber"
    else:  # blockscout, use that as the default fallback for the moment
        api = "module=block&action=eth_block_number"

    exdata, ex_status_code = get_from_explorer(api, network, logger=logger)
    if ex_status_code >= 400:
        if logger:
            logger.error("Error %s from block explorer, data: %s", ex_status_code, exdata)
        return -1
    if "result" not in exdata or not re.match(r'^(0x)?[0-9a-fA-F]+$', exdata["result"]):
        if logger:
            logger.error("Unusable response from block explorer: %s" % exdata)
        return -1
    return int(exdata["result"], 16)


# Set or get waiting status.
def waiting_tx_note(tx_hash=None, set_status=False, set_value=None):
    if (not tx_hash) and set_status:
        return None
    cache_store = waiting_tx_note
    cache_name = "hashes"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        hashes = set()
        setattr(cache_store, cache_name, hashes)
    else:
        hashes = getattr(cache_store, cache_name)
    if tx_hash and not set_status:
        return (tx_hash in hashes)
    if set_status:
        if set_value:
            hashes.add(tx_hash)
        else:
            hashes.discard(tx_hash)
        setattr(cache_store, cache_name, hashes)
    return (len(hashes))


def get_eth1_address_from_privkey(privkey):
    acct = Account.from_key(privkey)
    return acct.address


def get_event_logs_staged(contract_event, from_block=0, to_block="latest", stage_height=None, argument_filters=None, raise_errors=False, logger=None):
    event_list = []
    try:
        if not stage_height:
            stage_height = 1000000  # 1M blocks are ~5 months
        if to_block == "latest":
            to_block = contract_event.web3.eth.block_number
        if type(from_block) != int or type(to_block) != int:
            raise ValueError("The get_event_logs_staged variant needs from/to blocks to be numbers (or 'latest').")
        start_block = from_block
        end_block = to_block
        while start_block <= end_block:
            stage_to_block = start_block + stage_height
            if stage_to_block > end_block:
                stage_to_block = end_block
            if logger:
                logger.debug(f"Getting {contract_event.event_name} event logs of contract {contract_event.address} for blocks #{start_block}-{stage_to_block}...")
            event_list += contract_event.getLogs(fromBlock=start_block, toBlock=stage_to_block, argument_filters=argument_filters)
            start_block = stage_to_block if stage_to_block < end_block else end_block + 1
    except:
        if logger:
            logger.error("Error getting event logs: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        if raise_errors:
            raise  # Re-raises whatever exception we did get.
        else:
            return None
    return event_list


def check_eth1_address(eth_address_param, zero_allowed=False):
    if (not re.match(r'^(0x)?[0-9a-fA-F]{40}$', eth_address_param)):
        raise ValueError("Please specify a valid account address.")
    if (not zero_allowed and re.match(r'^(0x)?0{40}$', eth_address_param)):
        raise ValueError("Please specify a non-zero account address.")
    if not eth_address_param.startswith("0x"):
        eth_address_param = "0x" + eth_address_param
    if not Web3.isAddress(eth_address_param):
        raise ValueError("Please specify a valid Ethereum account address.")
    return Web3.toChecksumAddress(eth_address_param)


def check_eth1_privkey(privkey_param):
    if (not re.match(r'^(0x)?[0-9a-fA-F]{64}$', privkey_param)):
        raise ValueError("Please specify a valid private key.")
    if (re.match(r'^(0x)?0{64}$', privkey_param)):
        raise ValueError("Please specify a non-zero private key.")
    if not privkey_param.startswith("0x"):
        privkey_param = "0x" + privkey_param
    return privkey_param


def logging_middleware(make_request, w3):
    def middleware(method, params):
        # log JSON-RPC incoming call
        logging.info("RPC-> %s: %s", method, params)
        # perform the RPC request, getting the response
        response = make_request(method, params)
        # log JSON-RPC response
        logging.info("RPC<- %s: %s", method, response)
        # finally return the response
        return response
    return middleware


def patch_ecrecover_error_middleware(make_request, w3):
    def middleware(method, params):
        # personal_ecRecover encodes the string to hex twice, we need to undo that.
        if method == "personal_ecRecover" and params[0].startswith("0x"):
            params = (bytes.fromhex(params[0][2:]), params[1])
            logging.info("corrected message param of %s", method)
        # perform the RPC request, getting the response
        response = make_request(method, params)
        # finally return the response
        return response
    return middleware


class SimpleBlockNumberFilter:
    def __init__(self, filter_w3, start_block="latest", confirmations=0, max_return_count=None, logger=None):
        self.w3 = filter_w3
        self.logger = logger
        if type(confirmations) != int or confirmations < 0:
            raise ValueError("Confirmations needs to be a positive integer")
        self.confirmations = confirmations
        if max_return_count is not None and (type(max_return_count) != int or max_return_count < 1):
            raise ValueError("Max return count needs to be None or a positive integer")
        self.max_return_count = max_return_count
        current_block = self.w3.eth.block_number
        if start_block == "latest":
            self.last_block = current_block - self.confirmations
        elif type(start_block) == int and start_block >= 0 and start_block < current_block:
            self.last_block = start_block
        else:
            raise ValueError("Unsupported start block number")
        self.filter_id = "simpleblocknum"
        if self.logger:
            self.logger.debug(f"SimpleBlockNumberFilter initialized with #{self.last_block}.")

    def get_new_entries(self):
        # if self.logger:
        #     self.logger.debug(f"SimpleBlockNumberFilter: last #{self.last_block}, current #{self.w3.eth.block_number}")
        first_block = self.last_block + 1  # First block to return
        new_last_block = self.w3.eth.block_number - self.confirmations
        if new_last_block < first_block:
            return range(first_block, first_block)  # This should be an empty range.
        self.last_block = new_last_block
        if self.max_return_count is not None and self.last_block + 1 - first_block > self.max_return_count:
            self.last_block = first_block + self.max_return_count - 1
        return range(first_block, self.last_block + 1)  # range() excludes the "stop" (end), so add 1.

# Capacity API process utilities

from flask import Flask, json
from flask_cors import CORS
from flask_mail import Mail
from flasgger import Swagger
from web3 import Web3
from web3 import exceptions as web3_exceptions
import yaml
import os
import sys
import signal
import time
import gevent
import threading
import logging
import traceback
import pkg_resources
from gevent.pywsgi import WSGIServer
from . import capa_base
from . import capa_eth1


def get_api_config(primary_path="", fallback_path="config/config.yaml", defaults={}, logger=None):
    # Make sure to always call this with both path parameters before calling other functions in this module that use the config!
    # See if the config is cached already, otherwise cache it.
    cache_store = get_api_config
    cache_name = "config"
    cache_name_invalidate = "config_invalidate"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None or (hasattr(cache_store, cache_name_invalidate) and getattr(cache_store, cache_name_invalidate)):
        if hasattr(cache_store, cache_name_invalidate):
            delattr(cache_store, cache_name_invalidate)
        if not hasattr(cache_store, cache_name):
            setattr(cache_store, cache_name, None)
        # Now, actually get the config from the files via capa-eth.
        config = capa_eth1.get_eth1_config(primary_path, fallback_path, defaults, logger=logger)

        # Apply defaults for missing values
        capa_base.config_default(config, "rest_host", "127.0.0.1", defaults)
        capa_base.config_default(config, "rest_port", 12345, defaults)
        capa_base.config_default(config, "api_url_hostname", "", defaults)
        capa_base.config_default(config, "api_url_path", "", defaults)
        capa_base.config_default(config, "use_reverse_proxy", None, defaults)  # None will try auto-detection based on the app version
        capa_base.config_default(config, "event_poll_interval", 5, defaults)

        capa_base.config_default(config, "log_file_path", "log/capacity-api.log", defaults)
        capa_base.config_default(config, "log_file_maxbytes", "10M", defaults)
        capa_base.config_default(config, "log_level", "info", defaults)

        capa_base.config_default(config, "custom_block_filter_max_entries", 25, defaults)
        capa_base.config_default(config, "custom_block_filter_max_start_delay", None, defaults)
        capa_base.config_default(config, "delay_event_processing_blocks", 1, defaults)

        if "app" not in config:
            config["app"] = {}
        # Parse formatted values into what we actually want internally.
        config["log_file_maxbytes"] = capa_base.parse_bytestring(config["log_file_maxbytes"])
        setattr(cache_store, cache_name, config)
    else:
        config = getattr(cache_store, cache_name)
    return config


def invalidate_cached_api_config(logger=None):
    cache_store = get_api_config
    cache_name_invalidate = "config_invalidate"
    setattr(cache_store, cache_name_invalidate, True)
    capa_eth1.invalidate_cached_eth1_config(logger)


def invalidate_cached_keys(logger=None):
    cache_store = get_keys
    cache_name_invalidate = "keys_invalidate"
    setattr(cache_store, cache_name_invalidate, True)


def get_keys(config, default_keys={}, logger=None):
    cache_store = get_keys
    cache_name = "keys"
    cache_name_invalidate = "keys_invalidate"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None or (hasattr(cache_store, cache_name_invalidate) and getattr(cache_store, cache_name_invalidate)):
        if hasattr(cache_store, cache_name_invalidate):
            delattr(cache_store, cache_name_invalidate)
        if not hasattr(cache_store, cache_name):
            setattr(cache_store, cache_name, None)
        if os.path.isfile(config["cryptokeys_json_path"]):
            try:
                with open(config["cryptokeys_json_path"]) as json_file:
                    file_keys = json.load(json_file)
            except:
                if logger:
                    logger.error("Error reading data from file: %s (%s)" % (sys.exc_info()[0], sys.exc_info()[1]))
                return default_keys
        else:
            if logger:
                logger.error("File not found: %s" % config["cryptokeys_json_path"])
            return default_keys
        keys = {}
        for key in default_keys:
            keys[key] = file_keys[key] if key in file_keys else default_keys[key]
        setattr(cache_store, cache_name, keys)
    else:
        keys = getattr(cache_store, cache_name)
    return keys


def sigterm_handler(signal, frame):
    logging.warning("Got SIGTERM, stopping application.")
    sys.exit(0)


def run_api(app, config, additional_handling=None):
    ssl_context = None
    signal.signal(signal.SIGTERM, sigterm_handler)
    root_log_level, app_log_level = capa_base.get_log_levels(config["log_level"],
                                                             app.debug)
    if app.debug:
        # Start Flask debug server.
        logging.info("Starting up in debug mode with logging level %s (root %s)...",
                     app_log_level, root_log_level)
        app.run(host=config["rest_host"], port=config["rest_port"],
                ssl_context=ssl_context, threaded=True)
        rootLogger = logging.getLogger()
        rootLogger.setLevel(root_log_level)
        app.logger.setLevel(app_log_level)
    else:
        logging.info("Starting up in production mode with logging level %s (root %s)...",
                     app_log_level, root_log_level)
        # In production mode, add log handler to sys.stderr.
        # A stream handler is added by the initial .basicConfig() call anyhow,
        # so the line below is not needed.
        # app.logger.addHandler(logging.StreamHandler())
        file_handler = capa_base.get_logfile_handler(config["log_file_path"],
                                                     config["log_file_maxbytes"])
        rootLogger = logging.getLogger()
        # Again, a stream handler is added by default anyhow.
        # rootLogger.addHandler(logging.StreamHandler())
        rootLogger.addHandler(file_handler)  # causes all loggers to log to that file.
        rootLogger.setLevel(root_log_level)
        app.logger.setLevel(app_log_level)
        # Start WSGI server via gevent.
        wsgiLogger = logging.getLogger("wsgi")
        wsgiLogger.setLevel(root_log_level)
        # Once again, already goes to root handler anyhow.
        # wsgiLogger.addHandler(logging.StreamHandler())
        if additional_handling:
            # Some projects need additional handling here,
            # e.g. setting up a handler for logging slow requests.
            additional_handling()
        # Now start the server.
        http_server = WSGIServer(listener=(config["rest_host"], config["rest_port"]),
                                 application=app, log=wsgiLogger)
        try:
            logging.info("HTTP server starting at %s - note that events are not watched yet, make an API call to start that.",
                         get_api_url(config, external=False))
            http_server.serve_forever()
            # serve_forever() command will wait, so we usually do not get here.
            logging.warning("HTTP server ended execution, stopping application.")
        except KeyboardInterrupt:
            logging.warning("HTTP server interrupted (Crtl+C/SIGINT), stopping application.")


def set_up_logging_base():
    logging.basicConfig(level=logging.DEBUG, format="[%(asctime)s] %(levelname)s:%(name)s - %(message)s")


def get_api_url(config, external=False):
    if external:
        return f"https://{config['api_url_hostname']}/{config['api_url_path']}"
    return f"http://{config['rest_host']}:{config['rest_port']}/"


def get_core_versions():
    version_info = {}
    '''
    import types
    for name, val in globals().items():
        if isinstance(val, types.ModuleType):
            try:
                version_info[val.__name__] = val.__version__
            except:
                version_info[val.__name__] = f"{sys.exc_info()[0]}: {sys.exc_info()[1]}"
    '''
    version_info["cnp"] = pkg_resources.get_distribution("cnp").version
    # We could use `import web3` and then read web3.__version__ but this is nicer.
    # Same for flask and flasgger which we also don't import as a whole.
    version_info["web3py"] = pkg_resources.get_distribution("web3").version
    version_info["flask"] = pkg_resources.get_distribution("flask").version
    version_info["flasgger"] = pkg_resources.get_distribution("flasgger").version
    version_info["requests"] = pkg_resources.get_distribution("requests").version
    # For those where we import the whole module, use __version__ as it's more pythonic.
    version_info["gevent"] = gevent.__version__
    version_info["yaml"] = yaml.__version__
    version_info["python_full"] = sys.version_info
    version_info["python"] = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    return version_info


def set_up_flask(config, use_cors=False, use_mail=False,
                 app_name=__name__, spec_name=None,
                 app_title="Capacity REST API", app_version="x.y.z",
                 app_description="API for testing Capacity code",
                 contact_name="Capacity Blockchain Solutions GmbH",
                 contact_email="hello@capacity.at",
                 contact_url="https://capacity.at/"):
    app = Flask(app_name)

    app.config['SWAGGER'] = {
        "title": app_title,
        "uiversion": 3,
        "openapi": "3.0.3"
    }
    for option in config["app"]:
        app.config[option] = config["app"][option]

    if use_cors:
        CORS(app)
    if use_mail:
        mail = Mail(app)
    else:
        mail = None

    # Note: Resulting OpenAPI/swagger docs can be validated at https://editor.swagger.io/
    swagger_template = {
        "info": {
            "title": app_title,
            "description": app_description,
            "contact": {
                "name": contact_name,
                "email": contact_email,
                "url": contact_url,
            },
            "version": capa_base.printable_version(app_version)
        },
        "servers": [
            {
                "url": "/"
            }
        ],
        "components": {
            "schemas": {
                "GenericError": {
                    "type": "object",
                    "required": ["message"],
                    "properties": {
                        "message": {
                            "type": "string"
                        },
                        "code": {
                            "type": "string"
                        },
                        "info": {
                            "type": "object"
                        }
                    }
                }
            },
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer"
                }
            },
            "responses": {
                "InputError": {
                    "description": "Input Error",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/GenericError"
                            },
                            "example": {
                                "message": "Plase specify correct input values."
                            }
                        }
                    }
                },
                "Unauthorized": {
                    "description": "Unauthorized",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/GenericError"
                            },
                            "example": {
                                "message": "Authorization required to access this feature."
                            }
                        }
                    }
                },
                "NotFound": {
                    "description": "Not Found",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/GenericError"
                            },
                            "example": {
                                "message": "Requested item was not found."
                            }
                        }
                    }
                },
                "ServerError": {
                    "description": "Server Error",
                    "content": {
                        "application/json": {
                            "schema": {
                                "$ref": "#/components/schemas/GenericError"
                            },
                            "example": {
                                "message": "Internal server error. Please contact admins for help."
                            }
                        }
                    }
                },
                "TransactionResponse": {
                    "description": "Standard response for a call issuing a transaction",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "txhash": {
                                        "type": "string",
                                        "format": "ethereum-txhash"
                                    }
                                }
                            },
                            "example": {
                                "txhash": "0x0"
                            }
                        }
                    }
                }
            }
        }
    }
    swagger_config = Swagger.DEFAULT_CONFIG
    if spec_name:
        swagger_config["specs"][0]["route"] = f"/{spec_name}.json"
        swagger_config["specs"][0]["endpoint"] = spec_name
    if config["use_reverse_proxy"] or (config["use_reverse_proxy"] is None and app_version != "x.y.z"):
        # Set full URL on actual deployments (where we go through a reverse proxy), but not on testing setup.
        swagger_template["servers"][0]["url"] = get_api_url(config, external=True)
        if config["api_url_path"]:
            swagger_config['swagger_ui_bundle_js'] = f"/{config['api_url_path']}/flasgger_static/swagger-ui-bundle.js"
            swagger_config['swagger_ui_standalone_preset_js'] = f"/{config['api_url_path']}/flasgger_static/swagger-ui-standalone-preset.js"
            swagger_config['jquery_js'] = f"/{config['api_url_path']}/flasgger_static/lib/jquery.min.js"
            swagger_config['swagger_ui_css'] = f"/{config['api_url_path']}/flasgger_static/swagger-ui.css"
    swagger = Swagger(app, config=swagger_config, merge=True, template=swagger_template)
    return app, swagger, mail


def endpoint_list(app):
    links = []
    for rule in app.url_map.iter_rules():
        # Flask has a default route for serving static files, let's exclude it.
        if rule.endpoint != "static":
            links.append({"url": rule.rule,
                          "methods": ','.join([x for x in rule.methods if x not in ["OPTIONS", "HEAD"]])})
    return sorted(links, key=lambda rule: rule["url"])


def check_block_event_threads(watch_events, app, config, all_contracts_info,
                              get_event_web3=None, handle_event=None,
                              retrieve_start_block=None, store_handled_block=None,
                              set_catch_up_mode=None, get_multi_contract_info=None,
                              logger=None):
    # get_event_web3 and handle_event are required!
    if not get_event_web3 or not handle_event:
        if logger:
            logger.error("check_block_event_threads needs get_event_web3 and handle_event functions!")
        return None
    # Start event thread(s) one by one.
    event_threads_expected = 0
    for watch_info in watch_events:
        if watch_info["contract_id"] or watch_info["event"] != "block":
            # We handle events in block threads, do nothing here.
            continue
        event_w3 = get_event_web3(watch_info["l2"])
        # We expect an event thread for blocks.
        event_threads_expected = event_threads_expected + 1
        if not event_w3:
            # We have no connection to the chain, so we count an expected thread, but do nothing.
            continue
        # If no thread is running for this one, start one.
        if not len([thread.name for thread in threading.enumerate() if thread.name == "event_filter.%s" % watch_info["filter_name"]]):
            try:
                # Block filter, on all new mined blocks
                if retrieve_start_block:
                    nwdata = capa_eth1.get_network_data(event_w3, logger=logger)
                    start_block = retrieve_start_block(chain_id=nwdata["chain_id"], logger=logger)
                    if start_block:
                        handled_delay = event_w3.eth.block_number - start_block
                        if type(config["custom_block_filter_max_start_delay"]) == int and handled_delay > config["custom_block_filter_max_start_delay"]:
                            if logger:
                                logger.warning(f"Chain {nwdata['chain_id']}: Last handled block is {handled_delay} blocks old, skipping to latest (#{event_w3.eth.block_number}).")
                            start_block = "latest"
                        else:
                            logger.info(f"Chain {nwdata['chain_id']}: Last handled block is #{start_block} ({handled_delay} blocks old), restarting from there.")
                    if not start_block:
                        start_block = "latest"
                        if logger:
                            logger.info(f"Chain {nwdata['chain_id']}: No last handled block found, restarting from latest (#{event_w3.eth.block_number}).")
                else:
                    start_block = "latest"
                event_filter = capa_eth1.SimpleBlockNumberFilter(
                    event_w3,
                    start_block=start_block,
                    confirmations=config["delay_event_processing_blocks"],
                    max_return_count=config["custom_block_filter_max_entries"],
                    logger=logger
                )
                if event_filter:
                    worker = threading.Thread(
                        target=thread_loop,
                        args=(event_filter, watch_info, watch_events,
                              config["event_poll_interval"], all_contracts_info,
                              app, handle_event, get_event_web3,
                              store_handled_block, set_catch_up_mode,
                              get_multi_contract_info),
                        daemon=True
                    )
                    worker.start()
                elif logger:
                    logger.error("Could not get find event %s in contract %s to set up filter %s!",
                                 watch_info["event"], watch_info["contract_debug_name"], watch_info["filter_name"])
            except:
                if logger:
                    logger.error("Failed to set up filter %s (for event %s in contract %s): %s (%s)",
                                 watch_info["filter_name"], watch_info["event"], watch_info["contract_debug_name"],
                                 sys.exc_info()[0], sys.exc_info()[1])
                    if logger.isEnabledFor(logging.DEBUG):
                        traceback.print_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])
    return event_threads_expected


# Loop to handle block events, run in a separate thread.
def thread_loop(thread_filter, watch_info, watch_events, poll_interval,
                all_contracts_info, app, handle_event, get_event_web3,
                store_handled_block, set_catch_up_mode,
                get_multi_contract_info):
    filter_id = thread_filter.filter_id
    filter_name = watch_info["filter_name"]
    threading.current_thread().name = 'event_filter.%s' % filter_name
    # We usually get started when some other call is being done, which may be too busy,
    # so wait a few seconds before doing anything.
    time.sleep(3)
    with app.app_context():
        app.logger.info("Watch for filter %s (%s) established.", filter_id, filter_name)
        thread_w3 = get_event_web3(watch_info["l2"])
        if watch_info["event"] == "block" and store_handled_block:
            nwdata = capa_eth1.get_network_data(thread_w3, logger=app.logger)  # Used for param to store_handled_block() below, let's only query it once.
            last_stored = None
        unique = True if thread_w3 else False
        while unique:
            # Get all events we have not seen yet and handle them.
            # app.logger.info("Looking for filter: " + filter_id)
            try:
                event_entries = thread_filter.get_new_entries()
            except:
                app.logger.error("Error when getting new entries for filter %s (%s): %s; %s",
                                 filter_id, filter_name, sys.exc_info()[0], sys.exc_info()[1])
                app.logger.error(traceback.format_exc())
                app.logger.error("Terminating filter watch thread %s.", threading.current_thread().name)
                # Now, break out of this loop to end the thread. TODO: Potentially re-establish our filter?
                break
            if len(event_entries) > 20:
                catch_up_needed = True
                app.logger.info("Filter %s (%s) has a relatively high count of %s events to handle...",
                                filter_id, filter_name, len(event_entries))
            else:
                catch_up_needed = False
                app.logger.debug("Filter %s (%s) has %s events to handle...",
                                 filter_id, filter_name, len(event_entries))
            if set_catch_up_mode:
                set_catch_up_mode(catch_up_needed, watch_info["l2"], logger=app.logger)
            try:
                for event in event_entries:
                    handle_event(thread_w3, event, watch_info)
            except web3_exceptions.BlockNotFound:
                app.logger.info(f"Got exception web3.exceptions.BlockNotFound, Retrying (at least) the blocks #{event_entries[0]} to #{event_entries[-1]}.")
                # Wait shortly before retrying.
                if app.debug:
                    time.sleep(poll_interval)
                else:
                    gevent.sleep(poll_interval)
                continue
            except:
                app.logger.error("Error handling event in filter %s (%s): %s; %s",
                                 filter_id, filter_name, sys.exc_info()[0], sys.exc_info()[1])
                app.logger.error(traceback.format_exc())
                app.logger.error("Terminating filter watch thread %s.", threading.current_thread().name)
                # Now, break out of this loop to end the thread. TODO: Potentially re-establish our filter?
                break
            if len(event_entries) and watch_info["event"] == "block":
                handle_events_for_block_range(thread_w3, l2=watch_info["l2"],
                                              first=event_entries[0],
                                              last=event_entries[-1],
                                              watch_events=watch_events,
                                              all_contracts_info=all_contracts_info,
                                              handle_event=handle_event,
                                              get_multi_contract_info=get_multi_contract_info,
                                              logger=app.logger)
                # If we got to successfully go through this block or batch of blocks, store that we handled it.
                if store_handled_block:
                    if last_stored and last_stored > event_entries[-1]:
                        app.logger.error("Cannot go backward with last handled block - new value is %s, stored is %s.", event_entries[-1], last_stored)
                        app.logger.error("Terminating filter watch thread %s.", threading.current_thread().name)
                        # Now, break out of this loop to end the thread. TODO: Potentially re-establish our filter?
                        break
                    store_handled_block(event_entries[-1], chain_id=nwdata["chain_id"], logger=app.logger)
                    last_stored = event_entries[-1]
            if not catch_up_needed:
                # Wait shortly before retrying.
                if app.debug:
                    time.sleep(poll_interval)
                else:
                    gevent.sleep(poll_interval)
            # We had cases of doubly existing threads. Make sure we exit the thread in that case.
            if len([thread.name for thread in threading.enumerate() if thread.name == threading.current_thread().name]) > 1:
                app.logger.warning("Thread %s exists more than once, terminating.", threading.current_thread().name)
                unique = False
        # Give some info when we exit.
        app.logger.info("Exiting filter watch thread %s.", threading.current_thread().name)


def invalidate_watch_info_contracts(thread_w3):
    # Make sure that whatever provides get_multi_contract_info() is invalidated
    # before this if info provided from there has changed!
    cache_store = handle_events_for_block_range
    cache_name = f"watch_info_contracts_{id(thread_w3)}"
    delattr(cache_store, cache_name)


def handle_events_for_block_range(thread_w3, l2, first, last, watch_events,
                                  all_contracts_info, handle_event,
                                  get_multi_contract_info, logger):
    nwdata = capa_eth1.get_network_data(thread_w3, logger=logger)
    logger.debug(f"Chain {nwdata['chain_id']}: handling events for block {first} to {last}...")
    # See if the info is cached already, otherwise cache it.
    cache_store = handle_events_for_block_range
    cache_name = f"watch_info_contracts_{id(thread_w3)}"
    if not hasattr(cache_store, cache_name) or getattr(cache_store, cache_name) is None:
        if not hasattr(cache_store, cache_name):
            setattr(cache_store, cache_name, None)
        # Now, actually get the info.
        watch_info_contracts = {}
        for watch_info in watch_events:
            if watch_info["l2"] == l2 and watch_info["event"] != "block":
                # Get contract address(es) and ABI to watch.
                contract_addresses = None
                if get_multi_contract_info and watch_info["contract_id"] and watch_info["contract_id"].endswith("*"):
                    contract_addresses, contract_abi = get_multi_contract_info(watch_info["contract_id"],
                                                                               l2=watch_info["l2"], logger=logger)
                elif watch_info["contract_id"] and thread_w3:
                    contract_address = capa_eth1.get_address(watch_info["contract_id"], thread_w3,
                                                             all_contracts_info, logger)
                    if contract_address:
                        contract_addresses = [contract_address]
                        contract_abi = capa_eth1.get_abi(watch_info["contract_id"],
                                                         all_contracts_info, logger)
                # Assemble actual contract objects.
                if contract_addresses:
                    watch_info_contracts[watch_info["filter_name"]] = []
                    for contract_address in contract_addresses:
                        contract = thread_w3.eth.contract(address=contract_address, abi=contract_abi)
                        watch_info_contracts[watch_info["filter_name"]].append(contract)
                elif contract_addresses is None:
                    logger.error("Could not get address for %s contract to handle events for %s!",
                                 watch_info["contract_debug_name"], watch_info["filter_name"])
        setattr(cache_store, cache_name, watch_info_contracts)
    else:
        watch_info_contracts = getattr(cache_store, cache_name)
    # Actually retrieve and handle the log events.
    for watch_info in watch_events:
        if watch_info["filter_name"] not in watch_info_contracts:  # filter_name is unique!
            continue
        contracts = watch_info_contracts[watch_info["filter_name"]]
        for contract in contracts:
            contract_debug_name = watch_info["contract_debug_name"]
            for event in contract.events[watch_info["event"]].getLogs(fromBlock=first, toBlock=last):
                try:
                    handle_event(thread_w3, event, watch_info)
                except:
                    logger.error("Filter %s: Failed to process event %s in contract %s: %s (%s)",
                                 watch_info["filter_name"], watch_info["event"], contract_debug_name,
                                 sys.exc_info()[0], sys.exc_info()[1])
                    if logger.isEnabledFor(logging.DEBUG):
                        traceback.print_exception(sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2])


def status_fields_network(nwdata, logger=None):
    status = {}
    if nwdata:
        status["network_id"] = nwdata["network_id"]
        status["chain_id"] = nwdata["chain_id"]
        status["network_name"] = nwdata["network_name"]
    else:
        status["network_id"] = None
        status["chain_id"] = None
        status["network_name"] = None
    return status


def status_fields_blocks(w3, nwdata=None, retrieve_handled_block=None, logger=None):
    status = {}
    if w3 and retrieve_handled_block:
        if not nwdata:
            nwdata = capa_eth1.get_network_data(w3)
        status["last_handled_block"] = retrieve_handled_block(nwdata["chain_id"], logger=logger)
        status["last_chain_block"] = w3.eth.block_number
    else:
        status["last_handled_block"] = None
        status["last_chain_block"] = None
    return status


def status_fields_addresses(w3, addr_contracts_list={}, get_address=None, logger=None):
    status_addresses = {}
    if w3:
        for addr_name in addr_contracts_list:
            status_addresses[addr_name] = get_address(addr_contracts_list[addr_name], w3)
    else:
        for addr_name in addr_contracts_list:
            status_addresses[addr_name] = None
    return status_addresses


def status_fields_threads(event_threads_expected, timer_threads_expected=None, logger=None):
    status = {}
    status["event_threads_expected"] = event_threads_expected
    try:
        ev_threads_running_names = [thread.name for thread in threading.enumerate() if thread.name.startswith("event_filter.")]
        status["event_threads_running"] = len(ev_threads_running_names)
    except:
        if logger:
            logger.warning("Could not get thread info: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
        status["event_threads_running"] = None
    if timer_threads_expected is not None:
        status["timer_threads_expected"] = timer_threads_expected
        try:
            timer_threads_running_names = [thread.name for thread in threading.enumerate() if thread.name.startswith("timer.")]
            status["timer_threads_running"] = len(timer_threads_running_names)
        except:
            if logger:
                logger.warning("Could not get thread info: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            status["timer_threads_running"] = None
    try:
        status["total_threads_running"] = threading.active_count()
    except:
        status["total_threads_running"] = None
    return status


def chain_param_docstring():
    return """
          - name: chain
            description: The name or ID of the chain this contract is on ("default" to guess the correct one, usually falling back to Layer 1)
            in: path
            required: true
            schema:
              type: string
              enum:
              - default
              - eth
              - ethereum
              - ropsten
              - goerli
              - xdai
              - polygon
              - "1"
              - "3"
              - "5"
              - "100"
              - "137"
    """


def parse_chainparam(l1_w3, l2_w3, chain, ens=False, get_network_data=None, logger=None):
    if not get_network_data:
        get_network_data = capa_eth1.get_network_data
    if not l1_w3 and not l2_w3:
        return False, {"message": "No chains connected.", "code": "chain_connection_failure", "http_code": 500}
    # Get network data
    if l1_w3:
        nwdata_l1 = get_network_data(l1_w3, ens=ens, logger=logger)
    else:
        nwdata_l1 = None
    if l2_w3:
        nwdata_l2 = get_network_data(l2_w3, ens=ens, logger=logger)
    else:
        nwdata_l2 = None
    supported_chain_values = ["default"]
    if nwdata_l1:
        supported_chain_values.append(nwdata_l1["network_name"])
        supported_chain_values.append(str(nwdata_l1["chain_id"]))
    if nwdata_l2:
        supported_chain_values.append(nwdata_l2["network_name"])
        supported_chain_values.append(str(nwdata_l2["chain_id"]))
    if "main" in supported_chain_values:
        supported_chain_values.append("mainnet")
        supported_chain_values.append("ethereum")
        supported_chain_values.append("eth")
    if chain not in supported_chain_values:
        return False, {"message": f"Please specify a valid chain name ({', '.join(supported_chain_values)}).", "code": "unknown_chain", "http_code": 404}
    if chain == "ethereum" or chain == "eth" or chain == "mainnet":
        chain == "main"
    if nwdata_l1 and chain == str(nwdata_l1["chain_id"]):
        chain = nwdata_l1["network_name"]
    if nwdata_l2 and chain == str(nwdata_l2["chain_id"]):
        chain = nwdata_l2["network_name"]
    return True, (chain, nwdata_l1, nwdata_l2)


def root_route_docs():
    return yaml.safe_load(
        """
        responses:
          200:
            description: A list of endpoints
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    supported_urls:
                      type: array
                      items:
                        type: object
                        properties:
                          url:
                            type: string
                            format: url-path
                          methods:
                            type: array
                            items:
                              type: string
                              enum:
                              - GET
                              - POST
                              - PUT
                              - DELETE
                example: {
                  "supported_urls": [{"url": "/", "methods": ["GET"]}, {"url": "/demo", "methods": ["GET", "POST"]}]
                }
          500:
            $ref: '#/components/responses/ServerError'
        """)


def root_route(app, logger=None):
    try:
        supported_urls = endpoint_list(app)
    except:
        return 500, {"message": "Error getting list of endpoints: %s (%s)" % (sys.exc_info()[0], sys.exc_info()[1]), "code": "internal_error"}
    return 200, {"supported_urls": supported_urls}


def txinfo_docs(with_chain=False):
    return yaml.safe_load(
        """
        parameters:
        """
        + (chain_param_docstring() if with_chain else "")
        + """
          - name: txhash
            description: The transaction hash.
            in: path
            required: true
            schema:
              type: string
              format: ethereum-txhash
        responses:
          200:
            description: Information about this transaction
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    mined:
                      type: boolean
                    pending:
                      type: boolean
                    status:
                      type: integer
                      minimum: 0
                      maximum: 1
                    successful:
                      type: boolean
                    error_message:
                      type: string
                    blockNumber:
                      type: integer
                    transactionIndex:
                      type: integer
                    gasLimit:
                      type: integer
                    gasUsed:
                      type: integer
                example: {
                  "mined": true, "pending": false, "status": 0, "successful": false, "blockNumber": 104742, "transactionIndex": 8, "gasUsed": 147842
                }
          400:
            $ref: "#/components/responses/InputError"
          500:
            $ref: "#/components/responses/ServerError"
        """)


# Get the status/info of a transaction on the specified chain/network.
def txinfo(w3, txhash, logger=None):
    if not txhash or len(txhash) < 40:
        return 400, {"message": "Please specify a valid transaction hash.", "code": "invalid_input"}
    try:
        receipt = w3.eth.getTransactionReceipt(txhash)
        txdata = w3.eth.getTransaction(txhash)
    except web3_exceptions.TransactionNotFound as e:
        if logger:
            logger.debug(e)
        return 404, {"message": f"Transaction {txhash} not found on this chain.", "code": "not_found"}
    except ValueError as e:
        # This appears usually when something is wrong with the transaction, so return as 400 (user error).
        return 400, {"message": str(e.args[0]["message"]), "code": str(e.args[0]["code"])}
    except:
        return 500, {"message": "Error getting transaction info: %s (%s)" % (sys.exc_info()[0], sys.exc_info()[1]), "code": "chain_read_error"}
    if receipt is None:
        # Tx has not been mined, find out if it's pending.
        ''' Theoretically, this should work cross-node, but it comes back empty usually.
        pending_filter = w3.eth.filter("pending")
        for pendingtxhash in pending_filter.get_all_entries():
        '''
        # This is Parity-specific code, it will not work on any other node.
        # TODO: Find out how to do this in current clients!
        try:
            parityPendingTx = w3.manager.request_blocking("parity_pendingTransactions", [])
        except:
            if logger:
                logger.error("Could not get pending transactions: %s (%s)", sys.exc_info()[0], sys.exc_info()[1])
            parityPendingTx = []
        for pendingtx in parityPendingTx:
            pendingtxhash = pendingtx["hash"]
            # logger.info(pendingtxhash)
            if pendingtxhash == txhash:
                return 200, {
                    "mined": False,
                    "pending": True,
                    "status": None,
                    "successful": None,
                    "error_message": None,
                    "blockNumber": None,
                    "transactionIndex": None,
                    "gasLimit": None,
                    "gasUsed": None,
                }
        # Not pending, it's an unknown tx.
        return 404, {
            "mined": False,
            "pending": False,
            "status": None,
            "successful": None,
            "error_message": None,
            "blockNumber": None,
            "transactionIndex": None,
            "gasLimit": None,
            "gasUsed": None,
        }
    # Mined tx (part of the confirmed chain), send detailed info.
    # logger.info(receipt)
    # logger.info(txdata)
    message = None
    errcode = None
    if not bool(receipt.status):
        # Try to actually find out the error message.
        if (receipt.gasUsed >= txdata["gas"]):
            message = "Out of gas."
        else:
            try:
                w3.eth.call({"value": txdata["value"], "gas": txdata["gas"], "gasPrice": txdata["gasPrice"],
                             "to": txdata["to"], "from": txdata["from"], "data": txdata["input"]},
                            txdata.blockNumber)
            except ValueError as e:
                if type(e.args[0]) == str:
                    message = e.args[0]
                else:
                    errcode = e.args[0]["code"]
                    if e.args[0]["code"] == -32000:
                        # app.logger.info("Need to run against an archive node to find out the actual error message.")
                        message = "Undetermined: %s" % e.args[0]["message"]
                    elif e.args[0]["code"] == -32015:  # "VM execution error." - we can extract the reason from the data!
                        message = capa_eth1.decode_error_data(e.args[0]["data"])
                    else:
                        # No idea what happened.
                        # logger.info("Error %s: %s", e.args[0]["code"], e.args[0]["message"])
                        message = "Undetermined: %s" % e.args[0]["message"]
            except:
                if logger:
                    logger.info("Unknown error trying to get error message.")
                message = "Undetermined: Unknown error trying to get error message."
            if errcode == -32000:
                # Let's retry without the block number to estimate the problem...
                try:
                    w3.eth.call({"value": txdata["value"], "gas": txdata["gas"], "gasPrice": txdata["gasPrice"],
                                 "to": txdata["to"], "from": txdata["from"], "data": txdata["input"]})
                except ValueError as e:
                    if type(e.args[0]) == str:
                        message = "Estimated (use archive node to determine real cause) - %s" % e.args[0]
                    else:
                        errcode = e.args[0]["code"]
                        if e.args[0]["code"] == -32000:
                            # logger.info("Need to run against an archive node to find out the actual error message.")
                            message = "Undetermined (estimate): %s" % e.args[0]["message"]
                        elif e.args[0]["code"] == -32015:  # "VM execution error." - we can extract the reason from the data!
                            message = "Estimated (use archive node to determine real cause) - %s" % capa_eth1.decode_error_data(e.args[0]["data"])
                        else:
                            # No idea what happened.
                            # logger.info("Error %s: %s", e.args[0]["code"], e.args[0]["message"])
                            message = "Undetermined (estimate): %s" % e.args[0]["message"]
                except:
                    # logger.info("Unknown error trying to get error message.")
                    message = "Undetermined: Unknown error trying to get estimated error message."
    return 200, {
        "mined": True,
        "pending": False,
        "status": receipt.status,
        "successful": bool(receipt.status),
        "error_message": message,
        "blockNumber": receipt.blockNumber,
        "transactionIndex": receipt.transactionIndex,
        "gasLimit": txdata.gas,
        "gasUsed": receipt.gasUsed,
    }


def broadcast_docs(with_chain=False):
    return yaml.safe_load(
        ("        parameters:\n" + chain_param_docstring() if with_chain else "")
        + """
        requestBody:
          required: true
          content:
            multipart/form-data:
              schema:
                type: object
                required:
                  - tx
                properties:
                  tx:
                    description: The hex representation of the signed transaction.
                    type: string
        responses:
          200:
            description: The tx hash of the broadcast transaction
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    txhash:
                      type: string
                      format: ethereum-txhash
                example: {
                  "txhash": "0x0"
                }
          400:
            $ref: "#/components/responses/InputError"
          500:
            $ref: "#/components/responses/ServerError"
        """)


# Get the status/info of a transaction on the specified chain/network.
def broadcast(w3, request, logger=None):
    tx = request.form["tx"]
    if not tx:
        return 400, {"message": "Please specify a valid transaction.", "code": "invalid_input"}
    try:
        txhash = Web3.toHex(w3.eth.sendRawTransaction(tx))
    except ValueError as e:
        # This appears usually when something is wrong with the transaction, so return as 400 (user error).
        return 400, {"message": str(e.args[0]["message"]), "code": str(e.args[0]["code"])}
    except:
        return 500, {"message": "Error broadcasting transaction.", "code": "chain_write_error"}
    return 200, {"txhash": txhash}


def contract_info_docs(with_chain=False, all_contract_types=[]):
    docs = yaml.safe_load(
        """
        parameters:
        """
        + (chain_param_docstring() if with_chain else "")
        + """
          - name: contract_type
            description: Type of the contract to query
            in: path
            required: true
            schema:
              type: string
              enum: []
          - name: info_type
            description: Type of the information to get for that contract
            in: path
            required: true
            schema:
              type: string
              enum:
              - abi
              - address
              - instance
        responses:
          200:
            description: The requested info
            content:
              application/json:
                schema:
                  description: Either just the address, or a JSON ABI object, depending on info_type
                  oneOf:
                    - description: Contract ABI as generated by the Solidity compiler
                      type: object
                      format: ethereum-abi
                    - description: Ethereum address on which this contract has been deployed
                      type: string
                      format: ethereum-address
                    - description: Instance - address, deployment tx hash and contract ABI in one object
                      type: object
                      properties:
                        address:
                          type: string
                          format: ethereum-address
                        deploy_txhash:
                          type: string
                          format: ethereum-txhash
                        abi:
                          type: object
                          format: ethereum-abi
                examples:
                  abi:
                    summary: Contract ABI
                    value: [ ... ]
                  address:
                    summary: Ethereum address
                    value: "0x0"
          404:
            $ref: "#/components/responses/NotFound"
          500:
            $ref: "#/components/responses/ServerError"
        """)
    # {'parameters': [{'name': 'chain', 'description': 'The name or ID of the chain this contract is on ("default" to guess the correct one, usually falling back to Layer 1)', 'in': 'path', 'required': True, 'schema': {'type': 'string', 'enum': ['default', 'eth', 'ethereum', 'ropsten', 'goerli', 'xdai', 1, 3, 5, 100]}}, {'name': 'contract_type', 'description': 'Type of the contract to query', 'in': 'path', 'required': True, 'schema': {'type': 'string', 'enum': ['cs1_cryptostamp', 'cs1_onchainshop', 'cs1_colors', 'cs_nyc2020', 'cs2_presale', 'cs2_cryptostamp2', 'cs2_achievements', 'cs3_presale', 'csc_collections', 'csc_collection', 'csc_ensregistrar']}}, {'name': 'info_type', 'description': 'Type of the information to get for that contract', 'in': 'path', 'required': True, 'schema': {'type': 'string', 'enum': ['abi', 'address', 'instance']}}], 'responses': {200: {'description': 'The requested info', 'content': {'application/json': {'schema': {'description': 'Either just the address, or a JSON ABI object, depending on info_type', 'oneOf': [{'description': 'Contract ABI as generated by the Solidity compiler', 'type': 'object', 'format': 'ethereum-abi'}, {'description': 'Ethereum address on which this contract has been deployed', 'type': 'string', 'format': 'ethereum-address'}, {'description': 'Instance - address, deployment tx hash and contract ABI in one object', 'type': 'object', 'properties': {'address': {'type': 'string', 'format': 'ethereum-address'}, 'deploy_txhash': {'type': 'string', 'format': 'ethereum-txhash'}, 'abi': {'type': 'object', 'format': 'ethereum-abi'}}}]}, 'examples': {'abi': {'summary': 'Contract ABI', 'value': ['...']}, 'address': {'summary': 'Ethereum address', 'value': '0x0'}}}}}, 404: {'$ref': '#/components/responses/NotFound'}, 500: {'$ref': '#/components/responses/ServerError'}}}
    for i in range(len(docs["parameters"])):
        if docs["parameters"][i]["name"] == "contract_type" and type(all_contract_types) == list:
            docs["parameters"][i]["schema"]["enum"].extend(all_contract_types)
    return docs


# Get contract infomation.
def contract_info(nwdata, contract_type, info_type, all_contract_types, get_contract_info, logger=None):
    if contract_type not in all_contract_types:
        return 404, {"message": "Please specify a valid contract type.", "code": "unsupported_contract"}
    if info_type not in ["abi", "address", "instance"]:
        return 404, {"message": "Please specify a valid information type.", "code": "unsupported_info_type"}
    infodata = get_contract_info(contract_type, info_type, nwdata["network_id"])
    if not infodata:
        return 500, {"message": "Requested information could not be loaded.", "code": "internal_error"}
    # Don't use jsonify() if info_type results in a single value only.
    return 200, infodata

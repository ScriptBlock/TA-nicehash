import import_declare_test
from datetime import datetime
from time import mktime
import sys
import json
import os
import os.path as op
import uuid
import traceback
import requests
import hmac
from hashlib import sha256
from splunklib import modularinput as smi
from solnlib import conf_manager
from solnlib import log
from solnlib.modular_input import checkpointer

import re
sys.path.append(os.path.join('/opt/splunk','etc','apps','SA-VSCode','bin'))
import splunk_debug as dbg
dbg.enable_debugging(timeout=10)

MINIMAL_INTERVAL = 30
APP_NAME = __file__.split(op.sep)[-3]
CONF_NAME = "ta_nicehash"

def get_log_level(session_key, logger):
    """
    This function returns the log level for the addon from configuration file.
    :param session_key: session key for particular modular input.
    :return : log level configured in addon.
    """
    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))

        logging_details = settings_cfm.get_conf(
            CONF_NAME+"_settings").get("logging")

        log_level = logging_details.get('loglevel') if (
            logging_details.get('loglevel')) else 'INFO'
        return log_level

    except Exception:
        logger.error(
            "Failed to fetch the log details from the configuration taking INFO as default level.")
        return 'INFO'

def get_account_details(session_key, account_name, logger):
    """
    This function retrieves account details from addon configuration file.
    :param session_key: session key for particular modular input.
    :param account_name: account name configured in the addon.
    :param logger: provides logger of current input.
    :return : account details in form of a dictionary.    
    """
    try:
        cfm = conf_manager.ConfManager(
            session_key, APP_NAME, realm='__REST_CREDENTIAL__#{}#configs/conf-{}_account'.format(APP_NAME,CONF_NAME))
        account_conf_file = cfm.get_conf(CONF_NAME + '_account')
        logger.info(f"Fetched configured account {account_name} details.")
        return {
            "orgid": account_conf_file.get(account_name).get('orgid'),
            "apikey": account_conf_file.get(account_name).get('apikey'),
            "apisecret": account_conf_file.get(account_name).get('apisecret'),
        }
    except Exception as e:
        logger.error("Failed to fetch account details from configuration. {}".format(traceback.format_exc()))
        sys.exit(1)

def get_proxy_details(session_key, logger):
    try:
        settings_cfm = conf_manager.ConfManager(
            session_key,
            APP_NAME,
            realm="__REST_CREDENTIAL__#{}#configs/conf-{}_settings".format(APP_NAME,CONF_NAME))
        proxy_details = settings_cfm.get_conf(CONF_NAME+"_settings").get("proxy")        
        logger.info(f"Fetched proxy details.")
        
        return proxy_details
    except Exception as e:
        logger.error("Failed to fetch proxy details from configuration. {}".format(traceback.format_exc()))
        sys.exit(1)


def get_proxy_param(proxyDetails):
    try:
        useSocks = False
        if proxyDetails != None:
            if proxyDetails.get("proxy_enabled") == '1':
                proxyUsername = proxyDetails.get("proxy_username")
                proxyPassword = proxyDetails.get("proxy_password")
                if proxyUsername != None:
                    useSocks = True
                proxyUrl = proxyDetails.get("proxy_url")
                proxyPort = proxyDetails.get("proxy_port")

                if useSocks:
                    return {"https": "socks5://{}:{}@{}:{}".format(proxyUsername, proxyPassword, proxyUrl, proxyPort)}
                else:
                    return {"https": "https://{}:{}".format(proxyUrl, proxyPort)}
            else:
                return None
        else:
            return None
    except Exception as e:
        # logger.error("Failed to get proxy parameters.")
        sys.exit(1)

def get_records(logger, ew, inputItems, accountDetails, proxyParam):
    for ep in inputItems["endpoints"].split("|"):
        finalEPSourceType = re.sub("/", ":", ep)
        finalEPSourceType = re.sub("^:", "", finalEPSourceType)

        url = "https://api2.nicehash.com{}".format(ep)

        # get now
        now = datetime.now()
        now_ec_since_epoch = mktime(now.timetuple()) + now.microsecond / 1000000.0
        xtime = int(now_ec_since_epoch * 1000)

        # generate a nonce
        xnonce = str(uuid.uuid4())

        key = accountDetails.get("apikey")
        orgid = accountDetails.get("orgid")

        message = bytearray(key, 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray(str(xtime), 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray(xnonce, 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray(orgid, 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray("GET", 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray(ep, 'utf-8')
        message += bytearray('\x00', 'utf-8')
        message += bytearray('', 'utf-8')

        digest = hmac.new(bytearray(accountDetails.get("apisecret"), 'utf-8'), message, sha256).hexdigest()
        xauth = key + ":" + digest

        headers = {
            'X-Time': str(xtime),
            'X-Nonce': xnonce,
            'X-Auth': xauth,
            'Content-Type': 'application/json',
            'X-Organization-Id': orgid,
            'X-Request-Id': str(uuid.uuid4())
        }

        s = requests.Session()
        s.headers = headers
        s.proxies = proxyParam
        response = s.request(method="GET", url=url, timeout=(10.0,30.0))

        if response.status_code == 200:
            recordEvent = smi.Event()
            recordEvent.data = json.dumps(response.json())
            recordEvent.index = inputItems.get("index")
            recordEvent.sourceType = finalEPSourceType
            recordEvent.done = True
            recordEvent.unbroken = True
            recordEvent.host = "nicehashapi"
            recordEvent.time = now
            
            ew.write_event(recordEvent)

        elif response.content:
            raise Exception(str(response.status_code) + ": " + response.reason + ": " + str(response.content))
        else:
            raise Exception(str(response.status_code) + ": " + response.reason)



class NICEHASHAPI(smi.Script):

    def __init__(self):
        super(NICEHASHAPI, self).__init__()

    def get_scheme(self):
        scheme = smi.Scheme('NicehashAPI')
        scheme.description = 'Nicehash API'
        scheme.use_external_validation = True
        scheme.streaming_mode_xml = True
        scheme.use_single_instance = False

        scheme.add_argument(
            smi.Argument(
                'name',
                title='Name',
                description='Name',
                required_on_create=True
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'account',
                required_on_create=True,
            )
        )
        
        scheme.add_argument(
            smi.Argument(
                'endpoints',
                required_on_create=True,
            )
        )
        
       
        return scheme

    def validate_input(self, definition):
        return

    def stream_events(self, inputs, ew):

        metaConfigs = self._input_definition.metadata
        sessionKey = metaConfigs['session_key']
        inputName = list(inputs.inputs.keys())[0]

        inputItems = {}
        inputItems = inputs.inputs[inputName]

        # Generate logger with input name
        _, inputName = (inputName.split('//', 2))
        logger = log.Logs().get_logger('{}_input'.format(APP_NAME))

        # Log level configuration
        logLevel = get_log_level(sessionKey, logger)
        logger.setLevel(logLevel)        

        logger.debug("Modular input invoked.")

        # get the account name to do the data pull for
        accountName = inputItems.get('account')
        accountDetails = get_account_details(sessionKey, accountName, logger)        
        #apikey = accountDetails.get("apikey")
        #apisecret = accountDetails.get("apisecret")

        proxyDetails = get_proxy_details(sessionKey, logger)
        proxyParam = get_proxy_param(proxyDetails)

        get_records(logger, ew, inputItems, accountDetails, proxyParam)


if __name__ == '__main__':
    exit_code = NICEHASHAPI().run(sys.argv)
    sys.exit(exit_code)
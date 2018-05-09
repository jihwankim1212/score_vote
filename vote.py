#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2018 theloop, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""ICX SCORE Prototyping code to explain basic SCORE example, NOT OFFICIAL ICX CODE!!!!
NO GUARANTEE FOR ANY RISK OR TROUBLE.
"""

import os
import leveldb
import json

from loopchain.blockchain import ScoreBase
from loopchain.tools.score_helper import ScoreHelper, ScoreDatabaseType, LogLevel

class UserScore(ScoreBase):
    """ICX Coin Score code

    ICX SCORE Prototyping code to explain basic SCORE example, NOT OFFICIAL ICX CODE!!!!
    NO GUARANTEE FOR ANY RISK OR TROUBLE.

    """
    __score_info = None
    __db_vote_id = 'vote.db'
    __db = None
    __score_helper = None
    __initialized = False

    def __init__(self, info=None):
        """Initialize SCORE.
        """

        # Initialize SCORE info and DB module.
        self.logi('__init__() start')
        self.__init_score_info(info)
        self.__init_score_helper()
        self.__init_db()
        self.logd('__init__() end')

    def __init_score_info(self, info):
        """ Read package.json file as SCORE package information.

        ScoreHelper is special module to capsulize SCORE operation.
        """
        if info is None:
            with open(os.path.dirname(__file__)+'/'+ScoreBase.PACKAGE_FILE, 'r') as f:
                self.__score_info = json.loads(f.read())
                f.close()
        else:
            self.__score_info = info

    def __init_score_helper(self):
        """ Initialize ScoreHelper().

        ScoreHelper is special module to capsulize SCORE operation.
        """

        if self.__score_helper is None:
            self.__score_helper = ScoreHelper()

    def __init_db(self):
        """ Initialize database for SCORE.

        SCORE have to store all data into its own database.
        """

        self.logd('__init_db() start')
        if self.__db is None:
            db = self.__score_helper.load_database(
                score_id=self.__db_vote_id,
                database_type=ScoreDatabaseType.leveldb)
            self.logd(f'db({db}) is created.')
            self.__db = db

        # TESTING purpose.
        # Create virtual bank account ( 0x00000000000000000000000000000000000000000000 ) into 10^22 ICX.
        address = '0x' + '0' * 40
        value = get_balance(self.__db, address)
        if value == 0:
            value = 10 ** 22
            set_balance(self.__db, address, value)
            self.logd(f'address({address}): {value}')

        self.logd('__init_db() end')


    def invoke(self, transaction, block):
        """ Handler of 'Invoke' requests.

        It's event handler of invoke request. You need to implement this handler like below.
        0. Define the interface of functions in 'invoke' field of package.json.
        1. Parse transaction data and get the name of function by reading 'method' field of transaction.
        2. Call that function.

        :param transaction: transaction data.
        :param block: block data has transaction data.
        :return: response : Invoke result.
        """

        self.logd('invoke() start')

        response = None

        try:
            if not verify_transaction(transaction):
                raise IcxError(Code.INVALID_TRANSACTION)

            # Parse transaction data.
            data = transaction.get_data_string()
            params = json.loads(data)
            self.logi(data)

            methods = {
                'icx_init': self.__invoke_init,
                'icx_sendTransaction': self.__invoke_sendTransaction,
                'make_vote': self.__invoke_makeVote,
                'vote_tx': self.__invoke_voteTx
            }

            method_name = params['method']
            method = methods.get(method_name, None)
            if method is None:
                raise IcxError(Code.METHOD_NOT_FOUND, method_name)

            # Call pre-defined functions in package.json by the request in transaction.
            method(transaction, block, params['params'])

        # Return response code.
        except IcxError as ie:
            response = create_invoke_response(ie.code, ie.message)
        except Exception as e:
            response = create_invoke_response(Code.UnknownError, str(e))
        else:
            response = create_invoke_response(Code.OK)


        self.logi(f'invoke result: {str(response)}')
        self.logd('invoke() end')

        return response



    def __invoke_init(self, transaction, block, params):
        """ Initialize the value of account.

        :param transaction: Transaction data.
        :param block: Block data.
        :param params: params from transaction data including 'address' and'value'.
        """

        self.logd('__invoke_init() start')
        self.logd(f'{str(params)}')

        if self.__initialized:
            raise IcxError(Code.INVALID_TRANSACTION, 'icx_score has been already initialized.')

        address = params['address']
        value = params['value']
        set_balance_str(self.__db, address, value)
        self.__initialized = True

        self.logd('__invoke_init() end')



    def __invoke_sendTransaction(self, transaction, block, params):
        """ Transfer money to other's bank account.

        :param transaction: Transaction data.
        :param block: Block data.
        :param params: params from transaction data including 'from', 'to', and 'value'
        """
        self.logd('__invoke_sendTransaction() start')

        from_address = params['from']
        to_address = params['to']
        value = str_to_int(params['value'])

        if value <= 0:
            raise IcxError(Code.INVALID_PARAMS, f'value({value}) is invalid.')

        from_balance = get_balance(self.__db, from_address)
        if from_balance < value:
            raise IcxError(Code.INVALID_PARAMS,
                f'from_balance({from_balance}) is less than transaction value({value})')

        to_balance = get_balance(self.__db, to_address)

        from_balance -= value
        to_balance += value

        set_balances(self.__db,
            {from_address: from_balance, to_address: to_balance})

        self.logd('__invoke_sendTransaction() end')

    def __invoke_makeVote(self, transaction, block, params):
        """ Transfer money to other's bank account.

        :param transaction: Transaction data.
        :param block: Block data.
        :param params: params from transaction data including 'from', 'to', and 'value'
        """
        self.logd('__invoke_makeVote() start')

        #self.logd('__invoke_makeVote() db : ' + self.__db)

        subject = params['subject']
        items = params['items']
        itemsLen = len(items)
        createAddress = params['createAddress']

        #self.logd('__invoke_makeVote() subject : ' + subject)
        self.logd('__invoke_makeVote() subject')

        self.logd('__invoke_makeVote() subject : ' + subject)
        set_balance_str(self.__db, 'subject', subject)
        self.logd('__invoke_makeVote() createAddress : ' + createAddress)
        set_balance_str(self.__db, 'createAddress', createAddress)
        self.logd('__invoke_makeVote() itemCnt : ' + str(itemsLen))
        set_balance_str(self.__db, 'itemCnt', str(itemsLen))

        self.logd('__invoke_makeVote() while')

        #self.logd('__invoke_makeVote() getBalance subject : ' + get_balance(self.__db, 'subject'))
        #self.logd('__invoke_makeVote() getBalance itemCnt : ' + len(items))

        idx = 0
        #item = ''

        while idx < itemsLen :
            self.logd('__invoke_makeVote() items : ' + str(items))
            self.logd('__invoke_makeVote() item : ' + items[idx])
            #item = items[idx]
            set_balance_str(self.__db, 'item_' + str(idx), items[idx])
            self.logd('__invoke_makeVote() item : ' + items[idx])
            set_balance(self.__db, 'item_' + str(idx) + '_cnt', 0)
            self.logd('__invoke_makeVote() getBalance itemIdx')
            idx = idx + 1

        self.logd('__invoke_makeVote() end')

    def __invoke_voteTx(self, transaction, block, params):
        """ Transfer money to other's bank account.

        :param transaction: Transaction data.
        :param block: Block data.
        :param params: params from transaction data including 'from', 'to', and 'value'
        """
        self.logd('__invoke_voteTx() start')

        itemAddress = params['itemAddress']
        createAddress = params['createAddress']
        itemCnt = get_balance(self.__db, 'itemCnt')
        #itemIdx = 0

        #check already
        # while itemIdx < itemCnt:
        #     voteAddress = get_balance(self.__db, createAddress + '_' + str(itemIdx))
        #     if voteAddress is not None and voteAddress != '' :
        #         raise IcxError(Code.INVALID_TRANSACTION, 'vote has been already transaction.')
        #     itemIdx = itemIdx + 1

        itemIdx = 0
        itemAddressLen = len(itemAddress)
        while itemIdx < itemAddressLen :
            selectAddress = itemAddress[itemIdx]
            self.logd('__invoke_voteTx() voteAddress : ' + createAddress + '_' + str(itemIdx))
            set_balance_str(self.__db, createAddress + '_' + str(itemIdx), selectAddress)
            set_balance(self.__db, 'item_' + str(itemAddress) + '_cnt',
                        get_balance(self.__db, 'item_' + str(itemAddress) + '_cnt') + 1)
            itemIdx = itemIdx + 1

        self.logd('__invoke_voteTx() end')

    def query(self, params):
        """ Handler of 'Query' requests.

        It's event handler of query request. You need to implement this handler like below.
        0. Define the interface of functions in 'query' field of package.json.
        1. Parse transaction data and get the name of function by reading 'method' field of transaction.
        2. Call that function.

        :param transaction: transaction data.
        :param block: block data has transaction data.
        :return: response : Query result.
        """
        self.logd('query() start')
        self.logd('params: ' + str(params))

        _id = None
        response = None

        methods = {
            'icx_getBalance': self.__query_getBalance,
            'vote_getValue': self.__query_getValue,
            'vote_info': self.__query_voteInfo,
            'vote_items': self.__query_voteItems
        }

        try:
            request = json.loads(params)

            _id = request['id']
            method_name = request['method']

            response = methods.get(
                method_name, self.__handle_method_not_found)(_id, request)

        except IcxError as ie:
            response = create_jsonrpc_error_response(_id, ie.code, ie.message)
        except Exception as e:
            response = create_jsonrpc_error_response(_id, Code.UnknownError)

        self.logd('query() end')

        return json.dumps(response)

    def __query_getBalance(self, _id, request):
        """ Get the current value of bank account.

        :param _id: ID of request. Used it to distingush request.
        :param request: Request information
        :return:
        """
        self.logd('__query_getBalance() start')
        self.logd(f'{str(request)}')

        params = request['params']
        self.logd(params)
        address = params['address']
        self.logd(address)

        if not check_address(address):
            return create_jsonrpc_error_response(
                _id, Code.INVALID_PARAMS, f'invalid address({address})')

        value = get_balance_str(self.__db, address)
        response = create_jsonrpc_success_response(_id, value)

        self.logd('__query_get_balance() end')

        return response

    def __query_getValue(self, _id, request):
        """ Get the current value of bank account.

        :param _id: ID of request. Used it to distingush request.
        :param request: Request information
        :return:
        """
        self.logd('__query_getValue() start')
        self.logd(f'{str(request)}')

        params = request['params']
        self.logd(params)
        key = params['key']
        self.logd(key)

        value = get_balance_str(self.__db, key)
        response = create_jsonrpc_success_response(_id, value)

        self.logd('__query_getValue() end')

        return response

    def __query_voteInfo(self, _id, request):
        """ Get the current value of bank account.

        :param _id: ID of request. Used it to distingush request.
        :param request: Request information
        :return:
        """
        self.logd('__query_voteInfo() start')
        self.logd(f'{str(request)}')

        value = {}

        value['subject'] = get_balance_str(self.__db, 'subject')
        value['createAddress'] = get_balance_str(self.__db, 'createAddress')

        #self.logd('__query_voteInfo() db : ' + self.__db)

        response = create_jsonrpc_success_response(_id, value)

        self.logd('__query_voteInfo() end')

        return response

    def __query_voteItems(self, _id, request):
        """ Get the current value of bank account.

        :param _id: ID of request. Used it to distingush request.
        :param request: Request information
        :return:
        """
        self.logd('__query_voteItems() start')
        self.logd(f'{str(request)}')

        value = {}

        itemCnt = get_balance(self.__db, 'itemCnt')
        self.logd('__query_voteItems() itemCnt : ' + str(itemCnt))

        itemIdx = 0

        items = []

        self.logd('__query_voteItems() items : ' + str(items))
        while itemIdx < itemCnt:
            self.logd('__query_voteItems() itemIdx : ' + str(itemIdx))
            items.append({})
            items[itemIdx]['item'] = get_balance_str(self.__db, 'item_' + str(itemIdx))
            self.logd('__query_voteItems() items : ' + str(items))
            items[itemIdx]['cnt'] = get_balance_str(self.__db, 'item_' + str(itemIdx) + '_cnt')
            self.logd('__query_voteItems() items : ' + str(items))
            itemIdx = itemIdx + 1

        self.logd('__query_voteItems() value : ' + str(value))
        value['items'] = items

        response = create_jsonrpc_success_response(_id, value)

        self.logd('__query_voteItems() end')

        return response

    def __handle_method_not_found(self, _id, request):
        self.logd('__handle_method_not_found() start')

        method_name = request['method']
        response = create_jsonrpc_error_response(
            _id, Code.METHOD_NOT_FOUND, method_name)

        self.logd('__handle_method_not_found() end')

        return response

    def info(self):
        return self.__score_info

    def log(self, level, message):
        if self.__score_helper:
            self.__score_helper.log("ICX", message, level)

    def logd(self, message):
        self.log(LogLevel.DEBUG, message)

    def logi(self, message):
        self.log(LogLevel.INFO, message)


from enum import Enum

class Code(Enum):
    """Result code enumeration
    Refer to http://www.simple-is-better.org/json-rpc/jsonrpc20.html#examples
    """
    OK = 0

    # -32000 ~ -32099: Server error
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    PARSE_ERROR = -32700

    INVALID_TRANSACTION = -32800
    UNKNOWN_ERROR = -40000

__error_message = {
    Code.OK: "ok",

    Code.INVALID_REQUEST: "invalid request",
    Code.METHOD_NOT_FOUND: "method not found",
    Code.INVALID_PARAMS: "invalid params",
    Code.INTERNAL_ERROR: "internal error",
    Code.PARSE_ERROR: "parse error",

    Code.INVALID_TRANSACTION: "invalid transaction",
    Code.UNKNOWN_ERROR: "unknown error"
}

def get_code_message(code):
    default_message = "unknown code({code}-{str(code)})"
    return __error_message.get(code, default_message)

class IcxError(Exception):

    def __init__(self, code, message=None):
        self.code = code
        if message is None:
            message = get_code_message(code)
        self.message = message



def verify_transaction(transaction):
    """verify transaction using cryptography library
    """
    return True



def str_to_int(s):
    """Convert hexa string to int

    Args:
        hexa (str): ex) '0x1234'

    Returns:
        hexa string's int value
    """
    return int(s, 0)

def int_to_str(value):
    if type(value) != int:
        raise IcxError(Code.INVALID_PARAMS, 'param is not int type')

    return hex(value)

def is_hex(s):
    if not s.startswith('0x'):
        return False

    for i in range(2, len(s)):
        c = s[i]
        if '0' <= c <= '9' or 'a' <= c <= 'f':
            continue
        return False

    return True

def check_address(address):
    """Check icx address format
    Args:
        address (str):
        - lowercase alphabet
        - hexa string consists of 42 chars including '0x' prefix

    Return:
        bool: True or False
    """

    if not isinstance(address, str):
        return False
    if len(address) != 42:
        return False

    return is_hex(address)



def check_db(_db):
    if _db is None:
        raise IcxError(Code.INVALID_PARAMS, 'db is none')
    pass

def get_value(_db, key):
    """get value from leveldb.

    Args:
        _db (leveldb object)
        key (str)

    Returns:
        (str): hexa string
    """
    check_db(_db)
    value = None

    try:
        value = _db.Get(key.encode())
    except:
        return None

    return value.decode()

def set_value(_db, key, value):
    check_db(_db)
    _db.Put(key.encode(), value.encode())

def delete(_db, key):
    check_db(_db)
    _db.Delete(key.encode())

def get_balance_str(_db, address):
    value = get_value(_db, address)
    if value is None:
        value = '0x0'
    return value

def get_balance(_db, address):
    value = 0

    s = get_value(_db, address)
    if s is not None:
        value = str_to_int(s)

    return value

def set_balance_str(_db, address, value):
    """set balance to db.
    Args:
        address (str): icx address
        value (str): balance ex) '0x1234', '0x123'
    """
    set_value(_db, address, value)

def set_balance(_db, address, value):
    """set balance to db.
    Args:
        address (str): icx address
        value (int): balance ex) '0x1234', '0x123'
    """
    set_value(_db, address, int_to_str(value))

def set_balances(_db, params):
    """set balance to db.
    Args:
        _db (leveldb object)
        **kwargs (hash): ex {"0xb60e8dd61c5d32be8058bb8eb970870f07233155": 10}
    """
    check_db(_db)
    batch = leveldb.WriteBatch()

    for address in params:
        value = params[address]

        if value > 0:
            set_value(batch, address, int_to_str(value))
        elif value == 0:
            delete(batch, address)
        else:
            raise ValueError

    _db.Write(batch, sync=True)


__jsonrpc_version = "2.0"

def create_jsonrpc_error_response(_id, code, message=None, data=None):
    """Create jsonrpc error response json object.
    """
    response = create_jsonrpc_common_response(_id)
    response["error"] = create_jsonrpc_error_object(code, message, data)

    return response

def create_jsonrpc_success_response(_id, result):
    """Create jsonrpc success response json object.
    """
    response = create_jsonrpc_common_response(_id)
    response["result"] = result

    return response

def create_jsonrpc_common_response(_id):
    """Create common response json object
    """
    response = {
        "jsonrpc": __jsonrpc_version,
        "id": _id,
    }

    return response

def create_jsonrpc_error_object(code, message=None, data=None):
    if type(code) != Code:
        raise IcxError(Code.INVALID_PARAMS, "code is not Code type.")

    if message is None:
        message = get_code_message(code)

    error = {
        "code": code.value,
        "message": message
    }

    if data:
        error["data"] = data

    return error

def create_invoke_response(code, message=None, data=None):
    return create_jsonrpc_error_object(code, message, data)
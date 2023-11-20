import re
import sys
# import pickle
# import os
import json
import pickle
import sys
import os
# import asyncio
# import sched
# from apscheduler.schedulers.asyncio import AsyncIOScheduler
# from apscheduler.triggers.cron import CronTrigger
# import traceback
# import numpy as np
from clickhouse_driver.client import Client
from clickhouse_driver.errors import ServerException, SocketTimeoutError
# from concurrent.futures import ThreadPoolExecutor
import pymysql
import logging
# import logging.config
# from logging.handlers import QueueHandler, QueueListener
# import queue
import datetime
    



def train_test_split(df, split=0.7):
    # # shuffle df with reset index
    df = df.sample(frac=1).reset_index(drop=True)
    train_size = int(df.shape[0] * split)
    
    # # split train_data and test_data
    train_df = df.iloc[:train_size, :]
    predc_df = df.iloc[train_size:, :]
    
    return train_df, predc_df

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def execute_ch(sql, config, param=None, with_column_types=True):
    client = check_cs(config['cs'], index=1)
    print(client)
    if client == None:
        sys.exit(1)

    result = client.execute(sql, params=param, with_column_types=with_column_types)

    client.disconnect()
    return result

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def check_cs(cs, index=1):
    if index >= len(cs):
        logging.error('[clickhouse client ERROR] connect fail')
        return None
    
    '''입력 받은 config index 위치 출력'''
    ch = cs[index]
    print(ch)
    try:
        client = Client(ch['host'], port=ch['port'],
                        send_receive_timeout=int(ch['timeout']),
                        settings={'max_threads': int(ch['thread'])}
                       )
        client.connection.force_connect()
        if client.connection.connected:
            return client
        else:
            return check_cs(cs, index + 1)
    except:
        return check_cs(cs, index + 1)


def update_mysql_config(config, version, model_id=None):
    if model_id == None:
        print('connect_to_mysql: MODEL ID WAS NOT PROVIDED')
        return
    conn = pymysql.connect(host=config['host'], port=config['port'], user=config['user'], password=config['password'], db=config['db'])
    curs = conn.cursor()
    sql = 'select config from model_meta where model_id = {}'.format(model_id)
    curs.execute(sql)
    result = list(curs.fetchone())[0]
    model_config = json.loads(result)

    if model_config['train']['esoinn_version'] == "":  # # esoinn 최초 학습
        model_config['train']['feat_version'] = version
        model_config['predict']['feat_version'] = version
    model_config['predict']['model_version'] = version
    model_config['train']['esoinn_version'] = version
    print("UPDATE MODEL CONFIG", model_config)
    model_str = json.dumps(model_config, sort_keys=False, default=str).replace('"', '\\"').replace('***', model_config['train']['db_name'])
    # model_str = json.dumps(model_config, indent=4, sort_keys=False, default=str)
    print("JSON DUMPS")
    print("'{update_config}'".format(update_config=model_str))
    sql = "UPDATE model_meta SET config = '{update_config}' where model_id = {model_id}".format(update_config=model_str, model_id=model_id)
    print("SQL", sql)
    curs.execute(sql)
    conn.commit()
    conn.close()


def get_delta(delta):
    """
    load mySQL config (DTI 내부 AI 모델 설정 config) & now_delta, prev_delta 시간 변환
    """
    try:
        delta = delta.strip()
        delta = delta.replace(' ', '')
        unit, num = delta.split('=')[0], int(delta.split('=')[1])
        if unit == 'seconds':
            return datetime.timedelta(seconds=num)
        elif unit == 'minutes':
            return datetime.timedelta(minutes=num)
        elif unit == 'hours':
            return datetime.timedelta(hours=num)
        elif unit == 'days':
            return datetime.timedelta(days=num)
        elif unit == 'weeks':
            return datetime.timedelta(weeks=num)
        else:
            logging.error('[getDelta ELSE] delta: {} => return default value: days=1'.format(delta))
            return datetime.timedelta(days=1)
    except:
        logging.error('[getDelta ERROR] delta: {} => return default value: days=1'.format(delta))
        return datetime.timedelta(days=1)

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def save_filter_list(list=None, version=None, att_name=None, mode=None, l_type=None, d_type=None):
    pwd = os.path.dirname(os.path.realpath(__file__))

    if l_type == 'idx':
        if not os.path.exists(pwd + "/obj/" "{mode}_filter_idx_list".format(mode=mode)):
            os.makedirs(pwd + "/obj/" "{mode}_filter_idx_list".format(mode=mode))
        try:
            with open(pwd + "/obj/" "{mode}_filter_idx_list/filter_idx_list".format(mode=mode) + att_name + '_' + version + ".pickle", "wb") as f:
                pickle.dump(list, f)
        except:
            raise Exception

    elif l_type == 'se_time':
        if not os.path.exists(pwd + "/obj/" "{mode}_filter_se_time_list".format(mode=mode)):
            os.makedirs(pwd + "/obj/" "{mode}_filter_se_time_list".format(mode=mode))
        try:
            with open(pwd + "/obj/" "{mode}_filter_se_time_list/filter_se_time_list".format(mode=mode) + '_' + version + ".pickle", "wb") as f:
                pickle.dump(list, f)
        except:
            raise Exception

    elif l_type == 'data_collect':
        if not os.path.exists(pwd + "/obj/" "{d_type}_data_type_list".format(d_type=d_type)):
            os.makedirs(pwd + "/obj/" "{d_type}_data_type_list".format(d_type=d_type))
        try:
            with open(pwd + "/obj/" "{d_type}_data_type_list/data_type_list".format(d_type=d_type) + '_' + version + ".pickle", "wb") as f:
                pickle.dump(list, f)
        except:
            raise Exception

            
def load_filter_list(version=None, att_name=None, mode=None, l_type=None, d_type=None):
    pwd = os.path.dirname(os.path.realpath(__file__))

    if l_type == 'idx':
        try:
            with open(pwd + "/obj/" + '{mode}_filter_idx_list/filter_idx_list'.format(mode=mode) + att_name + '_' + version + ".pickle", "rb") as f:
                filter_idx_list = pickle.load(f)
        except:
            raise Exception

        return filter_idx_list

    elif l_type == 'se_time':
        try:
            with open(pwd + "/obj/" + '{mode}_filter_se_time_list/filter_se_time_list'.format(mode=mode) + '_' + version + ".pickle", "rb") as f:
                filter_se_time_list = pickle.load(f)
        except:
            raise Exception

        return filter_se_time_list

    elif l_type == 'data_collect':
        try:
            with open(pwd + "/obj/" + '{d_type}_data_type_list/data_type_list'.format(d_type=d_type) + '_' + version + ".pickle", "rb") as f:
                data_type_list = pickle.load(f)
        except:
            raise Exception

        return data_type_list

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
class DBCheck():
    def __init__(self, mode, config, model_config, index=0):
        """
        Click House 데이터베이스에 연결하고 테이블을 생성하거나 삭제, 수정하기 위한 클래스
        데이터베이스의 각 테이블 마다 객체를 생성하여 사용한다.
        """
        # Click House 에서 사용되는 Column 의 Type 값 모음
        self.CLICK_HOUSE_TYPES = ['Int8', 'Int16', 'Int32', 'Int64', 'Int128', 'Int256',
                         'UInt8', 'UInt16', 'UInt32', 'UInt64', 'UInt128', 'UInt256',
                         'Float32', 'Float64', 'Enum8', 'Enum16',
                         'Date', 'DateTime', 'DateTime64', 'IPv4', 'IPv6',
                         'String', 'FixedString', 'UUID', 'Decimal', 'Nested'
                         ]
        # Click House 에서 사용되는 Column 의 Type 값 중 다른 값을 포함할 수 있는 값 모음
        self.CLICK_HOUSE_WRAPPED_TYPES = ['Tuple', 'Array', 'Nullable', 'LowCardinality', 'Map']

        # Click House 에서 지원하는 테이블 수정 명령어 모음
        self.MODIFY_TYPE = ['ADD', 'DROP', 'RENAME', 'CLEAR', 'COMMENT', 'MODIFY']

        # SQL
        self.CONNECTION_TEST_SQL = 'SELECT 1'
        self.DROP_TABLE_SQL = 'DROP TABLE IF EXISTS %s'
        self.TABLE_CHECK_SQL = 'SELECT * FROM %s LIMIT 1'
        self.ALTER_TABLE_SQL = 'ALTER TABLE %s %s COLUMN '

        # 안내 메세지
        self.DB_CONNECTION_FAIL = '데이터베이스 연결에 실패했습니다.'
        self.NAME_ERROR = '데이터베이스 혹은 테이블 이름 유효성 검사에 실패했습니다.'
        self.COLUMN_NAME_OR_TYPE_ERROR = 'Column 정보가 유효하지 않습니다. Column 이름과 타입을 확인해주세요.'
        self.TABLE_CREATE_SUCCESS = '테이블 생성에 성공했습니다.'
        self.TABLE_DELETE_SUCCESS = '테이블 삭제에 성공했습니다.'
        self.TABLE_CREATE_FAIL = '테이블 생성에 실패했습니다.'
        self.TABLE_DELETE_FAIL = '테이블 삭제에 실패했습니다.'
        self.TABLE_ALREADY_EXISTS = '테이블이 이미 존재합니다.'
        self.TABLE_DOESNT_EXISTS = '테이블이 존재하지 않습니다.'
        self.TABLE_MODIFY_SUCCESS = '테이블 수정에 성공했습니다.'
        self.TABLE_MODIFY_FAIL = '테이블 수정에 실패했습니다.'
        self.MODIFY_TYPE_ERROR = '테이블 수정을 위한 명령어가 유효하지 않습니다. 가능한 명령어: ADD, DROP, RENAME, CLEAR, COMMENT, MODIFY'


        """
        :param database_name: 데이터베이스의 이름, 유효성 검사를 통과해야 한다.
        :param table_name: 테이블의 이름, 유효성 검사를 통과해야 한다.
        :return:
        """
        self.mode = mode
        self.index = index
        self.model_config = model_config
        
        self._client = check_cs(config['cs'])
        try:
            self._client.execute(self.CONNECTION_TEST_SQL)
        except SocketTimeoutError as ste:
            print(self.DB_CONNECTION_FAIL)
            return
    
    
    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
    def regex_check_eng_num_u(self, string):
        """
        영어나 숫자, _(underbar)로만 이루어진 표현인지 검증하기 위한 메소드
        :param string: 검증 대상 문자열
        :return: 검증 결과(Boolean)
        """
        regex_eng_num_u = re.compile(r'[a-zA-Z0-9_]')
        if regex_eng_num_u.match(string):
            return True
        return False

    def column_name_check(self, columns):
        """
        Table 생성할 때 Column 이름이나 Type 에 대한 유효성 검사를 위한 메소드
        :param columns: 튜플이나 리스트 형태의 데이터로 (Column 이름, Type) 쌍의 데이터의 모음
        :return: 유효성 검사 결과(Boolean)
        """
        for c in columns:
            if not self.regex_check_eng_num_u(c[0]):
                return False
            if c[1] not in self.CLICK_HOUSE_TYPES and c[1].split('(')[0] not in self.CLICK_HOUSE_WRAPPED_TYPES:
                return False
        return True

    def check_table_exist(self, table_name, c_names=None, c_types=None):
        """
        테이블이 존재하는지 검사
        :return: 테이블 존재 여부(Boolean)
        """
        try:
            sql = self.TABLE_CHECK_SQL % table_name
            data, meta = self._client.execute(sql, with_column_types=True)
            if c_names is not None and c_types is not None:
                col_names = [i[0] for i in meta]
                col_types = [i[1] for i in meta]
                if (sorted(col_names) != sorted(c_names)) or (sorted(col_types) != sorted(c_types)):
                    return False
        except ServerException as se:
            return False
        return True

    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
    def create_table(self, idx_data=None, cols=None, database_name=None, table_n=None, engine='MergeTree', partition='tuple()', order='tuple()'):
        """
        테이블이 존재하지 않을 경우 테이블을 생성한다.
        :param columns: 테이블의 Column 목록, 유효성 검사를 통과해야 한다.
        :param engine: Click House 의 테이블에 사용할 엔진을 지정한다. Def: MergeTree
        :param partition: 파티션의 기준을 지정한다. Def: tuple()
        :param order: 테이블의 정렬 순서를 지정한다. Def: tuple()
        :return: 테이블 생성 결과(Boolean)
        """
        if not self.regex_check_eng_num_u(database_name) or not self.regex_check_eng_num_u(table_n):
            print(self.NAME_ERROR)
            return
        table_name = database_name + '.' + table_n
        columns = []
        for col in cols:
            if col == 'lgtime':
                columns.append(('lgtime', 'DateTime'))
            elif col == 'logtime':
                columns.append(('logtime', 'DateTime'))
            elif col == 'src_ip':
                columns.append(('src_ip', 'String'))
            elif col == 'dst_ip':
                columns.append(('dst_ip', 'String'))
            elif col == 'version':
                columns.append(('version', 'String'))
            elif col == 'model_version':
                columns.append(('model_version', 'String'))
            elif col == 'index':
                columns.append(('index', 'Int64'))
            elif col == 'label':
                columns.append(('label', 'String'))
            elif col == 'ai_label':
                columns.append(('ai_label', 'String'))
            elif col == 'esoinn_label':
                columns.append(('esoinn_label', 'String'))
            elif col == 'model_id':
                columns.append(('model_id', 'Int64'))
            elif col == 'feature':
                columns.append(('feature', 'Array(String)'))
            elif col == 'score':
                columns.append(('score', 'Array(Float64)'))
            elif col == 'columns':
                columns.append(('columns', 'String'))
            elif col == 'model_type':
                columns.append(('model_type', 'String'))
            elif col == 'attack_type':
                columns.append(('attack_type', 'String'))
            elif col == 'train_start_time':
                columns.append(('train_start_time', 'DateTime'))
            elif col == 'epoch':
                columns.append(('epoch', 'Int64'))
            elif col == 'loss':
                columns.append(('loss', 'Float64'))
            elif col == 'data_shape':
                columns.append(('data_shape', 'String'))
            elif col == 'train_end_time':
                columns.append(('train_end_time', 'DateTime'))
            elif col == 'model_name':
                columns.append(('model_name', 'String'))

        if idx_data == None:
            pass
        else:
            for idx in idx_data:
                try:
                    cols.remove(idx)
                except:
                    pass
        # if self.mode=='train':
            # cols = cols[:-1]
        if table_name.find('collect_number') > 0:
            for col in cols:
                columns.append((col, 'Int64'))
        elif table_name.find('prep_number') > 0:
            for col in cols:
                columns.append((col, 'Float64'))
        elif table_name.find('collect_string') > 0:
            for col in cols:
                columns.append((col, 'String'))
        elif table_name.find('prep_string') > 0:
            for col in cols:
                columns.append((col, 'Float64'))
        elif table_name.find('collect_category') > 0:
            for col in cols:
                columns.append((col, 'String'))
        elif table_name.find('prep_category') > 0:
            for col in cols:
                columns.append((col, 'Float64'))
        elif table_name.find('pred_prep') > 0:
            for col in cols:
                columns.append((col, 'Float64'))
        elif table_name.find('pred_esoinn_result') > 0:
            for col in cols:
                columns.append((col, 'Float64'))
        print(columns)
        return [c[0] for c in columns]

    
    
    
    def delete_table(self, table_name):
        """
        테이블이 존재하는 경우 테이블을 삭제한다.
        :return: 테이블 삭제 결과(Boolean)
        """
        if not self.check_table_exist(table_name):
            print(self.TABLE_DOESNT_EXISTS)
        print('테이블이 삭제됩니다. 정말 삭제하시려면 테이블 이름을 입력하세요. (데이터베이스명 포함)')
        # name = input()
        # if name != self.table_name:
        #     print('잘못 입력하셨습니다. 삭제가 취소됩니다.')
        #     return
        try:
            sql = self.DROP_TABLE_SQL % table_name
            self._client.execute(sql)
            print(self.TABLE_DELETE_SUCCESS)
            return True
        except ServerException as se:
            print(se.message)
            print(self.TABLE_DELETE_FAIL)
            return False



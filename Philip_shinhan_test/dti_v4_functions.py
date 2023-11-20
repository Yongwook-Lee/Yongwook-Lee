import logging
from time import sleep
import time
from datetime import datetime as dt
from datetime import timedelta
from airflow import DAG, settings
from airflow.operators.python import PythonOperator, get_current_context
from airflow.operators.subdag import SubDagOperator
from airflow.operators.dummy import DummyOperator
import pandas as pd
# from airflow.hooks.postgres_hook import PostgresHook
import os
import platform
from sklearn.metrics import *
# from gensim.models.doc2vec import Doc2Vec, TaggedDocument
from sklearn import svm 
import ipaddress
from Philip_shinhan_test.dti_v4_utils import *  # 수정
from Philip_shinhan_test.dti_v4_query import *  # 수정
from Philip_shinhan_test.dti_v4_prep import *  # 수정
from Philip_shinhan_test.dti_v4_esoinn_xai import *  # 수정
from Philip_shinhan_test.dti_v4_data import DataCreation  # 수정

pwd = os.path.dirname(os.path.realpath(__file__))
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
def is_blocked_ip(ip_str, blocked_clsA_dict):
    clsA = ip_str.split(".")[0]
    if clsA not in blocked_clsA_dict:
        return 0
    for blocked_cidr in blocked_clsA_dict[clsA]:
        if ipaddress.IPv4Address(ip_str) in blocked_cidr:
#             log.info(str(blocked_cidr))
            return 1
    return 0



#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
def check_predict_by_blocked_ip(config, model_config, **kwargs):
    today = kwargs['dag_run'].execution_date.replace(microsecond=0).replace(second=0) + timedelta(hours=9)
    yesterday = today - timedelta(hours=24)
    t_day = today.strftime('%Y-%m-%d 00:00:00')
    y_day = yesterday.strftime('%Y-%m-%d 00:00:00')
    log.info(f'check_predict_by_blocked_ip from {y_day} to {t_day}')
    
    attack_result_sql = """select index, lgtime, src_ip, dst_ip, ai_label
                    from {db_name}.{table} 
                    where ai_label != 'normal'
                    and (lgtime >= '{start_date}' and lgtime < '{end_date}')
    """.format(db_name=model_config['db_name'], table=model_config['result_01_table'], start_date=y_day, end_date=t_day)
    log.info('sql : {}'.format(attack_result_sql))
    
    blocked_ip_df = pd.read_csv(pwd + model_config['blocked_ip'])
    
    blocked_clsA_dict = {}
    for idx, row in blocked_ip_df.iterrows():
        cidr_ip = str(row['network'])
        clsA = cidr_ip.split(".")[0]
        if clsA in blocked_clsA_dict:
            blocked_clsA_dict[clsA] += [ipaddress.IPv4Network(cidr_ip)]
        else:
            blocked_clsA_dict.update({clsA: [ipaddress.IPv4Network(cidr_ip)]})
    
    try:
        attack_result = execute_ch(attack_result_sql, config, with_column_types=True)
    except Exception as err:
        log.error('[ERROR] check_predict_by_blocked_ip\n{}\nsql : {}'.format(err, attack_result_sql))
        return
    attack_df = pd.DataFrame(attack_result[0], columns=[i[0] for i in attack_result[1]])
    
    ins_list = []
    for idx, row in attack_df.iterrows():
        src_ip = row['src_ip']
        dst_ip = row['dst_ip']
        tmp_dcit = {'index': row['index'], 'lgtime': row['lgtime'], 'src_ip': src_ip, 'dst_ip': dst_ip}

        tmp_dcit.update({'src_ip_flag': is_blocked_ip(src_ip, blocked_clsA_dict)})
        tmp_dcit.update({'dst_ip_flag': is_blocked_ip(dst_ip, blocked_clsA_dict)})
        tmp_dcit.update({'ai_label': row['ai_label']})
        ins_list.append(tmp_dcit)
    
    log.info('len(ins_list) : {} \nins_list[:10] :::::::::::::::::::::::\n{}'.format(len(ins_list), ins_list[:10]))
    try:
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['check_pred_table']), config, ins_list)
        log.info('check_predict_by_blocked_ip insert success')
    except Exception as err:
        log.error('check_predict_by_blocked_ip insert FAIL : {}'.format(err))


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#         
def make_report_file(config, model_config, **kwargs):
    today = kwargs['dag_run'].execution_date.replace(microsecond=0).replace(second=0) + timedelta(hours=9)
    # # airflow 스케쥴링이 밀림
    tmorrow = today + timedelta(hours=24)
    y_day = today.strftime('%Y-%m-%d 00:00:00')
    t_day = tmorrow.strftime('%Y-%m-%d 00:00:00')
    
    log.info(f'make_report_file from {y_day} to {t_day}')
    


    # 20230515 신한 협업 요청 : 탐지결과와 해당 이벤트 raw data mapping한 것 다시 data aggregation(group by time_group, src_ip, dst_ip)해서 dit 웹과 결과 같게 하기 
    # 2023-05-25 수정 : join 방식 수정
    # 수정
    supervised_sql = f"""select ai_label, time_group
    , arrayStringConcat(groupUniqArray(toString(logtime_kr)), ' ') as logtime_kr
    , src_ip
    , arrayStringConcat(groupUniqArray(toString(src_port)), ' ') as src_port
    , dst_ip
    , arrayStringConcat(groupUniqArray(toString(dst_port)), ' ') as dst_port
    , arrayStringConcat(groupUniqArray(http_method), ' ') as http_method
    , arrayStringConcat(groupUniqArray(http_host), ' ') as http_host
    , arrayStringConcat(groupUniqArray(http_agent), ' ') as http_agent
    , arrayStringConcat(groupUniqArray(http_path), ' ') as http_path
    , arrayStringConcat(groupUniqArray(http_query), ' ') as http_query
    , arrayStringConcat(groupUniqArray(http_tenc), ' ') as http_tenc
    , arrayStringConcat(groupUniqArray(http_retcode), ' ') as http_retcode
    , arrayStringConcat(groupUniqArray( arrayJoin(keyword)), ' ') as keyword

    from (select ai_label, lgtime as time_group, logtime_kr, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_tenc, http_retcode, groupUniqArray(features) as keyword
    from(select *, position(str_prep, features) as pos
    from(
        with toStartOfInterval(addHours(logtime, 9), INTERVAL 30 MINUTE) as lgtime,
            concat(toString(lgtime),', ', src_ip,', ', dst_ip) as map
        select map, lgtime, logtime_kr, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_tenc, http_retcode, replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), '[\-%./!@#$?,;:&*)(+=0-9]', ' ') as str_prep
        from default.dti_qm_httpd
        WHERE lgtime >= '{y_day}' and lgtime < '{t_day}'
        )
    inner join
        (
        with concat(toString(lgtime),', ', src_ip,', ', dst_ip) as map
        select map, lgtime, ai_label, src_ip, dst_ip, result[1] as features
        from(
            select lgtime, ai_label, src_ip, dst_ip, arrayJoin(res) as result
            from(
                select lgtime, ai_label, src_ip, dst_ip, arrayMap((x, y) -> [x, toString(y)], feature, score) as res
                from dti.TEST3005_svm_xai_resultd
                where ai_label != 'normal' and lgtime >= '{y_day}' and lgtime < '{t_day}'
                )
            where result[2] != '0'
            )
    ) using map
    where features != '' and pos != 0)
    group by ai_label, time_group, logtime_kr, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_tenc, http_retcode
    order by logtime_kr, src_ip, dst_ip) res

    group by ai_label, time_group, src_ip, dst_ip"""
    
    try:
        attack_result = execute_ch(supervised_sql, config, with_column_types=True)
    except Exception as err:
        log.error('[ERROR] make_report_file\n{}\nsupervised_sql : {}'.format(err, supervised_sql))
        return
    attack_df = pd.DataFrame(attack_result[0], columns=[i[0] for i in attack_result[1]])
    

    
    # # 20230515 신한 협업 요청 : 탐지결과와 해당 이벤트 raw data mapping한 것 다시 data aggregation(group by time_group, src_ip, dst_ip)해서 dit 웹과 결과 같게 하기 
    # 2023-05-25 수정 : join 방식 수정, keyword 내용 일부 수정
    # 수정
    anomaly_sql = f"""select ai_label, time_group
    , arrayStringConcat(groupUniqArray(toString(logtime_kr)), ' ') as logtime_kr
    , src_ip
    , arrayStringConcat(groupUniqArray(toString(src_port)), ' ') as src_port
    , dst_ip
    , arrayStringConcat(groupUniqArray(toString(dst_port)), ' ') as dst_port
    , arrayStringConcat(groupUniqArray(http_method), ' ') as http_method
    , arrayStringConcat(groupUniqArray(http_host), ' ') as http_host
    , arrayStringConcat(groupUniqArray(http_agent), ' ') as http_agent
    , arrayStringConcat(groupUniqArray(http_path), ' ') as http_path
    , arrayStringConcat(groupUniqArray(http_query), ' ') as http_query
    , arrayStringConcat(groupUniqArray(http_tenc), ' ') as http_tenc
    , arrayStringConcat(groupUniqArray(http_retcode), ' ') as http_retcode
    , arrayStringConcat(groupUniqArray( arrayJoin(keyword)), ' ') as keyword

from (select ai_label, lgtime as time_group, logtime_kr, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_tenc, http_retcode, groupUniqArray(features) as keyword
from(select *, position(str_prep, features) as pos
from(
    with toStartOfInterval(addHours(logtime, 9), INTERVAL 30 MINUTE) as lgtime,
        concat(toString(lgtime),', ', src_ip,', ', dst_ip) as map
    select map, lgtime, logtime_kr, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_tenc, http_retcode, replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), '[\-%./!@#$?,;:&*)(+=0-9]', ' ') as str_prep
    from default.dti_qm_httpd
    WHERE lgtime >= '{y_day}' and lgtime < '{t_day}'
    )
inner join
    (
    with concat(toString(lgtime),', ', src_ip,', ', dst_ip) as map
    select map, lgtime, ai_label, src_ip, dst_ip, result[1] as features
    from(
        select lgtime, ai_label, src_ip, dst_ip, arrayJoin(res) as result
        from(
            select lgtime, ai_label, src_ip, dst_ip, arrayMap((x, y) -> [x, toString(y)], feature, score) as res
            from dti.TEST3005_esoinn_xai_resultd
            where ai_label != 'normal' and  lgtime >= '{y_day}' and lgtime < '{t_day}'
            )
        where result[2] != '0'
        )
) using map
where features != '' and pos != 0)
group by ai_label, time_group, logtime_kr, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_tenc, http_retcode
order by logtime_kr, src_ip, dst_ip) res
group by ai_label, time_group, src_ip, dst_ip
;;"""
    
    try:
        anomaly_result = execute_ch(anomaly_sql, config, with_column_types=True)
    except Exception as err:
        log.error('[ERROR] make_report_file\n{}\nanomaly_sql : {}'.format(err, anomaly_sql))
        return
    anomaly_df = pd.DataFrame(anomaly_result[0], columns=[i[0] for i in anomaly_result[1]])
    
    # 2023-05-25 추가
    total_df = pd.concat([attack_df, anomaly_df])
    final_df = total_df.reset_index(drop=True)
    final_df['keyword']  = final_df['keyword'].apply(lambda x : tuple(x.split(' ')))
    
    

    
    try:
        ins_attack_res = execute_ch('insert into {} values'.format(
            model_config['db_name'] + '.'+ model_config['report_table']), config, final_df.values.tolist()) # 수정
        log.info(f'{ins_attack_res} data inserted')
    except Exception as err:
        log.error('[ERROR] make_report_file\n{}'.format(err))
    

def valid(mode, config, model_config):
    log.info("{} {} {}".format("*" * 30, "예측 데이터 불러오기", "*" * 30))
    merg_list = ['logtime', 'src_ip', 'dst_ip']
    data_version = model_config['val_data_version']
    pred_data = None
    try:
        f = open(pwd + "/obj/sampling_data/predc_df.pickle", "rb")
        pred_data = pickle.load(f)
        f.close()
    except Exception as err:
        log.error("[pred_data_load ERROR] {}".format(err))

    log.info(pred_data.info())
    log.info(pred_data.head())
    pred_data.reset_index(drop=False, inplace=True)
    pred_data = pred_data.drop(['lgtime'], axis=1)
    log.info(pred_data.info())
    log.info(pred_data.head())
    log.info(pred_data['agnt_qry'].head())
    
    esoinn_sql = """
    select index, logtime, src_ip, dst_ip, ai_label as esoinn_label
    from {}
    where version = '{}'
    """.format(model_config['db_name'] + '.' + model_config['result_01_table'], data_version)

    
    try:
        result, meta = execute_ch(esoinn_sql, config, with_column_types=True)
    except Exception as err:
        log.error('[ERROR] {}\nsql : {}'.format(err, esoinn_sql))
        
    esoinn_res_df = pd.DataFrame(result, columns=[m[0] for m in meta])
    esoinn_res_df['logtime'] = pd.to_datetime(esoinn_res_df['logtime'], format='%Y-%m-%d %H:%M:%S', utc=True)
    log.info("esoinn_res_df.info() \n{}".format(esoinn_res_df.info()))
    log.info("esoinn_res_df.head() \n{}".format(esoinn_res_df.head()))
    log.info(esoinn_res_df.shape)
    
    pred_data = pred_data.join(esoinn_res_df.set_index(['index'] + merg_list), on=['index'] + merg_list)
    
    log.info("pred_data.info() \n{}".format(pred_data.info()))
    log.info("pred_data.head() \n{}".format(pred_data.head()))
    log.info(pred_data.shape)
    keys, counts = np.unique(pred_data.esoinn_label, return_counts=True)
    log.info("first_ai_label keys : {}\ncnts : {}".format(keys, counts))
    
    cnn_sql = """
    select index, logtime, src_ip, dst_ip, ai_label
    from {}
    where version = '{}'
    """.format(model_config['db_name'] + '.' + model_config['esoinn_result_table'], data_version)
    log.info('second_sql  :::::::::::::::::::::\n{}'.format(cnn_sql))

    
    try:
        result, meta = execute_ch(cnn_sql, config, with_column_types=True)
    except Exception as err:
        log.error('[ERROR] {}\nsql : {}'.format(err, cnn_sql))
        
    cnn_res_df = pd.DataFrame(result, columns=[m[0] for m in meta])
#     with open(pwd + "/obj/sampling_data/cnn_res_df.pickle", "wb") as f:
#         pickle.dump(cnn_res_df, f)
    
    log.info("cnn_res_df.info() \n{}".format(cnn_res_df.info()))
    cnn_res_df['logtime'] = pd.to_datetime(cnn_res_df['logtime'], format='%Y-%m-%d %H:%M:%S', utc=True)
    log.info("cnn_res_df.info() \n{}".format(cnn_res_df.info()))
    log.info("cnn_res_df.head() \n{}".format(cnn_res_df.head()))
    log.info("cnn_res_df.shape : {}".format(cnn_res_df.shape))

    keys, counts = np.unique(cnn_res_df.ai_label, return_counts=True)
    log.info("ai_label in cnn_res_df keys : {}\ncnts : {}".format(keys, counts))
    
    pred_data = pred_data.join(cnn_res_df.set_index(['index'] + merg_list), on=['index'] + merg_list)
#     pred_data = pred_data.join(cnn_res_df.set_index(['index'] + merg_list + ['esoinn_label']), on=['index'] + merg_list + ['esoinn_label'])
    
    pred_data.ai_label.fillna(pred_data.esoinn_label, inplace=True)
    
    keys, counts = np.unique(pred_data.ai_label, return_counts=True)
    cluster_uniq = "keys : {}, cnts : {}".format(keys, counts)
    log.info("keys : {}\ncnts : {}".format(keys, counts))
    
    log.info(pred_data.info())
    log.info(pred_data.head())
    log.info("\n\n:::::::::::::::::::::::::::::::::::::::::::::::::::\ndata_version : {}".format(data_version))
    log.info("\nTOTAL accuracy_score :::::::: \n{}".format(accuracy_score(pred_data.label, pred_data.ai_label)))
    label_list = model_config['attack_array'].split(", ") + ['anomaly', 'normal']
    log.info("\nTOTAL confusion_matrix : \n{}\n{}".format(label_list, confusion_matrix(pred_data.label, pred_data.ai_label, labels=label_list)))
    
    pred_data['esoinn_label'] = pred_data['esoinn_label'].astype('str')
    log.info("\nfirst_ai_label accuracy_score :::::::: \n{}".format(accuracy_score(pred_data.label, pred_data.esoinn_label)))
    log.info("\nfirst_ai confusion_matrix : \n{}\n{}".format(label_list, confusion_matrix(pred_data.label, pred_data.esoinn_label, labels=label_list)))
    
    normal_attc_df = pred_data.copy()
    normal_attc_df.loc[normal_attc_df["label"] != "normal", "label"] = "attack"
    normal_attc_df.loc[normal_attc_df["esoinn_label"] != "normal", "esoinn_label"] = "attack"
    log.info("\nnormal_attc_df accuracy_score :::::::: \n{}".format(accuracy_score(normal_attc_df.label, normal_attc_df.esoinn_label)))
    log.info("\nnormal_attc_df confusion_matrix : \n{}\n{}".format(['attack', 'normal'], confusion_matrix(normal_attc_df.label, normal_attc_df.esoinn_label, labels=['attack', 'normal'])))
    
def mk_result_table(config, **kwargs):
    version = (kwargs['dag_run'].execution_date.replace(microsecond=0).replace(second=0) + timedelta(hours=9)).strftime("%Y%m%d%H%M%S")
#     print("test {}".format(version))
    ch = config['cs'][2]
    sql = mk_result_table_query(version)
    try:
        client = Client(ch['host'], port=ch['port'], send_receive_timeout=int(ch['timeout']), settings={'max_threads': int(ch['thread'])})
        client.connection.force_connect()
        log.info("##### client connected in {} #####\n".format(ch['host']))    
        log.info("sql for mk_result_table ::::::::::::::::::::::\n{}".format(sql))    
        result = client.execute(sql, params=None, with_column_types=True)
        log.info('{} ########### insert predict result data ##############'.format(result))
    except Exception as err:
        log.error("##### ERROR in calling CH client \n{}".format(err))
        log.info("##########")     
    finally : 
        client.disconnect()    

        
        
        
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#        
def get_data(mode, config, model_config, **kwargs):
    # [oliver] 2023.02.06 UTC+9 적용
#     version = (dt.now() + timedelta(hours=9)).strftime("%Y%m%d%H%M%S")
    version = kwargs['dag_run'].execution_date.replace(microsecond=0).replace(second=0) + timedelta(hours=9) + timedelta(minutes=30)## airflow 30분 밀림
    
    log.info("version {}, type : {}".format(version, type(version)))
    log.info("여기부터 시작 1")
    if mode == 'train' or mode == 'data_sampling':
        log.info("학습으로 들어옴 2")
        result = DataCreation(mode, config, model_config, version)
    else:
        log.info("학습 아닌것으로 들어옴 2")
        model_version = model_config['model_version']
        result = DataCreation(mode, config, model_config, version, model_version=model_version)

    str_cols = result.str_cols

    return {'version': version.strftime("%Y%m%d%H%M%S"), 'str_cols': str_cols}


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def int_preprocessing(mode, config, model_config, m_type=None, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']

    if m_type == 'cnn':
        log.info("model_config['cnn_idx_cols'] : {}".format(model_config['cnn_idx_cols']))
        t_name = model_config['db_name'] + '.' + 'cnn_' + model_config['table_number']
        idx_cols_list = ['index'] + model_config['cnn_idx_cols'].split(', ') + ['version']
        model_config['prep_table_number'] = 'cnn_' + model_config['prep_table_number']
    else:
        t_name = model_config['db_name'] + '.' + model_config['table_number']
        idx_cols_list = ['index'] + model_config['idx_cols'].split(', ') + ['version']

    log.info('VERSION {}'.format(version))

    int_data, int_meta = execute_ch(get_data_collection_info_query(table_name=t_name + ' limit 1'), config, param=None,
                                    with_column_types=True)
    cols = [m[0] for m in int_meta]
    cols = ", ".join(cols)
    log.info('cols : {}'.format(cols))
    sql = get_data_collection_column_query(table_name=t_name, columns=cols, version=version)
    log.info('SQL : {}'.format(sql))
    int_data, int_meta = execute_ch(sql, config, param=None, with_column_types=True)
    int_df = pd.DataFrame(data=int_data, columns=[m[0] for m in int_meta])
    log.info(int_df.info())
    columns = list(int_df)

    if mode == 'train':
        idx_cols_list = idx_cols_list + ['label']
    else:
        if m_type == 'cnn':
            idx_cols_list = idx_cols_list + ['esoinn_label']

    for col in idx_cols_list:
        log.info("columns.remove(col) : {}".format(col))
        columns.remove(col)
    log.info("columns : {}".format(columns))
    split_int_df = int_df[columns]
    log.info("split int df info :::::::::::::\n{}".format(split_int_df.info()))
    intPrep = IntProcessing()

    if mode == 'train' and (m_type == 'cnn' or model_config['esoinn_version'] == ""):  # # CNN의 학습/재학습 이거나 Esoinn이 최초 학습인 경우
        intPrep.save_scaling_model(split_int_df, version, how='MinMaxScaler', m_type=m_type)
        intPrep_df = intPrep.trnsfm_scal_data(split_int_df, version, m_type=m_type)
    elif m_type is None:  # # Esoinn TRANSFER_LEARNING 이거나 Esoinn 예측인 경우
        model_version = model_config['feat_version']
        log.info("ESOINN Model version : {model_version}".format(model_version=model_version))
        intPrep_df = intPrep.trnsfm_scal_data(split_int_df, model_version, m_type=m_type)
    else:
        model_version = model_config['model_version']
        log.info("CNN Model version : {model_version}".format(model_version=model_version))
        intPrep_df = intPrep.trnsfm_scal_data(split_int_df, model_version, m_type=m_type)

    int_df[columns] = intPrep_df
    log.info(int_df.info())

    dbcheck = DBCheck(mode='train', config=config, model_config=model_config)
    log.info("config_cols & df_cols {}, {}".format(idx_cols_list, list(int_df)))

    dbcheck.create_table(idx_data=idx_cols_list, cols=list(int_df), database_name=model_config['db_name'], table_n=model_config['prep_table_number'])

    ## Data version overlap check
    chk_sql = get_data_collection_column_query(
        table_name=model_config['db_name'] + '.' + model_config['prep_table_number'], columns='version',
        version=version)
    chk_data, chk_meta = execute_ch(chk_sql, config, param=None, with_column_types=True)
    chk_df = pd.DataFrame(data=chk_data, columns=[m[0] for m in chk_meta])

    if len(chk_df['version']) > 0:
        if version in chk_df['version'].to_list():
            pass
        else:
            execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['prep_table_number']),
                       config, int_df.to_dict('records'))
    else:
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['prep_table_number']), config,
                   int_df.to_dict('records'))


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def cat_preprocessing(mode, config, model_config, m_type=None, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    if m_type == 'cnn':
        t_name = model_config['db_name'] + '.' + 'cnn_' + model_config['table_category']
        idx_cols_list = ['index'] + model_config['cnn_idx_cols'].split(', ') + ['version']
        model_config['prep_table_category'] = 'cnn_' + model_config['prep_table_category']
    else:
        t_name = model_config['db_name'] + '.' + model_config['table_category']
        idx_cols_list = ['index'] + model_config['idx_cols'].split(', ') + ['version']

    log.info('VERSION {}'.format(version))

    cat_data, cat_meta = execute_ch(get_data_collection_info_query(table_name=t_name + ' limit 1'), config, param=None,
                                    with_column_types=True)
    cols = [m[0] for m in cat_meta]
    cols = ", ".join(cols)
    log.info('cols : {}'.format(cols))
    sql = get_data_collection_column_query(table_name=t_name, columns=cols, version=version)
    log.info('SQL : {}'.format(sql))

    cat_data, cat_meta = execute_ch(sql, config, param=None, with_column_types=True)
    cat_df = pd.DataFrame(data=cat_data, columns=[m[0] for m in cat_meta])
    log.info(cat_df.info())
    columns = list(cat_df)

    if mode == 'train':
        idx_cols_list = idx_cols_list + ['label']
    else:
        if m_type == 'cnn':
            idx_cols_list = idx_cols_list + ['esoinn_label']

    for col in idx_cols_list:
        columns.remove(col)
    split_cat_df = cat_df[columns]

    catPrep = CatProcessing()

    if mode == 'train' and (m_type == 'cnn' or model_config['esoinn_version'] == ""):  # # CNN의 학습/재학습 이거나 Esoinn이 최초 학습인 경우
        catPrep.save_one_hot_enc_model(split_cat_df, version, m_type=m_type)
        catPrep_df = catPrep.trnsfm_one_hot_enc_data(split_cat_df, version, m_type=m_type)
    elif m_type is None:  # # Esoinn TRANSFER_LEARNING 이거나 Esoinn 예측인 경우
        model_version = model_config['feat_version']
        log.info("ESOINN Model version : {model_version}".format(model_version=model_version))
        catPrep_df = catPrep.trnsfm_one_hot_enc_data(split_cat_df, model_version, m_type=m_type)
    else:
        model_version = model_config['model_version']
        log.info("CNN Model version : {model_version}".format(model_version=model_version))
        catPrep_df = catPrep.trnsfm_one_hot_enc_data(split_cat_df, model_version, m_type=m_type)

    completion_cat_df = pd.concat([cat_df[idx_cols_list], catPrep_df], axis=1)

    log.info(completion_cat_df.info())
    log.info(completion_cat_df)

    dbcheck = DBCheck(mode='train', config=config, model_config=model_config)
    log.info("config_cols & df_cols {}, {}".format(idx_cols_list, list(completion_cat_df)))

    dbcheck.create_table(idx_data=idx_cols_list, cols=list(completion_cat_df), database_name=model_config['db_name'], table_n=model_config['prep_table_category'])

    ## Data version overlap check
    chk_sql = get_data_collection_column_query(
        table_name=model_config['db_name'] + '.' + model_config['prep_table_category'], columns='version',
        version=version)
    chk_data, chk_meta = execute_ch(chk_sql, config, param=None, with_column_types=True)
    chk_df = pd.DataFrame(data=chk_data, columns=[m[0] for m in chk_meta])

    if len(chk_df['version']) > 0:
        if version in chk_df['version'].to_list():
            pass
        else:
            execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['prep_table_category']),
                       config, completion_cat_df.to_dict('records'))
    else:
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['prep_table_category']), config,
                   completion_cat_df.to_dict('records'))


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def str_preprocessing_t_no_sparse_mat(mode, config, model_config, column, m_type=None, **kwargs):
    tot_runtime = time.time()
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    log.info("version : {}, column  : {}".format(version, column))
    if m_type == 'cnn':
        t_name = model_config['db_name'] + '.' + 'cnn_' + model_config['table_string']
        cols = model_config['cnn_idx_cols'] + ', ' + str(column) + ', version, index'
        idx_cols_list = ['index'] + model_config['cnn_idx_cols'].split(', ') + ['version']
        model_config['prep_table_string'] = 'cnn_' + model_config['prep_table_string']
    else:
        t_name = model_config['db_name'] + '.' + model_config['table_string']
        cols = model_config['idx_cols'] + ', ' + str(column) + ', version, index'
        idx_cols_list = ['index'] + model_config['idx_cols'].split(', ') + ['version']

    if mode == 'train':
        cols = cols + ', label'
    else:
        if m_type == 'cnn':
            cols = cols + ', esoinn_label'
    #version ='20230727010000'
    sql = get_data_collection_column_query(table_name=t_name, columns=cols, version=version)
    str_data, str_meta = execute_ch(sql, config, param=None, with_column_types=True)
    str_df = pd.DataFrame(data=str_data, columns=[m[0] for m in str_meta])
    log.info(str_df.info())

    columns = list(str_df)

    if mode == 'train':
        idx_cols_list = idx_cols_list + ['label']
    else:
        if m_type == 'cnn':
            idx_cols_list = idx_cols_list + ['esoinn_label']

    for col in idx_cols_list:
        columns.remove(col)
    
    try:
        f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
        black_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close
    
    try:
        f = open(pwd + '/detect/' + model_config['whte_f_nm'], 'r')
        white_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close
    
    new_line = [i.strip().lower() for i in black_key_line] + [i.strip().lower() for i in white_key_line]
    log.info("len(new_line) {} \n{}".format(len(new_line), new_line))
    
    log.info('STEP 1 tf-idf')
    custom_voca = CustomTfidfVectorizer(max_features=len(new_line), vocabulary=new_line)
    log.info("columns : {}".format(columns))
    log.info("column : {}".format(column))
    
    log.info("len(columns) : {}, columns".format(len(columns), columns))
    if mode == 'train' and (m_type == 'cnn' or model_config['esoinn_version'] == ""):  # # 지도학습의 학습/재학습 이거나 Esoinn이 최초 학습인 경우
        # # binary hex to string
        StrProcessing().make_hex_to_string(str_df, column)
        custom_voca.fit(str_df[column].values, feature_list=columns, save_version=version, m_type=m_type)
        strPrepData = custom_voca.transform(str_df[column].values, feature_list=columns, save_version=version, mode=mode, m_type=m_type)
    elif m_type is None:  # # Esoinn TRANSFER_LEARNING 이거나 Esoinn 예측인 경우
        model_version = model_config['feat_version']
        log.info("ESOINN Model version : {model_version}".format(model_version=model_version))
        # # binary hex to string
        StrProcessing().make_hex_to_string(str_df, column)
        # [Oliver] TF-IDF 전처리 작업 시간 체크
        __start_time = time.time()
        strPrepData = custom_voca.transform(str_df[column].values, feature_list=columns, save_version=model_version,
                                            mode=mode, m_type=m_type)
        log.info(f'-------------------- tf-idf runtime is {round(time.time() - __start_time, 4)} seconds. --------------------')
    else:
        model_version = model_config['model_version']
        log.info("SUPERVISED Model version : {model_version}".format(model_version=model_version))
        # # binary hex to string
        StrProcessing().make_hex_to_string(str_df, column)
        strPrepData = custom_voca.transform(str_df[column].values, feature_list=columns, save_version=model_version, mode=mode, m_type=m_type)

    for col in list(strPrepData):
        strPrepData[col] = strPrepData[col].astype('float')

    log.info('STEP 2 add version')
    log.info('STEP 2 merge insert_data')
    log.info("idx_cols_list {} ".format(idx_cols_list))
    key_df = str_df[idx_cols_list]

    # [Oliver] Original Code
#     __start_time = time.time()
    if m_type == None:
        val_cols = pd.Series([[feat.replace(column + "_", "") for feat in list(strPrepData)] for _ in strPrepData.values], name='feature')
    else:
        val_cols = pd.Series([list(strPrepData) for _ in strPrepData.values], name='feature')
    
    key_df = key_df.merge(val_cols, left_index=True, right_index=True)
    values = pd.Series([vals for vals in strPrepData.values], name='score')
    key_df = key_df.merge(values, left_index=True, right_index=True)
    log.info("list(key_df) {} ".format(list(key_df)))
    log.info("key_df.shape: {}".format(key_df.shape))
    log.info("key_df.tail(n=5): {}".format(key_df.tail(n=5)))
    

    log.info('STEP 3 create DB if it needs')
    db_check = DBCheck(mode, config, model_config)
    idx_cols_list.append('feature')
    idx_cols_list.append('score')
    col_order = db_check.create_table(idx_data=idx_cols_list, cols=list(key_df), database_name=model_config['db_name'], table_n=model_config['prep_table_string'] + '__' + column)
    log.info('STEP 4 check version overlap')

    ## Data version overlap check
    chk_sql = get_data_collection_column_query(
        table_name=model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + column, columns='*',
        version=version)
    chk_data, chk_meta = execute_ch(chk_sql, config, param=None, with_column_types=True)
    chk_df = pd.DataFrame(data=chk_data, columns=[m[0] for m in chk_meta])
    log.info('CHECK 5 insert data')
    len_key_df = len(key_df)
    batch_size = 350000  # # max num of insert data
    temp_batch = 0
    if len_key_df % batch_size == 0:
        batch_count = len_key_df // batch_size
    else:
        batch_count = len_key_df // batch_size + 1
                
    if len(chk_df['version']) > 0:
        if version in chk_df['version'].to_list():
            pass
        else:
            for i in range(batch_count):
                if temp_batch + batch_size >= len_key_df:
                    end_batch = len_key_df
                else:
                    end_batch = temp_batch + batch_size
                
                log.info("index start {}, end {}".format(temp_batch, end_batch))
                string_insert_result = execute_ch('insert into {} values'.format(
                    model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + column), config, key_df[col_order][temp_batch: end_batch].values.tolist())
                temp_batch += batch_size
                log.info(string_insert_result)
                sleep(1)
    else:
        for i in range(batch_count):
            if temp_batch + batch_size >= len_key_df:
                end_batch = len_key_df
            else:
                end_batch = temp_batch + batch_size
            
            log.info("index start {}, end {}".format(temp_batch, end_batch))
            string_insert_result = execute_ch('insert into {} values'.format(
            model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + column), config,
                                          key_df[col_order][temp_batch: end_batch].values.tolist())
            temp_batch += batch_size
            log.info(string_insert_result)
            sleep(1)
    log.info('DONE CHECK 5 insert data')
#     log.info(f'-------------------- tot_runtime is {round(time.time() - __start_time, 4)} seconds. --------------------')
    
    

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
def train_esoinn_model_no_sparse_mat(mode, config, model_config, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    log.info("version : {}".format(version))
    str_cols = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['str_cols']
    str_cols.remove('label')
    

    # # st data preparation
    if model_config['esoinn_version'] == "":  # # 최초 학습
        ## Num DATA LOAD
        t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
        log.info("db_name: {}".format(model_config['db_name']))
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        train_sql = sql + " and (label='normal' or label in {att_name})".format(
            att_name=tuple(model_config['attack_array'].split(', ')))
        data, meta = execute_ch(train_sql, config, param=None, with_column_types=True)
        num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

        ## Category DATA LOAD
        t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        train_sql = sql + " and (label='normal' or label in {att_name})".format(
            att_name=tuple(model_config['attack_array'].split(', ')))
        data, meta = execute_ch(train_sql, config, param=None, with_column_types=True)
        cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

        merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version', 'label']
        total_df = pd.merge(num_df, cat_df, on=merge_list)
        idx_df = total_df.copy()
        log.info("merge_list: {}".format(merge_list))
        log.info("num_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(num_df.head(100)))
        log.info("cat_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(cat_df.head(100)))
        log.info("num_df.shape: {}".format(num_df.shape))
        log.info("cat_df.shape: {}".format(cat_df.shape))
        log.info("total_df.shape: {}".format(total_df.shape))
        log.info("total_df.head(100):::::::::::::::::::::::::::\n{}".format(total_df.head(100)))

        chk_idx_list = total_df['index'].tolist()

        ## String DATA LOAD
        for i in str_cols:

            t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
            sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
            train_sql = sql + " and (label='normal' or label in {att_name})".format(
                att_name=tuple(model_config['attack_array'].split(', ')))
            log.info("str query :::::::::::::::::::::\n{}".format(train_sql))
            data, meta = execute_ch(train_sql, config, param=None, with_column_types=True)
            tmp_df = pd.DataFrame(data, columns=[m[0] for m in meta])
            str_df = pd.DataFrame(tmp_df['score'].values.tolist(), columns=tmp_df['feature'][0])
            
            str_df = str_df.merge(tmp_df[merge_list], left_index=True, right_index=True)
            total_df = pd.merge(total_df, str_df, on=merge_list)
        
        
        log.info("total df unique label : {uq_label}".format(uq_label=total_df['label'].unique()))
        st_total_df = total_df.drop(merge_list, axis=1).copy()
#         save_ic_list(list=list(st_total_df), type='esoinn', version=version, mode=mode)

        log.info("len(list(total_df)) : {}, list(total_df) : {}".format(len(list(total_df)), list(total_df)))
        
        try:
            f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
            black_key_line = f.readlines()
        except Exception as err:
            log.error("[ERROR] {}".format(err))
        finally:
            f.close

        new_line = [i.strip().lower() for i in black_key_line]
        log.info("len(new_line) {} \n{}".format(len(new_line), new_line))
        
#         x_data = total_df.drop(merge_list, axis=1).values
        x_data = total_df[new_line].values
        y_data = total_df[['label']].values
        model_config['x_data_shape'] = x_data.shape
        model_config['y_data_shape'] = y_data.shape
        log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))
        log.info("y_data.shape : {}, type {}".format(y_data.shape, type(y_data)))

        # # st shuffle data
        val_ratio = model_config['validation_ratio']
        permutation = np.random.permutation(x_data.shape[0])
        log.info("\nval_data_ratio : {}\nnormal : [{}] \ntotal ATTACK : [{}]".format(val_ratio,
            (y_data[permutation[:int(x_data.shape[0] * val_ratio)]] == 'normal').sum(),
            (y_data[permutation[:int(x_data.shape[0] * val_ratio)]] != 'normal').sum()))
        
        keys, counts = np.unique(y_data[permutation[:int(x_data.shape[0] * val_ratio)]], return_counts=True)
        cluster_uniq = "label : {}, cnts : {}".format(keys, counts)
        log.info("label : {}\ncnts : {}".format(keys, counts))
        # # en shuffle_data

        # # st train_test_split
        x_vali = x_data[permutation[:int(x_data.shape[0] * val_ratio)]]
        y_vali = y_data[permutation[:int(y_data.shape[0] * val_ratio)]]
        x_data = x_data[permutation[int(x_data.shape[0] * val_ratio):]]
        y_data = y_data[permutation[int(y_data.shape[0] * val_ratio):]]
        # # en train_test_split

        # # save validation data for TRANSFER_LEARNING
        try:
            os.makedirs(pwd + "/obj/esoinn_valid_data/", exist_ok=True)
            with open(pwd + "/obj/esoinn_valid_data/valid_data_" + version + ".pickle", "wb") as f:
                pickle.dump([x_vali, y_vali], f)
        except Exception as err:
            log.error(err)

    else:  # # TRANSFER_LEARNING
        log.info("db_name: {}".format(model_config['db_name']))
        t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        sql += "and label='normal'"
        data, meta = execute_ch(sql, config, param=None, with_column_types=True)
        num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

        t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        sql += "and label='normal'"
        data, meta = execute_ch(sql, config, param=None, with_column_types=True)
        cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

        merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version', 'label']
        total_df = pd.merge(num_df, cat_df, on=merge_list)
        log.info("merge_list: {}".format(merge_list))
        log.info("num_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(num_df.head(100)))
        log.info("cat_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(cat_df.head(100)))
        log.info("num_df.shape: {}".format(num_df.shape))
        log.info("cat_df.shape: {}".format(cat_df.shape))
        log.info("total_df.shape: {}".format(total_df.shape))
        log.info("total_df.head(100):::::::::::::::::::::::::::\n{}".format(total_df.head(100)))
        log.info("bf loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

        chk_idx_list = total_df['index'].tolist()

        for i in str_cols:

            t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
            sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
            sql += "and label='normal'"
            data, meta = execute_ch(sql, config, param=None, with_column_types=True)
            
            tmp_data = pd.DataFrame(data, columns=[m[0] for m in meta])
            
            str_df = pd.DataFrame(tmp_data['score'].values.tolist(), columns=tmp_data['feature'][0])
            
            str_df = str_df.merge(tmp_data[merge_list], left_index=True, right_index=True)
            total_df = pd.merge(total_df, str_df, on=merge_list)

        log.info("af loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

        # total_df = total_df.sample(5000)

        log.info("af shuffle total_df.shape : {}".format(total_df.shape))

        total_df['model_version'] = version
        merge_list.append('model_version')

        log.info('DATA LOAD AND MERGE SUCCESS')
        log.info(merge_list)
        log.info(total_df.model_version)
        log.info("total df shape : {}".format(total_df.shape))

        log.info("feature_list ::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n{}".format(
            list(total_df.drop(merge_list, axis=1))))


        st_total_df = total_df.drop(merge_list, axis=1).copy()
        
        try:
            f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
            black_key_line = f.readlines()
        except Exception as err:
            log.error("[ERROR] {}".format(err))
        finally:
            f.close

        new_line = [i.strip().lower() for i in black_key_line]
        log.info("len(new_line) {} \n{}".format(len(new_line), new_line))
        
        st_total_df = st_total_df[new_line]
        log.info("bf pickle len(st_total_df.features) : {}, st_total_df.features : {}".format(
            len(list(st_total_df)), list(st_total_df)))

        # For Esoinn XAI

        x_data = st_total_df.values; y_data = None
        # x_data = total_df.drop(merge_list, axis=1).values
        model_config['x_data_shape'] = x_data.shape
        log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))

        # # load validation data
        try:
            f = open(pwd + "/obj/esoinn_valid_data/valid_data_" + model_config['esoinn_version'] + ".pickle", "rb")
            x_vali, y_vali = pickle.load(f)
            log.info("bf >>> y_vali.shape {}".format(y_vali.shape))
            f.close()
        except Exception as err:
            log.error(err)

        # # st shuffle data
        log.info("x_vali.shape : {}, y_vali.shape : {}".format(x_vali.shape, y_vali.shape))
        
        tot_val = np.concatenate((x_vali, y_vali), axis=1)
        old_norm_val = tot_val[np.where(tot_val[:, -1] == 'normal')]
        old_atck_val = tot_val[np.where(tot_val[:, -1] != 'normal')]
        old_norm_val = old_norm_val[np.random.permutation(old_norm_val.shape[0])[:old_norm_val.shape[0] // 2]]
        rand_idx = np.random.permutation(x_data.shape[0])
        new_x_val = x_data[rand_idx[:old_norm_val.shape[0]]]
        x_data = x_data[rand_idx[old_norm_val.shape[0]:]]
        new_y_val = np.array([['normal'] for _ in range(new_x_val.shape[0])])
        new_norm_val = np.concatenate((new_x_val, new_y_val), axis=1)
        tot_val = np.concatenate((old_norm_val, old_atck_val, new_norm_val), axis=0)
        x_vali = tot_val[:, :-1].astype(np.float)
        try:
            y_vali = tot_val[:, -1].reshape(y_vali.shape[0], y_vali.shape[1])
        except Exception as e:
            log.error(e)
            pass
        log.info("af >>> y_vali.shape {}".format(y_vali.shape))
        # # en shuffle data

        # # save validation data for TRANSFER_LEARNING
        try:
            os.makedirs(pwd + "/obj/esoinn_valid_data/", exist_ok=True)
            with open(pwd + "/obj/esoinn_valid_data/valid_data_" + version + ".pickle", "wb") as f:
                pickle.dump([x_vali, y_vali], f)
        except Exception as err:
            log.error(err)
    # # en data preparation

    # # st ESoinn LEARNING
    s = ESoinn(iteration_threshold=model_config['iter_size'], max_edge_age=model_config['e_age'],
               crcl_w=model_config['crcl_w'])

    s.check_point(
        save_version=version
        , monitor=model_config['monitor']
        , save_best_only=True
        , sava_last_model=True
        , save_plt_fig=False
        , patience=model_config['patience']
        , model_version=model_config['esoinn_version']
    )

    if model_config['esoinn_version'] == "":  # # 최초 학습
        s.fit(
            train_data=[x_data, y_data]
            , validation_data=[x_vali, y_vali]
            , epochs=model_config['esoinn_epochs']
            , full_shuffle_flag=True
        )
    else:  # # TRANSFER_LEARNING
        s.fit(
            # # TRANSFER_LEARNING의 학습 데이터 label은 normal 가정
            train_data=[x_data]
            , validation_data=[x_vali, y_vali]
            , epochs=model_config['esoinn_epochs']
            , full_shuffle_flag=False
        )
    # # en ESoinn LEARNING

    # # load prediction model
    pred_s = ESoinn()
    pred_s.load_esoinn_model(version)
    pred_Y = pred_s.predict(x_vali)
    acc = pred_s.get_evaluation(x_vali, y_vali, model_config['monitor'])
    log.info("version : {version}".format(version=version))
    log.info("{} : {}".format(model_config['monitor'], acc))
    keys, counts = np.unique(pred_s.trn_clust_lb, return_counts=True)
    cluster_uniq = "keys : {}, cnts : {}".format(keys, counts)
    log.info("keys : {}\ncnts : {}".format(keys, counts))
    """
    merge_list = ['model_name'] + ['index'] + model_config['idx_cols'].split(', ') + ['version', 'label'] + ['pred', 'accuracy']
    """
    log.info("esoinn validation result unique : {pred_Y}".format(pred_Y=pred_Y.ai_label.unique()))
    
    try:
        sql = """
    select {columns}
    from {table_name}
    """.format(table_name=model_config['db_name'] + '.' + model_config['history_table'], columns="max(idx)")
        idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0]) + 1
        
        # save model train history
        if model_config['esoinn_version'] == "":  # # 최초 학습
            seed_version = version
        else:
            seed_version = model_config['feat_version']
        
        label_list = model_config['attack_array'].split(", ") + ['anomaly', 'normal']
        
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['history_table']), config, [{'idx' : idx, 'model_id' : model_config['common']['model_id'], 'model_name' : 'esoinn', 'logtime' : dt.now().replace(microsecond=0) + timedelta(hours=9), 'feature' : ['accuracy_score', 'precision_score', 'recall_score', 'f1_score', 'patience', 'iter_size', 'e_age', 'crcl_w', 'feat_num'], 'score' : [accuracy_score(y_vali, pred_Y.ai_label), precision_score(y_vali, pred_Y.ai_label, average='weighted'), recall_score(y_vali, pred_Y.ai_label, average='weighted'), f1_score(y_vali, pred_Y.ai_label, average='weighted'), model_config['patience'], model_config['iter_size'], model_config['e_age'], model_config['crcl_w'], len(new_line)], 'label_list' : str(label_list), 'confusion_mat' : str(confusion_matrix(y_vali, pred_Y.ai_label, labels=label_list)), 'model_version' : version, 'seed_version' : seed_version}])
        

        log.info('ESOINN Model train history insert success')
    except Exception as err:
        log.error('ESOINN Model train history insert FAIL : {}'.format(err))
        
    log.info('ESOINN MODEL TRAIN SUCCESS')
    
    
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#     
def train_c_svm_binary_classification_model(mode, config, model_config, att_name, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    log.info("version : {}".format(version))
    str_cols = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['str_cols']
    str_cols.remove('label')
    
    # # st data preparation
    ## Num DATA LOAD
    t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
    log.info("db_name: {}".format(model_config['db_name']))
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    train_sql = sql + f" and (label='normal' or label = '{att_name}')"
    data, meta = execute_ch(train_sql, config, param=None, with_column_types=True)
    num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    ## Category DATA LOAD
    t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    train_sql = sql + f" and (label='normal' or label = '{att_name}')"
    data, meta = execute_ch(train_sql, config, param=None, with_column_types=True)
    cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version', 'label']
    total_df = pd.merge(num_df, cat_df, on=merge_list)
    idx_df = total_df.copy()
    log.info("merge_list: {}".format(merge_list))
    log.info("num_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(num_df.head(100)))
    log.info("cat_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(cat_df.head(100)))
    log.info("num_df.shape: {}".format(num_df.shape))
    log.info("cat_df.shape: {}".format(cat_df.shape))
    log.info("total_df.shape: {}".format(total_df.shape))
    log.info("total_df.head(100):::::::::::::::::::::::::::\n{}".format(total_df.head(100)))

    chk_idx_list = total_df['index'].tolist()

    ## String DATA LOAD
    for i in str_cols:

        t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        train_sql = sql + f" and (label='normal' or label = '{att_name}')"
        log.info("str query ::::::::::::::::::::::\n{}".format(train_sql))
        data, meta = execute_ch(train_sql, config, param=None, with_column_types=True)
        tmp_df = pd.DataFrame(data, columns=[m[0] for m in meta])
        str_df = pd.DataFrame(tmp_df['score'].values.tolist(), columns=tmp_df['feature'][0])

        str_df = str_df.merge(tmp_df[merge_list], left_index=True, right_index=True)
        total_df = pd.merge(total_df, str_df, on=merge_list)

    log.info("total df unique label : {uq_label}".format(uq_label=total_df['label'].unique()))
    st_total_df = total_df.drop(merge_list, axis=1).copy()

    log.info("len(list(total_df)) : {}, list(total_df) : {}".format(len(list(total_df)), list(total_df)))

    try:
        f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
        black_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close

    new_line = [i.strip().lower() for i in black_key_line]
    log.info("len(new_line) {} \n{}".format(len(new_line), new_line))

#         x_data = total_df.drop(merge_list, axis=1).values
    x_data = total_df[new_line].values
    y_data = np.ravel(total_df[['label']].values)  # total_df[['label']].values
    model_config['x_data_shape'] = x_data.shape
    model_config['y_data_shape'] = y_data.shape
    log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))
    log.info("y_data.shape : {}, type {}".format(y_data.shape, type(y_data)))

    # # st shuffle data
    val_ratio = model_config['validation_ratio']
    permutation = np.random.permutation(x_data.shape[0])
    log.info("\nval_data_ratio : {}\nnormal : [{}] \ntotal ATTACK : [{}]".format(val_ratio,
        (y_data[permutation[:int(x_data.shape[0] * val_ratio)]] == 'normal').sum(),
        (y_data[permutation[:int(x_data.shape[0] * val_ratio)]] != 'normal').sum()))

    keys, counts = np.unique(y_data[permutation[:int(x_data.shape[0] * val_ratio)]], return_counts=True)
    cluster_uniq = "label : {}, cnts : {}".format(keys, counts)
    log.info("label : {}\ncnts : {}".format(keys, counts))
    # # en shuffle_data

    # # st train_test_split
    x_vali = x_data[permutation[:int(x_data.shape[0] * val_ratio)]]
    y_vali = y_data[permutation[:int(y_data.shape[0] * val_ratio)]]
    x_data = x_data[permutation[int(x_data.shape[0] * val_ratio):]]
    y_data = y_data[permutation[int(y_data.shape[0] * val_ratio):]]
    # # en train_test_split

    # # save validation data for TRANSFER_LEARNING
#     try:
#         os.makedirs(pwd + "/obj/esoinn_valid_data/", exist_ok=True)
#         with open(pwd + "/obj/esoinn_valid_data/valid_data_" + version + ".pickle", "wb") as f:
#             pickle.dump([x_vali, y_vali], f)
#     except Exception as err:
#         log.error(err)
    # # en data preparation

    # # st Supervised LEARNING
    log.info('START Supervised Learning MODEL')
    train_st = dt.now().replace(microsecond=0) + timedelta(hours=9)
    ### st Supervised Learning Model ############################################
#     model = svm.SVC(decision_function_shape='ovo', verbose=1, tol=0.00001)
    model = svm.SVC(kernel='rbf', verbose=1, tol=0.00001)
    model.fit(x_data, y_data)
    label_y_df = pd.DataFrame(y_data, columns=['labels'])
    label_y_df['ai_label'] = model.predict(x_data) 
    
    log.info(label_y_df.groupby(['labels', 'ai_label']).size().to_string())
    labels_dict = dict(label_y_df.groupby(['labels', 'ai_label']).size().sort_values().groupby(level=0).tail(1).keys().tolist())
    log.info('labels_dict : {}'.format(labels_dict))
    supervised_dict = {'model' : model, 'labels_dict' : labels_dict}
    
    # # SAVE Supervised MODEL
    try:
        os.makedirs("{}/model/supervised_model/".format(pwd), exist_ok=True)
        with open("{}/model/supervised_model/supervised_{}_model_{}.pickle".format(pwd, att_name, version), "wb") as f:
            pickle.dump(supervised_dict, f)
        log.info("supervised_{}_model_{}.pickle saved".format(att_name, version))
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    
    # # LOAD Supervised MODEL
    log.info("LOAD version : {} supervised binary model ".format(version))
    try:
        with open("{}/model/supervised_model/supervised_{}_model_{}.pickle".format(pwd, att_name, version), "rb") as f:
            supervised_dict = pickle.load(f)
        log.info("supervised_{}_model_{}.pickle loaded".format(att_name, version))
    except Exception as err:
        log.error("[ERROR] {}".format(err))   
    
    pred_model = supervised_dict['model']
    labels_dict = supervised_dict['labels_dict']
    pred_y = model.predict(x_vali)
    invsrd_pred_y = [labels_dict[prd_y] for prd_y in pred_y]
    
    label_list = list(set(invsrd_pred_y))
    log.info("\nCONFUSION MATRIX (labels : {})\n {}".format(label_list, confusion_matrix(y_vali, invsrd_pred_y, labels=label_list)))
    log.info("\nacc : {}, precision : {}, recall : {}, f1_score : {}".format(accuracy_score(y_vali, invsrd_pred_y), precision_score(y_vali, invsrd_pred_y, average='weighted'), recall_score(y_vali, invsrd_pred_y, average='weighted'), f1_score(y_vali, invsrd_pred_y, average='weighted')))
    ### en Supervised Learning Model ############################################
    train_et = dt.now().replace(microsecond=0) + timedelta(hours=9)
        
    log.info('Supervised MODEL TRAIN SUCCESS')
    

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#    
def train_keras_quasi_svm_classification_model(mode, config, model_config, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    log.info("version : {}".format(version))
    str_cols = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['str_cols']
    str_cols.remove('label')
    
    # # st data preparation
    ## Num DATA LOAD
    t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
    log.info("db_name: {}".format(model_config['db_name']))
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    train_sql = sql + " and (label='normal' or label in {att_name})".format(
        att_name=tuple(model_config['attack_array'].split(', ')))
    data, meta = execute_ch(train_sql)
    num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    ## Category DATA LOAD
    t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    train_sql = sql + " and (label='normal' or label in {att_name})".format(
        att_name=tuple(model_config['attack_array'].split(', ')))
    data, meta = execute_ch(train_sql)
    cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version', 'label']
    total_df = pd.merge(num_df, cat_df, on=merge_list)
    idx_df = total_df.copy()
    log.info("merge_list: {}".format(merge_list))
    log.info("num_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(num_df.head(100)))
    log.info("cat_df.head(100)::::::::::::::::::::::::::::::::\n{}".format(cat_df.head(100)))
    log.info("num_df.shape: {}".format(num_df.shape))
    log.info("cat_df.shape: {}".format(cat_df.shape))
    log.info("total_df.shape: {}".format(total_df.shape))
    log.info("total_df.head(100):::::::::::::::::::::::::::\n{}".format(total_df.head(100)))

    chk_idx_list = total_df['index'].tolist()

    ## String DATA LOAD
    for i in str_cols:

        t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        train_sql = sql + " and (label='normal' or label in {att_name})".format(
            att_name=tuple(model_config['attack_array'].split(', ')))
        log.info("str query ::::::::::::::::::::::\n{}".format(train_sql))
        data, meta = execute_ch(train_sql)
        tmp_df = pd.DataFrame(data, columns=[m[0] for m in meta])
        str_df = pd.DataFrame(tmp_df['score'].values.tolist(), columns=tmp_df['feature'][0])

        str_df = str_df.merge(tmp_df[merge_list], left_index=True, right_index=True)
        total_df = pd.merge(total_df, str_df, on=merge_list)

    log.info("total df unique label : {uq_label}".format(uq_label=total_df['label'].unique()))
    st_total_df = total_df.drop(merge_list, axis=1).copy()

    log.info("len(list(total_df)) : {}, list(total_df) : {}".format(len(list(total_df)), list(total_df)))

    try:
        f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
        black_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close()
        
#     try:
#         f = open(pwd + '/detect/' + model_config['whte_f_nm'], 'r')
#         white_key_line = f.readlines()
#     except Exception as err:
#         log.error("[ERROR] {}".format(err))
#     finally:
#         f.close
    
#     new_line = [i.strip().lower() for i in black_key_line] + [i.strip().lower() for i in white_key_line]

    new_line = [i.strip().lower() for i in black_key_line]
    log.info("len(new_line) {} \n{}".format(len(new_line), new_line))


    x_data = total_df[new_line].values
    y_data = total_df[['label']].values  # np.ravel(total_df[['label']].values)   
    model_config['x_data_shape'] = x_data.shape
    model_config['y_data_shape'] = y_data.shape
    log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))
    log.info("y_data.shape : {}, type {}".format(y_data.shape, type(y_data)))

    # # st shuffle data
    val_ratio = model_config['validation_ratio']
    permutation = np.random.permutation(x_data.shape[0])
    log.info("\nval_data_ratio : {}\nnormal : [{}] \ntotal ATTACK : [{}]".format(val_ratio,
        (y_data[permutation[:int(x_data.shape[0] * val_ratio)]] == 'normal').sum(),
        (y_data[permutation[:int(x_data.shape[0] * val_ratio)]] != 'normal').sum()))

    keys, counts = np.unique(y_data[permutation[:int(x_data.shape[0] * val_ratio)]], return_counts=True)
    cluster_uniq = "label : {}, cnts : {}".format(keys, counts)
    log.info("label : {}\ncnts : {}".format(keys, counts))
    # # en shuffle_data

    # # st train_test_split
    valid_df = total_df.copy().iloc[permutation[:int(x_data.shape[0] * val_ratio)]]
    x_vali = x_data[permutation[:int(x_data.shape[0] * val_ratio)]]
    y_vali = pd.DataFrame(y_data[permutation[:int(y_data.shape[0] * val_ratio)]], columns=['']) 
    x_data = x_data[permutation[int(x_data.shape[0] * val_ratio):]]
    y_data = pd.DataFrame(y_data[permutation[int(y_data.shape[0] * val_ratio):]], columns=[''])
    # # en train_test_split
    
    catPrep = CatProcessing()
    catPrep.save_one_hot_enc_model(y_data, version, m_type='keras_quasi_svm')
    y_data = catPrep.trnsfm_one_hot_enc_data(y_data, version, m_type='keras_quasi_svm')
    y_vali = catPrep.trnsfm_one_hot_enc_data(y_vali, version, m_type='keras_quasi_svm')

    # # st Supervised LEARNING
    log.info('START keras_quasi_svm MODEL')
    train_st = dt.now().replace(microsecond=0) + timedelta(hours=9)
    ### st Supervised Learning Model ############################################
    # # st create q_svm 
    # # st setup
    from tensorflow import keras
    from tensorflow.keras import layers
    from tensorflow.keras.layers.experimental import RandomFourierFeatures
    from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint
    # # st set hyper_param
    batch_size = 2048 # 128
    patience = model_config['supervised_patience']
    scale = 10.0
    epoch = 20
    kernel_initializer = "gaussian"
    # # en set hyper_param
    # # en setu
    inp = keras.Input(shape=(x_data.shape[1],))
    q_svm = RandomFourierFeatures(output_dim=4096, scale=scale, kernel_initializer=kernel_initializer)(inp)
    out = layers.Dense(units=y_data.shape[1], name='predictions')(q_svm)
    model = keras.Model(inputs=inp, outputs=out)
    
    log.info(model.summary())
    # # en create q_svm 
    
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=1e-3),
        loss=keras.losses.hinge,
        metrics=[keras.metrics.CategoricalAccuracy(name="acc")],
    )
    
    os.makedirs("{}/model/supervised_model/".format(pwd), exist_ok=True)
    check_pointer = ModelCheckpoint(filepath='{}/model/supervised_model/keras_q_svm_{}.h5'.format(pwd, version)
                                   , monitor='val_loss'
                                   , verbose=1
                                   , mode='min'
                                   , save_best_only=True)
    tmp_step = 0
    while tmp_step < 30:
        log.info("batch_size : {} \nscale : {} \nkernel_initializer : {} \npatience : {}".format(batch_size, scale, kernel_initializer, patience))
        early_stop = EarlyStopping(monitor='val_loss', patience=patience, verbose=1, min_delta=0.001)
        model.fit(x_data, y_data, epochs=epoch, batch_size=batch_size, shuffle=True, verbose=1, validation_split=0.2, callbacks=[early_stop, check_pointer])

        tmp_pred = model.predict(x_vali).argmax(axis=1).tolist()
        tmp_pred_data = catPrep.return_categories(valid_df[merge_list], tmp_pred, version, m_type='keras_quasi_svm')
        f1_sc = f1_score(tmp_pred_data.label, tmp_pred_data.ai_label, average='weighted')
        if f1_sc > 0.925:
            log.info("\nkeras_quasi_svm TRAIN is DONE \nTOTAL f1_score : {}".format(f1_sc))
            break
        log.info("\nkeras_quasi_svm TRAIN is LOOPing \nTOTAL f1_score : {}".format(f1_sc))
        tmp_step += 1
        epoch += 5
        patience += 1
    
    # # st load keras_q_svm
    pred = model.predict(x_vali).argmax(axis=1).tolist()
    pred_data = catPrep.return_categories(valid_df[merge_list], pred, version, m_type='keras_quasi_svm')
    acc = accuracy_score(pred_data.label, pred_data.ai_label)
    # # en load keras_q_svm
    label_list = model_config['attack_array'].split(", ") + ['normal']
    confusion_mat = confusion_matrix(pred_data.label, pred_data.ai_label, labels=label_list)
    log.info("\nkeras_quasi_svm TRAIN is DONE \nTOTAL acc : {}".format(acc))
    log.info("\nTOTAL confusion_matrix : \n{}\n{}".format(label_list, confusion_mat))
    ### en Supervised Learning Model ############################################
    train_et = dt.now().replace(microsecond=0) + timedelta(hours=9)
    
    try:
        sql = """
    select {columns}
    from {table_name}
    """.format(table_name=model_config['db_name'] + '.' + model_config['history_table'], columns="max(idx)")
        idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0]) + 1
            
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['history_table']), config, [{'idx' : idx, 'model_id' : model_config['common']['model_id'], 'model_name' : 'keras_quasi_svm', 'logtime' : train_et, 'feature' : ['accuracy_score', 'precision_score', 'recall_score', 'f1_score'], 'score' : [acc, precision_score(pred_data.label, pred_data.ai_label, average='weighted'), recall_score(pred_data.label, pred_data.ai_label, average='weighted'), f1_score(pred_data.label, pred_data.ai_label, average='weighted')], 'label_list' : str(label_list), 'confusion_mat' : str(confusion_mat), 'model_version' : version, 'seed_version' : version}])
        log.info('keras_quasi_svm Model train history insert success')
    except Exception as err:
        log.error('keras_quasi_svm Model train history insert FAIL \n{}'.format(err))
        
    log.info('keras_quasi_svm MODEL TRAIN SUCCESS')


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%# 
def save_version(mode, config, model_config, **kwargs):
    model_id = config['model_id']
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    try:
        with open(pwd + "/obj/model_version_0.txt", "w") as f:
            f.write(version + "\n")
    except Exception as err:
        log.error("[ERROR save_version model_version_0] {}".format(err))
    
    sleep(1)
    try:
        with open(pwd + "/obj/model_version_1.txt", "w") as f:
            f.write(version + "\n")
    except Exception as err:
        log.error("[ERROR save_version model_version_1] {}".format(err))
        

    log.info('VERSION UPDATE IN CONFIG SUCCESS')


########### PREDICTION ##############################################################

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#    
def predict_esoinn_anomaly_model(mode, config, model_config, task_idx, tot_task, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    str_cols = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['str_cols']
    model_version = model_config['model_version']

    t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
    sql = get_data_collection_column_query(table_name=t_name, columns='min(index)', version=version)
    min_idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0])
    sql = get_data_collection_column_query(table_name=t_name, columns='max(index)', version=version)
    max_idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0])
    bat_size = (max_idx - min_idx + 1) // tot_task
    st_idx = min_idx + task_idx * bat_size
    en_idx = min_idx + (task_idx + 1) * bat_size
    if task_idx + 1 == tot_task:
        en_idx = max_idx + 1

    log.info("min_idx: {}, max_idx: {}, st_idx: {}, en_idx: {}".format(min_idx, max_idx, st_idx, en_idx))

    log.info("db_name: {}".format(model_config['db_name']))
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version']
    total_df = pd.merge(num_df, cat_df, on=merge_list)
    log.info("bf loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    chk_idx_list = total_df['index'].tolist()

    for i in str_cols:
        t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)

        log.info("str query :::::::::::::::::::::\n{}".format(sql))
        data, meta = execute_ch(sql, config, param=None, with_column_types=True)
        tmp_df = pd.DataFrame(data, columns=[m[0] for m in meta])
        # # tmp_df 가 empty인 경우, str_cols는 20221227 현재 single element의 array
        if len(tmp_df.index) == 0: return
        str_df = pd.DataFrame(tmp_df['score'].values.tolist(), columns=tmp_df['feature'][0])
            
        str_df = str_df.merge(tmp_df[merge_list], left_index=True, right_index=True)
        total_df = pd.merge(total_df, str_df, on=merge_list)

    log.info("af loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
#     # # TODO 분산저장 clickhouse DB 중 먹통되면 중복해서 data 가져옴
#     total_df.drop_duplicates(['index'], inplace=True)
#     log.info("af drop_duplicates total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    log.info("af total_df.shape : {}".format(total_df.shape))
    
    # # get normal prediction from svm.SVC
    t_name = model_config['db_name'] + '.' + model_config['result_01_table']
    sql = get_data_collection_column_query(table_name=t_name, columns=', '.join(merge_list), version=version)
    sql += " and ai_label = 'normal' and (index >= {st_idx} and index < {en_idx})".format(st_idx=st_idx, en_idx=en_idx)
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    norm_pred_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])
    log.info("norm_pred_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(norm_pred_df))
    
    total_df = pd.merge(left=total_df, right=norm_pred_df, how='inner', on=merge_list)
    log.info("af merge total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    total_df['model_version'] = model_version
    log.info("af total_df['model_version'] = model_version,  total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
    merge_list.append('model_version')

    log.info('DATA LOAD AND MERGE SUCCESS')
    log.info(merge_list)
    log.info(total_df.model_version)
    log.info("total df shape : {}".format(total_df.shape))

    log.info("feature_list ::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n{}".format(
        list(total_df.drop(merge_list, axis=1))))
    
    log.info("total_df :::::::::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    ## load prediction model
    pred_s = ESoinn()
    pred_s.load_esoinn_model(model_version)
    
    pred_s.crcl_w = model_config['crcl_w']
    
    st_total_df = total_df.drop(merge_list, axis=1).copy()
    
    try:
        f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
        black_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close
    sort_list = [i.strip().lower() for i in black_key_line]
    
    st_total_df = st_total_df[sort_list]
    log.info("bf pickle len(st_total_df.features) : {}, st_total_df.features : {}".format(
        len(list(st_total_df)), list(st_total_df)))

    x_data = st_total_df.values
    # x_data = total_df.drop(merge_list, axis=1).values
    model_config['x_data_shape'] = x_data.shape
    log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))

    ## esoinn prediction
    pred_Y = pred_s.predict(x_data)
    ### 비지도 학습이 공격으로 예측한 것은 anomaly로 재 ai_labeling 한다. #################################
    keys, counts = np.unique(pred_Y.ai_label, return_counts=True)
    log.info("\nbf pred_Y keys : {}\ncnts : {}".format(keys, counts))
    pred_Y = pred_Y.replace(model_config['attack_array'].split(', ') , 'normal')
#     keys, counts = np.unique(pred_Y.ai_label, return_counts=True)
#     log.info("\naf pred_Y keys : {}\ncnts : {}".format(keys, counts))
    ### 비지도 학습이 공격으로 예측한 것은 anomaly로 재 ai_labeling 한다. #################################
    result_pd = total_df.merge(pred_Y, left_index=True, right_index=True)
    log.info("result_pd.shape : {}\nresult_pd {}".format(result_pd.shape, result_pd))
    keys, counts = np.unique(result_pd.ai_label, return_counts=True)
    log.info("bf keys : {}\ncnts : {}".format(keys, counts))
    ### st BYPASS ######################################################################################
    anti_key_list = [['head']]
    for idx, tmp_row in result_pd[result_pd["ai_label"] == 'anomaly'].iterrows():
        if tmp_row["ai_label"] == 'anomaly':
            for tmp_val in anti_key_list:
                if sum(tmp_row[tmp_val]) > 0 and sum(tmp_row[[val for val in sort_list if val not in tmp_val]]) == 0:
                    result_pd.at[idx, "ai_label"] = "normal"
    ### en BYPASS ######################################################################################
    keys, counts = np.unique(result_pd.ai_label, return_counts=True)
    log.info("af keys : {}\ncnts : {}".format(keys, counts))
    
    for ai_att_name in list(result_pd.ai_label.unique()):
        save_filter_list(list=result_pd[result_pd.ai_label == ai_att_name]['index'].tolist(), version=version,
                         att_name=str(ai_att_name), mode=mode, l_type='idx')

    ## DB check
    dbcheck = DBCheck(mode=mode, config=config, model_config=model_config)

    try:
        merge_list.append('ai_label')
        result_pd = result_pd[merge_list]
        order = dbcheck.create_table(idx_data=merge_list, cols=list(result_pd), database_name=model_config['db_name'],
                             table_n=model_config['esoinn_result_table'])

        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['esoinn_result_table']), config,
                   result_pd[order].values.tolist())
        log.info('Esoinn Model prediction result insert success')
    except Exception as err:
        log.error("[ERROR] During insert Esoinn Model prediction result\n{}".format(err))

    log.info('TEST ESOINN PREDICT MODEL')
    
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
def predict_keras_quasi_svm_classification_model(mode, config, model_config, task_idx, tot_task, **kwargs):
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    str_cols = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['str_cols']
    model_version = model_config['model_version']
    


    t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
    sql = get_data_collection_column_query(table_name=t_name, columns='min(index)', version=version)
    min_idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0])
    sql = get_data_collection_column_query(table_name=t_name, columns='max(index)', version=version)
    max_idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0])
    
    bat_size = (max_idx - min_idx + 1) // tot_task
    st_idx = min_idx + task_idx * bat_size
    en_idx = min_idx + (task_idx + 1) * bat_size
    if task_idx + 1 == tot_task:
        en_idx = max_idx + 1
        
    log.info("min_idx: {}, max_idx: {}, st_idx: {}, en_idx: {}".format(min_idx, max_idx, st_idx, en_idx))

    log.info("db_name: {}".format(model_config['db_name']))
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)

    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])

    merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version']
    
    total_df = pd.merge(num_df, cat_df, on=merge_list)
    log.info("bf loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    chk_idx_list = total_df['index'].tolist()

    for i in str_cols:
        t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)

        log.info("str query ::::::::::::::::::: \n{}".format(sql))
        data, meta = execute_ch(sql, config, param=None, with_column_types=True)
        tmp_df = pd.DataFrame(data, columns=[m[0] for m in meta])
        # # tmp_df 가 empty인 경우, str_cols는 20221227 현재 single element의 array
        if len(tmp_df.index) == 0: return
        str_df = pd.DataFrame(tmp_df['score'].values.tolist(), columns=tmp_df['feature'][0])
        str_df = str_df.merge(tmp_df[merge_list], left_index=True, right_index=True)
        
        total_df = pd.merge(total_df, str_df, on=merge_list)
    
    log.info("af loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
#     # # TODO 분산저장 clickhouse DB 중 먹통되면 중복해서 data 가져옴
#     total_df.drop_duplicates(['index'], inplace=True)
#     log.info("af drop_duplicates total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    total_df['model_version'] = model_version
    merge_list.append('model_version')

    log.info('DATA LOAD AND MERGE SUCCESS')
    log.info("merge_list : {}".format(merge_list))
    log.info("total_df.model_version : {}".format(total_df.model_version))
    log.info("total df shape : {}".format(total_df.shape))
    log.info("total_df :::::::::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
    st_total_df = total_df.drop(merge_list, axis=1).copy()
    log.info("TOTAL feature_list :::::::::::::::::::::::::\n{}".format(list(st_total_df)))
    
    try:
        f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
        black_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close
    
#     try:
#         f = open(pwd + '/detect/' + model_config['whte_f_nm'], 'r')
#         white_key_line = f.readlines()
#     except Exception as err:
#         log.error("[ERROR] {}".format(err))
#     finally:
#         f.close
    
#     sort_list = [i.strip().lower() for i in black_key_line] + [i.strip().lower() for i in white_key_line]
    sort_list = [i.strip().lower() for i in black_key_line]
    
    st_total_df = st_total_df[sort_list]
    log.info("bf pickle len(st_total_df.features) : {}, st_total_df.features : {}".format(
        len(list(st_total_df)), list(st_total_df)))

    x_data = st_total_df.values
    # x_data = total_df.drop(merge_list, axis=1).values
    model_config['x_data_shape'] = x_data.shape
    log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))

    # # LOAD Supervised MODEL
    log.info("LOAD version : {} keras_quasi_svm model ".format(model_version))
    
    # # st load keras_q_svm
    from tensorflow.keras.layers.experimental import RandomFourierFeatures
    from tensorflow.keras.models import load_model
    pred_model = load_model('{}/model/supervised_model/keras_q_svm_{}.h5'.format(pwd, model_version), custom_objects={'RandomFourierFeatures': RandomFourierFeatures})

    pred = pred_model.predict(x_data).argmax(axis=1).tolist()
                         
    catPrep = CatProcessing()
#     result_pd = catPrep.return_categories(total_df[merge_list], pred, model_version, m_type='keras_svm')
    result_pd = catPrep.return_categories(total_df, pred, model_version, m_type='keras_quasi_svm')
    # # en load keras_q_svm
    
    log.info("result_pd.shape : {}\nresult_pd :::::::::::\n{}".format(result_pd.shape, result_pd))
    
    keys, counts = np.unique(result_pd.ai_label, return_counts=True)
    log.info("\nbf >>> ai_labels : {}\ncnts : {}".format(keys, counts))
    
    ### st BINARY CLASSIFICATION ######################################################################################
    for att_nm in model_config['attack_array'].split(', '):
        if result_pd[result_pd['ai_label'] != 'normal'].empty: break
        tmp_result_pd = result_pd[result_pd['ai_label'] == att_nm].copy()
        if tmp_result_pd.empty: continue

        log.info("LOAD {} version : {} supervised binary model ".format(att_nm, model_version))
        try:
            with open("{}/model/supervised_model/supervised_{}_model_{}.pickle".format(pwd, att_nm, model_version), "rb") as f:
                supervised_dict = pickle.load(f)
            log.info("supervised_{}_model_{}.pickle loaded".format(att_nm, model_version))
        except Exception as err:
            log.error("[ERROR] {}".format(err))  
            break

        pred_model = supervised_dict['model']
        labels_dict = supervised_dict['labels_dict']

        pred_y = pred_model.predict(tmp_result_pd[sort_list].values)
        tmp_result_pd['ai_label'] = [labels_dict[prd_y] for prd_y in pred_y]

        for idx, tmp_row in tmp_result_pd.iterrows():
            result_pd.at[idx, "ai_label"] = tmp_row['ai_label']
    ### en BINARY CLASSIFICATION ######################################################################################
    keys, counts = np.unique(result_pd.ai_label, return_counts=True)
    log.info("\naf1 >>> ai_labels : {}\ncnts : {}".format(keys, counts))
    ### st BYPASS ######################################################################################
    # 해당 공격에 들어 있으면 안 되는 키워드들
    anti_key_dict = { "SQL_Injection": ['head', 
                                        'robots',
                                        'bot',
                                        'bots',
                                        'bingbot',
                                        'googlebot',
                                        'requests',
                                        'sftp',
                                        'telescope',
                                        'vscode',
                                        'md',
                                        'delay',
                                        'case',
                                        'from',
                                        'pdrlabs',
                                        'node',
                                        'dockercfg',
                                        'python',
                                        'requests',
                                        'ckeditor',
                                        'xor',
                                        'view',
                                        'getlist',
                                        'now',
                                        'pw'
                                       ]  ## 'case' 'view' 다시 확인하기
                 , "Cross_Site_Scripting": ['now',
                                            'robots',
                                            'bot',
                                            'bots',
                                            'bingbot',
                                            'googlebot',
                                            'yisouspider',
                                            'ssh',
                                            'adsbot',
                                            'asc',
                                            'python',
                                            'requests'
                                           ]
                 , "Client_Server_Protocol_Manipulation": ['head'
                                                          ]
                }
    for tmp_lb, tmp_val in anti_key_dict.items():
        if result_pd[result_pd['ai_label'] != 'normal'].empty: break
        tmp_val = [val for val in tmp_val if val in sort_list]
        for idx, tmp_row in result_pd.iterrows():
            if tmp_row["ai_label"] == tmp_lb and sum(tmp_row[tmp_val]) > 0 and sum(tmp_row[[val for val in sort_list if val not in tmp_val]]) == 0:
                # # 잘 못 분류된 것 중 해당 키워드 있을 시, ai_label 재분류
                if sum(tmp_row[["crawler", "recon", "yisouspider"]]) > 0:
                    result_pd.at[idx, "ai_label"] = "Exposure_of_Sensitive_Information_to_an_Unauthorized_Actor"
                #elif sum(tmp_row[["python", "requests", "owa"]]) > 0 and sum(tmp_row[[val for val in sort_list if val not in ["python", "requests", "owa"]]]) == 0:
                elif sum(tmp_row[["owa"]]) > 0 and sum(tmp_row[[val for val in sort_list if val not in ["owa"]]]) == 0:
                    result_pd.at[idx, "ai_label"] = "Scanning_for_Vulnerable_Software"
                else:
                    result_pd.at[idx, "ai_label"] = "normal"
    ### en BYPASS ######################################################################################
    keys, counts = np.unique(result_pd.ai_label, return_counts=True)
    log.info("\naf2 >>> ai_labels : {}\ncnts : {}".format(keys, counts))
    


    ## DB check
    dbcheck = DBCheck(mode=mode, config=config, model_config=model_config)

    try:
        merge_list.append('ai_label')
        result_pd = result_pd[merge_list]
        
        result_pd['model_id'] = model_config['common']['model_id']
        merge_list.append('model_id')
        result_pd['model_name'] = 'keras_quasi_svm'
        merge_list.append('model_name')

        order = dbcheck.create_table(idx_data=merge_list, cols=list(result_pd), database_name=model_config['db_name'],
                             table_n=model_config['result_01_table'])

        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['result_01_table']), config,
                   result_pd[order].values.tolist())
        log.info('keras_quasi_svm_multi_classification Model prediction result insert success')
    except Exception as err:
        log.error("[ERROR] During insert keras_quasi_svm_multi_classification Model prediction result\n{}".format(err))
    
    ######### XAI ###########
    log.info("XAI MODEL START")
    
    invrs_preds = result_pd.ai_label.tolist()
    batch_size = len(x_data)
    
    XAI_result = pd.DataFrame()
    for i in range(batch_size):
        # # TODO XAI only attacks ?????
        if invrs_preds[i] == 'normal': continue
        
        diff = x_data[i, :]
        sorted_idx = sorted(range(len(diff)), key=lambda k: diff[k], reverse=True)

        xai_res = {
            'model_id': model_config['common']['model_id']
            , 'version': version
            , 'model_version': model_version
            , 'index': result_pd['index'].tolist()[i]
            , 'lgtime': result_pd['lgtime'].tolist()[i]
            , 'src_ip': result_pd['src_ip'].tolist()[i]
            , 'dst_ip': result_pd['dst_ip'].tolist()[i]
            , 'feature': [np.array(list(st_total_df))[sorted_idx]]
            , 'score': [diff[sorted_idx]]
            , 'ai_label': invrs_preds[i]
        }

        temp_df = pd.DataFrame(xai_res)
        XAI_result = pd.concat([XAI_result, temp_df])
    
    # # TODO invrs_preds 에 normal 만 있으면 for문 전에 return 하는 걸로????
    if XAI_result.empty:
        log.info("keras_quasi_svm_multi_classification xai result is empty")
        log.info('DONE keras_quasi_svm_multi_classification PREDICT MODEL')
        return
    log.info(XAI_result.info())
    log.info(XAI_result.ai_label.value_counts())
    log.info("FINISH XAI MODEL")
    
    try:
#         dbcheck.create_table(cols=list(XAI_result), database_name=model_config['db_name'],
#                          table_n=model_config['svm_xai_table'])
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['svm_xai_table']), config,
               XAI_result.to_dict('records'))
        log.info('keras_quasi_svm XAI Model prediction result insert success')
    except Exception as err:
        log.error("[ERROR] During insert keras_quasi_svm XAI Model prediction result\n{}".format(err))
    
    log.info('DONE keras_quasi_svm_multi_classification PREDICT MODEL')


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
def esoinn_xai_task_model_no_sparse_mat(mode, config, model_config, task_idx, tot_task, ** kwargs):
    # # esoinn xai 하기위한 공격 타입을 model_config에서 가져오기
    esoinn_atck_tp_list = model_config['esoinn_xai_attacks']
    version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']
    str_cols = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['str_cols']
    model_version = model_config['model_version']

    t_name = model_config['db_name'] + '.' + model_config['esoinn_result_table']
    sql = get_data_collection_column_query(table_name=t_name, columns='min(index)', version=version)
    min_idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0])
    sql = get_data_collection_column_query(table_name=t_name, columns='max(index)', version=version)
    max_idx = int(execute_ch(sql, config, param=None, with_column_types=True)[0][0][0])
    bat_size = (max_idx - min_idx + 1) // tot_task
    st_idx = min_idx + task_idx * bat_size
    en_idx = min_idx + (task_idx + 1) * bat_size
    if task_idx + 1 == tot_task:
        en_idx = max_idx + 1

    log.info("min_idx: {}, max_idx: {}, st_idx: {}, en_idx: {}".format(min_idx, max_idx, st_idx, en_idx))

    t_name = model_config['db_name'] + '.' + model_config['esoinn_result_table']
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
#     sql += "and index >= {st_idx} and index < {en_idx} and ai_label = '{att_name}'".format(st_idx=st_idx, en_idx=en_idx, att_name=esoinn_atck_tp_list)
    log.info("SQL IS :::::::::::::::::::::::::\n{}".format(sql) )
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)

    idx_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])
    log.info("idx_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(idx_df))
    filter_idx = idx_df['index'].tolist()
    log.info("filter_idx :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(filter_idx))

    t_name = model_config['db_name'] + '.' + model_config['prep_table_number']
    log.info("db_name: {}".format(model_config['db_name']))
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
    # sql = sql + "and index in {idx_tuple}".format(idx_tuple=tuple(filter_idx))
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    num_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])
    ## filter idx
    num_df = num_df[num_df['index'].isin(filter_idx)]

    t_name = model_config['db_name'] + '.' + model_config['prep_table_category']
    sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
    sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
    # sql = sql + "and index in {idx_tuple}".format(idx_tuple=tuple(filter_idx))
    data, meta = execute_ch(sql, config, param=None, with_column_types=True)
    cat_df = pd.DataFrame(data=data, columns=[m[0] for m in meta])
    ## filter idx
    cat_df = cat_df[cat_df['index'].isin(filter_idx)]

    merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version']
    total_df = pd.merge(num_df, cat_df, on=merge_list)
    log.info("bf loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))

    chk_idx_list = total_df['index'].tolist()

    for i in str_cols:
        t_name = model_config['db_name'] + '.' + model_config['prep_table_string'] + '__' + str(i)
        sql = get_data_collection_column_query(table_name=t_name, columns='*', version=version)
        sql += "and index >= {st_idx} and index < {en_idx}".format(st_idx=st_idx, en_idx=en_idx)
        # sql = sql + "and index in {idx_tuple}".format(idx_tuple=tuple(filter_idx))
        data, meta = execute_ch(sql, config, param=None, with_column_types=True)
        tmp_df = pd.DataFrame(data, columns=[m[0] for m in meta])
        # # tmp_df 가 empty인 경우, str_cols는 20221227 현재 single element의 array
        if len(tmp_df.index) == 0: return
        str_df = pd.DataFrame(tmp_df['score'].values.tolist(), columns=tmp_df['feature'][0])
            
        str_df = str_df.merge(tmp_df[merge_list], left_index=True, right_index=True)
        total_df = pd.merge(total_df, str_df, on=merge_list)

    total_df = pd.merge(total_df, idx_df, on=merge_list)
    log.info("af loop total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
    keys, counts = np.unique(total_df.ai_label, return_counts=True)
    log.info("\nesoinn ai_labels : {}\ncnts : {}".format(keys, counts))
#     # # TODO 분산저장 clickhouse DB 중 먹통되면 중복해서 data 가져옴
#     total_df.drop_duplicates(['index'], inplace=True)
#     log.info("af drop_duplicates total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
    merge_list = ['index'] + model_config['idx_cols'].split(', ') + ['version', 'model_version', 'ai_label']
    
    x_df = total_df.copy().drop(merge_list, axis=1)
    try:
        f = open(pwd + '/detect/' + model_config['blck_f_nm'], 'r')
        black_key_line = f.readlines()
    except Exception as err:
        log.error("[ERROR] {}".format(err))
    finally:
        f.close
    
    new_line = [i.strip().lower() for i in black_key_line]
    x_df = x_df[new_line]

    log.info("bf original x_df.shape : {}".format(x_df.shape))


    feature_list = list(x_df)
    log.info("feature_list ::::::::::::::::::::::::::::::::::::::::::::::::::::::::\n{}".format(feature_list))

    x_data = x_df.values
    model_config['x_data_shape'] = x_data.shape
    log.info("x_data.shape : {}, type {}".format(x_data.shape, type(x_data)))
    log.info("total_df :::::::::::::::::::::::::::::::::::::::::::::\n{}".format(total_df))
    log.info('ESOINN XAI MODEL LOAD')
    # # load prediction model
    pred_s = ESoinn()
    pred_s.load_esoinn_model(model_version)

    # # insert XAI results only for attack_type
    model_xai_stats = pd.DataFrame()
    for i in range(x_data.shape[0]):
        if total_df['ai_label'][i] not in esoinn_atck_tp_list: continue
#         log.info("x_data[i]:{} , len(feature_list):{}".format(x_data[i], len(feature_list)))
        result_df = pred_s.xai_esoinn(x_data[i], feature_list)
#         log.info("lgtime {}".format(total_df['lgtime'].tolist()[i]))
#         log.info(result_df)

        xai_res = {
            'model_id': model_config['common']['model_id']
            , 'version': version
            , 'model_version': model_version
            , 'index': total_df['index'].tolist()[i]
            , 'lgtime': total_df['lgtime'].tolist()[i]
            , 'src_ip': total_df['src_ip'].tolist()[i]
            , 'dst_ip': total_df['dst_ip'].tolist()[i]
            , 'feature': [result_df['feature']]
            , 'score': [result_df['diff']]
            , 'ai_label': total_df['ai_label'][i]
        }

        temp_df = pd.DataFrame(xai_res)
        model_xai_stats = pd.concat([model_xai_stats, temp_df])
    
    if model_xai_stats.empty:
        log.info("Esoinn xai result is empty")
        return
    
    log.info(model_xai_stats.info())
    try:
        log.info(model_xai_stats.ai_label.value_counts())
        log.info("FINISH XAI MODEL")
    except Exception as err:
        log.error("[ERROR] CHECK model_xai_stats\n{}".format(err))
    
    ## DB check
    dbcheck = DBCheck(mode=mode, config=config, model_config=model_config)

    try:
        order = dbcheck.create_table(cols=list(model_xai_stats), database_name=model_config['db_name'],
                             table_n=model_config['esoinn_xai_table'])
        execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['esoinn_xai_table']), config,
                   model_xai_stats[order].values.tolist())

        log.info('ESOINN XAI model result database insert success')
    except Exception as err:
        log.error("[ERROR] During insert Esoinn XAI Model prediction result\n{}".format(err))

    log.info('TEST ESOINN XAI MODEL')


# def threat_scoring(mode, config, model_config, **kwargs):
#     version = kwargs['ti'].xcom_pull(task_ids='data_collection_dag')['version']

#     # # get_raw_data
#     data, meta = execute_ch(
#         get_threat_scoring_data_query(model_config['db_name'] + '.' + model_config['esoinn_result_table'],
#                                       etc="version = '" + version + "' and ai_label != 'NORMAL'"), config)
#     raw_data = pd.DataFrame(data=data, columns=[m[0] for m in meta])
#     raw_data['round_day'] = raw_data['lgtime'].dt.floor('D')

#     all_data = pd.DataFrame()

#     ip_col = 'src_ip'
#     att_name = 'ai_label'
#     data, meta = execute_ch(get_mitre_data(), config)
#     mitre_data = pd.DataFrame(data=data, columns=[m[0] for m in meta])
#     mitre_data['scl_score'] = MinMaxScaler().fit_transform(mitre_data[['score']])

#     for i in range(raw_data[['round_day']].nunique().values[0]):
#         date = raw_data[['round_day']].drop_duplicates().sort_values('round_day').iloc[i]
#         search_days = 365
#         end_time = date['round_day'].strftime('%Y-%m-%d %H:%M:%S')
#         start_time = (date['round_day'] - datetime.timedelta(days=search_days)).strftime('%Y-%m-%d %H:%M:%S')
#         log.info("start_time: {} , end_time: {}".format(start_time, end_time))

#         data, meta = execute_ch(
#             get_threat_scoring_data_query(model_config['db_name'] + '.' + model_config['predict_table'], start_time,
#                                           end_time, etc="and version='" + version + "'"), config)
#         attack_data = pd.DataFrame(data=data, columns=[m[0] for m in meta])
#         data, meta = execute_ch(
#             get_threat_scoring_data_query(
#                 model_config['db_name'] + '.' + model_config['esoinn_result_table'], start_time, end_time,
#                 etc="and version = '" + version + "' and ai_label != 'NORMAL'"), config)
#         anomaly_data = pd.DataFrame(data=data, columns=[m[0] for m in meta])
#         # ids_data = load_ids_data(start_time, end_time)

#         valid_data = pd.DataFrame()

#         att_num = attack_data[attack_data[att_name] != 'NORMAL'][att_name].groupby(attack_data[ip_col]).count()
#         type_num = attack_data[att_name].groupby(attack_data[ip_col]).agg(['nunique'])
#         anomaly_num = anomaly_data[anomaly_data[att_name] != 'NORMAL'][att_name].groupby(anomaly_data[ip_col]).count()
#         # ids_num = ids_data[ip_col].groupby(ids_data[ip_col]).count()

#         valid_data[ip_col] = attack_data[ip_col].drop_duplicates().values
#         valid_data.set_index(ip_col, inplace=True)
#         valid_data.sort_index(inplace=True)

#         ## 위협 탐지 비율 및 유형 비율
#         valid_data = pd.merge(valid_data, pd.DataFrame(att_num / att_num.mean()), left_index=True, right_index=True,
#                               how='outer')
#         valid_data = pd.merge(valid_data, pd.DataFrame(type_num / type_num.mean()), left_index=True, right_index=True,
#                               how='outer')
#         valid_data.rename(columns={att_name: "att_ratio", "nunique": "type_ratio"}, inplace=True)

#         ## 이상행위 탐지 비율
#         valid_data = pd.merge(valid_data, pd.DataFrame(anomaly_num / anomaly_num.mean()), left_index=True,
#                               right_index=True, how='outer')
#         valid_data.rename(columns={att_name: "anomaly_ratio"}, inplace=True)

#         # ## 보안장비 탐지 비율
#         # valid_data = pd.merge(valid_data, pd.DataFrame(ids_num / ids_num.mean()), left_index=True, right_index=True,
#         #                       how='outer')
#         # valid_data.rename(columns={ip_col: "ids_ratio"}, inplace=True)

#         ## MITRE DATA RENAME
#         mitre_data.rename(columns={"att_name": att_name}, inplace=True)

#         for i in list(valid_data):
#             valid_data[i] = np.where(valid_data[i] >= 1, 1, valid_data[i])
#             valid_data[i].fillna(0, inplace=True)

#         valid_data['round_day'] = end_time
#         valid_data['round_day'] = pd.to_datetime(valid_data['round_day'])
#         all_data = pd.concat([all_data, valid_data])
#     all_data.reset_index(drop=False, inplace=True)

#     result_data = pd.DataFrame(raw_data)[['round_day', 'lgtime', ip_col, att_name]]
#     result_data = pd.merge(result_data, all_data, left_on=[ip_col, 'round_day'], right_on=[ip_col, 'round_day'])
#     result_data = pd.merge(result_data, mitre_data[[att_name, 'scl_score']], on=att_name)
#     result_data['sum_score'] = result_data['att_ratio'] + result_data['type_ratio'] + result_data['anomaly_ratio'] + \
#                                result_data['scl_score']
#     result_data['threat_score'] = ((-0.0625) * result_data['sum_score'] ** 2 + 0.5 * result_data['sum_score']) * 100

#     result_data.sort_values('threat_score')

#     log.info("result_data feat : {}\n::::::::::::::::::::::::::::::::::::::::::::::\n{}".format(list(result_data), result_data))

#     ins_result_data = result_data[['round_day', 'lgtime', 'src_ip', 'ai_label', 'sum_score', 'threat_score']]
#     model_ver = [model_config['model_version'] for _ in range(ins_result_data.shape[0])]
#     ins_result_data = ins_result_data.assign(model_version=model_ver)
#     ver = [version for _ in range(ins_result_data.shape[0])]
#     ins_result_data = ins_result_data.assign(version=ver)

#     try:
#         execute_ch(insert_prep_data_query(model_config['db_name'] + '.' + model_config['threat_scoring_table']), config,
#                    ins_result_data.to_dict('records'))
#         log.info('Threatscoring result insert success')
#     except Exception as err:
#         log.error("[ERROR] During insert Threatscoring result\n{}".format(err))
    
    
    
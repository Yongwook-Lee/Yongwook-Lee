from datetime import datetime as dt
from datetime import timedelta
from textwrap import dedent
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.subdag import SubDagOperator
from airflow.operators.dummy import DummyOperator
from airflow.utils.task_group import TaskGroup
from airflow.operators.python import get_current_context
from clickhouse_driver.client import Client
from clickhouse_driver.errors import ServerException, SocketTimeoutError
import pymysql
import platform
import logging
from Philip_shinhan_test.dti_v4_functions import * # 수정
log = logging.getLogger(__name__)


# These args will get passed on to each operator
# You can override them on a per-task basis during operator initialization
""" SHINHAN CONFIG LOAD """
config = {
    "model_id": 1002,
    "cs":[

        {
            "host": "211.115.206.9",
            "port": "9000",
            "timeout": "600000",
            "thread": "30"
        }
    ]
}

MODE = 'train'
MAIN_DAG = 'Philip_TestRegex_TRAIN' # 수정



""" DTI AI 모델 세팅 오류 존재"""
model_config = {
  "common": {
    "model_name": "TEST3005_DTI_V4_USING_ESOINN_CNN", # 수정
    "model_path": "TEST3005_DTI_V4_USING_ESOINN_CNN_MODEL", # 수정
    "model_id": 1002,
    "config_name": "TEST3005_DTI_V4_USING_ESOINN_CNN_CONFIG" # 수정
  },
    "is_test": 0,
    "data_limit": 5000, # 6000,
    "attack_limit": 15000,  # 5000,
    "interval": "30 minute",
    "idx_cols": "start_date, src_ip, dst_ip",
    "cnn_idx_cols": "lgtime, logtime, src_ip, dst_ip",
    "attack_array": "Exposure_of_Sensitive_Information_to_an_Unauthorized_Actor, Forceful_Browsing, Client_Server_Protocol_Manipulation, SQL_Injection, Scanning_for_Vulnerable_Software, Cross_Site_Scripting, Path_Traversal",
#     "target_keyword_dict": { "Client_Server_Protocol_Manipulation" : 'scalaj, redirecturl, curl'
#                             , "Exposure_of_Sensitive_Information_to_an_Unauthorized_Actor" : 'wp, GetData, yisouspider, manifest, GetList'
#                             , "Forceful_Browsing" : 'bot, googlebot, php, robots, bingbot, uptimerobot'
#                             },
    "train_days": 10, # 10
    "normal_days": 1,
    "attack_days": 800,
    "cnn_epochs": 100,
    "optimizer": "Adam",
    "batch_size": 256, # 1024, # 512, # 64, # 4096,
    "learning_rate": 0.005,
    "cnn_train_test_ratio": 0.8,
    "supervised_patience": 20, #5,
    "monitor": "f1_score",
    "crcl_w": 1.0,
    "iter_size": 3000, # 4000, # 2000, # 1200, # 600, ## 200,
    "e_age": 2000, # 2500, # 950, # 475, ## 50
    "esoinn_epochs": 1000,
    "patience": 50,
    "validation_ratio": 0.05,
    "esoinn_feat_num": 1000,
    #"blck_f_nm": "TEST3005vocabulary_20230602.txt",
    "blck_f_nm": "203words_20230517.txt",# 수정
    "whte_f_nm": "whitelist_key_20221128.txt", # 수정
    "db_name": "dti",
    "table_number": "TEST3005_train_collect_number", # 수정
    "table_string": "TEST3005_train_collect_string", # 수정
    "table_category": "TEST3005_train_collect_category", # 수정
    "prep_table_number": "TEST3005_train_prep_number", # 수정
    "prep_table_string": "TEST3005_train_prep_string", # 수정 # 이름 있으면 내부적으로 따로 데이터테이블 생성
    "prep_table_category": "TEST3005_train_prep_category", # 수정
    "history_table": "TEST3005_dti_ai_train_historyd", # 수정
#     "esoinn_history_table": "esoinn_train_history",
    "feat_version": "20220726064447",
    "esoinn_version": ""
}

m_type='cnn'

default_args = {
    'owner': 'CTILAB',
    'depends_on_past': True,
    'retries': 3,
    'retry_delay': timedelta(minutes=3),
    'config': config,
    'model_config': model_config,
    # 'queue': 'bash_queue',
    # 'pool': 'backfill',
    # 'priority_weight': 10,
    # 'end_date': dt(2016, 1, 1),
    #'wait_for_downstream': True,
    # 'dag': dag,
    # 'sla': timedelta(hours=2),
    # 'execution_timeout': timedelta(seconds=300),
    # 'on_failure_callback': some_function,
    # 'on_success_callback': some_other_function,
    # 'on_retry_callback': another_function,
    # 'sla_miss_callback': yet_another_function,
    # 'trigger_rule': 'all_success'
}
with DAG(MAIN_DAG,
         default_args=default_args,
         description='TEST3005_DTI_V4_AIRFLOW_MODEL_TRAINING', # 수정
#          schedule_interval='00 16 * * 0', 
         schedule_interval=timedelta(days=7), 
         start_date=dt(2023, 7, 14, 16, 0, 0),
         catchup=True,
         max_active_runs = 1,
         concurrency=1,
         tags=['TEST3005_DTI_V4'] # 수정
         ) as dag:

    # t1, t2 and t3 are examples of tasks created by instantiating operators
    data_collection_dag = PythonOperator(
        task_id='data_collection_dag',
        python_callable=get_data,
        provide_context=True,
        # template_dict={'version': "{{ ti.xcom_pull(task_ids='save_version') }}"},
        op_kwargs={'mode': MODE, 'config': default_args['config'], 'model_config': default_args['model_config']},
    )

    node_dag_0 = DummyOperator(task_id='node_dag_0')

    int_preprocessing_dag = PythonOperator(
        task_id='int_preprocessing_dag',
        python_callable=int_preprocessing,
        provide_context=True,
        op_kwargs={'mode': MODE, 'config': default_args['config'], 'model_config': default_args['model_config']},
    )

    cat_preprocessing_dag = PythonOperator(
        task_id='cat_preprocessing_dag',
        python_callable=cat_preprocessing,
        provide_context=True,
        op_kwargs={'mode': MODE, 'config': default_args['config'], 'model_config': default_args['model_config']},
    )
    
    with TaskGroup(group_id='str_preprocessing_tg') as str_preprocessing_tg:
        check_query = get_culumns_query('0000-00-00 00:00:00', '9999-00-00 00:00:00', '1 minute',
                                    'lgtime, src_ip, dst_ip') + ' limit 1'
        str_data, str_meta = execute_ch(check_query, config, param=None, with_column_types=True)

        columns = [m[0] for m in str_meta if m[1] == 'String']
        idx_cols_list = 'lgtime, src_ip, dst_ip'.split(', ')
        for col in idx_cols_list:
            try:
                columns.remove(col)
            except:
                pass

        for i in columns:
            t = PythonOperator(
                task_id='str_preprocessing_{0}'.format(i),
                task_group=str_preprocessing_tg,
                python_callable=str_preprocessing_t_no_sparse_mat,  # str_preprocessing_t,
                provide_context=True,
                dag=dag,
                op_kwargs={'mode': MODE, 'config': config,
                           'model_config': model_config, 'column': i}, )
    
    esoinn_train_model_dag = PythonOperator(
        task_id='esoinn_train_model_dag',
        python_callable=train_esoinn_model_no_sparse_mat, # train_esoinn_model_only_normal,
        provide_context=True,
        op_kwargs={'mode': MODE, 'config': config,
                   'model_config': model_config},
    )

    supervised_model_dag = PythonOperator(
        task_id='supervised_model_dag',
        python_callable=train_keras_quasi_svm_classification_model,  # train_c_svm_classification_model,   # train_keras_quasi_svm_classification_model
        provide_context=True,
        op_kwargs={'mode': MODE, 'config': config,
                   'model_config': model_config},
    )
    
    node_dag_1 = DummyOperator(task_id='node_dag_1')
    
    with TaskGroup(group_id='supervised_binary_model_tg') as supervised_binary_model_tg:

        for attack_name in model_config['attack_array'].split(', '):
            t = PythonOperator(
                task_id=f'supervised_{attack_name}_model',
                task_group=supervised_binary_model_tg,
                python_callable=train_c_svm_binary_classification_model, 
                provide_context=True,
                dag=dag,
                op_kwargs={'mode': MODE, 'config': config,
                           'model_config': model_config, 'att_name': attack_name}, )

    save_version_task = PythonOperator(
        task_id='save_version',
        python_callable=save_version,
        provide_context=True,
        op_kwargs={'mode': MODE, 'config': default_args['config'], 'model_config': default_args['model_config']},
    )
    
    data_collection_dag >> node_dag_0 >> [int_preprocessing_dag, cat_preprocessing_dag, str_preprocessing_tg] >> node_dag_1 >> [esoinn_train_model_dag, supervised_model_dag, supervised_binary_model_tg] >> save_version_task
    
    

    


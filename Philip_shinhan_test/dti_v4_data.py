from datetime import date, timedelta
from datetime import datetime as dt
import pandas as pd
import numpy as np
import os
import platform
import glob
import sys
from Philip_shinhan_test.dti_v4_utils import * 
from Philip_shinhan_test.dti_v4_query import *
from Philip_shinhan_test.dti_v4_prep import * 
pwd = os.path.dirname(os.path.realpath(__file__))

    # pwd = '/opt/airflow/dags/projects_esoinn/'

    
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
class DataCreation():
    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
    def __init__(self, mode, config, model_config, version, model_version=None, m_type=None, se_time_list=None, esoinn_attack_array=None):
        self.is_test = model_config['is_test']
        self.mode = mode
        self.db_check = DBCheck(mode, config, model_config)
        self.config = config
        self.model_config = model_config
#         self.today = date.today()
        # [oliver] 2023.02.06 UTC+9 적용
#         self.today = datetime.datetime.now()
        self.today = version  # datetime.datetime.now() + timedelta(hours=9)
        self.version = version.strftime("%Y%m%d%H%M%S")
        self.model_version = model_version
        self.end_time = self.today.strftime('%Y-%m-%d 00:00:00')
#         self.end_time = '2022-03-02 00:00:00'
        self.interval = model_config['interval']
        self.m_type = m_type
        if self.mode == 'train' or self.mode == 'data_sampling':
            self.data_limit = model_config['data_limit']
            self.attack_limit = model_config['attack_limit']
            self.normal_start_time = (self.today - timedelta(days = model_config['normal_days'])).strftime('%Y-%m-%d 00:00:00')
#             self.normal_start_time = '2022-03-01 00:00:00'
        
            # # default.dti_sh_demo_log의 min(logtime) : 2021-06-07 15:00:01
            self.attack_start_time = '2021-06-07 15:00:00'
            # # default.dti_sh_demo_log의 max(logtime) : 2021-06-15 06:59:49
            self.attack_end_time = '2021-06-15 07:00:00'
            # self.attack_start_time = (self.today - timedelta(days = model_config['attack_days'])).strftime('%Y-%m-%d %H:%M:%S')
            self.attack_array = model_config['attack_array'].split(', ')
        else:
            ################################################
            self.is_one_model = model_config['is_one_model']
            ################################################
            if self.m_type == 'cnn':
#                 self.pred_start_time = (self.today - model_config['prev_delta']).strftime('%Y-%m-%d %H:%M:%S')
#                 self.pred_end_time = (self.today - model_config['now_delta']).strftime('%Y-%m-%d %H:%M:%S')
#                 self.pred_start_time = se_time_list[0].strftime('%Y-%m-%d %H:%M:%S')
#                 self.pred_end_time = se_time_list[1].strftime('%Y-%m-%d %H:%M:%S')
                self.pred_start_time = datetime.datetime.strptime(se_time_list[0], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
                self.pred_end_time = (datetime.datetime.strptime(se_time_list[1], '%Y-%m-%d %H:%M:%S') + timedelta(minutes=1) * int(model_config['interval'].split()[0]) ).strftime('%Y-%m-%d %H:%M:%S')
#                 self.pred_end_time = datetime.datetime.strptime(se_time_list[1], '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d %H:%M:%S')
#                 self.pred_end_time = se_time_list[1]
#                 self.pred_start_time = '2022-01-01 00:00:00'
#                 self.pred_end_time = '2022-10-25 08:14:53'
                self.attack_array = esoinn_attack_array
            else:
                
                self.pred_start_time = (self.today - timedelta(minutes=model_config['prev_delta'])).strftime('%Y-%m-%d %H:%M:%S')
                self.pred_end_time = (self.today - timedelta(minutes=model_config['now_delta'])).strftime('%Y-%m-%d %H:%M:%S')
                # self.pred_start_time = (self.today - timedelta(days = 800)).strftime('%Y-%m-%d %H:%M:%S')
                # self.pred_end_time = self.end_time
#                 self.pred_start_time = '2021-06-08 18:00:00'
#                 self.pred_start_time = '2022-04-12 00:00:00'
#                 self.pred_end_time = '2022-04-12 00:01:00'

        self.index_cols = model_config['idx_cols']
        self.str_cols = None
        
        if self.mode == 'data_sampling':
            log.info('여긴 안올듯 data_smpling')
            self.make_sampling_data()
        elif self.mode == 'train':
            if self.m_type == 'cnn':
                self.cnn_train_data_load()
            else:
                self.train_days = model_config['train_days']
                log.info('여기서 train_data_load 진입')
                self.train_data_load()
        else:
            if self.m_type == 'cnn':
                self.cnn_pred_data_load()
            else:
                self.pred_data_load()
    
    def get_attack_data_for_training(self):
        print('******* 공격 데이터 불러오기 *******')  
        # # 고객사 공격 데이터 기반으로 보안팀이 만든 공격 데이터 파일을 불러 온다.
        
        attack_data_sql = """select logtime, src_ip, dst_ip, 
                replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(request)), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
        '[\-%.!@#$?,;:&*)(+=0-9]', ' ') as new_regex,
        hash
        
         from dti.attack_data_for_traind
            """
        try:
            result, meta = execute_ch(attack_data_sql, self.config, with_column_types = True)
        except Exception as err:
            print("[ERROR] {}".format(err))
        tot_attack_df = pd.DataFrame(result, columns=[m[0] for m in meta])
        
        try:
            f = open(pwd + '/detect/' + self.model_config['blck_f_nm'], 'r')
            black_key_line = f.readlines()
        except Excetion as err:
            log.error("[ERROR] {}".format(err))
        finally:
            f.close

        new_line = [i.strip().lower() for i in black_key_line] # + [i.strip().lower() for i in white_key_line]
        print("len(new_line) {}".format(len(new_line)))
        
        attck_list = [val.strip() for val in self.model_config['attack_array'].split(',')]
        
        tot_attack_data = pd.DataFrame()        
        for attack_label in attck_list:
            tmp_new_line = new_line.copy()
            attack_df = tot_attack_df[tot_attack_df['hash'] == attack_label]
            print("attack_df.shape {} : {}".format(attack_df.shape, attack_label))
            attack_data = self.filter_attack_data_for_training(attack_df, attack_label, tmp_new_line)
            print("attack_data.shape {}".format(attack_data.shape))
            attack_data = attack_data.sample(n=self.attack_limit, replace=True).reset_index(drop=True)
            # # 필요한 컬럼명으로 바꾸거나, 선택한다.
            # # 'lgtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label'
            attack_data.rename(columns={'logtime': 'lgtime', 'new_regex': 'agnt_qry', 'hash': 'label'}, inplace=True)
            attack_data = attack_data[['lgtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label']]
            attack_data['lgtime'] = pd.to_datetime(attack_data['lgtime'], format='%Y-%m-%d %H:%M:%S')
                
            ################################################################################
            ################################################################################
            print('ATTACK DATA PROPERTIES')
            print(attack_data.info())
            print(attack_data.head())
            print(attack_data['agnt_qry'].head())
            tot_attack_data = pd.concat([tot_attack_data, attack_data])
        return tot_attack_data
    
    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#  
    def get_attack_data_for_training2(self):
        print('******* 공격 데이터 불러오기 *******')   
        log.info('################### comming #####################3###')
        log.info('############## get_attack_dat_for_training2 #########')
        try:
            f = open(pwd + '/detect/' + self.model_config['blck_f_nm'], 'r')
            black_key_line = f.readlines()
        except Excetion as err:
            log.error("[ERROR] {}".format(err))
        finally:
            f.close

        new_line = [i.strip().lower() for i in black_key_line] # + [i.strip().lower() for i in white_key_line]
        print("len(new_line) {}".format(len(new_line)))
        
        attck_list = [val.strip() for val in self.model_config['attack_array'].split(',')]
        
        tot_attack_data = pd.DataFrame()        
        for attack_label in attck_list:
            tmp_new_line = new_line.copy()
            
            f = open(pwd + "/obj/train_data/attack_df/{}.pickle".format(attack_label), "rb")
            attack_df = pickle.load(f)
            f.close()
            print("attack_df.shape {} : {}".format(attack_df.shape, attack_label))
            attack_data = self.filter_attack_data_for_training(attack_df, attack_label, tmp_new_line)
            print("attack_data.shape {}".format(attack_data.shape))
            if attack_label in ['SQL_Injection']:
                attack_data = attack_data.sample(n=int(self.attack_limit * 1.5), replace=True).reset_index(drop=True)
            elif attack_label in ['Cross_Site_Scripting', 'Path_Traversal']:
                attack_data = attack_data.sample(n=int(self.attack_limit * 1.2), replace=True).reset_index(drop=True)
            else:
                attack_data = attack_data.sample(n=self.attack_limit, replace=True).reset_index(drop=True)
            
            ##################################################################################
            with open(pwd + "/obj/train_data/res_attack_data/{}.pickle".format(attack_label), "wb") as f:
                pickle.dump(attack_data, f)
            ##################################################################################
            # # 필요한 컬럼명으로 바꾸거나, 선택한다.
            # # 'lgtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label'
            attack_data.rename(columns={'logtime': 'lgtime', 'new_regex': 'agnt_qry', 'hash': 'label'}, inplace=True)
            attack_data = attack_data[['lgtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label']]
            attack_data['lgtime'] = pd.to_datetime(attack_data['lgtime'], format='%Y-%m-%d %H:%M:%S')
                
            print('ATTACK DATA PROPERTIES')
            print(attack_data.info())
            print(attack_data.head())
            print(attack_data['agnt_qry'].head())
            tot_attack_data = pd.concat([tot_attack_data, attack_data])
        return tot_attack_data
    
    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%# 
    def filter_attack_data_for_training(self, df, attack_label, tmp_new_line):
        log.info('################### comming #####################3###')
        log.info('############## filter_attack_data_for_training #########')
        column = 'new_regex'
        columns = [column]
        version = "00000000"
        m_type = None
        mode = 'train'
#         self.model_config['target_keyword_dict']
        target_keyword_dict = {
                            "Client_Server_Protocol_Manipulation" : ['scalaj', 'redirecturl', 'curl', 'guzzlehttp']
                            , "Exposure_of_Sensitive_Information_to_an_Unauthorized_Actor" : ['wp', 'getdata', 'yisouspider', 'manifest', 'getlist', 'scaninfo', 'pubmatic', 'crawler']
                            , "Forceful_Browsing" : ['bot', 'googlebot', 'php', 'robots', 'bingbot', 'uptimerobot', 'well', 'known', 'bidswitchbot', 'propfind', 'webdav']
                            , "Scanning_for_Vulnerable_Software" : ['urllib', 'zgrab']
                            , "SQL_Injection" : ['between']
                        }
        
        for key, val_list in target_keyword_dict.items():
            if key == attack_label:
                print(key, attack_label)
                continue
            for val in val_list:
                print(val)
                if val in tmp_new_line:
                    tmp_new_line.remove(val.strip().lower())
        print("len(tmp_new_line) : ", len(tmp_new_line))
        
        custom_voca = CustomTfidfVectorizer(max_features=len(tmp_new_line), vocabulary=tmp_new_line)
    
        str_df = df.copy()
        StrProcessing().make_hex_to_string(str_df, column)
        custom_voca.fit(str_df[column].values, feature_list=columns, save_version=version, m_type=m_type)
        strPrepData = custom_voca.transform(str_df[column].values, feature_list=columns, save_version=version, mode=mode, m_type=m_type)
        print("df.shape : {}, strPrepData.shape : {}".format(df.shape, strPrepData.shape))

        zro_list = []
        for idx, tfidf_val in strPrepData.iterrows():
            if sum(tfidf_val) == 0:
                zro_list.append(idx)

        non_zr_row_list = []
        for idx, row in df.iterrows():
            if idx not in zro_list:
                non_zr_row_list.append(row.to_dict())
    #         else:
    #             zr_row_list.append(row.to_dict())

        flted_df = pd.DataFrame(non_zr_row_list)
        print("flted_df.shape {}".format(flted_df.shape))
        return flted_df
        
#         return df[df['new_regex'].str.contains('|'.join(tmp_new_line))]

  
    def make_sampling_data(self):
        self.index_cols = self.model_config['cnn_idx_cols']
        print('NORMAL DATA START DATETIME: ', self.normal_start_time)
        print('NORMAL DATA END DATETIME  : ', self.end_time)
        print('DATA LIMIT: ', self.data_limit)
        print('ATTACK LIMIT: ', self.attack_limit)
        print('index_cols: ', self.index_cols)
        print('******* 정상 데이터 불러오기 *******')
        try:
            result, meta = execute_ch(normal_query(self.normal_start_time, self.end_time, self.data_limit, self.interval, self.index_cols), self.config, with_column_types = True)
        except Exception as err:
            print('ERROR: CHECK THE NORMAL DATA QUERY...\n{}\n'.format(err))
            print(normal_query(self.normal_start_time, self.end_time, self.data_limit, self.interval, self.index_cols))
            return                        
        if not result:
            print('ERROR: NORMAL DATA NOT FOUND. PLEASE CHECK YOUR DATETIME AND FILTER SETTINGS...')
            return
        feats = [m[0] for m in meta]
        normal_data = pd.DataFrame(result, columns = feats)
        print('NORMAL DATA PROPERTIES')
        
        print(normal_data.info())
        print(normal_data.head())
        print(normal_data['agnt_qry'].head())
        
        print('******* 공격 데이터 불러오기 *******')  
        # # 고객사 공격 데이터 기반으로 보안팀이 만든 공격 데이터 파일을 불러 온다.
        tot_attack_data = pd.DataFrame()
        file_list = glob.glob(pwd + "/detect/attack_data/*.csv")
        for f_path in file_list:
            print("f_path : {}".format(f_path))
            attack_data = pd.read_csv(f_path)
            if attack_data['hash'].iloc[0] not in self.attack_array:
                    continue
            
            attack_data = attack_data.sample(n=self.attack_limit, replace=True).reset_index(drop=True)
            
            # # 필요한 컬럼명으로 바꾸거나, 선택한다.
            # # 'lgtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label'
            attack_data.rename(columns={'logtime': 'lgtime', 'new_regex': 'agnt_qry', 'hash': 'label'}, inplace=True)
            attack_data['logtime'] = attack_data['lgtime'].copy()
            attack_data = attack_data[['lgtime', 'logtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label']]
            attack_data['lgtime'] = pd.to_datetime(attack_data['lgtime'], format='%Y-%m-%d %H:%M:%S')
            attack_data['logtime'] = pd.to_datetime(attack_data['logtime'], format='%Y-%m-%d %H:%M:%S')
            print('ATTACK DATA PROPERTIES')
            print(attack_data.info())
            print(attack_data.head())
            tot_attack_data = pd.concat([tot_attack_data, attack_data])
        
        tot_data = pd.concat([tot_attack_data, normal_data])
        print(tot_data.info())
        tot_data['lgtime'] = pd.to_datetime(tot_data['lgtime'], format='%Y-%m-%d %H:%M:%S', utc=True)
        tot_data['logtime'] = pd.to_datetime(tot_data['logtime'], format='%Y-%m-%d %H:%M:%S', utc=True)
        print(tot_data.info())
        # # 데이터 샘플링
        trn_df, prd_df = train_test_split(tot_data, split=self.model_config['trn_ratio'])
        os.makedirs(pwd + "/obj/sampling_data/", exist_ok=True)
        with open(pwd + "/obj/sampling_data/train_df.pickle", "wb") as f:
            print("\n\n:::::::::::::::::::::::: {} ::::::::::::::::::::::::".format("학습용 데이터 프레임 저장"))
            pickle.dump(trn_df, f)
            print(trn_df.info())
            print(trn_df.head())
            keys, cnts = np.unique(trn_df.label, return_counts=True)
            print("keys : {}\ncnt : {}".format(keys, cnts))
            print("\n\n:::::::::::::::::::::::: {} ::::::::::::::::::::::::".format("학습용 데이터 프레임 저장 완료"))
        
        with open(pwd + "/obj/sampling_data/predc_df.pickle", "wb") as f:
            print("\n\n:::::::::::::::::::::::: {} ::::::::::::::::::::::::".format("예측용 데이터 프레임 저장"))
            pickle.dump(prd_df, f)
            print(prd_df.info())
            print(prd_df.head())
            keys, cnts = np.unique(prd_df.label, return_counts=True)
            print("keys : {}\ncnt : {}".format(keys, cnts))
            print("\n\n:::::::::::::::::::::::: {} ::::::::::::::::::::::::".format("예측용 데이터 프레임 저장 완료"))

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#              
    def train_data_load(self):
        if self.is_test:
            print("{} {} {}".format("*" * 30, "학습데이터 불러오기", "*" * 30))
            try:
                f = open(pwd + "/obj/sampling_data/train_df.pickle", "rb")
                self.total_data = pickle.load(f)
                f.close()
            except Exception as err:
                print("[train_data_load ERROR] {}".format(err))

            print(self.total_data.info())
            print(self.total_data.head())
            print(self.total_data['agnt_qry'].head())
        else:            
            log.info("{} {} {}".format("*" * 10, "학습데이터 불러오기", "*" * 10))
            normal_data = pd.DataFrame()
            for i in range(self.train_days):
                st_time = dt.strptime(self.normal_start_time, '%Y-%m-%d 00:00:00') - timedelta(days=i)
                en_time = dt.strptime(self.end_time, '%Y-%m-%d 00:00:00') - timedelta(days=i)
                
                print('NORMAL DATA START DATETIME: ', st_time)
                print('NORMAL DATA END DATETIME  : ', en_time)
                print('DATA LIMIT: ', self.data_limit)
                
                try:
                    log.info('############ normal_data comming success ##########')
                    result, meta = execute_ch(normal_query(st_time, en_time, self.data_limit, self.interval, self.index_cols), self.config, with_column_types = True)
                except:
                    log.info('############ normal_data comming fail ##########')
                    log.error('ERROR: CHECK THE NORMAL DATA QUERY...')
                    log.error(normal_query(self.normal_start_time, self.end_time, self.data_limit, self.interval, self.index_cols))
                    return                        
                if not result:
                    print('ERROR: NORMAL DATA NOT FOUND. PLEASE CHECK YOUR DATETIME AND FILTER SETTINGS...')
                    return
                feats = [m[0] for m in meta]
                normal_df = pd.DataFrame(result, columns = feats)
                
                normal_data = pd.concat([normal_data, normal_df])
                log.info('%%%%%%%%%%%%%%%%%%%% Normal query step {} ################'.format(i))
            log.info('%%%%%%%%%%%%%%%%%%%% Normal query comming end ################')
            print('NORMAL DATA PROPERTIES')
            print(normal_data.info())
            normal_data['lgtime'] = pd.to_datetime(normal_data['lgtime'], format='%Y-%m-%d %H:%M:%S')
            print(normal_data.info())
            print(normal_data.head())
            print(normal_data['agnt_qry'].head())
            
            ################################################################################
            ################################################################################
            print('******* 공격 데이터 불러오기 *******')  
            tot_attack_data = self.get_attack_data_for_training2()

            self.total_data = pd.concat([normal_data, tot_attack_data]).convert_dtypes()
        
        self.total_data.reset_index(drop=True, inplace=True)
        self.total_data.reset_index(inplace=True)
        
        keys, counts = np.unique(self.total_data.label, return_counts=True)
        cluster_uniq = "keys : {}, cnts : {}".format(keys, counts)
        print("keys : {}\ncnts : {}".format(keys, counts))
        ########## [datetime timezone  ->  datetime] ##########
        datetime_tz_col = list(self.total_data.select_dtypes('datetimetz'))
        for col in datetime_tz_col:
            self.total_data[col] = pd.to_datetime(self.total_data[col]).dt.tz_localize(None)
            
        train_data, self.str_cols = self.__type_check(self.total_data)

        return train_data

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#         
    def pred_data_load(self):
        if self.is_test:
            print("{} {} {}".format("*" * 30, "예측 데이터 불러오기", "*" * 30))
            try:
                f = open(pwd + "/obj/sampling_data/predc_df.pickle", "rb")
                self.pred_data = pickle.load(f)
                f.close()
            except Exception as err:
                print("[pred_data_load ERROR] {}".format(err))

            print(self.pred_data.info())
            self.pred_data = self.pred_data.drop('label', axis=1)
            print(self.pred_data.info())
            print(self.pred_data.head())
            print(self.pred_data['agnt_qry'].head())
            # save pred time for CNN
            se_time_list = [str(min(self.pred_data['logtime'])), str(max(self.pred_data['logtime']))]
        else:

            print('PREDICT DATA START DATETIME: ', self.pred_start_time)
            print('PREDICT DATA END DATETIME  : ', self.pred_end_time)
            print('INTERVAL                   : ', self.interval)

            # save pred time for CNN
        #         se_time_list = [self.pred_start_time, self.pred_end_time + timedelta(seconds=59)]
            se_time_list = [self.pred_start_time, self.pred_end_time]

            print('******* 예측 데이터 불러오기 *******')
            # # st query, agent, host, path exceptions 가져오는 것 추가 by terry 20220818 
            exception_result, meta = execute_ch(""" select * from dti.mysql_exception """, self.config, with_column_types=True)
            feats = [m[0] for m in meta]
            excetpion_df = pd.DataFrame(exception_result,columns=feats)

            http_query_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_query']
            http_query_ex = '|'.join(http_query_ex['keyword'].values)

            http_agent_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_agent']
            http_agent_ex = '|'.join(http_agent_ex['keyword'].values)

            http_host_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_host']
            http_host_ex = '|'.join(http_host_ex['keyword'].values)

            http_path_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_path']
            http_path_ex = '|'.join(http_path_ex['keyword'].values)
            # # en query, agent, host, path exceptions 가져오는 것 추가 by terry 20220818 
            
            # # st src_ip, dst_ip exceptions 가져오는 것 추가(신한 협업 요청) by terry 20230116 
            src_ip_ex = excetpion_df[excetpion_df['selectcolumn'] == 'src_ip']
            src_ip_ex = '|'.join(src_ip_ex['keyword'].values)
            
            dst_ip_ex = excetpion_df[excetpion_df['selectcolumn'] == 'dst_ip']
            dst_ip_ex = '|'.join(dst_ip_ex['keyword'].values)
            # # en src_ip, dst_ip exceptions 가져오는 것 추가(신한 협업 요청) by terry 20230116 

            try:
#                 # # SH_v2 query 기반 by terry 20220818
#                 pred_sql = predict_query(self.pred_start_time, self.pred_end_time, http_agent_ex, http_path_ex, http_query_ex, http_host_ex, self.interval, self.index_cols)
                # # SH_v2 query 기반 src_ip, dst_ip exceptions 가져오는 것 추가(신한 협업 요청) by terry 20230116
                pred_sql = predict_query2(self.pred_start_time, self.pred_end_time, http_agent_ex, http_path_ex, http_query_ex, http_host_ex, src_ip_ex, dst_ip_ex, self.interval, self.index_cols)

                result, meta = execute_ch(pred_sql, self.config, with_column_types=True)

            except Exception as err:
                print('ERROR: CHECK THE PREDICT DATA QUERY...\n[ERROR]', err)
        #             print(get_culumns_query(self.pred_start_time, self.pred_end_time, self.interval, self.index_cols))
                print("\npred_sql :::::::::::::::::::\n{}".format(pred_sql))
                return

            if not result:
                print('ERROR: PREDICT DATA NOT FOUND. PLEASE CHECK YOUR DATETIME AND FILTER SETTINGS...')
                return

            feats = [m[0] for m in meta]
            self.pred_data = pd.DataFrame(result, columns = feats)

            print('PREDICT DATA PROPERTIES')
            size_data = "{}, {}, {}, {}\n".format(self.pred_start_time, self.pred_end_time, sys.getsizeof(self.pred_data), len(self.pred_data))
            with open(pwd + "/logs/size_of_data.csv", "a") as f:
                f.write(size_data)
            
            print(size_data)
            print(self.pred_data.info())
            print(self.pred_data.head())
            print(self.pred_data['agnt_qry'].head())
        
        # save pred time for CNN
        save_filter_list(list=se_time_list, version=self.version, mode=self.mode, l_type='se_time')
        print("SAVE SE TIME LIST {st} ~ {ed}".format(st=se_time_list[0],
                                                            ed=se_time_list[1]))
        self.pred_data.reset_index(inplace=True)
        
        ########## [datetime timezone  ->  datetime] ##########
        datetime_tz_col = list(self.pred_data.select_dtypes('datetimetz'))
        for col in datetime_tz_col:
            self.pred_data[col] = pd.to_datetime(self.pred_data[col]).dt.tz_localize(None)
            
        self.pred_data = self.pred_data.convert_dtypes()
        
        # self.__type_check(self.pred_data)
        pred_data, self.str_cols = self.__type_check(self.pred_data)

    def cnn_train_data_load(self):
        self.index_cols = self.model_config['cnn_idx_cols']
        self.model_config['table_number'] = 'cnn_' + self.model_config['table_number']
        self.model_config['table_category'] = 'cnn_' + self.model_config['table_category']
        self.model_config['table_string'] = 'cnn_' + self.model_config['table_string']

        if self.is_test:
            print("{} {} {}".format("*" * 30, "CNN 학습 데이터 불러오기", "*" * 30))
            try:
                f = open(pwd + "/obj/sampling_data/train_df.pickle", "rb")
                self.total_data = pickle.load(f)
                f.close()
            except Exception as err:
                print("[CNN train_data_load ERROR] {}".format(err))

            print(self.total_data.info())
            print(self.total_data.head())
            print(self.total_data['agnt_qry'].head())
        else:
            print('NORMAL DATA START DATETIME: ', self.normal_start_time)
            print('NORMAL DATA END DATETIME  : ', self.end_time)
        #         print('ATTACK DATA START DATETIME: ', self.attack_start_time)
        #         print('ATTACK DATA END DATETIME  : ', self.attack_end_time)
            print('DATA LIMIT: ', self.data_limit)
            print('******* 정상 데이터 불러오기 *******')

            try:
                result, meta = execute_ch(
                    normal_query(self.normal_start_time, self.end_time, self.data_limit, self.interval, self.index_cols),
                    self.config, with_column_types=True)
            except:
                print('ERROR: CHECK THE NORMAL DATA QUERY...')
                print(normal_query(self.normal_start_time, self.end_time, self.data_limit, self.interval, self.index_cols))
                return
            if not result:
                print('ERROR: NORMAL DATA NOT FOUND. PLEASE CHECK YOUR DATETIME AND FILTER SETTINGS...')
                return
            feats = [m[0] for m in meta]
            normal_data = pd.DataFrame(result, columns=feats)
            print('NORMAL DATA PROPERTIES')
            print(normal_data.info())
            print(normal_data.head())
            print(normal_data['agnt_qry'].head())

            print('******* 공격 데이터 불러오기 *******')  
            # # 고객사 공격 데이터 기반으로 보안팀이 만든 공격 데이터 파일을 불러 온다.
            tot_attack_data = pd.DataFrame()
            file_list = glob.glob(pwd + "/detect/attack_data/*.csv")
            for f_path in file_list:
                print("f_path : {}".format(f_path))
                attack_data = pd.read_csv(f_path)
                if attack_data['hash'].iloc[0] not in self.attack_array:
                    continue

                # # 필요한 컬럼명으로 바꾸거나, 선택한다.
                # # 'lgtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label'
                attack_data.rename(columns={'logtime': 'lgtime', 'new_regex': 'agnt_qry', 'hash': 'label'}, inplace=True)
                attack_data['logtime'] = attack_data['lgtime'].copy()
                attack_data = attack_data[['lgtime', 'logtime', 'src_ip', 'dst_ip', 'agnt_qry', 'label']]
                attack_data['lgtime'] = pd.to_datetime(attack_data['lgtime'], format='%Y-%m-%d %H:%M:%S')
                attack_data['logtime'] = pd.to_datetime(attack_data['logtime'], format='%Y-%m-%d %H:%M:%S')
                print('ATTACK DATA PROPERTIES')
                print(attack_data.info())
                print(attack_data.head())
                print(attack_data['agnt_qry'].head())
                tot_attack_data = pd.concat([tot_attack_data, attack_data])

            self.total_data = pd.concat([normal_data, tot_attack_data]).convert_dtypes()
        
        self.total_data.reset_index(drop=True, inplace=True)
        self.total_data.reset_index(inplace=True)

        ########## [datetime timezone  ->  datetime] ##########
        datetime_tz_col = list(self.total_data.select_dtypes('datetimetz'))
        for col in datetime_tz_col:
            self.total_data[col] = pd.to_datetime(self.total_data[col]).dt.tz_localize(None)

        train_data, self.str_cols = self.__type_check(self.total_data)

        return train_data

    def cnn_pred_data_load(self):
        self.index_cols = self.model_config['cnn_idx_cols']
        self.model_config['table_number'] = 'cnn_' + self.model_config['table_number']
        self.model_config['table_category'] = 'cnn_' + self.model_config['table_category']
        self.model_config['table_string'] = 'cnn_' + self.model_config['table_string']

        if self.is_test:
            print("{} {} {}".format("*" * 30, "CNN 예측 데이터 불러오기", "*" * 30))
            try:
                f = open(pwd + "/obj/sampling_data/predc_df.pickle", "rb")
                self.pred_data = pickle.load(f)
                f.close()
            except Exception as err:
                print("[CNN pred_data_load ERROR] {}".format(err))

            print(self.pred_data.info())
            self.pred_data['lgtime'] = pd.to_datetime(self.pred_data['lgtime'], format='%Y-%m-%d %H:%M:%S', utc=True)
            self.pred_data['logtime'] = pd.to_datetime(self.pred_data['logtime'], format='%Y-%m-%d %H:%M:%S', utc=True)
            self.pred_data = self.pred_data.loc[(self.pred_data['logtime'] >= self.pred_start_time) & (self.pred_data['logtime'] < self.pred_end_time)]
            print(self.pred_data.info())
            self.pred_data = self.pred_data.drop('label', axis=1)
            print(self.pred_data.info())
            print(self.pred_data.head())
            print(self.pred_data['agnt_qry'].head())
        else:
            print('PREDICT DATA START DATETIME: ', self.pred_start_time)
            print('PREDICT DATA END DATETIME  : ', self.pred_end_time)
            print('INTERVAL                   : ', self.interval)

            print('******* CNN MODEL 예측 데이터 불러오기 *******')
        #         # # st query, agent, host, path exceptions 가져오는 것 추가 by terry 20220818 
            exception_result, meta = execute_ch(""" select * from dti.mysql_exception """, self.config, with_column_types=True)
            feats = [m[0] for m in meta]
            excetpion_df = pd.DataFrame(exception_result,columns=feats)

            http_query_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_query']
            http_query_ex = '|'.join(http_query_ex['keyword'].values)

            http_agent_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_agent']
            http_agent_ex = '|'.join(http_agent_ex['keyword'].values)

            http_host_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_host']
            http_host_ex = '|'.join(http_host_ex['keyword'].values)

            http_path_ex = excetpion_df[excetpion_df['selectcolumn'] == 'http_path']
            http_path_ex = '|'.join(http_path_ex['keyword'].values)
        #         # # en query, agent, host, path exceptions 가져오는 것 추가 by terry 20220818 

            try:
                # # SH_v2 query 기반 by terry 20220818
                pred_sql = predict_query(self.pred_start_time, self.pred_end_time, http_agent_ex, http_path_ex, http_query_ex, http_host_ex, self.interval, self.index_cols)

                result, meta = execute_ch(pred_sql, self.config, with_column_types=True)

            except Exception as err:
                print('ERROR: CHECK THE PREDICT DATA QUERY...\n[ERROR]', err)
        #             print(get_culumns_query(self.pred_start_time, self.pred_end_time, self.interval, self.index_cols))
                print("\npred_sql :::::::::::::::::::\n{}".format(pred_sql))
                return

            if not result:
                print('ERROR: PREDICT DATA NOT FOUND. PLEASE CHECK YOUR DATETIME AND FILTER SETTINGS...')
                return

            feats = [m[0] for m in meta]
            self.pred_data = pd.DataFrame(result, columns = feats)

            print('PREDICT DATA PROPERTIES')
            print(self.pred_data.info())
            print(self.pred_data.head())
            print(self.pred_data['agnt_qry'].head())
        
        self.pred_data.reset_index(inplace=True)
        
        ########## [datetime timezone  ->  datetime] ##########
        datetime_tz_col = list(self.pred_data.select_dtypes('datetimetz'))
        for col in datetime_tz_col:
            self.pred_data[col] = pd.to_datetime(self.pred_data[col]).dt.tz_localize(None)

        self.pred_data = self.pred_data.convert_dtypes()
        print("self.pred_data.head(100) :::::::::::::::::::::::::: \n{}".format(self.pred_data.head(100)))
        print("self.pred_data.tail(100) :::::::::::::::::::::::::: \n{}".format(self.pred_data.tail(100)))
        
        ########### ESOINN AI LABEL MERGE #############
        ## ESOINN Result Data load
        esoinn_sql = get_data_collection_column_query(
            table_name=self.model_config['db_name'] + '.' + self.model_config['esoinn_result_table'],
            columns=' index, ' + self.model_config['idx_cols'] + ', ai_label as esoinn_label', version=self.version)
#         esoinn_sql = esoinn_sql + " and (ai_label != 'anomaly' and ai_label != 'normal')"
        if self.is_one_model:
            esoinn_sql += " and (ai_label != 'anomaly')"
        else:
            esoinn_sql += " and (ai_label != 'anomaly' and ai_label != 'normal')"
        
        print("esoinn_sql ::::::::::::::::::::::::::::::::: \n{}".format(esoinn_sql))
        esoinn_data, esoinn_meta = execute_ch(esoinn_sql, self.config, param=None, with_column_types=True)
        esoinn_df = pd.DataFrame(data=esoinn_data, columns=[m[0] for m in esoinn_meta])

        print("ESOINN Data Shape {}".format(esoinn_df.shape))
        print("esoinn_df.head(100) :::::::::::::::::::::::::: \n{}".format(esoinn_df.head(100)))
        print("::::::::::::::::::::::::::::\nesoinn_df.info() \n{}".format(esoinn_df.info()))
        print("::::::::::::::::::::::::::::\nself.pred_data.info() \n{}".format(self.pred_data.info()))

#         self.pred_data = pd.merge(esoinn_df, self.pred_data, on=['index'] + self.model_config['idx_cols'].split(', ')).reset_index(drop=True)
#         self.pred_data = pd.merge(esoinn_df, self.pred_data, on=self.model_config['idx_cols'].split(', ')).reset_index(drop=True)
        self.pred_data = pd.merge(esoinn_df, self.pred_data, on=['index'] + self.model_config['idx_cols'].split(', ')).reset_index(drop=True)
        self.pred_data = self.pred_data.convert_dtypes()
        print("pred data info", self.pred_data.info)
        # self.__type_check(self.pred_data)
        pred_data, self.str_cols = self.__type_check(self.pred_data)

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
    def __type_check(self, df, cat_threshold=10):
        df.reset_index(drop = True, inplace = True)
        if self.mode == 'train':
            ########## [label 데이터 분리] ##########
            X_data = df.drop('label', axis = 1)
            self.label_data = df[['label']].astype('string')
        else:
            if self.m_type == 'cnn':
                X_data = df.drop('esoinn_label', axis = 1)
                self.label_data = df[['esoinn_label']].astype('string')
            else:
                X_data = df.copy()
        
        ########## [datetime 데이터 분리] ##########
        X_data['version'] = self.version
        X_data['version'] = X_data['version'].astype('string')
        print(X_data.info())
        self.index_cols = ['index'] + self.index_cols.split(', ') + ['version']
        # print(self.index_cols)
        self.index_data = X_data[self.index_cols]

        if self.mode=='train':
            self.index_cols = self.index_cols + ['label']
        else:
            if self.m_type =='cnn':
                self.index_cols = self.index_cols + ['esoinn_label']

        print(X_data.info())
        X_data.drop(list(self.index_data), axis=1, inplace=True)

        if self.m_type == 'cnn':
            dt_list = ['cnn_num', 'cnn_cat', 'cnn_str']
        else:
            dt_list = ['num', 'cat', 'str']

        # if self.m_type !='cnn':
        if self.mode == 'train':
            ########## [유니크값이 2개 이상 100개 이하인 데이터 -> 카테고리 데이터] ##########
            for i in list(X_data):
                if X_data[i].nunique() >= 2 and X_data[i].nunique() <= cat_threshold:
                    X_data[i] = X_data[i].astype('category')

            ########## [num, str, category 데이터 분리] ##########
            self.num_data = X_data.select_dtypes('number')
#             self.str_data = X_data.select_dtypes('string')
            self.str_data = X_data.select_dtypes(include=['string', 'object'])
            self.cat_data = X_data.select_dtypes('category')

            print("NUM DATA", list(self.num_data))
            print("##############################")
            print("CAT DATA", list(self.cat_data))
            print("##############################")
            print("STR DATA", list(self.str_data))

            
            log.info('$$$$$$$$$$$$$$$$$$ we are here help me #########################')
            log.info('{}'.format(dt_list))
            log.info('$$$$$$$$$$$$$$$$$$ we are here help me end  #########################')
            for d_type in dt_list:
                if d_type == 'num' or d_type == 'cnn_num':
                    save_filter_list(list=list(self.num_data), version=self.version, d_type=d_type, l_type='data_collect')
                elif d_type == 'cat' or d_type == 'cnn_cat':
                    save_filter_list(list=list(self.cat_data), version=self.version, d_type=d_type, l_type='data_collect')
                elif d_type == 'str' or d_type == 'cnn_str':
                    save_filter_list(list=list(self.str_data), version=self.version, d_type=d_type, l_type='data_collect')

        else:
            # if self.m_type=='cnn':
            for d_type in dt_list:
                if d_type == 'num' or d_type == 'cnn_num':
                    num_list = load_filter_list(version=self.model_version, l_type='data_collect', d_type=d_type)
                elif d_type == 'cat' or d_type == 'cnn_cat':
                    cat_list = load_filter_list(version=self.model_version, l_type='data_collect', d_type=d_type)
                elif d_type == 'str' or d_type == 'cnn_str':
                    str_list = load_filter_list(version=self.model_version, l_type='data_collect', d_type=d_type)

            print("load num list", num_list)
            print("##############################")
            print("load cat list", cat_list)
            print("##############################")
            print("load str list", str_list)

            X_data[num_list] = X_data[num_list].astype('int')
            X_data[cat_list] = X_data[cat_list].astype('category')
            X_data[str_list] = X_data[str_list].astype('string')

            self.num_data = X_data.select_dtypes('number')
#             self.str_data = X_data.select_dtypes('string')
            self.str_data = X_data.select_dtypes(include=['string', 'object'])
            self.cat_data = X_data.select_dtypes('category')
        
            print("NUM DATA", list(self.num_data))
            print("##############################")
            print("CAT DATA", list(self.cat_data))
            print("##############################")
            print("STR DATA", list(self.str_data))

        
        self.__fill_null()
        if self.mode=='train' or self.m_type=='cnn':
            self.num_data = pd.concat([self.num_data, self.label_data], axis=1)
            self.str_data = pd.concat([self.str_data, self.label_data], axis=1)
            self.cat_data = pd.concat([self.cat_data, self.label_data], axis=1)

        ### version overlap check ###
        try:
            chk_sql = get_data_collection_column_query(
                table_name=self.model_config['db_name'] + '.' + self.model_config['table_number'], columns='version',
                version=self.version)
            chk_data, chk_meta = execute_ch(chk_sql, self.config, param=None, with_column_types=True)
            chk_num_df = pd.DataFrame(data=chk_data, columns=[m[0] for m in chk_meta])
        except Exception as err:
            chk_num_df = pd.DataFrame(columns=['version'])
            print("[ERROR check version overlap] {}".format(err))
            pass
        
        try:
            chk_sql = get_data_collection_column_query(
                table_name=self.model_config['db_name'] + '.' + self.model_config['table_string'], columns='version',
                version=self.version)
            chk_data, chk_meta = execute_ch(chk_sql, self.config, param=None, with_column_types=True)
            chk_df = pd.DataFrame(data=chk_data, columns=[m[0] for m in chk_meta])
        except Exception as err:
            chk_df = pd.DataFrame(columns=['version'])
            print("[ERROR check version overlap] {}".format(err))
            pass
        
        try:
            chk_sql = get_data_collection_column_query(
                table_name=self.model_config['db_name'] + '.' + self.model_config['table_category'], columns='version',
                version=self.version)
            chk_data, chk_meta = execute_ch(chk_sql, self.config, param=None, with_column_types=True)
            chk_cat_df = pd.DataFrame(data=chk_data, columns=[m[0] for m in chk_meta])
        except Exception as err:
            chk_cat_df = pd.DataFrame(columns=['version'])
            print("[ERROR check version overlap] {}".format(err))
            pass
        
        print("[check version overlap is DONE]")
        if len(chk_df['version']) > 0:
            if self.version in chk_num_df['version'].to_list():
                print("NUM version [{}] already exists".format(self.version))
                pass
            else:
                try:
                    order = self.db_check.create_table(self.index_cols, list(self.index_data) + list(self.num_data), database_name=self.model_config['db_name'], table_n=self.model_config['table_number'])
                    number_insert = execute_ch('insert into {} values'.format(self.model_config['db_name']+'.'+self.model_config['table_number']), self.config, pd.concat([self.index_data, self.num_data], axis=1)[order].values.tolist())
                    print('NUMBER : ', list(self.num_data), number_insert)
                except Exception as err:
                    print("[ERROR insert num] {}".format(err))
                    pass
                
            if self.version in chk_df['version'].to_list():
                print("STRING version [{}] already exists".format(self.version))
                pass
            else:
                try:
                    order = self.db_check.create_table(self.index_cols, list(self.index_data) + list(self.str_data), database_name=self.model_config['db_name'], table_n=self.model_config['table_string'])
                    string_insert = execute_ch('insert into {} values'.format(self.model_config['db_name']+'.'+self.model_config['table_string']), self.config, pd.concat([self.index_data, self.str_data], axis=1)[order].values.tolist())
                    print('STRING : ', list(self.str_data), string_insert)
                except Exception as err:
                    print("[ERROR insert string] {}".format(err))
                    pass
                
            if self.version in chk_cat_df['version'].to_list():
                print("CAT version [{}] already exists".format(self.version))
                pass
            else:
                try:
                    order = self.db_check.create_table(self.index_cols, list(self.index_data) + list(self.cat_data), database_name=self.model_config['db_name'], table_n=self.model_config['table_category'])
                    category_insert = execute_ch('insert into {} values'.format(self.model_config['db_name']+'.'+self.model_config['table_category']), self.config, pd.concat([self.index_data, self.cat_data.astype('string')], axis=1)[order].values.tolist())
                    print('CATEGORY : ', list(self.cat_data), category_insert)
                except Exception as err:
                    print("[ERROR insert cat] {}".format(err))
                    pass
        else:
            try:
                order = self.db_check.create_table(self.index_cols, list(self.index_data) + list(self.num_data), database_name=self.model_config['db_name'], table_n=self.model_config['table_number'])
                number_insert = execute_ch('insert into {} values'.format(self.model_config['db_name']+'.'+self.model_config['table_number']), self.config, pd.concat([self.index_data, self.num_data], axis=1)[order].values.tolist())
                print('NUMBER : ', list(self.num_data), number_insert)
            except:
                raise
            
            try:
                order = self.db_check.create_table(self.index_cols, list(self.index_data) + list(self.str_data), database_name=self.model_config['db_name'], table_n=self.model_config['table_string'])
                string_insert = execute_ch('insert into {} values'.format(self.model_config['db_name']+'.'+self.model_config['table_string']), self.config, pd.concat([self.index_data, self.str_data], axis=1)[order].values.tolist())
                print('STRING : ', list(self.str_data), string_insert)
            except:
                raise
            
            try:
                order = self.db_check.create_table(self.index_cols, list(self.index_data) + list(self.cat_data), database_name=self.model_config['db_name'], table_n=self.model_config['table_category'])
                category_insert = execute_ch('insert into {} values'.format(self.model_config['db_name']+'.'+self.model_config['table_category']), self.config, pd.concat([self.index_data, self.cat_data.astype('string')], axis=1)[order].values.tolist())
                print('CATEGORY : ', list(self.cat_data), category_insert)
            except:
                raise
        print('INDEXES : ', list(self.index_data))
        
        return X_data, list(self.str_data)

    def __fill_null(self):
        ########## [데이터 유형별 null 값 채우기] ##########
#         self.dt_data = self.dt_data.fillna('')
        self.num_data = self.num_data.fillna('-1')
        self.str_data = self.str_data.fillna('-')
        for col in self.cat_data:
            self.cat_data[col] = self.cat_data[col].cat.add_categories("empty").fillna("empty")
 
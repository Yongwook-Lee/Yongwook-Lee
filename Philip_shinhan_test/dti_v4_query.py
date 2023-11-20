def attack_query(attack, start_date, end_date, limit, interval, idx_cols='logtime, src_ip, dst_ip'):
# # plan B
# def attack_query(start_date, end_date, limit, interval, credential_rule, beaconing_rule, idx_cols='logtime, src_ip, dst_ip'):
#     # # plan A : CTiLab 내부 공격 데이터 default.dti_sh_demo_log
    sql = """
    select
        --toStartOfInterval(logtime, INTERVAL {interval}) as {idx_cols},
        logtime as {idx_cols},
        
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\-%./!@#$?,;:&*)(+=0-9_]', ' ')), ' ') as agent,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(splitByString('.php', http_query)[2]), '/..', ' pathsearcherdetected '), '[\-%./!@#$?,;:&*)(+=0-9_]', ' ')), ' ') as query,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(arrayStringConcat(arraySlice(splitByString('.php', http_query), 2), ' ')), '/..', ' pathsearcherdetected '), '[\-%./!@#$?,;:&*)(+=0-9_]', ' ')), ' ') as query,
        arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(arrayStringConcat([http_agent, splitByString('.php', http_query)[2]], ' ')), '/..', ' pathsearcherdetected '), '[\-%./!@#$?,;:&*)(+=0-9]', ' ')), ' ') as agnt_qry,
        '{attack}' as label
    
    from default.dti_sh_demo_log
        where (logtime >= '{start_date}' and logtime < '{end_date}')
            and hash == '{attack}'
        group by {idx_cols}
        limit {limit}
    """.format(interval=interval, attack=attack, start_date=start_date, end_date=end_date, limit=limit, idx_cols=idx_cols)
#     print("attack_query {}\n{}".format(">" * 50, sql))
    return sql


def normal_query(start_date, end_date, limit, interval, idx_cols='logtime, src_ip, dst_ip'):  
    #     # # plan A : CTiLab 내부 공격 데이터 default.dti_sh_demo_log
    if idx_cols == 'logtime, logtime, src_ip, dst_ip':
        idx_cols = 'logtime, addHours(logtime, 9) as logtime, src_ip, dst_ip'
        
    sql = """
 select toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols}, 
        
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query,
        arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
        '[\-%./!@#$?,;:&*)(+=0-9]', ' ')), ' ') as agnt_qry,
        'normal' as label
        
 from default.dti_qm_httpd
 where (logtime between toDateTime('{start_date}') and subtractHours(toDateTime('{end_date}'), 18))
         -- 20230515 신한 요청 사항 : http_server = 'BigIP'는 탐지된 것으로 학습에서도 제외한다.
        and not (http_host = '-' and http_agent = '-' and http_query = '-' and http_path = '-' and http_server = 'BigIP')
        -- and http_server != 'BigIP'
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_blockd
            where (logtime between '{start_date}' and '{end_date}')
            )
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_wafd
            where (logtime between '{start_date}' and '{end_date}')
            )
group by {idx_cols}                        
 limit {limit}
   
union all

 select toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols}, 
        
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query,
        arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
        '[\-%./!@#$?,;:&*)(+=0-9]', ' ')), ' ') as agnt_qry,
        'normal' as label
        
 from default.dti_qm_httpd
 where (logtime between addHours(toDateTime('{start_date}'), 6) and subtractHours(toDateTime('{end_date}'), 12))
         -- 20230515 신한 요청 사항 : http_server = 'BigIP'는 탐지된 것으로 학습에서도 제외한다.
         and not (http_host = '-' and http_agent = '-' and http_query = '-' and http_path = '-' and http_server = 'BigIP')
         -- and http_server != 'BigIP'
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_blockd
            where (logtime between '{start_date}' and '{end_date}')
            )
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_wafd
            where (logtime between '{start_date}' and '{end_date}')
            )
group by {idx_cols}                        
 limit {limit}
 
union all
   
 select toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols}, 
        
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query,
        arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
        '[\-%./!@#$?,;:&*)(+=0-9]', ' ')), ' ') as agnt_qry,
        'normal' as label
        
 from default.dti_qm_httpd
 where (logtime between addHours(toDateTime('{start_date}'), 12) and subtractHours(toDateTime('{end_date}'), 6))
         -- 20230515 신한 요청 사항 : http_server = 'BigIP'는 탐지된 것으로 학습에서도 제외한다.
         and not (http_host = '-' and http_agent = '-' and http_query = '-' and http_path = '-' and http_server = 'BigIP')
         -- and http_server != 'BigIP'
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_blockd
            where (logtime between '{start_date}' and '{end_date}')
            )
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_wafd
            where (logtime between '{start_date}' and '{end_date}')
            )
group by {idx_cols}                        
 limit {limit}
 
union all
   
 select toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols}, 
        
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query,
        arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
        '[\-%./!@#$?,;:&*)(+=0-9]', ' ')), ' ') as agnt_qry,
        'normal' as label
        
 from default.dti_qm_httpd
 where (logtime between addHours(toDateTime('{start_date}'), 18) and toDateTime('{end_date}'))
         -- 20230515 신한 요청 사항 : http_server = 'BigIP'는 탐지된 것으로 학습에서도 제외한다.
         and not (http_host = '-' and http_agent = '-' and http_query = '-' and http_path = '-' and http_server = 'BigIP')
         -- and http_server != 'BigIP'
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_blockd
            where (logtime between '{start_date}' and '{end_date}')
            )
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_wafd
            where (logtime between '{start_date}' and '{end_date}')
            )
group by {idx_cols}           
 limit {limit}
 
 """.format(interval=interval, start_date=start_date, end_date=end_date, limit=limit, idx_cols=idx_cols)
    
#     print("normal_query {}\n{}".format(">" * 50, sql))
    return sql

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def get_culumns_query(start_date, end_date, interval, idx_cols='logtime, src_ip, dst_ip'):
    sql = """
    select
        toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols},
        
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
        --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query
        arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_agent, http_query], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
        '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agnt_qry
        
    from default.dti_qm_httpd
        where (logtime >= subtractHours(toDateTime('{start_date}'), 9) and logtime < subtractHours(toDateTime('{end_date}'), 9))
    group by {idx_cols}
    """.format(interval=interval, start_date=start_date, end_date=end_date, idx_cols=idx_cols)
    return sql

# # def predict_query(start_date, end_date, interval, idx_cols='logtime, src_ip, dst_ip'):
# # # plan B : 신한 Real 공격 데이터 default.dti_qm_httpd
# def predict_query(start_date, end_date, http_agent_ex, http_path_ex, http_query_ex, http_host_ex, interval, idx_cols='logtime, src_ip, dst_ip'):
#     if idx_cols == 'logtime, logtime, src_ip, dst_ip':
#         idx_cols = 'logtime, addHours(logtime, 9) as logtime, src_ip, dst_ip'
# #     sql = """
# #     select
# #         toStartOfInterval(logtime, INTERVAL {interval}) as {idx_cols},
        
# #         --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
# #         --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query
# #         arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(arrayStringConcat([http_agent, splitByString('.php', http_query)[2]], ' ')), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agnt_qry
        
# #     from default.dti_qm_httpd
# #         where (logtime >= '{start_date}' and logtime < '{end_date}')
# #     group by {idx_cols}
# #     """.format(interval=interval, start_date=start_date, end_date=end_date, idx_cols=idx_cols)
    
#     # # plan B : 신한 Real 공격 데이터 default.dti_qm_httpd
#     sql = """ 
#      select
#         toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols}, 
#         arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, http_agent, http_path, http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), 
#         '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agnt_qry

#     from default.dti_qm_httpd
   
#     where (logtime >= subtractHours(toDateTime('{start_date}'), 9) and logtime < subtractHours(toDateTime('{end_date}'), 9))
#         and extractAll(lower(http_agent), lower('{http_agent_ex}')) = []
#         and extractAll(lower(http_path), lower('{http_path_ex}')) = []
#         and extractAll(lower(http_query), lower('{http_query_ex}')) = []
#         and extractAll(lower(http_host), lower('{http_host_ex}')) = []        
#         and not (http_agent = '-' or http_path = '-')
    
#     group by {idx_cols}
    
#             """.format(start_date=start_date, end_date=end_date, http_agent_ex=http_agent_ex, http_path_ex=http_path_ex,
#                        http_query_ex=http_query_ex, http_host_ex=http_host_ex, interval=interval, idx_cols=idx_cols)
#     print("predict_query {}\n{}".format(">" * 50, sql))
#     return sql

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%# 
# # [oliver] 2023.02.06 select에서 toStartOfInterval(addHours(logtime, ..))을 toStartOfInterval(logtime_kr, ..)로 변경.
def predict_query2(start_date, end_date, http_agent_ex, http_path_ex, http_query_ex, http_host_ex, src_ip_ex, dst_ip_ex, interval, idx_cols='logtime, src_ip, dst_ip'):
    if idx_cols == 'logtime, logtime, src_ip, dst_ip':
        idx_cols = 'logtime, addHours(logtime, 9) as logtime, src_ip, dst_ip'

    sql = """ 
     select
        toStartOfInterval(logtime_kr, INTERVAL {interval}) as {idx_cols}, 
        -- toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols},
            arrayStringConcat(groupUniqArray(replaceRegexpAll(replaceRegexpAll(replace(lower(decodeURLComponent(arrayStringConcat([http_method, http_host, replace(replace(replace(replace(replace(lower(http_agent), 'or', ''),'from', '' ),'protocol discovery', '' ),'alert.gogigong.kr', '' ),'preserving prefetch proxy', '' ), replace(replace(replace(replace(replace(replace(replace(replace(lower(http_path), 'alert', ''), 'javascript', ''), 'nice', ''), 'update.ini', ''), 'xmlrpc.php', ''), 'callservletservice.jsp', ''), '/etc/', ''), '.well-known/traffic-advice', ''), http_query, http_tenc], ' '))), '/..', ' pathsearcherdetected '), 'host: [0-9].', ' hostcheckdetected '), '[\-%.!@#$?,;:&*)(+=0-9]', ' ')), ' ') as agnt_qry
                                            -- '[\./!@#$?,;:&*)(_]'
    from default.dti_qm_httpd
   
    where (logtime >= subtractHours(toDateTime('{start_date}'), 9) and logtime < subtractHours(toDateTime('{end_date}'), 9))
        and extractAll(lower(http_agent), lower('{http_agent_ex}')) = []
        and extractAll(lower(http_path), lower('{http_path_ex}')) = []
        and extractAll(lower(http_query), lower('{http_query_ex}')) = []
        and extractAll(lower(http_host), lower('{http_host_ex}')) = []
        and extractAll(lower(IPv4NumToStringClassC(IPv4StringToNum(src_ip))), lower('{src_ip_ex}')) = []
        and not ( 
            ( lower(IPv4NumToStringClassC(IPv4StringToNum(src_ip))) in lower('{src_ip_ex}') )
            and ( lower(IPv4NumToStringClassC(IPv4StringToNum(dst_ip))) in lower('{dst_ip_ex}') )
            )
        -- 20230515 신한 요청 사항 : http_server = 'BigIP'는 탐지된 것으로 필터링 한다.
        and not (http_agent = '-' or http_path = '-' or http_server = 'BigIP')
        -- and http_server != 'BigIP'
        -- 20230410 신한 요청 사항 : dev_nm LIKE '%_m_%' or dev_nm LIKE '%_bh_%' 탐지된 건 제외
        and src_ip global not in
            (
            select distinct src_ip
            from default.dti_blockd
            where logtime >= subtractMinutes(toDateTime('{start_date}'), 15) 
            and logtime <= addMinutes(toDateTime('{end_date}'), 15)
            and (dev_nm LIKE '%_m_%' or dev_nm LIKE '%_bh_%')
            )
    group by {idx_cols}
    
            """.format(start_date=start_date, end_date=end_date, http_agent_ex=http_agent_ex, http_path_ex=http_path_ex,
                       http_query_ex=http_query_ex, http_host_ex=http_host_ex, src_ip_ex=src_ip_ex, dst_ip_ex=dst_ip_ex, interval=interval, idx_cols=idx_cols)
    
#     print("predict_query2 {}\n{}".format(">" * 50, sql))
    # logtime >= subtractHours(toDateTime('{start_date}'), 9) and logtime < subtractHours(toDateTime('{end_date}'), 9))
    # logtime >= '{start_date}' and logtime < '{end_date}'
    return sql

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def get_data_collection_info_query(table_name=None):
    sql = """
    select *
    from {table_name}
    """.format(table_name=table_name)
    print(sql)
    return sql

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def get_data_collection_column_query(table_name=None, columns=None, version=None):
    sql = """
    select {columns}
    from {table_name}
    where version=='{version}'
    """.format(table_name=table_name, columns=columns, version=version)
    print(sql)
    return sql

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
def insert_prep_data_query(table_name=None):
    sql = """
    insert into {table_name} values
    """.format(table_name=table_name)
    return sql


# def get_threat_scoring_data_query(table_name, start_date=None, end_date=None, etc=""):
#     if start_date is None:
#         sql = """
#         select * from {table_name} 
#         where {etc} 
#         """.format(table_name=table_name, etc=etc)
#     else:
#         sql = """
#         select * from {table_name} 
#         where logtime between '{start_date}' and '{end_date}' 
#         {etc}
#         """.format(table_name=table_name, start_date=start_date, end_date=end_date, etc=etc)

#     return sql


# def get_mitre_data():
#     sql = """
#     select att_name, score
#     from default.dti_attack_mapping dam, default.dti_mitre_score dms
#     where dam.mitre_step = dms.mitre_step
#     """
#     return sql

# # def predict_query(start_date, end_date, limit, interval):
# #     sql = """
# #     select
# #         toStartOfInterval(logtime, INTERVAL {interval}) as logtime, src_ip, dst_ip,

# #         --arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_host), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as host,
# #         arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
# #         arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query,
# #         'normal' as label
    
# #     from dti.dti_sh_demo_log
# #         where (logtime >= '{start_date}' and logtime < '{end_date}')
# #             and hash == 'normal'
# #         group by logtime, src_ip, dst_ip
# #         limit {limit}
# #     """.format(interval=interval, start_date=start_date, end_date=end_date, limit=limit)
    
# #     return sql

# def rule_split(rule):
#     rule_raw = rule.split(') or (')
#     cnt = len(rule_raw)
#     query_list = []
#     for i in range(cnt):
#         start = rule_raw[i].split(', ')[0]
#         start = start.replace('and((','')
#         start = 'and ('+str(start)
#         end = rule_raw[i].split(', ')[1].split("') ")[1]
#         end = end.replace('))','')
#         end = str(end) + ')'
#         keyword = rule_raw[i].split(', ')[1].split("') ")[0].split('|')
#         words = len(keyword)
#         for i in range(words):
#             keyword[i] = keyword[i].replace("'","")
#             keyword[i] = ", '"+keyword[i]+"') "
#             query = start+keyword[i]+str(end)
#             query_list.append(query)
#     return query_list

# def scanning_attack_sql_query(start_date, end_date, scanning_rule, limit, interval, idx_cols='logtime, src_ip, dst_ip'):
#     scanning_sql = """
    
#       select
#         toStartOfInterval(addHours(logtime, 9), INTERVAL {interval}) as {idx_cols}, max(addHours(end_time,9)) as end,
#         uniqExact(dst_port) as dst_port_cnt,
        
#         avg(if(extract(toString(http_retcode), '10')=='10', 1, 0)) as info_st,
#         avg(if(extract(toString(http_retcode), '20')=='20', 1, 0)) as succ_st,
#         avg(if(extract(toString(http_retcode), '30')=='30', 1, 0)) as redir_st,
#         avg(if(extract(toString(http_retcode), '40')=='40', 1, 0)) as cler_st,
#         avg(if(extract(toString(http_retcode), '50')=='50', 1, 0)) as serer_st,
#         avg(if(toString(http_retcode)=='-', 1, 0)) as oth_st,
        
#         arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_host), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as host,
#         arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(http_agent), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as agent,
#         arrayStringConcat(groupUniqArray(replaceRegexpAll(replace(decodeURLComponent(arrayStringConcat([http_path, http_query], ' ') as http_query), '/..', ' pathsearcherdetected '), '[\./!@#$?,;:&*)(_]', ' ')), ' ') as query,
        
#         'scanning' as label
        
#     from default.dti_qm_httpd
    
#     where logtime >= subtractHours(toDateTime(toDate('{logdate_s}')), 9) 
#             and logtime < subtractHours(toDateTime(toDate('{logdate_e}')), 9)
#             and src_ip global not in
#              (select distinct IP
#              from default.map_all_ipd 
#              )             
#       and not (http_host = '-' and http_agent = '-' and http_query = '-' and http_path = '-')
#       and (extract(toString(http_retcode), '20')!='20')   
#       {scanning_rule}
    
#     group by {idx_cols}
#     limit {lim}
    
#     """.format(logdate_s=start_date, logdate_e=end_date, lim=limit, scanning_rule=scanning_rule, interval=interval, idx_cols=idx_cols)
    
#     return scanning_sql


# def mk_result_table_query(version):
#     sql = """insert into dti.dti_resultd
#     SELECT
#       id, ai_label, time_group, addHours(logtime, 9) as logtime, src_ip, src_port, dst_ip, dst_port, http_method, http_host, http_agent, http_path, http_query, http_retcode, http_refer, app, packets_forward, bytes_forward, packets_backward, bytes_backward
#     FROM
#       (
#         WITH toStartOfInterval(addHours(logtime, 9), toIntervalMinute(30)) AS time_group,
#         concat(toString(time_group), ' > ', src_ip, ' > ', dst_ip) AS id
#         SELECT id, time_group, *
#         FROM default.dti_qm_httpd
#         WHERE time_group = (select min(logtime) from dti.TEST3005_pred_01_resultd where version ='{ver}')  AND NOT ((http_agent = '-') OR (http_path = '-'))
#       )      
#       INNER JOIN 
#       (
#         SELECT concat(toString(logtime), ' > ', src_ip, ' > ', dst_ip) AS id, ai_label
#         FROM dti.TEST3005_pred_01_resultd
#         WHERE version = '{ver}' AND ai_label != 'normal'
#         GROUP BY id, ai_label
#         UNION ALL
#         SELECT concat(toString(logtime), ' > ', src_ip, ' > ', dst_ip) AS id, upper(ai_label)
#         FROM dti.TEST3005_pred_esoinn_resultd
#         WHERE version = '{ver}' AND ai_label != 'normal'
#         GROUP BY id, ai_label
#       ) USING (id)""".format(ver=version)
#     return sql
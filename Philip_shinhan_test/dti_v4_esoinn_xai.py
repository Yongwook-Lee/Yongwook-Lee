import os
import random
import sys
import pandas as pd
import pickle
import logging

# Copyright (c) 2017 Gangchen Hua
# This software is released under the MIT License.
# http://opensource.org/licenses/mit-license.php

"""
E-SOINN in Python 3
Version 1.0
"""
from random import randint
from typing import overload
import numpy as np
from scipy.sparse import dok_matrix
from sklearn.base import BaseEstimator, ClusterMixin
from random import choice
import threading
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.metrics import *

# pwd = os.getcwd()
pwd = os.path.dirname(os.path.realpath(__file__))

log = logging.getLogger(__name__)

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
class ESoinn(BaseEstimator, ClusterMixin):
    INITIAL_LABEL = -1

    def __init__(self, dim=2, max_edge_age=50, iteration_threshold=200, c1=0.001, c2=1.0, crcl_w=1.0):
        # import tensorflow as tf
        # physical_devices = tf.config.list_physical_devices('GPU')
        # tf.config.experimental.set_memory_growth(physical_devices[0], True)
        # self.tf = tf

        self.dim = dim
        self.iteration_threshold = iteration_threshold
        self.c1 = c1
        self.c2 = c2
        self.max_edge_age = max_edge_age
        self.num_signal = 0
        self._reset_state()
        self.fig = plt.figure()
        self.color = []
        self.crcl_w = crcl_w
        self.trn_clust_lb = []

    def _reset_state(self):
        self.nodes = np.array([], dtype=np.float64)
        self.winning_times = []
        self.density = []
        self.N = []
        # if active
        self.won = []
        self.total_loop = 1
        self.s = []
        self.adjacent_mat = dok_matrix((0, 0), dtype=np.float64)
        self.node_labels = []
        self.labels_ = []
        self.sigs = []
        self.x_idx_list = []
        self.x_nois_idx_list = []
        self.monitor_result_list = []
        self.max_idx_monitor_result = 1

    def _set_state(self, esoinn_model):
        self.nodes = esoinn_model[0].copy()
        self.winning_times = esoinn_model[1].copy()
        self.density = esoinn_model[2].copy()
        self.N = esoinn_model[3].copy()
        self.won = esoinn_model[4].copy()
        self.total_loop = esoinn_model[5]
        self.s = esoinn_model[6].copy()
        self.adjacent_mat = esoinn_model[7].copy()
        self.node_labels = esoinn_model[8].copy()
        self.labels_ = esoinn_model[9].copy()
        self.sigs = esoinn_model[10].copy()
        self.x_idx_list = esoinn_model[11].copy()
        self.trn_clust_lb = esoinn_model[12].copy()  # 노드의 라벨
        self.crcl_w = esoinn_model[13]
        self.x_nois_idx_list = []

    def load_esoinn_model(self, save_version, epoch=0):
        self.__is_predict = True
        log.info("esoinn version : {}".format(save_version))
        try:
            if epoch == 0:
                with open("{}/model/esoinn_model_{}.pickle".format(pwd, save_version), "rb") as f:
                    esoinn_model = pickle.load(f)
                    self._set_state(esoinn_model)
            else:
                with open("{}/model/esoinn_model_{}_{}.pickle".format(pwd, save_version, epoch), "rb") as f:
                    esoinn_model = pickle.load(f)
                    self._set_state(esoinn_model)
        except:
            raise Exception
        log.info("esoinn_model load and initiated **************")

    def save_esoinn_model(self):
        x_idx_list = [[] for _ in range(len(self.x_idx_list))]
        sv_data = [
            self.nodes
            , self.winning_times
            , self.density
            , self.N
            , self.won
            , self.total_loop
            , self.s
            , self.adjacent_mat
            , self.node_labels
            , self.labels_
            , self.sigs
            , x_idx_list
            , self.trn_clust_lb
            , self.crcl_w
        ]

        try:
            os.makedirs("{}/model/".format(pwd), exist_ok=True)
            if self.sava_last_model:
                with open("{}/model/esoinn_model_{}.pickle".format(pwd, self.save_version), "wb") as f:
                    pickle.dump(sv_data, f)
                log.info("esoinn_model_{}.pickle saved".format(self.save_version))
            else:
                with open("{}/model/esoinn_model_{}_{}.pickle".format(pwd, self.save_version, self.total_loop - 1),
                          "wb") as f:
                    pickle.dump(sv_data, f)
                log.info("esoinn_model_{}_{}.pickle saved".format(self.save_version, self.total_loop - 1))
        except:
            raise Exception

    """
    :param
        X : signal 데이터 객체, numpy.ndarray
    :return
        X와 동일한 순서의 예측값 DataFrame 객체
    """

    def predict(self, X):
        if self.__is_predict:
            log.info("st SET INIT :::::::::::::::::::::::::::::::::::::::::::::::::::::::")
            log.info("crcl_w : {}".format(self.crcl_w))
            log.info("en SET INIT :::::::::::::::::::::::::::::::::::::::::::::::::::::::")
        self.tmp_noise_idx_list = []
        self.tmp_non_noise_list = [[] for _ in range(len(self.x_idx_list))]

        x_len = len(X)
        for x in range(x_len):
            self.pred_input_signal(X[x], x)

        # # 예측값을 담기 위한 리스트
        Y = ['' for _ in range(x_len)]
        # # noise로 분류되면 anomaly로 예측값을 붙힌다.
        for noise_idx in self.tmp_noise_idx_list:
            Y[noise_idx] = 'anomaly'
        
        # # 학습 때 생성된 node의 대표값(label)을 self.trn_clust_lb 담아, 각 signal의 예측값을 붙힌다.
        for trn_clust_idx in range(len(self.tmp_non_noise_list)):
            tmp_arr = self.tmp_non_noise_list[trn_clust_idx]
            for non_noise_idx in tmp_arr:
                Y[non_noise_idx] = self.trn_clust_lb[trn_clust_idx]

        return pd.DataFrame(data=Y, columns=['ai_label'])

    def pred_input_signal(self, signal: np.ndarray, x_idx):
        # Algorithm 3.4 (2)
        signal = self.__check_signal(signal)
        
        # # signal의 모든 feature 값이 0 이면 normal로 예측한다.
        if self.__is_predict and np.sum(signal) == 0:
            self.tmp_non_noise_list[self.trn_clust_lb.index('normal')].append(x_idx)
            return

        # Algorithm 3.4 (3)
        # winner has indexes of the closest node and the second closest node from new signal
        winner, dists = self.__find_nearest_nodes(2, signal)
        sim_thresholds = self.__calculate_similarity_thresholds(winner)
        
        # new node is noise(=anomaly)
#         if dists[0] > sim_thresholds[0] * self.crcl_w or dists[1] > sim_thresholds[1] * self.crcl_w:
        if dists[0] > sim_thresholds[0] or dists[1] > sim_thresholds[1]:  
            # # normal 주변의 noise는 normal 로 예측한다.
            if self.__is_predict and self.trn_clust_lb[winner[0]] == 'normal':   
                self.tmp_non_noise_list[winner[0]].append(x_idx)
            elif self.__is_predict and self.trn_clust_lb[winner[1]] == 'normal':
                self.tmp_non_noise_list[winner[1]].append(x_idx)
                
            else:
                if dists[0] > sim_thresholds[0] * self.crcl_w or dists[1] > sim_thresholds[1] * self.crcl_w:
                    self.tmp_noise_idx_list.append(x_idx)  # anomaly
                else:
                    self.tmp_non_noise_list[winner[0]].append(x_idx)
        else:
            self.tmp_non_noise_list[winner[0]].append(x_idx)
            
    def is_close_to(self, signal, x_idx, nearest_nodes_num=2, lb='normal'):
        winner, dists = self.__find_nearest_nodes(nearest_nodes_num, signal)
        for i in range(nearest_nodes_num):
            if self.__is_predict and self.trn_clust_lb[winner[i]] == lb:
                return True
#                 self.tmp_non_noise_list[winner[i]].append(x_idx)


    def fit(self, train_data, validation_data, epochs=100, full_shuffle_flag=True):
        """
        train data in batch manner
        :param
            train_data: list of array-like or ndarray
            validation_data: list of array-like or ndarray
            full_shuffle_flag : (True : train all data randomly)
                                (False : train like bagging)
        """
        self._reset_state()
        ################# init train and validation data
        log.info("check WORK_HOME : {} >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>".format(pwd))
        log.info("st SET INIT :::::::::::::::::::::::::::::::::::::::::::::::::::::::")
        log.info("max_edge_age : {}, iteration_threshold : {}, crcl_w : {}".format(self.max_edge_age,
                                                                                   self.iteration_threshold,
                                                                                   self.crcl_w))
        log.info("patience : {}, total_epochs : {}, monitor : {}".format(self.patience, epochs,  self.monitor))
        log.info("en SET INIT :::::::::::::::::::::::::::::::::::::::::::::::::::::::")

        X = train_data[0]
        self.X_valtn = validation_data[0]
        self.Y_valtn = validation_data[1]

        if self.model_version == "":  # # 최초 학습일 때
            self.y_train = train_data[1]

        else:  # # TRANSFER_LEARNING
            self.load_esoinn_model(self.model_version)
            if len(self.nodes) < 2:
                print("len(self.nodes) is {}, too few for TRANSFER_LEARNING.".format(len(self.nodes)))
                sys.exit()

            print("pre_LEARNING total_loop : {} >>>>>> reset total_loop".format(self.total_loop))
            # self.new_ptrn_idx = 0
            self.total_loop = 1
            print("TRANSFER_LEARNING total_loop : {}".format(self.total_loop))
            print("len(self.nodes) ::::::::::::::::::::::: {}".format(len(self.nodes)))
#             for node_idx, label in enumerate(self.trn_clust_lb):
#                 if label != 'normal':
#                     for k, v in self.adjacent_mat[node_idx, :].items():
#                         if len(self.trn_clust_lb) > k[1] and self.trn_clust_lb[k[1]] == 'normal':
#                             # # 공격 node 와 normal node 서로 연결된 edge 제거 (normal은 aging 후 제거됨. 공격은 aging 안 되고, 제거 안 됨)
#                             self.__remove_edge_from_adjacent_mat((node_idx, k[1]))
#                             continue
#                         # # 공격 노드의 edge는 TRANSFER_LEARNING 때, 1로 reset
#                         self.__set_edge_weight((node_idx, k[1]), 1)
#             print("reset all edges' age of attack nodes")
            keys, counts = np.unique(self.trn_clust_lb, return_counts=True)
            print("keys : {}\ncnts : {}".format(keys, counts))
            print("esoinn_version {} TRANSFER_LEARNING is ready {}".format(self.model_version, ">" * 50))
        ################# init train and validation data

        if full_shuffle_flag:  # train all data randomly
            # # train with All data (=normal and attack)
            tmp_signals = [(X[x], x) for x in range(len(X))]
#             if len(tmp_signals) > self.iteration_threshold * epochs:
#                 log.error(
#                     " total signal is too BIG. The setting of hyperparam can't train all signal\nlen(signals) : {} , iteration * epochs : {}".format(
#                         len(tmp_signals), self.iteration_threshold * epochs))
#                 sys.exit()

            signals = [j for _ in range(self.iteration_threshold * epochs // len(tmp_signals) + 1) for j in tmp_signals]

            # # choose signals randomly
            random.shuffle(signals)

            for sig in signals[:self.iteration_threshold * epochs]:
                is_stop = self.train_input_signal(sig[0], sig[1])
                if is_stop:
                    break

        else:  # train like bagging
            tot_sigs = 0
            while True:
                # # choose signals randomly
                x = random.randrange(len(X))

                # # train with All data (=normal and attack)
                is_stop = self.train_input_signal(X[x], x)
                if is_stop:
                    break
                tot_sigs += 1
                if tot_sigs >= self.iteration_threshold * epochs:
                    break

        return self

    def train_input_signal(self, signal: np.ndarray, x_idx):  # 1. numpy array 입력데이터 1개(이하 signal)와 그 index를 받는다.
        """
        Input a new signal one by one, which means training in online manner.
        fit() calls __init__() before training, which means resetting the
        state. So the function does batch training.
        :param signal: A new input signal
        :return:
        """
        # Algorithm 3.4 (2)
        signal = self.__check_signal(signal)  # 2. signal의 무결성 확인
        self.num_signal += 1
        self.sigs.append(signal)

        # Algorithm 3.4 (1)
        if len(self.nodes) < 2:  # 3. 최초 2개의 initial node 설정
            self.__add_node(signal, x_idx)
            return

        # Algorithm 3.4 (3)
        # winner has indexes of the closest node and the second closest node from new signal
        # 4-1. 기존 self.nodes의 노드들 중에 signal과 가장 가까운 2개 node(1등:winner[0], 2등:winner[1]) 구하고,
        # 각각의 거리(dists)구한다.
        winner, dists = self.__find_nearest_nodes(2, signal)

        ### st check same signal #####################################################
#         if len(np.where((self.nodes[winner[0]] - np.array(signal)) ** 2 > 0)[0]) == 0:
#             self.num_signal -= 1
#             self.sigs = self.sigs[:-1]
# #             self.__increment_edge_ages(winner[0])
#             return False
        ### en check same signal #####################################################

        # 4-2. 각 winner의 가장 먼 이웃 node거리를 threshold 값으로 구한다. (단, 이웃 node는 winner와 동일 cluster에 있다.)
        sim_thresholds = self.__calculate_similarity_thresholds(winner)

        """
        2.2.1. new node 생성 (= anomaly로 판단된 경우): false alarm(=false positive)를 줄이기 위한 방안
            1. 1등 node와 2등 node가 둘다 normal인 경우 normal로 판단
                => [주의] 대부분의 node가 normal인 경우 missing 발생 가능성 높음 
            2 sim_thresholds에 가중치(self.crcl_w > 1.0)를 주어, noise로 예측될 node를 제일 가까운 node에 붙힌다.
                => 가중치(self.crcl_w) 찾기 위해 많은 학습 시간 소요
        """
        # # 1. 1등 node와 2등 node가 둘다 normal인 경우 normal로 판단
        # if not (self.trn_clust_lb[winner[0]] == self.trn_clust_lb[winner[1]] == 'normal'):
        # # 2. sim_thresholds에 가중치(self.crcl_w > 1.0)를 주어, noise로 예측될 node를 제일 가까운 node에 붙힌다.
        if dists[0] > sim_thresholds[0] * self.crcl_w or dists[1] > sim_thresholds[1] * self.crcl_w:
            # 5-1. 가장 가까운 2개의 node(winner)와 signal의 거리가 각각의 threshold 보다 크면 새 node 생성한다.
            self.__add_node(signal, x_idx)
        else:  # 5-2. 입력 signal이 새 node가 아닌 경우 기존 node에 붙히고, density 등 update한다.
            # Algorithm 3.4 (4)
            # 5-2-1. 입력 signal과 가장 가까운 node(1등:winner[0])와 연결된 모든 엣지의 age를 1 증가
            self.__increment_edge_ages(winner[0])
            # Algorithm 3.4 (5)
            # 5-2-2. 1등(winner[0])과 2등(winner[1])의 subclass 합칠지 여부 판단
            need_add_edge, need_combine = self.__need_add_edge(winner)
            if need_add_edge:
                # Algorithm 3.4 (5)(a)
                self.__add_edge(winner)
            else:
                # Algorithm 3.4 (5)(b)
                self.__remove_edge_from_adjacent_mat(winner)
            # Algorithm 3.4 (5)(a) need combine subclasses
            if need_combine:  # 나중에 클래스 만들 때 자동으로 엮임(무시)
                self.__combine_subclass(winner)
            # Algorithm 3.4 (6) checked, maybe fixed problem N
            self.__update_density(winner[0])
            # Algorithm 3.4 (7)(8)
            self.__update_winner(winner[0], signal)
            ####################################################################################################
            # 5-2-3. 입력 signal이 새 node가 아니기 때문에, 가장 가까운 node(1등:winner[0])의 배열에 append 한다.
            # (입력 signal을 추적하기 위해 추가한 코드)
            self.x_idx_list[winner[0]].append(x_idx)
            ####################################################################################################
            # Algorithm 3.4 (8)
            self.__update_adjacent_nodes(winner[0], signal)

        # Algorithm 3.4 (9)
        self.__remove_old_edges()  # 6. hyper param 값(max_edge_age)보다 큰 엣지 제거한다.
        is_stop = False
        # Algorithm 3.4 (10)
        # 7. 입력 signal의 갯수가 iteration_threshold를 넘으면 classify 한다.
        # 이 조건문에 들어가기 전까지 계속 self.nodes에 signal을 추가한다.
        if self.num_signal % self.iteration_threshold == 0 and self.num_signal > 1:
            for i in range(len(self.won)):
                if self.won[i]:
                    self.N[i] += 1
            for i in range(len(self.won)):
                self.won[i] = False

            self.__separate_subclass()
            self.__delete_noise_nodes()  # 7-1. noise node를 self.nodes에서 제거한다.
            self.total_loop += 1
            self.__classify()  # 7-2. 남은 self.nodes를 classify 한다.
            if self.save_plt_fig:
                threading.Thread(self.plot_NN(self.total_loop - 1, "train"))
            ####################################################################################################
            self.__is_predict = False
            is_stop = self.__fit_val()  # 7-3. 학습 중에 validation data로 모델을 평가한다.(모델 평가를 위해 추가된 코드)
            ####################################################################################################

            self.sigs.clear()
        return is_stop

    # checked
    def __combine_subclass(self, winner):
        if self.node_labels[winner[0]] == self.node_labels[winner[1]]:
            raise ValueError
        class_id = self.node_labels[winner[0]]
        node_belong_to_class_1 = self.find_all_index(self.node_labels, self.node_labels[winner[1]])
        for i in node_belong_to_class_1:
            self.node_labels[i] = class_id

    # checked
    def __remove_old_edges(self):
        for i in list(self.adjacent_mat.keys()):
            if self.adjacent_mat[i] > self.max_edge_age + 1:
                #############################################
                print(i, "__remove_old_edges")
                #############################################
                self.adjacent_mat.pop((i[0], i[1]))

    # checked
    def __remove_edge_from_adjacent_mat(self, ids):
        if (ids[0], ids[1]) in self.adjacent_mat and (ids[1], ids[0]) in self.adjacent_mat:
            self.adjacent_mat.pop((ids[0], ids[1]))
            self.adjacent_mat.pop((ids[1], ids[0]))

    # Algorithm 3.1
    def __separate_subclass(self):
        # find all local apex
        density_dict = {}
        density = list(self.density)
        for i in range(len(self.density)):
            density_dict[i] = density[i]
        class_id = 0
        while len(density_dict) > 0:
            apex = max(density_dict, key=lambda x: density_dict[x])
            ids = []
            ids.append(apex)
            self.__get_nodes_by_apex(apex, ids, density_dict)
            for i in set(ids):
                if i not in density_dict:
                    raise ValueError
                self.node_labels[i] = class_id
                density_dict.pop(i)
            class_id += 1

    def __get_nodes_by_apex(self, apex, ids, density_dict):
        new_ids = []
        pals = self.adjacent_mat[apex]
        for k in pals.keys():
            i = k[1]
            if self.density[i] <= self.density[apex] and i in density_dict and i not in ids:
                ids.append(i)
                new_ids.append(i)
        if len(new_ids) != 0:
            for i in new_ids:
                self.__get_nodes_by_apex(i, ids, density_dict)
        else:
            return

    # Algorithm 3.2, checked
    """
    :return need_add_edge, need_combine
    """

    def __need_add_edge(self, winner):
        # 1등 또는 2등이 -1 클래스에 있으면 합치지 않음
        if self.node_labels[winner[0]] == self.INITIAL_LABEL or \
                self.node_labels[winner[1]] == self.INITIAL_LABEL:
            return True, False
        # 1등과 2등이 같은 클래스에 있으면 합치지 않음 (이미 같은 클래스에 합쳐 있으므로)
        elif self.node_labels[winner[0]] == self.node_labels[winner[1]]:
            return True, False
        else:
            mean_density_0, max_density_0 = self.__mean_max_density(self.node_labels[winner[0]])
            mean_density_1, max_density_1 = self.__mean_max_density(self.node_labels[winner[1]])
            alpha_0 = self.calculate_alpha(mean_density_0, max_density_0)
            alpha_1 = self.calculate_alpha(mean_density_1, max_density_1)
            min_density = min([self.density[winner[0]], self.density[winner[1]]])
            # 서로 다른 클래스이고, min_density 보다 작으면 합침
            if alpha_0 * max_density_0 < min_density or alpha_1 * max_density_1 < min_density:  # (7),(8)
                return True, True
            else:  # 서로 다른 클래스이고, min_density 보다 둘 다 크면 안 합침
                return False, False

    @staticmethod
    def calculate_alpha(mean_density, max_density):
        if max_density > 3.0 * mean_density:
            return 1.0
        elif 2.0 * mean_density < max_density <= 3.0 * mean_density:
            return 0.5
        else:
            return 0.0

    @staticmethod
    def find_all_index(ob, item):
        return [i for i, a in enumerate(ob) if a == item]

    # checked
    def __mean_max_density(self, class_id):
        node_belong_to_class = self.find_all_index(self.node_labels, class_id)
        avg_density = 0.0
        max_density = 0.0
        for i in node_belong_to_class:
            avg_density += self.density[i]
            if self.density[i] > max_density:
                max_density = self.density[i]
        avg_density /= len(node_belong_to_class)
        return avg_density, max_density

    @overload
    def __check_signal(self, signal: list) -> None:
        ...

    def __check_signal(self, signal: np.ndarray):
        """
        check type and dimensionality of an input signal.
        If signal is the first input signal, set the dimension of it as
        self.dim. So, this method have to be called before calling functions
        that use self.dim.
        :param signal: an input signal
        """
        if isinstance(signal, list):
            signal = np.array(signal)
        if not (isinstance(signal, np.ndarray)):
            raise TypeError()
        if len(signal.shape) != 1:
            raise TypeError()
        self.dim = signal.shape[0]
        if not (hasattr(self, 'dim')):
            self.dim = signal.shape[0]
        else:
            if signal.shape[0] != self.dim:
                raise TypeError()
        return signal

    # checked
    def __add_node(self, signal: np.ndarray, x_idx):
        n = self.nodes.shape[0]
        self.nodes.resize((n + 1, self.dim))
        self.nodes[-1, :] = signal
        self.winning_times.append(1)
        self.adjacent_mat.resize((n + 1, n + 1))
        self.N.append(1)
        self.density.append(0)
        self.s.append(0)
        self.won.append(False)
        self.node_labels.append(self.INITIAL_LABEL)
        # add index of input signal from data X, one node can represent several signals
        self.x_idx_list.append([x_idx])

    """
    :param
        trgt_node : 입력 signal과 비교할 대상 node (which is from winners)
        signal : XAI 분석 대상 입력 데이터
        feat_df : model.get_feature_names()의 결과 DataFrame
    :return
        DataFrame : 입력 signal의 각 feature 차이가 작은 값 순으로 DataFrame 결과 반환
    """

    def get_diff_by_feat(self, trgt_node, signal, feat_df):
        # # 입력 signal에서 feature 값이 존재하는 index만 뽑는다.
        idx_list = sorted(list(np.where(np.array(signal) != 0)[0]))
        # # 대상 node와 입력 signal에 각 feature 값 차이의 절대값을 계산한다.
        diff = (abs(self.nodes[trgt_node] - np.array(signal)))[idx_list]
        sorted_idx = sorted(range(len(diff)), key=lambda k: diff[k])
        feat_list = list(feat_df[idx_list])

        return pd.DataFrame(data=[[diff[i], feat_list[i]] for i in sorted_idx], columns=['diff', 'feature'])

    """
    :param
        signal : XAI 분석 대상 입력 데이터
        feat_df : model.get_feature_names()의 결과 DataFrame
        num_norm : 입력 signal과 유사한 normal node 객체 수 (default=2)
    :return
        DataFrame : 뽑힌 normal node들의 각 feature값과 입력 signal feature값 차이가 큰 값 순의 DataFrame 결과 반환
    """

    def explain_anomaly(self, signal, feat_df, num_norm=2):
        # # 전체 node 대상으로, 입력 signal과 가까운 순의 node 리스트 객체(winners), 그 거리 행렬(dists)
        winners, dists = self.__find_nearest_nodes(len(self.nodes), signal)
        # # num_norm 갯수 만큼 anomaly로 판단된 입력 signal과 가장 가까운 normal node 순으로 뽑는다.
        normal_win_list = []
        for i in range(len(winners)):
            if self.trn_clust_lb[winners[i]] == 'normal':
                normal_win_list.append(i)
            if len(normal_win_list) >= num_norm:
                break

        merge_avg_dict = {}
        for i in normal_win_list:
            # log.info("idx:{}, its label:{}".format(i, self.trn_clust_lb[winners[i]]))
            # #  입력 signal의 feature와 차이의 값을 계산한다.
            result = self.get_diff_by_feat(winners[i], signal, feat_df)
            for j in range(result.shape[0]):
                if result['feature'][j] in merge_avg_dict:
                    merge_avg_dict[result['feature'][j]].append(result['diff'][j])
                else:
                    merge_avg_dict.update({result['feature'][j]: [result['diff'][j]]})
        # # normal node의 feature 별로 평균을 계산한다.
        result_list = [[np.mean(val_arr), feat] for feat, val_arr in merge_avg_dict.items()]
        # # feature 별로 계산된 평균 내림차 순으로 정렬(anomaly는 normal node 와 동일한 feature에 대해 큰 차이가 있을 것이라는 idea 기반)
        return pd.DataFrame(data=[[tmp[0], tmp[1]] for tmp in sorted(result_list, reverse=True)],
                            columns=['diff', 'feature'])

    """
    :param
        signal : XAI 분석 대상 입력 데이터
        feat_list : 입력 데이터 signal의 각 값의 feature 명 list 또는 numpy array
    :return
        DataFrame : 각 feature 별 거리 차 계산 결과
    """

    def xai_esoinn(self, signal, feat_list):
        winners, dists = self.__find_nearest_nodes(2, signal)
        sim_thresholds = self.__calculate_similarity_thresholds(winners)
        feat_df = pd.Series(feat_list)

        # # 4.2.2 new node is noise(=anomaly)
        if dists[0] > sim_thresholds[0] or dists[1] > sim_thresholds[1]:
            return self.explain_anomaly(signal, feat_df)
        else:
            # # 가장 가까운 대표 node의 feature 와 signal의 feature가 동일한 경우
            if len(np.where((self.nodes[winners[0]] - np.array(signal)) ** 2 > 0)[0]) == 0:
                log.info("the signal and the winner node are identical")
                return self.get_diff_by_feat(winners[0], signal, feat_df)
            else:  # # 4.2.3. 가장 가까운 대표 node와 비교
                return self.get_diff_by_feat(winners[0], signal, feat_df)

    # ### st tensorflow __find_nearest_nodes #########################################
    # def __find_nearest_nodes(self, num: int, signal: np.ndarray):
    #     import tensorflow as tf
    #     n = self.nodes.shape[0]
    #     D = tf.reduce_sum(tf.math.squared_difference(self.nodes, np.array([signal] * n)), 1)
    #     # sq_dists, indexes = tf.nn.top_k(- D, num)
    #     sq_dists, indexes = tf.nn.top_k(tf.negative(D), num)
    #     return list(indexes.numpy()), list(- sq_dists.numpy())
    # ### en tensorflow __find_nearest_nodes #########################################

    ### st original __find_nearest_nodes #########################################
    # checked
    def __find_nearest_nodes(self, num: int, signal: np.ndarray):
        n = self.nodes.shape[0]
        indexes = [0] * num
        sq_dists = [0.0] * num
        D = np.sum((self.nodes - np.array([signal] * n)) ** 2, 1)
        for i in range(num):
            indexes[i] = np.nanargmin(D)
            sq_dists[i] = D[indexes[i]]
            D[indexes[i]] = float('nan')
        return indexes, sq_dists

    ### en original __find_nearest_nodes #########################################

    # checked
    def __calculate_similarity_thresholds(self, node_indexes):
        # import tensorflow as tf
        sim_thresholds = []
        for i in node_indexes:
            pals = self.adjacent_mat[i, :]
            if len(pals) == 0:
                idx, sq_dists = self.__find_nearest_nodes(2, self.nodes[i, :])
                sim_thresholds.append(sq_dists[1])
            else:
                pal_indexes = []
                for k in pals.keys():
                    pal_indexes.append(k[1])
                sq_dists = np.sum((self.nodes[pal_indexes] - np.array([self.nodes[i]] * len(pal_indexes))) ** 2, 1)
                # sq_dists = tf.reduce_sum(
                #     tf.math.squared_difference(self.nodes[pal_indexes], np.array([self.nodes[i]] * len(pal_indexes))),
                #     1).numpy()
                # sq_dists = self.tf.reduce_sum(
                #     self.tf.math.squared_difference(self.nodes[pal_indexes],
                #                                     np.array([self.nodes[i]] * len(pal_indexes))),
                #     1).numpy()
                sim_thresholds.append(np.max(sq_dists))
        return sim_thresholds

    # checked
    def __add_edge(self, node_indexes):
        self.__set_edge_weight(node_indexes, 1)

    # checked
    def __increment_edge_ages(self, winner_index):
        for k, v in self.adjacent_mat[winner_index, :].items():
#             if len(self.trn_clust_lb) > winner_index and len(self.trn_clust_lb) > k[1]:
#                 # # 공격 노드끼리 연결된 edge는 aging하지 않는다.
#                 if self.trn_clust_lb[winner_index] != 'normal' and self.trn_clust_lb[k[1]] != 'normal':
#                     if self.adjacent_mat[winner_index, k[1]] > 1: continue
            self.__set_edge_weight((winner_index, k[1]), v + 1)

    # checked
    def __set_edge_weight(self, index, weight):
        self.adjacent_mat[index[0], index[1]] = weight
        self.adjacent_mat[index[1], index[0]] = weight

    # checked
    def __update_winner(self, winner_index, signal):
        w = self.nodes[winner_index]
        self.nodes[winner_index] = w + (signal - w) / self.winning_times[winner_index]

    # checked, maybe fixed the problem
    def __update_density(self, winner_index):
        self.winning_times[winner_index] += 1
        # if self.N[winner_index] == 0:
        #     raise ValueError
        pals = self.adjacent_mat[winner_index]
        pal_indexes = []
        for k in pals.keys():
            pal_indexes.append(k[1])
        if len(pal_indexes) != 0:
            sq_dists = np.sum((self.nodes[pal_indexes] - np.array([self.nodes[winner_index]] * len(pal_indexes))) ** 2,
                              1)
            mean_adjacent_density = np.mean(np.sqrt(sq_dists))
            p = 1.0 / ((1.0 + mean_adjacent_density) ** 2)
            self.s[winner_index] += p
            if self.N[winner_index] == 0:
                self.density[winner_index] = self.s[winner_index]
            else:
                self.density[winner_index] = self.s[winner_index] / self.N[winner_index]

        if self.s[winner_index] > 0:
            self.won[winner_index] = True

    # checked
    def __update_adjacent_nodes(self, winner_index, signal):
        pals = self.adjacent_mat[winner_index]
        for k in pals.keys():
            i = k[1]
            w = self.nodes[i]
            self.nodes[i] = w + (signal - w) / (100 * self.winning_times[i])

    # checked
    def __delete_nodes(self, indexes):
        if not indexes:
            return
        n = len(self.winning_times)

        self.batch_noise = np.array(self.node_labels)[indexes]

        self.nodes = np.delete(self.nodes, indexes, 0)
        remained_indexes = list(set([i for i in range(n)]) - set(indexes))

        self.not_noise = np.array(self.node_labels)[remained_indexes]

        self.winning_times = [self.winning_times[i] for i in remained_indexes]
        self.N = [self.N[i] for i in remained_indexes]
        self.density = [self.density[i] for i in remained_indexes]
        self.node_labels = [self.node_labels[i] for i in remained_indexes]
        self.won = [self.won[i] for i in remained_indexes]
        self.s = [self.s[i] for i in remained_indexes]
        self.__delete_nodes_from_adjacent_mat(indexes, n, len(remained_indexes))

    # checked
    def __delete_nodes_from_adjacent_mat(self, indexes, prev_n, next_n):
        while indexes:
            next_adjacent_mat = dok_matrix((prev_n, prev_n))
            for key1, key2 in self.adjacent_mat.keys():
                if key1 == indexes[0] or key2 == indexes[0]:
                    continue
                if key1 > indexes[0]:
                    new_key1 = key1 - 1
                else:
                    new_key1 = key1
                if key2 > indexes[0]:
                    new_key2 = key2 - 1
                else:
                    new_key2 = key2
                # Because dok_matrix.__getitem__ is slow,
                # access as dictionary.
                next_adjacent_mat[new_key1, new_key2] = super(dok_matrix, self.adjacent_mat).__getitem__((key1, key2))
            self.adjacent_mat = next_adjacent_mat.copy()
            indexes = [i - 1 for i in indexes]
            indexes.pop(0)
        self.adjacent_mat.resize((next_n, next_n))

    # checked
    def __delete_noise_nodes(self):
        n = len(self.winning_times)
        noise_indexes = []
        mean_density_all = np.mean(self.density)
        for i in range(n):
            if len(self.adjacent_mat[i, :]) == 2 and self.density[i] < self.c1 * mean_density_all:
                noise_indexes.append(i)
            elif len(self.adjacent_mat[i, :]) == 1 and self.density[i] < self.c2 * mean_density_all:
                noise_indexes.append(i)
            elif len(self.adjacent_mat[i, :]) == 0:
                noise_indexes.append(i)
        self.__delete_nodes(noise_indexes)
        ######################################################################################################
        self.x_nois_idx_list = [self.x_idx_list[i] for i in range(len(self.x_idx_list)) if i in noise_indexes]
        self.x_idx_list = [self.x_idx_list[i] for i in range(len(self.x_idx_list)) if i not in noise_indexes]

    def __get_connected_node(self, index, indexes):
        new_ids = []
        pals = self.adjacent_mat[index]
        for k in pals.keys():
            i = k[1]
            if i not in indexes:
                indexes.append(i)
                new_ids.append(i)

        if len(new_ids) != 0:
            for i in new_ids:
                self.__get_connected_node(i, indexes)
        else:
            return

    # Algorithm 3.3
    def __classify(self):
        need_classified = list(range(len(self.node_labels)))
        for i in range(len(self.node_labels)):
            self.node_labels[i] = self.INITIAL_LABEL
        class_id = 0
        while len(need_classified) > 0:
            indexes = []
            index = choice(need_classified)
            #             index = need_classified[0]
            indexes.append(index)
            self.__get_connected_node(index, indexes)
            for i in indexes:
                self.node_labels[i] = class_id
                need_classified.remove(i)
            class_id += 1

    def plot_NN(self, idx, trn_tst):
        plt.figure(figsize=(10, 10))
        plt.cla()
        # for k in self.sigs:
        #     plt.plot(k[0], k[1], 'cx')
        pca = PCA(n_components=2)
        nodes_pca = pca.fit_transform(self.nodes)

        for k in self.adjacent_mat.keys():
            plt.plot(nodes_pca[k, 0], nodes_pca[k, 1], 'k', c='blue')
        # plt.plot(nodes[:, 0], nodes[:, 1], 'ro')

        #         color = ['black', 'red', 'saddlebrown', 'skyblue', 'magenta', 'green', 'gold']

        for i in range(len(nodes_pca)):
            if len(self.color) < len(nodes_pca):
                self.color.append('#%06X' % randint(0, 0xFFFFFF))

        color_dict = {}

        for i in range(len(nodes_pca)):
            if not self.node_labels[i] in color_dict:
                color_dict[self.node_labels[i]] = self.color[i]
            plt.plot(nodes_pca[i][0], nodes_pca[i][1], 'ro', c=color_dict[self.node_labels[i]])

        plt.grid(True)
        plt.show()
        os.makedirs("{}/figures/{}_{}_{}/".format(pwd, trn_tst, self.iteration_threshold, self.max_edge_age),
                    exist_ok=True)
        plt.savefig('{}/figures/{}_{}_{}/fig_{}.jpg'.format(pwd, trn_tst, self.iteration_threshold, self.max_edge_age,
                                                            str(idx)))

    def __fit_val(self):
        self.tmp_noise_idx_list = []
        self.tmp_non_noise_list = [[] for _ in range(len(self.x_idx_list))]

        if self.model_version != "":  # # TRANSFER_LEARNING
            # self.new_ptrn_idx += 1
            # self.trn_clust_lb = [
            #     self.trn_clust_lb[i] if i < len(self.trn_clust_lb) else 'new_pattern' + str(self.new_ptrn_idx) for i in
            #     range(len(self.x_idx_list))]

            # # All TRANSFER_LEARNING signal must be 'normal'
            self.trn_clust_lb = [
                self.trn_clust_lb[i] if i < len(self.trn_clust_lb) else 'normal' for i in
                range(len(self.x_idx_list))]

        else:
            # # get the most frequent label from each node array
            self.trn_clust_lb = [self.__most_common_label([self.y_train[i][0] for i in arr]) if len(arr) > 0 else '' for
                                 arr in self.x_idx_list]

        monitor_result = self.__calculate_monitor(self.X_valtn, self.Y_valtn)
        if len(self.monitor_result_list) == 1 or self.save_best_only is False:
            self.save_esoinn_model()
            self.max_idx_monitor_result = self.total_loop - 1
        elif self.save_best_only is True and max(self.monitor_result_list[:-1]) < monitor_result:
            self.save_esoinn_model()
            self.max_idx_monitor_result = self.total_loop - 1

#         for node_idx, label in enumerate(self.trn_clust_lb):
#             if label != 'normal':
#                 for k, v in self.adjacent_mat[node_idx, :].items():
#                     if len(self.trn_clust_lb) > k[1] and self.trn_clust_lb[k[1]] == 'normal':
#                         # # 공격 node 와 normal node 서로 연결된 edge 제거 (normal은 aging 후 제거됨. 공격은 aging 안 되고, 제거 안 됨)
#                         self.__remove_edge_from_adjacent_mat((node_idx, k[1]))
#                         continue
#                     # # 공격 노드의 edge age는 iter후 1로 reset
#                     self.__set_edge_weight((node_idx, k[1]), 1)

        keys, counts = np.unique(self.trn_clust_lb, return_counts=True)
        print("keys : {}\ncnts : {}".format(keys, counts))
        print("len(self.nodes) ::::::::::::::::::::::: {}".format(len(self.nodes)))
        log.info("__fit_val {} DONE\n".format(self.total_loop - 1))

        if self.patience != 0 and self.patience <= len(self.monitor_result_list) - self.max_idx_monitor_result:
            log.info("EarlyStopping {}".format(":" * 30))
            return True
        return False

    def __most_common_label(self, arr):
        return max(set(arr), key=arr.count)

#     def __calculate_monitor(self, X, Y):
#         delta = 1e-4
#         pred_lst = [pred for pred in self.predict(X)['ai_label']]
#         Y_list = [tmp_arr[0] for tmp_arr in Y]

#         tot = len(pred_lst)
#         tp = 0; tn = 0; fp = 0; fn = 0; wc = 0
#         for i in range(tot):
#             tmp_pred = pred_lst[i]
#             tmp_true = Y_list[i]
#             if tmp_true == 'normal':  # # 정답 normal
#                 if tmp_pred == 'normal':
#                     tn += 1
#                 else:  # false alarm
#                     fp += 1
#             else:  # # 정답 ATTACK
#                 if tmp_pred == 'anomaly' or tmp_pred == tmp_true:
#                     tp += 1
#                 elif tmp_pred == 'normal':  # missing
#                     fn += 1
#                 else:  # wrong_clustering
#                     wc += 1
#                     log.info("pred:{}, true:{}".format(tmp_pred, tmp_true))

#         accur = (tp + tn) / ((tp + fp + fn + tn) + wc + delta)
#         preci = tp / (tp + fp + delta)
#         recal = tp / (tp + fn + delta)
#         f1_sc = 2 * recal * preci / (recal + preci + delta)

#         log.info("\nepoch : {}\ntp: {} \tfn: {}\nfp: {} \ttn: {}\t\twrong_clustering: {}".format(
#             "%4d" % (self.total_loop - 1), tp, fn, fp, tn, wc))
#         log.info("accuracy : {} , precision : {} , recall : {} , f1_score : {}".format("%.4f" % accur, "%.4f" % preci,
#                                                                                        "%.4f" % recal, "%.4f" % f1_sc))

#         if self.monitor in 'accuracy':
#             self.monitor_result_list.append(accur)
#             return accur
#         elif self.monitor in 'precision':
#             self.monitor_result_list.append(preci)
#             return preci
#         elif self.monitor in 'recall':
#             self.monitor_result_list.append(recal)
#             return recal
#         elif self.monitor in 'f1_score':
#             self.monitor_result_list.append(f1_sc)
#             return f1_sc
#         else:
#             log.error(" set monitor option, eg : accuracy, precision, recall, f1_score")
#             sys.exit()

    def __calculate_monitor(self, X, Y):
        pred_lst = [pred for pred in self.predict(X)['ai_label']]
        Y_list = [tmp_arr[0] for tmp_arr in Y]
        
        label_list = list(set(pred_lst))
        log.info("\nepoch : {}\nconfusion_matrix {}::::::::::::::::::::::::::::::::: \n{}".format("%4d" % (self.total_loop - 1), label_list, confusion_matrix(Y_list, pred_lst, labels=label_list) ))

        accur = accuracy_score(Y_list, pred_lst)
        preci = precision_score(Y_list, pred_lst, average='weighted')
        recal = recall_score(Y_list, pred_lst, average='weighted')
        f1_sc = f1_score(Y_list, pred_lst, average='weighted')
        log.info("accuracy : {} , precision : {} , recall : {} , f1_score : {}".format("%.4f" % accur, "%.4f" % preci,
                                                                                       "%.4f" % recal, "%.4f" % f1_sc))

        if self.monitor in 'accuracy':
            self.monitor_result_list.append(accur)
            return accur
        elif self.monitor in 'precision':
            self.monitor_result_list.append(preci)
            return preci
        elif self.monitor in 'recall':
            self.monitor_result_list.append(recal)
            return recal
        elif self.monitor in 'f1_score':
            self.monitor_result_list.append(f1_sc)
            return f1_sc
        else:
            log.error(" set monitor option, eg : accuracy, precision, recall, f1_score")
            sys.exit()

    def check_point(self, save_version, monitor='acc', save_best_only=False, sava_last_model=False, save_plt_fig=False,
                    patience=0, model_version=""):
        self.save_version = save_version
        self.monitor = monitor
        self.save_best_only = save_best_only
        self.sava_last_model = sava_last_model
        self.save_plt_fig = save_plt_fig
        self.patience = patience
        self.model_version = model_version

    def get_cnt_by_label(self, node_idx_list, label_np_arr, label_name):
        return len([i for i in node_idx_list if label_np_arr[i][0] == label_name])

    def get_evaluation(self, X, Y, monitor):
        self.monitor = monitor
        return self.__calculate_monitor(X, Y)

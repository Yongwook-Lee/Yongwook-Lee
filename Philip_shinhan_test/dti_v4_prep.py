from sklearn.preprocessing import StandardScaler, MinMaxScaler, MaxAbsScaler, RobustScaler, QuantileTransformer, \
    PowerTransformer
import pickle
import sys
import os
import string
from scipy.sparse import csr_matrix, dok_matrix
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.feature_extraction.text import TfidfVectorizer, TfidfTransformer, _document_frequency
from sklearn.utils.validation import check_is_fitted, FLOAT_DTYPES, _deprecate_positional_args
from sklearn.utils import _IS_32BIT
import scipy.sparse as sp
import array
from collections import defaultdict
import numbers
import warnings
import logging

import pandas as pd
import numpy as np
from multiprocessing import Pool
from multiprocessing.pool import ThreadPool
from functools import partial

from sklearn.preprocessing import OneHotEncoder

log = logging.getLogger(__name__)
# pwd = sys.path[0]
pwd = os.path.dirname(os.path.realpath(__file__))

# pwd = '/usr/local/src/dags/cnn'

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#
class IntProcessing:  # NumProcessing, NumericProcessing : data could be not only integer but also float
    def __init__(self):
        pass

    """
    save_scaling_model : save scaling model by scaling method

    :param
        data : train data
        save_version : path to save scaling model
        how : defined scaling method
    """

    def save_scaling_model(self, df, save_version, m_type=None, how=(
            'StandardScaler', 'MinMaxScaler', 'MaxAbsScaler', 'RobustScaler', 'QuantileTransformer',
            'PowerTransformer')):
        if not list(df):
            print('WARNING: THERE IS NO NUMERICAL DATA...')
            return
        data = df.copy()  # if df needs to be filtered
        # 1. choose scaling method
        if how == 'StandardScaler':
            scl_model = StandardScaler()
        elif how == 'MinMaxScaler':
            scl_model = MinMaxScaler()
        elif how == 'MaxAbsScaler':
            scl_model = MaxAbsScaler()
        elif how == 'RobustScaler':
            scl_model = RobustScaler()
        elif how == 'QuantileTransformer':
            scl_model = QuantileTransformer()
        elif how == 'PowerTransformer':
            scl_model = PowerTransformer()
        else:
            print("Scaling model [ ", how, "] is not defined")
            sys.exit()

        # 2. fit
        scl_model.fit(data)
        if m_type == 'cnn':
            if not os.path.exists(pwd + "/obj/cnn_scl_model"):
                os.makedirs(pwd + "/obj/cnn_scl_model")
            try:
                # 4. save model
                with open(pwd + "/obj/cnn_scl_model/cnn_scl_model_" + save_version + ".pickle", "wb") as f:
                    pickle.dump(scl_model, f)
            except:
                raise Exception
        else:
            if not os.path.exists(pwd + "/obj/scl_model"):
                os.makedirs(pwd + "/obj/scl_model")
            try:
                # 4. save model
                with open(pwd + "/obj/scl_model/scl_model_" + save_version + ".pickle", "wb") as f:
                    pickle.dump(scl_model, f)
            except:
                raise Exception
        # TODO discuss how to handle exceptions (in class or in pipeline)
        # except IOError as err:
        #     print(err)

    """
    trnsfm_scal_data : transform data by scaling model

    :param 
        data :
        save_version : path for scaling model

    :return
        scaled data
    """

    def trnsfm_scal_data(self, df, save_version, m_type=None):
        if not list(df):
            print('WARNING: THERE IS NO NUMERICAL DATA...')
            return
        try:
            if m_type == 'cnn':
                with open(pwd + "/obj/cnn_scl_model/cnn_scl_model_" + save_version + ".pickle", "rb") as f:
                    scl_model = pickle.load(f)
            else:
                with open(pwd + "/obj/scl_model/scl_model_" + save_version + ".pickle", "rb") as f:
                    scl_model = pickle.load(f)
            # 3. transform
            return scl_model.transform(df)
        except:
            raise Exception

        # except IOError as err:
        #     print(err)


#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
class StrProcessing:
    def __init__(self):
        pass
    
    def make_hex_to_string(self, df, col):
        # # binary hex to string
        for idx, value in df[col].items():
            if type(value) is not str:
                df.at[idx, col] = str(value).replace("\\", "/")

    def tfidf_model_fit(self, df, feature, n_grams, max_features, token_pattern=r"(?u)\b\w\w+\b"):
        stop_word_list = ['bbs', 'write', 'modify', 'board', 'delete', 'id', 'contents', 'writer', 'page']
        data = df.copy()
        data.fillna(' ', inplace=True)
        col_list = list(data.columns)
        # fit_list = list(set(data[feature]))
        tfidf_vectorizer = TfidfVectorizer(analyzer='word', ngram_range=n_grams, max_features=max_features,
                                           stop_words=stop_word_list, token_pattern=token_pattern)
        tfidf_vectorizer.fit(data[feature].values)
        return tfidf_vectorizer

    def save_tfidf_model_fit(self, df, feature_list, n_grams, max_features, save_version,
                             token_pattern=r"(?u)\b\w\w+\b"):
        tfidf_model_list = []
        for feature in feature_list:
            tfidf_model = self.tfidf_model_fit(df, feature, n_grams, max_features, token_pattern)
            tfidf_model_list.append(tfidf_model)

            if not os.path.exists(pwd + "/obj/" + str(feature) + "_tfidf_model"):
                os.makedirs(pwd + "/obj/" + str(feature) + "_tfidf_model")
            try:
                with open(pwd + "/obj/" + str(feature) + "_tfidf_model/" + str(
                        feature) + "_tfidf_model_" + save_version + ".pickle", "wb") as f:
                    pickle.dump(tfidf_model, f)
            except:
                raise Exception
            print(feature, pwd + "/obj save complete **************")
        return tfidf_model_list

    def tfidf_model_trans(self, model, df, feature, batch_size):
        data = df.copy()
        temp_batch = 0
        temp_df = pd.DataFrame()
        if len(data) % batch_size == 0:
            batch_count = int(len(data) / batch_size)
        else:
            batch_count = int(len(data) / batch_size) + 1

        tf_feature = model.get_feature_names()
        for i in range(batch_count):
            if temp_batch + batch_size >= len(data):
                end_batch = len(data)
            else:
                end_batch = temp_batch + batch_size
            trans_list = list(data[feature][temp_batch: end_batch])
            ############################### st pool ###############################
            # flag = True
            # tries = 0
            # while flag and tries < 10:
            #     try:
            #         tries += 1
            #         with Pool(20) as p:
            #             tf_data = p.map(model.transform, [[item] for item in trans_list])
            #             p.close()
            #             p.join()
            #         flag = False
            #     except:
            #         print("trial : {}".format(str(tries)))
            #         pass
            # tf_feature = model.get_feature_names()
            # tf_df = pd.DataFrame(columns=[feature + '_' + name for name in tf_feature], data = np.concatenate([item.toarray() for item in tf_data]))
            # temp_df = pd.concat([temp_df, tf_df], sort = True)
            # temp_batch += batch_size
            ############################### en pool ###############################

            tf_data = model.transform(data[feature][temp_batch: end_batch]).todense()  # instead of Pool
            temp_batch += batch_size
            tf_df = pd.DataFrame(columns=[feature + '_' + tf_name for tf_name in tf_feature], data=tf_data)
            temp_df = pd.concat([temp_df, tf_df])
        temp_df.fillna(0, inplace=True)
        temp_df.reset_index(drop=True, inplace=True)
        return temp_df, tf_feature

    def load_tfidf_model_trans(self, df, feature_list, batch_size, save_version):
        data = df.copy()
        prep_data = pd.DataFrame()
        for feature in feature_list:
            try:
                with open(pwd + "/obj/" + str(feature) + "_tfidf_model/" + str(
                        feature) + "_tfidf_model_" + save_version + ".pickle", "rb") as f:
                    tfidf_model = pickle.load(f)
            except:
                raise Exception
            print(feature + " model load complete **************")

            res_df, _ = self.tfidf_model_trans(tfidf_model, data, feature, batch_size)  ### max feature
            prep_data = pd.concat([prep_data, res_df], 1)
        drop_feat = []
        for f in list(prep_data):
            if len(f) > 30:
                drop_feat.append(f)
        final_feats = list(prep_data)
        for d in drop_feat:
            final_feats.remove(d)
        return prep_data[final_feats]

    # TODO
    """
    remove punctuation
    :param
        text : String Obj
    :return
        punctuation free text : String Obj
    """

    def remove_punctuation(self, text):
        punc_free = "".join([i for i in text if i not in string.punctuation])
        return punc_free

    """
    BOW : tokenization => voca => encoding
    """

    def get_tokenized_voca(self, text_arr):
        # TODO CountVectorizer with args
        # vect = CountVectorizer(min_df=5, stop_words='???').fit(text_arr)
        vect = CountVectorizer().fit(text_arr)
        return vect, vect.vocabulary_

    def get_BOW(self, vect, text_arr):
        return vect.transform(text_arr)

    def get_feature_names(self, vect):
        return vect.get_feature_names()

    def count_non_zero_from_df(self, df):
        count = df[df != 0].count()
        srt_cnt = count.sort_values(ascending=False)
        return srt_cnt / df.shape[0]

    """
    :param
        df : DataFrame
        num : DataFrame에서 선택할 feature(=column) 갯수 (default : 1000, -1은 all features
    :return
        feature list 
    """
    def get_most_wanted_features(self, df, num=1000):
        if num == -1:
            return list(df)

        res_df = pd.Series()
        for i in range(2):  # 0 : 공격, 1 : 전체
            tmp_df = df.copy()
            if i == 0:  # 공격에서만 count
                tmp_df = tmp_df[tmp_df['label'] != 'normal']
            # 학습이므로 label 있다 가정
            tmp_df.drop('label', inplace=True, axis=1)
            res_df = pd.concat([res_df, self.count_non_zero_from_df(tmp_df)], axis=0)

        res_df = res_df.sort_values(ascending=False)

        res_set = set()
        for val in list(res_df.index):
            res_set.add(val)
            if len(res_set) == num: break
        return list(res_set)

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
class CatProcessing:
    def __init__(self):
        pass
    
    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
    def save_one_hot_enc_model(self, df, save_version, m_type=None):
        if not list(df):
            print('WARNING: THERE IS NO CATEGORICAL DATA...')
            return
        print(list(df.columns))

        data = df.copy()
        # convert numeric to string
        data = data.astype(str)
        # 1. choose cat method, sparse=False to return numpy array
        ohe_model = OneHotEncoder(sparse=False, handle_unknown='ignore')
        # 2. fit
        ohe_model.fit(data)
        
        os.makedirs(pwd + "/obj/one_hot_model", exist_ok=True)
        if m_type is None:
            try:
                # 4. save model
                with open(pwd + "/obj/one_hot_model/one_hot_model_" + save_version + ".pickle", "wb") as f:
                    pickle.dump(ohe_model, f)
            except:
                raise Exception
            
        else:
            try:
                # 4. save model
                with open(pwd + f"/obj/{m_type}_one_hot_model/{m_type}_one_hot_model_" + save_version + ".pickle", "wb") as f:
                    pickle.dump(ohe_model, f)
            except:
                raise Exception
    
    #%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%#       
    def trnsfm_one_hot_enc_data(self, df, save_version, m_type=None):
        if not list(df):
            print('WARNING: THERE IS NO CATEGORICAL DATA...')
            return
        
        if m_type is None:
            try:
                with open(pwd + "/obj/one_hot_model/one_hot_model_" + save_version + ".pickle", "rb") as f:
                    ohe_model = pickle.load(f)
                # 3. transform
                return pd.DataFrame(columns=[list(df)[int(i[1:i.find('_')])] + '_' + i[i.find('_') + 1:] for i in
                                             ohe_model.get_feature_names()], data=ohe_model.transform(df))
            except:
                raise Exception
        else:
            try:
                with open(pwd + f"/obj/{m_type}_one_hot_model/{m_type}_one_hot_model_" + save_version + ".pickle", "rb") as f:
                    ohe_model = pickle.load(f)
                # 3. transform
                return pd.DataFrame(columns=[list(df)[int(i[1:i.find('_')])] + '_' + i[i.find('_') + 1:] for i in
                                             ohe_model.get_feature_names()], data=ohe_model.transform(df))
            except:
                raise Exception
            

    def inverse_transform(self, df, save_version):
        if m_type is None:
            try:
                with open(pwd + "/obj/one_hot_model/one_hot_model_" + save_version + ".pickle", "rb") as f:
                    ohe_model = pickle.load(f)
                # 3. transform
                return ohe_model.inverse_transform(df)
            except:
                raise Exception
        else:
            try:
                with open(pwd + f"/obj/{m_type}_one_hot_model/{m_type}_one_hot_model_" + save_version + ".pickle", "rb") as f:
                    ohe_model = pickle.load(f)
                # 3. transform
                return ohe_model.inverse_transform(df)
            except:
                raise Exception

    def return_categories(self, x, pred, save_version, m_type=None):
        if m_type is None:
            with open(pwd + "/obj/one_hot_model/one_hot_model_" + save_version + ".pickle", "rb") as f:
                ohe_model = pickle.load(f)
        else:
            with open(pwd + f"/obj/{m_type}_one_hot_model/{m_type}_one_hot_model_" + save_version + ".pickle", "rb") as f:
                ohe_model = pickle.load(f)

        categories_array = ohe_model.categories_
        class_dict = {}

        for i in range(len(categories_array[0])):
            class_dict[i] = categories_array[0][i]

        # result_df = x.drop('label', axis=1)
        result_df = x.copy()
        if 'ai_label' in list(result_df):
            result_df.drop('ai_label', axis=1, inplace=True)

        result_df['ai_label'] = pred

        label_list = np.array([])
        for i in range(len(result_df)):
            label_list = np.append(label_list, class_dict[tuple(result_df.ai_label)[i]])

        result_df['ai_label'] = label_list

        return result_df

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%# 
class CustomCountVectorizer(CountVectorizer):
    @_deprecate_positional_args
    def __init__(self, *, input='content', encoding='utf-8',
                 decode_error='strict', strip_accents=None,
                 lowercase=True, preprocessor=None, tokenizer=None,
                 stop_words=None, token_pattern=r"(?u)\b\w\w+\b",
                 ngram_range=(1, 1), analyzer='word',
                 max_df=1.0, min_df=1, max_features=None,
                 vocabulary=None, binary=False, dtype=np.int64):
        self.input = input
        self.encoding = encoding
        self.decode_error = decode_error
        self.strip_accents = strip_accents
        self.preprocessor = preprocessor
        self.tokenizer = tokenizer
        self.analyzer = analyzer
        self.lowercase = lowercase
        self.token_pattern = token_pattern
        self.stop_words = stop_words
        self.max_df = max_df
        self.min_df = min_df
        if max_df < 0 or min_df < 0:
            raise ValueError("negative value for max_df or min_df")
        self.max_features = max_features
        if max_features is not None:
            if (not isinstance(max_features, numbers.Integral) or
                    max_features <= 0):
                raise ValueError(
                    "max_features=%r, neither a positive integer nor None"
                    % max_features)
        self.ngram_range = ngram_range
        self.vocabulary = vocabulary
        self.binary = binary
        self.dtype = dtype

    def _limit_features(self, X, vocabulary, high=None, low=None, limit=None, fit=True):
        """Remove too rare or too common features.
        Prune features that are non zero in more samples than high or less
        documents than low, modifying the vocabulary, and restricting it to
        at most the limit most frequent.
        This does not prune samples with zero features.
        """
        if high is None and low is None and limit is None:
            return X, set()

        # Calculate a mask based on document frequencies
        dfs = _document_frequency(X)
        mask = np.ones(len(dfs), dtype=bool)
        if high is not None:
            mask &= dfs <= high
        if low is not None:
            mask &= dfs >= low

        # 2022-03-21 [Selena] 사용자가 입력한 단어를 True 처리
        if self.fixed_vocabulary_:
            mask |= [v in self.vocabulary for v in vocabulary]

        if limit is not None and mask.sum() > limit:
            tfs = np.asarray(X.sum(axis=0)).ravel()

            # 2022-03-21 [Selena] 사용자가 입력한 단어를 우선적으로 선별
            h = max(tfs)
            if self.fixed_vocabulary_:
                for vocab in self.vocabulary:
                    tfs[vocabulary[vocab]] = h + 1

            mask_inds = (-tfs[mask]).argsort()[:limit]
            new_mask = np.zeros(len(dfs), dtype=bool)
            new_mask[np.where(mask)[0][mask_inds]] = True
            mask = new_mask

        new_indices = np.cumsum(mask) - 1  # maps old indices to new
        removed_terms = set()
        for term, old_index in list(vocabulary.items()):
            if mask[old_index]:
                vocabulary[term] = new_indices[old_index]
            else:
                del vocabulary[term]
                removed_terms.add(term)
        kept_indices = np.where(mask)[0]
        if len(kept_indices) == 0:
            raise ValueError(
                "After pruning, no terms remain. Try a lower min_df or a higher max_df."
            )
        return X[:, kept_indices], removed_terms

    def _count_vocab(self, raw_documents, fixed_vocab, transform=False):
        """Create sparse feature matrix, and vocabulary where fixed_vocab=False"""
        # * 2022-03-21 [Selena]
        # transform 변수 추가 및 fixed_vocab 변수 사용방법 변경
        # transform: transform 메소드를 통해 실행된 경우 새로운 단어의 추가 없이 기존 단어장을 이용
        #            기존 fixed_vocab 변수를 통해 분기처리되던 로직을 transform 으로 변경
        # fixed_vocab: 사용자가 단어장을 입력한 경우, 단어 선별 작업 후 사용자 입력 단어 추가

        if transform:  # 기존 단어장 이용
            vocabulary = self.vocabulary_
        else:
            # Add a new value when a new vocabulary item is seen
            vocabulary = defaultdict()
            vocabulary.default_factory = vocabulary.__len__

        analyze = self.build_analyzer()
        j_indices = []
        indptr = []

        values = _make_int_array()
        indptr.append(0)
        for doc in raw_documents:
            feature_counter = {}

            # 2022-03-21 [Selena] 사용자가 입력한 단어를 단어장에 추가
            if fixed_vocab and not transform:
                for vocab in self.vocabulary:
                    feature_counter[vocabulary[vocab]] = 0

            for feature in analyze(doc):
                try:
                    feature_idx = vocabulary[feature]
                    if feature_idx not in feature_counter:
                        feature_counter[feature_idx] = 1
                    else:
                        feature_counter[feature_idx] += 1
                except KeyError:
                    # Ignore out-of-vocabulary items for fixed_vocab=True
                    continue

            j_indices.extend(feature_counter.keys())
            values.extend(feature_counter.values())
            indptr.append(len(j_indices))

        if not transform:  # 단어장을 새로 만든 경우 실행
            # disable defaultdict behaviour
            vocabulary = dict(vocabulary)
            if not vocabulary:
                raise ValueError(
                    "empty vocabulary; perhaps the documents only contain stop words"
                )

        if indptr[-1] > np.iinfo(np.int32).max:  # = 2**31 - 1
            if _IS_32BIT:
                raise ValueError(
                    (
                        "sparse CSR array has {} non-zero "
                        "elements and requires 64 bit indexing, "
                        "which is unsupported with 32 bit Python."
                    ).format(indptr[-1])
                )
            indices_dtype = np.int64

        else:
            indices_dtype = np.int32
        j_indices = np.asarray(j_indices, dtype=indices_dtype)
        indptr = np.asarray(indptr, dtype=indices_dtype)
        values = np.frombuffer(values, dtype=np.intc)

        X = sp.csr_matrix(
            (values, j_indices, indptr),
            shape=(len(indptr) - 1, len(vocabulary)),
            dtype=self.dtype,
        )
        X.sort_indices()
        return vocabulary, X

    def fit_transform(self, raw_documents, y=None):
        """Learn the vocabulary dictionary and return document-term matrix.
        This is equivalent to fit followed by transform, but more efficiently
        implemented.
        Parameters
        ----------
        raw_documents : iterable
            An iterable which generates either str, unicode or file objects.
        y : None
            This parameter is ignored.
        Returns
        -------
        X : array of shape (n_samples, n_features)
            Document-term matrix.
        """
        # We intentionally don't call the transform method to make
        # fit_transform overridable without unwanted side effects in
        # TfidfVectorizer.
        if isinstance(raw_documents, str):
            raise ValueError(
                "Iterable over raw text documents expected, string object received."
            )

        self._validate_params()
        self._validate_vocabulary()
        max_df = self.max_df
        min_df = self.min_df
        max_features = self.max_features

        if self.fixed_vocabulary_ and self.lowercase:
            for term in self.vocabulary:
                if any(map(str.isupper, term)):
                    warnings.warn(
                        "Upper case characters found in"
                        " vocabulary while 'lowercase'"
                        " is True. These entries will not"
                        " be matched with any documents"
                    )
                    break

        vocabulary, X = self._count_vocab(raw_documents, self.fixed_vocabulary_)

        if self.binary:
            X.data.fill(1)

        # 2022-03-21 [Selena] fixed_vocabulary_ 일 때만 실행하던 코드를 항상 실행하도록 수정
        n_doc = X.shape[0]
        max_doc_count = (
            max_df if isinstance(max_df, numbers.Integral) else max_df * n_doc
        )
        min_doc_count = (
            min_df if isinstance(min_df, numbers.Integral) else min_df * n_doc
        )
        if max_doc_count < min_doc_count:
            raise ValueError("max_df corresponds to < documents than min_df")
        if max_features is not None:
            X = self._sort_features(X, vocabulary)
        X, self.stop_words_ = self._limit_features(
            X, vocabulary, max_doc_count, min_doc_count, max_features, fit=True
        )
        if max_features is None:
            X = self._sort_features(X, vocabulary)
        self.vocabulary_ = vocabulary

        return X

    def transform(self, raw_documents):
        """Transform documents to document-term matrix.
        Extract token counts out of raw text documents using the vocabulary
        fitted with fit or the one provided to the constructor.
        Parameters
        ----------
        raw_documents : iterable
            An iterable which generates either str, unicode or file objects.
        Returns
        -------
        X : sparse matrix of shape (n_samples, n_features)
            Document-term matrix.
        """
        if isinstance(raw_documents, str):
            raise ValueError(
                "Iterable over raw text documents expected, string object received."
            )
        self._check_vocabulary()

        # use the same matrix-building strategy as fit_transform
        # 2022-03-21 [Selena] transform 메소드에서 _count_vocab 실행 시 transform 변수에 True 값을 전달하여
        # 단어장을 새로 생성하지 않도록 수정
        _, X = self._count_vocab(raw_documents, fixed_vocab=True, transform=True)
        if self.binary:
            X.data.fill(1)
        return X

#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%# 
def _make_int_array():
    """Construct an array.array of a type suitable for scipy.sparse indices."""
    return array.array(str("i"))


# 2022-03-21 [Selena] CustomTfidfVectorizer 는 CustomCountVectorizer 의 기능을 상속받아 사용하기 위해 작성되었으며,
# 기존 TfidfVectorizer 에서 수정된 코드는 없음
#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%% 생존 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%# 
class CustomTfidfVectorizer(CustomCountVectorizer):
    @_deprecate_positional_args
    def __init__(self, *, input='content', encoding='utf-8',
                 decode_error='strict', strip_accents=None, lowercase=True,
                 preprocessor=None, tokenizer=None, analyzer='word',
                 stop_words=None, token_pattern=r"(?u)\b\w\w+\b",
                 ngram_range=(1, 1), max_df=1.0, min_df=1,
                 max_features=None, vocabulary=None, binary=False,
                 dtype=np.float64, norm='l2', use_idf=True, smooth_idf=True,
                 sublinear_tf=False):

        super().__init__(
            input=input, encoding=encoding, decode_error=decode_error,
            strip_accents=strip_accents, lowercase=lowercase,
            preprocessor=preprocessor, tokenizer=tokenizer, analyzer=analyzer,
            stop_words=stop_words, token_pattern=token_pattern,
            ngram_range=ngram_range, max_df=max_df, min_df=min_df,
            max_features=max_features, vocabulary=vocabulary, binary=binary,
            dtype=dtype)

        self._tfidf = TfidfTransformer(norm=norm, use_idf=use_idf,
                                       smooth_idf=smooth_idf,
                                       sublinear_tf=sublinear_tf)

    # Broadcast the TF-IDF parameters to the underlying transformer instance
    # for easy grid search and repr

    @property
    def norm(self):
        return self._tfidf.norm

    @norm.setter
    def norm(self, value):
        self._tfidf.norm = value

    @property
    def use_idf(self):
        return self._tfidf.use_idf

    @use_idf.setter
    def use_idf(self, value):
        self._tfidf.use_idf = value

    @property
    def smooth_idf(self):
        return self._tfidf.smooth_idf

    @smooth_idf.setter
    def smooth_idf(self, value):
        self._tfidf.smooth_idf = value

    @property
    def sublinear_tf(self):
        return self._tfidf.sublinear_tf

    @sublinear_tf.setter
    def sublinear_tf(self, value):
        self._tfidf.sublinear_tf = value

    @property
    def idf_(self):
        return self._tfidf.idf_

    @idf_.setter
    def idf_(self, value):
        self._validate_vocabulary()
        if hasattr(self, 'vocabulary_'):
            if len(self.vocabulary_) != len(value):
                raise ValueError("idf length = %d must be equal "
                                 "to vocabulary size = %d" %
                                 (len(value), len(self.vocabulary)))
        self._tfidf.idf_ = value

    def _check_params(self):
        if self.dtype not in FLOAT_DTYPES:
            warnings.warn("Only {} 'dtype' should be used. {} 'dtype' will "
                          "be converted to np.float64."
                          .format(FLOAT_DTYPES, self.dtype),
                          UserWarning)

    def fit(self, raw_documents, feature_list=None, save_version=None, y=None, m_type=None):
        """Learn vocabulary and idf from training set.

        Parameters
        ----------
        raw_documents : iterable
            An iterable which yields either str, unicode or file objects.
        y : None
            This parameter is not needed to compute tfidf.

        Returns
        -------
        self : object
            Fitted vectorizer.
        """
        self._check_params()
        self._warn_for_unused_params()
        X = super().fit_transform(raw_documents)
        self._tfidf.fit(X)

        for feature in feature_list:
            if m_type == 'cnn':
                if not os.path.exists(pwd + "/obj/" + str(feature) + "_cnn_tfidf_model"):
                    os.makedirs(pwd + "/obj/" + str(feature) + "_cnn_tfidf_model")
                try:
                    with open(pwd + "/obj/" + str(feature) + "_cnn_tfidf_model/" + str(
                            feature) + "_cnn_tfidf_model_" + save_version + ".pickle", "wb") as f:
                        pickle.dump(self._tfidf, f)
                except:
                    raise Exception
            else:
                if not os.path.exists(pwd + "/obj/" + str(feature) + "_tfidf_model"):
                    os.makedirs(pwd + "/obj/" + str(feature) + "_tfidf_model")
                try:
                    with open(pwd + "/obj/" + str(feature) + "_tfidf_model/" + str(
                            feature) + "_tfidf_model_" + save_version + ".pickle", "wb") as f:
                        pickle.dump(self._tfidf, f)
                except:
                    raise Exception
            print(feature, pwd + "/obj save complete **************")

        return self

    def fit_transform(self, raw_documents, y=None):
        """Learn vocabulary and idf, return document-term matrix.

        This is equivalent to fit followed by transform, but more efficiently
        implemented.

        Parameters
        ----------
        raw_documents : iterable
            An iterable which yields either str, unicode or file objects.
        y : None
            This parameter is ignored.

        Returns
        -------
        X : sparse matrix of (n_samples, n_features)
            Tf-idf-weighted document-term matrix.
        """
        self._check_params()
        X = super().fit_transform(raw_documents)
        self._tfidf.fit(X)
        # X is already a transformed view of raw_documents so
        # we set copy to False
        return self._tfidf.transform(X, copy=False)

    def transform(self, raw_documents, feature_list=None, save_version=None, mode=None, m_type=None):
        """Transform documents to document-term matrix.

        Uses the vocabulary and document frequencies (df) learned by fit (or
        fit_transform).

        Parameters
        ----------
        raw_documents : iterable
            An iterable which yields either str, unicode or file objects.

        Returns
        -------
        X : sparse matrix of (n_samples, n_features)
            Tf-idf-weighted document-term matrix.
        """
        if mode == 'train':
            check_is_fitted(self, msg='The TF-IDF vectorizer is not fitted')

        for feature in feature_list:
            if m_type == 'cnn':
                try:
                    with open(pwd + "/obj/" + str(feature) + "_cnn_tfidf_model/" + str(
                            feature) + "_cnn_tfidf_model_" + save_version + ".pickle", "rb") as f:
                        transform_model = pickle.load(f)
                except:
                    raise Exception
            else:
                try:
                    with open(pwd + "/obj/" + str(feature) + "_tfidf_model/" + str(
                            feature) + "_tfidf_model_" + save_version + ".pickle", "rb") as f:
                        transform_model = pickle.load(f)
                except:
                    raise Exception
            print(feature + " model load complete **************")
            batch_size=10000
            if raw_documents.shape[0] > batch_size:
                trans_data = self.trans_to_batch_size(raw_documents, feature, model=transform_model, batch_size=batch_size)
            else:
                trans_data = self.trans_no_batch(raw_documents, feature, model=transform_model)

        return trans_data

    def _more_tags(self):
        return {'X_types': ['string'], '_skip_test': True}
    
    def transform_pool(self, model, trans_array):
        X = super().transform(trans_array)
        tf_data = model.transform(X, copy=False).toarray()
        return tf_data
    
    def trans_no_batch(self, raw_documents, feature, model=None):
        data = raw_documents.copy()
        tf_data = self.transform_pool(model, data)
#         tf_df = pd.DataFrame(columns=[feature + '_' + tf_name for tf_name in list(dict(sorted(self.vocabulary_.items(), key=lambda item: item[1])))], data=tf_data)
        tf_df = pd.DataFrame(columns=[tf_name for tf_name in list(dict(sorted(self.vocabulary_.items(), key=lambda item: item[1])))], data=tf_data)
        tf_df.fillna(0, inplace=True)
        tf_df.reset_index(drop=True, inplace=True)
        return tf_df
        
    def trans_to_batch_size(self, raw_documents, feature, model=None, batch_size=None):
        data = raw_documents.copy()
        temp_batch = 0
        temp_df = pd.DataFrame()

        if len(data) % batch_size == 0:
            batch_count = int(len(data) / batch_size)
        else:
            batch_count = int(len(data) / batch_size) + 1

        for i in range(batch_count):
            if temp_batch + batch_size >= len(data):
                end_batch = len(data)
            else:
                end_batch = temp_batch + batch_size
            trans_array = data[temp_batch: end_batch]
            ### st multi_process ######################################
#             print("TOTAL CPU : {}".format(os.cpu_count()))
            num_cores = 20
            if len(trans_array) <= num_cores:
                num_cores = 1
            split_trans_array = np.array_split(trans_array, num_cores)
            tmp_func = partial(self.transform_pool, model)
            pool = ThreadPool(num_cores)
            tf_data = np.concatenate(pool.map(tmp_func, split_trans_array))
            pool.close()
            pool.join()
            ### en multi_process ######################################
            temp_batch += batch_size
#             tf_df = pd.DataFrame(columns=[feature + '_' + tf_name for tf_name in list(dict(sorted(self.vocabulary_.items(), key=lambda item: item[1])))], data=tf_data)
            tf_df = pd.DataFrame(columns=[tf_name for tf_name in list(dict(sorted(self.vocabulary_.items(), key=lambda item: item[1])))], data=tf_data)
            temp_df = pd.concat([temp_df, tf_df])
        temp_df.fillna(0, inplace=True)
        temp_df.reset_index(drop=True, inplace=True)
        return temp_df

#     def trans_to_batch_size(self, raw_documents, feature, model=None, batch_size=None):
#         data = raw_documents.copy()
#         temp_batch = 0
#         temp_df = pd.DataFrame()

#         if len(data) % batch_size == 0:
#             batch_count = int(len(data) / batch_size)
#         else:
#             batch_count = int(len(data) / batch_size) + 1

#         for i in range(batch_count):
#             if temp_batch + batch_size >= len(data):
#                 end_batch = len(data)
#             else:
#                 end_batch = temp_batch + batch_size

#             trans_array = data[temp_batch: end_batch]
#             X = super().transform(trans_array)

#             tf_data = model.transform(X, copy=False).toarray()

#             temp_batch += batch_size
#             tf_df = pd.DataFrame(columns=[feature + '_' + tf_name for tf_name in
#                                           list(dict(sorted(self.vocabulary_.items(), key=lambda item: item[1])))],
#                                  data=tf_data)
#             temp_df = pd.concat([temp_df, tf_df])

#         temp_df.fillna(0, inplace=True)
#         temp_df.reset_index(drop=True, inplace=True)

#         return temp_df

        # drop_feat = []
        # for f in list(temp_df):
        #     if len(f) > 30:
        #         drop_feat.append(f)
        # final_feats = list(temp_df)
        # for d in drop_feat:
        #     final_feats.remove(d)
        #
        # return temp_df[final_feats]



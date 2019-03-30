
"""
Contributers :  Deepak Joshi
                Sunil Poyagadde Rao
                Kartikeya pai
                Nikhil Shivamurthy
"""

import pandas as pd
import numpy as np
import sys
import sklearn


#1. LOADING THE DAATASET
# attach the column names to the dataset
col_names = ["duration","protocol_type","service","flag","src_bytes",
    "dst_bytes","land","wrong_fragment","urgent","hot","num_failed_logins",
    "logged_in","num_compromised","root_shell","su_attempted","num_root",
    "num_file_creations","num_shells","num_access_files","num_outbound_cmds",
    "is_host_login","is_guest_login","count","srv_count","serror_rate",
    "srv_serror_rate","rerror_rate","srv_rerror_rate","same_srv_rate",
    "diff_srv_rate","srv_diff_host_rate","dst_host_count","dst_host_srv_count",
    "dst_host_same_srv_rate","dst_host_diff_srv_rate","dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate","dst_host_serror_rate","dst_host_srv_serror_rate",
    "dst_host_rerror_rate","dst_host_srv_rerror_rate","label"]


df = pd.read_csv("KDDTrain+_2.csv", header=None, names = col_names)
df_test = pd.read_csv("KDDTest+_2.csv", header=None, names = col_names)

# print('Dimensions of the Training set:',df.shape)
# # print('Dimensions of the Test set:',df_test.shape)


#LABEL DISTRIBUTION OF TRAINING AND TEST DATASET
# print('Label distribution Training set:')
# print(df['label'].value_counts())
# print()
# print('Label distribution Test set:')
# print(df_test['label'].value_counts())

#************************************************************************************
#2. DATA PREPROCESSING
#Identify Categorical Features
# print('Training set:')
# for col_name in df.columns:
#     if df[col_name].dtypes == 'object' :
#         unique_cat = len(df[col_name].unique())
#         print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=unique_cat))
#
#
# print()
# print('Distribution of categories in service:')
# print(df['service'].value_counts().sort_values(ascending=False).head())


# # Test set
# print('Test set:')
# for col_name in df_test.columns:
#     if df_test[col_name].dtypes == 'object' :
#         unique_cat = len(df_test[col_name].unique())
#         print("Feature '{col_name}' has {unique_cat} categories".format(col_name=col_name, unique_cat=unique_cat))
#

#****************************************************************************************

#3. LABEL ENCODER
from sklearn.preprocessing import LabelEncoder,OneHotEncoder
categorical_columns=['protocol_type', 'service', 'flag']
# insert code to get a list of categorical columns into a variable, categorical_columns
categorical_columns=['protocol_type', 'service', 'flag']
 # Get the categorical values into a 2D numpy array
df_categorical_values = df[categorical_columns]
testdf_categorical_values = df_test[categorical_columns]
df_categorical_values.head()

#Make column names for dummies
unique_protocol=sorted(df.protocol_type.unique())
string1 = 'Protocol_type_'
unique_protocol2=[string1 + x for x in unique_protocol]
# service
unique_service=sorted(df.service.unique())
string2 = 'service_'
unique_service2=[string2 + x for x in unique_service]
# flag
unique_flag=sorted(df.flag.unique())
string3 = 'flag_'
unique_flag2=[string3 + x for x in unique_flag]
# put together
dumcols=unique_protocol2 + unique_service2 + unique_flag2


#doing same for test set
unique_service_test=sorted(df_test.service.unique())
unique_service2_test=[string2 + x for x in unique_service_test]
testdumcols=unique_protocol2 + unique_service2_test + unique_flag2

#Transform categorical features into numbers using LabelEncoder()
df_categorical_values_enc=df_categorical_values.apply(LabelEncoder().fit_transform)
#print(df_categorical_values_enc.head())

# test set
testdf_categorical_values_enc=testdf_categorical_values.apply(LabelEncoder().fit_transform)

#One-Hot-Encoding
enc = OneHotEncoder()
df_categorical_values_encenc = enc.fit_transform(df_categorical_values_enc)
df_cat_data = pd.DataFrame(df_categorical_values_encenc.toarray(),columns=dumcols)
# test set
testdf_categorical_values_encenc = enc.fit_transform(testdf_categorical_values_enc)
testdf_cat_data = pd.DataFrame(testdf_categorical_values_encenc.toarray(),columns=testdumcols)

#Add 6 missing categories from train set to test set
trainservice=df['service'].tolist()
testservice= df_test['service'].tolist()
difference=list(set(trainservice) - set(testservice))
string = 'service_'
difference=[string + x for x in difference]
#print(diference)

for col in difference:
    testdf_cat_data[col] = 0
#print(testdf_cat_data.shape)


#Joining encoded categorical dataframe with the non-categorical dataframe
newdf=df.join(df_cat_data)
newdf.drop('flag', axis=1, inplace=True)
newdf.drop('protocol_type', axis=1, inplace=True)
newdf.drop('service', axis=1, inplace=True)

# test data
newdf_test=df_test.join(testdf_cat_data)
newdf_test.drop('flag', axis=1, inplace=True)
newdf_test.drop('protocol_type', axis=1, inplace=True)
newdf_test.drop('service', axis=1, inplace=True)
# print(newdf.shape)
# print(newdf_test.shape)

#Split Dataset into 4 datasets for every attack category
#Rename every attack label: 0=normal, 1=DoS, 2=Probe, 3=R2L and 4=U2R.
#Replace labels column with new labels column
#Make new datasets
labeldf=newdf['label']
labeldf_test=newdf_test['label']
# change the label column
newlabeldf=labeldf.replace({ 'normal' : 0, 'neptune' : 1 ,'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                           'ipsweep' : 2,'nmap' : 2,'portsweep' : 2,'satan' : 2,'mscan' : 2,'saint' : 2
                           ,'ftp_write': 3,'guess_passwd': 3,'imap': 3,'multihop': 3,'phf': 3,'spy': 3,'warezclient': 3,'warezmaster': 3,'sendmail': 3,'named': 3,'snmpgetattack': 3,'snmpguess': 3,'xlock': 3,'xsnoop': 3,'httptunnel': 3,
                           'buffer_overflow': 4,'loadmodule': 4,'perl': 4,'rootkit': 4,'ps': 4,'sqlattack': 4,'xterm': 4})
newlabeldf_test=labeldf_test.replace({ 'normal' : 0, 'neptune' : 1 ,'back': 1, 'land': 1, 'pod': 1, 'smurf': 1, 'teardrop': 1,'mailbomb': 1, 'apache2': 1, 'processtable': 1, 'udpstorm': 1, 'worm': 1,
                           'ipsweep' : 2,'nmap' : 2,'portsweep' : 2,'satan' : 2,'mscan' : 2,'saint' : 2
                           ,'ftp_write': 3,'guess_passwd': 3,'imap': 3,'multihop': 3,'phf': 3,'spy': 3,'warezclient': 3,'warezmaster': 3,'sendmail': 3,'named': 3,'snmpgetattack': 3,'snmpguess': 3,'xlock': 3,'xsnoop': 3,'httptunnel': 3,
                           'buffer_overflow': 4,'loadmodule': 4,'perl': 4,'rootkit': 4,'ps': 4,'sqlattack': 4,'xterm': 4})

# put the new label column back
newdf['label'] = newlabeldf
newdf_test['label'] = newlabeldf_test

to_drop_DoS = [2,3,4]
to_drop_Probe = [1,3,4]
to_drop_R2L = [1,2,4]
to_drop_U2R = [1,2,3]
DoS_df=newdf[~newdf['label'].isin(to_drop_DoS)]
Probe_df=newdf[~newdf['label'].isin(to_drop_Probe)]
R2L_df=newdf[~newdf['label'].isin(to_drop_R2L)]
U2R_df=newdf[~newdf['label'].isin(to_drop_U2R)]

#test
DoS_df_test=newdf_test[~newdf_test['label'].isin(to_drop_DoS)]
Probe_df_test=newdf_test[~newdf_test['label'].isin(to_drop_Probe)]
R2L_df_test=newdf_test[~newdf_test['label'].isin(to_drop_R2L)]
U2R_df_test=newdf_test[~newdf_test['label'].isin(to_drop_U2R)]

#***************************************************************************************************

#Step 4: Feature Scaling
# Split dataframes into X & Y
# assign X as a dataframe of feautures and Y as a series of outcome variables
X_DoS = DoS_df.drop('label',1)
X_Probe = Probe_df.drop('label',1)
X_R2L = R2L_df.drop('label',1)
X_U2R = U2R_df.drop('label',1)

# test set
X_DoS_test = DoS_df_test.drop('label',1)
X_Probe_test = Probe_df_test.drop('label',1)
X_R2L_test = R2L_df_test.drop('label',1)
X_U2R_test = U2R_df_test.drop('label',1)

colNames=list(X_DoS)
colNames_test=list(X_DoS_test)

#Use StandardScaler() to scale the dataframes
from sklearn import preprocessing

scaler1 = preprocessing.StandardScaler().fit(X_DoS)
scaler2 = preprocessing.StandardScaler().fit(X_Probe)
scaler3 = preprocessing.StandardScaler().fit(X_R2L)
scaler4 = preprocessing.StandardScaler().fit(X_U2R)

# test data
scaler5 = preprocessing.StandardScaler().fit(X_DoS_test)
scaler6 = preprocessing.StandardScaler().fit(X_Probe_test)
scaler7 = preprocessing.StandardScaler().fit(X_R2L_test)
scaler8 = preprocessing.StandardScaler().fit(X_U2R_test)

#*******************************************************************************************
#Feature Selection
from sklearn.feature_selection import SelectPercentile, f_classif
np.seterr(divide='ignore', invalid='ignore');
selector=SelectPercentile(f_classif, percentile=10)
X_newDoS = selector.fit_transform(X_DoS,Y_DoS)

#Get the features that were selected: DoS
true=selector.get_support()
newcolindex_DoS=[i for i, x in enumerate(true) if x]
newcolname_DoS=list( colNames[i] for i in newcolindex_DoS )
X_newProbe = selector.fit_transform(X_Probe,Y_Probe)

#Get the features that were selected: Probe
true=selector.get_support()
newcolindex_Probe=[i for i, x in enumerate(true) if x]
newcolname_Probe=list( colNames[i] for i in newcolindex_Probe )


print('Features selected for DoS:',newcolname_DoS)
print()
print('Features selected for Probe:',newcolname_Probe)


#Recursive Feature Elimination, select 13 features each of 122
from sklearn.feature_selection import RFE
clf = RandomForestClassifier(n_jobs=2)
rfe = RFE(estimator=clf, n_features_to_select=13, step=1)
rfe.fit(X_DoS, Y_DoS)
X_rfeDoS=rfe.transform(X_DoS)
true=rfe.support_
rfecolindex_DoS=[i for i, x in enumerate(true) if x]
rfecolname_DoS=list(colNames[i] for i in rfecolindex_DoS)

rfe.fit(X_Probe, Y_Probe)
X_rfeProbe=rfe.transform(X_Probe)
true=rfe.support_
rfecolindex_Probe=[i for i, x in enumerate(true) if x]
rfecolname_Probe=list(colNames[i] for i in rfecolindex_Probe)

print('Features selected for DoS:',rfecolname_DoS)
print()
print('Features selected for Probe:',rfecolname_Probe)

#Step 4: Build the model
# selected features
clf_rfeDoS=RandomForestClassifier(n_jobs=2)
clf_rfeProbe=RandomForestClassifier(n_jobs=2)
clf_rfeR2L=RandomForestClassifier(n_jobs=2)
clf_rfeU2R=RandomForestClassifier(n_jobs=2)
clf_rfeDoS.fit(X_rfeDoS, Y_DoS)
clf_rfeProbe.fit(X_rfeProbe, Y_Probe)
clf_rfeR2L.fit(X_rfeR2L, Y_R2L)
clf_rfeU2R.fit(X_rfeU2R, Y_U2R)

#Step 5: Prediction & Evaluation

#DOS
Y_DoS_pred=clf_DoS.predict(X_DoS_test)
# Create confusion matrix
pd.crosstab(Y_DoS_test, Y_DoS_pred, rownames=['Actual attacks'], colnames=['Predicted attacks'])

#PROBE
Y_Probe_pred=clf_Probe.predict(X_Probe_test)
# Create confusion matrix
pd.crosstab(Y_Probe_test, Y_Probe_pred, rownames=['Actual attacks'], colnames=['Predicted attacks'])


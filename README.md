# Intrusion-Detection-System
CMPE 209 Network Security Project 

Description:

•	Technology stack - NLS-KDD dataset, Python, Scikit-learn, Feature selection: Anova-F test and Recursive Feature Elimination (RFE), Build Model: Random Forest Regression,

•	This project deals with Design and Development of IDS for testing intrusion against back dos, buffer overflow, ftp write, imap, nmap probe, Smurf dos, IPsweep probe, teardrop dos etc. Accuracy achieved is 87%.

This work aims to perform the work done by Nkiama, Said and Saidu (2016) in: https://thesai.org/Downloads/Volume7No4/Paper_19-A_Subset_Feature_Elimination_Mechanism_for_Intrusion_Detection_System.pdf

Method Description

Step 1: Data preprocessing:
All features are made numerical using one-Hot-encoding. The features are scaled to avoid features with large values that may weigh too much in the results.

Step 2: Feature Selection:
Eliminate redundant and irrelevant data by selecting a subset of relevant features that fully represents the given problem. Univariate feature selection with ANOVA F-test. This analyzes each feature individually to detemine the strength of the relationship between the feature and labels. Using SecondPercentile method (sklearn.feature_selection) to select features based on percentile of the highest scores. When this subset is found: Recursive Feature Elimination (RFE) is applied.

Step 4: Build the model:
Decision tree model is built.

Step 5: Prediction & Evaluation (validation):
Using the test data to make predictions of the model. Multiple scores are considered such as:accuracy score,confusion matrix. perform a 10-fold cross-validation.


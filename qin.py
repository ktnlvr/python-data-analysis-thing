# %%
import pandas as pd
from matplotlib import pyplot as plt
from scipy import stats
import numpy as np
import plotly.express as px
import kagglehub
from os.path import join as path_join

# %%
data_root = kagglehub.dataset_download("andrewkronser/cve-common-vulnerabilities-and-exposures")

# %%
## 📌 1. Loading the Dataset

# >## 💡 **Interpretation**:
# -   **mod_date: The date the entry was last modified.**
# -  **pub_date: The date the entry was published.**
# -  **cvss: Common Vulnerability Scoring System (CVSS) score, a measure of the severity of a vulnerability.**
# -  **cwe_code: Common Weakness Enumeration (CWE) code, identifying the type of weakness.**
# -  **cwe_name: The name associated with the CWE code.**
# -  **summary: A text summary of the vulnerability.**
# -  **access_authentication.**
# -  **access_complexity: how difficult it is to execute.**
# -  **access_vector: how the attack is performed, aka via network or locally.**

df = pd.read_csv(path_join(data_root, 'cve.csv'), header=0, index_col=0)
df.mod_date = pd.to_datetime(df.mod_date)
df.pub_date = pd.to_datetime(df.pub_date)

df.info() 
non_par_com = {"NONE": 0, "COMPLETE": 2, "PARTIAL": 1}
low_med_hih = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
non_sin_mul = {"NONE": 0, "SINGLE": 1, "MULTIPLE": 2}
loc_adj_net = {"LOCAL": 0, "ADJACENT_NETWORK": 1, "NETWORK": 2}

ordinal_remapping = {
    "access_authentication": non_sin_mul,
    "access_complexity": low_med_hih,
    "access_vector": loc_adj_net,
    "impact_availability": non_par_com,
    "impact_confidentiality": non_par_com,
    "impact_integrity": non_par_com,
}

for ordinal_column in ordinal_remapping:
    df[ordinal_column] = df[ordinal_column].apply(
        lambda v: ordinal_remapping[ordinal_column].get(v, v)
    )


## 🧼 2. Handling Missing Data

missing_counts = df.isnull().sum()
print("Missing Data Count:\n", missing_counts)

## **3. Probability Distribution & Descriptive Stats**
### 🎯 Expected Value (Mean)

# The McCumber Cube is a model framework created by John McCumber in 1991 to
# help organizations establish and evaluate information security initiatives
# by considering all of the related factors that impact them.
# This security model has three dimensions:
# The foundational principles for protecting information systems.
# 1.availability, 2.integrity, 3.Confidentiality ✅
# The protection of information in each of its possible states.
# The security measures used to protect data.
#

# Min and Max of DataFrame columns
print("Minimum values in each column:")
print(df.min(numeric_only=True))

print("\nMaximum values in each column:")
print(df.max(numeric_only=True))

# Geometric Mean
# Calculate the geometric mean of cvss
geometric_mean_cvss = stats.gmean(df["cvss"].dropna())
print(f"\nGeometric Mean of cvss: {geometric_mean_cvss:.2f}")

# Calculate the geometric mean of cwe_code
geometric_mean_cwe_code = stats.gmean(df["cwe_code"].dropna())
print(f"\nGeometric Mean of cwe_code: {geometric_mean_cwe_code:.2f}")


# %%

# Min and Max of DataFrame columns
print("Minimum values in each column:")
print(df.min(numeric_only=True))

print("\nMaximum values in each column:")
print(df.max(numeric_only=True))

# %%
### 📈 Variance and Standard Deviation


## 📊 4.Visualising Relationships

### 📊 4.1 Distribution Shapes

column_name = 'impact_confidentiality'

# Drop NaN values just in case
clean_impact_confidentiality = df[column_name].dropna()

# Mean, Variance, and Standard Deviation
mean_val = np.mean(clean_impact_confidentiality)
var_val = np.var(clean_impact_confidentiality, ddof=1)     # sample variance
std_val = np.std(clean_impact_confidentiality, ddof=1)     # sample standard deviation

print(f"Mean (Expected Value): {mean_val:.4f}")
print(f"Variance: {var_val:.4f}")
print(f"Standard Deviation: {std_val:.4f}")

# Visualize distribution
plt.hist(clean_impact_confidentiality, bins=30)
plt.title(f"Histogram of {column_name}")
plt.xlabel(column_name)
plt.ylabel("Frequency")
plt.show()

# Summary:
# The histogram shows the distribution of the impact_confidentiality values in our dataset.
#
# We also calculated key descriptive statistics:
#
# - The mean value of approximately 0.8659 indicates the average confidentiality values in the dataset.
# - The variance of 0.5085 tells us how spread out the values are — specifically, it’s the average of the squared differences from the mean.
# - The standard deviation of 0.7131 shows that most of the confidentiality values are within ±0.7131 units of the mean —
# a more interpretable measure than variance since it shares the same units as the data.
# - The histogram is asymmetric and slightly skewed, suggesting that the distribution is not perfectly normal.
# - There's a wide spread in the values, ranging from slightly below 15000 to above 40000.


### 📦 4.2 Outliers in Boxplots

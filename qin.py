# %%
import pandas as pd
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

## 🧼 2. Handling Missing Data

missing_counts = df.isnull().sum()
print("Missing Data Count:\n", missing_counts)

## **3. Probability Distribution & Descriptive Stats**
### 🎯 Expected Value (Mean)

from scipy import stats

# Convert the 'access_complexity' column to a list
access_complexity_list = df['access_complexity'].tolist()

# Unique access_complexity
unique_access_complexity = list(set(access_complexity_list))
print("\nUnique access_complexity:", unique_access_complexity)

# Unique impact_availability
access_impact_availability = df['impact_availability'].tolist()
unique_impact_availability = list(set(access_impact_availability))
print("\nUnique impact_availability:", unique_impact_availability)

# Unique impact_confidentiality
access_impact_confidentiality = df['impact_confidentiality'].tolist()
unique_impact_confidentiality = list(set(access_impact_confidentiality))
print("\nUnique impact_confidentiality:", unique_impact_confidentiality)

# Unique impact_integrity
access_impact_integrity  = df['impact_integrity'].tolist()
unique_impact_integrity  = list(set(access_impact_integrity ))
print("\nUnique impact_integrity:", unique_impact_integrity )

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

from scipy import stats

# Min and Max of DataFrame columns
print("Minimum values in each column:")
print(df.min(numeric_only=True))

print("\nMaximum values in each column:")
print(df.max(numeric_only=True))



# Geometric Mean
# Calculate the geometric mean of cvss
geometric_mean_cvss = stats.gmean(df["cvss"].dropna())
print(f"\nGeometric Mean of cvss: {geometric_mean_cvss:.2f}")




# %%

# Min and Max of DataFrame columns
print("Minimum values in each column:")
print(df.min(numeric_only=True))

print("\nMaximum values in each column:")
print(df.max(numeric_only=True))
# %%

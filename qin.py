# %%
import pandas as pd
import numpy as np
import plotly.express as px
import kagglehub
from os.path import join as path_join

# %%
data_root = kagglehub.dataset_download("andrewkronser/cve-common-vulnerabilities-and-exposures")

# %%
df = pd.read_csv(path_join(data_root, 'cve.csv'), header=0, index_col=0)
df.mod_date = pd.to_datetime(df.mod_date)
df.pub_date = pd.to_datetime(df.pub_date)

df.info() 

# %%

# Min and Max of DataFrame columns
print("Minimum values in each column:")
print(df.min(numeric_only=True))

print("\nMaximum values in each column:")
print(df.max(numeric_only=True))
# %%

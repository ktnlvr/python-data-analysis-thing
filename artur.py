# %%
import pandas as pd
import numpy as np
import plotly.express as px
from dataset import df
from statsmodels.tsa.seasonal import STL
import ruptures as rpt
from scipy.stats import ttest_ind

df.info()

df["pub_year"] = df["pub_date"].dt.year
df["pub_year_month"] = df["pub_date"].dt.to_period("M").dt.to_timestamp()

# %%

df.describe()

# %%
# General count of events over time

year_x_count = df.groupby("pub_year").size().reset_index(name="count")
px.line(year_x_count, x="pub_year", y="count", log_y=True)

# %%
# Seasonal/Trend Decomposition, wanted to try this one for a while

month_year_df = df.copy()

month_year_x_count = (
    month_year_df.groupby("pub_year_month").size().reset_index(name="count")
)

stl = STL(month_year_x_count["count"], period=12)
result = stl.fit()

month_year_x_count["trend"] = result.trend
month_year_x_count["season"] = result.seasonal
month_year_x_count["resid"] = result.resid

display(px.line(month_year_x_count, x="pub_year_month", y="season"))
display(px.line(month_year_x_count, x="pub_year_month", y="trend"))
display(px.line(month_year_x_count, x="pub_year_month", y="resid"))

# %%
# Ok, it seems like a lot of vulnerabilities are published in December

month_x_count = (
    df.groupby(by=lambda d: df["pub_date"][d].month).size().reset_index(name="count")
)

px.bar(month_x_count, x="index", y="count")

# No clear anomalies in December? Weird, maybe they happened before some date because the vulnerability archives were updated

# %%

december_vuln_count = (
    df[df["pub_date"].dt.month == 1]
    .groupby("pub_year")
    .size()
    .reset_index(name="count")
)

non_december_vuln_count = (
    df[df["pub_date"].dt.month != 1]
    .groupby("pub_year")
    .size()
    .reset_index(name="count")
) / 11

# %%

_, pvalue = ttest_ind(december_vuln_count["count"], non_december_vuln_count["count"])
print(pvalue, pvalue < 0.05)

# Ok, no trend in December, nice, so it was a fluke

# %%
# Is there a significant amount of critical vulnerabilities discovered over time?

# %%
# For further processing split into training and test data

# Decided arbitrarily, as if we are calculating from that point
split_date = "2016-12-20"

train_df = df[df["pub_date"] <= split_date]
test_df = df[df["pub_date"] > split_date]

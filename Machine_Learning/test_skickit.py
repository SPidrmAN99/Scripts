#import os
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.linear_model import LinearRegression

#os.system('cls')
# Download and prepare data
data_root = "https://github.com/ageron/data/raw/main/"
lifesat = pd.read_csv(data_root + "lifesat/lifesat.csv")
print(lifesat.columns)  # Add this to debug column names
X = lifesat[["GDP per capita (USD)"]].values  # Updated column name
y = lifesat["Life satisfaction"].values

# Visualize data
lifesat.plot(kind='scatter', grid=True, x="GDP per capita (USD)", y="Life satisfaction")  # Updated column name
plt.axis([23500, 62500, 4, 9])
plt.show()

# Select a linear model
model = LinearRegression()

# Train the model
model.fit(X, y)

# Make a prediction for Cyprus
X_new = [[37655.2]]
print(model.predict(X_new))
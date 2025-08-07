"""
Machine Learning based anomaly detection for Chronicle SIEM
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from typing import List, Dict

class AnomalyDetector:
    def __init__(self):
        self.scaler = StandardScaler()
        self.isolation_forest = IsolationForest(
            contamination=0.1,
            random_state=42
        )
        self._initialize_neural_network()

    def _initialize_neural_network(self):
        """Initialize autoencoder for deep anomaly detection"""
        self.autoencoder = tf.keras.Sequential([
            tf.keras.layers.Dense(64, activation='relu', input_shape=(32,)),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(16, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32)
        ])
        self.autoencoder.compile(optimizer='adam', loss='mse')

    def process_features(self, events: List[Dict]) -> np.ndarray:
        """Extract and normalize features from events"""
        features = []
        for event in events:
            feature_vector = [
                event.get('bytes_transferred', 0),
                event.get('request_count', 0),
                event.get('unique_ips', 0),
                event.get('access_count', 0),
                # Time-based features
                event.get('hour_of_day', 0),
                event.get('day_of_week', 0),
                # Add more relevant features
            ]
            features.append(feature_vector)
        return self.scaler.fit_transform(np.array(features))

    def detect_anomalies(self, events: List[Dict]) -> List[Dict]:
        """Detect anomalies using multiple methods"""
        features = self.process_features(events)
        
        # Isolation Forest detection
        if_predictions = self.isolation_forest.fit_predict(features)
        
        # Autoencoder detection
        reconstructed = self.autoencoder.predict(features)
        reconstruction_errors = np.mean(np.square(features - reconstructed), axis=1)
        ae_predictions = reconstruction_errors > np.percentile(reconstruction_errors, 90)
        
        # Combine predictions
        anomalies = []
        for idx, (event, if_pred, ae_pred) in enumerate(zip(events, if_predictions, ae_predictions)):
            if if_pred == -1 or ae_pred:  # If either method detects anomaly
                anomaly = event.copy()
                anomaly.update({
                    'anomaly_score': reconstruction_errors[idx],
                    'detection_method': 'isolation_forest' if if_pred == -1 else 'autoencoder',
                    'confidence': float(reconstruction_errors[idx] / np.max(reconstruction_errors))
                })
                anomalies.append(anomaly)
        
        return anomalies

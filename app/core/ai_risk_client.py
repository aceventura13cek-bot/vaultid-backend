"""
AI Risk Scoring Client
Integrates with AI engineer's risk assessment service
"""

import requests
from typing import Dict, Optional
import logging

logger = logging.getLogger(__name__)


class AIRiskClient:
    """
    Client for AI risk scoring service
    
    The AI service provides:
    - Risk score (0-100)
    - Anomaly detection
    - IP reputation checking
    - Behavioral analysis
    """
    
    def __init__(self, ai_service_url: str = "http://localhost:5000"):
        self.ai_service_url = ai_service_url
        self.enabled = True  # Can be toggled via config
    
    def calculate_login_risk(
        self,
        user_id: int,
        email: str,
        ip_address: str,
        user_agent: str,
        location: str = "Unknown"
    ) -> Dict:
        """
        Calculate risk score for login attempt
        
        Returns: {
            'risk_score': int (0-100),
            'anomaly_detected': bool,
            'anomaly_reason': str,
            'recommendations': list
        }
        """
        if not self.enabled:
            return self._default_response()
        
        try:
            # Prepare request data
            payload = {
                "user_id": user_id,
                "email": email,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "location": location,
                "event_type": "login"
            }
            
            # Call AI service
            response = requests.post(
                f"{self.ai_service_url}/api/risk/assess",
                json=payload,
                timeout=3  # 3 second timeout
            )
            
            if response.status_code == 200:
                result = response.json()
                
                logger.info(f"AI Risk Score for {email}: {result.get('risk_score', 0)}")
                
                return {
                    "risk_score": result.get("risk_score", 0),
                    "anomaly_detected": result.get("anomaly_detected", False),
                    "anomaly_reason": result.get("anomaly_reason", ""),
                    "recommendations": result.get("recommendations", [])
                }
            else:
                logger.warning(f"AI service returned {response.status_code}")
                return self._default_response()
        
        except requests.exceptions.Timeout:
            logger.warning("AI service timeout - using default risk score")
            return self._default_response()
        
        except requests.exceptions.ConnectionError:
            logger.warning("AI service unavailable - using default risk score")
            return self._default_response()
        
        except Exception as e:
            logger.error(f"AI risk calculation error: {e}")
            return self._default_response()
    
    def should_require_mfa(self, risk_score: int) -> bool:
        """
        Determine if MFA should be required based on risk score
        
        Risk Levels:
        - 0-20: Low risk (no MFA)
        - 21-50: Medium risk (optional MFA)
        - 51-100: High risk (require MFA)
        """
        return risk_score > 50
    
    def _default_response(self) -> Dict:
        """
        Default response when AI service is unavailable
        """
        return {
            "risk_score": 0,
            "anomaly_detected": False,
            "anomaly_reason": "",
            "recommendations": []
        }
    
    def check_health(self) -> bool:
        """
        Check if AI service is available
        """
        try:
            response = requests.get(
                f"{self.ai_service_url}/health",
                timeout=2
            )
            return response.status_code == 200
        except:
            return False


# Singleton instance
ai_risk_client = AIRiskClient()
# src/generation/llm_client.py
"""LLM client for scenario generation and evaluation."""

import time
import json
from typing import Optional, Dict, Any, List
from abc import ABC, abstractmethod

from config import config
from utils.logging_config import get_logger

logger = get_logger(__name__)

class BaseLLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        """Generate response from LLM."""
        pass
    
    @abstractmethod
    def is_available(self) -> bool:
        """Check if LLM service is available."""
        pass

#TODO: remove OpenAI references - not doing OpenAI 
class OpenAIClient(BaseLLMClient):
    """OpenAI API client."""
    
    def __init__(self):
        """Initialize OpenAI client."""
        try:
            import openai
            self.openai = openai
            self.client = openai.OpenAI(api_key=config.OPENAI_API_KEY)
            self.model = config.OPENAI_MODEL
            logger.info(f"OpenAI client initialized with model: {self.model}")
        except ImportError:
            logger.error("OpenAI library not installed. Install with: pip install openai")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI client: {e}")
            raise
    
    def generate(self, prompt: str, max_tokens: int = 2000, 
                temperature: float = 0.7, **kwargs) -> Optional[str]:
        """Generate response using OpenAI API.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens in response
            temperature: Creativity/randomness (0.0-1.0)
            **kwargs: Additional parameters
            
        Returns:
            Generated response or None if failed
        """
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=temperature,
                timeout=60
            )
            
            result = response.choices[0].message.content
            logger.info(f"OpenAI generation successful ({len(result)} characters)")
            return result
            
        except Exception as e:
            logger.error(f"OpenAI generation failed: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if OpenAI service is available."""
        try:
            # Simple test call
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Test"}],
                max_tokens=5
            )
            return True
        except Exception as e:
            logger.warning(f"OpenAI service unavailable: {e}")
            return False

class AnthropicClient(BaseLLMClient):
    """Anthropic Claude API client."""
    
    def __init__(self):
        """Initialize Anthropic client."""
        try:
            import anthropic
            self.anthropic = anthropic
            self.client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
            self.model = config.ANTHROPIC_MODEL
            logger.info(f"Anthropic client initialized with model: {self.model}")
        except ImportError:
            logger.error("Anthropic library not installed. Install with: pip install anthropic")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic client: {e}")
            raise
    
    def generate(self, prompt: str, max_tokens: int = 2000, 
                temperature: float = 0.7, **kwargs) -> Optional[str]:
        """Generate response using Anthropic API.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens in response
            temperature: Creativity/randomness (0.0-1.0)
            **kwargs: Additional parameters
            
        Returns:
            Generated response or None if failed
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}]
            )
            
            result = response.content[0].text
            logger.info(f"Anthropic generation successful ({len(result)} characters)")
            return result
            
        except Exception as e:
            logger.error(f"Anthropic generation failed: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if Anthropic service is available."""
        try:
            # Simple test call
            response = self.client.messages.create(
                model=self.model,
                max_tokens=5,
                messages=[{"role": "user", "content": "Test"}]
            )
            return True
        except Exception as e:
            logger.warning(f"Anthropic service unavailable: {e}")
            return False

class MockLLMClient(BaseLLMClient):
    """Mock LLM client for testing and development."""
    
    def __init__(self):
        """Initialize mock client."""
        logger.info("Mock LLM client initialized")
    
    def generate(self, prompt: str, **kwargs) -> Optional[str]:
        """Generate mock response.
        
        Args:
            prompt: Input prompt (analyzed for response)
            **kwargs: Ignored parameters
            
        Returns:
            Mock response based on prompt content
        """
        # Simulate processing time
        time.sleep(1)
        
        # Generate response based on prompt content
        if "evaluation" in prompt.lower() or "assess" in prompt.lower():
            return self._generate_mock_evaluation()
        else:
            return self._generate_mock_scenario(prompt)
    
    def is_available(self) -> bool:
        """Mock client is always available."""
        return True
    
    def _generate_mock_evaluation(self) -> str:
        """Generate mock evaluation response."""
        mock_evaluation = {
            "scores": {
                "level_of_detail": 7,
                "technical_accuracy": 8,
                "realism": 7,
                "creativity": 6,
                "understandability": 8
            },
            "overall_score": 7.2,
            "strengths": [
                "Clear step-by-step technical implementation",
                "Realistic timeline and resource requirements",
                "Good coverage of detection opportunities"
            ],
            "improvements": [
                "Could include more creative attack vectors",
                "Additional cleanup procedures needed"
            ],
            "justification": "Well-structured scenario with solid technical foundation and clear execution steps. Minor improvements needed in creativity and cleanup procedures."
        }
        
        return json.dumps(mock_evaluation, indent=2)
    
    def _generate_mock_scenario(self, prompt: str) -> str:
        """Generate mock scenario based on prompt content."""
        # Extract key terms from prompt
        query_terms = []
        if "phishing" in prompt.lower():
            query_terms.append("phishing")
        if "lateral movement" in prompt.lower():
            query_terms.append("lateral movement")
        if "privilege escalation" in prompt.lower():
            query_terms.append("privilege escalation")
        
        attack_type = query_terms[0] if query_terms else "general attack"
        
        mock_scenario = f"""
# Corporate {attack_type.title()} Exercise

## Objective
Demonstrate {attack_type} techniques in a controlled corporate environment to test defensive capabilities and incident response procedures.

## Prerequisites
- Valid test accounts with limited privileges
- Red team toolkit (Metasploit, Cobalt Strike, or equivalent)
- Network access to target environment
- Authorization from management and legal clearance
- Coordination with blue team for monitoring

## Attack Timeline

### Phase 1: Reconnaissance (30 minutes)
- Conduct passive information gathering using OSINT techniques
- Identify target email addresses and organizational structure
- Map network topology using publicly available information
- Document findings for attack planning

### Phase 2: Initial Access (1 hour)
- Execute {attack_type} campaign targeting identified personnel
- Establish initial foothold in target environment
- Deploy persistence mechanisms for maintained access
- Validate access and establish command and control

### Phase 3: Discovery and Lateral Movement (90 minutes)
- Conduct internal network reconnaissance
- Identify valuable targets and privilege escalation opportunities
- Move laterally to additional systems using discovered credentials
- Maintain operational security to avoid detection

### Phase 4: Objective Completion (60 minutes)
- Access target systems or data repositories
- Document successful compromise without data exfiltration
- Prepare evidence of successful scenario completion
- Begin cleanup procedures

## Techniques Used
- T1566.001: Spear-phishing with attachment
- T1078: Valid accounts for persistence
- T1083: File and directory discovery
- T1021: Remote services for lateral movement

## Detection Opportunities
- Email security alerts for suspicious attachments
- Unusual authentication patterns and login anomalies
- Network traffic analysis for C2 communications
- Endpoint detection for suspicious process execution
- Privilege escalation attempts and system modifications

## Success Metrics
- Successful initial access within allocated timeframe
- Lateral movement to at least 2 additional systems
- Access to target data or systems without actual compromise
- Completion without triggering automated blocking mechanisms
- Comprehensive documentation of attack path and techniques

## Resources Required
- Red team workstation with attack tools
- Test user accounts and email access
- Network connectivity to target environment
- Collaboration tools for team coordination
- Documentation templates for reporting

## Cleanup and Documentation
- Remove all backdoors and persistence mechanisms
- Delete temporary files and artifacts
- Reset any modified system configurations
- Provide comprehensive after-action report
- Brief blue team on attack techniques and indicators

This scenario provides a realistic assessment of organizational security posture while maintaining ethical boundaries and proper authorization.
"""
        
        logger.info(f"Generated mock scenario for: {attack_type}")
        return mock_scenario.strip()

class LLMClient:
    """Main LLM client with automatic provider selection and fallback."""
    
    def __init__(self, preferred_provider: str = None):
        """Initialize LLM client with provider selection.
        
        Args:
            preferred_provider: Preferred LLM provider ('openai', 'anthropic', 'mock')
        """
        self.client = None
        self.provider = None
        self.retry_count = config.MAX_RETRIES
        
        # Determine available providers
        available_providers = self._get_available_providers()
        
        if not available_providers:
            logger.warning("No LLM providers available, using mock client")
            self.client = MockLLMClient()
            self.provider = "mock"
            return
        
        # Select provider
        if preferred_provider and preferred_provider in available_providers:
            selected_provider = preferred_provider
        else:
            selected_provider = available_providers[0]  # Use first available
        
        # Initialize client
        try:
            if selected_provider == "openai":
                self.client = OpenAIClient()
            elif selected_provider == "anthropic":
                self.client = AnthropicClient()
            else:
                self.client = MockLLMClient()
            
            self.provider = selected_provider
            logger.info(f"LLM client initialized with provider: {self.provider}")
            
        except Exception as e:
            logger.error(f"Failed to initialize {selected_provider} client: {e}")
            logger.info("Falling back to mock client")
            self.client = MockLLMClient()
            self.provider = "mock"
    
    def generate(self, prompt: str, max_tokens: int = 2000, 
                temperature: float = 0.7, **kwargs) -> Optional[str]:
        """Generate response with retry logic.
        
        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens in response
            temperature: Creativity/randomness (0.0-1.0)
            **kwargs: Additional parameters
            
        Returns:
            Generated response or None if all attempts failed
        """
        for attempt in range(self.retry_count):
            try:
                result = self.client.generate(
                    prompt=prompt,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    **kwargs
                )
                
                if result:
                    return result
                else:
                    logger.warning(f"Generation attempt {attempt + 1} returned empty result")
                    
            except Exception as e:
                logger.error(f"Generation attempt {attempt + 1} failed: {e}")
                
                if attempt < self.retry_count - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.info(f"Retrying in {wait_time} seconds...")
                    time.sleep(wait_time)
        
        logger.error("All generation attempts failed")
        return None
    
    def is_available(self) -> bool:
        """Check if LLM service is available."""
        return self.client.is_available() if self.client else False
    
    def get_provider_info(self) -> Dict[str, Any]:
        """Get information about current provider.
        
        Returns:
            Provider information dictionary
        """
        return {
            "provider": self.provider,
            "available": self.is_available(),
            "client_type": type(self.client).__name__,
            "retry_count": self.retry_count
        }
    
    def _get_available_providers(self) -> List[str]:
        """Determine which LLM providers are available.
        
        Returns:
            List of available provider names
        """
        available = []
        
        # Check OpenAI
        if config.OPENAI_API_KEY:
            try:
                import openai
                available.append("openai")
            except ImportError:
                logger.warning("OpenAI library not available")
        
        # Check Anthropic
        if config.ANTHROPIC_API_KEY:
            try:
                import anthropic
                available.append("anthropic")
            except ImportError:
                logger.warning("Anthropic library not available")
        
        # Mock is always available
        available.append("mock")
        
        logger.info(f"Available LLM providers: {available}")
        return available
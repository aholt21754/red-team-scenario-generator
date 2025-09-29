import json
import csv
import os
from datetime import datetime
from typing import Dict, Any, Optional
import uuid

# Import configuration for evaluation criteria
try:
    from config import config
    EVALUATION_CRITERIA = config.EVALUATION_CRITERIA
    EVALUATION_SCALE_MAX = config.EVALUATION_SCALE_MAX
    EVALUATION_SCALE_MIN = config.EVALUATION_SCALE_MIN
except ImportError:
    # Fallback if config not available
    EVALUATION_CRITERIA = [
        "level_of_detail",
        "technical_accuracy", 
        "realism",
        "creativity",
        "alignment"
    ]
    EVALUATION_SCALE_MAX = 5
    EVALUATION_SCALE_MIN = 1

class RedTeamChatbotLogger:
    """
    Logger for Red Team Scenario Generation Chatbot
    Handles both individual detailed logs and summary CSV tracking
    Uses EVALUATION_CRITERIA from config.py for structured evaluation data
    """
    
    def __init__(self, 
                 individual_logs_dir: str = "logs/chatbot_runs", 
                 csv_summary_path: str = "logs/chatbot_summary.csv"):
        """
        Initialize the logger with specified directories and files
        
        Args:
            individual_logs_dir: Directory to store individual detailed log files
            csv_summary_path: Path to the summary CSV file
        """
        self.individual_logs_dir = individual_logs_dir
        self.csv_summary_path = csv_summary_path
        self.evaluation_criteria = EVALUATION_CRITERIA
        self.scale_max = EVALUATION_SCALE_MAX
        self.scale_min = EVALUATION_SCALE_MIN
        
        # Create directories if they don't exist
        os.makedirs(individual_logs_dir, exist_ok=True)
        
        # Initialize CSV file with headers if it doesn't exist
        self._initialize_csv()
    
    def _initialize_csv(self):
        """Initialize the CSV file with headers including evaluation criteria"""
        if not os.path.exists(self.csv_summary_path):
            # Create headers: basic info + individual criterion scores + overall score
            headers = ['filename', 'timestamp', 'run_id', 'overall_score']
            
            # Add individual criterion score columns
            for criterion in self.evaluation_criteria:
                headers.append(f'{criterion}_score')
            
            # Add additional analysis columns
            headers.extend([
                'num_strengths', 
                'num_improvements', 
                'word_count',
                'difficulty_level'
            ])
            
            with open(self.csv_summary_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(headers)
    
    def _generate_filename(self) -> str:
        """Generate a unique filename for each run"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = str(uuid.uuid4())[:8]  # Short UUID for uniqueness
        return f"redteam_run_{timestamp}_{run_id}.json"
    
    def _extract_evaluation_data(self, evaluation_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract and structure evaluation data according to EVALUATION_CRITERIA
        
        Args:
            evaluation_results: Raw evaluation results dictionary
            
        Returns:
            Structured evaluation data matching config criteria
        """
        extracted_data = {}
        
        # Handle different input formats for evaluation results
        if 'scores' in evaluation_results:
            # If using EvaluationResult format from evaluator.py
            scores = evaluation_results['scores']
            extracted_data.update({
                'criterion_scores': scores,
                'overall_score': evaluation_results.get('overall_score', 0.0),
                'strengths': evaluation_results.get('strengths', []),
                'improvements': evaluation_results.get('improvements', []),
                'justification': evaluation_results.get('justification', '')
            })
        else:
            # Legacy format or custom evaluation results
            scores = {}
            for criterion in self.evaluation_criteria:
                # Look for criterion scores in various possible keys
                score_key = f"{criterion}_score"
                if score_key in evaluation_results:
                    scores[criterion] = evaluation_results[score_key]
                elif criterion in evaluation_results:
                    scores[criterion] = evaluation_results[criterion]
                else:
                    scores[criterion] = 0  # Default if not found
            
            extracted_data.update({
                'criterion_scores': scores,
                'overall_score': evaluation_results.get('overall_score', 
                                                      sum(scores.values()) / len(scores) if scores else 0.0),
                'strengths': evaluation_results.get('strengths', []),
                'improvements': evaluation_results.get('improvements', []),
                'justification': evaluation_results.get('justification', '')
            })
        
        return extracted_data
    
    def log_chatbot_run(self, 
                       user_input: str, 
                       chatbot_output: str, 
                       evaluation_results: Dict[str, Any], 
                       overall_score: Optional[float] = None,
                       additional_metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Log a complete chatbot run with detailed information and summary
        
        Args:
            user_input: The input request/prompt given to the chatbot
            chatbot_output: The generated red team scenario from the chatbot
            evaluation_results: Dictionary containing evaluation metrics and results
            overall_score: Overall evaluation score (optional, will be extracted from evaluation_results)
            additional_metadata: Optional additional information to log
        
        Returns:
            str: The filename of the created detailed log file
        """
        
        # Generate unique filename
        filename = self._generate_filename()
        filepath = os.path.join(self.individual_logs_dir, filename)
        
        # Create timestamp and run ID
        timestamp = datetime.now().isoformat()
        run_id = filename.split('_')[-1].split('.')[0]  # Extract UUID from filename
        
        # Extract and structure evaluation data
        eval_data = self._extract_evaluation_data(evaluation_results)
        
        # Use provided overall_score or extract from evaluation data
        final_overall_score = overall_score if overall_score is not None else eval_data['overall_score']
        
        # Calculate additional metrics for analysis
        word_count = len(chatbot_output.split()) if chatbot_output else 0
        
        # Create detailed log entry with structured evaluation data
        detailed_log = {
            "run_id": run_id,
            "timestamp": timestamp,
            "user_input": user_input,
            "chatbot_output": chatbot_output,
            "evaluation_results": {
                "criterion_scores": eval_data['criterion_scores'],
                "overall_score": final_overall_score,
                "strengths": eval_data['strengths'],
                "improvements": eval_data['improvements'],
                "justification": eval_data['justification'],
                "evaluation_criteria_used": self.evaluation_criteria,
                "scale_range": f"{self.scale_min}-{self.scale_max}",
                "raw_evaluation_input": evaluation_results  # Keep original for reference
            },
            "analysis_metrics": {
                "word_count": word_count,
                "num_strengths": len(eval_data['strengths']),
                "num_improvements": len(eval_data['improvements'])
            },
            "metadata": additional_metadata or {}
        }
        
        # Save detailed log to individual file
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(detailed_log, f, indent=2, ensure_ascii=False)
        
        # Append summary to CSV with all evaluation criteria
        self._append_to_csv(filename, timestamp, run_id, eval_data, final_overall_score, 
                           word_count, additional_metadata or {})
        
        return filename
    
    def _append_to_csv(self, filename: str, timestamp: str, run_id: str, 
                      eval_data: Dict[str, Any], overall_score: float, 
                      word_count: int, metadata: Dict[str, Any]):
        """Append a new row to the summary CSV file with all evaluation criteria"""
        
        # Prepare row data
        row_data = [
            filename,
            timestamp,
            run_id,
            overall_score
        ]
        
        # Add individual criterion scores
        for criterion in self.evaluation_criteria:
            score = eval_data['criterion_scores'].get(criterion, 0)
            row_data.append(score)
        
        # Add additional analysis data
        row_data.extend([
            len(eval_data['strengths']),      # num_strengths
            len(eval_data['improvements']),   # num_improvements
            word_count,                       # word_count
            metadata.get('difficulty_level', '')       # difficulty_level
        ])
        
        # Write to CSV
        with open(self.csv_summary_path, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(row_data)
    



# Example usage with your specific evaluation criteria
def example_usage():
    """Example of how to use the RedTeamChatbotLogger with config.py evaluation criteria"""
    
    # Initialize logger
    logger = RedTeamChatbotLogger(
        individual_logs_dir="red_team_logs",
        csv_summary_path="red_team_summary.csv"
    )
    
    # Example chatbot run data
    user_input = "Generate a phishing attack scenario targeting a healthcare organization"
    
    chatbot_output = """
    Red Team Scenario: Healthcare Phishing Attack
    
    Objective: Test organization's response to targeted phishing attempts
    
    Scenario Details:
    - Target: Healthcare staff with access to patient records
    - Vector: Spear-phishing emails disguised as urgent patient transfer requests
    - Payload: Credential harvesting page mimicking hospital login portal
    - Timeline: 2-week campaign with escalating urgency
    
    Success Metrics:
    - Click-through rate on malicious links
    - Credential submission rate
    - Time to detection by security team
    - Incident response effectiveness
    """
    
    # Example evaluation results using your config criteria
    evaluation_results = {
        "scores": {
            "level_of_detail": 4,
            "technical_accuracy": 4, 
            "realism": 5,
            "creativity": 3,
            "alignment": 4
        },
        "overall_score": 4.0,
        "strengths": [
            "Realistic attack vector appropriate for healthcare",
            "Clear timeline and escalation strategy",
            "Specific success metrics defined"
        ],
        "improvements": [
            "Could include more technical implementation details",
            "Missing specific tools and techniques references",
            "Could benefit from MITRE ATT&CK technique mapping"
        ],
        "justification": "Scenario provides good foundation with realistic healthcare targeting but needs more technical depth for implementation."
    }
    
    additional_metadata = {
        "difficulty_level": "intermediate",
        "estimated_duration": "2 weeks",
        "required_tools": ["email spoofing", "web hosting", "credential harvester"]
    }
    
    # Log the run
    filename = logger.log_chatbot_run(
        user_input=user_input,
        chatbot_output=chatbot_output,
        evaluation_results=evaluation_results,
        additional_metadata=additional_metadata
    )
    
    print(f"Logged chatbot run to: {filename}")

if __name__ == "__main__":
    example_usage()
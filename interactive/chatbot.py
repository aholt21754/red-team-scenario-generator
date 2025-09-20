# chatbot.py
"""Interactive chatbot interface for Red Team Scenario Generator."""

import sys
import json
from pathlib import Path
from typing import Dict, List, Optional

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.append(str(src_path))

from database.vector_db import VectorDB
from generation.scenario_generator import ScenarioGenerator, ScenarioRequest
from generation.llm_client import LLMClient
from evaluation.evaluator import ScenarioEvaluator
from utils.logging_config import setup_logging, get_logger

logger = get_logger(__name__)

class RedTeamChatbot:
    """Interactive chatbot for red team scenario generation and refinement."""
    
    def __init__(self):
        """Initialize the chatbot with all necessary components."""
        self.vector_db = None
        self.scenario_generator = None
        self.current_scenario = None
        self.conversation_history = []
        self.user_preferences = {
            "environment": "Corporate",
            "skill_level": "Intermediate", 
            "default_duration": "2-4 hours",
            "team_size": 3
        }
        
    def initialize(self) -> bool:
        """Initialize all components."""
        try:
            print("🤖 Initializing Red Team Scenario Generator...")
            
            # Setup logging
            setup_logging()
            
            # Initialize vector database
            print("📚 Loading knowledge base...")
            self.vector_db = VectorDB()
            if not self.vector_db.connect():
                print("❌ Failed to connect to knowledge base")
                return False
            
            if not self.vector_db.create_collection(reset_if_exists=False):
                print("❌ Failed to access knowledge base")
                return False
            
            stats = self.vector_db.get_collection_stats()
            if not stats or stats['total_documents'] == 0:
                print("❌ Knowledge base is empty. Run 'python main.py --setup' first")
                return False
                
            print(f"✅ Knowledge base ready ({stats['total_documents']} techniques loaded)")
            
            # Initialize LLM and scenario generator
            print("🧠 Initializing AI components...")
            llm_client = LLMClient()
            if not llm_client.is_available():
                print("❌ AI service not available. Check your API key configuration.")
                return False
                
            print(f"✅ AI ready (using {llm_client.provider})")
            
            evaluator = ScenarioEvaluator()
            self.scenario_generator = ScenarioGenerator(
                vector_db=self.vector_db,
                llm_client=llm_client,
                evaluator=evaluator
            )
            
            print("✅ Scenario generator ready")
            return True
            
        except Exception as e:
            print(f"❌ Initialization failed: {e}")
            return False
    
    def start_chat(self):
        """Start the interactive chat session."""
        if not self.initialize():
            print("Failed to initialize. Please check your setup.")
            return
            
        print("\n" + "="*80)
        print("🛡️  RED TEAM SCENARIO GENERATOR CHATBOT")
        print("="*80)
        print("I can help you generate and refine red team scenarios!")
        print("\nWhat I can do:")
        print("• Generate custom red team scenarios")
        print("• Refine scenarios based on your feedback")
        print("• Suggest defensive measures")
        print("• Adapt scenarios to your environment")
        print("\nCommands:")
        print("• Type your scenario request naturally")
        print("• 'refine' - improve the current scenario")
        print("• 'evaluate' - get detailed evaluation")
        print("• 'settings' - view/change preferences")
        print("• 'help' - show this help")
        print("• 'quit' - exit")
        print("="*80)
        
        while True:
            try:
                user_input = input(f"\n🤖 You: ").strip()
                
                if not user_input:
                    continue
                    
                if user_input.lower() in ['quit', 'exit', 'q']:
                    print("👋 Thanks for using Red Team Scenario Generator!")
                    break
                elif user_input.lower() == 'help':
                    self._show_help()
                elif user_input.lower() == 'settings':
                    self._handle_settings()
                elif user_input.lower() == 'evaluate':
                    self._handle_evaluate()
                elif user_input.lower() == 'refine':
                    self._handle_refine()
                elif user_input.lower().startswith('set '):
                    self._handle_setting_change(user_input)
                else:
                    self._handle_scenario_request(user_input)
                    
            except KeyboardInterrupt:
                print("\n👋 Goodbye!")
                break
            except Exception as e:
                print(f"❌ Error: {e}")
                logger.error(f"Chat error: {e}")
    
    def _handle_scenario_request(self, user_input: str):
        """Handle a scenario generation request."""
        print("🔍 Analyzing your request...")
        
        # Save to conversation history
        self.conversation_history.append({"role": "user", "content": user_input})
        
        try:
            # Create scenario request
            request = ScenarioRequest(
                query=user_input,
                environment=self.user_preferences["environment"],
                skill_level=self.user_preferences["skill_level"],
                target_duration=self.user_preferences["default_duration"],
                team_size=self.user_preferences["team_size"]
            )
            
            # Generate scenario
            print("🎯 Generating scenario...")
            scenario = self.scenario_generator.generate_scenario(request, evaluate=True)
            
            if scenario:
                self.current_scenario = scenario
                self._display_scenario(scenario)
                
                # Add to conversation history
                self.conversation_history.append({
                    "role": "assistant", 
                    "content": f"Generated scenario: {scenario.title}",
                    "scenario": scenario
                })
                
                # Ask for feedback
                print("\n💭 What would you like me to adjust or refine about this scenario?")
                print("    Or ask me about defensive measures, detection points, or variations.")
                
            else:
                print("❌ Failed to generate scenario. Please try rephrasing your request.")
                
        except Exception as e:
            print(f"❌ Error generating scenario: {e}")
            logger.error(f"Scenario generation error: {e}")
    
    def _handle_refine(self):
        """Handle scenario refinement."""
        if not self.current_scenario:
            print("❌ No current scenario to refine. Please generate a scenario first.")
            return
            
        print("🔧 How would you like me to refine the current scenario?")
        print("Examples:")
        print("• 'Make it more challenging'")
        print("• 'Add more stealth techniques'")
        print("• 'Focus on Windows environment'")
        print("• 'Include more social engineering'")
        
        refinement = input("Refinement request: ").strip()
        if not refinement:
            return
            
        print("🎯 Refining scenario...")
        
        # Create new request with refinement
        refined_query = f"{self.current_scenario.objective}. {refinement}"
        request = ScenarioRequest(
            query=refined_query,
            environment=self.user_preferences["environment"],
            skill_level=self.user_preferences["skill_level"],
            target_duration=self.user_preferences["default_duration"],
            team_size=self.user_preferences["team_size"]
        )
        
        try:
            refined_scenario = self.scenario_generator.generate_scenario(request, evaluate=True)
            if refined_scenario:
                self.current_scenario = refined_scenario
                print("✨ Refined scenario:")
                self._display_scenario(refined_scenario)
            else:
                print("❌ Failed to refine scenario. Please try a different approach.")
        except Exception as e:
            print(f"❌ Error refining scenario: {e}")
    
    def _handle_evaluate(self):
        """Handle detailed evaluation request."""
        if not self.current_scenario:
            print("❌ No current scenario to evaluate. Please generate a scenario first.")
            return
            
        if hasattr(self.current_scenario, 'evaluation_scores') and self.current_scenario.evaluation_scores:
            print("📊 DETAILED SCENARIO EVALUATION")
            print("="*50)
            
            # Show scores
            total_score = sum(self.current_scenario.evaluation_scores.values())
            avg_score = total_score / len(self.current_scenario.evaluation_scores)
            
            print(f"Overall Score: {avg_score:.1f}/10")
            print("\nDetailed Scores:")
            for criterion, score in self.current_scenario.evaluation_scores.items():
                criterion_display = criterion.replace('_', ' ').title()
                bar = "█" * int(score) + "░" * (10 - int(score))
                print(f"  {criterion_display:20} {score:2.0f}/10 [{bar}]")
            
            # Provide recommendations
            print("\n💡 Recommendations:")
            low_scores = [k for k, v in self.current_scenario.evaluation_scores.items() if v < 7]
            if low_scores:
                for criterion in low_scores:
                    print(f"  • Consider improving {criterion.replace('_', ' ')}")
            else:
                print("  • Excellent scenario! Consider creating variations for different skill levels.")
                
        else:
            print("❌ No evaluation data available for current scenario.")
    
    def _handle_settings(self):
        """Handle settings display and modification."""
        print("⚙️  CURRENT SETTINGS")
        print("="*30)
        for key, value in self.user_preferences.items():
            print(f"{key.replace('_', ' ').title()}: {value}")
        
        print("\nTo change a setting, use: set <setting> <value>")
        print("Example: set environment Cloud")
        print("Available settings: environment, skill_level, default_duration, team_size")
    
    def _handle_setting_change(self, command: str):
        """Handle setting changes."""
        parts = command.split(' ', 2)
        if len(parts) < 3:
            print("❌ Usage: set <setting> <value>")
            return
            
        setting = parts[1].lower().replace(' ', '_')
        value = parts[2]
        
        if setting in self.user_preferences:
            # Convert team_size to int if needed
            if setting == 'team_size':
                try:
                    value = int(value)
                except ValueError:
                    print("❌ Team size must be a number")
                    return
                    
            self.user_preferences[setting] = value
            print(f"✅ Set {setting.replace('_', ' ')} to: {value}")
        else:
            print(f"❌ Unknown setting: {setting}")
            print("Available: environment, skill_level, default_duration, team_size")
    
    def _display_scenario(self, scenario):
        """Display a generated scenario in a formatted way."""
        print("\n" + "="*80)
        print(f"📋 {scenario.title}")
        print("="*80)
        
        print(f"🎯 Objective: {scenario.objective}")
        print(f"🏢 Environment: {self.user_preferences['environment']}")
        print(f"📈 Skill Level: {self.user_preferences['skill_level']}")
        
        # Show timeline
        if scenario.timeline:
            print(f"\n⏱️  Timeline:")
            for phase in scenario.timeline:
                print(f"   • {phase.get('phase', 'Phase')}: {phase.get('description', '')} ({phase.get('duration', 'TBD')})")
        
        # Show techniques
        if scenario.techniques_used:
            print(f"\n🔧 Techniques Used:")
            for technique in scenario.techniques_used[:5]:  # Show first 5
                print(f"   • {technique}")
        
        # Show detection points
        if scenario.detection_points:
            print(f"\n🔍 Detection Opportunities:")
            for detection in scenario.detection_points[:3]:  # Show first 3
                print(f"   • {detection}")
        
        # Show evaluation score if available
        if hasattr(scenario, 'evaluation_scores') and scenario.evaluation_scores:
            scores = scenario.evaluation_scores
            avg_score = sum(scores.values()) / len(scores)
            print(f"\n📊 Quality Score: {avg_score:.1f}/10")
        
        print("\n" + "="*80)
    
    def _show_help(self):
        """Show detailed help information."""
        print("\n🤖 RED TEAM SCENARIO GENERATOR HELP")
        print("="*50)
        print("SCENARIO REQUESTS:")
        print("• 'Generate a phishing scenario for corporate environment'")
        print("• 'Create a lateral movement exercise using valid accounts'")
        print("• 'Design a privilege escalation scenario for Windows'")
        print("• 'Build a social engineering attack via phone calls'")
        print()
        print("REFINEMENT:")
        print("• 'refine' - Improve current scenario")
        print("• 'Make it more stealthy'")
        print("• 'Add persistence mechanisms'")
        print("• 'Focus on cloud environment'")
        print()
        print("ANALYSIS:")
        print("• 'evaluate' - Detailed quality assessment")
        print("• 'What defenses should we implement?'")
        print("• 'How would blue team detect this?'")
        print()
        print("SETTINGS:")
        print("• 'settings' - View current preferences")
        print("• 'set environment Cloud' - Change environment")
        print("• 'set skill_level Advanced' - Change difficulty")
        print("="*50)

def main():
    """Main entry point for the chatbot."""
    chatbot = RedTeamChatbot()
    chatbot.start_chat()

if __name__ == "__main__":
    main()
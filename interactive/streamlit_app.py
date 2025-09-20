# streamlit_app.py
"""Streamlit web interface for Red Team Scenario Generator."""

import streamlit as st
import sys
from pathlib import Path
import json
import os

# Add src to path - having real problems with the calc here so hard coding for now
src_path = Path(__file__).parent.parent / "src"
sys.path.append("/Users/annholt/red-team-scenario-generator/src")

#st.write("**Debug Info:**")
#st.write(f"Current working directory: {os.getcwd()}")
#st.write(f"Script location: {__file__}")
#st.write(f"Python path: {sys.path[:6]}...")  # Show first 3 entries

# Try to list src directory
#src_path = Path(__file__).parent / "src"
#st.write(f"Looking for src at: {src_path}")
#if src_path.exists():
#    st.write(f"✅ src directory found at: {src_path}")
#    st.write(f"Contents: {list(src_path.iterdir())}")
#else:
#    st.write(f"❌ src directory not found at: {src_path}")

from database.vector_db import VectorDB
from generation.scenario_generator import ScenarioGenerator, ScenarioRequest
from generation.llm_client import LLMClient
from evaluation.evaluator import ScenarioEvaluator

# Page configuration
st.set_page_config(
    page_title="Red Team Scenario Generator",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

@st.cache_resource
def initialize_components():
    """Initialize and cache the scenario generation components."""
    try:
        # Initialize vector database
        vector_db = VectorDB()
        if not vector_db.connect():
            st.error("Failed to connect to knowledge base")
            return None
        
        if not vector_db.create_collection(reset_if_exists=False):
            st.error("Failed to access knowledge base")
            return None
        
        stats = vector_db.get_collection_stats()
        if not stats or stats['total_documents'] == 0:
            st.error("Knowledge base is empty. Run 'python main.py --setup' first")
            return None
        
        # Initialize LLM and scenario generator
        llm_client = LLMClient()
        if not llm_client.is_available():
            st.error("AI service not available. Check your API key configuration.")
            return None
        
        evaluator = ScenarioEvaluator()
        scenario_generator = ScenarioGenerator(
            vector_db=vector_db,
            llm_client=llm_client,
            evaluator=evaluator
        )
        
        return {
            'generator': scenario_generator,
            'vector_db': vector_db,
            'stats': stats,
            'llm_provider': llm_client.provider
        }
        
    except Exception as e:
        st.error(f"Initialization failed: {e}")
        return None

def main():
    """Main Streamlit application."""
    
    # Title and header
    st.title("🛡️ Red Team Scenario Generator")
    st.markdown("*AI-powered tool for generating and refining cybersecurity red team scenarios*")
    
    # Initialize components
    components = initialize_components()
    if not components:
        st.stop()
    
    # Sidebar for settings and info
    with st.sidebar:
        st.header("⚙️ Settings")
        
        # Environment settings
        environment = st.selectbox(
            "Target Environment",
            ["Corporate", "Cloud", "Healthcare", "Financial", "Government", "Educational"],
            index=0
        )
        
        skill_level = st.selectbox(
            "Skill Level",
            ["Beginner", "Intermediate", "Advanced", "Expert"],
            index=1
        )
        
        duration = st.selectbox(
            "Target Duration",
            ["1-2 hours", "2-4 hours", "4-6 hours", "Full day", "Multi-day"],
            index=1
        )
        
        team_size = st.slider("Team Size", 1, 10, 3)
        
        # System info
        st.header("📊 System Status")
        st.success(f"✅ Knowledge Base: {components['stats']['total_documents']} techniques")
        st.success(f"✅ AI Provider: {components['llm_provider']}")
        
        # Quick examples
        st.header("💡 Example Requests")
        examples = [
            "Phishing attack targeting remote workers",
            "Lateral movement using valid accounts",
            "Privilege escalation in Windows domain",
            "Social engineering via phone calls",
            "Cloud infrastructure compromise",
            "Supply chain attack simulation"
        ]
        
        for example in examples:
            if st.button(example, key=f"example_{example[:10]}"):
                st.session_state.scenario_query = example
    
    # Main content area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.header("🎯 Scenario Generation")
        
        # Scenario request input
        scenario_query = st.text_area(
            "Describe the red team scenario you want to generate:",
            value=st.session_state.get('scenario_query', ''),
            height=100,
            placeholder="Example: Generate a spear-phishing scenario targeting corporate executives with the goal of establishing persistent access..."
        )
        
        # Generation buttons
        col_gen1, col_gen2, col_gen3 = st.columns(3)
        
        with col_gen1:
            generate_btn = st.button("🚀 Generate Scenario", type="primary")
        
        with col_gen2:
            refine_btn = st.button("🔧 Refine Current", disabled=not st.session_state.get('current_scenario'))
        
        with col_gen3:
            evaluate_btn = st.button("📊 Detailed Evaluation", disabled=not st.session_state.get('current_scenario'))
        
        # Handle generation
        if generate_btn and scenario_query:
            with st.spinner("🧠 Generating scenario..."):
                try:
                    request = ScenarioRequest(
                        query=scenario_query,
                        environment=environment,
                        skill_level=skill_level,
                        target_duration=duration,
                        team_size=team_size
                    )
                    
                    scenario = components['generator'].generate_scenario(request, evaluate=True)
                    
                    if scenario:
                        st.session_state.current_scenario = scenario
                        st.success("✅ Scenario generated successfully!")
                    else:
                        st.error("❌ Failed to generate scenario. Please try rephrasing your request.")
                        
                except Exception as e:
                    st.error(f"❌ Error: {e}")
        
        # Handle refinement
        if refine_btn:
            refinement_query = st.text_input("How should I refine the scenario?", 
                                           placeholder="Make it more stealthy, add persistence, focus on specific platform...")
            
            if refinement_query:
                with st.spinner("🔧 Refining scenario..."):
                    try:
                        current = st.session_state.current_scenario
                        refined_query = f"{current.objective}. {refinement_query}"
                        
                        request = ScenarioRequest(
                            query=refined_query,
                            environment=environment,
                            skill_level=skill_level,
                            target_duration=duration,
                            team_size=team_size
                        )
                        
                        refined_scenario = components['generator'].generate_scenario(request, evaluate=True)
                        
                        if refined_scenario:
                            st.session_state.current_scenario = refined_scenario
                            st.success("✅ Scenario refined successfully!")
                        else:
                            st.error("❌ Failed to refine scenario.")
                            
                    except Exception as e:
                        st.error(f"❌ Error: {e}")
        
        # Display current scenario
        if st.session_state.get('current_scenario'):
            scenario = st.session_state.current_scenario
            
            st.header(f"📋 {scenario.title}")
            
            # Scenario details in tabs
            tab1, tab2, tab3, tab4 = st.tabs(["📖 Overview", "⏱️ Timeline", "🔧 Technical", "🔍 Detection"])
            
            with tab1:
                st.subheader("🎯 Objective")
                st.write(scenario.objective)
                
                st.subheader("📝 Description")
                st.write(scenario.description)
                
                if hasattr(scenario, 'evaluation_scores') and scenario.evaluation_scores:
                    st.subheader("📊 Quality Score")
                    scores = scenario.evaluation_scores
                    avg_score = sum(scores.values()) / len(scores)
                    
                    # Create progress bar for overall score
                    st.metric("Overall Quality", f"{avg_score:.1f}/10")
                    
                    # Show individual scores
                    score_cols = st.columns(len(scores))
                    for i, (criterion, score) in enumerate(scores.items()):
                        with score_cols[i]:
                            st.metric(
                                criterion.replace('_', ' ').title(),
                                f"{score}/10",
                                delta=None
                            )
            
            with tab2:
                st.subheader("⏱️ Execution Timeline")
                if scenario.timeline:
                    for i, phase in enumerate(scenario.timeline, 1):
                        with st.expander(f"Phase {i}: {phase.get('phase', 'Unknown')}"):
                            st.write(f"**Duration:** {phase.get('duration', 'TBD')}")
                            st.write(f"**Description:** {phase.get('description', 'No description available')}")
                else:
                    st.info("No timeline information available")
            
            with tab3:
                col_tech1, col_tech2 = st.columns(2)
                
                with col_tech1:
                    st.subheader("🔧 Techniques Used")
                    if scenario.techniques_used:
                        for technique in scenario.techniques_used:
                            st.write(f"• {technique}")
                    else:
                        st.info("No techniques specified")
                
                with col_tech2:
                    st.subheader("📋 Prerequisites")
                    if scenario.prerequisites:
                        for prereq in scenario.prerequisites:
                            st.write(f"• {prereq}")
                    else:
                        st.info("No prerequisites specified")
                
                st.subheader("🎯 Success Metrics")
                if scenario.success_metrics:
                    for metric in scenario.success_metrics:
                        st.write(f"• {metric}")
                else:
                    st.info("No success metrics specified")
            
            with tab4:
                st.subheader("🔍 Detection Points")
                if scenario.detection_points:
                    for detection in scenario.detection_points:
                        st.write(f"• {detection}")
                else:
                    st.info("No detection points specified")
                
                st.subheader("🛠️ Resources Required")
                if scenario.resources_required:
                    for resource in scenario.resources_required:
                        st.write(f"• {resource}")
                else:
                    st.info("No resources specified")
        
        # Handle detailed evaluation
        if evaluate_btn and st.session_state.get('current_scenario'):
            st.header("📊 Detailed Evaluation")
            scenario = st.session_state.current_scenario
            
            if hasattr(scenario, 'evaluation_scores') and scenario.evaluation_scores:
                scores = scenario.evaluation_scores
                
                # Create visualization of scores
                st.subheader("Score Breakdown")
                for criterion, score in scores.items():
                    criterion_display = criterion.replace('_', ' ').title()
                    st.write(f"**{criterion_display}**")
                    st.progress(score / 10)
                    st.write(f"Score: {score}/10")
                    st.write("")
                
                # Recommendations
                st.subheader("💡 Recommendations")
                low_scores = [k for k, v in scores.items() if v < 7]
                
                if low_scores:
                    st.warning("Areas for improvement:")
                    for criterion in low_scores:
                        st.write(f"• Consider enhancing {criterion.replace('_', ' ')}")
                else:
                    st.success("Excellent scenario quality! Consider creating variations for different environments or skill levels.")
            else:
                st.error("No evaluation data available")
    
    with col2:
        st.header("💬 Chat Assistant")
        
        # Initialize chat history
        if 'chat_history' not in st.session_state:
            st.session_state.chat_history = []
        
        # Chat input
        user_question = st.text_input("Ask about scenarios, defenses, or refinements:", 
                                     placeholder="How can we defend against this? What variations should we try?")
        
        if user_question:
            # Add user message to chat
            st.session_state.chat_history.append({"role": "user", "content": user_question})
            
            # Generate response (simplified for now)
            if "defend" in user_question.lower() or "defense" in user_question.lower():
                response = "🛡️ Consider implementing: Email filtering, user training, endpoint detection, network monitoring, and incident response procedures."
            elif "variation" in user_question.lower():
                response = "🔄 Try these variations: Different attack vectors, various environments, alternative persistence methods, or modified social engineering approaches."
            else:
                response = "🤖 I can help you refine scenarios, suggest defenses, or create variations. What specific aspect would you like to explore?"
            
            st.session_state.chat_history.append({"role": "assistant", "content": response})
        
        # Display chat history
        for message in st.session_state.chat_history[-6:]:  # Show last 6 messages
            if message["role"] == "user":
                st.write(f"👤 **You:** {message['content']}")
            else:
                st.write(f"🤖 **Assistant:** {message['content']}")

# Initialize session state
if 'current_scenario' not in st.session_state:
    st.session_state.current_scenario = None

if 'scenario_query' not in st.session_state:
    st.session_state.scenario_query = ''

if __name__ == "__main__":
    main()
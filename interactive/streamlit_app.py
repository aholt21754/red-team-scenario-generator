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
        environment = st.sidebar.selectbox(
            "🌍 Target Environment",
            options=["Corporate", "Web Applications", "Cloud", "Mobile", "Network", "Generic"],
            index=0,  # Default to Corporate
            help="Filters scenarios based on CAPEC environment suitability data"
        )

        skill_level = st.sidebar.selectbox(
            "🎯 Skill Level",
            options=["Beginner", "Intermediate", "Expert"],
            index=1,  # Default to Intermediate
            help="Matches scenarios to CAPEC complexity levels"
        )

        duration = st.sidebar.selectbox(
            "⏱️ Target Duration",
            options=["1-2 hours", "2-4 hours", "4-6 hours", "6-8 hours"],
            index=1,  # Default to 2-4 hours
            help="Expected exercise duration"
        )

        team_size = st.sidebar.slider(
            "👥 Team Size",
            min_value=1,
            max_value=8,
            value=3,
            help="Number of red team members"
        )

        # System info
        st.header("📊 Knowledge Base Status")
        # Get detailed type distribution
        type_distribution = components['stats'].get('type_distribution', {})

        # Display the enhanced status
        total_docs = components['stats']['total_documents']
        st.success(f"✅ **Total Knowledge Base:** {total_docs:,} techniques")
        st.success(f"✅ **AI Provider:** {components['llm_provider']}")

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
        
        generate_btn = st.button("🚀 Generate Scenario", type="primary")
        
        
        
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
        
        # Display current scenario
        if st.session_state.get('current_scenario'):
            scenario = st.session_state.current_scenario
            
            st.header(f"📋 {scenario.title}")
            
            # Scenario details in tabs
            st.subheader("🎯 Objective")
            st.write(scenario.objective)
            
            st.subheader("📝 Description")
            description = scenario.description

            # Handle long descriptions gracefully
            if len(description) > 1500:
                # Very long - use expander
                with st.expander("📖 View Full Description (Click to Expand)"):
                    st.markdown(description)
                
                # Show summary
                lines = description.split('\n')
                summary_lines = []
                for line in lines[:10]:  # First 10 lines
                    if line.strip():
                        summary_lines.append(line)
                
                st.write("**Summary (first 10 lines):**")
                st.write('\n'.join(summary_lines) + "\n\n*[Click above to see full description]*")

            elif len(description) > 800:
                # Medium length - show with scroll
                st.text_area(
                    "Full Description:", 
                    value=description,
                    height=300,
                    disabled=True  # Read-only
                )
            else:
                # Short description - show normally
                st.write(description)

                
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
            
                           
                
        
   
    with col2:
        st.header("📊 Detailed Evaluation")

        if st.session_state.get('current_scenario'):
            scenario = st.session_state.current_scenario
            
            if hasattr(scenario, 'evaluation_result') and scenario.evaluation_result:
                evaluation = scenario.evaluation_result
                
                # Overall score at the top
                st.subheader("📊 Overall Score")
                st.metric("Total Score", f"{evaluation.overall_score}/5")

                # Detailed Scores
                st.subheader("📈 Detailed Score Breakdown")
                for criterion, score in evaluation.scores.items():
                    criterion_display = criterion.replace('_', ' ').title()
                    st.write(f"**{criterion_display}**")
                    st.progress(score / 5)
                
                # Create tabs for detailed feedback
                tab1, tab2, tab3 = st.tabs(["✅ Strengths", "💡 Improvements", "📋 Analysis"])
                
                with tab1:
                    st.subheader("✅ Scenario Strengths")
                    if evaluation.strengths:
                        for i, strength in enumerate(evaluation.strengths, 1):
                            st.success(f"**{i}.** {strength}")
                    else:
                        st.info("No specific strengths identified in this evaluation.")
                
                with tab2:
                    st.subheader("💡 Areas for Improvement")
                    if evaluation.improvements:
                        for i, improvement in enumerate(evaluation.improvements, 1):
                            st.warning(f"**{i}.** {improvement}")
                    else:
                        st.success("No major improvements identified - excellent work!")
                
                with tab3:
                    st.subheader("📋 Justification")
                    if evaluation.justification:
                        st.markdown("**Evaluator's Detailed Analysis:**")
                        # Use expander for long justifications
                        if len(evaluation.justification) > 500:
                            with st.expander("📖 View Full Analysis (Click to Expand)", expanded=True):
                                st.write(evaluation.justification)
                        else:
                            st.write(evaluation.justification)
                    else:
                        st.info("No detailed analysis available for this evaluation.")
            else:
                st.error("No evaluation data available")
        
 

# Initialize session state
if 'current_scenario' not in st.session_state:
    st.session_state.current_scenario = None

if 'scenario_query' not in st.session_state:
    st.session_state.scenario_query = ''

if __name__ == "__main__":
    main()
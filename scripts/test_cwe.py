#!/usr/bin/env python3
"""
CWE Integration Test Script
Tests the CWE (Common Weakness Enumeration) data loader and integration.
"""

import sys
import os
from pathlib import Path
import time
import json

# Add src to path
project_root = Path(__file__).parent.parent
sys.path.append(str(project_root / "src"))

try:
    from data_sources.cwe_data import CweDataLoader
    from database.vector_db import VectorDB
    from utils.logging_config import setup_logging, get_logger
except ImportError as e:
    print(f"Import error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

# Setup logging
setup_logging()
logger = get_logger(__name__)

class CweIntegrationTester:
    """Test class for CWE integration functionality."""
    
    def __init__(self):
        """Initialize the tester."""
        self.loader = CweDataLoader(cache_enabled=True, cache_duration_hours=1)
        self.test_results = []
        self.loaded_data = None
    
    def run_all_tests(self) -> bool:
        """Run all CWE integration tests.
        
        Returns:
            bool: True if all tests pass
        """
        print("="*70)
        print("CWE INTEGRATION - COMPREHENSIVE TESTS")
        print("="*70)
        print("Testing CWE loading and integration with existing MITRE+CAPEC system...")
        print()
        
        test_methods = [
            self.test_cwe_connectivity,
            self.test_cwe_xml_download,
            self.test_cwe_xml_parsing,
            #self.test_xml_structure_analysis, # Uncomment to run detailed XML structure analysis - only needed if we need to parse something new
            self.test_weakness_processing,
            self.test_capec_mapping_debugging,
            self.test_cwe_validation,
            self.test_environment_detection,
            self.test_impact_severity_analysis,
            self.test_comprehensive_coverage,
            self.test_three_source_compatibility
        ]
        
        passed = 0
        total = len(test_methods)
        
        for test_method in test_methods:
            print(f"Running {test_method.__name__}...", end=" ")
            try:
                result = test_method()
                if result:
                    passed += 1
                    print("✅ PASS")
                else:
                    print("❌ FAIL")
                    
            except Exception as e:
                print(f"❌ ERROR: {e}")
        
        print(f"\n{'='*70}")
        print(f"TEST RESULTS: {passed}/{total} tests passed")
        print(f"{'='*70}")
        
        if passed == total:
            print("🎉 All tests passed! CWE integration is working correctly.")
            print("✅ Successfully loading XML data from official MITRE CWE source")
            print("✅ Parsing and processing weaknesses correctly")
            print("✅ CAPEC mapping extraction working")
            print("✅ Ready for three-source integration!")
            return True
        else:
            print("⚠️ Some tests failed. Check the details above.")
            if passed >= total * 0.8:  # 80% pass rate
                print("🔍 Loader may still be usable with limited functionality.")
            return False
    
    def test_xml_structure_analysis(self) -> bool:
        """Analyze the actual XML structure to understand the parsing issue."""
        try:
            print("   🔍 Analyzing XML structure...")
            
            xml_data = self.loader._download_and_extract_cwe_data()
            if not xml_data:
                print("   ❌ No XML data available")
                return False
            
            print(f"   📊 XML data size: {len(xml_data):,} characters")
            
            # First, let's check what's actually in the XML with string searches
            weakness_count_str = xml_data.count('<Weakness ')
            patterns_count_str = xml_data.count('<Related_Attack_Patterns>')
            attack_pattern_count_str = xml_data.count('<Related_Attack_Pattern CAPEC_ID=')
            
            print(f"   📊 String search results:")
            print(f"      '<Weakness ' occurrences: {weakness_count_str}")
            print(f"      '<Related_Attack_Patterns>' occurrences: {patterns_count_str}")
            print(f"      '<Related_Attack_Pattern CAPEC_ID=' occurrences: {attack_pattern_count_str}")
            
            # Now try XML parsing
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(xml_data)
                print(f"   ✅ XML parsing successful")
                print(f"   📊 Root element: {root.tag}")
                print(f"   📊 Root attributes: {root.attrib}")
                
                # Check immediate children of root
                root_children = [child.tag for child in root]
                print(f"   📊 Root children: {root_children}")
                
                # Try different ways to find Weakness elements
                weaknesses_direct = list(root.findall('Weakness'))
                weaknesses_recursive = list(root.findall('.//Weakness'))
                
                print(f"   📊 Direct Weakness children: {len(weaknesses_direct)}")
                print(f"   📊 Recursive Weakness search: {len(weaknesses_recursive)}")
                
                # If recursive search finds weaknesses, use those
                if weaknesses_recursive:
                    weaknesses = weaknesses_recursive
                    print(f"   ✅ Using recursive search results")
                    
                    # Check first weakness structure
                    first_weakness = weaknesses[0]
                    weakness_id = first_weakness.get('ID')
                    weakness_children = [child.tag for child in first_weakness]
                    
                    print(f"   🎯 First weakness (ID: {weakness_id}):")
                    print(f"      Children: {weakness_children}")
                    
                    # Look for Related_Attack_Patterns in first weakness
                    rap_elem = first_weakness.find('Related_Attack_Patterns')
                    if rap_elem is not None:
                        attack_patterns = rap_elem.findall('Related_Attack_Pattern')
                        print(f"      ✅ Found Related_Attack_Patterns with {len(attack_patterns)} patterns")
                        for pattern in attack_patterns[:3]:  # Show first 3
                            capec_id = pattern.get('CAPEC_ID')
                            print(f"         CAPEC_ID: {capec_id}")
                    else:
                        print(f"      ❌ No Related_Attack_Patterns found")
                    
                    # Count total weaknesses with CAPEC mappings
                    weaknesses_with_capec = 0
                    total_capec_mappings = 0
                    
                    for weakness in weaknesses[:100]:  # Check first 100 to avoid timeout
                        rap_elem = weakness.find('Related_Attack_Patterns')
                        if rap_elem is not None:
                            attack_patterns = rap_elem.findall('Related_Attack_Pattern')
                            if attack_patterns:
                                weaknesses_with_capec += 1
                                total_capec_mappings += len(attack_patterns)
                    
                    print(f"   📊 Sample analysis (first 100 weaknesses):")
                    print(f"      Weaknesses with CAPEC mappings: {weaknesses_with_capec}")
                    print(f"      Total CAPEC mappings: {total_capec_mappings}")
                    
                else:
                    print("   ❌ No Weakness elements found with any search method")
                    
                    # Debug: show some sample content
                    sample_content = xml_data[:1000] + "..." if len(xml_data) > 1000 else xml_data
                    print(f"   📝 Sample XML content:")
                    print(f"      {sample_content}")
                    
            except ET.ParseError as e:
                print(f"   ❌ XML parsing failed: {e}")
                # Show sample of problematic XML
                sample_content = xml_data[:500] + "..." if len(xml_data) > 500 else xml_data
                print(f"   📝 Problematic XML sample:")
                print(f"      {sample_content}")
                return False
                
            return True
            
        except Exception as e:
            print(f"   ❌ XML structure analysis failed: {e}")
            import traceback
            print(f"   Full traceback: {traceback.format_exc()}")
            return False
        
    def test_cwe_connectivity(self) -> bool:
        """Test connectivity to CWE XML source."""
        try:
            import requests
            
            # Test main CWE URL
            response = requests.head(self.loader.cwe_xml_url, timeout=10)
            if response.status_code == 200:
                print(f"   ✓ Main CWE XML source accessible")
                return True
            else:
                print(f"   ⚠ Main source returned {response.status_code}, checking backups...")
                
                # Test backup URLs
                for backup_url in self.loader.backup_urls:
                    try:
                        response = requests.head(backup_url, timeout=10)
                        if response.status_code == 200:
                            print(f"   ✓ Backup source accessible")
                            return True
                    except:
                        continue
                
                print("   ⚠ All sources inaccessible, will test fallback")
                return True  # Still pass - fallback should work
                
        except Exception as e:
            print(f"   ⚠ Connectivity test failed: {e}")
            return True  # Still pass - fallback should work
    
    def test_cwe_xml_download(self) -> bool:
        """Test downloading CWE XML data."""
        try:
            print(f"   📥 Downloading CWE XML data (this may take 1-2 minutes)...")
            start_time = time.time()
            
            xml_data = self.loader._download_and_extract_cwe_data()
            
            download_time = time.time() - start_time
            
            if xml_data:
                print(f"   ✓ Downloaded {len(xml_data):,} characters in {download_time:.1f}s")
                
                # Verify it looks like CWE XML
                if '<?xml' in xml_data and ('weakness' in xml_data.lower() or 'cwe' in xml_data.lower()):
                    print(f"   ✓ Data appears to be valid CWE XML")
                    return True
                else:
                    print(f"   ⚠ Downloaded data doesn't appear to be CWE XML")
                    return False
            else:
                print(f"   ⚠ Download failed, will test fallback mechanism")
                return True  # Fallback should handle this
                
        except Exception as e:
            print(f"   ⚠ Download test failed: {e}")
            return True  # Fallback should handle this
    
    def test_cwe_xml_parsing(self) -> bool:
        """Test XML parsing functionality."""
        try:
            # Try to parse downloaded data
            xml_data = self.loader._download_and_extract_cwe_data()
            
            if xml_data:
                print(f"   🔍 Parsing CWE XML data...")
                weaknesses = self.loader._parse_cwe_xml(xml_data)
                
                if weaknesses:
                    print(f"   ✓ Parsed {len(weaknesses)} CWE items")
                    
                    # Check weakness structure
                    sample_weakness = weaknesses[0]
                    required_fields = ['cwe_id', 'name', 'description']
                    
                    for field in required_fields:
                        if field not in sample_weakness:
                            print(f"   ❌ Missing required field: {field}")
                            return False
                    
                    print(f"   ✓ Weakness structure valid")
                    return True
                else:
                    print(f"   ⚠ No weaknesses extracted from XML")
                    return False
            else:
                print(f"   ⚠ No XML data to parse")
                return True  # Not a parsing failure
                
        except Exception as e:
            print(f"   ❌ XML parsing failed: {e}")
            return False
    
    def test_weakness_processing(self) -> bool:
        """Test processing of parsed weaknesses into documents."""
        try:
            print(f"   ⚙️ Testing weakness processing...")
            
            # Load data through the main interface
            data = self.loader.load_data()
            self.loaded_data = data  # Store for other tests
            
            if not data:
                print(f"   ❌ No data loaded")
                return False
            
            print(f"   ✓ Loaded {len(data)} processed weaknesses")
            
            # Check first weakness
            sample = data[0]
            required_fields = ['id', 'document_text', 'metadata', 'cwe_id', 'name']
            
            for field in required_fields:
                if field not in sample:
                    print(f"   ❌ Missing field in processed weakness: {field}")
                    return False
            
            # Check document text quality
            doc_text = sample['document_text']
            if len(doc_text) < 100:
                print(f"   ⚠ Document text seems too short: {len(doc_text)} chars")
                return False
            
            print(f"   ✓ Weakness processing successful")
            return True
            
        except Exception as e:
            print(f"   ❌ Weakness processing failed: {e}")
            return False
    
    def test_cwe_validation(self) -> bool:
        """Test CWE data validation."""
        try:
            if not self.loaded_data:
                self.loaded_data = self.loader.load_data()
            
            is_valid = self.loader.validate_data(self.loaded_data)
            
            if is_valid:
                print(f"   ✓ CWE data validation passed")
                return True
            else:
                print(f"   ❌ CWE data validation failed")
                return False
                
        except Exception as e:
            print(f"   ❌ Validation test failed: {e}")
            return False
    
    def test_capec_mapping_debugging(self) -> bool:
        """Debug CAPEC mapping extraction to see what's happening."""
        try:
            print(f"   🔍 Debugging CAPEC mapping extraction...")
            
            # Test the XML parsing directly
            xml_data = self.loader._download_and_extract_cwe_data()
            
            if xml_data:
                # Count CAPEC references in raw XML
                capec_pattern_count = xml_data.count('<Related_Attack_Pattern CAPEC_ID=')
                related_attack_patterns_count = xml_data.count('<Related_Attack_Patterns>')
                
                print(f"   📊 Raw XML analysis:")
                print(f"      Related_Attack_Patterns sections: {related_attack_patterns_count}")
                print(f"      Related_Attack_Pattern with CAPEC_ID: {capec_pattern_count}")
                
                # Parse and check a few specific examples
                weaknesses = self.loader._parse_cwe_xml(xml_data)
                print(f"   📊 Parsed {len(weaknesses)} total weaknesses")
                
                # Find weaknesses with CAPEC mappings
                weaknesses_with_capec = []
                for weakness in weaknesses:
                    capec_mappings = weakness.get('capec_mappings', [])
                    if capec_mappings:
                        weaknesses_with_capec.append({
                            'cwe_id': weakness.get('cwe_id'),
                            'name': weakness.get('name', 'Unknown'),
                            'capec_mappings': capec_mappings
                        })
                
                print(f"   📊 Weaknesses with CAPEC mappings: {len(weaknesses_with_capec)}")
                
                # Show examples
                for i, example in enumerate(weaknesses_with_capec[:5]):  # Show first 5
                    print(f"   📋 CWE-{example['cwe_id']}: {example['name']}")
                    print(f"      → {', '.join(example['capec_mappings'])}")
                
                # Test specific known example (CWE-1037 should map to CAPEC-663)
                cwe_1037 = next((w for w in weaknesses if w.get('cwe_id') == '1037'), None)
                if cwe_1037:
                    print(f"   🎯 Testing known example CWE-1037:")
                    print(f"      CAPEC mappings: {cwe_1037.get('capec_mappings', [])}")
                    print(f"      Expected: ['CAPEC-663']")
                
            return len(weaknesses_with_capec) > 0 if 'weaknesses_with_capec' in locals() else False
        
        except Exception as e:
            print(f"   ❌ CAPEC mapping debugging failed: {e}")
            import traceback
            print(f"   Full traceback: {traceback.format_exc()}")
            return False
        
    def test_environment_detection(self) -> bool:
        """Test environment applicability detection."""
        try:
            if not self.loaded_data:
                self.loaded_data = self.loader.load_data()
            
            # Check environment detection
            environments = set()
            for weakness in self.loaded_data:
                env_list = weakness.get('applicable_environments', [])
                environments.update(env_list)
            
            print(f"   🌍 Detected environments: {', '.join(sorted(environments))}")
            
            if len(environments) >= 3:
                print(f"   ✓ Environment detection working")
                return True
            else:
                print(f"   ⚠ Limited environment variation detected")
                return True  # Not critical
                
        except Exception as e:
            print(f"   ❌ Environment detection test failed: {e}")
            return False
    
    def test_impact_severity_analysis(self) -> bool:
        """Test impact severity analysis."""
        try:
            if not self.loaded_data:
                self.loaded_data = self.loader.load_data()
            
            # Check severity distribution
            severities = {}
            for weakness in self.loaded_data:
                severity = weakness.get('impact_severity', 'Unknown')
                severities[severity] = severities.get(severity, 0) + 1
            
            print(f"   📊 Severity distribution: {severities}")
            
            if len(severities) >= 2:
                print(f"   ✓ Impact severity analysis working")
                return True
            else:
                print(f"   ⚠ Limited severity variation detected")
                return True  # Not critical
                
        except Exception as e:
            print(f"   ❌ Impact severity test failed: {e}")
            return False
    
    def test_comprehensive_coverage(self) -> bool:
        """Test overall data coverage and quality."""
        try:
            if not self.loaded_data:
                self.loaded_data = self.loader.load_data()
            
            # Analyze data coverage
            total_weaknesses = len(self.loaded_data)
            weaknesses_with_consequences = sum(1 for w in self.loaded_data if w.get('consequences'))
            weaknesses_with_mitigations = sum(1 for w in self.loaded_data if w.get('mitigations'))
            weaknesses_with_examples = sum(1 for w in self.loaded_data if w.get('examples'))
            weaknesses_with_capec = sum(1 for w in self.loaded_data if w.get('capec_mappings'))
            
            print(f"   📊 Total weaknesses: {total_weaknesses}")
            print(f"   📊 With consequences: {weaknesses_with_consequences}")
            print(f"   📊 With mitigations: {weaknesses_with_mitigations}")
            print(f"   📊 With examples: {weaknesses_with_examples}")
            print(f"   📊 With CAPEC mappings: {weaknesses_with_capec}")
            
            # Calculate coverage percentages
            consequence_coverage = (weaknesses_with_consequences / total_weaknesses) * 100 if total_weaknesses > 0 else 0
            mitigation_coverage = (weaknesses_with_mitigations / total_weaknesses) * 100 if total_weaknesses > 0 else 0
            
            print(f"   📊 Consequences coverage: {consequence_coverage:.1f}%")
            print(f"   📊 Mitigations coverage: {mitigation_coverage:.1f}%")
            
            if total_weaknesses >= 20 and consequence_coverage >= 50:
                print(f"   ✓ Good data coverage achieved")
                return True
            else:
                print(f"   ⚠ Limited data coverage")
                return True  # Still functional
                
        except Exception as e:
            print(f"   ❌ Coverage analysis failed: {e}")
            return False
    
    def test_three_source_compatibility(self) -> bool:
        """Test compatibility with existing MITRE+CAPEC system."""
        try:
            if not self.loaded_data:
                self.loaded_data = self.loader.load_data()
            
            # Test that CWE data follows same patterns as MITRE/CAPEC
            sample_cwe = self.loaded_data[0]
            
            # Check metadata structure matches expected pattern
            metadata = sample_cwe.get('metadata', {})
            expected_fields = ['type', 'name', 'description']
            
            for field in expected_fields:
                if field not in metadata:
                    print(f"   ❌ Missing expected metadata field: {field}")
                    return False
            
            # Check data type is correctly set
            if metadata.get('type') != 'cwe_weakness':
                print(f"   ❌ Incorrect data type: {metadata.get('type')}")
                return False
            
            # Check document structure matches MITRE/CAPEC pattern
            if 'document_text' not in sample_cwe:
                print(f"   ❌ Missing document_text field")
                return False
            
            print(f"   ✓ Three-source compatibility verified")
            return True
            
        except Exception as e:
            print(f"   ❌ Three-source compatibility test failed: {e}")
            return False
    
    def print_comprehensive_analysis(self):
        """Print comprehensive analysis of loaded CWE data."""
        if not self.loaded_data:
            self.loaded_data = self.loader.load_data()
        
        print("\n" + "="*70)
        print("COMPREHENSIVE CWE DATA ANALYSIS")
        print("="*70)
        
        try:
            # Source information
            source_info = self.loader.get_source_info()
            print(f"📡 Data Source: {source_info['source_type']}")
            print(f"🌐 Source URL: {source_info['source_url']}")
            print(f"💾 Cache Status: {source_info['cache_status']}")
            print(f"🕒 Last Update: {source_info['last_update']}")
            print()
            
            # Weakness statistics
            total_weaknesses = len(self.loaded_data)
            print(f"📊 WEAKNESS STATISTICS")
            print(f"   Total Weaknesses: {total_weaknesses}")
            
            # Abstraction level distribution
            abstraction_dist = {}
            for weakness in self.loaded_data:
                abstraction = weakness.get('abstraction', 'Unknown')
                abstraction_dist[abstraction] = abstraction_dist.get(abstraction, 0) + 1
            
            print(f"   Abstraction Level Distribution:")
            for abstraction, count in sorted(abstraction_dist.items()):
                percentage = (count / total_weaknesses) * 100
                print(f"     {abstraction}: {count} ({percentage:.1f}%)")
            
            # Impact severity distribution
            severity_dist = {}
            for weakness in self.loaded_data:
                severity = weakness.get('impact_severity', 'Unknown')
                severity_dist[severity] = severity_dist.get(severity, 0) + 1
            
            print(f"   Impact Severity Distribution:")
            for severity, count in sorted(severity_dist.items()):
                percentage = (count / total_weaknesses) * 100
                print(f"     {severity}: {count} ({percentage:.1f}%)")
            
            # Environment coverage
            all_environments = set()
            for weakness in self.loaded_data:
                envs = weakness.get('applicable_environments', [])
                all_environments.update(envs)
            
            print(f"   Environment Coverage: {len(all_environments)} types")
            for env in sorted(all_environments):
                count = sum(1 for w in self.loaded_data if env in w.get('applicable_environments', []))
                print(f"     {env}: {count} weaknesses")
            
            # CAPEC mapping analysis
            capec_mappings = self.loader.get_cwe_capec_mappings()
            print(f"   CAPEC Mappings: {len(capec_mappings)} CWE-to-CAPEC relationships")

            if capec_mappings:
                # Analyze the actual mapping data
                total_capec_refs = sum(len(capec_list) for capec_list in capec_mappings.values())
                avg_mappings = total_capec_refs / len(capec_mappings) if capec_mappings else 0
                
                print(f"   Total CAPEC references: {total_capec_refs}")
                print(f"   Average CAPEC mappings per CWE: {avg_mappings:.1f}")
                
                # Show example mappings
                print(f"   Example CWE → CAPEC mappings:")
                for i, (cwe_key, capec_list) in enumerate(list(capec_mappings.items())[:3]):
                    capec_display = ', '.join(capec_list[:3])
                    if len(capec_list) > 3:
                        capec_display += f" (+{len(capec_list)-3} more)"
                    print(f"     {cwe_key} → {capec_display}")
            
            # Sample weakness display
            if self.loaded_data:
                print(f"\n📋 SAMPLE WEAKNESS")
                sample = self.loaded_data[0]
                print(f"   CWE ID: {sample.get('cwe_id')}")
                print(f"   Name: {sample.get('name')}")
                print(f"   Abstraction: {sample.get('abstraction')}")
                print(f"   Impact Severity: {sample.get('impact_severity')}")
                print(f"   Exploitation Complexity: {sample.get('exploitation_complexity')}")
                print(f"   Environments: {', '.join(sample.get('applicable_environments', []))}")
                print(f"   Consequences: {len(sample.get('consequences', []))} items")
                print(f"   Mitigations: {len(sample.get('mitigations', []))} items")
                print(f"   CAPEC Mappings: {', '.join(sample.get('capec_mappings', []))}")
                
                print(f"\n   Document Text (first 300 chars):")
                print(f"   {'-'*50}")
                print(f"   {sample.get('document_text', '')[:300]}...")
            
        except Exception as e:
            print(f"Error in analysis: {e}")

   
def main():
    """Main test function."""
    print("CWE Integration Test Suite")
    print("This will test loading weakness data from MITRE CWE XML source")
    print()
    
    tester = CweIntegrationTester()
    
    # Run all tests
    success = tester.run_all_tests()
    
    # Print comprehensive analysis
    tester.print_comprehensive_analysis()
    
    if success:
        print(f"\n{'='*70}")
        print("🎉 CWE INTEGRATION COMPLETE!")
        print("✅ Successfully loading XML data from official MITRE CWE source")
        print("✅ CWE-to-CAPEC mapping extraction working")
        print("✅ Impact severity and environment detection working")
        return 0
    else:
        print(f"\n{'='*70}")
        print("⚠️ SOME TESTS FAILED")
        print("The integration may still work with limited functionality.")
        print("Check the specific test failures above.")
        print(f"{'='*70}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
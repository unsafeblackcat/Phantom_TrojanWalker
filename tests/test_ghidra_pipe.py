"""
Integration tests for the Ghidra Pipe module.
Tests basic functionality: open, analyze, functions, strings, decompile.
"""
import os
import sys
import pytest

# Add module path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GHIDRA_PIPE_DIR = os.path.join(ROOT_DIR, "module", "ghidra_pipe")
if GHIDRA_PIPE_DIR not in sys.path:
    sys.path.insert(0, GHIDRA_PIPE_DIR)

from conftest import requires_ghidra

# Sample binary path
SAMPLE_BINARY = os.path.join(ROOT_DIR, "data", "uploads", "ran_emu")


def sample_exists():
    """Check if the sample binary exists."""
    return os.path.isfile(SAMPLE_BINARY)


requires_sample = pytest.mark.skipif(
    not sample_exists(),
    reason=f"Sample binary not found: {SAMPLE_BINARY}"
)


@requires_ghidra
@requires_sample
class TestGhidraAnalyzer:
    """Tests for GhidraAnalyzer class."""
    
    def test_open_binary(self):
        """Test opening a binary file with Ghidra."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            result = analyzer.open()
            assert result is True, "Failed to open binary"
        finally:
            analyzer.close()
    
    def test_analyze_binary(self):
        """Test running analysis on a binary."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            assert analyzer.open() is True
            result = analyzer.analyze()
            assert isinstance(result, dict)
            assert result.get("status") == "done"
        finally:
            analyzer.close()
    
    def test_get_functions(self):
        """Test getting function list."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            assert analyzer.open() is True
            analyzer.analyze()
            
            functions = analyzer.get_functions()
            assert isinstance(functions, list)
            assert len(functions) > 0, "No functions found"
            
            # Check function structure
            func = functions[0]
            assert "name" in func
            assert "offset" in func
            
            print(f"Found {len(functions)} functions")
            for f in functions[:5]:
                print(f"  - {f['name']} @ 0x{f['offset']:x}")
        finally:
            analyzer.close()
    
    def test_get_strings(self):
        """Test getting strings from binary."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            assert analyzer.open() is True
            analyzer.analyze()
            
            strings = analyzer.get_strings()
            assert isinstance(strings, list)
            
            print(f"Found {len(strings)} strings")
            for s in strings[:10]:
                print(f"  - {s.get('string', '')[:50]}")
        finally:
            analyzer.close()
    
    def test_get_metadata(self):
        """Test getting binary metadata."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            assert analyzer.open() is True
            
            info = analyzer.get_info()
            assert isinstance(info, dict)
            assert "core" in info or "bin" in info
            
            print(f"Metadata: {info}")
        finally:
            analyzer.close()
    
    def test_decompile_batch(self):
        """Test batch decompilation of functions."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            assert analyzer.open() is True
            analyzer.analyze()
            
            # Get some functions to decompile
            functions = analyzer.get_functions()
            assert len(functions) > 0
            
            # Take first 3 functions (or fewer if not enough)
            func_names = [f["name"] for f in functions[:3] if f.get("name")]
            assert len(func_names) > 0, "No function names to decompile"
            
            # Batch decompile
            results = analyzer.get_decompiled_code_batch(func_names)
            assert isinstance(results, list)
            assert len(results) > 0, "No decompilation results"
            
            # Check result structure
            for r in results:
                assert "address" in r
                assert "code" in r
                assert len(r["code"]) > 0, f"Empty code for {r['address']}"
                
                # Code should look like C (contains basic C syntax)
                code = r["code"]
                assert any(c in code for c in ["{", "}", ";", "return"]), \
                    f"Code doesn't look like C: {code[:100]}"
            
            print(f"Successfully decompiled {len(results)} functions")
            for r in results:
                print(f"\n--- {r['address']} ---")
                print(r["code"][:500] + "..." if len(r["code"]) > 500 else r["code"])
                
        finally:
            analyzer.close()
    
    def test_get_callgraph(self):
        """Test getting call graph."""
        from analyzer import GhidraAnalyzer
        
        analyzer = GhidraAnalyzer(SAMPLE_BINARY)
        try:
            assert analyzer.open() is True
            analyzer.analyze()
            
            callgraph = analyzer.get_global_call_graph()
            assert isinstance(callgraph, dict)
            
            # Should have nodes and edges (might be empty for simple binaries)
            if "nodes" in callgraph:
                print(f"Call graph: {len(callgraph.get('nodes', []))} nodes, "
                      f"{len(callgraph.get('edges', []))} edges")
        finally:
            analyzer.close()


@requires_ghidra
@requires_sample
def test_decompile_ran_emu():
    """
    Main integration test: Decompile the ran_emu sample binary.
    This is the primary test requested by the user.
    """
    from analyzer import GhidraAnalyzer
    
    print(f"\n{'='*60}")
    print(f"Testing Ghidra decompilation on: {SAMPLE_BINARY}")
    print(f"{'='*60}\n")
    
    analyzer = GhidraAnalyzer(SAMPLE_BINARY)
    try:
        # Open
        print("1. Opening binary...")
        assert analyzer.open() is True, "Failed to open binary"
        print("   ✓ Binary opened successfully")
        
        # Analyze
        print("\n2. Running analysis...")
        result = analyzer.analyze()
        assert result.get("status") == "done", f"Analysis failed: {result}"
        print("   ✓ Analysis completed")
        
        # Get info
        print("\n3. Getting metadata...")
        info = analyzer.get_info()
        print(f"   Format: {info.get('core', {}).get('format', 'unknown')}")
        print(f"   Arch: {info.get('bin', {}).get('arch', 'unknown')}")
        print(f"   Bits: {info.get('bin', {}).get('bits', 'unknown')}")
        
        # Get functions
        print("\n4. Getting functions...")
        functions = analyzer.get_functions()
        print(f"   Found {len(functions)} functions")
        
        # Filter interesting functions (auto-named like FUN_* or entry points)
        interesting = [f for f in functions if 
                       f.get("name", "").startswith("FUN_") or
                       f.get("name", "").lower() in ["main", "entry", "_start"]]
        
        if not interesting:
            interesting = functions[:5]  # Take first 5 if no FUN_ found
        
        print(f"   Selected {len(interesting)} functions for decompilation")
        
        # Decompile
        print("\n5. Decompiling functions...")
        func_names = [f["name"] for f in interesting if f.get("name")]
        results = analyzer.get_decompiled_code_batch(func_names)
        
        assert len(results) > 0, "No functions were decompiled"
        print(f"   ✓ Successfully decompiled {len(results)} functions")
        
        # Print decompiled code
        print("\n6. Decompiled code samples:")
        for r in results[:3]:  # Show first 3
            print(f"\n{'='*40}")
            print(f"Function: {r['address']}")
            print(f"{'='*40}")
            code = r["code"]
            if len(code) > 1000:
                print(code[:1000] + "\n... (truncated)")
            else:
                print(code)
        
        print(f"\n{'='*60}")
        print("✓ All tests passed successfully!")
        print(f"{'='*60}\n")
        
    finally:
        analyzer.close()


if __name__ == "__main__":
    # Run tests directly
    pytest.main([__file__, "-v", "-s"])

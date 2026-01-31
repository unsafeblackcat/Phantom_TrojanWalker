"""
GhidraAnalyzer: A module for binary analysis using pyghidra.
Provides functions, strings, metadata, call graph, and decompilation.
"""
import os
import logging
import tempfile
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

# Lazy-loaded Ghidra/Java classes (populated after pyghidra.start())
_ghidra_started = False
_DecompInterface = None
_ConsoleTaskMonitor = None
_StringDataInstance = None


def _ensure_ghidra_started():
    """Initialize pyghidra/JVM if not already started."""
    global _ghidra_started, _DecompInterface, _ConsoleTaskMonitor, _StringDataInstance
    if _ghidra_started:
        return
    
    import pyghidra
    pyghidra.start()
    
    # Import Ghidra Java classes via JPype bridge
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.data import StringDataInstance
    
    _DecompInterface = DecompInterface
    _ConsoleTaskMonitor = ConsoleTaskMonitor
    _StringDataInstance = StringDataInstance
    _ghidra_started = True
    logger.info("Ghidra/pyghidra initialized successfully")


class GhidraAnalyzer:
    """
    Analyzer class for binary files using Ghidra/pyghidra.
    Provides API similar to RizinAnalyzer for compatibility.
    """
    
    def __init__(self, file_path: str):
        self.file_path = file_path
        self._ctx = None
        self._flat_api = None
        self._program = None
        self._decompiler = None
        self._project_dir = None
    
    def open(self) -> bool:
        """
        Initialize Ghidra and open the binary file.
        Returns True on success, False on failure.
        """
        try:
            _ensure_ghidra_started()
            
            import pyghidra
            
            # Create a temporary project directory for this analysis
            self._project_dir = tempfile.mkdtemp(prefix="ghidra_project_")
            project_name = "TempProject"
            
            # Open the program with pyghidra (analyze=False, we'll do it explicitly)
            # Store the context manager to prevent garbage collection closing the program
            self._ctx = pyghidra.open_program(
                self.file_path,
                analyze=False,
                project_location=self._project_dir,
                project_name=project_name
            )
            self._flat_api = self._ctx.__enter__()
            
            self._program = self._flat_api.getCurrentProgram()
            
            # Initialize decompiler interface
            self._decompiler = _DecompInterface()
            self._decompiler.openProgram(self._program)
            
            logger.info(f"Opened binary: {self.file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error opening binary with Ghidra: {e}")
            return False
    
    def analyze(self, level: str = "full") -> Dict[str, str]:
        """
        Execute analysis on the binary.
        level is kept for API compatibility but Ghidra always does full analysis.
        """
        if not self._program:
            return {"status": "error", "message": "Program not opened"}
        
        try:
            # Run Ghidra auto-analysis
            self._flat_api.analyzeAll(self._program)
            logger.info("Ghidra analysis completed")
            return {"status": "done"}
        except Exception as e:
            logger.error(f"Analysis error: {e}")
            return {"status": "error", "message": str(e)}
    
    def get_functions(self) -> List[Dict[str, Any]]:
        """
        Get list of functions in the binary.
        Returns list of dicts with: name, offset, size, signature
        """
        if not self._program:
            return []
        
        functions = []
        try:
            func_manager = self._program.getFunctionManager()
            func_iter = func_manager.getFunctions(True)  # Forward iteration
            
            for func in func_iter:
                entry = func.getEntryPoint()
                body = func.getBody()
                
                func_info = {
                    "name": func.getName(),
                    "offset": entry.getOffset() if entry else 0,
                    "size": body.getNumAddresses() if body else 0,
                    "signature": func.getSignature().getPrototypeString() if func.getSignature() else ""
                }
                functions.append(func_info)
            
            logger.info(f"Found {len(functions)} functions")
            return functions
            
        except Exception as e:
            logger.error(f"Error getting functions: {e}")
            return []
    
    def get_strings(self) -> List[Dict[str, Any]]:
        """
        Get strings from the binary.
        Returns list of dicts with: string, vaddr, section, type, length
        """
        if not self._program:
            return []
        
        strings = []
        try:
            listing = self._program.getListing()
            data_iter = listing.getDefinedData(True)  # Forward iteration
            
            for data in data_iter:
                # Check if this data is a string type
                data_type = data.getDataType()
                type_name = data_type.getName().lower() if data_type else ""
                
                if "string" in type_name or "unicode" in type_name:
                    try:
                        value = data.getValue()
                        if value is not None:
                            str_value = str(value)
                            if str_value and len(str_value) > 0:
                                addr = data.getAddress()
                                strings.append({
                                    "string": str_value,
                                    "vaddr": addr.getOffset() if addr else 0,
                                    "section": "",  # Ghidra doesn't expose section info directly here
                                    "type": type_name,
                                    "length": len(str_value)
                                })
                    except Exception:
                        pass  # Skip problematic strings
            
            logger.info(f"Found {len(strings)} strings")
            return strings
            
        except Exception as e:
            logger.error(f"Error getting strings: {e}")
            return []
    
    def get_info(self) -> Dict[str, Any]:
        """
        Get binary metadata/info.
        Returns dict compatible with existing frontend expectations.
        """
        if not self._program:
            return {}
        
        try:
            lang = self._program.getLanguage()
            compiler_spec = self._program.getCompilerSpec()
            exe_format = self._program.getExecutableFormat()
            
            # Build info structure compatible with frontend
            info = {
                "core": {
                    "file": os.path.basename(self.file_path),
                    "format": exe_format or "unknown",
                    "mode": str(lang.getLanguageDescription().getSize()) if lang else "unknown",
                    "type": "executable",
                },
                "bin": {
                    "arch": str(lang.getProcessor()) if lang else "unknown",
                    "bits": lang.getLanguageDescription().getSize() if lang else 0,
                    "machine": str(lang.getLanguageDescription().getProcessor()) if lang else "unknown",
                    "os": compiler_spec.getCompilerSpecID().getIdAsString() if compiler_spec else "unknown",
                    "endian": "little" if lang and lang.isBigEndian() == False else "big",
                    "compiler": compiler_spec.getCompilerSpecID().getIdAsString() if compiler_spec else "unknown",
                }
            }
            
            return info
            
        except Exception as e:
            logger.error(f"Error getting info: {e}")
            return {}
    
    def get_decompiled_code(self, address_or_name: str) -> Optional[Dict[str, str]]:
        """
        Decompile a single function by name or address.
        Returns dict with 'code' key, or None on failure.
        """
        if not self._program or not self._decompiler:
            return None
        
        try:
            func = self._find_function(address_or_name)
            if not func:
                return None
            
            monitor = _ConsoleTaskMonitor()
            results = self._decompiler.decompileFunction(func, 60, monitor)
            
            if results and results.decompileCompleted():
                decomp_func = results.getDecompiledFunction()
                if decomp_func:
                    return {"code": decomp_func.getC()}
            
            return None
            
        except Exception as e:
            logger.error(f"Error decompiling {address_or_name}: {e}")
            return None
    
    def get_decompiled_code_batch(self, addresses: List[str]) -> List[Dict[str, str]]:
        """
        Batch decompile multiple functions.
        Returns list of dicts with 'address' and 'code' keys.
        """
        if not self._program or not self._decompiler:
            return []
        
        results = []
        monitor = _ConsoleTaskMonitor()
        
        for addr in addresses:
            try:
                func = self._find_function(addr)
                if not func:
                    continue
                
                decomp_results = self._decompiler.decompileFunction(func, 60, monitor)
                
                if decomp_results and decomp_results.decompileCompleted():
                    decomp_func = decomp_results.getDecompiledFunction()
                    if decomp_func:
                        code = decomp_func.getC()
                        if code:
                            results.append({
                                "address": addr,
                                "code": code
                            })
                            
            except Exception as e:
                logger.warning(f"Error decompiling {addr}: {e}")
                continue
        
        logger.info(f"Decompiled {len(results)}/{len(addresses)} functions")
        return results
    
    def get_global_call_graph(self) -> Dict[str, Any]:
        """
        Generate global call graph.
        Returns dict with 'nodes' and 'edges' lists.
        """
        if not self._program:
            return {}
        
        try:
            func_manager = self._program.getFunctionManager()
            ref_manager = self._program.getReferenceManager()
            
            nodes = []
            edges = []
            func_map = {}  # name -> node index
            
            # First pass: collect all functions as nodes
            func_iter = func_manager.getFunctions(True)
            for idx, func in enumerate(func_iter):
                name = func.getName()
                nodes.append({
                    "id": idx,
                    "name": name,
                    "offset": func.getEntryPoint().getOffset() if func.getEntryPoint() else 0
                })
                func_map[name] = idx
            
            # Second pass: find call references to build edges
            func_iter = func_manager.getFunctions(True)
            for func in func_iter:
                caller_name = func.getName()
                if caller_name not in func_map:
                    continue
                
                # Get all references from this function's body
                body = func.getBody()
                if not body:
                    continue
                
                # Iterate through the function body looking for call references
                called_funcs = set()
                ref_iter = ref_manager.getReferenceSourceIterator(body, True)
                for ref in ref_iter:
                    if ref.getReferenceType().isCall():
                        to_addr = ref.getToAddress()
                        callee = func_manager.getFunctionAt(to_addr)
                        if callee:
                            called_funcs.add(callee.getName())
                
                for callee_name in called_funcs:
                    if callee_name in func_map:
                        edges.append({
                            "from": func_map[caller_name],
                            "to": func_map[callee_name]
                        })
            
            logger.info(f"Call graph: {len(nodes)} nodes, {len(edges)} edges")
            return {"nodes": nodes, "edges": edges}
            
        except Exception as e:
            logger.error(f"Error generating call graph: {e}")
            return {}
    
    def _find_function(self, address_or_name: str) -> Optional[Any]:
        """
        Find a function by name or address string.
        """
        if not self._program:
            return None
        
        func_manager = self._program.getFunctionManager()
        
        # Try to parse as hex address first
        try:
            if address_or_name.startswith("0x"):
                addr_val = int(address_or_name, 16)
            elif address_or_name.startswith("fcn."):
                # Rizin-style auto-named function (fcn.00401000)
                addr_val = int(address_or_name[4:], 16)
            else:
                addr_val = None
            
            if addr_val is not None:
                addr_factory = self._program.getAddressFactory()
                addr = addr_factory.getDefaultAddressSpace().getAddress(addr_val)
                func = func_manager.getFunctionAt(addr)
                if func:
                    return func
                # Also try containing function
                func = func_manager.getFunctionContaining(addr)
                if func:
                    return func
        except (ValueError, Exception):
            pass
        
        # Try to find by name
        func_iter = func_manager.getFunctions(True)
        for func in func_iter:
            if func.getName() == address_or_name:
                return func
        
        return None
    
    def close(self):
        """
        Close the analyzer and release resources.
        """
        try:
            if self._decompiler:
                self._decompiler.closeProgram()
                self._decompiler.dispose()
                self._decompiler = None
            
            if self._ctx:
                # Exit the context manager properly
                try:
                    self._ctx.__exit__(None, None, None)
                except Exception:
                    pass
                self._ctx = None
                self._flat_api = None
            
            self._program = None
            
            # Cleanup temp project directory
            if self._project_dir and os.path.exists(self._project_dir):
                import shutil
                try:
                    shutil.rmtree(self._project_dir)
                except Exception:
                    pass
                self._project_dir = None
            
            logger.info("GhidraAnalyzer closed")
            
        except Exception as e:
            logger.error(f"Error closing analyzer: {e}")
    
    def __enter__(self):
        self.open()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

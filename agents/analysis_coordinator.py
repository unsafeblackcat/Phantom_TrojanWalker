import logging
from typing import Dict, Any, List
from fastapi import UploadFile

from ghidra_client import GhidraClient
from agent_core import FunctionAnalysisAgent, MalwareAnalysisAgent

logger = logging.getLogger(__name__)

class AnalysisCoordinator:
    def __init__(self, ghidra_client: GhidraClient, func_agent: FunctionAnalysisAgent, malware_agent: MalwareAnalysisAgent):
        self.ghidra = ghidra_client
        self.func_agent = func_agent
        self.malware_agent = malware_agent

    def _normalize_func_name(self, name: str) -> str:
        if not name:
            return ""
        base = str(name).strip()
        # Ghidra/disassemblers often prefix symbols, keep the last segment for matching
        for prefix in ("FUN_", "thunk_FUN_", "LAB_", "DAT_", "PTR_", "s_"):
            if base.startswith(prefix):
                base = base[len(prefix):]
        # Handle legacy rizin prefixes for compatibility
        for prefix in ("sym.", "fcn.", "sub.", "loc.", "imp.", "obj.", "dbg."):
            if base.startswith(prefix):
                base = base[len(prefix):]
        # Sometimes symbols still contain dots/underscores after stripping
        if "." in base:
            base = base.split(".")[-1]
        base = base.lstrip("_")
        return base.lower()

    def _is_ai_target_function(self, name: str) -> bool:
        if not name:
            return False
        # Ghidra auto-named functions start with FUN_
        if str(name).startswith("FUN_"):
            return True
        # Legacy rizin format
        if str(name).startswith("fcn."):
            return True
        normalized = self._normalize_func_name(str(name))
        # Cover common entrypoints across C/C++ and Windows binaries
        interesting = {
            "main",
            "wmain",
            "winmain",
            "wwinmain",
            "dllmain",
            # Common CRT/loader entrypoints
            "maincrtstartup",
            "winmaincrtstartup",
            "dllmaincrtstartup",
            "tmaincrtstartup",
            "wtmaincrtstartup",
            # Linux/ELF entrypoints
            "_start",
            "start",
            "entry",
        }
        return normalized in interesting

    def _is_entry_point_function(self, name: str) -> bool:
        """Check if function is an entry point that should always be analyzed."""
        if not name:
            return False
        normalized = self._normalize_func_name(str(name))
        # Entry points that must always be analyzed, even if not called by others.
        entry_points = {
            "main",
            "wmain",
            "winmain",
            "wwinmain",
            "dllmain",
            "_start",
            "start",
            "entry",
        }
        return normalized in entry_points

    def _build_functions_payload(self, raw_funcs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Refactor: isolate mapping logic for readability and reuse.
        return [
            {
                "name": f.get("name"),
                "offset": f.get("offset"),
                "size": f.get("size"),
                "signature": f.get("signature"),
            }
            for f in raw_funcs
        ]

    def _extract_function_names(self, functions_data: List[Dict[str, Any]]) -> List[str]:
        # Refactor: keep filtering rules in one place.
        return [f["name"] for f in functions_data if f.get("name")]

    def _filter_function_names_for_decompile(self, func_names: List[str]) -> List[str]:
        """Limit decompile targets to auto-named and common entrypoint functions."""
        return [name for name in func_names if self._is_ai_target_function(name)]

    def _map_decompiled_results(self, decompiled_codes_raw: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        # Refactor: normalize backend results and guard missing fields.
        mapped: List[Dict[str, str]] = []
        # 后端返回格式为 [{"address": "name_or_addr", "code": "..."}]
        for item in decompiled_codes_raw:
            name = item.get("address")  # address 字段包含我们发送的名称
            code = item.get("code")
            if code and name:
                mapped.append({
                    "name": name,
                    "code": code,
                })
        return mapped

    def _filter_target_functions(self, decompiled_codes: List[Dict[str, str]]) -> List[Dict[str, str]]:
        # Refactor: single-responsibility filtering step for AI analysis.
        return [
            item
            for item in decompiled_codes
            if self._is_ai_target_function(item.get("name"))
        ]

    def _build_callers_lookup(self, function_xrefs: List[Dict[str, Any]] | None) -> Dict[str, List[Dict[str, Any]]]:
        """Build a lookup from function name to its callers list."""
        if not function_xrefs:
            return {}
        lookup: Dict[str, List[Dict[str, Any]]] = {}
        for xref in function_xrefs:
            name = xref.get("name") if isinstance(xref, dict) else None
            if name:
                callers = xref.get("callers", []) if isinstance(xref, dict) else []
                lookup[name] = callers or []
        return lookup

    def _filter_functions_with_callers(
        self,
        target_funcs: List[Dict[str, str]],
        callers_lookup: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, str]]:
        """
        Filter out functions that have no callers, unless they are entry points.
        Entry points (main/WinMain/DllMain/entry) are always kept.
        """
        filtered: List[Dict[str, str]] = []
        for item in target_funcs:
            name = item.get("name")
            if not name:
                continue
            # Always keep entry point functions
            if self._is_entry_point_function(name):
                filtered.append(item)
                continue
            # Keep functions that have at least one caller
            callers = callers_lookup.get(name, [])
            if len(callers) > 0:
                filtered.append(item)
        return filtered

    def _select_key_function_analyses(self, function_analysis_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        # Refactor: keep ATT&CK selection logic isolated and testable.
        key_results: List[Dict[str, Any]] = []
        for item in function_analysis_results:
            analysis = item.get("analysis") if isinstance(item, dict) else None
            if not isinstance(analysis, dict):
                continue
            # skip errored analyses
            if "error" in analysis:
                continue
            attack_matches = analysis.get("attack_matches")
            if isinstance(attack_matches, list) and len(attack_matches) > 0:
                key_results.append(item)
        return key_results

    async def analyze_file(self, file: UploadFile) -> Dict[str, Any]:
        content = await file.read()
        return await self.analyze_content(file.filename, content, file.content_type)

    async def analyze_content(self, filename: str, content: bytes, content_type: str = "application/octet-stream") -> Dict[str, Any]:
        logger.info(f"Start analyzing file: {filename}")
        
        # 1. Check Health
        logger.info("Step 1: Checking Ghidra backend health...")
        await self.ghidra.check_health()

        # 2. Upload
        logger.info(f"Step 2: Uploading file '{filename}' to backend...")
        await self.ghidra.upload_file(filename, content, content_type)

        # 3. Trigger Analysis
        logger.info("Step 3: Triggering Ghidra analysis...")
        await self.ghidra.trigger_analysis()

        # 4. Fetch Metadata
        logger.info("Step 4: Fetching binary metadata...")
        metadata = await self.ghidra.get_metadata()

        # 5. Fetch Functions
        logger.info("Step 5: Fetching and filtering functions...")
        raw_funcs = await self.ghidra.get_functions()
        if raw_funcs is None:
            logger.warning("Ghidra returned null functions list; defaulting to empty")
            raw_funcs = []

        functions_data = self._build_functions_payload(raw_funcs)

        # 6. Fetch Strings
        logger.info("Step 6: Fetching strings from binary...")
        strings_data = await self.ghidra.get_strings()
        if strings_data is None:
            logger.warning("Ghidra returned null strings list; defaulting to empty")
            strings_data = []

        # 7. Call Graph
        logger.info("Step 7: Generating global call graph...")
        await self.ghidra.get_callgraph()

        # 7.5 Fetch function cross-references (callers/callees)
        logger.info("Step 7.5: Fetching function cross-references...")
        func_names = self._extract_function_names(functions_data)
        decompile_targets = self._filter_function_names_for_decompile(func_names)
        logger.info(f"Xrefs targets: {len(decompile_targets)} functions")
        function_xrefs = await self.ghidra.get_function_xrefs_batch(decompile_targets)
        if function_xrefs is None:
            logger.warning("Ghidra returned null xrefs list; defaulting to empty")
            function_xrefs = []
        callers_lookup = self._build_callers_lookup(function_xrefs)
        logger.info(f"Got xrefs for {len(function_xrefs)} functions")

        # 8. Decompile (Batch)
        logger.info(f"Step 8: Decompiling functions (Batch mode)...")
        
        # 调用批量反编译接口 (后端支持通过名称或地址反编译)
        logger.info(f"Decompile targets: {len(decompile_targets)} functions")
        decompiled_codes_raw = await self.ghidra.get_decompiled_codes_batch(decompile_targets)
        if decompiled_codes_raw is None:
            logger.warning("Ghidra returned null decompile list; defaulting to empty")
            decompiled_codes_raw = []
        
        # 将原始结果直接映射到最终结果
        decompiled_codes = self._map_decompiled_results(decompiled_codes_raw)

        # 9. AI Analysis (Parallel)
        logger.info(f"Step 9: Analyzing {len(decompiled_codes)} decompiled functions...")

        # 分析目标函数：FUN_* / fcn.* 自动命名函数 + 常见入口函数（main/WinMain/DllMain 等）
        target_funcs = self._filter_target_functions(decompiled_codes)
        
        # 9.1 Filter out functions with no callers (except entry points)
        # 如果一个函数没有被其他任何函数调用，则不分析该函数（入口函数例外）
        target_funcs = self._filter_functions_with_callers(target_funcs, callers_lookup)
        logger.info(f"After caller filter: {len(target_funcs)} functions to analyze")
        
        if not target_funcs:
            logger.info("No target functions found for AI analysis, skipping function analysis step.")
            function_analysis_results = []
        else:
            function_analysis_results = await self.func_agent.analyze_decompiled_batch(target_funcs)

        # 9.5 Filter key functions (ATT&CK matched)
        # 只把“能映射到 ATT&CK 的重点函数”交给最终报告 Agent，减少噪音。
        # 规则：只要 attack_matches 非空，就视为重点函数（不依赖 confidence 阈值）。

        key_function_analysis_results = self._select_key_function_analyses(function_analysis_results)

        logger.info(
            "Step 9.5: Selected %d key functions (ATT&CK matched)",
            len(key_function_analysis_results),
        )

        # 10. Malware Report
        logger.info("Step 10: Generating final malware analysis report (ATT&CK-focused)...")
        final_malware_report = await self.malware_agent.analyze(
            analysis_results=key_function_analysis_results,
            metadata=metadata,
        )

        logger.info(f"Analysis complete for file: {filename}")
        return {
            "metadata": metadata,
            "functions": functions_data,
            "strings": strings_data,
            "decompiled_code": decompiled_codes,
            "function_xrefs": function_xrefs,
            "function_analyses": function_analysis_results,
            "malware_report": final_malware_report
        }

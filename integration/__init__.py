"""Integration module for threat classification"""
from .run_with_skill import (
    process_with_skill,
    process_batch_with_skill,
    build_skill_input,
    build_skill_prompt,
    call_gemma_api,
    main as integration_main
)
from .runtime import (
    ThreatClassificationRuntime,
    DetectionResult,
    process_with_browser
)

__all__ = [
    'process_with_skill',
    'process_batch_with_skill',
    'build_skill_input',
    'build_skill_prompt',
    'call_gemma_api',
    'integration_main',
    'ThreatClassificationRuntime',
    'DetectionResult',
    'process_with_browser',
]
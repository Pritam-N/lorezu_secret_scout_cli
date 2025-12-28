from __future__ import annotations

from typing import Callable, Dict, List

from scout.core.models import StructuredFormat
from scout.parsers.dotenv_parser import parse_dotenv
from scout.parsers.ini_parser import parse_ini
from scout.parsers.json_parser import parse_json
from scout.parsers.toml_parser import parse_toml
from scout.parsers.yaml_parser import parse_yaml
from scout.parsers.types import ParsedKV

ParserFn = Callable[[str], List[ParsedKV]]

PARSERS: Dict[StructuredFormat, ParserFn] = {
    StructuredFormat.DOTENV: parse_dotenv,
    StructuredFormat.YAML: parse_yaml,
    StructuredFormat.JSON: parse_json,
    StructuredFormat.TOML: parse_toml,
    StructuredFormat.INI: parse_ini,
}
"""Blacklist module - Cloud blacklist client"""
from .blacklist_client import WDClient, query_wd_black_type, query_single_url
from .black_type_mapper import map_black_type, map_wd_info_type

__all__ = ['WDClient', 'query_wd_black_type', 'query_single_url', 'map_black_type', 'map_wd_info_type']
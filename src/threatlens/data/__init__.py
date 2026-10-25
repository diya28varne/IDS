"""Dataset intake: paths, schema checks, loading, and leakage-safe splits.

This package does not train models and does not download datasets.
"""

from threatlens.data.clean import CleaningReport, clean_flow_csv, clean_flow_frame
from threatlens.data.config import DEFAULT_RANDOM_SEED, project_root, raw_data_dir
from threatlens.data.dataset import DatasetReport, inspect_dataset, load_csv
from threatlens.data.features import (
    ConstantColumnFilter,
    FeatureMatrix,
    filter_splits_drop_constants,
    fit_constant_column_filter,
    prepare_features_labels,
)
from threatlens.data.load import load_flow_csv
from threatlens.data.schema import FlowSchema, validate_flow_frame
from threatlens.data.split import FeatureLabelSplit, split_features_labels, split_xy

__all__ = [
    "CleaningReport",
    "ConstantColumnFilter",
    "DEFAULT_RANDOM_SEED",
    "DatasetReport",
    "FeatureLabelSplit",
    "FeatureMatrix",
    "FlowSchema",
    "clean_flow_csv",
    "clean_flow_frame",
    "filter_splits_drop_constants",
    "fit_constant_column_filter",
    "inspect_dataset",
    "load_csv",
    "load_flow_csv",
    "prepare_features_labels",
    "project_root",
    "raw_data_dir",
    "split_features_labels",
    "split_xy",
    "validate_flow_frame",
]

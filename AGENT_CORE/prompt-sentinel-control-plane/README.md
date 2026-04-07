# prompt-sentinel-control-plane

Enterprise control-plane scaffold for Prompt_Sentinel.

## Target Responsibilities

- policy distribution and inheritance across teams and repos
- approval and capability workflows for guarded actions
- key metadata, rotation orchestration, and separation-of-duty hooks
- audit search, export, and SIEM delivery
- sanitized threat-vector sharing across deployments

## In This Repo

- `src/prompt_sentinel_control_plane/`: FastAPI-style service skeleton
- `schemas/`: enterprise bundle, approval, alert, and threat-vector schemas

## Product Role

This package is the Enterprise layer above `prompt-sentinel-core`. It is where Prompt_Sentinel grows from a paid Guard add-on into centralized enterprise governance.
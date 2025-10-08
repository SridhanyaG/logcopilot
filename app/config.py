from pydantic_settings import BaseSettings
from pydantic import Field
import yaml
import os
from pathlib import Path

class Settings(BaseSettings):
    aws_region: str = Field(default="us-east-1")
    log_group_name: str = Field(default="/ecs/crocin-backend")

    ecr_repository: str | None = None
    ecr_image_tag: str | None = None
    ecr_image_digest: str | None = None

    github_repo: str | None = None  # e.g. owner/repo
    github_branch: str | None = None
    release_version: str | None = None
    requirements_path: str | None = None

    openai_api_key: str | None = None
    openai_model: str = Field(default="gpt-4o-mini")
    
    # LLM Configuration
    llm_provider: str = Field(default="openai")  # Options: "openai" or "core_ai"
    core_ai_token: str | None = None
    core_ai_client_id: str | None = None
    core_ai_url: str = Field(default="https://int.lionis.ai/api/v1/llm/chat/completions")
    
    # NVD API Configuration
    nvd_api_key: str | None = None
    nvd_base_url: str = Field(default="https://services.nvd.nist.gov/rest/json")
    
    # Scheduler Configuration
    scheduler: dict = Field(default_factory=dict)
    
    # Monitoring Configuration  
    monitoring: dict = Field(default_factory=dict)

    class Config:
        env_file = ".env"
        extra = "ignore"

    @classmethod
    def load_from_yaml(cls, yaml_path: str = "config.yaml"):
        """Load settings from YAML config file"""
        if os.path.exists(yaml_path):
            with open(yaml_path, 'r') as f:
                config = yaml.safe_load(f)
            
            # Override with YAML values if they exist
            settings = cls()
            if 'aws' in config:
                aws_config = config['aws']
                settings.aws_region = aws_config.get('region', settings.aws_region)
                settings.log_group_name = aws_config.get('log_group', settings.log_group_name)
                if 'ecr' in aws_config:
                    ecr_config = aws_config['ecr']
                    settings.ecr_repository = ecr_config.get('repository', settings.ecr_repository)
                    settings.ecr_image_tag = ecr_config.get('image_tag', settings.ecr_image_tag)
                    settings.ecr_image_digest = ecr_config.get('image_digest', settings.ecr_image_digest)
            
            if 'github' in config:
                github_config = config['github']
                settings.github_repo = github_config.get('repository', settings.github_repo)
                settings.github_branch = github_config.get('branch', settings.github_branch)
            
            if 'project' in config:
                project_config = config['project']
                settings.release_version = project_config.get('version', settings.release_version)
            
            if 'files' in config:
                files_config = config['files']
                settings.requirements_path = files_config.get('requirements_path', settings.requirements_path)
            
            if 'llm' in config:
                llm_config = config['llm']
                print(f"Loading LLM configuration from YAML")
                settings.openai_model = llm_config.get('model', settings.openai_model)
                print(f"OpenAI model set to: {settings.openai_model}")
                settings.llm_provider = llm_config.get('provider', settings.llm_provider)
                print(f"LLM provider set to: {settings.llm_provider}")
                
                # Load Core AI configuration if present
                if 'core_ai' in llm_config:
                    print("Loading Core AI configuration from YAML")
                    core_ai_config = llm_config['core_ai']
                    settings.core_ai_token = core_ai_config.get('token', settings.core_ai_token)
                    settings.core_ai_client_id = core_ai_config.get('client_id', settings.core_ai_client_id)
                    settings.core_ai_url = core_ai_config.get('url', settings.core_ai_url)
                    print(f"Core AI URL set to: {settings.core_ai_url}")
                    print(f"Core AI token present: {bool(settings.core_ai_token)}")
                    print(f"Core AI client ID present: {bool(settings.core_ai_client_id)}")
                else:
                    print("No Core AI configuration found in YAML")
            
            if 'scheduler' in config:
                settings.scheduler = config['scheduler']
            
            if 'monitoring' in config:
                settings.monitoring = config['monitoring']
            
            return settings
        
        return cls()

settings = Settings.load_from_yaml()

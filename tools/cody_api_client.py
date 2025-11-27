#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#!/usr/bin/env python3
# -*- coding: UTF-8 -*-
#
# Copyright 2025 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""SPSDK Cody API client for external AI assistance.

This module provides functionality for communicating with Cody API services
to enable AI-powered assistance within SPSDK tools and workflows.
"""

import json
import logging
import os
from typing import Optional

import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class CodyApiClient:
    """SPSDK Cody API Client.

    Singleton client for communicating with Cody API services, providing
    unified access to AI-powered code analysis and completion capabilities.
    Manages authentication, configuration, and request handling for SPSDK
    development tools integration.

    :cvar _instance: Singleton instance reference.
    :cvar _initialized: Initialization state flag.
    """

    _instance = None
    _initialized = False

    def __new__(cls) -> "CodyApiClient":
        """Create or return the singleton instance of CodyApiClient.

        Implements the singleton pattern to ensure only one instance of the API client
        exists throughout the application lifecycle.

        :param cls: The class being instantiated.
        :return: The singleton instance of CodyApiClient.
        """
        if cls._instance is None:
            cls._instance = super(CodyApiClient, cls).__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the Cody API client with configuration from environment variables.

        Sets up API credentials, endpoints, headers, and model configuration required
        for communication with the Cody API service. The initialization is performed
        only once using a singleton pattern.

        :raises ValueError: When CODY_SRC_ACCESS_TOKEN environment variable is not set.
        """
        if self._initialized:
            return

        # Configuration from environment
        self.max_tokens = int(os.environ.get("CODY_MAX_TOKENS", "4000"))
        self.temperature = float(os.environ.get("CODY_TEMPERATURE", "0.2"))
        self.timeout = int(os.environ.get("CODY_TIMEOUT", "60"))
        self.verify_ssl = os.environ.get("CODY_VERIFY_SSL", "false").lower() == "true"

        # Set up API credentials and endpoints
        self.access_token = os.environ.get("CODY_SRC_ACCESS_TOKEN")
        if not self.access_token:
            raise ValueError("CODY_SRC_ACCESS_TOKEN environment variable is required")

        self.endpoint = os.environ.get("CODY_SRC_ENDPOINT", "https://sourcegraph.com/")

        # API URL
        self.chat_completions_url = (
            f"{self.endpoint}/.api/completions/stream"
            "?api-version=1&client-name=cody-data-processor&client-version=1.0"
        )

        # Headers
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"token {self.access_token}",
        }

        # Determine model to use
        self.model = self._determine_model()

        self._initialized = True
        LOGGER.info(f"✅ Cody API client initialized with model: {self.model}")

    def _get_available_models(self) -> list[str]:
        """Fetch available models from the Cody API endpoint.

        Attempts to retrieve the list of available models from the API's models endpoint.
        Handles different response formats and gracefully falls back to an empty list
        if the API is unavailable or returns an error.

        :return: List of available model names, empty list if unavailable.
        """
        try:
            models_url = f"{self.endpoint}/.api/models"
            api_response = requests.get(
                models_url, headers=self.headers, timeout=10, verify=self.verify_ssl
            )
            if api_response.status_code == 200:
                models_data = api_response.json()
                # Handle different possible response formats
                if isinstance(models_data, dict):
                    return models_data.get("models", [])
                if isinstance(models_data, list):
                    return models_data
            else:
                LOGGER.debug(f"Models API returned status {api_response.status_code}")
        except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
            LOGGER.debug(f"Could not fetch available models: {e}")
        return []

    def _select_best_model(self, preferred_models: list[str]) -> str:
        """Select the best available model from preferred list.

        This method attempts to find the most suitable model by first checking
        preferred models in order of preference. If none are available, it falls
        back to any available Claude Sonnet model, or uses the first preferred
        model as a last resort.

        :param preferred_models: List of model names in order of preference.
        :return: Name of the selected model.
        """
        available_models = self._get_available_models()

        if not available_models:
            # If we can't get available models, use the first preferred model
            LOGGER.info("Could not fetch available models, using first preferred model")
            return preferred_models[0]

        # Try preferred models in order
        for model in preferred_models:
            if model in available_models:
                LOGGER.info(f"Selected model: {model}")
                return model

        # If none of the preferred models are available, use the first available model
        # that contains "claude" and "sonnet" (as a reasonable fallback)
        for model in available_models:
            if "claude" in model.lower() and "sonnet" in model.lower():
                LOGGER.warning(f"Using fallback model: {model}")
                return model

        # Last resort: use first preferred model anyway
        LOGGER.warning(f"No suitable models found, using fallback: {preferred_models[0]}")
        return preferred_models[0]

    def _determine_model(self) -> str:
        """Determine which model to use with automatic detection and environment variable support.

        The method prioritizes environment variable CODY_MODEL over automatic selection.
        If no environment variable is set, it attempts to select the best available model
        from a predefined list of preferred models ordered by preference.

        :return: Selected model identifier string.
        """
        # 1. Check environment variable first (highest priority)
        env_model = os.environ.get("CODY_MODEL")
        if env_model:
            LOGGER.info(f"Using model from CODY_MODEL environment variable: {env_model}")
            return env_model

        # 2. Auto-select from preferred list (ordered by preference - newest first)
        preferred_models = [
            "anthropic::2024-10-22::claude-sonnet-4-latest",
            "anthropic::2024-12-20::claude-3-7-sonnet-latest",
            "anthropic::2024-10-22::claude-3-7-sonnet-latest",
            "anthropic::claude-3-sonnet-latest",
            "anthropic::claude-3-sonnet-20240229",  # Additional fallback
        ]

        return self._select_best_model(preferred_models)

    def send_prompt(self, prompt: str) -> Optional[str]:
        """Send prompt to Cody and wait for response (blocking).

        This method sends a prompt to the Cody API using streaming response processing.
        It handles the complete request lifecycle including error handling and response parsing.

        :param prompt: The prompt text to send to Cody API.
        :return: Response content from Cody or None if request failed.

        """
        data = {
            "maxTokensToSample": self.max_tokens,
            "messages": [{"speaker": "human", "text": prompt}],
            "model": self.model,
            "temperature": self.temperature,
            "topK": -1,
            "topP": -1,
            "stream": True,
        }

        try:
            LOGGER.info(f"Sending prompt to Cody using model: {self.model}")

            api_response = requests.post(
                self.chat_completions_url,
                headers=self.headers,
                json=data,
                stream=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            api_response.raise_for_status()

            # Process streaming response
            last_response = ""
            for line in api_response.iter_lines(decode_unicode=True):
                if line.startswith('data: {"'):
                    last_response = line[6:]

            if last_response:
                result = json.loads(last_response)["completion"]
                LOGGER.info("✅ Received response from Cody")
                return result

            LOGGER.error("❌ No response received from Cody")
            return None

        except requests.RequestException as e:
            LOGGER.error(f"❌ API request failed: {str(e)}")
            return None
        except json.JSONDecodeError as e:
            LOGGER.error(f"❌ Failed to parse response: {str(e)}")
            return None
        except KeyError as e:
            LOGGER.error(f"❌ Missing expected field in response: {str(e)}")
            return None


# Simple function for easy usage
def send_prompt_to_cody(prompt: str) -> Optional[str]:
    """Send a prompt to Cody API and retrieve the response.

    This function creates a new CodyApiClient instance and sends the provided
    prompt to the Cody service for processing.

    :param prompt: The text prompt to send to Cody API.
    :return: Response content from Cody API, or None if the request failed.
    """
    client = CodyApiClient()
    return client.send_prompt(prompt)


if __name__ == "__main__":
    # Example usage
    response = send_prompt_to_cody("What are best practices for register definitions?")
    if response:
        print("🤖 Cody's response:")
        print(response)
    else:
        print("❌ Failed to get response from Cody")

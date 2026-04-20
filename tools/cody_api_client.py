#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2025-2026 NXP
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
        # Normalize endpoint - remove trailing slash for consistency
        self.endpoint = self.endpoint.rstrip("/")

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
        # Try multiple possible endpoints
        possible_endpoints = [
            f"{self.endpoint}/.api/models",
            f"{self.endpoint}/.api/llm/models",
            f"{self.endpoint}/api/models",
        ]

        for models_url in possible_endpoints:
            try:
                LOGGER.debug(f"Trying models endpoint: {models_url}")
                api_response = requests.get(
                    models_url, headers=self.headers, timeout=10, verify=self.verify_ssl
                )

                if api_response.status_code == 200:
                    LOGGER.debug(f"Response from {models_url}: {api_response.text[:200]}")
                    models_data = api_response.json()

                    # Handle different possible response formats
                    if isinstance(models_data, dict):
                        # Try different possible keys
                        for key in ["models", "data", "available_models", "llms"]:
                            if key in models_data:
                                models = models_data[key]
                                if isinstance(models, list):
                                    # Extract model names if they're objects
                                    model_names = []
                                    for model in models:
                                        if isinstance(model, str):
                                            model_names.append(model)
                                        elif isinstance(model, dict) and "name" in model:
                                            model_names.append(model["name"])
                                        elif isinstance(model, dict) and "id" in model:
                                            model_names.append(model["id"])
                                    if model_names:
                                        LOGGER.info(f"Found {len(model_names)} models from API")
                                        return model_names
                    elif isinstance(models_data, list):
                        # Direct list of models
                        model_names = []
                        for model in models_data:
                            if isinstance(model, str):
                                model_names.append(model)
                            elif isinstance(model, dict) and "name" in model:
                                model_names.append(model["name"])
                            elif isinstance(model, dict) and "id" in model:
                                model_names.append(model["id"])
                        if model_names:
                            LOGGER.info(f"Found {len(model_names)} models from API")
                            return model_names
                else:
                    LOGGER.debug(
                        f"Models API at {models_url} returned status {api_response.status_code}"
                    )

            except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
                LOGGER.debug(f"Could not fetch models from {models_url}: {e}")
                continue

        LOGGER.warning("Could not fetch available models from any endpoint")
        return []

    def _determine_model(self) -> str:
        """Determine which model to use with automatic detection and environment variable support.

        The method prioritizes environment variable CODY_MODEL over automatic selection.
        If no environment variable is set, it uses autodetection to select the first
        available model from the API.

        :return: Selected model identifier string.
        :raises ValueError: If CODY_MODEL is not set and no models are available from API.
        """
        # Check environment variable first (highest priority)
        env_model = os.environ.get("CODY_MODEL")
        if env_model:
            LOGGER.info(f"Using model from CODY_MODEL environment variable: {env_model}")
            return env_model

        # Auto-detect from API
        available_models = self._get_available_models()

        if not available_models:
            raise ValueError(
                "No models available from API and CODY_MODEL environment variable not set. "
                "Please set CODY_MODEL to specify a model explicitly."
            )

        # Use the first available model
        selected_model = available_models[0]
        LOGGER.info(f"Auto-selected model: {selected_model}")
        LOGGER.debug(f"Available models: {available_models}")

        return selected_model

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
            LOGGER.debug(f"Request URL: {self.chat_completions_url}")

            api_response = requests.post(
                self.chat_completions_url,
                headers=self.headers,
                json=data,
                stream=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            # Log response status for debugging
            LOGGER.debug(f"Response status: {api_response.status_code}")

            api_response.raise_for_status()

            # Process streaming response - improved parsing
            full_response = ""
            last_completion = ""

            for line in api_response.iter_lines(decode_unicode=True):

                if not line or line.strip() == "":
                    continue

                LOGGER.debug(f"Received line: {line[:100]}...")

                # Handle different streaming formats
                if line.startswith("data: "):
                    json_str = line[6:].strip()
                    if json_str and json_str != "[DONE]":
                        try:
                            chunk = json.loads(json_str)
                            # Try different possible response formats
                            if "completion" in chunk:
                                last_completion = chunk["completion"]
                            elif "delta" in chunk and "text" in chunk["delta"]:
                                full_response += chunk["delta"]["text"]
                            elif "text" in chunk:
                                full_response += chunk["text"]
                        except json.JSONDecodeError as e:
                            LOGGER.debug(f"Failed to parse chunk: {e}")
                            continue
                elif line.startswith("{"):
                    # Direct JSON without 'data:' prefix
                    try:
                        chunk = json.loads(line)
                        if "completion" in chunk:
                            last_completion = chunk["completion"]
                        elif "delta" in chunk and "text" in chunk["delta"]:
                            full_response += chunk["delta"]["text"]
                        elif "text" in chunk:
                            full_response += chunk["text"]
                    except json.JSONDecodeError as e:
                        LOGGER.debug(f"Failed to parse JSON line: {e}")
                        continue

            # Return the best available response
            result = last_completion if last_completion else full_response

            if result:
                LOGGER.info("✅ Received response from Cody")
                return result

            LOGGER.error("❌ No response content received from Cody")
            return None

        except requests.HTTPError as e:
            LOGGER.error(f"❌ HTTP error: {e}")
            LOGGER.error(f"Response content: {e.response.text if e.response else 'N/A'}")
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
        except Exception as e:
            LOGGER.error(f"❌ Unexpected error: {str(e)}")
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
    # Example usage with debug logging
    logging.getLogger().setLevel(logging.DEBUG)

    response = send_prompt_to_cody("What are best practices for register definitions?")
    if response:
        print("🤖 Cody's response:")
        print(response)
    else:
        print("❌ Failed to get response from Cody")

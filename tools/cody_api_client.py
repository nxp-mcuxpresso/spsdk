#!/usr/bin/env python
#
# Copyright 2025-2026 NXP
#
# SPDX-License-Identifier: BSD-3-Clause

"""AI API client for external assistance (Cody and OpenAI-compatible endpoints).

This module provides functionality for communicating with AI API services
to enable AI-powered assistance within SPSDK tools and workflows. Supports
both Sourcegraph Cody and any OpenAI-compatible endpoint (Azure OpenAI,
Ollama, vLLM, llama.cpp, LM Studio, etc.).

Backend selection is controlled by the ``LLM_BACKEND`` environment variable:
  - ``cody``   — Sourcegraph Cody (default, backward-compatible)
  - ``openai`` — Any OpenAI-compatible ``/v1/chat/completions`` endpoint
"""

import json
import logging
import os

import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)


class LlmApiClient:
    """AI API Client supporting Cody and OpenAI-compatible backends.

    Singleton client for communicating with AI API services, providing
    unified access to AI-powered code analysis and completion capabilities.
    The backend is selected via the ``LLM_BACKEND`` environment variable.

    :cvar _instance: Singleton instance reference.
    :cvar _initialized: Initialization state flag.
    """

    BACKEND_CODY = "cody"
    BACKEND_OPENAI = "openai"

    _instance = None
    _initialized = False

    def __new__(cls) -> "LlmApiClient":
        """Create or return the singleton instance of LlmApiClient.

        :return: The singleton instance of LlmApiClient.
        """
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self) -> None:
        """Initialize the API client with configuration from environment variables.

        Common variables (both backends):
          - ``LLM_BACKEND``      — ``cody`` (default) or ``openai``
          - ``LLM_MODEL``        — Model name (alias: ``CODY_MODEL``)
          - ``LLM_MAX_TOKENS``   — Max response tokens (alias: ``CODY_MAX_TOKENS``, default 4000)
          - ``LLM_TEMPERATURE``  — Sampling temperature (alias: ``CODY_TEMPERATURE``, default 0.2)
          - ``LLM_TIMEOUT``      — Request timeout in seconds (alias: ``CODY_TIMEOUT``, default 60)
          - ``LLM_VERIFY_SSL``   — Verify TLS certificates (alias: ``CODY_VERIFY_SSL``, default false)

        Cody backend variables:
          - ``CODY_SRC_ACCESS_TOKEN`` — Sourcegraph access token
          - ``CODY_SRC_ENDPOINT``     — Sourcegraph instance URL

        OpenAI backend variables:
          - ``OPENAI_API_KEY``   — API key (``Bearer`` auth)
          - ``OPENAI_BASE_URL``  — Base URL, e.g. ``http://localhost:11434/v1``
          - ``OPENAI_SYSTEM_PROMPT`` — Optional system prompt prepended to every request

        :raises ValueError: When required credentials are missing.
        """
        if self._initialized:
            return

        self.backend = os.environ.get("LLM_BACKEND", self.BACKEND_CODY).lower()

        # Shared configuration (with backward-compatible CODY_* aliases)
        self.max_tokens = int(
            os.environ.get("LLM_MAX_TOKENS", os.environ.get("CODY_MAX_TOKENS", "4000"))
        )
        self.temperature = float(
            os.environ.get("LLM_TEMPERATURE", os.environ.get("CODY_TEMPERATURE", "0.2"))
        )
        self.timeout = int(os.environ.get("LLM_TIMEOUT", os.environ.get("CODY_TIMEOUT", "60")))
        self.verify_ssl = (
            os.environ.get("LLM_VERIFY_SSL", os.environ.get("CODY_VERIFY_SSL", "false")).lower()
            == "true"
        )

        if self.backend == self.BACKEND_OPENAI:
            self._init_openai()
        else:
            self._init_cody()

        self._initialized = True
        LOGGER.info(f"✅ LLM API client initialized — backend={self.backend}, model={self.model}")

    # ------------------------------------------------------------------
    # Backend-specific initialization
    # ------------------------------------------------------------------

    def _init_cody(self) -> None:
        """Set up Sourcegraph Cody backend."""
        self.access_token = os.environ.get("CODY_SRC_ACCESS_TOKEN")
        if not self.access_token:
            raise ValueError("CODY_SRC_ACCESS_TOKEN environment variable is required")

        self.endpoint = os.environ.get("CODY_SRC_ENDPOINT", "https://sourcegraph.com/").rstrip("/")
        self.chat_completions_url = (
            f"{self.endpoint}/.api/completions/stream"
            "?api-version=1&client-name=cody-data-processor&client-version=1.0"
        )
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"token {self.access_token}",
        }
        self.model = self._determine_model()

    def _init_openai(self) -> None:
        """Set up OpenAI-compatible backend."""
        self.access_token = os.environ.get("OPENAI_API_KEY", "")
        base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
        self.chat_completions_url = f"{base_url}/chat/completions"
        self.endpoint = base_url
        self.system_prompt: str | None = os.environ.get("OPENAI_SYSTEM_PROMPT")

        self.headers = {
            "Content-Type": "application/json",
        }
        if self.access_token:
            self.headers["Authorization"] = f"Bearer {self.access_token}"

        self.model = os.environ.get("LLM_MODEL", os.environ.get("CODY_MODEL", "gpt-4o"))

    # ------------------------------------------------------------------
    # Model discovery (Cody)
    # ------------------------------------------------------------------

    def _get_available_models(self) -> list[str]:
        """Fetch available models from the API endpoint.

        Tries multiple Cody and OpenAI-style model list endpoints, returning
        model names from the first successful response.

        :return: List of available model names, empty list if unavailable.
        """
        possible_endpoints = [
            f"{self.endpoint}/.api/models",
            f"{self.endpoint}/.api/llm/models",
            f"{self.endpoint}/api/models",
            f"{self.endpoint}/models",
        ]

        for models_url in possible_endpoints:
            try:
                LOGGER.debug(f"Trying models endpoint: {models_url}")
                api_response = requests.get(
                    models_url, headers=self.headers, timeout=10, verify=self.verify_ssl
                )
                if api_response.status_code != 200:
                    LOGGER.debug(
                        f"Models API at {models_url} returned status {api_response.status_code}"
                    )
                    continue

                model_names = self._parse_model_list(api_response.json())
                if model_names:
                    LOGGER.info(f"Found {len(model_names)} models from API")
                    return model_names

            except (requests.RequestException, json.JSONDecodeError, KeyError) as e:
                LOGGER.debug(f"Could not fetch models from {models_url}: {e}")
                continue

        LOGGER.warning("Could not fetch available models from any endpoint")
        return []

    @staticmethod
    def _parse_model_list(models_data: object) -> list[str]:
        """Extract model name strings from various API response formats.

        :param models_data: Parsed JSON response — may be a list or dict.
        :return: List of model name strings.
        """

        def _extract_names(items: list) -> list[str]:  # type: ignore[type-arg]
            names: list[str] = []
            for item in items:
                if isinstance(item, str):
                    names.append(item)
                elif isinstance(item, dict):
                    names.append(item.get("name") or item.get("id", ""))
            return [n for n in names if n]

        if isinstance(models_data, list):
            return _extract_names(models_data)

        if isinstance(models_data, dict):
            for key in ("models", "data", "available_models", "llms"):
                if key in models_data and isinstance(models_data[key], list):
                    result = _extract_names(models_data[key])
                    if result:
                        return result
        return []

    def _determine_model(self) -> str:
        """Determine which model to use via env-var or auto-detection.

        :return: Selected model identifier string.
        :raises ValueError: If no model can be determined.
        """
        env_model = os.environ.get("LLM_MODEL", os.environ.get("CODY_MODEL"))
        if env_model:
            LOGGER.info(f"Using model from environment variable: {env_model}")
            return env_model

        available_models = self._get_available_models()
        if not available_models:
            raise ValueError(
                "No models available from API and LLM_MODEL / CODY_MODEL not set. "
                "Please set LLM_MODEL to specify a model explicitly."
            )

        selected_model = available_models[0]
        LOGGER.info(f"Auto-selected model: {selected_model}")
        return selected_model

    # ------------------------------------------------------------------
    # Send prompt
    # ------------------------------------------------------------------

    def send_prompt(self, prompt: str) -> str | None:
        """Send a prompt and wait for a response (blocking, streaming).

        Automatically dispatches to the Cody or OpenAI protocol based on
        the configured backend.

        :param prompt: The prompt text to send.
        :return: Response content or None if the request failed.
        """
        if self.backend == self.BACKEND_OPENAI:
            return self._send_openai(prompt)
        return self._send_cody(prompt)

    def _send_cody(self, prompt: str) -> str | None:
        """Send a prompt via the Sourcegraph Cody streaming API.

        :param prompt: The prompt text.
        :return: Response content or None.
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
        return self._stream_request(data, response_style="cody")

    def _send_openai(self, prompt: str) -> str | None:
        """Send a prompt via an OpenAI-compatible chat/completions API.

        :param prompt: The prompt text.
        :return: Response content or None.
        """
        messages: list[dict[str, str]] = []
        if self.system_prompt:
            messages.append({"role": "system", "content": self.system_prompt})
        messages.append({"role": "user", "content": prompt})

        data = {
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "stream": True,
        }
        return self._stream_request(data, response_style="openai")

    def _stream_request(self, data: dict, response_style: str) -> str | None:  # type: ignore[type-arg]
        """Execute a streaming POST and collect the response text.

        :param data: JSON payload for the request.
        :param response_style: ``"cody"`` or ``"openai"`` — controls chunk parsing.
        :return: Collected response text or None.
        """
        try:
            LOGGER.info(f"Sending prompt using model: {self.model}")
            LOGGER.debug(f"Request URL: {self.chat_completions_url}")

            api_response = requests.post(
                self.chat_completions_url,
                headers=self.headers,
                json=data,
                stream=True,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            api_response.raise_for_status()

            if response_style == "openai":
                result = self._collect_openai_stream(api_response)
            else:
                result = self._collect_cody_stream(api_response)

            if result:
                LOGGER.info("✅ Received response from LLM")
                return result

            LOGGER.error("❌ No response content received")
            return None

        except requests.HTTPError as e:
            LOGGER.error(f"❌ HTTP error: {e}")
            LOGGER.error(f"Response content: {e.response.text if e.response else 'N/A'}")
        except requests.RequestException as e:
            LOGGER.error(f"❌ API request failed: {e}")
        except (json.JSONDecodeError, KeyError) as e:
            LOGGER.error(f"❌ Response parsing error: {e}")
        except Exception as e:
            LOGGER.error(f"❌ Unexpected error: {e}")
        return None

    # ------------------------------------------------------------------
    # Stream collectors
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_cody_stream(api_response: requests.Response) -> str:
        """Parse Sourcegraph Cody streaming response.

        :param api_response: The streaming HTTP response.
        :return: Collected response text.
        """
        full_response = ""
        last_completion = ""

        for line in api_response.iter_lines(decode_unicode=True):
            if not line or line.strip() == "":
                continue

            json_str = None
            if line.startswith("data: "):
                json_str = line[6:].strip()
                if json_str == "[DONE]":
                    continue
            elif line.startswith("{"):
                json_str = line

            if not json_str:
                continue
            try:
                chunk = json.loads(json_str)
                if "completion" in chunk:
                    last_completion = chunk["completion"]
                elif "delta" in chunk and "text" in chunk["delta"]:
                    full_response += chunk["delta"]["text"]
                elif "text" in chunk:
                    full_response += chunk["text"]
            except json.JSONDecodeError:
                continue

        return last_completion or full_response

    @staticmethod
    def _collect_openai_stream(api_response: requests.Response) -> str:
        """Parse OpenAI-compatible SSE streaming response.

        :param api_response: The streaming HTTP response.
        :return: Collected response text.
        """
        full_response = ""

        for line in api_response.iter_lines(decode_unicode=True):
            if not line or not line.startswith("data: "):
                continue
            json_str = line[6:].strip()
            if json_str == "[DONE]":
                break
            try:
                chunk = json.loads(json_str)
                choices = chunk.get("choices", [])
                if choices:
                    delta = choices[0].get("delta", {})
                    content = delta.get("content", "")
                    if content:
                        full_response += content
            except json.JSONDecodeError:
                continue

        return full_response


# Backward-compatible alias
CodyApiClient = LlmApiClient


def send_prompt_to_cody(prompt: str) -> str | None:
    """Send a prompt to the configured LLM backend and retrieve the response.

    Works with both Cody and OpenAI-compatible backends. The backend is
    selected via the ``LLM_BACKEND`` environment variable (default: ``cody``).

    :param prompt: The text prompt to send.
    :return: Response content, or None if the request failed.
    """
    client = LlmApiClient()
    return client.send_prompt(prompt)


if __name__ == "__main__":
    # Example usage with debug logging
    logging.getLogger().setLevel(logging.DEBUG)

    response = send_prompt_to_cody("What are best practices for register definitions?")
    if response:
        print("🤖 Response:")
        print(response)
    else:
        print("❌ Failed to get response")

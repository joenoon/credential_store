# Copyright (c) 2025 Joe Noon <https://github.com/joenoon>
#
# MIT License
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
defmodule CredentialStore do
  @moduledoc """
  Per-environment encrypted credential storage.

  Secrets are stored in `priv/secrets.enc.json` with top-level keys as environment
  names (e.g. "dev", "prod"). Each environment section is encrypted with its own key
  via the `CREDENTIAL_STORE_KEY` environment variable.
  """

  @encrypted_file "priv/secrets.enc.json"
  @check_key "_cs_check"
  @check_value "ok"

  @doc """
  Loads decrypted secrets for a specific environment from the app's encrypted secrets file.

  Uses the `CREDENTIAL_STORE_KEY` environment variable for decryption.

  ## Options

    * `:env` - (required) the environment section to decrypt (e.g. `:dev`, `:prod`)

  ## Examples

      secrets = CredentialStore.load_secrets(:my_app, env: :dev)

  """
  def load_secrets(app, opts \\ []) do
    key = get_key!()
    env = opts[:env] || raise ArgumentError, "env option is required"
    encrypted = read_file!(Application.app_dir(app, @encrypted_file))
    data = Jason.decode!(encrypted)

    section =
      Map.get(data, to_string(env)) ||
        raise "No section '#{env}' found in secrets file"

    decrypt_data(section, key)
  end

  @doc """
  Fetches a secret by key or nested path, returning nil if not found.

  ## Examples

      CredentialStore.get(secrets, "LLM_API_KEY")
      CredentialStore.get(secrets, ["nested", "key"])

  """
  def get(secrets, path) when is_list(path) do
    Enum.reduce_while(path, secrets, fn key, acc ->
      case Map.fetch(acc, key) do
        {:ok, value} -> {:cont, value}
        :error -> {:halt, nil}
      end
    end)
  end

  def get(secrets, key) when is_binary(key) do
    get(secrets, [key])
  end

  @doc """
  Fetches a secret by key or nested path, raising if not found.

  ## Examples

      CredentialStore.get!(secrets, "LLM_API_KEY")

  """
  def get!(secrets, path) when is_list(path) do
    case get(secrets, path) do
      nil -> raise KeyError, "Key path #{inspect(path)} not found in secrets"
      value -> value
    end
  end

  def get!(secrets, key) when is_binary(key) do
    get!(secrets, [key])
  end

  @doc """
  Loads the decrypted secrets map for a given environment section from the encrypted file.

  Returns an empty map if the file or section doesn't exist.
  """
  def load_section(env) do
    key = get_key!()

    case File.read(@encrypted_file) do
      {:ok, contents} ->
        data = Jason.decode!(contents)

        case Map.get(data, to_string(env)) do
          nil ->
            {:ok, %{}}

          section ->
            decrypted = decrypt_data(section, key)

            if Map.get(decrypted, @check_key) == @check_value do
              {:ok, Map.delete(decrypted, @check_key)}
            else
              {:error, :wrong_key}
            end
        end

      {:error, :enoent} ->
        {:ok, %{}}
    end
  end

  @doc """
  Encrypts a plaintext map and saves it as the given environment section
  in the encrypted file, preserving other environment sections.
  """
  def save_section(env, plaintext_map) do
    key = get_key!()
    with_check = Map.put(plaintext_map, @check_key, @check_value)
    encrypted_section = encrypt_data(with_check, key)

    existing =
      case File.read(@encrypted_file) do
        {:ok, contents} -> Jason.decode!(contents)
        {:error, :enoent} -> %{}
      end

    merged = Map.put(existing, to_string(env), encrypted_section)
    File.write!(@encrypted_file, Jason.encode_to_iodata!(merged, pretty: true))
  end

  @doc "Encrypts data recursively, leaving keys plaintext and encrypting string values."
  def encrypt_data(map, key) when is_map(map) do
    Map.new(map, fn {k, v} -> {k, encrypt_data(v, key)} end)
  end

  def encrypt_data(list, key) when is_list(list) do
    Enum.map(list, &encrypt_data(&1, key))
  end

  def encrypt_data(str, key) when is_binary(str) do
    iv = binary_part(:crypto.hash(:sha256, str), 0, 16)
    pad_len = 16 - rem(byte_size(str), 16)
    padded_str = str <> String.duplicate(<<pad_len>>, pad_len)
    hashed_key = :crypto.hash(:sha256, key)
    ciphertext = :crypto.crypto_one_time(:aes_256_cbc, hashed_key, iv, padded_str, true)
    Base.encode64(iv <> ciphertext)
  end

  def encrypt_data(value, _key), do: value

  @doc "Decrypts data recursively, decoding encrypted string values."
  def decrypt_data(map, key) when is_map(map) do
    Map.new(map, fn {k, v} -> {k, decrypt_data(v, key)} end)
  end

  def decrypt_data(list, key) when is_list(list) do
    Enum.map(list, &decrypt_data(&1, key))
  end

  def decrypt_data(str, key) when is_binary(str) do
    encrypted = Base.decode64!(str)
    iv = binary_part(encrypted, 0, 16)
    ciphertext = binary_part(encrypted, 16, byte_size(encrypted) - 16)
    hashed_key = :crypto.hash(:sha256, key)
    padded = :crypto.crypto_one_time(:aes_256_cbc, hashed_key, iv, ciphertext, false)
    unpad(padded)
  end

  def decrypt_data(value, _key), do: value

  defp get_key! do
    System.get_env("CREDENTIAL_STORE_KEY") ||
      raise "CREDENTIAL_STORE_KEY env var required (any string, e.g., UUID)"
  end

  defp read_file!(file) do
    unless File.exists?(file) do
      raise "File '#{file}' not found"
    end

    File.read!(file)
  end

  defp unpad(padded) do
    pad_len = :binary.last(padded)

    if pad_len > 0 and pad_len <= 16 do
      binary_part(padded, 0, byte_size(padded) - pad_len)
    else
      padded
    end
  end
end

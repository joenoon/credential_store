defmodule CredentialStore.Editor do
  @moduledoc """
  Interactive in-memory editor for credential store secrets.
  No decrypted file ever touches disk.
  """

  @doc """
  Starts the interactive editor for the given environment.

  Accepts optional `:gets` and `:puts` function options for testability.
  Defaults to `&IO.gets/1` and `&IO.puts/1`.
  """
  def run(env, opts \\ []) do
    gets = Keyword.get(opts, :gets, &IO.gets/1)
    puts = Keyword.get(opts, :puts, &IO.puts/1)

    case CredentialStore.load_section(env) do
      {:ok, secrets} ->
        display_and_loop(env, secrets, gets, puts)

      {:error, :wrong_key} ->
        puts.("Error: CREDENTIAL_STORE_KEY does not match the key used to encrypt '#{env}' secrets.")
        puts.("Check your key and try again.")
    end
  end

  defp display_and_loop(env, secrets, gets, puts) do
    print_header(env, puts)
    print_secrets(secrets, puts)
    print_commands(puts)
    loop(env, secrets, gets, puts)
  end

  defp loop(env, secrets, gets, puts) do
    input = gets.("> ") |> to_string() |> String.trim() |> String.downcase()

    case input do
      "a" -> handle_add(env, secrets, gets, puts)
      "e" -> handle_edit(env, secrets, gets, puts)
      "d" -> handle_delete(env, secrets, gets, puts)
      "v" -> handle_view(env, secrets, gets, puts)
      "s" -> handle_save(env, secrets, puts)
      "q" -> handle_quit(puts)
      _ ->
        puts.("Unknown command. Use [a]dd [e]dit [d]elete [v]iew [s]ave [q]uit")
        loop(env, secrets, gets, puts)
    end
  end

  defp handle_add(env, secrets, gets, puts) do
    key = gets.("Key name: ") |> to_string() |> String.trim()

    if key == "" do
      puts.("Key name cannot be empty.")
      display_and_loop(env, secrets, gets, puts)
    else
      value = gets.("Value: ") |> to_string() |> String.trim()
      updated = Map.put(secrets, key, value)
      puts.("Added #{key}.")
      display_and_loop(env, updated, gets, puts)
    end
  end

  defp handle_edit(env, secrets, gets, puts) do
    keys = sorted_keys(secrets)

    if keys == [] do
      puts.("No secrets to edit.")
      display_and_loop(env, secrets, gets, puts)
    else
      input = gets.("Number to edit: ") |> to_string() |> String.trim()

      case parse_index(input, keys) do
        {:ok, key} ->
          value = gets.("New value for #{key}: ") |> to_string() |> String.trim()
          updated = Map.put(secrets, key, value)
          puts.("Updated #{key}.")
          display_and_loop(env, updated, gets, puts)

        :error ->
          puts.("Invalid number.")
          display_and_loop(env, secrets, gets, puts)
      end
    end
  end

  defp handle_delete(env, secrets, gets, puts) do
    keys = sorted_keys(secrets)

    if keys == [] do
      puts.("No secrets to delete.")
      display_and_loop(env, secrets, gets, puts)
    else
      input = gets.("Number to delete: ") |> to_string() |> String.trim()

      case parse_index(input, keys) do
        {:ok, key} ->
          confirm =
            gets.("Delete #{key}? [y/N]: ")
            |> to_string()
            |> String.trim()
            |> String.downcase()

          if confirm == "y" do
            updated = Map.delete(secrets, key)
            puts.("Deleted #{key}.")
            display_and_loop(env, updated, gets, puts)
          else
            puts.("Cancelled.")
            display_and_loop(env, secrets, gets, puts)
          end

        :error ->
          puts.("Invalid number.")
          display_and_loop(env, secrets, gets, puts)
      end
    end
  end

  defp handle_view(env, secrets, gets, puts) do
    keys = sorted_keys(secrets)

    if keys == [] do
      puts.("No secrets to view.")
      display_and_loop(env, secrets, gets, puts)
    else
      input = gets.("Number to view: ") |> to_string() |> String.trim()

      case parse_index(input, keys) do
        {:ok, key} ->
          puts.("#{key} = #{Map.get(secrets, key)}")
          display_and_loop(env, secrets, gets, puts)

        :error ->
          puts.("Invalid number.")
          display_and_loop(env, secrets, gets, puts)
      end
    end
  end

  defp handle_save(env, secrets, puts) do
    CredentialStore.save_section(env, secrets)
    puts.("Saved (env: #{env}).")
  end

  defp handle_quit(puts) do
    puts.("Quit without saving.")
  end

  defp print_header(env, puts) do
    puts.("")
    puts.("CredentialStore (env: #{env})")
    puts.(String.duplicate("\u2500", 30))
    puts.("")
  end

  defp print_secrets(secrets, puts) when map_size(secrets) == 0 do
    puts.("  (no secrets yet — use [a]dd to create one)")
    puts.("")
  end

  defp print_secrets(secrets, puts) do
    puts.("Current secrets:")

    secrets
    |> sorted_keys()
    |> Enum.with_index(1)
    |> Enum.each(fn {key, idx} ->
      puts.("  #{idx}. #{key} = #{mask(Map.get(secrets, key))}")
    end)

    puts.("")
  end

  defp print_commands(puts) do
    puts.("Commands: [a]dd  [e]dit  [d]elete  [v]iew  [s]ave & exit  [q]uit without saving")
    puts.("")
  end

  defp sorted_keys(secrets) do
    secrets |> Map.keys() |> Enum.sort()
  end

  defp parse_index(input, keys) do
    case Integer.parse(input) do
      {num, ""} when num >= 1 and num <= length(keys) ->
        {:ok, Enum.at(keys, num - 1)}

      _ ->
        :error
    end
  end

  @doc """
  Masks a secret value for display.

  Values >= 8 chars: first 12 chars + "..." + last 3 chars.
  Values < 8 chars: "******".
  """
  def mask(value) when is_binary(value) and byte_size(value) >= 8 do
    prefix_len = min(12, byte_size(value))
    prefix = binary_part(value, 0, prefix_len)
    suffix = binary_part(value, byte_size(value) - 3, 3)
    "#{prefix}...#{suffix}"
  end

  def mask(value) when is_binary(value), do: "******"
  def mask(_value), do: "******"
end
